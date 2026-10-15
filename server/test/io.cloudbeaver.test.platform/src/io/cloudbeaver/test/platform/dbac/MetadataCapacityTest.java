/*
 * DBeaver - Universal Database Manager
 * Copyright (C) 2010-2026 DBeaver Corp and others
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.cloudbeaver.test.platform.dbac;

import io.cloudbeaver.app.CEAppStarter;
import io.cloudbeaver.model.app.ServletApplication;
import io.cloudbeaver.model.config.WebDatabaseConfig;
import io.cloudbeaver.service.dbac.DbacSecurityControllerFactory;
import io.cloudbeaver.service.dbac.PolicyServiceHolder;
import io.cloudbeaver.service.dbac.db.DbacCBDatabase;
import io.cloudbeaver.service.dbac.db.DbacSchema;
import io.cloudbeaver.service.dbac.policy.BoundedMetadataConnections;
import io.cloudbeaver.service.dbac.policy.DbAccessKey;
import io.cloudbeaver.service.dbac.policy.DbAccessPolicyConfig;
import io.cloudbeaver.service.dbac.policy.DbAccessPolicyService;
import io.cloudbeaver.service.dbac.policy.DbOperationCategory;
import io.cloudbeaver.service.dbac.policy.DenialReason;
import io.cloudbeaver.service.dbac.policy.WriteAuthorizationRequest;
import io.cloudbeaver.service.dbac.policy.enforcement.DeploymentGuard;
import io.cloudbeaver.service.dbac.policy.enforcement.EnforcementGate;
import io.cloudbeaver.service.dbac.policy.enforcement.EnforcementKeyLocks;
import io.cloudbeaver.service.dbac.policy.enforcement.TransactionTaintRegistry;
import io.cloudbeaver.service.dbac.tempwrite.MetadataConnectionSource;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteGrant;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteGrantRepository;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteMutationCoordinator;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteMutationResult;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteMutationStatus;
import io.cloudbeaver.service.dbac.tempwrite.TempWritePermissionKey;
import io.cloudbeaver.service.security.EmbeddedSecurityControllerFactory;
import io.cloudbeaver.test.platform.dbac.KeyLockTestSupport.Worker;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.IOException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.RecordComponent;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BooleanSupplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * P6-0 S-CAP: what four metadata slots do to write requests, measured on this machine and pinned where it is deterministic
 * <p>
 * Slice 4a keeps the metadata lease capacity at {@link BoundedMetadataConnections#CAPACITY} = 4, with no way to
 * configure it. These cases pin that, show that nothing waits for a grant key or user lock while it holds a metadata
 * connection, that a fifth request is refused at once without borrowing or submitting anything, that hung borrows
 * never keep a request past its budget and that capacity comes back once they end. CAP-5 records how 1, 4, 8 and 16
 * concurrent requests fare on the local H2 - a measurement of this test environment, not a throughput promise.
 * <p>
 * Requests go through the enforcement gate on a lifecycle of the case's own, as GT-1 - GT-35 do; the metadata
 * database is the server's H2, reached through a source that counts every borrow and can hold it.
 */
@Timeout(value = 300, unit = TimeUnit.SECONDS, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
public class MetadataCapacityTest {

    private static final String USER_PREFIX = "dbac-cap-";
    private static final String PROJECT = "cap-project";
    private static final String CONNECTION = "cap-connection";
    private static final String HOST = "db.internal.example";
    private static final String DATABASE = "customer_prod";
    private static final Duration GRANT = Duration.ofMinutes(30);
    private static final long WAIT_SECONDS = 30;
    private static final AtomicLong SEQUENCE = new AtomicLong();
    private static final AtomicLong CONTEXT_IDS = new AtomicLong(9_300_000L);
    private static final Pattern LOCK_CALL = Pattern.compile(
        "\\.(lockGrantForWrite|lockUserForWrite|tryLockGrantForRead|tryLockUserForRead)\\(");

    private final List<Lab> labs = new ArrayList<>();
    private final TempWriteGrantRepository repository = new TempWriteGrantRepository();

    @BeforeAll
    public static void prepare() throws Exception {
        CEAppStarter.startServerIfNotStarted();
        Assertions.assertNotNull(EmbeddedSecurityControllerFactory.getDbInstance(), "FIXTURE: the server metadata database must exist");
    }

    @AfterEach
    public void cleanUp() throws Exception {
        List<Throwable> shutdowns = new ArrayList<>();
        for (Lab lab : labs) {
            lab.releaseBorrows();
            shutdowns.addAll(lab.shutdown());
        }
        labs.clear();
        try (Connection connection = h2().openConnection()) {
            for (String table : List.of("DBAC_AUDIT_EVENT", "DBAC_TW_HISTORY", "DBAC_TW_CURRENT", "CB_USER", "CB_AUTH_SUBJECT")) {
                String column = table.equals("CB_AUTH_SUBJECT") ? "SUBJECT_ID" : "USER_ID";
                try (PreparedStatement dbStat = connection.prepareStatement(
                    "DELETE FROM {table_prefix}" + table + " WHERE " + column + " LIKE ?")) {
                    dbStat.setString(1, USER_PREFIX + "%");
                    dbStat.executeUpdate();
                }
            }
        }
        Assertions.assertEquals(List.of(), shutdowns.stream().map(t -> t.getClass().getName()).toList(),
            "FIXTURE: a lifecycle did not shut down cleanly");
    }

    @NotNull
    private static MetadataConnectionSource h2() {
        return EmbeddedSecurityControllerFactory.getDbInstance()::openConnection;
    }

    // ---------------------------------------------------------------- CAP-1, CAP-2: the fixed shape

    /**
     * CAP-1: four slots and four workers per metadata database, and nothing that could configure another number
     */
    @Test
    public void cap1TheCapacityIsFourAndCannotBeConfigured() {
        List<String> violations = new ArrayList<>();
        expect(violations, "CAPACITY", 4, BoundedMetadataConnections.CAPACITY);
        expect(violations, "WORKERS", 4, BoundedMetadataConnections.WORKERS);
        expect(violations, "the tuning's components", List.of("finishWait", "keepAlive", "probe"),
            components(BoundedMetadataConnections.Tuning.class));
        expect(violations, "the policy configuration's components", List.of("clockSkewThreshold", "maxGrantDuration",
            "expiryGuardMargin", "auditTimeout", "keyLockTimeout", "snapshotTimeout"), components(DbAccessPolicyConfig.class));
        List<String> factories = new ArrayList<>();
        for (Method method : BoundedMetadataConnections.class.getDeclaredMethods()) {
            if (Modifier.isPublic(method.getModifiers()) && Modifier.isStatic(method.getModifiers())
                && method.getReturnType() == BoundedMetadataConnections.Owned.class) {
                factories.add(method.getName() + Arrays.stream(method.getParameterTypes()).map(Class::getSimpleName).toList());
            }
        }
        Collections.sort(factories);
        expect(violations, "the public ways to make one", List.of("create[MetadataConnectionSource, Tuning]",
            "create[MetadataConnectionSource]"), factories);
        expect(violations, "public constructors", 0, BoundedMetadataConnections.class.getConstructors().length);
        Assertions.assertEquals(List.of(), violations, "CAP-1");
    }

    @NotNull
    private static List<String> components(@NotNull Class<?> type) {
        RecordComponent[] components = type.getRecordComponents();
        return components == null ? List.of() : Arrays.stream(components).map(RecordComponent::getName).toList();
    }

    /**
     * CAP-2: nothing waits for a grant key or user lock while it holds a metadata connection
     * <p>
     * First the production sources: the only calls that take one of these locks are the gate's two reads, the
     * coordinator's grant and revoke, and the four user writers of the security controller. Then each of them,
     * made to wait for its lock by a writer the case holds, is seen waiting with no metadata connection opened.
     */
    @Test
    public void cap2NothingWaitsForAKeyLockWhileHoldingAMetadataConnection() throws Exception {
        List<String> violations = new ArrayList<>();
        expect(violations, "production calls that take a grant key or user lock", Map.of(
            "DbacEmbeddedSecurityController.java", List.of("lockUserForWrite", "lockUserForWrite", "lockUserForWrite", "lockUserForWrite"),
            "EnforcementGate.java", List.of("tryLockGrantForRead", "tryLockUserForRead"),
            "TempWriteMutationCoordinator.java", List.of("lockGrantForWrite", "tryLockUserForRead", "lockGrantForWrite")
        ), new TreeMap<>(productionLockCalls()));

        Lab lab = lab(config(Duration.ofSeconds(2)));
        String user = grantedUser("cap2-gate");
        DbAccessKey key = new DbAccessKey(user, PROJECT, CONNECTION);
        for (String which : List.of("grant key", "user")) {
            String what = "the gate waiting for the " + which + " lock: ";
            int opened = lab.opens.get();
            try (WriteHold held = which.equals("grant key") ? WriteHold.grant(key) : WriteHold.user(user)) {
                Worker<EnforcementGate.Result<String>> request = Worker.start("dbac-cap2-gate",
                    () -> lab.gate.enter().run(request(user), new Context(), new Operation()));
                if (!KeyLockTestSupport.awaitParked(request.thread)) {
                    violations.add(what + "the request must wait");
                }
                expect(violations, what + "metadata connections opened while it waits", opened, lab.opens.get());
                held.release();
                expectExecuted(violations, what, request);
            }
        }

        coordinatorWaits(violations, "grant waiting for the grant key", true, true);
        coordinatorWaits(violations, "grant waiting for the user", true, false);
        coordinatorWaits(violations, "revoke waiting for the grant key", false, true);

        try (KeyLockTestSupport.UserDb db = KeyLockTestSupport.UserDb.open()) {
            for (String operation : List.of("deleteUser", "enableUser", "deleteTeam")) {
                String what = "the controller's " + operation + " waiting for the user lock: ";
                String subject = operation.equals("deleteTeam") ? db.newTeam("cap2") : db.newUser("cap2-" + operation, true);
                db.arm();
                db.hooks().reset();
                try (WriteHold held = WriteHold.user(subject)) {
                    Worker<Object> call = Worker.start("dbac-cap2-controller", () -> {
                        switch (operation) {
                            case "deleteUser" -> db.controller.deleteUser(subject);
                            case "enableUser" -> db.controller.enableUser(subject, false, "dbac-cap-admin", "capacity test");
                            default -> db.controller.deleteTeam(subject, true);
                        }
                        return null;
                    });
                    if (!KeyLockTestSupport.awaitParked(call.thread)) {
                        violations.add(what + "the call must wait");
                    }
                    expect(violations, what + "metadata connections opened while it waits", 0, db.hooks().opened.get());
                    held.release();
                    if (!call.awaitDone() || call.error != null) {
                        violations.add(what + "the call must finish once the lock is free, got " + call.error);
                    }
                }
            }
        }
        Assertions.assertEquals(List.of(), violations, "CAP-2");
    }

    private void coordinatorWaits(@NotNull List<String> violations, @NotNull String what, boolean grant, boolean onKey) throws Exception {
        String user = activeUser("cap2-" + (grant ? "grant" : "revoke"));
        TempWritePermissionKey key = new TempWritePermissionKey(user, PROJECT, CONNECTION);
        if (!grant) {
            grant(user);
        }
        KeyLockTestSupport.Hooks hooks = new KeyLockTestSupport.Hooks();
        TempWriteMutationCoordinator coordinator = TempWriteMutationCoordinator.withoutAuditing(
            KeyLockTestSupport.hooked(h2(), hooks), repository);
        DbAccessKey accessKey = new DbAccessKey(user, PROJECT, CONNECTION);
        try (WriteHold held = onKey ? WriteHold.grant(accessKey) : WriteHold.user(user)) {
            Worker<TempWriteMutationResult> call = Worker.start("dbac-cap2-coordinator", () -> grant
                ? coordinator.grant(TempWriteTestSupport.grantRequest(key, revisionOf(key), GRANT, "capacity test"))
                : coordinator.revoke(TempWriteTestSupport.revokeRequest(key, revisionOf(key))));
            if (!KeyLockTestSupport.awaitParked(call.thread)) {
                violations.add(what + ": the call must wait");
            }
            expect(violations, what + ": metadata connections opened while it waits", 0, hooks.opened.get());
            held.release();
            if (!call.awaitDone() || call.error != null || call.result == null
                || call.result.status() != TempWriteMutationStatus.COMMITTED) {
                violations.add(what + ": the call must commit once the lock is free, got " + call.result + " / " + call.error);
            }
        }
    }

    private static long revisionOf(@NotNull TempWritePermissionKey key) throws SQLException {
        try (Connection connection = h2().openConnection()) {
            Long revision = TempWriteTestSupport.currentRevision(connection, key);
            return revision == null ? TempWriteGrant.NO_ROW_REVISION : revision;
        }
    }

    /** Every call in the production sources that takes a grant key or user lock, by file, in source order */
    @NotNull
    private static Map<String, List<String>> productionLockCalls() throws IOException {
        Map<String, List<String>> calls = new TreeMap<>();
        try (Stream<Path> files = Files.walk(MetadataLeaseTest.repositoryRoot().resolve("server/bundles"))) {
            for (Path file : files.filter(f -> f.toString().endsWith(".java") && f.toString().contains("src")).toList()) {
                if (file.getFileName().toString().equals("EnforcementKeyLocks.java")) {
                    continue;
                }
                Matcher matcher = LOCK_CALL.matcher(Files.readString(file, StandardCharsets.UTF_8));
                while (matcher.find()) {
                    calls.computeIfAbsent(file.getFileName().toString(), f -> new ArrayList<>()).add(matcher.group(1));
                }
            }
        }
        return calls;
    }

    // ---------------------------------------------------------------- CAP-3, CAP-4: saturation

    /**
     * CAP-3: with all four slots taken, a fifth request is refused at once - nothing borrowed, nothing submitted - and capacity comes back
     */
    @Test
    public void cap3AFifthRequestIsRefusedAtOnceAndCapacityComesBack() throws Exception {
        List<String> violations = new ArrayList<>();
        Lab lab = lab(config(Duration.ofSeconds(10)));
        String user = grantedUser("cap3");
        lab.holdBorrows();
        final List<Worker<EnforcementGate.Result<String>>> four = startRequests(lab, user, 4);
        Assertions.assertTrue(eventually(() -> lab.atGate.get() == 4), "FIXTURE: four borrows must be held");
        expect(violations, "slots while four borrows are held", 0, lab.leases.availableSlots());
        int opened = lab.opens.get();
        final long submitted = lab.leases.submittedTasks();
        Operation fifthOperation = new Operation();
        long start = System.nanoTime();
        EnforcementGate.Result<String> fifth = lab.gate.enter().run(request(user), new Context(), fifthOperation);
        long fifthMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
        expect(violations, "the fifth request", DenialReason.PERMISSION_STORE_UNAVAILABLE, reasonOf(fifth));
        if (fifthMillis >= 1_000) {
            violations.add("the fifth request must be refused at once, took " + fifthMillis + "ms");
        }
        expect(violations, "borrows for the fifth request", opened, lab.opens.get());
        expect(violations, "tasks submitted for the fifth request", submitted, lab.leases.submittedTasks());
        expect(violations, "the fifth request's operation", 0, fifthOperation.executes.get());
        lab.releaseBorrows();
        for (Worker<EnforcementGate.Result<String>> request : four) {
            expectExecuted(violations, "one of the four, once their borrows went through", request);
        }
        if (!eventually(() -> lab.leases.availableSlots() == 4)) {
            violations.add("every slot must come back, available " + lab.leases.availableSlots());
        }
        expectExecuted(violations, "a request after the four", Worker.start("dbac-cap3-after",
            () -> lab.gate.enter().run(request(user), new Context(), new Operation())));
        Assertions.assertEquals(List.of(), violations, "CAP-3");
    }

    /**
     * CAP-4: hung borrows never keep their requests past the snapshot budget, a fifth is refused at once, and capacity comes back
     */
    @Test
    public void cap4HungBorrowsNeverHoldARequestPastItsBudget() throws Exception {
        List<String> violations = new ArrayList<>();
        Duration snapshot = Duration.ofSeconds(2);
        Lab lab = lab(config(snapshot));
        String user = grantedUser("cap4");
        lab.holdBorrows();
        List<Worker<EnforcementGate.Result<String>>> four = startRequests(lab, user, 4);
        long bound = snapshot.toMillis() + 2_000;
        for (Worker<EnforcementGate.Result<String>> request : four) {
            if (!request.done.await(bound, TimeUnit.MILLISECONDS)) {
                violations.add("a request whose borrow hangs must return within " + bound + "ms");
                continue;
            }
            expect(violations, "a request whose borrow hangs", DenialReason.PERMISSION_STORE_UNAVAILABLE, reasonOf(request.result));
        }
        expect(violations, "workers still stuck in their borrows", 4, lab.leases.runningWorkers());
        expect(violations, "slots while the borrows hang", 0, lab.leases.availableSlots());
        int opened = lab.opens.get();
        final long submitted = lab.leases.submittedTasks();
        long start = System.nanoTime();
        EnforcementGate.Result<String> fifth = lab.gate.enter().run(request(user), new Context(), new Operation());
        long fifthMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
        expect(violations, "a request while every borrow hangs", DenialReason.PERMISSION_STORE_UNAVAILABLE, reasonOf(fifth));
        if (fifthMillis >= 1_000) {
            violations.add("a request while every borrow hangs must be refused at once, took " + fifthMillis + "ms");
        }
        expect(violations, "borrows for it", opened, lab.opens.get());
        expect(violations, "tasks submitted for it", submitted, lab.leases.submittedTasks());
        lab.releaseBorrows();
        if (!eventually(() -> lab.leases.availableSlots() == 4 && lab.leases.runningWorkers() == 0)) {
            violations.add("the late borrows must end and give every slot back, available " + lab.leases.availableSlots());
        }
        expectExecuted(violations, "a request once the borrows ended", Worker.start("dbac-cap4-after",
            () -> lab.gate.enter().run(request(user), new Context(), new Operation())));
        Assertions.assertEquals(List.of(), violations, "CAP-4");
    }

    // ---------------------------------------------------------------- CAP-5: a measurement

    /**
     * CAP-5: 1, 4, 8 and 16 concurrent requests, measured on this machine's H2 - recorded, not promised
     * <p>
     * Twice: with the borrows as fast as H2 gives them, and with every borrow taking 50 ms longer. Each line of
     * {@code DBAC_CAPACITY_MEASURE} records how many ran, how many were refused for want of a slot - at the
     * snapshot (PERMISSION_STORE_UNAVAILABLE) or at the allowed row (AUDIT_WRITE_FAILED) - the longest a request
     * took and how many connections were borrowed. Pinned is only what holds on any machine: every request
     * either runs or is refused for one of those two, none waits past its budgets, a request borrows at most
     * twice, and the four slots come back after each round.
     */
    @Test
    public void cap5ConcurrentRequestsAreMeasuredNotPromised() throws Exception {
        List<String> violations = new ArrayList<>();
        List<String> table = new ArrayList<>();
        DbAccessPolicyConfig config = config(DbAccessPolicyConfig.DEFAULT_SNAPSHOT_TIMEOUT);
        long bound = config.snapshotTimeout().toMillis() + config.auditTimeout().toMillis() + 2_000;
        for (long delay : new long[]{0, 50}) {
            Lab lab = lab(config);
            lab.borrowDelayMillis = delay;
            String user = grantedUser("cap5");
            for (int concurrent : new int[]{1, 4, 8, 16}) {
                String what = "delay " + delay + "ms, " + concurrent + " at once: ";
                int opened = lab.opens.get();
                long submitted = lab.leases.submittedTasks();
                CyclicBarrier start = new CyclicBarrier(concurrent);
                List<Worker<long[]>> requests = new ArrayList<>();
                for (int i = 0; i < concurrent; i++) {
                    requests.add(Worker.start("dbac-cap5-" + i, () -> {
                        start.await(WAIT_SECONDS, TimeUnit.SECONDS);
                        long begin = System.nanoTime();
                        EnforcementGate.Result<String> result = lab.gate.enter().run(request(user), new Context(), new Operation());
                        long millis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - begin);
                        DenialReason reason = reasonOf(result);
                        int kind = result instanceof EnforcementGate.Executed ? 0
                            : reason == DenialReason.PERMISSION_STORE_UNAVAILABLE ? 1
                            : reason == DenialReason.AUDIT_WRITE_FAILED ? 2 : 3;
                        return new long[]{kind, millis};
                    }));
                }
                int[] counts = new int[4];
                long longest = 0;
                for (Worker<long[]> request : requests) {
                    if (!request.awaitDone() || request.result == null) {
                        violations.add(what + "a request did not return: " + request.error);
                        continue;
                    }
                    counts[(int) request.result[0]]++;
                    longest = Math.max(longest, request.result[1]);
                }
                int borrows = lab.opens.get() - opened;
                long tasks = lab.leases.submittedTasks() - submitted;
                String line = "profile=H2+" + delay + "ms requests=" + concurrent + " executed=" + counts[0] + " psu=" + counts[1]
                    + " auditFailed=" + counts[2] + " other=" + counts[3] + " maxMillis=" + longest + " borrows=" + borrows
                    + " submitted=" + tasks;
                table.add(line);
                System.out.println("DBAC_CAPACITY_MEASURE " + line);
                expect(violations, what + "requests neither run nor refused for want of the store or its audit", 0, counts[3]);
                if (longest > bound) {
                    violations.add(what + "a request took " + longest + "ms, past T_s + T_audit + 2s = " + bound + "ms");
                }
                if (borrows > 2 * concurrent) {
                    violations.add(what + "more than two borrows a request: " + borrows);
                }
                if (!eventually(() -> lab.leases.availableSlots() == 4)) {
                    violations.add(what + "the slots must come back, available " + lab.leases.availableSlots());
                }
            }
        }
        System.out.println("DBAC_CAPACITY_TABLE\n" + String.join("\n", table));
        Assertions.assertEquals(List.of(), violations, "CAP-5");
    }

    // ---------------------------------------------------------------- the lab

    @NotNull
    private Lab lab(@NotNull DbAccessPolicyConfig config) throws Exception {
        Lab lab = new Lab(config);
        labs.add(lab);
        return lab;
    }

    /**
     * A lifecycle of its own over the server's H2, its gate, and a source that counts every borrow and can hold or slow it
     */
    private static final class Lab {
        final LifecycleTestSupport.Fixture lifecycle = new LifecycleTestSupport.Fixture();
        final AtomicInteger opens = new AtomicInteger();
        final AtomicInteger atGate = new AtomicInteger();
        final LifecycleTestSupport.TestFactory factory;
        final EnforcementGate gate;
        final BoundedMetadataConnections leases;
        @Nullable
        volatile CountDownLatch borrowGate;
        volatile long borrowDelayMillis;

        Lab(@NotNull DbAccessPolicyConfig config) throws Exception {
            DeploymentGuard.Admission admission = new DeploymentGuard.Admission() {
                @NotNull
                @Override
                public String deploymentMode() {
                    return DeploymentGuard.MODE_TEST;
                }

                @Override
                public boolean assertSingleProcess() {
                    return true;
                }
            };
            DbacSecurityControllerFactory.Admitter admitter = (database, revoke) ->
                new DeploymentGuard.Admitted(admission, lifecycle.lease);
            DbacSecurityControllerFactory.ServiceFactory services = database -> new DbAccessPolicyService(
                database.metadataLeases(), config, Clock.systemUTC(), System::nanoTime);
            this.factory = new LifecycleTestSupport.TestFactory(lifecycle,
                new DbacSecurityControllerFactory.LifecycleSeams(admitter, lifecycle.registrar, lifecycle.sink, services));
            factory.databaseMaker = (application, databaseConfig, shutdown) ->
                new SourcedDb(application, databaseConfig, shutdown, this::open);
            factory.init();
            PolicyServiceHolder holder = factory.holderForTest();
            PolicyServiceHolder.Ready ready = Assertions.assertInstanceOf(PolicyServiceHolder.Ready.class, holder.current(),
                "FIXTURE: the lifecycle must reach Ready");
            this.leases = Assertions.assertInstanceOf(BoundedMetadataConnections.class, ready.database().metadataLeases(),
                "FIXTURE: the metadata leases must be the bounded source");
            this.gate = EnforcementGate.of(holder, EnforcementGate.KeyLockSource.of(EnforcementKeyLocks.global()),
                TransactionTaintRegistry.isolated());
        }

        /** Every borrow from now on waits, the way a metadata pool waits for a connection, until released */
        void holdBorrows() {
            borrowGate = new CountDownLatch(1);
        }

        void releaseBorrows() {
            CountDownLatch held = borrowGate;
            borrowGate = null;
            if (held != null) {
                held.countDown();
            }
        }

        @NotNull
        Connection open() throws SQLException {
            opens.incrementAndGet();
            CountDownLatch held = borrowGate;
            if (held != null) {
                atGate.incrementAndGet();
                awaitUninterruptibly(held);
            }
            long delay = borrowDelayMillis;
            if (delay > 0) {
                sleepUninterruptibly(delay);
            }
            return h2().openConnection();
        }

        @NotNull
        List<Throwable> shutdown() {
            List<Throwable> thrown = new ArrayList<>();
            synchronized (factory.databases) {
                for (DbacCBDatabase database : factory.databases) {
                    Throwable failure = LifecycleTestSupport.shutdownCatching(database);
                    if (failure != null) {
                        thrown.add(failure);
                    }
                }
            }
            return thrown;
        }
    }

    private static void awaitUninterruptibly(@NotNull CountDownLatch latch) {
        boolean interrupted = false;
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(WAIT_SECONDS * 4);
        while (latch.getCount() > 0 && System.nanoTime() < deadline) {
            try {
                latch.await(100, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                interrupted = true;
            }
        }
        if (interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    private static void sleepUninterruptibly(long millis) {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(millis);
        boolean interrupted = false;
        while (System.nanoTime() < deadline) {
            try {
                Thread.sleep(Math.max(1, TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime())));
            } catch (InterruptedException e) {
                interrupted = true;
            }
        }
        if (interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * A metadata database that lends connections from the case's source and has no pool of its own; its schema is the server's
     */
    private static final class SourcedDb extends DbacCBDatabase {
        private final MetadataConnectionSource source;

        SourcedDb(
            @NotNull ServletApplication application,
            @NotNull WebDatabaseConfig config,
            @NotNull ShutdownLifecycle lifecycle,
            @NotNull MetadataConnectionSource source
        ) {
            super(application, config, DbacSchema.getSchemaConfigs(), lifecycle);
            this.source = source;
        }

        @Override
        public void initialize() {
            // the server's schema is installed already
        }

        @NotNull
        @Override
        public Connection openConnection() throws SQLException {
            return source.openConnection();
        }

        @Override
        protected void closeConnection() {
            // no pool of its own
        }
    }

    /** An operation with no transaction of its own that always confirms */
    private static final class Operation implements EnforcementGate.Execution<String> {
        final AtomicInteger executes = new AtomicInteger();

        @Override
        public boolean transactionActive() {
            return false;
        }

        @Nullable
        @Override
        public DenialReason confirm() {
            return null;
        }

        @Override
        public boolean rollback() {
            return true;
        }

        @Override
        public void sever() {
            // nothing to sever
        }

        @NotNull
        @Override
        public String execute() {
            executes.incrementAndGet();
            return "done";
        }
    }

    /** A context of its own for each request */
    private static final class Context implements EnforcementGate.ContextRef {
        private final long id = CONTEXT_IDS.incrementAndGet();
        private final Object identity = new Object();

        @Override
        public long contextId() {
            return id;
        }

        @NotNull
        @Override
        public Object identity() {
            return identity;
        }
    }

    /** A write lock held by a thread of its own until released */
    private static final class WriteHold implements AutoCloseable {
        private final CountDownLatch release = new CountDownLatch(1);
        private final Worker<Object> worker;

        private WriteHold(@NotNull Take take) throws InterruptedException {
            CountDownLatch held = new CountDownLatch(1);
            this.worker = Worker.start("dbac-cap-writer", () -> {
                try (EnforcementKeyLocks.Held ignored = take.take()) {
                    held.countDown();
                    release.await(WAIT_SECONDS * 2, TimeUnit.SECONDS);
                }
                return null;
            });
            Assertions.assertTrue(held.await(WAIT_SECONDS, TimeUnit.SECONDS), "FIXTURE: the write lock was not taken");
        }

        @FunctionalInterface
        private interface Take {
            @NotNull
            EnforcementKeyLocks.Held take();
        }

        @NotNull
        static WriteHold grant(@NotNull DbAccessKey key) throws InterruptedException {
            return new WriteHold(() -> EnforcementKeyLocks.global().lockGrantForWrite(key));
        }

        @NotNull
        static WriteHold user(@NotNull String userId) throws InterruptedException {
            return new WriteHold(() -> EnforcementKeyLocks.global().lockUserForWrite(userId));
        }

        void release() throws InterruptedException {
            release.countDown();
            Assertions.assertTrue(worker.awaitDone(), "FIXTURE: the writer did not finish");
        }

        @Override
        public void close() throws InterruptedException {
            release();
        }
    }

    // ---------------------------------------------------------------- fixtures

    @NotNull
    private static DbAccessPolicyConfig config(@NotNull Duration snapshotTimeout) {
        DbAccessPolicyConfig defaults = DbAccessPolicyConfig.defaults();
        return new DbAccessPolicyConfig(defaults.clockSkewThreshold(), defaults.maxGrantDuration(), defaults.expiryGuardMargin(),
            defaults.auditTimeout(), defaults.keyLockTimeout(), snapshotTimeout);
    }

    @NotNull
    private static WriteAuthorizationRequest request(@NotNull String user) {
        return WriteAuthorizationRequest.of(user, PolicyTestSupport.container(PROJECT, CONNECTION, HOST, DATABASE),
            DbOperationCategory.SQL_TEXT);
    }

    @NotNull
    private static String activeUser(@NotNull String tag) throws SQLException {
        String user = USER_PREFIX + tag + "-" + Long.toHexString(System.nanoTime()) + "-" + SEQUENCE.incrementAndGet();
        try (Connection connection = h2().openConnection()) {
            PolicyTestSupport.putUser(connection, user, true);
        }
        return user;
    }

    @NotNull
    private String grantedUser(@NotNull String tag) throws Exception {
        String user = activeUser(tag);
        grant(user);
        return user;
    }

    private void grant(@NotNull String user) throws Exception {
        TempWritePermissionKey key = new TempWritePermissionKey(user, PROJECT, CONNECTION);
        TempWriteMutationResult result = TempWriteMutationCoordinator.withoutAuditing(h2(), repository)
            .grant(TempWriteTestSupport.grantRequest(key, TempWriteGrant.NO_ROW_REVISION, GRANT, "capacity test"));
        Assertions.assertEquals(TempWriteMutationStatus.COMMITTED, result.status(), "FIXTURE: the grant must be committed");
    }

    @NotNull
    private List<Worker<EnforcementGate.Result<String>>> startRequests(@NotNull Lab lab, @NotNull String user, int count) {
        List<Worker<EnforcementGate.Result<String>>> started = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            started.add(Worker.start("dbac-cap-request-" + i, () -> lab.gate.enter().run(request(user), new Context(), new Operation())));
        }
        return started;
    }

    @Nullable
    private static DenialReason reasonOf(@Nullable EnforcementGate.Result<String> result) {
        return result instanceof EnforcementGate.Denied<String> denied ? denied.reason() : null;
    }

    private static void expectExecuted(
        @NotNull List<String> violations,
        @NotNull String what,
        @NotNull Worker<EnforcementGate.Result<String>> request
    ) throws InterruptedException {
        if (!request.awaitDone()) {
            violations.add(what + ": the request did not return");
        } else if (!(request.result instanceof EnforcementGate.Executed<String>)) {
            violations.add(what + ": expected to run, got " + (request.error != null ? request.error : reasonOf(request.result)));
        }
    }

    private static void expect(@NotNull List<String> violations, @NotNull String what, @Nullable Object expected, @Nullable Object actual) {
        if (!java.util.Objects.equals(expected, actual)) {
            violations.add(what + ": expected " + expected + ", got " + actual);
        }
    }

    private static boolean eventually(@NotNull BooleanSupplier condition) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(WAIT_SECONDS);
        while (System.nanoTime() < deadline) {
            if (condition.getAsBoolean()) {
                return true;
            }
            Thread.sleep(20);
        }
        return condition.getAsBoolean();
    }
}
