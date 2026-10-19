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
import io.cloudbeaver.service.dbac.policy.AuthorizationDecision;
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
import io.cloudbeaver.service.dbac.tempwrite.TempWritePermissionKey;
import io.cloudbeaver.service.security.EmbeddedSecurityControllerFactory;
import io.cloudbeaver.service.security.db.CBDatabase;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.jkiss.dbeaver.model.DBPDataSourceContainer;
import org.jkiss.dbeaver.model.app.DBPDataSourceRegistry;
import org.jkiss.dbeaver.model.app.DBPProject;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.LongSupplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * P5-4: the enforcement gate - one attempt decided, recorded, and run or refused, on a lifecycle of its own
 * <p>
 * Every case builds its own policy lifecycle through the production factory: a holder that reaches Ready,
 * an admission the test can make fail, and a policy service whose monotonic clock the test moves. Its
 * metadata database lends connections to a real database - the test server's H2, or a PostgreSQL schema
 * the real migration installed - through a watcher that journals every connection, every audit row and its
 * close. The key locks are the real shared ones, seen through a recording source; the taint registry is one
 * of the case's own, journaling each operation. The platform side - transaction state, rollback, sever,
 * confirmation and the operation - is a scripted execution. Every step therefore lands in one ordered
 * journal, and each case asserts on the order as well as on the outcome.
 * <p>
 * The production entry points are not wired; nothing here calls one.
 */
@Timeout(value = 300, unit = TimeUnit.SECONDS, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
public class EnforcementGateTest {

    private static final String PG_SCHEMA = "dbac_pg_gate";
    /** Every user these tests make starts with this, so their rows can be found and removed */
    private static final String USER_PREFIX = "dbac-gt-";
    private static final String PROJECT = "gt-project";
    private static final String OTHER_PROJECT = "gt-project-b";
    private static final String CONNECTION = "gt-connection";
    private static final String HOST = "db.internal.example";
    private static final String DATABASE = "customer_prod";
    private static final Duration GRANT = Duration.ofMinutes(30);
    private static final Duration WAIT = Duration.ofSeconds(30);
    private static final String DONE = "done";
    private static final String AUDIT_INSERT = "INSERT INTO {table_prefix}DBAC_AUDIT_EVENT";

    /** A lock wait this short makes every timeout case quick */
    private static final DbAccessPolicyConfig SHORT_WAIT = config(Duration.ofMillis(300));
    /** One long enough that a case can look at the gate while it waits */
    private static final DbAccessPolicyConfig LONG_WAIT = config(Duration.ofSeconds(20));

    private static final AtomicLong SEQUENCE = new AtomicLong();
    private static final AtomicLong CONTEXT_IDS = new AtomicLong(9_100_000L);
    private static boolean installed;

    private final List<Lab> labs = new ArrayList<>();
    private final TempWriteGrantRepository repository = new TempWriteGrantRepository();

    /** A metadata database the lifecycle reads permissions from and writes audit rows to */
    private record Engine(@NotNull String name, @NotNull MetadataConnectionSource source) {
    }

    @BeforeAll
    public static void prepare() throws Exception {
        CEAppStarter.startServerIfNotStarted();
        Assertions.assertNotNull(EmbeddedSecurityControllerFactory.getDbInstance(), "FIXTURE: the server metadata database must exist");
        EnforcementTestSupport.requirePostgres(KeyLockTestSupport.MONITOR);
        KeyLockTestSupport.installDbacSchema(PG_SCHEMA);
        try (Connection connection = KeyLockTestSupport.openPostgres(PG_SCHEMA)) {
            FenceTestSupport.installUserTables(connection);
        }
        installed = true;
    }

    @AfterAll
    public static void dropSchema() throws Exception {
        if (!installed) {
            return;
        }
        KeyLockTestSupport.dropSchema(PG_SCHEMA);
        Assertions.assertEquals(0, KeyLockTestSupport.countSchemas(PG_SCHEMA), "FIXTURE: the PostgreSQL schema was left behind");
    }

    @AfterEach
    public void cleanUp() throws Exception {
        List<Throwable> shutdowns = new ArrayList<>();
        for (Lab lab : labs) {
            shutdowns.addAll(lab.shutdown());
        }
        labs.clear();
        for (Engine engine : List.of(h2(), postgres())) {
            try (Connection connection = engine.source().openConnection()) {
                for (String table : List.of("DBAC_AUDIT_EVENT", "DBAC_TW_HISTORY", "DBAC_TW_CURRENT", "CB_USER", "CB_AUTH_SUBJECT")) {
                    String column = table.equals("CB_AUTH_SUBJECT") ? "SUBJECT_ID" : "USER_ID";
                    try (PreparedStatement dbStat = connection.prepareStatement(
                        "DELETE FROM {table_prefix}" + table + " WHERE " + column + " LIKE ?")) {
                        dbStat.setString(1, USER_PREFIX + "%");
                        dbStat.executeUpdate();
                    }
                }
            }
        }
        Assertions.assertEquals(List.of(), shutdowns.stream().map(t -> t.getClass().getName()).toList(),
            "FIXTURE: a lifecycle did not shut down cleanly");
    }

    @NotNull
    private static Engine h2() {
        CBDatabase database = EmbeddedSecurityControllerFactory.getDbInstance();
        return new Engine("H2", database::openConnection);
    }

    @NotNull
    private static Engine postgres() {
        return new Engine("PostgreSQL", () -> KeyLockTestSupport.openPostgres(PG_SCHEMA));
    }

    // ---------------------------------------------------------------- GT-1 - GT-3: locks

    /**
     * GT-1: while the gate waits for the grant key's lock, and then for the user's, no metadata connection is open
     * <p>
     * Another thread holds the grant key's write lock; the gate parks on its read. Not one metadata connection
     * may have been opened by then. The same with the user's write lock held. Once released, the attempt runs.
     */
    @Test
    public void gt1NoMetadataConnectionWhileWaitingForALock() throws Throwable {
        List<String> violations = new ArrayList<>();
        for (Engine engine : List.of(h2(), postgres())) {
            for (String which : List.of("grant", "user")) {
                String what = engine.name() + ", waiting for the " + which + " lock";
                Lab lab = lab(engine, LONG_WAIT);
                String user = grantedUser(engine, "gt1");
                DbAccessKey key = new DbAccessKey(user, PROJECT, CONNECTION);
                Context context = new Context();
                Script script = new Script(lab);
                try (WriteHolder held = which.equals("grant") ? WriteHolder.grant(key) : WriteHolder.user(user)) {
                    MetadataTestSupport.Pending<EnforcementGate.Result<String>> attempt = MetadataTestSupport.start(
                        "dbac-gt1", () -> lab.gate.enter().run(request(user), context, script));
                    if (!KeyLockTestSupport.awaitParked(attempt.thread())) {
                        violations.add(what + ": the gate must wait for the lock");
                    }
                    expect(violations, what + ": metadata connections opened while waiting", 0, lab.opens.get());
                    held.release();
                    expectExecuted(violations, what, attempt.await(WAIT));
                }
            }
        }
        Assertions.assertEquals(List.of(), violations, "GT-1");
    }

    /**
     * GT-2: the grant key's lock before the user's, and the user's released before the grant key's - on every way out
     * <p>
     * An attempt that runs, one refused by its decision, one refused by the taint registry, one refused after the
     * allowed row, one whose operation throws, and one whose user lock times out.
     */
    @Test
    public void gt2GrantLockFirstUserLockReleasedFirst() throws Throwable {
        final List<String> violations = new ArrayList<>();
        Lab lab = lab(h2(), SHORT_WAIT);
        String user = grantedUser(lab.engine, "gt2");
        String unknown = activeUser(lab.engine, "gt2-nogrant");

        Map<String, Lab.Run> runs = new TreeMap<>();
        runs.put("executed", lab.run(user, new Context(), script -> { }));
        runs.put("refused by the decision", lab.run(unknown, new Context(), script -> { }));
        Context tainted = new Context();
        lab.registry.markTainted(tainted.id, tainted.identity);
        runs.put("refused by the taint state", lab.run(user, tainted, script -> { }));
        runs.put("refused after the allowed row", lab.run(user, new Context(), script -> script.confirmation = DenialReason.GRANT_STALE));
        runs.put("the operation throws",
            lab.run(user, new Context(), script -> script.executeFails = new IllegalStateException("operation")));
        for (Map.Entry<String, Lab.Run> one : runs.entrySet()) {
            List<String> locks = one.getValue().events().stream().filter(e -> e.startsWith("K ") || e.startsWith("U ")).toList();
            expect(violations, one.getKey(), List.of("K wait", "K acquire", "U wait", "U acquire", "U release", "K release"), locks);
        }
        try (WriteHolder ignored = WriteHolder.user(user)) {
            Lab.Run timedOut = lab.run(user, new Context(), script -> { });
            List<String> locks = timedOut.events().stream().filter(e -> e.startsWith("K ") || e.startsWith("U ")).toList();
            expect(violations, "the user lock times out", List.of("K wait", "K acquire", "U wait", "U timeout", "K release"), locks);
        }
        Assertions.assertEquals(List.of(), violations, "GT-2");
    }

    /**
     * GT-3: a timeout, an interrupt, a RuntimeException or an Error - after each, both locks are free again
     * <p>
     * The grant key's lock and the user's time out; the gate is interrupted while it waits for either; the
     * window fails with a RuntimeException and with an Error. Each is {@code PERMISSION_STORE_UNAVAILABLE}, the
     * operation does not run, and another thread then takes both write locks at once. An interrupt that ended
     * the wait is set again when the attempt returns - and was not set while the rollback and the audit ran.
     */
    @Test
    public void gt3EveryWayOutReleasesBothLocks() throws Throwable {
        List<String> violations = new ArrayList<>();
        for (Engine engine : List.of(h2(), postgres())) {
            Lab lab = lab(engine, SHORT_WAIT);
            String user = grantedUser(engine, "gt3");
            DbAccessKey key = new DbAccessKey(user, PROJECT, CONNECTION);
            for (String which : List.of("grant", "user")) {
                String what = engine.name() + ", the " + which + " lock times out";
                try (WriteHolder ignored = which.equals("grant") ? WriteHolder.grant(key) : WriteHolder.user(user)) {
                    Lab.Run run = lab.run(user, new Context(), script -> script.active = true);
                    expectDenied(violations, what, run, DenialReason.PERMISSION_STORE_UNAVAILABLE);
                }
                expectLocksFree(violations, what, key);
            }
            for (Throwable failure : List.of(new LifecycleTestSupport.InjectedRuntimeException("window"),
                new LifecycleTestSupport.InjectedError("window"))) {
                String what = engine.name() + ", the window throws " + failure.getClass().getSimpleName();
                lab.clock.failOnRead(lab.clock.reads() + 1, failure);
                Lab.Run run = lab.run(user, new Context(), script -> { });
                expectDenied(violations, what, run, DenialReason.PERMISSION_STORE_UNAVAILABLE);
                expectLocksFree(violations, what, key);
            }
        }

        Lab lab = lab(h2(), LONG_WAIT);
        String user = grantedUser(lab.engine, "gt3-interrupt");
        DbAccessKey key = new DbAccessKey(user, PROJECT, CONNECTION);
        for (String which : List.of("grant", "user")) {
            String what = "interrupted while waiting for the " + which + " lock";
            Script script = new Script(lab);
            script.active = true;
            Context context = new Context();
            AtomicReference<Boolean> interruptedAfter = new AtomicReference<>();
            lab.mark(context);
            try (WriteHolder ignored = which.equals("grant") ? WriteHolder.grant(key) : WriteHolder.user(user)) {
                MetadataTestSupport.Pending<EnforcementGate.Result<String>> attempt = MetadataTestSupport.start("dbac-gt3", () -> {
                    EnforcementGate.Result<String> result = lab.gate.enter().run(request(user), context, script);
                    interruptedAfter.set(Thread.currentThread().isInterrupted());
                    return result;
                });
                if (!KeyLockTestSupport.awaitParked(attempt.thread())) {
                    violations.add(what + ": the gate must wait for the lock");
                }
                attempt.thread().interrupt();
                MetadataTestSupport.Outcome<EnforcementGate.Result<String>> outcome = attempt.await(WAIT);
                expectDeniedOutcome(violations, what, outcome, DenialReason.PERMISSION_STORE_UNAVAILABLE);
            }
            expect(violations, what + ": the interrupt is set again on return", Boolean.TRUE, interruptedAfter.get());
            expect(violations, what + ": the rollback ran without it", List.of("rollback interrupted=false"),
                script.events.stream().filter(e -> e.startsWith("rollback")).toList());
            expect(violations, what + ": the audit ran without it",
                List.of("audit WRITE_DENIED PERMISSION_STORE_UNAVAILABLE interrupted=false"),
                lab.audits(context));
            expectLocksFree(violations, what, key);
        }
        Assertions.assertEquals(List.of(), violations, "GT-3");
    }

    // ---------------------------------------------------------------- GT-4, GT-5: no execute without every check

    /**
     * GT-4: whatever the window throws - opening, check-1, check-2 - the attempt is refused and the operation does not run
     */
    @Test
    public void gt4AWindowFailureRefusesAndRunsNothing() throws Throwable {
        List<String> violations = new ArrayList<>();
        Lab lab = lab(h2(), SHORT_WAIT);
        String user = grantedUser(lab.engine, "gt4");
        for (Throwable failure : List.of(new LifecycleTestSupport.InjectedRuntimeException("clock"),
            new LifecycleTestSupport.InjectedError("clock"))) {
            String kind = failure.getClass().getSimpleName();
            lab.clock.failOnRead(lab.clock.reads() + 1, failure);
            expectDenied(violations, kind + " opening the window", lab.run(user, new Context(), s -> { }),
                DenialReason.PERMISSION_STORE_UNAVAILABLE);
            lab.clock.failOnRead(lab.clock.reads() + 2, failure);
            expectDenied(violations, kind + " at check-1", lab.run(user, new Context(), s -> { }),
                DenialReason.PERMISSION_STORE_UNAVAILABLE);
            lab.onAllowedClosed = () -> lab.clock.failOnRead(lab.clock.reads() + 1, failure);
            Context context = new Context();
            Lab.Run atCheckTwo = lab.run(user, context, s -> { });
            lab.onAllowedClosed = () -> { };
            expectDenied(violations, kind + " at check-2", atCheckTwo, DenialReason.PERMISSION_STORE_UNAVAILABLE);
            expect(violations, kind + " at check-2: the allowed row and its correction",
                List.of("audit WRITE_ALLOWED interrupted=false", "audit WRITE_DENIED PERMISSION_STORE_UNAVAILABLE interrupted=false"),
                lab.audits(context));
        }
        Assertions.assertEquals(List.of(), violations, "GT-4");
    }

    /**
     * GT-5: check-2 refusing, the confirmation refusing or failing, the policy service changing - the operation does not run
     * <p>
     * Each comes after the allowed row, so each leaves that row and a correcting denial for the same grant.
     */
    @Test
    public void gt5NoExecuteUnlessCheckTwoHolderAndConfirmationAllAgree() throws Throwable {
        List<String> violations = new ArrayList<>();
        Lab lab = lab(h2(), SHORT_WAIT);
        String user = grantedUser(lab.engine, "gt5");

        lab.onAllowedClosed = () -> lab.clock.advance(Duration.ofHours(1));
        Context expired = new Context();
        expectDenied(violations, "check-2 refuses", lab.run(user, expired, s -> { }), DenialReason.GRANT_EXPIRED);
        lab.onAllowedClosed = () -> { };
        expect(violations, "check-2 refuses: rows", List.of("audit WRITE_ALLOWED interrupted=false",
            "audit WRITE_DENIED GRANT_EXPIRED interrupted=false"), lab.audits(expired));

        Context stale = new Context();
        expectDenied(violations, "the confirmation refuses", lab.run(user, stale, s -> s.confirmation = DenialReason.GRANT_STALE),
            DenialReason.GRANT_STALE);
        expect(violations, "the confirmation refuses: rows", List.of("audit WRITE_ALLOWED interrupted=false",
            "audit WRITE_DENIED GRANT_STALE interrupted=false"), lab.audits(stale));

        for (Throwable failure : List.of(new LifecycleTestSupport.InjectedRuntimeException("confirm"),
            new LifecycleTestSupport.InjectedError("confirm"))) {
            String what = "the confirmation throws " + failure.getClass().getSimpleName();
            Context context = new Context();
            expectDenied(violations, what, lab.run(user, context, s -> s.confirmFails = failure),
                DenialReason.PERMISSION_STORE_UNAVAILABLE);
            expect(violations, what + ": rows", List.of("audit WRITE_ALLOWED interrupted=false",
                "audit WRITE_DENIED PERMISSION_STORE_UNAVAILABLE interrupted=false"), lab.audits(context));
        }

        Lab revoked = lab(h2(), SHORT_WAIT);
        revoked.onAllowedClosed = () -> revoked.revocation.get().revoke(PolicyServiceHolder.FailureCode.ADVISORY_LOCK_LOST);
        Context changed = new Context();
        Lab.Run run = revoked.run(user, changed, s -> { });
        expectDenied(violations, "the policy service changes before the operation", run, DenialReason.PERMISSION_STORE_UNAVAILABLE);
        expect(violations, "the policy service changes: rows", List.of("audit WRITE_ALLOWED interrupted=false",
            "audit WRITE_DENIED PERMISSION_STORE_UNAVAILABLE interrupted=false"), revoked.audits(changed));
        expect(violations, "the policy service changes: confirmation asked", 0L,
            run.events().stream().filter(e -> e.equals("confirm")).count());
        Assertions.assertEquals(List.of(), violations, "GT-5");
    }

    // ---------------------------------------------------------------- GT-6 - GT-10: shape and static guards

    /**
     * GT-6: nothing public hands out an intermediate decision, a window, a budget or an audit result
     * <p>
     * The gate's public surface is {@code global()}, {@code of(...)} and {@code enter()}; an entry's is {@code run()};
     * the results are {@code Executed} and {@code Denied}, with private constructors. No public method of any gate
     * type returns or takes a decision, a window, a budget, an audit outcome, a writer, a key, a key resolution or
     * the policy service's state.
     */
    @Test
    public void gt6NoIntermediateDecisionIsPublic() {
        List<String> violations = new ArrayList<>();
        expect(violations, "gate methods", new TreeSet<>(List.of("enter()", "global()",
            "of(PolicyServiceHolder, KeyLockSource, TransactionTaintRegistry)")), publicMethods(EnforcementGate.class));
        expect(violations, "entry methods", new TreeSet<>(List.of("run(WriteAuthorizationRequest, ContextRef, Execution)")),
            publicMethods(EnforcementGate.Entry.class));
        expect(violations, "result kinds", List.of(EnforcementGate.Executed.class, EnforcementGate.Denied.class),
            Arrays.asList(EnforcementGate.Result.class.getPermittedSubclasses()));
        Set<Class<?>> forbidden = Set.of(AuthorizationDecision.class, DbAccessPolicyService.ExpiryWindow.class,
            io.cloudbeaver.service.dbac.policy.MetadataBudget.class, io.cloudbeaver.service.dbac.policy.enforcement.AuditOutcome.class,
            io.cloudbeaver.service.dbac.policy.enforcement.AccessAuditWriter.class, DbAccessKey.class,
            DbAccessPolicyService.KeyResolution.class, PolicyServiceHolder.Ready.class, DbAccessPolicyService.class);
        List<Class<?>> types = new ArrayList<>(List.of(EnforcementGate.class));
        types.addAll(Arrays.asList(EnforcementGate.class.getDeclaredClasses()));
        for (Class<?> type : types) {
            for (Method method : type.getDeclaredMethods()) {
                if (!Modifier.isPublic(method.getModifiers()) || type == EnforcementGate.KeyLockSource.class) {
                    continue;
                }
                List<Class<?>> mentioned = new ArrayList<>(List.of(method.getParameterTypes()));
                mentioned.add(method.getReturnType());
                for (Class<?> one : mentioned) {
                    if (forbidden.contains(one)) {
                        violations.add(type.getSimpleName() + "." + method.getName() + " exposes " + one.getSimpleName());
                    }
                }
            }
            for (Constructor<?> constructor : type.getDeclaredConstructors()) {
                if (Modifier.isPublic(constructor.getModifiers()) || Modifier.isProtected(constructor.getModifiers())) {
                    violations.add(type.getSimpleName() + " has a constructor that is not private: " + constructor);
                }
            }
            for (Field field : type.getDeclaredFields()) {
                if (Modifier.isPublic(field.getModifiers()) && !field.isEnumConstant()) {
                    violations.add(type.getSimpleName() + " has a public field " + field.getName());
                }
            }
        }
        Assertions.assertEquals(List.of(), violations, "GT-6");
    }

    /**
     * GT-7: an entry runs once, on the thread that entered - a second run, another thread or a reuse after a failure is refused
     * <p>
     * A refused call does nothing: no transaction question, no rollback, no lock, no row.
     */
    @Test
    public void gt7AnEntryRunsOnceOnItsOwnThread() throws Throwable {
        List<String> violations = new ArrayList<>();
        Lab lab = lab(h2(), SHORT_WAIT);
        String user = grantedUser(lab.engine, "gt7");

        EnforcementGate.Entry entry = lab.gate.enter();
        Script first = new Script(lab);
        expectExecutedResult(violations, "the first run", entry.run(request(user), new Context(), first));
        Script second = new Script(lab);
        expectRefusedCall(violations, "a second run", () -> entry.run(request(user), new Context(), second), second);

        EnforcementGate.Entry foreign = lab.gate.enter();
        Script elsewhere = new Script(lab);
        MetadataTestSupport.Outcome<EnforcementGate.Result<String>> other =
            MetadataTestSupport.within(WAIT, () -> foreign.run(request(user), new Context(), elsewhere));
        if (!(other.thrown() instanceof IllegalStateException)) {
            violations.add("a run on another thread must be refused, got " + other.value() + " / " + other.thrown());
        }
        expect(violations, "a run on another thread: what it did", List.of(), elsewhere.events);
        expectExecutedResult(violations, "the owner may still run it", foreign.run(request(user), new Context(), new Script(lab)));

        EnforcementGate.Entry failed = lab.gate.enter();
        Script throwing = new Script(lab);
        throwing.executeFails = new IllegalStateException("operation");
        try {
            failed.run(request(user), new Context(), throwing);
            violations.add("the operation's exception must reach the caller");
        } catch (IllegalStateException expected) {
            // the operation's own exception
        }
        Script reuse = new Script(lab);
        expectRefusedCall(violations, "a reuse after a failure", () -> failed.run(request(user), new Context(), reuse), reuse);

        lab.admission.answer = false;
        EnforcementGate.Entry preliminary = lab.gate.enter();
        lab.admission.answer = true;
        expectDeniedResult(violations, "a preliminary denial", preliminary.run(request(user), new Context(), new Script(lab)),
            DenialReason.PERMISSION_STORE_UNAVAILABLE);
        Script again = new Script(lab);
        expectRefusedCall(violations, "a preliminary denial run again", () -> preliminary.run(request(user), new Context(), again), again);
        Assertions.assertEquals(List.of(), violations, "GT-7");
    }

    /**
     * GT-8: the production policy service measures the expiry window with {@code System.nanoTime}
     * <p>
     * Every production construction of the service is the two-argument one, which takes the system clocks; and the
     * server's own service, as it runs, reads a monotonic clock that agrees with {@code System.nanoTime()}.
     */
    @Test
    public void gt8TheProductionServiceUsesNanoTime() throws Throwable {
        List<String> violations = new ArrayList<>();
        String twoArgument = "(Lio/cloudbeaver/service/dbac/policy/MetadataLeaseSource;"
            + "Lio/cloudbeaver/service/dbac/policy/DbAccessPolicyConfig;)V";
        Set<String> constructions = new TreeSet<>();
        for (ClassFile one : productionClasses()) {
            for (String ref : one.methodRefs) {
                if (ref.startsWith("io/cloudbeaver/service/dbac/policy/DbAccessPolicyService#<init>#")
                    && !one.name.startsWith("io/cloudbeaver/service/dbac/policy/DbAccessPolicyService")
                ) {
                    constructions.add(one.name + " " + ref.substring(ref.lastIndexOf('#') + 1));
                }
            }
        }
        if (constructions.isEmpty() || !constructions.stream().allMatch(c -> c.endsWith(twoArgument))) {
            violations.add("production must build the service only with the two-argument constructor, found " + constructions);
        }
        PolicyServiceHolder.State state = PolicyServiceHolder.global().current();
        if (!(state instanceof PolicyServiceHolder.Ready ready)) {
            violations.add("FIXTURE: the server's policy service must be ready, it is " + state);
        } else {
            Field field = DbAccessPolicyService.class.getDeclaredField("monotonicClock");
            field.setAccessible(true);
            LongSupplier clock = (LongSupplier) field.get(ready.service());
            long before = System.nanoTime();
            long read = clock.getAsLong();
            long after = System.nanoTime();
            if (read < before || read > after) {
                violations.add("the server's monotonic clock must be System.nanoTime(), read " + read
                    + " between " + before + " and " + after);
            }
        }
        Assertions.assertEquals(List.of(), violations, "GT-8");
    }

    /**
     * GT-9: in production only the gate decides and records, and only the transaction adapter enters it
     * <p>
     * Read from the bytecode of every server bundle. {@code authorize}, {@code openExpiryWindow},
     * {@code resolveKey} and the window's steps are called by the gate alone (and by the service delegating to its
     * own window); the audit writer is made and called by the gate alone; the taint registry's state and the gate's
     * own rollback are read and recorded by the gate alone, its marks by the gate and the transaction adapter
     * {@code DbacEnforcedExecution} - after the platform was called or for an explicit rollback - and the release
     * after an explicit rollback by that adapter alone; no production class makes a registry of its own. The gate
     * is made by nothing outside it, and called from outside only by the adapter, and only through
     * {@code global()}, {@code enter()}, {@code run()} and the two results - never {@code of(...)}. The adapter does
     * call all three, and the transaction entry points reach DBAC through the adapter alone. The adapter refers to
     * no decision, window, budget, writer, holder, key lock or deployment type.
     */
    @Test
    public void gt9OnlyTheGateDecidesRecordsAndMarks() throws Throwable {
        String service = "io/cloudbeaver/service/dbac/policy/DbAccessPolicyService";
        String window = service + "$ExpiryWindow";
        String writer = "io/cloudbeaver/service/dbac/policy/enforcement/AccessAuditWriter";
        String registry = "io/cloudbeaver/service/dbac/policy/enforcement/TransactionTaintRegistry";
        String gate = "io/cloudbeaver/service/dbac/policy/enforcement/EnforcementGate";
        String adapter = "io/cloudbeaver/service/sql/DbacEnforcedExecution";
        String entryPoints = "io/cloudbeaver/service/sql/WebSQLContextInfo";
        record Guard(String name, Set<String> targets, Set<String> allowedCallers) {
        }

        // What the adapter may call of the gate; anything else of the gate, from anywhere outside it, is a violation
        Set<String> adapterEntry = Set.of(gate + "#global", gate + "#enter", gate + "$Entry#run", gate + "$Denied#reason",
            gate + "$Executed#value");

        List<Guard> guards = List.of(
            new Guard("decisions", Set.of(service + "#authorize", service + "#openExpiryWindow", service + "#resolveKey",
                window + "#authorize", window + "#requireMarginBeforeAudit", window + "#claimAuditBudget",
                window + "#requireMarginBeforeExecute"), Set.of(gate, service)),
            new Guard("audit writer", Set.of(writer + "#<init>", writer + "#recordAllowedBeforeExecution", writer + "#recordDenied"),
                Set.of(gate, writer)),
            new Guard("taint state", Set.of(registry + "#state", registry + "#rollbackSucceeded"), Set.of(gate, registry)),
            new Guard("taint marks", Set.of(registry + "#markTainted", registry + "#markBlocked"), Set.of(gate, registry, adapter)),
            new Guard("explicit release", Set.of(registry + "#releaseAfterExplicitRollback"), Set.of(registry, adapter)),
            new Guard("registries of their own", Set.of(registry + "#isolated", registry + "#<init>"), Set.of(registry)),
            new Guard("the gate", Set.of(gate + "#*"), Set.of(gate)));
        List<String> violations = new ArrayList<>();
        int scanned = 0;
        Set<String> adapterCalls = new TreeSet<>();
        Set<String> entryPointCalls = new TreeSet<>();
        for (ClassFile one : productionClasses()) {
            scanned++;
            boolean isAdapter = ownerIs(one.name, adapter);
            for (Guard guard : guards) {
                if (guard.allowedCallers().stream().anyMatch(allowed -> ownerIs(one.name, allowed))) {
                    continue;
                }
                for (String ref : one.methodRefs) {
                    String target = ref.substring(0, ref.lastIndexOf('#'));
                    String owner = target.substring(0, target.indexOf('#'));
                    boolean hit = guard.targets().contains(target) || guard.targets().stream()
                        .anyMatch(wanted -> wanted.endsWith("#*") && ownerIs(owner, wanted.substring(0, wanted.length() - 2)));
                    if (hit && !(isAdapter && adapterEntry.contains(target))) {
                        violations.add(guard.name() + ": " + one.name + " calls " + target);
                    }
                }
            }
            for (String ref : one.methodRefs) {
                String target = ref.substring(0, ref.lastIndexOf('#'));
                if (isAdapter) {
                    adapterCalls.add(target);
                }
                if (ownerIs(one.name, entryPoints)) {
                    entryPointCalls.add(target);
                }
            }
            if (isAdapter) {
                for (String referenced : one.classRefs) {
                    for (String forbidden : List.of("AuthorizationDecision", "DbAccessPolicyService", "MetadataBudget",
                        "AccessAuditWriter", "PolicyServiceHolder", "EnforcementKeyLocks", "DeploymentGuard", "MetadataLease")) {
                        if (referenced.endsWith("/" + forbidden) || referenced.contains("/" + forbidden + "$")) {
                            violations.add("the adapter's surface: " + one.name + " refers to " + referenced);
                        }
                    }
                }
            }
            if (ownerIs(one.name, entryPoints)) {
                for (String referenced : one.classRefs) {
                    if (referenced.startsWith("io/cloudbeaver/service/dbac/")) {
                        violations.add("the entry points: " + one.name + " refers to " + referenced + " other than through the adapter");
                    }
                }
            }
        }
        for (String needed : List.of(gate + "#global", gate + "#enter", gate + "$Entry#run", registry + "#markBlocked",
            registry + "#releaseAfterExplicitRollback")) {
            if (!adapterCalls.contains(needed)) {
                violations.add("the adapter must call " + needed);
            }
        }
        for (String needed : List.of(adapter + "#commit", adapter + "#autoCommitOn", adapter + "#rollback")) {
            if (!entryPointCalls.contains(needed)) {
                violations.add("the entry points must call " + needed);
            }
        }
        Assertions.assertTrue(scanned > 100, "FIXTURE GT-9: the server bundles' classes must be found, found " + scanned);
        Assertions.assertEquals(List.of(), violations, "GT-9");
    }

    /**
     * GT-10: the gate reaches no platform execution, JDBC, coordinator or controller type, in its bytecode or its imports
     */
    @Test
    public void gt10TheGateReachesNoPlatformOrWriterType() throws Throwable {
        List<String> violations = new ArrayList<>();
        for (ClassFile one : productionClasses()) {
            if (!one.name.equals("io/cloudbeaver/service/dbac/policy/enforcement/EnforcementGate")
                && !one.name.startsWith("io/cloudbeaver/service/dbac/policy/enforcement/EnforcementGate$")
            ) {
                continue;
            }
            for (String referenced : one.classRefs) {
                if (!allowedGateReference(referenced)) {
                    violations.add(one.name + " refers to " + referenced);
                }
            }
        }
        Path source = MetadataShutdownTest.dbacSourceRoot().resolve("io/cloudbeaver/service/dbac/policy/enforcement/EnforcementGate.java");
        for (String line : Files.readAllLines(source, StandardCharsets.UTF_8)) {
            String trimmed = line.trim();
            if (trimmed.startsWith("import ")) {
                String imported = trimmed.substring("import ".length()).replace(";", "").trim();
                if (imported.startsWith("static ") || !allowedGateReference(imported.replace('.', '/'))) {
                    violations.add("EnforcementGate.java imports " + imported);
                }
            }
        }
        Assertions.assertEquals(List.of(), violations, "GT-10");
    }

    // ---------------------------------------------------------------- GT-11, GT-12: keys

    /**
     * GT-11: a decision about any key but the locked one is refused - an identity that changed under the lock
     * <p>
     * The container reports one project while the key is resolved and locked, another when the decision is made.
     * With a grant under the other key the decision would allow, without one it would deny; either way the attempt
     * is {@code PERMISSION_STORE_UNAVAILABLE}, the operation does not run, and the denial is recorded for the locked
     * key.
     */
    @Test
    public void gt11ADecisionAboutAnotherKeyIsRefused() throws Throwable {
        List<String> violations = new ArrayList<>();
        Lab lab = lab(h2(), SHORT_WAIT);
        String granted = grantedUser(lab.engine, "gt11");
        grant(lab.engine, granted, OTHER_PROJECT);
        String onlyHere = grantedUser(lab.engine, "gt11-one");
        for (String user : List.of(granted, onlyHere)) {
            String what = user.equals(granted) ? "the other key is granted too" : "the other key has no grant";
            Drifting drifting = new Drifting();
            lab.locks.afterUser = () -> drifting.projectId.set(OTHER_PROJECT);
            Context context = new Context();
            Script script = new Script(lab);
            EnforcementGate.Result<String> result = lab.gate.enter().run(
                WriteAuthorizationRequest.of(user, drifting.container, DbOperationCategory.SQL_TEXT), context, script);
            lab.locks.afterUser = () -> { };
            expectDeniedResult(violations, what, result, DenialReason.PERMISSION_STORE_UNAVAILABLE);
            expect(violations, what + ": executes", 0, script.executes.get());
            expect(violations, what + ": the denial, for the locked key",
                List.of("WRITE_DENIED DENY PERMISSION_STORE_UNAVAILABLE " + PROJECT), rows(lab.engine, user).stream()
                    .map(row -> row.type() + " " + row.decision() + " " + row.reason() + " " + row.project()).toList());
        }
        Assertions.assertEquals(List.of(), violations, "GT-11");
    }

    /**
     * GT-12: a request with no key - no identity, no container, a category the gate does not run - takes no lock and leaves no row
     */
    @Test
    public void gt12NoKeyNoLockNoRow() throws Throwable {
        List<String> violations = new ArrayList<>();
        Lab lab = lab(h2(), SHORT_WAIT);
        String user = grantedUser(lab.engine, "gt12");
        record Case(String name, WriteAuthorizationRequest request, DenialReason reason) {
        }

        for (Case one : List.of(
            new Case("no identity", WriteAuthorizationRequest.of(null, container(), DbOperationCategory.SQL_TEXT),
                DenialReason.IDENTITY_MISSING),
            new Case("no container", WriteAuthorizationRequest.of(user, null, DbOperationCategory.SQL_TEXT),
                DenialReason.CONNECTION_UNKNOWN),
            new Case("a read", WriteAuthorizationRequest.of(user, container(), DbOperationCategory.CONTAINER_READ),
                DenialReason.OPERATION_UNSUPPORTED),
            new Case("a rollback", WriteAuthorizationRequest.of(user, container(), DbOperationCategory.TRANSACTION_ROLLBACK),
                DenialReason.OPERATION_UNSUPPORTED))
        ) {
            lab.events.clear();
            int opens = lab.opens.get();
            Script script = new Script(lab);
            EnforcementGate.Result<String> result = lab.gate.enter().run(one.request(), new Context(), script);
            expectDeniedResult(violations, one.name(), result, one.reason());
            expect(violations, one.name() + ": locks", List.of(),
                lab.events.stream().filter(e -> e.startsWith("K ") || e.startsWith("U ")).toList());
            expect(violations, one.name() + ": metadata connections", opens, lab.opens.get());
        }
        expect(violations, "rows", List.of(), rows(lab.engine, user));
        Assertions.assertEquals(List.of(), violations, "GT-12");
    }

    // ---------------------------------------------------------------- GT-13 - GT-22: the common way out

    /**
     * GT-13: a refused attempt with an open transaction is marked tainted, rolled back and then clean - or blocked
     * <p>
     * The decision denies ({@code NO_GRANT}). While the rollback runs the context is {@code TAINTED}; after one that
     * worked it is clean again, after one that did not it is severed and {@code BLOCKED}. The reason stays the
     * decision's either way.
     */
    @Test
    public void gt13ARefusalRollsBackAndRecordsTheOutcome() throws Throwable {
        List<String> violations = new ArrayList<>();
        for (Engine engine : List.of(h2(), postgres())) {
            Lab lab = lab(engine, SHORT_WAIT);
            String user = activeUser(engine, "gt13");
            for (boolean works : new boolean[]{true, false}) {
                String what = engine.name() + ", rollback " + (works ? "works" : "fails");
                Context context = new Context();
                AtomicReference<Object> during = new AtomicReference<>();
                Lab.Run run = lab.run(user, context, script -> {
                    script.active = true;
                    script.rollbackWorks = works;
                    script.onRollback = () -> during.set(stateOf(lab, context));
                });
                expectDenied(violations, what, run, DenialReason.NO_GRANT);
                expect(violations, what + ": state during the rollback", TransactionTaintRegistry.State.TAINTED, during.get());
                expect(violations, what + ": state after",
                    works ? TransactionTaintRegistry.State.CLEAN : TransactionTaintRegistry.State.BLOCKED, stateOf(lab, context));
                expect(violations, what + ": severed", works ? 0 : 1, run.script().severs.get());
                expect(violations, what + ": the denial", List.of("audit WRITE_DENIED NO_GRANT interrupted=false"), lab.audits(context));
            }
        }
        Assertions.assertEquals(List.of(), violations, "GT-13");
    }

    /**
     * GT-14: a context already tainted or blocked is refused for that, before anything is decided
     * <p>
     * No snapshot is read: the only metadata statement is the denial's own row.
     */
    @Test
    public void gt14ATaintedOrBlockedContextIsRefusedBeforeAnyDecision() throws Throwable {
        List<String> violations = new ArrayList<>();
        Lab lab = lab(h2(), SHORT_WAIT);
        String user = grantedUser(lab.engine, "gt14");
        for (TransactionTaintRegistry.State state
            : List.of(TransactionTaintRegistry.State.TAINTED, TransactionTaintRegistry.State.BLOCKED)
        ) {
            Context context = new Context();
            if (state == TransactionTaintRegistry.State.TAINTED) {
                lab.registry.markTainted(context.id, context.identity);
            } else {
                lab.registry.markBlocked(context.id, context.identity);
            }
            lab.events.clear();
            Lab.Run run = lab.run(user, context, script -> { });
            DenialReason expected = state == TransactionTaintRegistry.State.TAINTED
                ? DenialReason.TRANSACTION_TAINTED : DenialReason.CONNECTION_BLOCKED;
            expectDenied(violations, state.name(), run, expected);
            expect(violations, state + ": statements other than the denial's row", List.of(),
                lab.events.stream().filter(e -> e.startsWith("statement")).toList());
            expect(violations, state + ": the denial", List.of("audit WRITE_DENIED " + expected + " interrupted=false"),
                lab.audits(context));
        }
        Assertions.assertEquals(List.of(), violations, "GT-14");
    }

    /**
     * GT-15: a key that cannot be resolved, with a transaction open, is still rolled back - and nothing runs
     */
    @Test
    public void gt15AKeyFailureStillRollsBack() throws Throwable {
        List<String> violations = new ArrayList<>();
        Lab lab = lab(h2(), SHORT_WAIT);
        Context context = new Context();
        Lab.Run run = lab.run(WriteAuthorizationRequest.of(null, container(), DbOperationCategory.SQL_TEXT), context,
            script -> script.active = true);
        expectDenied(violations, "no identity", run, DenialReason.IDENTITY_MISSING);
        expect(violations, "rollbacks", 1, run.script().rollbacks.get());
        expect(violations, "state after", TransactionTaintRegistry.State.CLEAN, stateOf(lab, context));
        Assertions.assertEquals(List.of(), violations, "GT-15");
    }

    /**
     * GT-16: a grant key lock that times out, with a transaction open, is rolled back and recorded as refused
     */
    @Test
    public void gt16AGrantLockTimeoutRollsBack() throws Throwable {
        List<String> violations = new ArrayList<>();
        for (Engine engine : List.of(h2(), postgres())) {
            Lab lab = lab(engine, SHORT_WAIT);
            String user = grantedUser(engine, "gt16");
            Context context = new Context();
            Lab.Run run;
            try (WriteHolder ignored = WriteHolder.grant(new DbAccessKey(user, PROJECT, CONNECTION))) {
                run = lab.run(user, context, script -> script.active = true);
            }
            expectDenied(violations, engine.name(), run, DenialReason.PERMISSION_STORE_UNAVAILABLE);
            expectWithinTk(violations, engine.name(), run);
            expect(violations, engine.name() + ": rollbacks", 1, run.script().rollbacks.get());
            expect(violations, engine.name() + ": user lock asked", List.of(),
                run.events().stream().filter(e -> e.startsWith("U ")).toList());
            expect(violations, engine.name() + ": the denial", List.of("audit WRITE_DENIED PERMISSION_STORE_UNAVAILABLE interrupted=false"),
                lab.audits(context));
        }
        Assertions.assertEquals(List.of(), violations, "GT-16");
    }

    /**
     * GT-17: a user lock that times out, with a transaction open, is rolled back - and the grant key's lock is released
     */
    @Test
    public void gt17AUserLockTimeoutRollsBack() throws Throwable {
        List<String> violations = new ArrayList<>();
        Lab lab = lab(h2(), SHORT_WAIT);
        String user = grantedUser(lab.engine, "gt17");
        final DbAccessKey key = new DbAccessKey(user, PROJECT, CONNECTION);
        Context context = new Context();
        Lab.Run run;
        try (WriteHolder ignored = WriteHolder.user(user)) {
            run = lab.run(user, context, script -> script.active = true);
        }
        expectDenied(violations, "user lock timeout", run, DenialReason.PERMISSION_STORE_UNAVAILABLE);
        expectWithinTk(violations, "user lock timeout", run);
        expect(violations, "rollbacks", 1, run.script().rollbacks.get());
        expect(violations, "the denial", List.of("audit WRITE_DENIED PERMISSION_STORE_UNAVAILABLE interrupted=false"), lab.audits(context));
        expectLocksFree(violations, "user lock timeout", key);
        Assertions.assertEquals(List.of(), violations, "GT-17");
    }

    /**
     * GT-18: a rollback that fails or throws - after a key failure, a grant lock timeout or a user lock timeout - is severed and blocked
     * <p>
     * A sever that throws is logged and the context is still blocked. The reason stays the original one.
     */
    @Test
    public void gt18AFailedRollbackSeversAndBlocks() throws Throwable {
        List<String> violations = new ArrayList<>();
        Lab lab = lab(h2(), SHORT_WAIT);
        String user = grantedUser(lab.engine, "gt18");
        DbAccessKey key = new DbAccessKey(user, PROJECT, CONNECTION);
        record Failure(String name, boolean returnsFalse, @Nullable Throwable thrown, @Nullable Throwable severFails) {
        }

        List<Failure> failures = List.of(
            new Failure("returns false", true, null, null),
            new Failure("throws a RuntimeException", false, new LifecycleTestSupport.InjectedRuntimeException("rollback"), null),
            new Failure("throws an Error", false, new LifecycleTestSupport.InjectedError("rollback"), null),
            new Failure("returns false and the sever throws", true, null, new LifecycleTestSupport.InjectedRuntimeException("sever")));
        for (String path : List.of("key failure", "grant lock timeout", "user lock timeout")) {
            for (Failure failure : failures) {
                String what = path + ", rollback " + failure.name();
                Context context = new Context();
                WriteAuthorizationRequest request = path.equals("key failure")
                    ? WriteAuthorizationRequest.of(null, container(), DbOperationCategory.SQL_TEXT) : request(user);
                Lab.Run run;
                try (WriteHolder ignored = path.equals("grant lock timeout") ? WriteHolder.grant(key)
                    : path.equals("user lock timeout") ? WriteHolder.user(user) : WriteHolder.none()) {
                    run = lab.run(request, context, script -> {
                        script.active = true;
                        script.rollbackWorks = !failure.returnsFalse();
                        script.rollbackFails = failure.thrown();
                        script.severFails = failure.severFails();
                    });
                }
                expectDenied(violations, what, run, path.equals("key failure")
                    ? DenialReason.IDENTITY_MISSING : DenialReason.PERMISSION_STORE_UNAVAILABLE);
                expect(violations, what + ": severs", 1, run.script().severs.get());
                expect(violations, what + ": state", TransactionTaintRegistry.State.BLOCKED, stateOf(lab, context));
            }
        }
        Assertions.assertEquals(List.of(), violations, "GT-18");
    }

    /**
     * GT-19: a refusal without a key leaves no audit row, and still rolls back exactly once
     */
    @Test
    public void gt19NoKeyNoRowButOneRollback() throws Throwable {
        List<String> violations = new ArrayList<>();
        Lab lab = lab(h2(), SHORT_WAIT);
        String user = activeUser(lab.engine, "gt19");
        for (WriteAuthorizationRequest request : List.of(
            WriteAuthorizationRequest.of(null, container(), DbOperationCategory.SQL_TEXT),
            WriteAuthorizationRequest.of(user, null, DbOperationCategory.SQL_TEXT),
            WriteAuthorizationRequest.of(user, container(), DbOperationCategory.CONTAINER_READ))
        ) {
            lab.events.clear();
            Lab.Run run = lab.run(request, new Context(), script -> script.active = true);
            expect(violations, request + ": rollbacks", 1, run.script().rollbacks.get());
            expect(violations, request + ": audit rows", List.of(), lab.events.stream().filter(e -> e.startsWith("audit")).toList());
        }
        expect(violations, "rows", List.of(), rows(lab.engine, user));
        Assertions.assertEquals(List.of(), violations, "GT-19");
    }

    /**
     * GT-20: a transaction question that throws - a RuntimeException or an Error - counts as an open transaction
     */
    @Test
    public void gt20AFailingTransactionQuestionMeansRollBack() throws Throwable {
        List<String> violations = new ArrayList<>();
        Lab lab = lab(h2(), SHORT_WAIT);
        String user = activeUser(lab.engine, "gt20");
        for (Throwable failure : List.of(new LifecycleTestSupport.InjectedRuntimeException("transactionActive"),
            new LifecycleTestSupport.InjectedError("transactionActive"))) {
            Lab.Run run = lab.run(user, new Context(), script -> script.activeFails = failure);
            expectDenied(violations, failure.getClass().getSimpleName(), run, DenialReason.NO_GRANT);
            expect(violations, failure.getClass().getSimpleName() + ": questions", 1, run.script().actives.get());
            expect(violations, failure.getClass().getSimpleName() + ": rollbacks", 1, run.script().rollbacks.get());
        }
        Assertions.assertEquals(List.of(), violations, "GT-20");
    }

    /**
     * GT-21: a blocked context stays blocked through a refusal whose rollback worked; only an explicit rollback releases it
     */
    @Test
    public void gt21ABlockedContextIsNeverReleasedByTheGate() throws Throwable {
        List<String> violations = new ArrayList<>();
        Lab lab = lab(h2(), SHORT_WAIT);
        String user = grantedUser(lab.engine, "gt21");
        Context context = new Context();
        lab.registry.markBlocked(context.id, context.identity);
        Lab.Run run = lab.run(user, context, script -> script.active = true);
        expectDenied(violations, "blocked", run, DenialReason.CONNECTION_BLOCKED);
        expect(violations, "rollbacks", 1, run.script().rollbacks.get());
        expect(violations, "state after the gate's rollback", TransactionTaintRegistry.State.BLOCKED, stateOf(lab, context));
        expect(violations, "a second attempt", DenialReason.CONNECTION_BLOCKED,
            reasonOf(lab.run(user, context, script -> script.active = true).result()));
        lab.registry.releaseAfterExplicitRollback(context.id, context.identity);
        expect(violations, "after the explicit rollback", TransactionTaintRegistry.State.CLEAN, stateOf(lab, context));
        expectExecuted(violations, "after the explicit rollback, an attempt", lab.run(user, context, script -> { }).outcome());
        Assertions.assertEquals(List.of(), violations, "GT-21");
    }

    /**
     * GT-22: on every refusal that records a row, the row comes after the rollback - and the taint mark before it
     * <p>
     * The journal of each refusal must read: the transaction question, the taint mark, the rollback, its outcome in
     * the registry, then the {@code WRITE_DENIED} row. Run for a grant lock timeout, a user lock timeout, a tainted
     * context, a denying decision, check-1, a failed allowed row, check-2, the policy service changing and the
     * confirmation - on H2 and PostgreSQL.
     */
    @Test
    public void gt22TheAuditRowComesAfterTheRollback() throws Throwable {
        List<String> violations = new ArrayList<>();
        for (Engine engine : List.of(h2(), postgres())) {
            Lab lab = lab(engine, SHORT_WAIT);
            String user = grantedUser(engine, "gt22");
            final String unknown = activeUser(engine, "gt22-nogrant");
            DbAccessKey key = new DbAccessKey(user, PROJECT, CONNECTION);
            Map<String, Lab.Run> runs = new TreeMap<>();
            try (WriteHolder ignored = WriteHolder.grant(key)) {
                runs.put("grant lock timeout", lab.run(user, new Context(), script -> script.active = true));
            }
            try (WriteHolder ignored = WriteHolder.user(user)) {
                runs.put("user lock timeout", lab.run(user, new Context(), script -> script.active = true));
            }
            Context tainted = new Context();
            lab.registry.markTainted(tainted.id, tainted.identity);
            runs.put("tainted", lab.run(user, tainted, script -> script.active = true));
            runs.put("decision", lab.run(unknown, new Context(), script -> script.active = true));
            lab.onSnapshotClosed = () -> lab.clock.advance(Duration.ofHours(1));
            runs.put("check-1", lab.run(user, new Context(), script -> script.active = true));
            lab.onSnapshotClosed = () -> { };
            lab.failAllowedInsert = true;
            runs.put("allowed row failed", lab.run(user, new Context(), script -> script.active = true));
            lab.failAllowedInsert = false;
            lab.onAllowedClosed = () -> lab.clock.advance(Duration.ofHours(1));
            runs.put("check-2", lab.run(user, new Context(), script -> script.active = true));
            lab.onAllowedClosed = () -> { };
            runs.put("confirmation", lab.run(user, new Context(), script -> {
                script.active = true;
                script.confirmation = DenialReason.GRANT_STALE;
            }));
            for (Map.Entry<String, Lab.Run> one : runs.entrySet()) {
                List<String> order = one.getValue().events().stream()
                    .filter(e -> e.equals("transactionActive") || e.startsWith("rollback") || e.startsWith("audit WRITE_DENIED")
                        || e.equals("registry MARK_TAINTED") || e.equals("registry ROLLBACK_SUCCEEDED"))
                    .map(e -> e.startsWith("audit WRITE_DENIED") ? "audit WRITE_DENIED" : e.startsWith("rollback") ? "rollback" : e)
                    .toList();
                expect(violations, engine.name() + ", " + one.getKey(), List.of("transactionActive", "registry MARK_TAINTED", "rollback",
                    "registry ROLLBACK_SUCCEEDED", "audit WRITE_DENIED"), order);
            }
            Lab revoked = lab(engine, SHORT_WAIT);
            revoked.onAllowedClosed = () -> revoked.revocation.get().revoke(PolicyServiceHolder.FailureCode.ADVISORY_LOCK_LOST);
            Lab.Run changed = revoked.run(user, new Context(), script -> script.active = true);
            List<String> order = changed.events().stream()
                .filter(e -> e.equals("transactionActive") || e.startsWith("rollback") || e.startsWith("audit WRITE_DENIED"))
                .map(e -> e.startsWith("audit WRITE_DENIED") ? "audit WRITE_DENIED" : e.startsWith("rollback") ? "rollback" : e).toList();
            expect(violations, engine.name() + ", the policy service changed",
                List.of("transactionActive", "rollback", "audit WRITE_DENIED"), order);
        }
        Assertions.assertEquals(List.of(), violations, "GT-22");
    }

    // ---------------------------------------------------------------- GT-23 - GT-33

    /**
     * GT-23: a refusal at {@code enter()} still rolls back when the caller runs the entry
     * <p>
     * The policy service not ready, the admission answering no, throwing a RuntimeException or an Error, and the
     * service changing during the admission: each entry's run asks about the transaction once, rolls it back -
     * severing and blocking when that fails - and refuses with {@code PERMISSION_STORE_UNAVAILABLE}, with no lock, no
     * metadata connection and no row.
     */
    @Test
    public void gt23APreliminaryRefusalStillRollsBack() throws Throwable {
        List<String> violations = new ArrayList<>();
        String user = grantedUser(h2(), "gt23");
        record Case(String name, java.util.function.Consumer<Lab> arrange) {
        }

        List<Case> cases = List.of(
            new Case("not ready", lab -> lab.revocation.get().revoke(PolicyServiceHolder.FailureCode.ADVISORY_LOCK_LOST)),
            new Case("the admission says no", lab -> lab.admission.answer = false),
            new Case("the admission throws a RuntimeException",
                lab -> lab.admission.fails = new LifecycleTestSupport.InjectedRuntimeException("admission")),
            new Case("the admission throws an Error", lab -> lab.admission.fails = new LifecycleTestSupport.InjectedError("admission")),
            new Case("the service changes during the admission",
                lab -> lab.admission.during = () -> lab.revocation.get().revoke(PolicyServiceHolder.FailureCode.ADVISORY_LOCK_LOST)));
        for (Case one : cases) {
            for (boolean works : new boolean[]{true, false}) {
                final String what = one.name() + ", rollback " + (works ? "works" : "fails");
                Lab lab = lab(h2(), SHORT_WAIT);
                one.arrange().accept(lab);
                final Context context = new Context();
                Script script = new Script(lab);
                script.active = true;
                script.rollbackWorks = works;
                EnforcementGate.Entry entry = lab.gate.enter();
                lab.events.clear();
                final int opens = lab.opens.get();
                expectDeniedResult(violations, what, entry.run(request(user), context, script), DenialReason.PERMISSION_STORE_UNAVAILABLE);
                expect(violations, what + ": rollbacks", 1, script.rollbacks.get());
                expect(violations, what + ": severs", works ? 0 : 1, script.severs.get());
                expect(violations, what + ": state", works ? TransactionTaintRegistry.State.CLEAN : TransactionTaintRegistry.State.BLOCKED,
                    stateOf(lab, context));
                expect(violations, what + ": locks and rows", List.of(), lab.events.stream()
                    .filter(e -> e.startsWith("K ") || e.startsWith("U ") || e.startsWith("audit")).toList());
                expect(violations, what + ": metadata connections", opens, lab.opens.get());
                expect(violations, what + ": executes", 0, script.executes.get());
            }
        }
        Assertions.assertEquals(List.of(), violations, "GT-23");
    }

    /**
     * GT-24: the operation runs once, only after its {@code WRITE_ALLOWED} row is committed and visible
     * <p>
     * Inside the operation another connection must already find the row. The journal reads: the allowed row, the
     * confirmation, the operation. On H2 and PostgreSQL.
     */
    @Test
    public void gt24TheOperationRunsOnlyAfterTheAllowedRowIsCommitted() throws Throwable {
        List<String> violations = new ArrayList<>();
        for (Engine engine : List.of(h2(), postgres())) {
            Lab lab = lab(engine, SHORT_WAIT);
            String user = grantedUser(engine, "gt24");
            AtomicReference<List<Row>> seen = new AtomicReference<>();
            Lab.Run run = lab.run(user, new Context(), script -> script.onExecute = () -> seen.set(rows(engine, user)));
            expectExecuted(violations, engine.name(), run.outcome());
            expect(violations, engine.name() + ": executes", 1, run.script().executes.get());
            expect(violations, engine.name() + ": rows another connection saw from inside the operation", List.of("WRITE_ALLOWED ALLOW"),
                seen.get() == null ? null : seen.get().stream().map(row -> row.type() + " " + row.decision()).toList());
            List<String> order = run.events().stream()
                .filter(e -> e.startsWith("audit") || e.equals("confirm") || e.equals("execute")).toList();
            expect(violations, engine.name() + ": order", List.of("audit WRITE_ALLOWED interrupted=false", "confirm", "execute"), order);
        }
        Assertions.assertEquals(List.of(), violations, "GT-24");
    }

    /**
     * GT-25: an allowed row that is not recorded stops the attempt - no check-2, no confirmation, no operation
     * <p>
     * The insert fails, or it commits only after the budget check-1 reserved has run out. Either is
     * {@code AUDIT_WRITE_FAILED}, the window's clock is not read again, and a correcting denial is written - beside
     * the late row, which exists.
     */
    @Test
    public void gt25AFailedAllowedRowStopsEverything() throws Throwable {
        List<String> violations = new ArrayList<>();
        Lab lab = lab(h2(), SHORT_WAIT);
        String user = grantedUser(lab.engine, "gt25");
        for (boolean late : new boolean[]{false, true}) {
            final String what = late ? "committed past the budget" : "the insert fails";
            if (late) {
                lab.beforeAllowedInsert = () -> lab.clock.advance(lab.config.auditTimeout().plusMillis(1));
            } else {
                lab.failAllowedInsert = true;
            }
            AtomicInteger readsAfter = new AtomicInteger(-1);
            lab.onAllowedClosed = () -> readsAfter.set(lab.clock.reads());
            Context context = new Context();
            final Lab.Run run = lab.run(user, context, script -> { });
            lab.beforeAllowedInsert = () -> { };
            lab.failAllowedInsert = false;
            lab.onAllowedClosed = () -> { };
            expectDenied(violations, what, run, DenialReason.AUDIT_WRITE_FAILED);
            expect(violations, what + ": clock reads after the allowed row", readsAfter.get(), lab.clock.reads());
            expect(violations, what + ": confirmations", 0, run.script().confirms.get());
            expect(violations, what + ": the correction", List.of("audit WRITE_ALLOWED interrupted=false",
                "audit WRITE_DENIED AUDIT_WRITE_FAILED interrupted=false"), lab.audits(context));
        }
        expect(violations, "rows", List.of("WRITE_ALLOWED ALLOW null", "WRITE_DENIED DENY AUDIT_WRITE_FAILED",
            "WRITE_DENIED DENY AUDIT_WRITE_FAILED"), rows(lab.engine, user).stream()
            .map(row -> row.type() + " " + row.decision() + " " + row.reason()).sorted().toList());
        Assertions.assertEquals(List.of(), violations, "GT-25");
    }

    /**
     * GT-26: a correction is a row of its own - a new id, the same grant, a denial - on H2 and PostgreSQL
     */
    @Test
    public void gt26ACorrectionHasItsOwnEventId() throws Throwable {
        List<String> violations = new ArrayList<>();
        for (Engine engine : List.of(h2(), postgres())) {
            Lab lab = lab(engine, SHORT_WAIT);
            String user = grantedUser(engine, "gt26");
            lab.onAllowedClosed = () -> lab.clock.advance(Duration.ofHours(1));
            expectDenied(violations, engine.name(), lab.run(user, new Context(), script -> { }), DenialReason.GRANT_EXPIRED);
            List<Row> rows = rows(engine, user);
            if (rows.size() != 2) {
                violations.add(engine.name() + ": expected the allowed row and its correction, got " + rows);
                continue;
            }
            Row allowed = rows.stream().filter(row -> row.type().equals("WRITE_ALLOWED")).findFirst().orElse(null);
            Row denied = rows.stream().filter(row -> row.type().equals("WRITE_DENIED")).findFirst().orElse(null);
            if (allowed == null || denied == null || allowed.id().equals(denied.id())
                || !"DENY".equals(denied.decision()) || !"GRANT_EXPIRED".equals(denied.reason())
            ) {
                violations.add(engine.name() + ": a correction needs a new id and a denial, got " + rows);
            } else {
                expect(violations, engine.name() + ": the correction's key, grant, category and expiry",
                    List.of(allowed.project(), allowed.connection(), String.valueOf(allowed.grant()), allowed.category(),
                        String.valueOf(allowed.expires())),
                    List.of(denied.project(), denied.connection(), String.valueOf(denied.grant()), denied.category(),
                        String.valueOf(denied.expires())));
                if (allowed.grant() == null || allowed.expires() == null) {
                    violations.add(engine.name() + ": the allowed row must name its grant and expiry, got " + allowed);
                }
            }
        }
        Assertions.assertEquals(List.of(), violations, "GT-26");
    }

    /**
     * GT-27: what the operation throws reaches the caller as it is - no correction, no rollback, both locks free
     */
    @Test
    public void gt27AnOperationFailureIsNotCorrected() throws Throwable {
        List<String> violations = new ArrayList<>();
        Lab lab = lab(h2(), SHORT_WAIT);
        String user = grantedUser(lab.engine, "gt27");
        DbAccessKey key = new DbAccessKey(user, PROJECT, CONNECTION);
        for (Throwable failure : List.of(new SQLException("operation", "42000"), new IllegalStateException("operation"),
            new LifecycleTestSupport.InjectedError("operation"))) {
            final String what = failure.getClass().getSimpleName();
            Context context = new Context();
            Script script = new Script(lab);
            if (failure instanceof Exception exception) {
                script.executeFails = exception;
            } else {
                script.executeErrors = (Error) failure;
            }
            Throwable thrown = null;
            lab.mark(context);
            try {
                lab.gate.enter().run(request(user), context, script);
            } catch (Throwable t) {
                thrown = t;
            }
            if (thrown != failure) {
                violations.add(what + ": the operation's own exception must reach the caller, got " + thrown);
            }
            expect(violations, what + ": rows", List.of("audit WRITE_ALLOWED interrupted=false"), lab.audits(context));
            expect(violations, what + ": transaction questions and rollbacks", List.of(0, 0),
                List.of(script.actives.get(), script.rollbacks.get()));
            expectLocksFree(violations, what, key);
        }
        Assertions.assertEquals(List.of(), violations, "GT-27");
    }

    /**
     * GT-28: once the operation has been called, the writer is not - whether the operation returned or threw
     */
    @Test
    public void gt28NothingIsWrittenAfterTheOperation() throws Throwable {
        List<String> violations = new ArrayList<>();
        Lab lab = lab(h2(), SHORT_WAIT);
        String user = grantedUser(lab.engine, "gt28");
        for (boolean throwing : new boolean[]{false, true}) {
            final String what = throwing ? "the operation throws" : "the operation returns";
            Context context = new Context();
            Script script = new Script(lab);
            if (throwing) {
                script.executeFails = new IllegalStateException("operation");
            }
            lab.mark(context);
            int from = lab.events.size();
            try {
                lab.gate.enter().run(request(user), context, script);
            } catch (IllegalStateException expected) {
                // the operation's own
            }
            List<String> events;
            synchronized (lab.events) {
                events = new ArrayList<>(lab.events.subList(from, lab.events.size()));
            }
            int executed = events.indexOf("execute");
            if (executed < 0) {
                violations.add(what + ": the operation did not run");
                continue;
            }
            expect(violations, what + ": rows after the operation", List.of(),
                events.subList(executed, events.size()).stream().filter(e -> e.startsWith("audit") || e.equals("metadata open")).toList());
            expect(violations, what + ": executes", 1, script.executes.get());
        }
        Assertions.assertEquals(List.of(), violations, "GT-28");
    }

    /**
     * GT-29: the registry is told about the context object itself
     * <p>
     * After a refusal whose rollback failed, the registry reports the context's own object as blocked, and refuses
     * to answer for another object under the same id - so it holds the caller's object, not a wrapper.
     */
    @Test
    public void gt29TheRegistrySeesTheContextObjectItself() throws Throwable {
        List<String> violations = new ArrayList<>();
        Lab lab = lab(h2(), SHORT_WAIT);
        String user = activeUser(lab.engine, "gt29");
        Context context = new Context();
        lab.run(user, context, script -> {
            script.active = true;
            script.rollbackWorks = false;
        });
        expect(violations, "the context object", TransactionTaintRegistry.State.BLOCKED, stateOf(lab, context));
        try {
            TransactionTaintRegistry.State other = lab.registry.state(context.id, new Object());
            violations.add("another object under the same id must be refused, got " + other);
        } catch (IllegalStateException expected) {
            // the registry holds the caller's object
        }
        Assertions.assertEquals(List.of(), violations, "GT-29");
    }

    /**
     * GT-30: a policy service that changes between {@code enter()} and the operation refuses the attempt
     */
    @Test
    public void gt30AChangedPolicyServiceRefuses() throws Throwable {
        List<String> violations = new ArrayList<>();
        Lab lab = lab(h2(), SHORT_WAIT);
        String user = grantedUser(lab.engine, "gt30");
        EnforcementGate.Entry entry = lab.gate.enter();
        lab.revocation.get().revoke(PolicyServiceHolder.FailureCode.ADVISORY_LOCK_LOST);
        Context context = new Context();
        Script script = new Script(lab);
        lab.mark(context);
        expectDeniedResult(violations, "revoked after enter", entry.run(request(user), context, script),
            DenialReason.PERMISSION_STORE_UNAVAILABLE);
        expect(violations, "executes", 0, script.executes.get());
        expect(violations, "rows", List.of("audit WRITE_ALLOWED interrupted=false",
            "audit WRITE_DENIED PERMISSION_STORE_UNAVAILABLE interrupted=false"), lab.audits(context));
        Assertions.assertEquals(List.of(), violations, "GT-30");
    }

    /**
     * GT-31: the admission is checked in {@code enter()}, before the caller's own locks, and nowhere else
     * <p>
     * The caller journals taking its instance lock between the two calls; the admission must come before it, once.
     * {@code enter()} itself takes no lock and opens no metadata connection.
     */
    @Test
    public void gt31TheAdmissionIsCheckedBeforeTheCallersLocks() throws Throwable {
        List<String> violations = new ArrayList<>();
        Lab lab = lab(h2(), SHORT_WAIT);
        final String user = grantedUser(lab.engine, "gt31");
        lab.events.clear();
        int opens = lab.opens.get();
        final EnforcementGate.Entry entry = lab.gate.enter();
        expect(violations, "enter: events", List.of("assertSingleProcess"), new ArrayList<>(lab.events));
        expect(violations, "enter: metadata connections", opens, lab.opens.get());
        lab.events.add("caller X");
        Script script = new Script(lab);
        expectExecutedResult(violations, "the attempt", entry.run(request(user), new Context(), script));
        List<String> events = new ArrayList<>(lab.events);
        expect(violations, "admissions", 1L, events.stream().filter(e -> e.equals("assertSingleProcess")).count());
        if (events.indexOf("assertSingleProcess") > events.indexOf("caller X")) {
            violations.add("the admission must be checked before the caller's lock: " + events);
        }
        Assertions.assertEquals(List.of(), violations, "GT-31");
    }

    /**
     * GT-32: a retry is a new attempt - a new entry, a new window, new rows
     */
    @Test
    public void gt32ARetryIsANewAttempt() throws Throwable {
        List<String> violations = new ArrayList<>();
        Lab lab = lab(h2(), SHORT_WAIT);
        String user = grantedUser(lab.engine, "gt32");
        Context context = new Context();
        int readsBefore = lab.clock.reads();
        expectExecuted(violations, "first", lab.run(user, context, script -> { }).outcome());
        int readsFirst = lab.clock.reads() - readsBefore;
        expectExecuted(violations, "retry", lab.run(user, context, script -> { }).outcome());
        int readsSecond = lab.clock.reads() - readsBefore - readsFirst;
        List<Row> rows = rows(lab.engine, user);
        expect(violations, "allowed rows", 2, rows.size());
        expect(violations, "distinct ids", 2, (int) rows.stream().map(Row::id).distinct().count());
        if (readsFirst <= 0 || readsSecond <= 0) {
            violations.add("each attempt must open and measure a window of its own, clock reads " + readsFirst + " then " + readsSecond);
        }
        Assertions.assertEquals(List.of(), violations, "GT-32");
    }

    /**
     * GT-33: key resolution is pure - no metadata connection, no decision - and refuses exactly as authorize does
     * <p>
     * Nothing outside the service can make a key resolution, and nothing in the gate's API takes a key.
     */
    @Test
    public void gt33KeyResolutionIsPure() throws Throwable {
        List<String> violations = new ArrayList<>();
        Lab lab = lab(h2(), SHORT_WAIT);
        String user = grantedUser(lab.engine, "gt33");
        DbAccessPolicyService service = ((PolicyServiceHolder.Ready) lab.holder.current()).service();
        int opens = lab.opens.get();
        DbAccessPolicyService.KeyResolution resolved = service.resolveKey(request(user));
        expect(violations, "metadata connections", opens, lab.opens.get());
        expect(violations, "the key", new DbAccessKey(user, PROJECT, CONNECTION), resolved.key());
        expect(violations, "the key authorize decides about", resolved.key(), service.authorize(request(user)).key());
        List<WriteAuthorizationRequest> refused = List.of(
            WriteAuthorizationRequest.of(null, container(), DbOperationCategory.SQL_TEXT),
            WriteAuthorizationRequest.of(" ", container(), DbOperationCategory.SQL_TEXT),
            WriteAuthorizationRequest.of(user, null, DbOperationCategory.SQL_TEXT),
            WriteAuthorizationRequest.of(user, PolicyTestSupport.container("anonymous", CONNECTION, HOST, DATABASE),
                DbOperationCategory.SQL_TEXT),
            WriteAuthorizationRequest.of(user, PolicyTestSupport.builder(PROJECT, CONNECTION).registryHoldsSomethingElse().build(),
                DbOperationCategory.SQL_TEXT),
            WriteAuthorizationRequest.of(user, container(), DbOperationCategory.CONTAINER_READ));
        for (WriteAuthorizationRequest request : refused) {
            opens = lab.opens.get();
            DbAccessPolicyService.KeyResolution resolution = service.resolveKey(request);
            expect(violations, request + ": metadata connections", opens, lab.opens.get());
            expect(violations, request + ": no key", null, resolution.key());
            expect(violations, request + ": the same refusal as authorize", service.authorize(request).denialReason(),
                resolution.failure());
        }
        expect(violations, "a rollback", DenialReason.OPERATION_UNSUPPORTED,
            service.resolveKey(WriteAuthorizationRequest.of(user, container(), DbOperationCategory.TRANSACTION_ROLLBACK)).failure());
        for (Constructor<?> constructor : DbAccessPolicyService.KeyResolution.class.getDeclaredConstructors()) {
            if (!Modifier.isPrivate(constructor.getModifiers())) {
                violations.add("a key resolution can be made outside the service: " + constructor);
            }
        }
        List<Class<?>> gateTypes = new ArrayList<>(List.of(EnforcementGate.class));
        gateTypes.addAll(Arrays.asList(EnforcementGate.class.getDeclaredClasses()));
        for (Class<?> type : gateTypes) {
            if (type == EnforcementGate.KeyLockSource.class) {
                continue;
            }
            for (Method method : type.getMethods()) {
                for (Class<?> parameter : method.getParameterTypes()) {
                    if (parameter == DbAccessKey.class || parameter == DbAccessPolicyService.KeyResolution.class) {
                        violations.add(type.getSimpleName() + "." + method.getName() + " takes a key from outside");
                    }
                }
            }
        }
        Assertions.assertEquals(List.of(), violations, "GT-33");
    }

    /**
     * GT-35: a registry that cannot answer - closed, or holding another live object under the context's id - refuses
     * <p>
     * Either way the attempt is {@code PERMISSION_STORE_UNAVAILABLE}: the open transaction is rolled back once, the
     * denial is recorded, nothing runs, and a refusal - not an exception - comes back. The other object's entry is
     * left as it was: the gate's own marks for a context it cannot claim fail, are logged, and change nothing.
     */
    @Test
    public void gt35ARegistryThatCannotAnswerRefuses() throws Throwable {
        List<String> violations = new ArrayList<>();
        Lab lab = lab(h2(), SHORT_WAIT);
        String user = grantedUser(lab.engine, "gt35");

        Context other = new Context();
        lab.registry.markTainted(other.id, other.identity);
        Context sameId = new Context(other.id);
        Lab.Run conflict = lab.run(user, sameId, script -> script.active = true);
        expectDenied(violations, "another object holds the id", conflict, DenialReason.PERMISSION_STORE_UNAVAILABLE);
        expect(violations, "another object holds the id: rollbacks", 1, conflict.script().rollbacks.get());
        expect(violations, "another object holds the id: the denial",
            List.of("audit WRITE_DENIED PERMISSION_STORE_UNAVAILABLE interrupted=false"), lab.audits(sameId));
        expect(violations, "the other object's entry", TransactionTaintRegistry.State.TAINTED, stateOf(lab, other));

        lab.registry.clear();
        Context closed = new Context();
        Lab.Run run = lab.run(user, closed, script -> script.active = true);
        expectDenied(violations, "a closed registry", run, DenialReason.PERMISSION_STORE_UNAVAILABLE);
        expect(violations, "a closed registry: rollbacks", 1, run.script().rollbacks.get());
        expect(violations, "a closed registry: the denial",
            List.of("audit WRITE_DENIED PERMISSION_STORE_UNAVAILABLE interrupted=false"), lab.audits(closed));
        Assertions.assertEquals(List.of(), violations, "GT-35");
    }

    /**
     * GT-34: the entry-point test written for the next slice stays out of the suite and the verifier
     * <p>
     * Matched as a whole name, so P6-A's {@code TransactionEnforcementEntryPointTest} is not taken for it; that copy
     * carries none of the Explain cases, which stay unregistered for P6-B.
     */
    @Test
    public void gt34TheEntryPointTestStaysUnregistered() throws IOException {
        Path root = MetadataLeaseTest.repositoryRoot();
        String suite = Files.readString(root.resolve(
            "server/test/io.cloudbeaver.test.platform/src/io/cloudbeaver/test/platform/CEServerTestSuite.java"), StandardCharsets.UTF_8);
        String verifier = Files.readString(root.resolve(".github/scripts/verify_dbac_surefire.py"), StandardCharsets.UTF_8);
        String copy = Files.readString(root.resolve(
            "server/test/io.cloudbeaver.test.platform/src/io/cloudbeaver/test/platform/dbac/TransactionEnforcementEntryPointTest.java"),
            StandardCharsets.UTF_8);
        Pattern original = Pattern.compile("\\bEnforcementEntryPointTest\\b");
        Assertions.assertFalse(original.matcher(suite).find(), "GT-34: the suite must not register EnforcementEntryPointTest");
        Assertions.assertFalse(original.matcher(verifier).find(), "GT-34: the verifier must not count EnforcementEntryPointTest");
        for (String explain : List.of("EXP-1", "EXP-2", "EnforcementTestSupport.explain(", "DbOperationCategory.EXPLAIN")) {
            Assertions.assertFalse(copy.contains(explain), "GT-34: the registered P6-A copy must carry no Explain case: " + explain);
        }
    }

    // ---------------------------------------------------------------- the lab

    @NotNull
    private Lab lab(@NotNull Engine engine, @NotNull DbAccessPolicyConfig config) throws Exception {
        Lab lab = new Lab(engine, config);
        labs.add(lab);
        return lab;
    }

    /** Runs inside a watched call; may throw anything */
    @FunctionalInterface
    private interface Hook {
        void run() throws Exception;
    }

    /**
     * One isolated policy lifecycle, built by the production factory, and everything it did, in order
     */
    private final class Lab {
        final Engine engine;
        final DbAccessPolicyConfig config;
        final List<String> events = Collections.synchronizedList(new ArrayList<>());
        final LifecycleTestSupport.Fixture lifecycle = new LifecycleTestSupport.Fixture();
        final SpyAdmission admission = new SpyAdmission(events);
        final TestClock clock = new TestClock();
        final AtomicInteger opens = new AtomicInteger();
        final AtomicReference<DeploymentGuard.Revocation> revocation = new AtomicReference<>();
        final TransactionTaintRegistry registry;
        final RecordingLocks locks;
        final LifecycleTestSupport.TestFactory factory;
        final PolicyServiceHolder holder;
        final EnforcementGate gate;
        /** Just before the WRITE_ALLOWED insert executes */
        volatile Hook beforeAllowedInsert = () -> { };
        /** When the connection that ran the WRITE_ALLOWED insert is closed - after the writer settled its outcome */
        volatile Hook onAllowedClosed = () -> { };
        /** When the connection that read the authorization snapshot is closed */
        volatile Hook onSnapshotClosed = () -> { };
        volatile boolean failAllowedInsert;

        Lab(@NotNull Engine engine, @NotNull DbAccessPolicyConfig config) throws Exception {
            this.engine = engine;
            this.config = config;
            this.registry = TransactionTaintRegistry.isolated((operation, contextId) -> events.add("registry " + operation));
            this.locks = new RecordingLocks(EnforcementGate.KeyLockSource.of(EnforcementKeyLocks.global()), events);
            DbacSecurityControllerFactory.Admitter admitter = (database, revoke) -> {
                revocation.set(revoke);
                return new DeploymentGuard.Admitted(admission, lifecycle.lease);
            };
            DbacSecurityControllerFactory.ServiceFactory services = database -> new DbAccessPolicyService(
                database.metadataLeases(), config, Clock.systemUTC(), clock);
            this.factory = new LifecycleTestSupport.TestFactory(lifecycle,
                new DbacSecurityControllerFactory.LifecycleSeams(admitter, lifecycle.registrar, lifecycle.sink, services));
            factory.databaseMaker = (application, databaseConfig, shutdown) ->
                new SourcedDb(application, databaseConfig, shutdown, this::open);
            factory.init();
            this.holder = factory.holderForTest();
            Assertions.assertInstanceOf(PolicyServiceHolder.Ready.class, holder.current(), "FIXTURE: the lifecycle must reach Ready");
            this.gate = EnforcementGate.of(holder, locks, registry);
            events.clear();
        }

        /** What one attempt returned and journaled */
        record Run(@NotNull MetadataTestSupport.Outcome<EnforcementGate.Result<String>> outcome, @NotNull Script script,
                   @NotNull List<String> events) {
            @Nullable
            EnforcementGate.Result<String> result() {
                return outcome.value();
            }
        }

        @NotNull
        Run run(@NotNull String user, @NotNull Context context, @NotNull Arrangement arrange) throws Exception {
            return run(request(user), context, arrange);
        }

        @NotNull
        Run run(@NotNull WriteAuthorizationRequest request, @NotNull Context context, @NotNull Arrangement arrange) throws Exception {
            Script script = new Script(this);
            arrange.apply(script);
            mark(context);
            int from = events.size();
            EnforcementGate.Result<String> result = null;
            Throwable thrown = null;
            long start = System.nanoTime();
            try {
                result = gate.enter().run(request, context, script);
            } catch (Throwable t) {
                thrown = t;
            }
            List<String> journal;
            synchronized (events) {
                journal = new ArrayList<>(events.subList(from, events.size()));
            }
            return new Run(new MetadataTestSupport.Outcome<>(result, thrown, System.nanoTime() - start, true), script, journal);
        }

        /** Starts a context's section of the journal, so its audit rows can be told apart */
        void mark(@NotNull Context context) {
            events.add("attempt " + context.id);
        }

        /** The audit rows this lab journaled for one context's attempts */
        @NotNull
        List<String> audits(@NotNull Context context) {
            synchronized (events) {
                List<String> found = new ArrayList<>();
                boolean inside = false;
                for (String event : events) {
                    if (event.equals("attempt " + context.id)) {
                        inside = true;
                    } else if (event.startsWith("attempt ")) {
                        inside = false;
                    } else if (inside && event.startsWith("audit")) {
                        found.add(event);
                    }
                }
                return found;
            }
        }

        @NotNull
        Connection open() throws SQLException {
            opens.incrementAndGet();
            events.add("metadata open");
            return watch(engine.source().openConnection());
        }

        @NotNull
        private Connection watch(@NotNull Connection delegate) {
            boolean[] allowedInsert = {false};
            boolean[] snapshot = {false};
            return MetadataTestSupport.proxy(Connection.class, (self, method, args) -> {
                switch (method.getName()) {
                    case "prepareStatement" -> {
                        String sql = (String) args[0];
                        PreparedStatement statement = (PreparedStatement) invoke(delegate, method, args);
                        if (!sql.startsWith(AUDIT_INSERT)) {
                            events.add("statement");
                            snapshot[0] = true;
                            return statement;
                        }
                        Object[] bound = new Object[16];
                        return MetadataTestSupport.proxy(PreparedStatement.class, (inner, innerMethod, innerArgs) -> {
                            String name = innerMethod.getName();
                            if (name.equals("setString") || name.equals("setObject")) {
                                bound[(Integer) innerArgs[0]] = innerArgs[1];
                            }
                            if (!name.equals("executeUpdate")) {
                                return invoke(statement, innerMethod, innerArgs);
                            }
                            String type = (String) bound[2];
                            Object reason = bound[10];
                            events.add("audit " + type + (reason == null ? "" : " " + reason)
                                + " interrupted=" + Thread.currentThread().isInterrupted());
                            boolean allowed = "WRITE_ALLOWED".equals(type);
                            if (allowed) {
                                allowedInsert[0] = true;
                                beforeAllowedInsert.run();
                                if (failAllowedInsert) {
                                    throw new SQLException("injected audit failure", "08006");
                                }
                            }
                            return invoke(statement, innerMethod, innerArgs);
                        });
                    }
                    case "close" -> {
                        Object result = invoke(delegate, method, args);
                        if (allowedInsert[0]) {
                            allowedInsert[0] = false;
                            onAllowedClosed.run();
                        }
                        if (snapshot[0]) {
                            snapshot[0] = false;
                            onSnapshotClosed.run();
                        }
                        return result;
                    }
                    case "hashCode" -> {
                        return System.identityHashCode(self);
                    }
                    case "equals" -> {
                        return self == args[0];
                    }
                    default -> {
                        return invoke(delegate, method, args);
                    }
                }
            });
        }

        /** Shuts the lifecycle's database down; what that threw */
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

    /** Shapes an attempt's script before it runs */
    @FunctionalInterface
    private interface Arrangement {
        void apply(@NotNull Script script);
    }

    /**
     * The platform's side of one attempt, scripted, journaling each call into its lab
     */
    private static final class Script implements EnforcementGate.Execution<String> {
        final List<String> events = Collections.synchronizedList(new ArrayList<>());
        final List<String> labEvents;
        final AtomicInteger actives = new AtomicInteger();
        final AtomicInteger rollbacks = new AtomicInteger();
        final AtomicInteger severs = new AtomicInteger();
        final AtomicInteger confirms = new AtomicInteger();
        final AtomicInteger executes = new AtomicInteger();
        volatile boolean active;
        @Nullable volatile Throwable activeFails;
        volatile boolean rollbackWorks = true;
        @Nullable volatile Throwable rollbackFails;
        @Nullable volatile Throwable severFails;
        @Nullable volatile DenialReason confirmation;
        @Nullable volatile Throwable confirmFails;
        @Nullable volatile Exception executeFails;
        @Nullable volatile Error executeErrors;
        volatile Hook onRollback = () -> { };
        volatile Hook onExecute = () -> { };

        Script(@NotNull Lab lab) {
            this.labEvents = lab.events;
        }

        private void note(@NotNull String event) {
            events.add(event);
            labEvents.add(event);
        }

        @Override
        public boolean transactionActive() {
            actives.incrementAndGet();
            note("transactionActive");
            raise(activeFails);
            return active;
        }

        @Nullable
        @Override
        public DenialReason confirm() {
            confirms.incrementAndGet();
            note("confirm");
            raise(confirmFails);
            return confirmation;
        }

        @Override
        public boolean rollback() {
            rollbacks.incrementAndGet();
            note("rollback interrupted=" + Thread.currentThread().isInterrupted());
            try {
                onRollback.run();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
            raise(rollbackFails);
            return rollbackWorks;
        }

        @Override
        public void sever() {
            severs.incrementAndGet();
            note("sever");
            raise(severFails);
        }

        @NotNull
        @Override
        public String execute() throws Exception {
            executes.incrementAndGet();
            note("execute");
            onExecute.run();
            if (executeFails != null) {
                throw executeFails;
            }
            if (executeErrors != null) {
                throw executeErrors;
            }
            return DONE;
        }

        private static void raise(@Nullable Throwable failure) {
            if (failure instanceof RuntimeException runtime) {
                throw runtime;
            }
            if (failure instanceof Error error) {
                throw error;
            }
        }
    }

    /** A context: an id and a long-lived object, as the platform's execution context would be */
    private static final class Context implements EnforcementGate.ContextRef {
        final long id;
        final Object identity = new Object();

        Context() {
            this(CONTEXT_IDS.incrementAndGet());
        }

        /** Another object under an id that may already be taken */
        Context(long id) {
            this.id = id;
        }

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

    /** An admission the test can make answer no, throw, or do something while it is asked */
    private static final class SpyAdmission implements DeploymentGuard.Admission {
        final List<String> events;
        volatile boolean answer = true;
        @Nullable volatile Throwable fails;
        volatile Runnable during = () -> { };

        SpyAdmission(@NotNull List<String> events) {
            this.events = events;
        }

        @NotNull
        @Override
        public String deploymentMode() {
            return DeploymentGuard.MODE_TEST;
        }

        @Override
        public boolean assertSingleProcess() {
            events.add("assertSingleProcess");
            during.run();
            Script.raise(fails);
            return answer;
        }
    }

    /** The policy service's monotonic clock: real time plus whatever the test adds, failing on a chosen read */
    private static final class TestClock implements LongSupplier {
        private final AtomicLong offset = new AtomicLong();
        private final AtomicInteger reads = new AtomicInteger();
        private volatile int failingRead = -1;
        @Nullable
        private volatile Throwable failure;

        @Override
        public long getAsLong() {
            int read = reads.incrementAndGet();
            Throwable fail = failure;
            if (read == failingRead && fail != null) {
                failingRead = -1;
                failure = null;
                Script.raise(fail);
            }
            return System.nanoTime() + offset.get();
        }

        void advance(@NotNull Duration by) {
            offset.addAndGet(by.toNanos());
        }

        int reads() {
            return reads.get();
        }

        /** Throws {@code failure} on read number {@code read}, once */
        void failOnRead(int read, @NotNull Throwable failure) {
            this.failure = failure;
            this.failingRead = read;
        }
    }

    /** The real shared key locks, journaled: each wait, its outcome and each release */
    private static final class RecordingLocks implements EnforcementGate.KeyLockSource {
        private final EnforcementGate.KeyLockSource real;
        private final List<String> events;
        volatile Hook afterUser = () -> { };

        RecordingLocks(@NotNull EnforcementGate.KeyLockSource real, @NotNull List<String> events) {
            this.real = real;
            this.events = events;
        }

        @Nullable
        @Override
        public EnforcementKeyLocks.Held grant(@NotNull DbAccessKey key, @NotNull Duration timeout) throws InterruptedException {
            return recorded("K", () -> real.grant(key, timeout), () -> { });
        }

        @Nullable
        @Override
        public EnforcementKeyLocks.Held user(@NotNull String userId, @NotNull Duration timeout) throws InterruptedException {
            return recorded("U", () -> real.user(userId, timeout), afterUser);
        }

        @FunctionalInterface
        private interface Take {
            @Nullable
            EnforcementKeyLocks.Held take() throws InterruptedException;
        }

        @Nullable
        private EnforcementKeyLocks.Held recorded(
            @NotNull String name,
            @NotNull Take take,
            @NotNull Hook after
        ) throws InterruptedException {
            events.add(name + " wait");
            EnforcementKeyLocks.Held held;
            try {
                held = take.take();
            } catch (InterruptedException e) {
                events.add(name + " interrupted");
                throw e;
            }
            if (held == null) {
                events.add(name + " timeout");
                return null;
            }
            events.add(name + " acquire");
            try {
                after.run();
            } catch (Exception e) {
                held.close();
                throw new IllegalStateException(e);
            }
            return () -> {
                events.add(name + " release");
                held.close();
            };
        }
    }

    /** A write lock held by a thread of its own until released */
    private static final class WriteHolder implements AutoCloseable {
        private final CountDownLatch release = new CountDownLatch(1);
        @Nullable
        private final Thread thread;

        private WriteHolder(@Nullable Take take) throws InterruptedException {
            if (take == null) {
                thread = null;
                return;
            }
            CountDownLatch held = new CountDownLatch(1);
            thread = new Thread(() -> {
                try (EnforcementKeyLocks.Held ignored = take.take()) {
                    held.countDown();
                    release.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }, "dbac-gt-writer");
            thread.setDaemon(true);
            thread.start();
            Assertions.assertTrue(held.await(30, TimeUnit.SECONDS), "FIXTURE: the write lock was not taken");
        }

        @FunctionalInterface
        private interface Take {
            @NotNull
            EnforcementKeyLocks.Held take();
        }

        @NotNull
        static WriteHolder grant(@NotNull DbAccessKey key) throws InterruptedException {
            return new WriteHolder(() -> EnforcementKeyLocks.global().lockGrantForWrite(key));
        }

        @NotNull
        static WriteHolder user(@NotNull String userId) throws InterruptedException {
            return new WriteHolder(() -> EnforcementKeyLocks.global().lockUserForWrite(userId));
        }

        @NotNull
        static WriteHolder none() throws InterruptedException {
            return new WriteHolder(null);
        }

        void release() throws InterruptedException {
            release.countDown();
            if (thread != null) {
                thread.join(TimeUnit.SECONDS.toMillis(30));
            }
        }

        @Override
        public void close() throws InterruptedException {
            release();
        }
    }

    /**
     * A metadata database that lends connections to whatever source the case chose, and has no pool of its own
     * <p>
     * Its schema is the engine's, installed already, so {@code initialize()} does nothing.
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
            // the engine's schema is installed already
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

    /**
     * A container whose project reports a different id once told to; everything else is the fixture container's
     */
    private static final class Drifting {
        final AtomicReference<String> projectId = new AtomicReference<>(PROJECT);
        final DBPDataSourceContainer container;

        Drifting() {
            DBPDataSourceContainer inner = container();
            DBPDataSourceContainer[] self = new DBPDataSourceContainer[1];
            DBPDataSourceRegistry registry = MetadataTestSupport.proxy(DBPDataSourceRegistry.class, (p, m, a) -> switch (m.getName()) {
                case "getDataSource" -> self[0];
                case "hashCode" -> System.identityHashCode(p);
                case "equals" -> p == a[0];
                case "toString" -> "registry:drifting";
                default -> throw new UnsupportedOperationException("registry." + m.getName());
            });
            DBPProject project = MetadataTestSupport.proxy(DBPProject.class, (p, m, a) -> switch (m.getName()) {
                case "getId" -> projectId.get();
                case "getDataSourceRegistry" -> registry;
                case "hashCode" -> System.identityHashCode(p);
                case "equals" -> p == a[0];
                case "toString" -> "project:drifting";
                default -> throw new UnsupportedOperationException("project." + m.getName());
            });
            self[0] = MetadataTestSupport.proxy(DBPDataSourceContainer.class, (p, m, a) -> switch (m.getName()) {
                case "getProject" -> project;
                case "hashCode" -> System.identityHashCode(p);
                case "equals" -> p == a[0];
                case "toString" -> "container:drifting";
                default -> invoke(inner, m, a);
            });
            container = self[0];
        }
    }

    // ---------------------------------------------------------------- fixtures

    @NotNull
    private static DbAccessPolicyConfig config(@NotNull Duration keyLockTimeout) {
        DbAccessPolicyConfig defaults = DbAccessPolicyConfig.defaults();
        return new DbAccessPolicyConfig(defaults.clockSkewThreshold(), defaults.maxGrantDuration(), defaults.expiryGuardMargin(),
            defaults.auditTimeout(), keyLockTimeout, defaults.snapshotTimeout());
    }

    @NotNull
    private static DBPDataSourceContainer container() {
        return PolicyTestSupport.container(PROJECT, CONNECTION, HOST, DATABASE);
    }

    @NotNull
    private static WriteAuthorizationRequest request(@NotNull String user) {
        return WriteAuthorizationRequest.of(user, container(), DbOperationCategory.SQL_TEXT);
    }

    @NotNull
    private static String activeUser(@NotNull Engine engine, @NotNull String tag) throws Exception {
        String user = USER_PREFIX + tag + "-" + Long.toHexString(System.nanoTime()) + "-" + SEQUENCE.incrementAndGet();
        try (Connection connection = engine.source().openConnection()) {
            PolicyTestSupport.putUser(connection, user, true);
        }
        return user;
    }

    @NotNull
    private String grantedUser(@NotNull Engine engine, @NotNull String tag) throws Exception {
        String user = activeUser(engine, tag);
        grant(engine, user, PROJECT);
        return user;
    }

    private void grant(@NotNull Engine engine, @NotNull String user, @NotNull String project) throws Exception {
        TempWritePermissionKey key = new TempWritePermissionKey(user, project, CONNECTION);
        TempWriteMutationCoordinator.withoutAuditing(engine.source(), repository)
            .grant(TempWriteTestSupport.grantRequest(key, TempWriteGrant.NO_ROW_REVISION, GRANT, "gate test"));
        try (Connection connection = engine.source().openConnection()) {
            Assertions.assertEquals(1, TempWriteTestSupport.countCurrent(connection, key), "FIXTURE: the grant must exist");
        }
    }

    /** One audit row, as read by a connection of its own */
    private record Row(String id, String type, String decision, @Nullable String reason, @Nullable String grant, String project,
                       String connection, String category, @Nullable String expires) {
    }

    @NotNull
    private static List<Row> rows(@NotNull Engine engine, @NotNull String user) {
        try (Connection connection = engine.source().openConnection();
             PreparedStatement dbStat = connection.prepareStatement(
                 "SELECT EVENT_ID, EVENT_TYPE, DECISION, DENIAL_REASON, GRANT_ID, PROJECT_ID, CONNECTION_ID, OPERATION_CATEGORY,"
                     + " EXPIRES_AT FROM {table_prefix}DBAC_AUDIT_EVENT WHERE USER_ID = ? ORDER BY EVENT_TYPE, EVENT_ID")) {
            dbStat.setString(1, user);
            List<Row> rows = new ArrayList<>();
            try (ResultSet dbResult = dbStat.executeQuery()) {
                while (dbResult.next()) {
                    java.time.OffsetDateTime expires = dbResult.getObject(9, java.time.OffsetDateTime.class);
                    rows.add(new Row(dbResult.getString(1), dbResult.getString(2), dbResult.getString(3), dbResult.getString(4),
                        dbResult.getString(5), dbResult.getString(6), dbResult.getString(7), dbResult.getString(8),
                        expires == null ? null : expires.toInstant().toString()));
                }
            }
            return rows;
        } catch (SQLException e) {
            throw new IllegalStateException("FIXTURE: the audit rows could not be read", e);
        }
    }

    // ---------------------------------------------------------------- checks

    private static void expect(@NotNull List<String> violations, @NotNull String what, @Nullable Object expected, @Nullable Object actual) {
        if (expected == null ? actual != null : !expected.equals(actual)) {
            violations.add(what + ": expected " + expected + ", got " + actual);
        }
    }

    /** The registry's answer for the context, or {@code "refused"} when it will not give one */
    @NotNull
    private static Object stateOf(@NotNull Lab lab, @NotNull Context context) {
        try {
            return lab.registry.state(context.id, context.identity);
        } catch (IllegalStateException e) {
            return "refused";
        }
    }

    /** A lock timeout refuses after the configured {@code T_k} - 300 ms here - not after some other wait */
    private static void expectWithinTk(@NotNull List<String> violations, @NotNull String what, @NotNull Lab.Run run) {
        long millis = TimeUnit.NANOSECONDS.toMillis(run.outcome().elapsedNanos());
        if (millis >= 4000) {
            violations.add(what + ": a lock wait of T_k = " + SHORT_WAIT.keyLockTimeout().toMillis() + "ms took " + millis + "ms");
        }
    }

    @Nullable
    private static DenialReason reasonOf(@Nullable EnforcementGate.Result<String> result) {
        return result instanceof EnforcementGate.Denied<String> denied ? denied.reason() : null;
    }

    private static void expectDenied(
        @NotNull List<String> violations,
        @NotNull String what,
        @NotNull Lab.Run run,
        @NotNull DenialReason reason
    ) {
        expectDeniedOutcome(violations, what, run.outcome(), reason);
        expect(violations, what + ": executes", 0, run.script().executes.get());
    }

    private static void expectDeniedOutcome(
        @NotNull List<String> violations,
        @NotNull String what,
        @NotNull MetadataTestSupport.Outcome<EnforcementGate.Result<String>> outcome,
        @NotNull DenialReason reason
    ) {
        if (!outcome.finished() || outcome.thrown() != null) {
            violations.add(what + ": the attempt must return, got finished=" + outcome.finished() + " thrown=" + outcome.thrown());
            return;
        }
        expectDeniedResult(violations, what, outcome.value(), reason);
    }

    private static void expectDeniedResult(
        @NotNull List<String> violations,
        @NotNull String what,
        @Nullable EnforcementGate.Result<String> result,
        @NotNull DenialReason reason
    ) {
        if (reasonOf(result) != reason) {
            violations.add(what + ": expected a denial for " + reason + ", got " + describe(result));
        }
    }

    private static void expectExecuted(
        @NotNull List<String> violations,
        @NotNull String what,
        @NotNull MetadataTestSupport.Outcome<EnforcementGate.Result<String>> outcome
    ) {
        if (!outcome.finished() || outcome.thrown() != null) {
            violations.add(what + ": the attempt must return, got finished=" + outcome.finished() + " thrown=" + outcome.thrown());
            return;
        }
        expectExecutedResult(violations, what, outcome.value());
    }

    private static void expectExecutedResult(
        @NotNull List<String> violations,
        @NotNull String what,
        @Nullable EnforcementGate.Result<String> result
    ) {
        if (!(result instanceof EnforcementGate.Executed<String> executed) || !DONE.equals(executed.value())) {
            violations.add(what + ": expected the operation to run, got " + describe(result));
        }
    }

    @NotNull
    private static String describe(@Nullable EnforcementGate.Result<String> result) {
        if (result instanceof EnforcementGate.Denied<String> denied) {
            return "a denial for " + denied.reason();
        }
        if (result instanceof EnforcementGate.Executed<String> executed) {
            return "executed: " + executed.value();
        }
        return String.valueOf(result);
    }

    /** A call the entry must refuse with IllegalStateException, having done nothing */
    private static void expectRefusedCall(@NotNull List<String> violations, @NotNull String what, @NotNull MetadataTestSupport.Call<?> call,
                                          @NotNull Script script) {
        try {
            Object result = call.call();
            violations.add(what + ": must be refused, got " + result);
        } catch (IllegalStateException expected) {
            expect(violations, what + ": what it did", List.of(), script.events);
        } catch (Throwable t) {
            violations.add(what + ": must be refused with IllegalStateException, got " + t.getClass().getName());
        }
    }

    /** Both write locks of the key can be taken at once from another thread */
    private static void expectLocksFree(@NotNull List<String> violations, @NotNull String what, @NotNull DbAccessKey key) {
        MetadataTestSupport.Outcome<Boolean> free = MetadataTestSupport.within(Duration.ofSeconds(5), () -> {
            try (EnforcementKeyLocks.Held grant = EnforcementKeyLocks.global().lockGrantForWrite(key);
                 EnforcementKeyLocks.Held user = EnforcementKeyLocks.global().lockUserForWrite(key.userId())) {
                return grant != null && user != null;
            }
        });
        if (!free.finished() || !Boolean.TRUE.equals(free.value())) {
            violations.add(what + ": both locks must be free afterwards");
        }
    }

    @Nullable
    private static Object invoke(@NotNull Object target, @NotNull Method method, @Nullable Object[] args) throws Throwable {
        try {
            return method.invoke(target, args);
        } catch (InvocationTargetException e) {
            throw e.getCause();
        }
    }

    @NotNull
    private static Set<String> publicMethods(@NotNull Class<?> type) {
        Set<String> found = new TreeSet<>();
        for (Method method : type.getDeclaredMethods()) {
            if (Modifier.isPublic(method.getModifiers()) && !method.isSynthetic()) {
                StringBuilder text = new StringBuilder(method.getName()).append('(');
                Class<?>[] parameters = method.getParameterTypes();
                for (int i = 0; i < parameters.length; i++) {
                    text.append(i == 0 ? "" : ", ").append(parameters[i].getSimpleName());
                }
                found.add(text.append(')').toString());
            }
        }
        return found;
    }

    // ---------------------------------------------------------------- bytecode

    /**
     * Everything the gate's classes may refer to: a package ends in '/', a name starting with '=' matches only itself,
     * any other class matches itself and its nested classes
     */
    private static final List<String> ALLOWED_GATE_REFERENCES = List.of(
        "java/lang/",
        "java/time/Duration",
        "java/time/OffsetDateTime",
        "java/util/Objects",
        "java/util/UUID",
        "java/util/function/Supplier",
        "org/jkiss/code/",
        "org/jkiss/dbeaver/Log",
        "io/cloudbeaver/service/dbac/PolicyServiceHolder",
        "io/cloudbeaver/service/dbac/db/DbacCBDatabase",
        "io/cloudbeaver/service/dbac/policy/AuthorizationAuditPayload",
        "io/cloudbeaver/service/dbac/policy/AuthorizationDecision",
        "io/cloudbeaver/service/dbac/policy/DbAccessDecision",
        "io/cloudbeaver/service/dbac/policy/DbAccessKey",
        "io/cloudbeaver/service/dbac/policy/DbAccessPolicyConfig",
        "io/cloudbeaver/service/dbac/policy/DbAccessPolicyService",
        "io/cloudbeaver/service/dbac/policy/DbOperationCategory",
        "io/cloudbeaver/service/dbac/policy/DenialReason",
        "io/cloudbeaver/service/dbac/policy/MetadataBudget",
        "io/cloudbeaver/service/dbac/policy/MetadataLeaseSource",
        "io/cloudbeaver/service/dbac/policy/WriteAuthorizationRequest",
        "io/cloudbeaver/service/dbac/policy/enforcement/EnforcementGate",
        "io/cloudbeaver/service/dbac/policy/enforcement/EnforcementKeyLocks",
        "io/cloudbeaver/service/dbac/policy/enforcement/TransactionTaintRegistry",
        "io/cloudbeaver/service/dbac/policy/enforcement/AccessAuditWriter",
        "io/cloudbeaver/service/dbac/policy/enforcement/AuditOutcome",
        "io/cloudbeaver/service/dbac/policy/enforcement/AuditEventId",
        "=io/cloudbeaver/service/dbac/policy/enforcement/DeploymentGuard",
        "io/cloudbeaver/service/dbac/policy/enforcement/DeploymentGuard$Admission");

    private static boolean allowedGateReference(@NotNull String name) {
        for (String allowed : ALLOWED_GATE_REFERENCES) {
            if (allowed.startsWith("=")) {
                if (name.equals(allowed.substring(1))) {
                    return true;
                }
                continue;
            }
            boolean matches = allowed.endsWith("/")
                ? name.startsWith(allowed) && (!name.substring(allowed.length()).contains("/")
                    || allowed.equals("java/lang/") && name.startsWith("java/lang/invoke/"))
                : name.equals(allowed) || name.startsWith(allowed + "$");
            if (matches) {
                return true;
            }
        }
        return false;
    }

    private static boolean ownerIs(@NotNull String owner, @NotNull String type) {
        return owner.equals(type) || owner.startsWith(type + "$");
    }

    /** One compiled class: its name, the classes it names, and the methods it calls as {@code owner#name#descriptor} */
    private record ClassFile(@NotNull String name, @NotNull Set<String> classRefs, @NotNull Set<String> methodRefs) {
    }

    /** Every class compiled from the server bundles */
    @NotNull
    private static List<ClassFile> productionClasses() throws IOException {
        Path bundles = MetadataLeaseTest.repositoryRoot().resolve("server/bundles");
        List<ClassFile> classes = new ArrayList<>();
        try (Stream<Path> roots = Files.list(bundles)) {
            for (Path classesDir : roots.map(bundle -> bundle.resolve("target/classes")).filter(Files::isDirectory).toList()) {
                try (Stream<Path> files = Files.walk(classesDir)) {
                    for (Path file : files.filter(path -> path.toString().endsWith(".class")).toList()) {
                        classes.add(parse(Files.readAllBytes(file)));
                    }
                }
            }
        }
        return classes;
    }

    private static final Pattern DESCRIPTOR_TYPE = Pattern.compile("L([\\w/$]+)[;<]");

    @NotNull
    private static ClassFile parse(@NotNull byte[] bytes) throws IOException {
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes));
        if (in.readInt() != 0xCAFEBABE) {
            throw new IOException("not a class file");
        }
        in.readUnsignedShort();
        in.readUnsignedShort();
        int count = in.readUnsignedShort();
        String[] utf8 = new String[count];
        int[][] refs = new int[count][];
        int[] tags = new int[count];
        Set<Integer> literals = new HashSet<>();
        for (int i = 1; i < count; i++) {
            int tag = in.readUnsignedByte();
            tags[i] = tag;
            switch (tag) {
                case 1 -> utf8[i] = in.readUTF();
                case 3, 4 -> in.readInt();
                case 5, 6 -> {
                    in.readLong();
                    i++;
                }
                case 7, 16, 19, 20 -> refs[i] = new int[]{in.readUnsignedShort()};
                case 8 -> literals.add(in.readUnsignedShort());
                case 9, 10, 11, 12 -> refs[i] = new int[]{in.readUnsignedShort(), in.readUnsignedShort()};
                case 15 -> {
                    in.readUnsignedByte();
                    in.readUnsignedShort();
                }
                case 17, 18 -> in.readInt();
                default -> throw new IOException("constant pool tag " + tag);
            }
        }
        int access = in.readUnsignedShort();
        int thisClass = in.readUnsignedShort();
        String name = utf8[refs[thisClass][0]];
        Set<String> classes = new TreeSet<>();
        Set<String> methods = new TreeSet<>();
        for (int i = 1; i < count; i++) {
            if (tags[i] == 7) {
                String className = utf8[refs[i][0]];
                if (className.startsWith("[")) {
                    addDescriptorTypes(classes, className);
                } else {
                    classes.add(className);
                }
            } else if (tags[i] == 1 && !literals.contains(i)) {
                addDescriptorTypes(classes, utf8[i]);
            } else if (tags[i] == 10 || tags[i] == 11) {
                String owner = utf8[refs[refs[i][0]][0]];
                int[] nameAndType = refs[refs[i][1]];
                methods.add(owner + "#" + utf8[nameAndType[0]] + "#" + utf8[nameAndType[1]]);
            }
        }
        if (access < 0) {
            throw new IOException("unreachable");
        }
        return new ClassFile(name, classes, methods);
    }

    private static void addDescriptorTypes(@NotNull Set<String> into, @NotNull String text) {
        Matcher matcher = DESCRIPTOR_TYPE.matcher(text);
        while (matcher.find()) {
            into.add(matcher.group(1));
        }
    }
}
