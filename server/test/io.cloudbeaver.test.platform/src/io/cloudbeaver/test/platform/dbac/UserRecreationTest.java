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
import io.cloudbeaver.auth.NoAuthCredentialsProvider;
import io.cloudbeaver.model.config.SMControllerConfiguration;
import io.cloudbeaver.service.dbac.DbacEmbeddedSecurityController;
import io.cloudbeaver.service.dbac.policy.AuthorizationDecision;
import io.cloudbeaver.service.dbac.policy.DbAccessPolicyConfig;
import io.cloudbeaver.service.dbac.policy.DbAccessPolicyService;
import io.cloudbeaver.service.dbac.policy.DbOperationCategory;
import io.cloudbeaver.service.dbac.policy.DenialReason;
import io.cloudbeaver.service.dbac.policy.LeaseState;
import io.cloudbeaver.service.dbac.policy.MetadataBudget;
import io.cloudbeaver.service.dbac.policy.MetadataLease;
import io.cloudbeaver.service.dbac.policy.MetadataPurpose;
import io.cloudbeaver.service.dbac.policy.WriteAuthorizationRequest;
import io.cloudbeaver.service.dbac.policy.enforcement.EnforcementKeyLocks;
import io.cloudbeaver.service.dbac.tempwrite.MetadataConnectionSource;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteAuditSink;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteConflictReason;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteGrant;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteGrantRepository;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteMutationCoordinator;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteMutationResult;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteMutationStatus;
import io.cloudbeaver.service.dbac.tempwrite.TempWritePermissionKey;
import io.cloudbeaver.service.security.db.CBDatabase;
import io.cloudbeaver.test.platform.dbac.KeyLockTestSupport.Hooks;
import io.cloudbeaver.test.platform.dbac.KeyLockTestSupport.Pause;
import io.cloudbeaver.test.platform.dbac.KeyLockTestSupport.Reader;
import io.cloudbeaver.test.platform.dbac.KeyLockTestSupport.UserDb;
import io.cloudbeaver.test.platform.dbac.KeyLockTestSupport.Worker;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.jkiss.dbeaver.model.exec.DBCException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * P5-F: a user and a grant cannot outlive each other into a new incarnation of the same id
 * <p>
 * The deletion fence is exercised through the controller production builds, over an H2 metadata database
 * of its own whose connections the test can stop at a chosen statement. The grant fence is exercised
 * through the coordinator on that H2 database and on PostgreSQL. Races are ordered by latches, pauses
 * and thread states - a measured time is only ever a second opinion.
 * <p>
 * The controller is not run on a PostgreSQL metadata database: that integration is NOT VERIFIED, as in P4.
 * On PostgreSQL a deletion is the user lock and the row deletion the controller would make.
 */
@Timeout(value = 300, unit = TimeUnit.SECONDS, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
public class UserRecreationTest {

    private static final String PG_SCHEMA = "dbac_pg_userfence";
    private static final String PROJECT = FenceTestSupport.PROJECT;
    private static final String CONNECTION = FenceTestSupport.CONNECTION;
    private static final String HOST = "db.internal.example";
    private static final String DATABASE = "customer_prod";

    /** The statement the deletion fence runs, as it is prepared */
    private static final String FENCE_QUERY = "SELECT COUNT(*) AS ACTIVE_GRANTS";
    /** Upstream's first statement of a deletion: the token invalidation, run under the user lock */
    private static final String TOKEN_DELETE = "DELETE FROM CB_AUTH_TOKEN";

    /** A short {@code T_k}, so a grant gives up on a held user well within the test */
    private static final Duration SHORT_TK = Duration.ofSeconds(1);

    private static UserDb db;

    private final TempWriteGrantRepository repository = new TempWriteGrantRepository();
    private final MetadataLeaseFixture leases = new MetadataLeaseFixture();

    /** A metadata database a grant runs against, and how a user is made and removed there */
    private record Engine(@NotNull String name, @NotNull MetadataConnectionSource source, boolean postgres) {
    }

    @BeforeAll
    public static void prepare() throws Exception {
        CEAppStarter.startServerIfNotStarted();
        EnforcementTestSupport.requirePostgres(KeyLockTestSupport.MONITOR);
        KeyLockTestSupport.installDbacSchema(PG_SCHEMA);
        try (Connection connection = KeyLockTestSupport.openPostgres(PG_SCHEMA)) {
            FenceTestSupport.installUserTables(connection);
        }
        db = UserDb.open();
    }

    @AfterAll
    public static void cleanUp() throws Exception {
        try {
            if (db != null) {
                db.close();
            }
        } finally {
            KeyLockTestSupport.dropSchema(PG_SCHEMA);
            Assertions.assertEquals(0, KeyLockTestSupport.countSchemas(PG_SCHEMA), "FIXTURE: the PostgreSQL schema was left behind");
        }
    }

    @AfterEach
    public void disarm() {
        db.database.armed = false;
        db.hooks().reset();
        leases.close();
    }

    @NotNull
    private static List<Engine> engines() {
        return List.of(
            new Engine("H2", () -> db.database.plain(), false),
            new Engine("PostgreSQL", () -> KeyLockTestSupport.openPostgres(PG_SCHEMA), true));
    }

    // ---------------------------------------------------------------- the deletion fence

    /**
     * UR-1: a user holding a grant that is neither revoked nor expired is not deleted - user, session, token and events are untouched
     */
    @Test
    public void ur1AUserHoldingALiveGrantIsNotDeleted() throws Exception {
        final List<String> violations = new ArrayList<>();
        Engine h2 = engines().get(0);
        String user = db.newUser("ur1", true);
        db.insertSessionAndToken(user);
        commitGrant(h2, user);
        String before = db.snapshot(user);

        db.arm();
        AtomicReference<Boolean> userReadableAtFence = new AtomicReference<>();
        db.hooks().before = sql -> {
            if (KeyLockTestSupport.normalized(sql).startsWith(FENCE_QUERY)) {
                userReadableAtFence.set(readableElsewhere(user));
            }
        };
        List<?> pool = KeyLockTestSupport.eventPool();
        Worker<Object> deletion;
        boolean finishedWhileQueueHeld;
        List<Object> queueBefore;
        List<Object> queueAfter;
        synchronized (pool) {
            queueBefore = new ArrayList<>(pool);
            deletion = Worker.start("dbac-ur1-delete", () -> {
                db.controller.deleteUser(user);
                return null;
            });
            finishedWhileQueueHeld = deletion.done.await(10, TimeUnit.SECONDS);
            queueAfter = new ArrayList<>(pool);
        }
        Assertions.assertTrue(deletion.awaitDone(), "UR-1: the deletion did not finish");
        expect(violations, "UR-1: the deletion is refused", DBCException.class, classOf(deletion.error));
        expect(violations, "UR-1: the refusal queues no event", true, finishedWhileQueueHeld);
        expect(violations, "UR-1: the event queue is unchanged", queueBefore, queueAfter);
        expect(violations, "UR-1: user, session and token are unchanged", before, db.snapshot(user));
        expect(violations, "UR-1: nothing is deleted", 0L, db.hooks().count("DELETE"));
        expect(violations, "UR-1: the grant is still live", false, revoked(h2, user));
        expect(violations, "UR-1: the fence runs while the deletion holds the user", Boolean.FALSE, userReadableAtFence.get());

        db.hooks().reset();
        String waited = db.newUser("ur1-waited", true);
        commitGrant(h2, waited);
        db.arm();
        Worker<Object> parkedDeletion;
        boolean parked;
        int openedWhileWaiting;
        long fenceWhileWaiting;
        try (Reader reader = Reader.ofUser(waited)) {
            parkedDeletion = Worker.start("dbac-ur1-waited", () -> {
                db.controller.deleteUser(waited);
                return null;
            });
            parked = KeyLockTestSupport.awaitParked(parkedDeletion.thread);
            openedWhileWaiting = db.hooks().opened.get();
            fenceWhileWaiting = db.hooks().count(FENCE_QUERY);
        }
        Assertions.assertTrue(parkedDeletion.awaitDone(), "UR-1: the waiting deletion did not finish");
        expect(violations, "UR-1: a deletion waits for a reader of the user", true, parked);
        expect(violations, "UR-1: the waiting deletion opens no metadata connection", 0, openedWhileWaiting);
        expect(violations, "UR-1: the waiting deletion runs no fence statement", 0L, fenceWhileWaiting);
        expect(violations, "UR-1: once it runs, the deletion is refused", DBCException.class, classOf(parkedDeletion.error));
        expect(violations, "UR-1: and the user stays", 1, db.count("CB_USER", "USER_ID", waited));
        Assertions.assertEquals(List.of(), violations, "UR-1");
    }

    /**
     * UR-2: a user whose grants are only expired or revoked is deleted, and the same id created again is allowed nothing
     */
    @Test
    public void ur2ExpiredOrRevokedGrantsDoNotHoldADeletionAndGiveNothingToTheNextIncarnation() throws Exception {
        final List<String> violations = new ArrayList<>();
        Engine h2 = engines().get(0);
        String expired = db.newUser("ur2-expired", true);
        commitGrant(h2, expired);
        expire(h2, expired);
        String revoked = db.newUser("ur2-revoked", true);
        commitGrant(h2, revoked);
        TempWriteMutationResult revoke = TempWriteMutationCoordinator.withoutAuditing(h2.source(), repository)
            .revoke(TempWriteTestSupport.revokeRequest(key(revoked), TempWriteGrant.FIRST_REVISION));
        Assertions.assertEquals(TempWriteMutationStatus.COMMITTED, revoke.status(), "FIXTURE UR-2: the revoke must commit");

        for (String user : List.of(expired, revoked)) {
            Throwable thrown = call(() -> db.controller.deleteUser(user));
            expect(violations, "UR-2: " + user + " is deleted", null, classOf(thrown));
            int left = db.count("CB_USER", "USER_ID", user);
            expect(violations, "UR-2: " + user + " row is gone", 0, left);
            if (left == 0) {
                // The next incarnation; a refused deletion has none, and is judged on the violation above.
                db.insertUser(user, true);
            }
        }
        DbAccessPolicyService service = new DbAccessPolicyService(db.database.metadataLeases(), DbAccessPolicyConfig.defaults());
        AuthorizationDecision afterExpired = service.authorize(request(expired));
        AuthorizationDecision afterRevoked = service.authorize(request(revoked));
        expect(violations, "UR-2: the new incarnation of the expired user is not allowed", false, afterExpired.isAllowed());
        expect(violations, "UR-2: because the grant is expired", DenialReason.GRANT_EXPIRED, afterExpired.denialReason());
        expect(violations, "UR-2: the new incarnation of the revoked user is not allowed", false, afterRevoked.isAllowed());
        expect(violations, "UR-2: because the grant is revoked", DenialReason.GRANT_REVOKED, afterRevoked.denialReason());
        Assertions.assertEquals(List.of(), violations, "UR-2");
    }

    // ---------------------------------------------------------------- the grant fence

    /**
     * UR-3: a grant to a user that does not exist is refused, and so is a supersede after the user was removed - nothing is written
     */
    @Test
    public void ur3AGrantToAUserThatDoesNotExistIsRefused() throws Exception {
        final List<String> violations = new ArrayList<>();
        for (Engine engine : engines()) {
            String label = "UR-3 [" + engine.name() + "]";
            String missing = uniqueUser("ur3-missing");
            TempWriteMutationResult result = grant(violations, label + " new grant", engine, missing, TempWriteGrant.NO_ROW_REVISION);
            expectRefused(violations, label + " new grant", result, TempWriteConflictReason.USER_MISSING, 1);
            try (Connection connection = engine.source().openConnection()) {
                expect(violations, label + ": no grant row", 0, TempWriteTestSupport.countCurrent(connection, key(missing)));
                expect(violations, label + ": no history", List.of(), TempWriteTestSupport.historyOf(connection, key(missing)));
            }

            String removed = createUser(engine, "ur3-removed");
            commitGrant(engine, removed);
            removeUser(engine, removed);
            List<String> history;
            TempWriteGrant stored;
            try (Connection connection = engine.source().openConnection()) {
                history = TempWriteTestSupport.historyOf(connection, key(removed));
                stored = repository.findCurrent(connection, key(removed)).orElseThrow();
            }
            TempWriteMutationResult supersede = grant(violations, label + " supersede", engine, removed, TempWriteGrant.FIRST_REVISION);
            expectRefused(violations, label + " supersede", supersede, TempWriteConflictReason.USER_MISSING, 1);
            try (Connection connection = engine.source().openConnection()) {
                TempWriteGrant after = repository.findCurrent(connection, key(removed)).orElseThrow();
                expect(violations, label + ": the row is unchanged", stored.grantId() + "@" + stored.revision(),
                    after.grantId() + "@" + after.revision());
                expect(violations, label + ": the history is unchanged", history, TempWriteTestSupport.historyOf(connection, key(removed)));
            }
        }
        Assertions.assertEquals(List.of(), violations, "UR-3");
    }

    /**
     * UR-4: a grant waits, with no connection, while the user is being deleted, and is refused once the deletion has committed
     */
    @Test
    public void ur4AGrantWaitsForADeletionAndIsThenRefused() throws Exception {
        final List<String> violations = new ArrayList<>();
        for (Engine engine : engines()) {
            String label = "UR-4 [" + engine.name() + "]";
            String user = createUser(engine, "ur4");
            Deletion deletion = Deletion.start(engine, user);
            Hooks grantHooks = new Hooks();
            Worker<TempWriteMutationResult> grant;
            boolean parked;
            int opened;
            try {
                deletion.awaitHolding(label);
                grant = Worker.start("dbac-ur4-grant",
                    () -> coordinator(engine, grantHooks).grant(grantRequest(user, TempWriteGrant.NO_ROW_REVISION)));
                parked = KeyLockTestSupport.awaitParked(grant.thread);
                opened = grantHooks.opened.get();
            } finally {
                deletion.release();
            }
            deletion.awaitDone(label);
            TempWriteMutationResult result = grant.get(label + " grant");
            expect(violations, label + ": the grant waits while the user is being deleted", true, parked);
            expect(violations, label + ": the waiting grant opens no metadata connection", 0, opened);
            expectRefused(violations, label, result, TempWriteConflictReason.USER_MISSING, 1);
            try (Connection connection = engine.source().openConnection()) {
                expect(violations, label + ": no grant row", 0, TempWriteTestSupport.countCurrent(connection, key(user)));
            }
        }
        Assertions.assertEquals(List.of(), violations, "UR-4");
    }

    /**
     * UR-5: a deletion waits for a grant in flight, then finds the grant it just committed and is refused
     */
    @Test
    public void ur5ADeletionWaitsForAGrantInFlightAndIsThenRefused() throws Exception {
        final List<String> violations = new ArrayList<>();
        Engine h2 = engines().get(0);
        String user = db.newUser("ur5", true);
        Pause atWrite = new Pause();
        Hooks grantHooks = new Hooks();
        grantHooks.before = sql -> {
            if (KeyLockTestSupport.isWrite(sql)) {
                atWrite.hit();
            }
        };
        Worker<TempWriteMutationResult> grant = Worker.start("dbac-ur5-grant",
            () -> coordinator(h2, grantHooks).grant(grantRequest(user, TempWriteGrant.NO_ROW_REVISION)));
        Worker<Object> deletion;
        boolean parked;
        int openedWhileWaiting;
        int usersWhileWaiting;
        try {
            atWrite.awaitReached("UR-5 the grant's write");
            db.arm();
            deletion = Worker.start("dbac-ur5-delete", () -> {
                db.controller.deleteUser(user);
                return null;
            });
            parked = KeyLockTestSupport.awaitParked(deletion.thread);
            openedWhileWaiting = db.hooks().opened.get();
            usersWhileWaiting = db.count("CB_USER", "USER_ID", user);
        } finally {
            atWrite.release();
        }
        final TempWriteMutationResult granted = grant.get("UR-5 grant");
        Assertions.assertTrue(deletion.awaitDone(), "UR-5: the deletion did not finish");
        expect(violations, "UR-5: the deletion waits for the grant in flight", true, parked);
        expect(violations, "UR-5: the waiting deletion opens no metadata connection", 0, openedWhileWaiting);
        expect(violations, "UR-5: the user exists while the grant is in flight", 1, usersWhileWaiting);
        expect(violations, "UR-5: the grant commits", TempWriteMutationStatus.COMMITTED, granted.status());
        expect(violations, "UR-5: the deletion is then refused", DBCException.class, classOf(deletion.error));
        expect(violations, "UR-5: the user stays", 1, db.count("CB_USER", "USER_ID", user));
        expect(violations, "UR-5: the grant stays live", false, revoked(h2, user));
        Assertions.assertEquals(List.of(), violations, "UR-5");
    }

    /**
     * UR-6: a deletion whose fence cannot be confirmed is refused, and the log carries no detail
     * <p>
     * Not confirmed: the fence statement fails, the metadata source is full, the database is not DBAC's.
     */
    @Test
    public void ur6ADeletionThatCannotBeConfirmedIsRefused() throws Throwable {
        final List<String> violations = new ArrayList<>();
        String failing = db.newUser("ur6-failing", true);
        String before = db.snapshot(failing);
        db.arm();
        db.hooks().before = sql -> {
            if (KeyLockTestSupport.normalized(sql).startsWith(FENCE_QUERY)) {
                throw new SQLException("injected fence failure " + LifecycleTestSupport.SECRET_MARKER, "08006");
            }
        };
        AtomicReference<Throwable> thrown = new AtomicReference<>();
        final LifecycleTestSupport.Captured captured =
            LifecycleTestSupport.captureLogs(() -> thrown.set(call(() -> db.controller.deleteUser(failing))));
        expectFenceRefusal(violations, "UR-6 [statement fails]", thrown.get());
        expect(violations, "UR-6 [statement fails]: the user is unchanged", before, db.snapshot(failing));
        expect(violations, "UR-6 [statement fails]: nothing is deleted", 0L, db.hooks().count("DELETE"));
        expect(violations, "UR-6 [statement fails]: the refusal is logged by event code", true,
            captured.dbacMessages().stream().anyMatch(message -> message.contains("event=DBAC_USER_DELETION_FENCE")));
        for (String problem : LifecycleTestSupport.logContractViolations(captured,
            List.of(LifecycleTestSupport.SECRET_MARKER, "injected fence failure", failing, "08006"))) {
            violations.add("UR-6 [statement fails]: " + problem);
        }

        db.database.armed = false;
        db.hooks().reset();
        String full = db.newUser("ur6-full", true);
        final String fullBefore = db.snapshot(full);
        List<MetadataLease> held = new ArrayList<>();
        Throwable refused;
        try {
            for (int i = 0; i < 4; i++) {
                held.add(db.database.metadataLeases().open(
                    MetadataBudget.startingNow(System::nanoTime, Duration.ofSeconds(30)), MetadataPurpose.SNAPSHOT));
            }
            refused = call(() -> db.controller.deleteUser(full));
        } finally {
            for (MetadataLease lease : held) {
                lease.close();
            }
        }
        expect(violations, "FIXTURE UR-6 [source full]: every held lease was returned", true,
            held.stream().allMatch(lease -> lease.state() == LeaseState.RETURNED));
        expectFenceRefusal(violations, "UR-6 [source full]", refused);
        expect(violations, "UR-6 [source full]: the user is unchanged", fullBefore, db.snapshot(full));

        CBDatabase notDbac = new CBDatabase(LifecycleTestSupport.application(), LifecycleTestSupport.h2Config(), List.of());
        DbacEmbeddedSecurityController<?> controller = new DbacEmbeddedSecurityController<>(
            LifecycleTestSupport.application(), notDbac, new NoAuthCredentialsProvider(), new SMControllerConfiguration());
        expectFenceRefusal(violations, "UR-6 [not a DBAC database]", call(() -> controller.deleteUser(uniqueUser("ur6-plain"))));
        Assertions.assertEquals(List.of(), violations, "UR-6");
    }

    /**
     * UR-7: on PostgreSQL, a user deleted and created again inherits neither a revoked nor an expired grant
     */
    @Test
    public void ur7OnPostgresARecreatedUserInheritsNothing() throws Exception {
        final List<String> violations = new ArrayList<>();
        Engine postgres = engines().get(1);
        String revoked = createUser(postgres, "ur7-revoked");
        commitGrant(postgres, revoked);
        TempWriteMutationResult revoke = TempWriteMutationCoordinator.withoutAuditing(postgres.source(), repository)
            .revoke(TempWriteTestSupport.revokeRequest(key(revoked), TempWriteGrant.FIRST_REVISION));
        Assertions.assertEquals(TempWriteMutationStatus.COMMITTED, revoke.status(), "FIXTURE UR-7: the revoke must commit");
        String expired = createUser(postgres, "ur7-expired");
        commitGrant(postgres, expired);
        expire(postgres, expired);
        for (String user : List.of(revoked, expired)) {
            removeUser(postgres, user);
            try (Connection connection = postgres.source().openConnection()) {
                PolicyTestSupport.putUser(connection, user, true);
            }
        }
        DbAccessPolicyService service = new DbAccessPolicyService(
            leases.of(postgres.source()), DbAccessPolicyConfig.defaults(), PolicyTestSupport.systemClock());
        AuthorizationDecision afterRevoked = service.authorize(request(revoked));
        AuthorizationDecision afterExpired = service.authorize(request(expired));
        expect(violations, "UR-7: the recreated revoked user is not allowed", false, afterRevoked.isAllowed());
        expect(violations, "UR-7: because the grant is revoked", DenialReason.GRANT_REVOKED, afterRevoked.denialReason());
        expect(violations, "UR-7: the recreated expired user is not allowed", false, afterExpired.isAllowed());
        expect(violations, "UR-7: because the grant is expired", DenialReason.GRANT_EXPIRED, afterExpired.denialReason());
        Assertions.assertEquals(List.of(), violations, "UR-7");
    }

    /**
     * UR-8: a grant that cannot have the user within {@code T_k} is refused without a connection
     * <p>
     * An interrupt set before the call survives the refusal.
     */
    @Test
    public void ur8AGrantThatCannotHaveTheUserInTimeIsRefused() throws Exception {
        final List<String> violations = new ArrayList<>();
        DbAccessPolicyConfig config = shortKeyLockTimeout();
        for (Engine engine : engines()) {
            String label = "UR-8 [" + engine.name() + "]";
            String user = createUser(engine, "ur8");
            Deletion deletion = Deletion.start(engine, user);
            Hooks grantHooks = new Hooks();
            Worker<TempWriteMutationResult> grant;
            long elapsedNanos;
            try {
                deletion.awaitHolding(label);
                long start = System.nanoTime();
                grant = Worker.start("dbac-ur8-grant", () -> {
                    Thread.currentThread().interrupt();
                    return new TempWriteMutationCoordinator(KeyLockTestSupport.hooked(engine.source(), grantHooks), repository,
                        TempWriteAuditSink.NONE, config)
                        .grant(grantRequest(user, TempWriteGrant.NO_ROW_REVISION));
                });
                Assertions.assertTrue(grant.awaitDone(), label + ": the grant did not return");
                elapsedNanos = System.nanoTime() - start;
            } finally {
                deletion.release();
            }
            deletion.awaitDone(label);
            if (grant.error != null) {
                violations.add(label + ": the grant threw " + grant.error.getClass().getName());
                continue;
            }
            expectRefused(violations, label, grant.result, TempWriteConflictReason.USER_LOCK_TIMEOUT, 0);
            expect(violations, label + ": no metadata connection", 0, grantHooks.opened.get());
            expect(violations, label + ": the interrupt set before the call is set again on return", true, grant.interruptedOnReturn);
            expect(violations, label + ": the grant waited about T_k (a second opinion)", true,
                elapsedNanos >= SHORT_TK.toNanos() - TimeUnit.MILLISECONDS.toNanos(100));
        }
        Assertions.assertEquals(List.of(), violations, "UR-8");
    }

    // ---------------------------------------------------------------- helpers

    /**
     * A deletion in progress that holds the user's write lock until released
     * <p>
     * On H2 it is the controller's own deletion, stopped at its first upstream statement - the fence has
     * passed by then. On PostgreSQL it is the lock and the row deletion the controller would make.
     */
    private static final class Deletion {
        private final CountDownLatch holding = new CountDownLatch(1);
        private final Pause pause = new Pause();
        private final CountDownLatch release = new CountDownLatch(1);
        private Worker<Object> worker;

        @NotNull
        static Deletion start(@NotNull Engine engine, @NotNull String user) {
            Deletion deletion = new Deletion();
            if (engine.postgres()) {
                deletion.worker = Worker.start("dbac-fence-pg-delete", () -> {
                    try (EnforcementKeyLocks.Held ignored = EnforcementKeyLocks.global().lockUserForWrite(user)) {
                        deletion.holding.countDown();
                        deletion.release.await(KeyLockTestSupport.TIMEOUT_SECONDS * 2, TimeUnit.SECONDS);
                        removeUser(engine, user);
                    }
                    return null;
                });
            } else {
                db.hooks().reset();
                db.arm();
                db.hooks().before = sql -> {
                    if (KeyLockTestSupport.normalized(sql).startsWith(TOKEN_DELETE)) {
                        deletion.holding.countDown();
                        deletion.pause.hit();
                    }
                };
                deletion.worker = Worker.start("dbac-fence-h2-delete", () -> {
                    db.controller.deleteUser(user);
                    return null;
                });
            }
            return deletion;
        }

        void awaitHolding(@NotNull String label) throws InterruptedException {
            Assertions.assertTrue(holding.await(KeyLockTestSupport.TIMEOUT_SECONDS, TimeUnit.SECONDS),
                "FIXTURE " + label + ": the deletion never took the user");
        }

        void release() {
            release.countDown();
            pause.release();
        }

        void awaitDone(@NotNull String label) throws InterruptedException {
            worker.get(label + " deletion");
            db.database.armed = false;
            db.hooks().reset();
        }
    }

    @NotNull
    private TempWriteMutationCoordinator coordinator(@NotNull Engine engine, @NotNull Hooks hooks) {
        return TempWriteMutationCoordinator.withoutAuditing(KeyLockTestSupport.hooked(engine.source(), hooks), repository);
    }

    /** One grant, a failure recorded as a violation rather than thrown */
    @Nullable
    private TempWriteMutationResult grant(
        @NotNull List<String> violations,
        @NotNull String label,
        @NotNull Engine engine,
        @NotNull String user,
        long startRevision
    ) {
        try {
            return coordinator(engine, new Hooks()).grant(grantRequest(user, startRevision));
        } catch (SQLException | RuntimeException e) {
            violations.add(label + ": the grant threw " + e.getClass().getName());
            return null;
        }
    }

    private void commitGrant(@NotNull Engine engine, @NotNull String user) throws SQLException {
        TempWriteMutationResult result = coordinator(engine, new Hooks()).grant(grantRequest(user, TempWriteGrant.NO_ROW_REVISION));
        Assertions.assertEquals(TempWriteMutationStatus.COMMITTED, result.status(), "FIXTURE: the setup grant must commit: " + result);
    }

    @NotNull
    private static io.cloudbeaver.service.dbac.tempwrite.TempWriteGrantRequest grantRequest(@NotNull String user, long startRevision) {
        return TempWriteTestSupport.grantRequest(key(user), startRevision, TempWriteTestSupport.DEFAULT_DURATION, "user fence");
    }

    @NotNull
    private static TempWritePermissionKey key(@NotNull String user) {
        return new TempWritePermissionKey(user, PROJECT, CONNECTION);
    }

    @NotNull
    private static String uniqueUser(@NotNull String tag) {
        return "dbac-p5f-" + tag + "-" + Long.toHexString(System.nanoTime());
    }

    @NotNull
    private static String createUser(@NotNull Engine engine, @NotNull String tag) throws Exception {
        if (!engine.postgres()) {
            return db.newUser(tag, true);
        }
        String user = uniqueUser(tag);
        try (Connection connection = engine.source().openConnection()) {
            PolicyTestSupport.putUser(connection, user, true);
        }
        return user;
    }

    /** Removes the user's rows with SQL, as a deletion that bypassed DBAC would */
    private static void removeUser(@NotNull Engine engine, @NotNull String user) throws SQLException {
        try (Connection connection = engine.source().openConnection()) {
            PolicyTestSupport.deleteUser(connection, user);
        }
    }

    /** Moves the user's grant into the past, as time would */
    private static void expire(@NotNull Engine engine, @NotNull String user) throws SQLException {
        try (Connection connection = engine.source().openConnection();
             PreparedStatement dbStat = connection.prepareStatement(
                 "UPDATE {table_prefix}DBAC_TW_CURRENT SET EXPIRES_AT=? WHERE USER_ID=? AND PROJECT_ID=? AND CONNECTION_ID=?")) {
            dbStat.setObject(1, OffsetDateTime.now(ZoneOffset.UTC).minusMinutes(5));
            dbStat.setString(2, user);
            dbStat.setString(3, PROJECT);
            dbStat.setString(4, CONNECTION);
            Assertions.assertEquals(1, dbStat.executeUpdate(), "FIXTURE: the grant to expire is missing");
        }
    }

    private boolean revoked(@NotNull Engine engine, @NotNull String user) throws SQLException {
        try (Connection connection = engine.source().openConnection()) {
            return repository.findCurrent(connection, key(user)).map(TempWriteGrant::isRevoked).orElse(true);
        }
    }

    /** Whether another thread can take the user's read lock now; a lock probe that cannot fail the hook it runs in */
    private static boolean readableElsewhere(@NotNull String user) throws SQLException {
        try {
            return KeyLockTestSupport.userReadableElsewhere(user);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new SQLException("FIXTURE: interrupted while probing the user lock", e);
        }
    }

    @NotNull
    private static WriteAuthorizationRequest request(@NotNull String user) {
        return WriteAuthorizationRequest.of(user, PolicyTestSupport.container(PROJECT, CONNECTION, HOST, DATABASE),
            DbOperationCategory.SQL_TEXT);
    }

    @NotNull
    private static DbAccessPolicyConfig shortKeyLockTimeout() {
        return new DbAccessPolicyConfig(
            DbAccessPolicyConfig.DEFAULT_CLOCK_SKEW_THRESHOLD,
            DbAccessPolicyConfig.DEFAULT_MAX_GRANT_DURATION,
            DbAccessPolicyConfig.DEFAULT_EXPIRY_GUARD_MARGIN,
            DbAccessPolicyConfig.DEFAULT_AUDIT_TIMEOUT,
            SHORT_TK);
    }

    /** A refusal by the user fence: the status, the reason, the attempts, and nothing written or named */
    private static void expectRefused(
        @NotNull List<String> violations,
        @NotNull String label,
        @Nullable TempWriteMutationResult result,
        @NotNull TempWriteConflictReason reason,
        int attempts
    ) {
        if (result == null) {
            violations.add(label + ": no result");
            return;
        }
        expect(violations, label + ": status", TempWriteMutationStatus.USER_FENCE_REFUSED, result.status());
        expect(violations, label + ": reason", reason, result.conflictReason());
        expect(violations, label + ": attempts", attempts, result.attempts());
        expect(violations, label + ": rows", 0, result.affectedRows());
        expect(violations, label + ": revision", null, result.revision());
        expect(violations, label + ": grant id", null, result.grantId());
        expect(violations, label + ": refused", true, result.isRefused());
    }

    /** The deletion fence's own refusal - a {@code DBCException} DBAC wrote, carrying no cause */
    private static void expectFenceRefusal(@NotNull List<String> violations, @NotNull String label, @Nullable Throwable thrown) {
        expect(violations, label + ": the deletion is refused", DBCException.class, classOf(thrown));
        if (thrown != null) {
            expect(violations, label + ": by the DBAC fence", true, String.valueOf(thrown.getMessage()).startsWith("DBAC "));
            expect(violations, label + ": with no cause", null, classOf(thrown.getCause()));
        }
    }

    /** Something whose failure is the result */
    @FunctionalInterface
    private interface Call {
        void run() throws Throwable;
    }

    @Nullable
    private static Throwable call(@NotNull Call call) {
        try {
            call.run();
            return null;
        } catch (Throwable e) {
            return e;
        }
    }

    @Nullable
    private static Class<?> classOf(@Nullable Throwable error) {
        return error == null ? null : error.getClass();
    }

    private static void expect(@NotNull List<String> violations, @NotNull String what, @Nullable Object expected, @Nullable Object actual) {
        if (!Objects.equals(expected, actual)) {
            violations.add(what + ": expected " + expected + ", got " + actual);
        }
    }
}
