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
import io.cloudbeaver.service.dbac.db.DbacSchemaConstants;
import io.cloudbeaver.service.dbac.policy.DbAccessKey;
import io.cloudbeaver.service.dbac.policy.DbAccessPolicyConfig;
import io.cloudbeaver.service.dbac.policy.enforcement.EnforcementKeyLocks;
import io.cloudbeaver.service.dbac.tempwrite.MetadataConnectionSource;
import io.cloudbeaver.service.dbac.tempwrite.MetadataDbClock;
import io.cloudbeaver.service.dbac.tempwrite.MetadataDbTime;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteChangeType;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteGrant;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteGrantRepository;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteHistoryEvent;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteMutationCoordinator;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteMutationResult;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteMutationStatus;
import io.cloudbeaver.service.dbac.tempwrite.TempWritePermissionKey;
import io.cloudbeaver.test.platform.dbac.KeyLockTestSupport.Hooks;
import io.cloudbeaver.test.platform.dbac.KeyLockTestSupport.Pause;
import io.cloudbeaver.test.platform.dbac.KeyLockTestSupport.Reader;
import io.cloudbeaver.test.platform.dbac.KeyLockTestSupport.Worker;
import org.jkiss.code.NotNull;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * P4: the grant-key (K) write lock that grant, supersede and revoke take
 * <p>
 * Every mutation goes through {@code TempWriteMutationCoordinator}, which takes the key's write lock
 * before it opens a metadata connection and gives it back only after the attempt that decided has
 * committed or rolled back. The readers here are simulated with the registry's timed read API - the
 * enforcement gate that will hold them for real is not wired yet, so nothing here claims that a
 * write through CloudBeaver is blocked.
 * <p>
 * Each race runs against the server's H2 metadata database and against PostgreSQL. KL tags the
 * writer contract, KR the registry itself.
 */
@Timeout(value = 180, unit = TimeUnit.SECONDS, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
public class GrantRevokeRaceTest {

    private static final String PG_SCHEMA = "dbac_pg_keylocks";
    private static final String PROJECT = "kl-project";
    private static final String CONNECTION = "kl-connection";

    private static EnforcementTestSupport.Fixtures fixtures;

    private final TempWriteGrantRepository repository = new TempWriteGrantRepository();
    private final List<TempWritePermissionKey> touched = Collections.synchronizedList(new ArrayList<>());

    /** A metadata database a race runs against */
    private record Engine(@NotNull String name, @NotNull MetadataConnectionSource source) {
    }

    @BeforeAll
    public static void prepare() throws Exception {
        CEAppStarter.startServerIfNotStarted();
        EnforcementTestSupport.requirePostgres(KeyLockTestSupport.MONITOR);
        KeyLockTestSupport.installDbacSchema(PG_SCHEMA);
        fixtures = EnforcementTestSupport.fixtures("p4kl", KeyLockTestSupport.MONITOR);
    }

    @AfterAll
    public static void cleanUp() throws Exception {
        try {
            if (fixtures != null) {
                fixtures.afterAll();
            }
        } finally {
            KeyLockTestSupport.dropSchema(PG_SCHEMA);
            Assertions.assertEquals(0, KeyLockTestSupport.countSchemas(PG_SCHEMA), "FIXTURE: the PostgreSQL schema was left behind");
        }
    }

    @AfterEach
    public void forgetKeys() throws Exception {
        if (fixtures != null) {
            fixtures.afterEach();
        }
        for (Engine engine : engines()) {
            try (Connection connection = engine.source().openConnection()) {
                for (TempWritePermissionKey key : new ArrayList<>(touched)) {
                    TempWriteTestSupport.deleteKey(connection, key);
                }
            }
        }
        touched.clear();
    }

    @NotNull
    private static List<Engine> engines() {
        return List.of(
            new Engine("H2", () -> EnforcementTestSupport.metadata().openConnection()),
            new Engine("PostgreSQL", () -> KeyLockTestSupport.openPostgres(PG_SCHEMA)));
    }

    // ---------------------------------------------------------------- KL

    /**
     * KL-1: a second mutation of the same key waits for the first to commit, without touching the database, then is refused
     */
    @Test
    public void kl1SameKeyMutationsAreSerialized() throws Exception {
        for (Engine engine : engines()) {
            String label = "KL-1 [" + engine.name() + "]";
            TempWritePermissionKey key = key("kl1");
            commitGrant(engine, key, TempWriteGrant.NO_ROW_REVISION);
            Pause pause = new Pause();
            Hooks first = new Hooks();
            first.before = sql -> {
                if (KeyLockTestSupport.isWrite(sql)) {
                    pause.hit();
                }
            };
            Hooks second = new Hooks();
            Worker<TempWriteMutationResult> supersede = Worker.start("dbac-kl1-supersede",
                () -> coordinator(engine, first).grant(grantRequest(key, TempWriteGrant.FIRST_REVISION, "supersede")));
            Worker<TempWriteMutationResult> revoke = null;
            boolean waited;
            int opened;
            try {
                pause.awaitReached(label + " the superseding write");
                revoke = Worker.start("dbac-kl1-revoke",
                    () -> coordinator(engine, second).revoke(revokeRequest(key, TempWriteGrant.FIRST_REVISION)));
                waited = KeyLockTestSupport.awaitParked(revoke.thread);
                opened = second.opened.get();
            } finally {
                pause.release();
            }
            TempWriteMutationResult superseded = supersede.get(label + " supersede");
            TempWriteMutationResult revoked = revoke.get(label + " revoke");

            Assertions.assertTrue(waited, label + ": a revoke of a key whose supersede is in flight must wait on the key lock");
            Assertions.assertEquals(0, opened, label + ": the waiting revoke must not open a metadata connection");
            Assertions.assertEquals(TempWriteMutationStatus.COMMITTED, superseded.status(), label + ": the first writer commits");
            Assertions.assertEquals(TempWriteMutationStatus.CONFLICT_SUPERSEDED, revoked.status(),
                label + ": the waiting revoke started from a revision that moved and must be refused");
            try (Connection connection = engine.source().openConnection()) {
                Assertions.assertEquals(2L, TempWriteTestSupport.currentRevision(connection, key), label + ": revision");
                Assertions.assertEquals(List.of("GRANTED@1", "GRANTED@2", "SUPERSEDED@2"),
                    TempWriteTestSupport.historyOf(connection, key), label + ": history");
            }
        }
    }

    /**
     * KL-2: a mutation of another key is not held up by a key in flight
     */
    @Test
    public void kl2DifferentKeysProceedIndependently() throws Exception {
        for (Engine engine : engines()) {
            String label = "KL-2 [" + engine.name() + "]";
            TempWritePermissionKey held = key("kl2-held");
            TempWritePermissionKey other = key("kl2-other");
            commitGrant(engine, other, TempWriteGrant.NO_ROW_REVISION);
            Pause pause = new Pause();
            Hooks hooks = new Hooks();
            hooks.before = sql -> {
                if (KeyLockTestSupport.isWrite(sql)) {
                    pause.hit();
                }
            };
            Worker<TempWriteMutationResult> paused = Worker.start("dbac-kl2-paused",
                () -> coordinator(engine, hooks).grant(grantRequest(held, TempWriteGrant.NO_ROW_REVISION, "paused")));
            TempWriteMutationResult otherResult;
            try {
                pause.awaitReached(label + " the paused grant");
                Worker<TempWriteMutationResult> revoke = Worker.start("dbac-kl2-other",
                    () -> coordinator(engine, new Hooks()).revoke(revokeRequest(other, TempWriteGrant.FIRST_REVISION)));
                otherResult = revoke.get(label + " the other key's revoke, while the first key is held");
            } finally {
                pause.release();
            }
            paused.get(label + " the paused grant");
            Assertions.assertEquals(TempWriteMutationStatus.COMMITTED, otherResult.status(),
                label + ": a revoke of another key must complete while the first key is held");
        }
    }

    /**
     * KL-3: the key stays locked until the commit is visible, and a reader that gets it afterwards sees the change
     */
    @Test
    public void kl3TheKeyLockIsHeldUntilTheCommitIsVisible() throws Exception {
        for (Engine engine : engines()) {
            String label = "KL-3 [" + engine.name() + "]";
            TempWritePermissionKey key = key("kl3");
            DbAccessKey accessKey = KeyLockTestSupport.accessKey(key);
            commitGrant(engine, key, TempWriteGrant.NO_ROW_REVISION);
            Pause beforeCommit = new Pause();
            Pause afterCommit = new Pause();
            Hooks hooks = new Hooks();
            hooks.beforeCommit = beforeCommit::hit;
            hooks.afterCommit = afterCommit::hit;
            Worker<TempWriteMutationResult> revoke = Worker.start("dbac-kl3-revoke",
                () -> coordinator(engine, hooks).revoke(revokeRequest(key, TempWriteGrant.FIRST_REVISION)));
            boolean readableBeforeCommit;
            boolean revokedBeforeCommit;
            boolean readableAfterCommit;
            boolean revokedAfterCommit;
            try {
                beforeCommit.awaitReached(label + " the revoke's commit");
                readableBeforeCommit = KeyLockTestSupport.grantReadableElsewhere(accessKey);
                revokedBeforeCommit = revoked(engine, key);
                beforeCommit.release();
                afterCommit.awaitReached(label + " the end of the revoke's commit");
                readableAfterCommit = KeyLockTestSupport.grantReadableElsewhere(accessKey);
                revokedAfterCommit = revoked(engine, key);
            } finally {
                beforeCommit.release();
                afterCommit.release();
            }
            final TempWriteMutationResult result = revoke.get(label + " revoke");
            boolean revokedUnderReadLock;
            try (EnforcementKeyLocks.Held held = EnforcementKeyLocks.global().tryLockGrantForRead(accessKey, KeyLockTestSupport.PROBE)) {
                Assertions.assertNotNull(held, label + ": once the revoke returned, a reader must get the key");
                revokedUnderReadLock = revoked(engine, key);
            }

            Assertions.assertFalse(readableBeforeCommit, label + ": a reader must not get the key while the revoke is about to commit");
            Assertions.assertFalse(revokedBeforeCommit, label + ": FIXTURE the revoke was visible before its commit");
            Assertions.assertTrue(revokedAfterCommit, label + ": FIXTURE the committed revoke was not visible to another connection");
            Assertions.assertFalse(readableAfterCommit,
                label + ": the key lock must still be held when the commit has become visible, until the revoke returns");
            Assertions.assertEquals(TempWriteMutationStatus.COMMITTED, result.status(), label + ": revoke");
            Assertions.assertTrue(revokedUnderReadLock, label + ": a reader that gets the key afterwards must see the revoke");
        }
    }

    /** How KL-4 makes an attempt fail */
    private enum Failure {
        SQL,
        RUNTIME,
        ERROR
    }

    /**
     * KL-4: every way out - SQLException, RuntimeException, Error, retries used up - releases the key and restores the interrupt
     */
    @Test
    public void kl4EveryFailureReleasesTheKeyLockAndRestoresTheInterrupt() throws Exception {
        String history = DbacSchemaConstants.TABLE_TW_HISTORY.toUpperCase(Locale.ROOT);
        for (Engine engine : engines()) {
            for (Failure failure : Failure.values()) {
                String label = "KL-4 [" + engine.name() + " " + failure + "]";
                TempWritePermissionKey key = key("kl4-" + failure.name().toLowerCase(Locale.ROOT));
                Hooks hooks = new Hooks();
                hooks.before = sql -> {
                    if (KeyLockTestSupport.normalized(sql).startsWith("INSERT INTO " + history)) {
                        switch (failure) {
                            case SQL -> throw new SQLException("injected history failure", "42000");
                            case RUNTIME -> throw new IllegalStateException("injected history failure");
                            default -> throw new LifecycleTestSupport.InjectedError("history");
                        }
                    }
                };
                Worker<TempWriteMutationResult> grant = Worker.start("dbac-kl4-grant", () -> {
                    Thread.currentThread().interrupt();
                    return coordinator(engine, hooks).grant(grantRequest(key, TempWriteGrant.NO_ROW_REVISION, "failing"));
                });
                Assertions.assertTrue(grant.awaitDone(), label + ": the grant did not finish");
                Class<? extends Throwable> expected = switch (failure) {
                    case SQL -> SQLException.class;
                    case RUNTIME -> IllegalStateException.class;
                    case ERROR -> LifecycleTestSupport.InjectedError.class;
                };
                Assertions.assertInstanceOf(expected, grant.error, label + ": the injected failure must reach the caller");
                assertReleasedAndRestored(label, key, hooks, grant);
                try (Connection connection = engine.source().openConnection()) {
                    Assertions.assertEquals(0, TempWriteTestSupport.countCurrent(connection, key), label + ": nothing may be stored");
                }
            }

            TempWritePermissionKey granted = key("kl4-retry-grant");
            assertTheKeyIsHeldAcrossRetries("KL-4 [" + engine.name() + " grant retries]", engine, granted,
                c -> c.grant(grantRequest(granted, TempWriteGrant.NO_ROW_REVISION, "contended")));
            TempWritePermissionKey revoked = key("kl4-retry-revoke");
            commitGrant(engine, revoked, TempWriteGrant.NO_ROW_REVISION);
            assertTheKeyIsHeldAcrossRetries("KL-4 [" + engine.name() + " revoke retries]", engine, revoked,
                c -> c.revoke(revokeRequest(revoked, TempWriteGrant.FIRST_REVISION)));
        }
    }

    /**
     * Runs a mutation whose every write meets contention until the retries are used up, and checks the key is held throughout
     * <p>
     * Every attempt records whether another thread could read the key at its write. A reader also queues
     * behind the first attempt: the lock is fair, so if the key were let go between two attempts this
     * reader would be the one to get it then. It records how many attempts had opened a connection by the
     * time it got in, which must be all of them.
     */
    private void assertTheKeyIsHeldAcrossRetries(
        @NotNull String label,
        @NotNull Engine engine,
        @NotNull TempWritePermissionKey key,
        @NotNull KeyLockTestSupport.Mutation mutation
    ) throws Exception {
        DbAccessKey accessKey = KeyLockTestSupport.accessKey(key);
        List<Boolean> readableDuringAttempts = Collections.synchronizedList(new ArrayList<>());
        AtomicReference<Worker<Integer>> queuedReader = new AtomicReference<>();
        List<Boolean> queuedReaderParked = Collections.synchronizedList(new ArrayList<>());
        Hooks hooks = new Hooks();
        hooks.before = sql -> {
            if (KeyLockTestSupport.isWrite(sql)) {
                try {
                    if (queuedReader.get() == null) {
                        Worker<Integer> reader = Worker.start("dbac-kl4-queued-reader", () -> {
                            try (EnforcementKeyLocks.Held held =
                                     EnforcementKeyLocks.global().tryLockGrantForRead(accessKey, KeyLockTestSupport.READER_WAIT)) {
                                return held == null ? -1 : hooks.opened.get();
                            }
                        });
                        queuedReader.set(reader);
                        queuedReaderParked.add(KeyLockTestSupport.awaitParked(reader.thread));
                    }
                    readableDuringAttempts.add(KeyLockTestSupport.grantReadableElsewhere(accessKey));
                } catch (InterruptedException e) {
                    throw new SQLException("FIXTURE: interrupted probe", e);
                }
                throw new SQLException("injected contention", "40001");
            }
        };
        Worker<TempWriteMutationResult> worker = Worker.start("dbac-kl4-retry", () -> {
            Thread.currentThread().interrupt();
            return mutation.run(coordinator(engine, hooks));
        });
        TempWriteMutationResult result = worker.get(label);
        int attempts = TempWriteMutationCoordinator.MAX_TRANSIENT_RETRIES + 1;
        Assertions.assertEquals(TempWriteMutationStatus.RETRY_EXHAUSTED, result.status(), label + ": status");
        Assertions.assertEquals(attempts, readableDuringAttempts.size(),
            "FIXTURE " + label + ": every attempt must have reached its write");
        Assertions.assertEquals(List.of(Boolean.TRUE), queuedReaderParked,
            "FIXTURE " + label + ": the queued reader must have been waiting during the first attempt");
        Assertions.assertFalse(readableDuringAttempts.contains(Boolean.TRUE),
            label + ": the key must stay locked across every retry, got " + readableDuringAttempts);
        Assertions.assertEquals(attempts, queuedReader.get().get(label + " queued reader").intValue(),
            label + ": a reader queued during the first attempt must get the key only after the last attempt,"
                + " not between two of them");
        assertReleasedAndRestored(label, key, hooks, worker);
    }

    private static void assertReleasedAndRestored(
        @NotNull String label,
        @NotNull TempWritePermissionKey key,
        @NotNull Hooks hooks,
        @NotNull Worker<?> worker
    ) throws InterruptedException {
        DbAccessKey accessKey = KeyLockTestSupport.accessKey(key);
        Assertions.assertFalse(hooks.statements().isEmpty(), "FIXTURE " + label + ": no statement was run");
        Assertions.assertFalse(hooks.anyInterrupted(),
            label + ": the interrupt set before the call must be cleared while the mutation runs");
        Assertions.assertTrue(worker.interruptedOnReturn, label + ": the interrupt must be restored when the call returns");
        Assertions.assertTrue(KeyLockTestSupport.grantReadableElsewhere(accessKey), label + ": a reader must get the key afterwards");
        Assertions.assertTrue(KeyLockTestSupport.grantWritableElsewhere(accessKey), label + ": a writer must get the key afterwards");
    }

    /**
     * KL-5: grant and revoke take neither the user lock nor a connection's X or M
     */
    @Test
    public void kl5GrantAndRevokeTakeNoUserOrConnectionLock() throws Exception {
        Engine engine = engines().get(0);
        TempWritePermissionKey key = key("kl5");
        Pause pause = new Pause();
        Hooks hooks = new Hooks();
        hooks.before = sql -> {
            if (KeyLockTestSupport.isWrite(sql)) {
                pause.hit();
            }
        };
        Worker<TempWriteMutationResult> grant = Worker.start("dbac-kl5-grant",
            () -> coordinator(engine, hooks).grant(grantRequest(key, TempWriteGrant.NO_ROW_REVISION, "kl5")));
        boolean userWritable;
        try {
            pause.awaitReached("KL-5 the grant's write");
            userWritable = KeyLockTestSupport.userWritableElsewhere(key.userId());
        } finally {
            pause.release();
        }
        grant.get("KL-5 grant");
        Assertions.assertTrue(userWritable, "KL-5: a grant in flight must not hold the user's lock");

        // closed by fixtures.afterEach()
        EnforcementTestSupport.Target target = fixtures.readOnlyTarget(fixtures.user);
        TempWritePermissionKey other = key("kl5-xm");
        boolean finished = KeyLockTestSupport.finishesWhileXAndMHeld(target, () -> {
            coordinator(engine, new Hooks()).grant(grantRequest(other, TempWriteGrant.NO_ROW_REVISION, "under X and M"));
            return coordinator(engine, new Hooks()).revoke(revokeRequest(other, TempWriteGrant.FIRST_REVISION));
        });
        Assertions.assertTrue(finished, "KL-5: a grant and a revoke must finish while a connection's X and M are held elsewhere");
    }

    /**
     * KL-6: an interrupt set before the call, or arriving while it waits, neither skips the mutation nor is lost
     */
    @Test
    public void kl6AnInterruptDoesNotSkipTheMutationAndIsRestored() throws Exception {
        for (Engine engine : engines()) {
            String label = "KL-6 [" + engine.name() + "]";
            TempWritePermissionKey before = key("kl6-before");
            commitGrant(engine, before, TempWriteGrant.NO_ROW_REVISION);
            Hooks beforeHooks = new Hooks();
            Worker<TempWriteMutationResult> interrupted = Worker.start("dbac-kl6-before", () -> {
                Thread.currentThread().interrupt();
                return coordinator(engine, beforeHooks).revoke(revokeRequest(before, TempWriteGrant.FIRST_REVISION));
            });
            Assertions.assertEquals(TempWriteMutationStatus.COMMITTED, interrupted.get(label + " pre-interrupted revoke").status(),
                label + ": a revoke called with the interrupt set must still commit");
            Assertions.assertTrue(revoked(engine, before), label + ": the pre-interrupted revoke must be stored");
            assertReleasedAndRestored(label + " pre-interrupted", before, beforeHooks, interrupted);

            TempWritePermissionKey waiting = key("kl6-waiting");
            commitGrant(engine, waiting, TempWriteGrant.NO_ROW_REVISION);
            Hooks waitingHooks = new Hooks();
            Worker<TempWriteMutationResult> revoke;
            boolean parked;
            boolean parkedAfterInterrupt;
            try (Reader reader = Reader.ofGrant(KeyLockTestSupport.accessKey(waiting))) {
                revoke = Worker.start("dbac-kl6-waiting",
                    () -> coordinator(engine, waitingHooks).revoke(revokeRequest(waiting, TempWriteGrant.FIRST_REVISION)));
                parked = KeyLockTestSupport.awaitParked(revoke.thread);
                revoke.thread.interrupt();
                parkedAfterInterrupt = KeyLockTestSupport.awaitParked(revoke.thread);
                Assertions.assertFalse(revoked(engine, waiting), label + ": nothing may change while the reader holds the key");
            }
            TempWriteMutationResult result = revoke.get(label + " interrupted while waiting");
            Assertions.assertTrue(parked, label + ": the revoke must wait for the reader");
            Assertions.assertTrue(parkedAfterInterrupt, label + ": an interrupt must not end the wait");
            Assertions.assertEquals(TempWriteMutationStatus.COMMITTED, result.status(), label + ": the interrupted revoke must commit");
            assertReleasedAndRestored(label + " interrupted while waiting", waiting, waitingHooks, revoke);
        }
    }

    /**
     * KL-7 (V6): a revoke behind a reader that holds the key longer than T_k does not fail - it waits and then commits
     */
    @Test
    public void kl7RevokeOutwaitsTheReaderTimeout() throws Exception {
        Duration readerTimeout = DbAccessPolicyConfig.DEFAULT_KEY_LOCK_TIMEOUT;
        for (Engine engine : engines()) {
            String label = "KL-7 [" + engine.name() + "]";
            TempWritePermissionKey key = key("kl7");
            commitGrant(engine, key, TempWriteGrant.NO_ROW_REVISION);
            Worker<TempWriteMutationResult> revoke;
            boolean parked;
            boolean stillWaiting;
            long waitedNanos;
            try (Reader reader = Reader.ofGrant(KeyLockTestSupport.accessKey(key))) {
                long start = System.nanoTime();
                revoke = Worker.start("dbac-kl7-revoke",
                    () -> coordinator(engine, new Hooks()).revoke(revokeRequest(key, TempWriteGrant.FIRST_REVISION)));
                parked = KeyLockTestSupport.awaitParked(revoke.thread);
                Thread.sleep(readerTimeout.plusSeconds(1).toMillis());
                waitedNanos = System.nanoTime() - start;
                stillWaiting = !revoke.finished() && revoke.thread.isAlive();
            }
            TempWriteMutationResult result = revoke.get(label);
            Assertions.assertTrue(parked, label + ": the revoke must wait for the reader");
            Assertions.assertTrue(stillWaiting, label + ": the revoke must still be waiting, not failed, after "
                + TimeUnit.NANOSECONDS.toMillis(waitedNanos) + " ms - longer than T_k " + readerTimeout.toMillis() + " ms");
            Assertions.assertEquals(TempWriteMutationStatus.COMMITTED, result.status(), label + ": the revoke must then commit");
            Assertions.assertTrue(revoked(engine, key), label + ": the revoke must be stored");
        }
    }

    /**
     * KL-8: the key is exactly the three strings - an equal key built elsewhere excludes, a differently cased one does not
     */
    @Test
    public void kl8TheKeyIsTheExactTriple() throws Exception {
        for (Engine engine : engines()) {
            String label = "KL-8 [" + engine.name() + "]";
            String suffix = Long.toHexString(System.nanoTime());
            TempWritePermissionKey mixed = remember(new TempWritePermissionKey("dbac-p4-Case-" + suffix, PROJECT, CONNECTION));
            TempWritePermissionKey lower = remember(new TempWritePermissionKey("dbac-p4-case-" + suffix, PROJECT, CONNECTION));
            commitGrant(engine, mixed, TempWriteGrant.NO_ROW_REVISION);
            commitGrant(engine, lower, TempWriteGrant.NO_ROW_REVISION);
            DbAccessKey builtElsewhere = new DbAccessKey(
                new String(mixed.userId().toCharArray()), new String(PROJECT.toCharArray()), new String(CONNECTION.toCharArray()));
            Worker<TempWriteMutationResult> excluded;
            boolean parked;
            TempWriteMutationResult lowerResult;
            try (Reader reader = Reader.ofGrant(builtElsewhere)) {
                excluded = Worker.start("dbac-kl8-mixed",
                    () -> coordinator(engine, new Hooks()).revoke(revokeRequest(mixed, TempWriteGrant.FIRST_REVISION)));
                parked = KeyLockTestSupport.awaitParked(excluded.thread);
                lowerResult = Worker.start("dbac-kl8-lower",
                    () -> coordinator(engine, new Hooks()).revoke(revokeRequest(lower, TempWriteGrant.FIRST_REVISION)))
                    .get(label + " the differently cased key");
            }
            excluded.get(label + " the excluded revoke");
            Assertions.assertTrue(parked, label + ": a reader of an equal key built elsewhere must hold the revoke back");
            Assertions.assertEquals(TempWriteMutationStatus.COMMITTED, lowerResult.status(),
                label + ": a key that differs in case is another key and must not be held back");
        }
    }

    /**
     * KL-9 (I12): a commit that never took the key lock is still refused - the coordinator retries and the fixed start revision stops it
     * <p>
     * The key lock orders the writers that take it. A row written without it - by another process, or by
     * a path that does not go through the coordinator - is kept out by the compare-and-set and by the
     * start revision the request carries, which a retry must not refresh. Here such a commit is injected
     * on its own connection just as the first attempt is about to write: the write misses (no row at the
     * read revision, or a primary-key collision), the coordinator looks again, sees the revision moved and
     * refuses. A grant that refreshed the revision on retry would commit over the revoke and bring the
     * permission back; a revoke that did would take away a grant issued after the one it was asked to end.
     */
    @Test
    public void kl9ACommitThatBypassesTheKeyLockIsRefusedOnRetry() throws Exception {
        String current = DbacSchemaConstants.TABLE_TW_CURRENT.toUpperCase(Locale.ROOT);
        for (Engine engine : engines()) {
            String label = "KL-9 [" + engine.name() + " revoke committed under a grant]";
            TempWritePermissionKey key = key("kl9-revoked");
            commitGrant(engine, key, TempWriteGrant.NO_ROW_REVISION);
            AtomicInteger updates = new AtomicInteger();
            Hooks hooks = new Hooks();
            hooks.before = sql -> {
                if (KeyLockTestSupport.normalized(sql).startsWith("UPDATE " + current) && updates.getAndIncrement() == 0) {
                    commitRevokeWithoutTheLock(engine, key);
                }
            };
            TempWriteMutationResult late = coordinator(engine, hooks).grant(grantRequest(key, TempWriteGrant.FIRST_REVISION, "late"));
            Assertions.assertTrue(updates.get() >= 1, "FIXTURE " + label + ": the grant never reached its write");
            Assertions.assertEquals(TempWriteMutationStatus.CONFLICT_SUPERSEDED, late.status(),
                label + ": a grant whose read revision was revoked behind it must be refused, not committed over the revoke");
            Assertions.assertEquals(2, late.attempts(), label + ": the refusal must come from the retry, after the missed write");
            Assertions.assertEquals(1, updates.get(), label + ": the refused grant must not write again");
            try (Connection connection = engine.source().openConnection()) {
                TempWriteGrant stored = repository.findCurrent(connection, key).orElseThrow();
                Assertions.assertTrue(stored.isRevoked(), label + ": the revoke must stand");
                Assertions.assertEquals(2L, stored.revision(), label + ": revision");
                Assertions.assertEquals(List.of("GRANTED@1", "REVOKED@2"), TempWriteTestSupport.historyOf(connection, key),
                    label + ": the refused grant must leave no history");
            }

            label = "KL-9 [" + engine.name() + " first grant committed under a grant]";
            TempWritePermissionKey fresh = key("kl9-inserted");
            AtomicInteger inserts = new AtomicInteger();
            AtomicReference<String> injectedGrantId = new AtomicReference<>();
            Hooks insertHooks = new Hooks();
            insertHooks.before = sql -> {
                if (KeyLockTestSupport.normalized(sql).startsWith("INSERT INTO " + current) && inserts.getAndIncrement() == 0) {
                    injectedGrantId.set(commitGrantWithoutTheLock(engine, fresh));
                }
            };
            TempWriteMutationResult second = coordinator(engine, insertHooks).grant(
                grantRequest(fresh, TempWriteGrant.NO_ROW_REVISION, "late first"));
            Assertions.assertNotNull(injectedGrantId.get(), "FIXTURE " + label + ": the grant never reached its insert");
            Assertions.assertEquals(TempWriteMutationStatus.CONFLICT_SUPERSEDED, second.status(),
                label + ": a first grant that collided with a committed one must be refused, not written over it");
            Assertions.assertEquals(2, second.attempts(), label + ": the refusal must come from the retry, after the collision");
            Assertions.assertEquals(1, inserts.get(), label + ": the refused grant must not insert again");
            Assertions.assertEquals(0, insertHooks.count("UPDATE " + current), label + ": the refused grant must not update the row");
            try (Connection connection = engine.source().openConnection()) {
                TempWriteGrant stored = repository.findCurrent(connection, fresh).orElseThrow();
                Assertions.assertEquals(injectedGrantId.get(), stored.grantId(), label + ": the committed grant must stand");
                Assertions.assertEquals(TempWriteGrant.FIRST_REVISION, stored.revision(), label + ": revision");
                Assertions.assertEquals(List.of("GRANTED@1"), TempWriteTestSupport.historyOf(connection, fresh),
                    label + ": the refused grant must leave no history");
            }

            label = "KL-9 [" + engine.name() + " grant committed under a revoke]";
            TempWritePermissionKey superseded = key("kl9-superseded");
            commitGrant(engine, superseded, TempWriteGrant.NO_ROW_REVISION);
            AtomicInteger revokeUpdates = new AtomicInteger();
            AtomicReference<String> newGrantId = new AtomicReference<>();
            Hooks revokeHooks = new Hooks();
            revokeHooks.before = sql -> {
                if (KeyLockTestSupport.normalized(sql).startsWith("UPDATE " + current) && revokeUpdates.getAndIncrement() == 0) {
                    newGrantId.set(commitSupersedeWithoutTheLock(engine, superseded));
                }
            };
            TempWriteMutationResult lateRevoke = coordinator(engine, revokeHooks).revoke(
                revokeRequest(superseded, TempWriteGrant.FIRST_REVISION));
            Assertions.assertNotNull(newGrantId.get(), "FIXTURE " + label + ": the revoke never reached its write");
            Assertions.assertEquals(TempWriteMutationStatus.CONFLICT_SUPERSEDED, lateRevoke.status(),
                label + ": a revoke of revision 1 must be refused once a newer grant replaced it, not revoke that grant");
            Assertions.assertEquals(2, lateRevoke.attempts(), label + ": the refusal must come from the retry, after the missed write");
            Assertions.assertEquals(1, revokeUpdates.get(), label + ": the refused revoke must not write again");
            try (Connection connection = engine.source().openConnection()) {
                TempWriteGrant stored = repository.findCurrent(connection, superseded).orElseThrow();
                Assertions.assertEquals(newGrantId.get(), stored.grantId(), label + ": the newer grant must stand");
                Assertions.assertFalse(stored.isRevoked(), label + ": the newer grant must not be revoked");
                Assertions.assertEquals(2L, stored.revision(), label + ": revision");
                Assertions.assertEquals(List.of("GRANTED@1", "GRANTED@2", "SUPERSEDED@2"),
                    TempWriteTestSupport.historyOf(connection, superseded), label + ": the refused revoke must leave no history");
            }
        }
    }

    // ---------------------------------------------------------------- KR

    /**
     * KR-1: there is one registry and nothing can make another
     */
    @Test
    public void kr1TheRegistryIsOneInstance() {
        Assertions.assertSame(EnforcementKeyLocks.global(), EnforcementKeyLocks.global(), "KR-1: global() must return one instance");
        Assertions.assertTrue(Modifier.isFinal(EnforcementKeyLocks.class.getModifiers()), "KR-1: the registry class must be final");
        for (Constructor<?> constructor : EnforcementKeyLocks.class.getDeclaredConstructors()) {
            Assertions.assertTrue(Modifier.isPrivate(constructor.getModifiers()), "KR-1: every constructor must be private");
        }
    }

    /**
     * KR-2: a timed read needs a positive timeout no longer than the T_k ceiling, and an identity
     */
    @Test
    public void kr2TimedReadsRefuseBadTimeoutsAndIdentities() throws Exception {
        EnforcementKeyLocks locks = EnforcementKeyLocks.global();
        DbAccessKey key = new DbAccessKey("dbac-p4-kr2-" + System.nanoTime(), PROJECT, CONNECTION);
        String user = key.userId();
        List<Duration> bad = new ArrayList<>(List.of(Duration.ZERO, Duration.ofNanos(-1), Duration.ofSeconds(-5),
            EnforcementKeyLocks.MAX_READ_TIMEOUT.plusNanos(1)));
        bad.add(null);
        for (Duration timeout : bad) {
            Assertions.assertThrows(IllegalArgumentException.class, () -> locks.tryLockGrantForRead(key, timeout),
                "KR-2: a grant read must refuse timeout " + timeout);
            Assertions.assertThrows(IllegalArgumentException.class, () -> locks.tryLockUserForRead(user, timeout),
                "KR-2: a user read must refuse timeout " + timeout);
        }
        Assertions.assertThrows(IllegalArgumentException.class, () -> locks.tryLockGrantForRead(null, Duration.ofSeconds(1)),
            "KR-2: a grant read needs a key");
        Assertions.assertThrows(IllegalArgumentException.class, () -> locks.tryLockUserForRead(null, Duration.ofSeconds(1)),
            "KR-2: a user read needs a user");
        Assertions.assertThrows(IllegalArgumentException.class, () -> locks.lockGrantForWrite(null), "KR-2: a grant write needs a key");
        Assertions.assertThrows(IllegalArgumentException.class, () -> locks.lockUserForWrite(null), "KR-2: a user write needs a user");
        try (EnforcementKeyLocks.Held held = locks.tryLockGrantForRead(key, EnforcementKeyLocks.MAX_READ_TIMEOUT)) {
            Assertions.assertNotNull(held, "KR-2: the ceiling itself is a valid timeout");
        }
        Assertions.assertEquals(EnforcementKeyLocks.MAX_READ_TIMEOUT, policyConfig(EnforcementKeyLocks.MAX_READ_TIMEOUT).keyLockTimeout(),
            "KR-2: the policy configuration must accept the registry's ceiling as T_k");
        Assertions.assertThrows(IllegalArgumentException.class, () -> policyConfig(EnforcementKeyLocks.MAX_READ_TIMEOUT.plusMillis(1)),
            "KR-2: the registry's ceiling must be the policy configuration's ceiling for T_k");
    }

    @NotNull
    private static DbAccessPolicyConfig policyConfig(@NotNull Duration keyLockTimeout) {
        return new DbAccessPolicyConfig(
            DbAccessPolicyConfig.DEFAULT_CLOCK_SKEW_THRESHOLD,
            DbAccessPolicyConfig.DEFAULT_MAX_GRANT_DURATION,
            DbAccessPolicyConfig.DEFAULT_EXPIRY_GUARD_MARGIN,
            DbAccessPolicyConfig.DEFAULT_AUDIT_TIMEOUT,
            keyLockTimeout);
    }

    /**
     * KR-3: every lock is fair and kept once made; a queued writer holds back a new timed reader
     */
    @Test
    public void kr3LocksAreFairAndKept() throws Exception {
        DbAccessKey key = new DbAccessKey("dbac-p4-kr3-" + System.nanoTime(), PROJECT, CONNECTION);
        String user = key.userId();
        Assertions.assertTrue(KeyLockTestSupport.grantReadable(key), "FIXTURE: KR-3 the key is free");
        Assertions.assertTrue(KeyLockTestSupport.userReadable(user), "FIXTURE: KR-3 the user is free");
        ReentrantReadWriteLock grantLock = lockFor(key);
        ReentrantReadWriteLock userLock = lockFor(user);
        Assertions.assertNotNull(grantLock, "KR-3: the registry must keep the key's lock after it was released");
        Assertions.assertNotNull(userLock, "KR-3: the registry must keep the user's lock after it was released");
        Assertions.assertTrue(grantLock.isFair(), "KR-3: the key's lock must be fair");
        Assertions.assertTrue(userLock.isFair(), "KR-3: the user's lock must be fair");
        Assertions.assertTrue(KeyLockTestSupport.grantReadable(key), "FIXTURE: KR-3 the key is free again");
        Assertions.assertSame(grantLock, lockFor(key), "KR-3: the same key must keep the same lock");
        Assertions.assertSame(userLock, lockFor(user), "KR-3: the same user must keep the same lock");
        for (ReentrantReadWriteLock lock : allLocks()) {
            Assertions.assertTrue(lock.isFair(), "KR-3: every lock in the registry must be fair");
        }

        CountDownLatch release = new CountDownLatch(1);
        Worker<Object> writer;
        boolean writerParked;
        boolean newReaderGotIn;
        try (Reader reader = Reader.ofGrant(key)) {
            writer = Worker.start("dbac-kr3-writer", () -> {
                try (EnforcementKeyLocks.Held ignored = EnforcementKeyLocks.global().lockGrantForWrite(key)) {
                    release.await(KeyLockTestSupport.TIMEOUT_SECONDS, TimeUnit.SECONDS);
                }
                return null;
            });
            writerParked = KeyLockTestSupport.awaitParked(writer.thread);
            newReaderGotIn = KeyLockTestSupport.grantReadable(key);
        } finally {
            release.countDown();
        }
        writer = waitFor(writer);
        Assertions.assertTrue(writerParked, "KR-3: a writer must queue behind a reader");
        Assertions.assertFalse(newReaderGotIn, "KR-3: a new timed reader must not overtake a queued writer");
        Assertions.assertTrue(KeyLockTestSupport.grantReadable(key), "KR-3: the key must be free again afterwards");
    }

    /**
     * KR-4: a timed read that times out or is interrupted leaves the lock as it was
     */
    @Test
    public void kr4AFailedOrInterruptedReadLeavesTheLockUsable() throws Exception {
        DbAccessKey key = new DbAccessKey("dbac-p4-kr4-" + System.nanoTime(), PROJECT, CONNECTION);
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch writing = new CountDownLatch(1);
        Worker<Object> writer = Worker.start("dbac-kr4-writer", () -> {
            try (EnforcementKeyLocks.Held ignored = EnforcementKeyLocks.global().lockGrantForWrite(key)) {
                writing.countDown();
                release.await(KeyLockTestSupport.TIMEOUT_SECONDS, TimeUnit.SECONDS);
            }
            return null;
        });
        boolean timedOut;
        Worker<EnforcementKeyLocks.Held> interrupted;
        boolean interruptedWaited;
        try {
            Assertions.assertTrue(writing.await(KeyLockTestSupport.TIMEOUT_SECONDS, TimeUnit.SECONDS), "FIXTURE: KR-4 writer");
            timedOut = !KeyLockTestSupport.grantReadable(key);
            interrupted = Worker.start("dbac-kr4-interrupted",
                () -> EnforcementKeyLocks.global().tryLockGrantForRead(key, Duration.ofSeconds(20)));
            interruptedWaited = KeyLockTestSupport.awaitParked(interrupted.thread);
            interrupted.thread.interrupt();
            Assertions.assertTrue(interrupted.awaitDone(), "KR-4: an interrupted timed read must return");
        } finally {
            release.countDown();
        }
        waitFor(writer);
        Assertions.assertTrue(timedOut, "KR-4: a timed read must fail while a writer holds the key");
        Assertions.assertTrue(interruptedWaited, "KR-4: the interrupted read must have been waiting");
        Assertions.assertInstanceOf(InterruptedException.class, interrupted.error,
            "KR-4: an interrupted timed read throws InterruptedException");
        Assertions.assertNull(interrupted.result, "KR-4: an interrupted timed read holds nothing");
        ReentrantReadWriteLock lock = lockFor(key);
        Assertions.assertNotNull(lock, "KR-4: the lock must still be in the registry");
        Assertions.assertEquals(0, lock.getReadLockCount(), "KR-4: no read hold may be left behind");
        Assertions.assertFalse(lock.isWriteLocked(), "KR-4: no write hold may be left behind");
        Assertions.assertFalse(lock.hasQueuedThreads(), "KR-4: no waiter may be left behind");
        Assertions.assertTrue(KeyLockTestSupport.grantWritableElsewhere(key), "KR-4: a writer must get the key afterwards");
        Assertions.assertTrue(KeyLockTestSupport.grantReadable(key), "KR-4: a reader must get the key afterwards");
    }

    // ---------------------------------------------------------------- helpers

    @NotNull
    private static <V> Worker<V> waitFor(@NotNull Worker<V> worker) throws InterruptedException {
        Assertions.assertTrue(worker.awaitDone(), "FIXTURE: " + worker.thread.getName() + " did not finish");
        return worker;
    }

    /** The registry's lock for a key or user, found by reflection, or null when the registry keeps none */
    @org.jkiss.code.Nullable
    private static ReentrantReadWriteLock lockFor(@NotNull Object identity) throws IllegalAccessException {
        for (Field field : EnforcementKeyLocks.class.getDeclaredFields()) {
            if (Map.class.isAssignableFrom(field.getType())) {
                field.setAccessible(true);
                Object lock = ((Map<?, ?>) field.get(EnforcementKeyLocks.global())).get(identity);
                if (lock instanceof ReentrantReadWriteLock readWriteLock) {
                    return readWriteLock;
                }
            }
        }
        return null;
    }

    @NotNull
    private static List<ReentrantReadWriteLock> allLocks() throws IllegalAccessException {
        List<ReentrantReadWriteLock> locks = new ArrayList<>();
        for (Field field : EnforcementKeyLocks.class.getDeclaredFields()) {
            if (Map.class.isAssignableFrom(field.getType())) {
                field.setAccessible(true);
                for (Object lock : ((Map<?, ?>) field.get(EnforcementKeyLocks.global())).values()) {
                    if (lock instanceof ReentrantReadWriteLock readWriteLock) {
                        locks.add(readWriteLock);
                    }
                }
            }
        }
        return locks;
    }

    @NotNull
    private TempWritePermissionKey key(@NotNull String tag) {
        return remember(new TempWritePermissionKey("dbac-p4-" + tag + "-" + Long.toHexString(System.nanoTime()), PROJECT, CONNECTION));
    }

    @NotNull
    private TempWritePermissionKey remember(@NotNull TempWritePermissionKey key) {
        touched.add(key);
        return key;
    }

    @NotNull
    private TempWriteMutationCoordinator coordinator(@NotNull Engine engine, @NotNull Hooks hooks) {
        return TempWriteMutationCoordinator.withoutAuditing(KeyLockTestSupport.hooked(engine.source(), hooks), repository);
    }

    private void commitGrant(@NotNull Engine engine, @NotNull TempWritePermissionKey key, long startRevision) throws SQLException {
        TempWriteMutationResult result = coordinator(engine, new Hooks()).grant(grantRequest(key, startRevision, "setup"));
        Assertions.assertEquals(TempWriteMutationStatus.COMMITTED, result.status(), "FIXTURE: the setup grant must commit");
    }

    @NotNull
    private static io.cloudbeaver.service.dbac.tempwrite.TempWriteGrantRequest grantRequest(
        @NotNull TempWritePermissionKey key,
        long startRevision,
        @NotNull String reason
    ) {
        return TempWriteTestSupport.grantRequest(key, startRevision, TempWriteTestSupport.DEFAULT_DURATION, reason);
    }

    @NotNull
    private static io.cloudbeaver.service.dbac.tempwrite.TempWriteRevokeRequest revokeRequest(
        @NotNull TempWritePermissionKey key,
        long startRevision
    ) {
        return TempWriteTestSupport.revokeRequest(key, startRevision);
    }

    /**
     * Revokes the key's current grant on a connection of its own, through the repository and without the key lock
     */
    private void commitRevokeWithoutTheLock(@NotNull Engine engine, @NotNull TempWritePermissionKey key) throws SQLException {
        try (Connection bypass = engine.source().openConnection()) {
            bypass.setAutoCommit(false);
            try {
                TempWriteGrant stored = repository.findCurrent(bypass, key).orElseThrow();
                MetadataDbTime now = MetadataDbClock.readNow(bypass);
                long revision = stored.revision() + 1;
                if (repository.revokeCurrentWithRevision(bypass, key, stored.revision(), revision, now, "dbac-p4-bypass", "KL-9") != 1) {
                    throw new SQLException("FIXTURE: the bypassing revoke did not apply");
                }
                repository.appendHistory(bypass, new TempWriteHistoryEvent(UUID.randomUUID().toString(), stored.grantId(),
                    TempWriteChangeType.REVOKED, now, key, "dbac-p4-bypass", stored.expiresAt(), "KL-9", revision));
                bypass.commit();
            } catch (SQLException | RuntimeException | Error e) {
                bypass.rollback();
                throw e;
            } finally {
                bypass.setAutoCommit(true);
            }
        }
    }

    /**
     * Replaces the key's current grant with a new one on a connection of its own, through the repository and without the key lock
     *
     * @return the new grant's id
     */
    @NotNull
    private String commitSupersedeWithoutTheLock(@NotNull Engine engine, @NotNull TempWritePermissionKey key) throws SQLException {
        try (Connection bypass = engine.source().openConnection()) {
            bypass.setAutoCommit(false);
            try {
                TempWriteGrant old = repository.findCurrent(bypass, key).orElseThrow();
                MetadataDbTime now = MetadataDbClock.readNow(bypass);
                long revision = old.revision() + 1;
                TempWriteGrant grant = TempWriteTestSupport.storedGrant(key, revision, now);
                if (repository.updateCurrentWithRevision(bypass, grant, old.revision()) != 1) {
                    throw new SQLException("FIXTURE: the bypassing supersede did not apply");
                }
                repository.appendHistory(bypass, new TempWriteHistoryEvent(UUID.randomUUID().toString(), old.grantId(),
                    TempWriteChangeType.SUPERSEDED, now, key, grant.grantedBy(), old.expiresAt(), grant.reason(), revision));
                repository.appendHistory(bypass, new TempWriteHistoryEvent(UUID.randomUUID().toString(), grant.grantId(),
                    TempWriteChangeType.GRANTED, now, key, grant.grantedBy(), grant.expiresAt(), grant.reason(), revision));
                bypass.commit();
                return grant.grantId();
            } catch (SQLException | RuntimeException | Error e) {
                bypass.rollback();
                throw e;
            } finally {
                bypass.setAutoCommit(true);
            }
        }
    }

    /**
     * Commits a first grant of the key on a connection of its own, through the repository and without the key lock
     *
     * @return the committed grant's id
     */
    @NotNull
    private String commitGrantWithoutTheLock(@NotNull Engine engine, @NotNull TempWritePermissionKey key) throws SQLException {
        try (Connection bypass = engine.source().openConnection()) {
            bypass.setAutoCommit(false);
            try {
                MetadataDbTime now = MetadataDbClock.readNow(bypass);
                TempWriteGrant grant = TempWriteTestSupport.storedGrant(key, TempWriteGrant.FIRST_REVISION, now);
                if (repository.insertCurrent(bypass, grant) != 1) {
                    throw new SQLException("FIXTURE: the bypassing grant did not apply");
                }
                repository.appendHistory(bypass, new TempWriteHistoryEvent(UUID.randomUUID().toString(), grant.grantId(),
                    TempWriteChangeType.GRANTED, now, key, grant.grantedBy(), grant.expiresAt(), grant.reason(), grant.revision()));
                bypass.commit();
                return grant.grantId();
            } catch (SQLException | RuntimeException | Error e) {
                bypass.rollback();
                throw e;
            } finally {
                bypass.setAutoCommit(true);
            }
        }
    }

    private boolean revoked(@NotNull Engine engine, @NotNull TempWritePermissionKey key) throws SQLException {
        try (Connection connection = engine.source().openConnection()) {
            return repository.findCurrent(connection, key).map(TempWriteGrant::isRevoked).orElse(false);
        }
    }
}
