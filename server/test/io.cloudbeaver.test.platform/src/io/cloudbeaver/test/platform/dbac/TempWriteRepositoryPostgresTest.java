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

import io.cloudbeaver.service.dbac.db.DbacSchemaConstants;
import io.cloudbeaver.service.dbac.db.DbacSchemaVersionManager;
import io.cloudbeaver.service.dbac.tempwrite.MetadataDbClock;
import io.cloudbeaver.service.dbac.tempwrite.MetadataDbTime;
import io.cloudbeaver.service.dbac.tempwrite.MetadataTransaction;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteGrant;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteGrantRepository;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteMutationCoordinator;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteMutationResult;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteMutationStatus;
import io.cloudbeaver.service.dbac.tempwrite.TempWritePermissionKey;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.jkiss.dbeaver.ext.postgresql.model.PostgreDialect;
import org.jkiss.dbeaver.model.connection.InternalDatabaseConfig;
import org.jkiss.dbeaver.model.impl.jdbc.exec.JDBCTransaction;
import org.jkiss.dbeaver.model.runtime.DBRProgressMonitor;
import org.jkiss.dbeaver.model.runtime.LoggingProgressMonitor;
import org.jkiss.dbeaver.model.sql.SQLDialect;
import org.jkiss.dbeaver.model.sql.db.InternalProxyConnection;
import org.jkiss.dbeaver.model.sql.schema.SQLSchemaManager;
import org.jkiss.utils.CommonUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/**
 * TEMP_WRITE persistence on PostgreSQL, where losing a compare-and-set behaves differently
 * <p>
 * H2 cannot show the behaviour that shapes the coordinator's error handling: PostgreSQL leaves a
 * transaction in {@code 25P02} after any failed statement, so every later statement in it fails too.
 * A build that retried inside the failed transaction would look correct on H2 and be broken here.
 * These tests drive that path with a real server and a real {@link PostgreDialect} install.
 * <p>
 * Runs only against a disposable PostgreSQL at the configured URL, never a shared or production
 * database. Start one with:
 * {@code docker run -d --name dbac-pg-test -e POSTGRES_PASSWORD=dbactest -e POSTGRES_DB=dbactest
 * -p 55432:5432 postgres:16-alpine}
 * <p>
 * <b>Required mode.</b> With {@code -Ddbac.test.postgres.required=true} an unusable database is a
 * failure rather than a skip, so "PostgreSQL verified" cannot be claimed by a run that skipped.
 */
public class TempWriteRepositoryPostgresTest {

    private static final String URL = System.getProperty(
        "dbac.test.postgres.url", "jdbc:postgresql://localhost:55432/dbactest");
    private static final String USER = System.getProperty("dbac.test.postgres.user", "postgres");
    private static final String PASSWORD = System.getProperty("dbac.test.postgres.password", "dbactest");

    private static final boolean REQUIRED =
        CommonUtils.toBoolean(System.getProperty("dbac.test.postgres.required"));

    private static final DBRProgressMonitor MONITOR = new LoggingProgressMonitor();
    private static final SQLDialect DIALECT = new PostgreDialect();

    private static final String SCHEMA = "dbac_pg_tempwrite";
    private static final String PROJECT = "tw-project";
    private static final String CONNECTION = "tw-connection";

    private static Driver driver;

    private final TempWriteGrantRepository repository = new TempWriteGrantRepository();

    @BeforeAll
    public static void installSchema() throws Exception {
        try {
            driver = loadDriver();
            try (Connection raw = connect(); Statement dbStat = raw.createStatement()) {
                dbStat.execute("DROP SCHEMA IF EXISTS " + SCHEMA + " CASCADE");
                dbStat.execute("CREATE SCHEMA " + SCHEMA);
            }
            InternalDatabaseConfig config = DbacTestSupport.config(null, SCHEMA);
            try (Connection raw = connect()) {
                Connection connection = new InternalProxyConnection(raw, config);
                connection.setAutoCommit(false);
                new SQLSchemaManager(
                    DbacSchemaConstants.SCHEMA_ID,
                    DbacTestSupport.realScriptSource(),
                    monitor -> connection,
                    new DbacSchemaVersionManager(
                        DbacSchemaConstants.CURRENT_SCHEMA_VERSION,
                        DbacSchemaConstants.SCHEMA_ID,
                        DbacTestSupport.realScriptSource()),
                    DIALECT,
                    DbacSchemaConstants.CURRENT_SCHEMA_VERSION,
                    DbacSchemaConstants.OBSOLETE_SCHEMA_VERSION,
                    config,
                    null).updateSchema(MONITOR);
            }
        } catch (Exception e) {
            if (REQUIRED) {
                throw new IllegalStateException(
                    "dbac.test.postgres.required=true but the disposable PostgreSQL at " + URL
                        + " is not usable: " + DbacTestSupport.describe(e), e);
            }
            String notice = "POSTGRESQL NOT VERIFIED: every test in TempWriteRepositoryPostgresTest was"
                + " skipped because " + URL + " is not usable (" + e.getMessage() + "). Re-run with"
                + " -Ddbac.test.postgres.required=true to turn this into a failure.";
            System.out.println("[DBAC] " + notice);
            Assumptions.abort(notice);
        }
    }

    @AfterAll
    public static void dropSchema() throws Exception {
        if (driver == null) {
            return;
        }
        try (Connection raw = connect(); Statement dbStat = raw.createStatement()) {
            dbStat.execute("DROP SCHEMA IF EXISTS " + SCHEMA + " CASCADE");
        }
    }

    // ---------------------------------------------------------------- compare-and-set

    @Test
    public void firstGrantInsertsAtRevisionOneAndIncrements() throws Exception {
        TempWritePermissionKey key = key("pg-revision");
        TempWriteMutationResult first = grant(key, TempWriteGrant.NO_ROW_REVISION, "first");
        Assertions.assertEquals(TempWriteMutationStatus.COMMITTED, first.status());
        Assertions.assertEquals(TempWriteGrant.FIRST_REVISION, first.revision());
        TempWriteMutationResult second = grant(key, TempWriteGrant.FIRST_REVISION, "second");
        Assertions.assertEquals(2L, second.revision());
        assertHistory(key, List.of("GRANTED@1", "GRANTED@2", "SUPERSEDED@2"));
    }

    @Test
    public void staleStartRevisionIsRefusedWithoutRetrying() throws Exception {
        TempWritePermissionKey key = key("pg-stale");
        grant(key, TempWriteGrant.NO_ROW_REVISION, "first");
        TempWriteMutationResult refused = grant(key, TempWriteGrant.NO_ROW_REVISION, "stale");
        Assertions.assertEquals(TempWriteMutationStatus.CONFLICT_SUPERSEDED, refused.status());
        Assertions.assertEquals(1, refused.attempts());
        assertHistory(key, List.of("GRANTED@1"));
    }

    @Test
    public void keysAreIsolatedByUserProjectAndConnection() throws Exception {
        TempWritePermissionKey granted = key("pg-scoped");
        grant(granted, TempWriteGrant.NO_ROW_REVISION, "scoped");
        try (Connection connection = open()) {
            Assertions.assertTrue(repository.findCurrent(connection, granted).isPresent());
            Assertions.assertTrue(repository.findCurrent(
                connection, new TempWritePermissionKey("pg-scoped-other", PROJECT, CONNECTION)).isEmpty());
            Assertions.assertTrue(repository.findCurrent(
                connection, new TempWritePermissionKey("pg-scoped", PROJECT, "other-conn")).isEmpty());
            Assertions.assertTrue(repository.findCurrent(
                connection, new TempWritePermissionKey("pg-scoped", "other-proj", CONNECTION)).isEmpty());
        }
    }

    // ---------------------------------------------------------------- aborted transaction

    /**
     * PostgreSQL really does abort the whole transaction after a duplicate key, as assumed
     * <p>
     * Characterisation, not a test of our code. If this ever stopped holding, the coordinator's
     * insistence on rolling back and opening a new transaction would be unnecessary rather than
     * wrong - but while it holds, retrying in place is not an option.
     */
    @Test
    public void failedStatementPoisonsTheRestOfTheTransaction() throws Exception {
        TempWritePermissionKey key = key("pg-aborted");
        grant(key, TempWriteGrant.NO_ROW_REVISION, "existing");
        try (Connection connection = open();
             JDBCTransaction txn = new JDBCTransaction(connection)
        ) {
            SQLException duplicate = Assertions.assertThrows(
                SQLException.class, () -> insertDuplicate(connection, key));
            Assertions.assertEquals("23505", duplicate.getSQLState());
            SQLException poisoned = Assertions.assertThrows(
                SQLException.class, () -> repository.findCurrent(connection, key));
            Assertions.assertEquals(
                DbacTestSupport.SQL_STATE_IN_FAILED_TRANSACTION, poisoned.getSQLState(),
                "PostgreSQL must report the transaction as aborted, which is why a retry needs a new one");
            txn.rollback();
            Assertions.assertTrue(
                repository.findCurrent(connection, key).isPresent(),
                "the same connection is usable again after an explicit rollback");
        }
    }

    /**
     * A primary key collision is survived by starting over, not by continuing
     */
    @Test
    public void concurrentGrantsLeaveOneWinnerAfterThePrimaryKeyCollision() throws Exception {
        TempWritePermissionKey key = key("pg-concurrent");
        CyclicBarrier barrier = new CyclicBarrier(2);
        List<TempWriteMutationResult> results = runBoth(
            () -> barrierCoordinator(barrier).grant(TempWriteTestSupport.grantRequest(
                key, TempWriteGrant.NO_ROW_REVISION, Duration.ofMinutes(30), "first")),
            () -> barrierCoordinator(barrier).grant(TempWriteTestSupport.grantRequest(
                key, TempWriteGrant.NO_ROW_REVISION, Duration.ofMinutes(60), "second")));
        long committed = results.stream().filter(TempWriteMutationResult::isCommitted).count();
        long refused = results.stream().filter(TempWriteMutationResult::isRefused).count();
        Assertions.assertEquals(1, committed, "exactly one writer may win: " + results);
        Assertions.assertEquals(1, refused, "exactly one writer must be refused: " + results);
        try (Connection connection = open()) {
            Assertions.assertEquals(1, TempWriteTestSupport.countCurrent(connection, key));
            Assertions.assertEquals(
                TempWriteGrant.FIRST_REVISION, TempWriteTestSupport.currentRevision(connection, key));
        }
        assertHistory(key, List.of("GRANTED@1"));
    }

    /**
     * A grant released after a revoke committed cannot resurrect the permission
     */
    @Test
    public void grantDelayedPastARevokeCannotResurrect() throws Exception {
        TempWritePermissionKey key = key("pg-delayed");
        grant(key, TempWriteGrant.NO_ROW_REVISION, "original");
        CountDownLatch hasRead = new CountDownLatch(1);
        CountDownLatch mayWrite = new CountDownLatch(1);
        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            final Future<TempWriteMutationResult> delayed = pool.submit(
                () -> pausedCoordinator(hasRead, mayWrite).grant(TempWriteTestSupport.grantRequest(
                    key, TempWriteGrant.FIRST_REVISION, Duration.ofMinutes(30), "delayed")));
            // Both halves forced: the grant has read revision 1 before the revoke starts, and cannot
            // write until the revoke has committed.
            Assertions.assertTrue(
                hasRead.await(30, TimeUnit.SECONDS), "the delayed grant never reached its write");
            Assertions.assertEquals(
                TempWriteMutationStatus.COMMITTED,
                coordinator().revoke(
                    TempWriteTestSupport.revokeRequest(key, TempWriteGrant.FIRST_REVISION)).status());
            mayWrite.countDown();
            Assertions.assertEquals(
                TempWriteMutationStatus.CONFLICT_SUPERSEDED,
                delayed.get(60, TimeUnit.SECONDS).status());
        } finally {
            pool.shutdownNow();
        }
        try (Connection connection = open()) {
            TempWriteGrant current = repository.findCurrent(connection, key).orElseThrow();
            Assertions.assertTrue(current.isRevoked(), "the revoke must still stand");
        }
        assertHistory(key, List.of("GRANTED@1", "REVOKED@2"));
    }

    // ---------------------------------------------------------------- atomicity and errors

    @Test
    public void historyFailureRollsBackTheCurrentRow() throws Exception {
        TempWritePermissionKey key = key("pg-history-fails");
        TempWriteMutationCoordinator failing = TempWriteMutationCoordinator.withoutAuditing(
            TempWriteTestSupport.failingOn(
                TempWriteRepositoryPostgresTest::open, TempWriteTestSupport.HISTORY_TABLE, "42601"),
            repository);
        Assertions.assertThrows(
            SQLException.class,
            () -> failing.grant(TempWriteTestSupport.grantRequest(
                key, TempWriteGrant.NO_ROW_REVISION, Duration.ofMinutes(30), "history")));
        try (Connection connection = open()) {
            Assertions.assertEquals(0, TempWriteTestSupport.countCurrent(connection, key));
        }
        assertHistory(key, List.of());
    }

    /**
     * When the rollback itself fails, nothing is stored and nothing is hidden
     * <p>
     * Worth running here as well as on H2, because PostgreSQL is where the transaction is already
     * aborted by the time the rollback is attempted. If restoring auto-commit committed the pending
     * write, this is the engine where a grant would be stored without its history event.
     */
    @Test
    public void rollbackFailureStoresNothingAndIsNotHidden() throws Exception {
        TempWritePermissionKey key = key("pg-rollback-fails");
        TempWriteTestSupport.RollbackFailureProbe probe = new TempWriteTestSupport.RollbackFailureProbe(
            TempWriteRepositoryPostgresTest::open, TempWriteTestSupport.HISTORY_TABLE, "42601");
        TempWriteMutationCoordinator coordinator = TempWriteMutationCoordinator.withoutAuditing(probe, repository);

        SQLException failure = Assertions.assertThrows(
            SQLException.class,
            () -> coordinator.grant(TempWriteTestSupport.grantRequest(
                key, TempWriteGrant.NO_ROW_REVISION, Duration.ofMinutes(30), "rollback")));

        System.out.println("[DBAC] PostgreSQL rollback-failure probe: " + probe.describe());
        Assertions.assertEquals("42601", failure.getSQLState(), "the original failure must reach the caller");
        Assertions.assertTrue(
            hasSqlState(failure.getSuppressed(), "08006"),
            "the rollback failure must be visible to the caller, not only in a log");
        Assertions.assertEquals(
            0, probe.autoCommitTrue.get(),
            "restoring auto-commit after a failed rollback would commit the pending write");
        Assertions.assertEquals(0, probe.commits.get(), "nothing may be committed");
        Assertions.assertEquals(1, probe.rollbacks.get(), "a failed rollback must not be retried");
        Assertions.assertEquals(
            1, probe.currentWrites.get(), "a failed rollback is terminal, so no new compare-and-set");
        Assertions.assertEquals(
            1, probe.opened.get(), "a poisoned connection must not be replaced and retried");
        Assertions.assertTrue(
            probe.aborts.get() >= 1,
            "close() must attempt to sever the poisoned connection rather than hand it back intact");
        try (Connection connection = open()) {
            Assertions.assertEquals(0, TempWriteTestSupport.countCurrent(connection, key));
        }
        assertHistory(key, List.of());
    }

    /**
     * A transaction nobody finished stores nothing on this engine either
     * <p>
     * Worth running on both: whether leaving auto-commit restoration to close() commits the pending
     * work is a driver behaviour, and the guarantee has to hold on the engine that actually runs in
     * production rather than only on the one the fast tests use.
     */
    @Test
    public void transactionNobodyFinishedStoresNothing() throws Exception {
        TempWritePermissionKey key = key("pg-abandoned");
        try (Connection connection = open();
             MetadataTransaction txn = new MetadataTransaction(connection)
        ) {
            MetadataDbTime dbNow = MetadataDbClock.readNow(connection);
            Assertions.assertEquals(
                1,
                repository.insertCurrent(
                    connection, TempWriteTestSupport.storedGrant(key, TempWriteGrant.FIRST_REVISION, dbNow)),
                "Precondition: the row must really have been written inside the transaction");
            // No commit(), no rollback().
        }
        try (Connection connection = open()) {
            Assertions.assertEquals(
                0, TempWriteTestSupport.countCurrent(connection, key),
                "closing without a decision must not commit the write");
        }
        assertHistory(key, List.of());
    }

    @Test
    public void unfinishedTransactionThatCannotRollBackIsSevered() throws Exception {
        TempWritePermissionKey key = key("pg-abandoned-stuck");
        TempWriteTestSupport.RollbackFailureProbe probe = new TempWriteTestSupport.RollbackFailureProbe(
            TempWriteRepositoryPostgresTest::open, "NO_SUCH_TABLE_FRAGMENT", "42601");
        try (Connection connection = probe.openConnection();
             MetadataTransaction txn = new MetadataTransaction(connection)
        ) {
            MetadataDbTime dbNow = MetadataDbClock.readNow(connection);
            repository.insertCurrent(
                connection, TempWriteTestSupport.storedGrant(key, TempWriteGrant.FIRST_REVISION, dbNow));
        }
        System.out.println("[DBAC] PostgreSQL abandoned-transaction probe: " + probe.describe());
        // Storage first, counters after: a regression here has to report itself as a stored row.
        try (Connection connection = open()) {
            Assertions.assertEquals(
                0, TempWriteTestSupport.countCurrent(connection, key),
                "closing without a decision must not commit the write");
        }
        assertHistory(key, List.of());
        Assertions.assertEquals(
            0, probe.autoCommitTrue.get(),
            "auto-commit must not be restored when the closing rollback failed");
        Assertions.assertEquals(0, probe.commits.get(), "nothing may be committed");
        Assertions.assertEquals(1, probe.rollbacks.get(), "close() must try exactly one rollback");
        Assertions.assertTrue(
            probe.aborts.get() >= 1,
            "close() must attempt to sever the connection; whether the driver honours abort is its own"
                + " business, and the pool's rollback-on-return covers the case where it does not");
    }

    /**
     * The same guarantee when the rollback fails with an unchecked exception rather than SQLException
     * <p>
     * Measured on this engine storing one grant row - with no history and no audit entry - back when
     * the poisoned state was decided inside {@code catch (SQLException)}.
     */
    @Test
    public void uncheckedRollbackFailureIsAlsoTerminal() throws Exception {
        assertRollbackFailureIsTerminal(
            key("pg-rollback-unchecked"), "unchecked",
            () -> new IllegalStateException("Injected unchecked rollback failure"));
    }

    @Test
    public void errorFromRollbackIsAlsoTerminal() throws Exception {
        assertRollbackFailureIsTerminal(
            key("pg-rollback-error"), "error",
            () -> new LinkageError("Injected Error from rollback"));
    }

    private void assertRollbackFailureIsTerminal(
        @NotNull TempWritePermissionKey key,
        @NotNull String reason,
        @NotNull Supplier<Throwable> injected
    ) throws Exception {
        TempWriteTestSupport.RollbackFailureProbe probe = new TempWriteTestSupport.RollbackFailureProbe(
            TempWriteRepositoryPostgresTest::open, TempWriteTestSupport.HISTORY_TABLE, "42601", injected);
        TempWriteMutationCoordinator coordinator = TempWriteMutationCoordinator.withoutAuditing(probe, repository);

        // Throwable, not SQLException, and the exception class asserted last: what the row looks
        // like is the invariant, and which class escaped is a detail. See the H2 counterpart.
        final Throwable thrown = Assertions.assertThrows(
            Throwable.class,
            () -> coordinator.grant(TempWriteTestSupport.grantRequest(
                key, TempWriteGrant.NO_ROW_REVISION, Duration.ofMinutes(30), reason)));

        System.out.println("[DBAC] PostgreSQL " + reason + " rollback-failure probe: " + probe.describe());
        try (Connection connection = open()) {
            Assertions.assertEquals(
                0, TempWriteTestSupport.countCurrent(connection, key),
                "a rollback failure of any exception class must store nothing");
        }
        assertHistory(key, List.of());
        Assertions.assertEquals(
            0, probe.autoCommitTrue.get(),
            "restoring auto-commit after a failed rollback would commit the pending write");
        Assertions.assertEquals(0, probe.commits.get(), "nothing may be committed");
        Assertions.assertTrue(probe.aborts.get() >= 1, "close() must attempt to sever the poisoned connection");
        Assertions.assertEquals(1, probe.rollbacks.get(), "a failed rollback must not be retried");
        Assertions.assertEquals(1, probe.currentWrites.get(), "a failed rollback is terminal");
        Assertions.assertEquals(1, probe.opened.get(), "a poisoned connection must not be replaced");

        SQLException failure = Assertions.assertInstanceOf(
            SQLException.class, thrown,
            "the original failure must reach the caller, not the rollback failure that followed it");
        Assertions.assertEquals("42601", failure.getSQLState());
        Throwable expected = injected.get();
        Assertions.assertTrue(
            java.util.Arrays.stream(failure.getSuppressed())
                .anyMatch(suppressed -> suppressed.getClass() == expected.getClass()),
            "the rollback failure must be attached to the failure the caller sees, got: "
                + java.util.Arrays.toString(failure.getSuppressed()));
    }

    @Test
    public void transientConflictBeyondTheRetryLimitFailsClosed() throws Exception {
        TempWritePermissionKey key = key("pg-retry");
        TempWriteMutationCoordinator alwaysContended = TempWriteMutationCoordinator.withoutAuditing(
            TempWriteTestSupport.failingOn(
                TempWriteRepositoryPostgresTest::open,
                "INSERT INTO " + TempWriteTestSupport.CURRENT_TABLE, "23505"),
            repository);
        TempWriteMutationResult result = alwaysContended.grant(TempWriteTestSupport.grantRequest(
            key, TempWriteGrant.NO_ROW_REVISION, Duration.ofMinutes(30), "contended"));
        Assertions.assertEquals(TempWriteMutationStatus.RETRY_EXHAUSTED, result.status());
        Assertions.assertEquals(
            TempWriteMutationCoordinator.MAX_TRANSIENT_RETRIES + 1, result.attempts());
        try (Connection connection = open()) {
            Assertions.assertEquals(0, TempWriteTestSupport.countCurrent(connection, key));
        }
    }

    // ---------------------------------------------------------------- clock

    /**
     * PostgreSQL's clock and its timestamp precision, pinned rather than assumed
     */
    @Test
    public void databaseClockAndPrecisionArePinned() throws Exception {
        TempWritePermissionKey key = key("pg-clock");
        Duration duration = Duration.ofMinutes(45);
        TempWriteMutationCoordinator coordinator = coordinator();
        coordinator.grant(TempWriteTestSupport.grantRequest(
            key, TempWriteGrant.NO_ROW_REVISION, duration, "clock"));
        try (Connection connection = open()) {
            TempWriteGrant stored = repository.findCurrent(connection, key).orElseThrow();
            Assertions.assertEquals(
                duration, Duration.between(stored.grantedAt().instant(), stored.expiresAt().instant()));
            MetadataDbTime dbNow = MetadataDbClock.readNow(connection);
            Assertions.assertTrue(stored.expiresAt().instant().isAfter(dbNow.instant()));
            int nanos = stored.grantedAt().stored().getNano();
            Assertions.assertEquals(
                0, nanos % 1000,
                "PostgreSQL keeps microseconds, so the nanosecond digits must be zero");
            System.out.println("[DBAC] PostgreSQL stored GRANTED_AT=" + stored.grantedAt().stored()
                + " nanos=" + nanos);
        }
    }

    // ---------------------------------------------------------------- time zone crossing

    /**
     * A grant written from one session time zone reads back as the same instant in another
     * <p>
     * This is the defect schema version 2 removes, tested in the direction that matters. With naive
     * {@code TIMESTAMP} the stored value was a wall clock rendered in the writing session's zone, and
     * the PostgreSQL driver takes that zone from the client JVM: a grant issued on a UTC node and
     * checked on an Asia/Seoul node was nine hours out. Both directions are exercised, because only
     * one of them extends a grant and it is not obvious in advance which.
     */
    @Test
    public void grantReadsBackAsTheSameInstantFromAnotherSessionZone() throws Exception {
        TempWritePermissionKey key = key("pg-tz-cross");
        Instant written;
        Instant expires;
        // A fresh connection per call: the coordinator owns and closes the one it is given.
        TempWriteMutationCoordinator.withoutAuditing(() -> openAt("UTC"), repository).grant(
            TempWriteTestSupport.grantRequest(
                key, TempWriteGrant.NO_ROW_REVISION, Duration.ofMinutes(45), "written in UTC"));
        try (Connection utc = openAt("UTC")) {
            TempWriteGrant stored = repository.findCurrent(utc, key).orElseThrow();
            written = stored.grantedAt().instant();
            expires = stored.expiresAt().instant();
        }
        for (String zone : new String[]{"Asia/Seoul", "America/New_York", "UTC"}) {
            try (Connection other = openAt(zone)) {
                TempWriteGrant seen = repository.findCurrent(other, key).orElseThrow();
                Assertions.assertEquals(
                    written, seen.grantedAt().instant(), "GRANTED_AT must not depend on " + zone);
                Assertions.assertEquals(
                    expires, seen.expiresAt().instant(), "EXPIRES_AT must not depend on " + zone);
            }
        }
        // And the other direction: written from Seoul, read from UTC.
        TempWritePermissionKey seoulKey = key("pg-tz-cross-seoul");
        Instant fromSeoul;
        TempWriteMutationCoordinator.withoutAuditing(() -> openAt("Asia/Seoul"), repository).grant(
            TempWriteTestSupport.grantRequest(
                seoulKey, TempWriteGrant.NO_ROW_REVISION, Duration.ofMinutes(45), "written in Seoul"));
        try (Connection seoul = openAt("Asia/Seoul")) {
            fromSeoul = repository.findCurrent(seoul, seoulKey).orElseThrow().expiresAt().instant();
        }
        try (Connection utc = openAt("UTC")) {
            Assertions.assertEquals(
                fromSeoul,
                repository.findCurrent(utc, seoulKey).orElseThrow().expiresAt().instant(),
                "a grant written from Asia/Seoul must expire at the same instant seen from UTC");
        }
    }

    /**
     * The in-database expiry comparison gives the same answer whatever zone the session runs in
     * <p>
     * Phase 2 compares {@code EXPIRES_AT > CURRENT_TIMESTAMP} inside the database. That is only sound
     * if both sides mean the same thing in every session, which is what a zoned column guarantees and
     * a naive one did not. Checked with a grant that has already expired and one that has not, so a
     * comparison that silently shifted would show up as a disagreement rather than as two "not yet
     * expired" answers.
     */
    @Test
    public void expiryComparisonIsTheSameInEverySessionZone() throws Exception {
        TempWritePermissionKey live = key("pg-tz-live");
        TempWriteMutationCoordinator.withoutAuditing(() -> openAt("UTC"), repository).grant(
            TempWriteTestSupport.grantRequest(
                live, TempWriteGrant.NO_ROW_REVISION, Duration.ofMinutes(45), "live"));
        TempWritePermissionKey expired = key("pg-tz-expired");
        TempWriteMutationCoordinator.withoutAuditing(() -> openAt("UTC"), repository).grant(
            TempWriteTestSupport.grantRequest(
                expired, TempWriteGrant.NO_ROW_REVISION, Duration.ofMinutes(45), "to be expired"));
        try (Connection utc = openAt("UTC")) {
            expireInThePast(utc, expired);
        }
        for (String zone : new String[]{"UTC", "Asia/Seoul", "America/New_York"}) {
            try (Connection other = openAt(zone)) {
                Assertions.assertTrue(
                    isUnexpiredInDatabase(other, live), "the live grant must read as live in " + zone);
                Assertions.assertFalse(
                    isUnexpiredInDatabase(other, expired),
                    "the expired grant must read as expired in " + zone);
            }
        }
    }

    /**
     * Two instants an hour apart across a DST fall-back stay an hour apart
     * <p>
     * The single-node half of the same defect. In {@code America/New_York} the wall clock repeats, so
     * 05:30Z and 06:30Z on 2026-11-01 both render as 01:30 - a naive column stored them as the same
     * value and a grant spanning that hour lived an hour longer than it was granted for. A zoned
     * column keeps them distinct, whatever zone the session uses to look.
     */
    @Test
    public void dstFallBackKeepsTwoInstantsDistinct() throws Exception {
        Instant before = Instant.parse("2026-11-01T05:30:00Z");
        Instant after = Instant.parse("2026-11-01T06:30:00Z");
        Assertions.assertEquals(
            LocalDateTime.of(2026, 11, 1, 1, 30),
            before.atZone(ZoneId.of("America/New_York")).toLocalDateTime(),
            "precondition: the two instants share a wall clock in New York");
        Assertions.assertEquals(
            LocalDateTime.of(2026, 11, 1, 1, 30),
            after.atZone(ZoneId.of("America/New_York")).toLocalDateTime(),
            "precondition: the two instants share a wall clock in New York");

        try (Connection newYork = openAt("America/New_York")) {
            storeProbeInstants(newYork, before, after);
            try (PreparedStatement dbStat = newYork.prepareStatement(
                "SELECT A, B FROM " + SCHEMA + ".DBAC_TZ_PROBE")
            ) {
                try (ResultSet dbResult = dbStat.executeQuery()) {
                    Assertions.assertTrue(dbResult.next());
                    Instant storedBefore = dbResult.getObject(1, OffsetDateTime.class).toInstant();
                    Instant storedAfter = dbResult.getObject(2, OffsetDateTime.class).toInstant();
                    Assertions.assertEquals(before, storedBefore);
                    Assertions.assertEquals(after, storedAfter);
                    Assertions.assertEquals(
                        Duration.ofHours(1), Duration.between(storedBefore, storedAfter),
                        "a zoned column must keep the two instants an hour apart");
                }
            }
            dropProbe(newYork);
        }
    }

    /**
     * A clock that cannot be read fails the request rather than falling back to the JVM
     */
    @Test
    public void clockFailureFailsClosed() throws Exception {
        TempWritePermissionKey key = key("pg-clock-fails");
        TempWriteMutationCoordinator coordinator = TempWriteMutationCoordinator.withoutAuditing(
            TempWriteTestSupport.failingOn(
                TempWriteRepositoryPostgresTest::open, "SELECT CURRENT_TIMESTAMP", "42601"),
            repository);
        Assertions.assertThrows(
            SQLException.class,
            () -> coordinator.grant(TempWriteTestSupport.grantRequest(
                key, TempWriteGrant.NO_ROW_REVISION, Duration.ofMinutes(30), "clock down")));
        try (Connection connection = open()) {
            Assertions.assertEquals(0, TempWriteTestSupport.countCurrent(connection, key));
        }
        assertHistory(key, List.of());
    }

    // ---------------------------------------------------------------- helpers

    @NotNull
    private TempWriteMutationResult grant(
        @NotNull TempWritePermissionKey key,
        long startRevision,
        @NotNull String reason
    ) throws SQLException {
        return coordinator().grant(TempWriteTestSupport.grantRequest(
            key, startRevision, Duration.ofMinutes(30), reason));
    }

    @NotNull
    private TempWriteMutationCoordinator coordinator() {
        return TempWriteMutationCoordinator.withoutAuditing(TempWriteRepositoryPostgresTest::open, repository);
    }

    @NotNull
    private TempWriteMutationCoordinator barrierCoordinator(@NotNull CyclicBarrier barrier) {
        return TempWriteMutationCoordinator.withoutAuditing(
            TempWriteTestSupport.barrierBeforeWrite(TempWriteRepositoryPostgresTest::open, barrier),
            repository);
    }

    @NotNull
    private TempWriteMutationCoordinator pausedCoordinator(
        @NotNull CountDownLatch hasRead,
        @NotNull CountDownLatch mayWrite
    ) {
        return TempWriteMutationCoordinator.withoutAuditing(
            TempWriteTestSupport.pauseBeforeWrite(TempWriteRepositoryPostgresTest::open, hasRead, mayWrite),
            repository);
    }

    private void assertHistory(
        @NotNull TempWritePermissionKey key,
        @NotNull List<String> expected
    ) throws SQLException {
        try (Connection connection = open()) {
            Assertions.assertEquals(expected, TempWriteTestSupport.historyOf(connection, key));
        }
    }

    /**
     * Whether any of these carries a given SQLSTATE
     */
    private static boolean hasSqlState(@NotNull Throwable[] candidates, @NotNull String sqlState) {
        for (Throwable candidate : candidates) {
            if (candidate instanceof SQLException sql && sqlState.equals(sql.getSQLState())) {
                return true;
            }
        }
        return false;
    }

    private static void insertDuplicate(
        @NotNull Connection connection,
        @NotNull TempWritePermissionKey key
    ) throws SQLException {
        try (PreparedStatement dbStat = connection.prepareStatement(
            "INSERT INTO " + TempWriteTestSupport.CURRENT_TABLE
                + " (USER_ID, PROJECT_ID, CONNECTION_ID, GRANT_ID, REVISION, GRANTED_BY, GRANTED_AT,"
                + " EXPIRES_AT, REASON, DRIVER_ID)"
                + " VALUES(?,?,?,?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,?,?)")
        ) {
            dbStat.setString(1, key.userId());
            dbStat.setString(2, key.projectId());
            dbStat.setString(3, key.connectionId());
            dbStat.setString(4, "duplicate");
            dbStat.setLong(5, 99L);
            dbStat.setString(6, "admin");
            dbStat.setString(7, "duplicate probe");
            dbStat.setString(8, "postgres-jdbc");
            dbStat.executeUpdate();
        }
    }

    @NotNull
    private static TempWritePermissionKey key(@NotNull String user) {
        return new TempWritePermissionKey(user, PROJECT, CONNECTION);
    }

    /**
     * Opens a metadata connection through the production proxy, so {@code {table_prefix}} is substituted
     */
    @NotNull
    private static Connection open() throws SQLException {
        return new InternalProxyConnection(connect(), DbacTestSupport.config(null, SCHEMA));
    }

    /**
     * Opens a metadata connection whose session runs in a chosen time zone
     * <p>
     * {@code SET TIME ZONE} is what the driver itself does at connect time from the client JVM's
     * default, so setting it explicitly reproduces a node in another zone without needing a second
     * JVM. That is the whole mechanism behind the version 1 defect.
     */
    @NotNull
    private static Connection openAt(@NotNull String zone) throws SQLException {
        Connection connection = open();
        try (Statement dbStat = connection.createStatement()) {
            dbStat.execute("SET TIME ZONE '" + zone + "'");
        }
        return connection;
    }

    /**
     * Whether the database itself considers this grant unexpired, using the Phase 2 comparison
     */
    private static boolean isUnexpiredInDatabase(
        @NotNull Connection connection,
        @NotNull TempWritePermissionKey key
    ) throws SQLException {
        try (PreparedStatement dbStat = connection.prepareStatement(
            "SELECT 1 FROM " + TempWriteTestSupport.CURRENT_TABLE
                + " WHERE USER_ID=? AND PROJECT_ID=? AND CONNECTION_ID=?"
                + " AND REVOKED_AT IS NULL AND EXPIRES_AT > CURRENT_TIMESTAMP")
        ) {
            dbStat.setString(1, key.userId());
            dbStat.setString(2, key.projectId());
            dbStat.setString(3, key.connectionId());
            try (ResultSet dbResult = dbStat.executeQuery()) {
                return dbResult.next();
            }
        }
    }

    /**
     * Moves a grant's expiry into the past, bypassing the coordinator on purpose
     */
    private static void expireInThePast(
        @NotNull Connection connection,
        @NotNull TempWritePermissionKey key
    ) throws SQLException {
        try (PreparedStatement dbStat = connection.prepareStatement(
            "UPDATE " + TempWriteTestSupport.CURRENT_TABLE + " SET EXPIRES_AT=?"
                + " WHERE USER_ID=? AND PROJECT_ID=? AND CONNECTION_ID=?")
        ) {
            dbStat.setObject(1, Instant.parse("2020-01-01T00:00:00Z").atOffset(ZoneOffset.UTC));
            dbStat.setString(2, key.userId());
            dbStat.setString(3, key.projectId());
            dbStat.setString(4, key.connectionId());
            dbStat.executeUpdate();
        }
    }

    private static void storeProbeInstants(
        @NotNull Connection connection,
        @NotNull Instant first,
        @NotNull Instant second
    ) throws SQLException {
        try (Statement dbStat = connection.createStatement()) {
            dbStat.execute("DROP TABLE IF EXISTS " + SCHEMA + ".DBAC_TZ_PROBE");
            dbStat.execute("CREATE TABLE " + SCHEMA + ".DBAC_TZ_PROBE"
                + " (A TIMESTAMP WITH TIME ZONE, B TIMESTAMP WITH TIME ZONE)");
        }
        try (PreparedStatement dbStat = connection.prepareStatement(
            "INSERT INTO " + SCHEMA + ".DBAC_TZ_PROBE VALUES(?,?)")
        ) {
            dbStat.setObject(1, first.atOffset(ZoneOffset.UTC));
            dbStat.setObject(2, second.atOffset(ZoneOffset.UTC));
            dbStat.executeUpdate();
        }
    }

    private static void dropProbe(@NotNull Connection connection) throws SQLException {
        try (Statement dbStat = connection.createStatement()) {
            dbStat.execute("DROP TABLE IF EXISTS " + SCHEMA + ".DBAC_TZ_PROBE");
        }
    }

    @NotNull
    private static Connection connect() throws SQLException {
        Connection connection = driver.connect(URL, credentials());
        if (connection == null) {
            throw new SQLException("The PostgreSQL driver did not accept " + URL);
        }
        return connection;
    }

    @NotNull
    private static Properties credentials() {
        Properties properties = new Properties();
        properties.setProperty("user", USER);
        properties.setProperty("password", PASSWORD);
        return properties;
    }

    @NotNull
    private static Driver loadDriver() throws Exception {
        File jar = findDriverJar();
        if (jar == null) {
            throw new IllegalStateException("PostgreSQL JDBC driver jar not found under deploy/drivers");
        }
        URLClassLoader loader = new URLClassLoader(
            new URL[]{jar.toURI().toURL()}, Driver.class.getClassLoader());
        return (Driver) Class.forName("org.postgresql.Driver", true, loader)
            .getDeclaredConstructor().newInstance();
    }

    @Nullable
    private static File findDriverJar() {
        File dir = new File(System.getProperty("user.dir"));
        for (int i = 0; i < 6 && dir != null; i++, dir = dir.getParentFile()) {
            File candidate = new File(dir, "deploy/drivers/postgresql");
            File[] jars = candidate.listFiles((d, name) ->
                name.startsWith("postgresql-") && name.endsWith(".jar"));
            if (jars != null && jars.length > 0) {
                return jars[0];
            }
        }
        return null;
    }

    @NotNull
    private static List<TempWriteMutationResult> runBoth(
        @NotNull Callable<TempWriteMutationResult> first,
        @NotNull Callable<TempWriteMutationResult> second
    ) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<TempWriteMutationResult> a = pool.submit(first);
            Future<TempWriteMutationResult> b = pool.submit(second);
            return List.of(a.get(60, TimeUnit.SECONDS), b.get(60, TimeUnit.SECONDS));
        } finally {
            pool.shutdownNow();
        }
    }
}
