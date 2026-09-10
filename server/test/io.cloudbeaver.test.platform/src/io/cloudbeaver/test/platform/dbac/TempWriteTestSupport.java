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
import io.cloudbeaver.service.dbac.tempwrite.EndpointSnapshot;
import io.cloudbeaver.service.dbac.tempwrite.MetadataConnectionSource;
import io.cloudbeaver.service.dbac.tempwrite.MetadataDbTime;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteGrant;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteGrantRequest;
import io.cloudbeaver.service.dbac.tempwrite.TempWritePermissionKey;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteRevokeRequest;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

/**
 * Shared fixtures for the TEMP_WRITE persistence tests
 * <p>
 * Two things here matter more than convenience. The connection wrappers let a test decide exactly
 * which statement fails and exactly when two writers meet, because the paths that decide whether a
 * state change is left half applied are not paths to leave to whatever a real race happens to
 * produce. And the barrier wrapper trips between the read and the write of a compare-and-set, which
 * is the only window where two grants genuinely contend - starting two threads and hoping is not a
 * concurrency test.
 * <p>
 * Deliberately not a JUnit class so the offline harness can use it too.
 */
final class TempWriteTestSupport {

    static final String CURRENT_TABLE = "{table_prefix}" + DbacSchemaConstants.TABLE_TW_CURRENT;
    static final String HISTORY_TABLE = "{table_prefix}" + DbacSchemaConstants.TABLE_TW_HISTORY;

    /** Long enough that nothing under test expires while a test runs. */
    static final Duration DEFAULT_DURATION = Duration.ofMinutes(30);

    private static final long BARRIER_TIMEOUT_SECONDS = 30;

    private TempWriteTestSupport() {
        // fixtures only
    }

    @NotNull
    static TempWritePermissionKey key(@NotNull String user, @NotNull String project, @NotNull String connection) {
        return new TempWritePermissionKey(user, project, connection);
    }

    /**
     * The endpoint every fixture grant is issued for
     * <p>
     * Matches the container {@code PolicyTestSupport} builds by default, so a policy test that uses
     * both fixtures is comparing an endpoint against itself unless it deliberately varies one field.
     */
    @NotNull
    static final EndpointSnapshot ENDPOINT = new EndpointSnapshot(
        "postgresql", "postgres-jdbc", "MANUAL", "db.internal.example", "5432", "customer_prod");

    /**
     * Builds a grant request whose start revision is fixed by the caller
     * <p>
     * The start revision is a test parameter on purpose: passing a stale one is how the refusal path
     * gets exercised without having to win a race first.
     */
    @NotNull
    static TempWriteGrantRequest grantRequest(
        @NotNull TempWritePermissionKey key,
        long observedRevisionAtRequestStart,
        @NotNull Duration duration,
        @NotNull String reason
    ) {
        return grantRequest(key, observedRevisionAtRequestStart, duration, reason, ENDPOINT);
    }

    /**
     * A grant request for an endpoint other than the default fixture's
     * <p>
     * Needed by any test whose connection is not the default PostgreSQL one: the grant records the
     * endpoint it was issued for, so granting with the default endpoint and then authorizing a
     * MySQL connection is a mismatch, not a permission.
     */
    @NotNull
    static TempWriteGrantRequest grantRequest(
        @NotNull TempWritePermissionKey key,
        long observedRevisionAtRequestStart,
        @NotNull Duration duration,
        @NotNull String reason,
        @NotNull EndpointSnapshot endpoint
    ) {
        return new TempWriteGrantRequest(
            key,
            "grant-" + UUID.randomUUID(),
            "admin-1",
            duration,
            reason,
            endpoint,
            observedRevisionAtRequestStart);
    }

    /**
     * A grant row ready to be written straight through the repository
     * <p>
     * For the tests that need to write inside a transaction they control themselves, rather than one
     * the coordinator opens and closes for them.
     */
    @NotNull
    static TempWriteGrant storedGrant(
        @NotNull TempWritePermissionKey key,
        long revision,
        @NotNull MetadataDbTime dbNow
    ) {
        return new TempWriteGrant(
            key, "grant-" + UUID.randomUUID(), revision, "admin-1",
            dbNow, dbNow.plus(DEFAULT_DURATION), "abandoned transaction probe",
            null, null, null, ENDPOINT);
    }

    @NotNull
    static TempWriteRevokeRequest revokeRequest(
        @NotNull TempWritePermissionKey key,
        long observedRevisionAtRequestStart
    ) {
        return new TempWriteRevokeRequest(key, "admin-2", "no longer needed", observedRevisionAtRequestStart);
    }

    // ---------------------------------------------------------------- direct reads

    /**
     * Counts current rows of one key, without going through the repository
     * <p>
     * Reading the table directly is the point: a test that used the code under test to check the code
     * under test would agree with a broken implementation.
     */
    static int countCurrent(@NotNull Connection connection, @NotNull TempWritePermissionKey key)
            throws SQLException {
        try (PreparedStatement dbStat = connection.prepareStatement(
            "SELECT COUNT(*) FROM " + CURRENT_TABLE + " WHERE USER_ID=? AND PROJECT_ID=? AND CONNECTION_ID=?")
        ) {
            bindKey(dbStat, key);
            try (ResultSet dbResult = dbStat.executeQuery()) {
                dbResult.next();
                return dbResult.getInt(1);
            }
        }
    }

    /**
     * Reads the history of one key as {@code CHANGE_TYPE@REVISION}, ordered by revision then type
     * <p>
     * Ordered by the columns rather than by insertion, so a replacement - which writes two rows sharing
     * one revision - compares deterministically.
     */
    @NotNull
    static List<String> historyOf(@NotNull Connection connection, @NotNull TempWritePermissionKey key)
            throws SQLException {
        List<String> events = new ArrayList<>();
        try (PreparedStatement dbStat = connection.prepareStatement(
            "SELECT CHANGE_TYPE, REVISION FROM " + HISTORY_TABLE
                + " WHERE USER_ID=? AND PROJECT_ID=? AND CONNECTION_ID=? ORDER BY REVISION, CHANGE_TYPE")
        ) {
            bindKey(dbStat, key);
            try (ResultSet dbResult = dbStat.executeQuery()) {
                while (dbResult.next()) {
                    events.add(dbResult.getString(1) + "@" + dbResult.getLong(2));
                }
            }
        }
        return events;
    }

    @Nullable
    static Long currentRevision(@NotNull Connection connection, @NotNull TempWritePermissionKey key)
            throws SQLException {
        try (PreparedStatement dbStat = connection.prepareStatement(
            "SELECT REVISION FROM " + CURRENT_TABLE + " WHERE USER_ID=? AND PROJECT_ID=? AND CONNECTION_ID=?")
        ) {
            bindKey(dbStat, key);
            try (ResultSet dbResult = dbStat.executeQuery()) {
                return dbResult.next() ? dbResult.getLong(1) : null;
            }
        }
    }

    /**
     * Removes every trace of a key so a test starts from a known state
     */
    static void deleteKey(@NotNull Connection connection, @NotNull TempWritePermissionKey key)
            throws SQLException {
        for (String table : new String[]{CURRENT_TABLE, HISTORY_TABLE}) {
            try (PreparedStatement dbStat = connection.prepareStatement(
                "DELETE FROM " + table + " WHERE USER_ID=? AND PROJECT_ID=? AND CONNECTION_ID=?")
            ) {
                bindKey(dbStat, key);
                dbStat.executeUpdate();
            }
        }
    }

    private static void bindKey(@NotNull PreparedStatement dbStat, @NotNull TempWritePermissionKey key)
            throws SQLException {
        dbStat.setString(1, key.userId());
        dbStat.setString(2, key.projectId());
        dbStat.setString(3, key.connectionId());
    }

    // ---------------------------------------------------------------- failure injection

    /**
     * Wraps a source so any statement whose SQL contains {@code fragment} fails with {@code sqlState}
     * <p>
     * Used to drive the rollback and retry paths. Which state is chosen decides which path: a state
     * the coordinator treats as contention makes it look again, anything else must propagate.
     */
    @NotNull
    static MetadataConnectionSource failingOn(
        @NotNull MetadataConnectionSource target,
        @NotNull String fragment,
        @NotNull String sqlState
    ) {
        return () -> intercept(target.openConnection(), sql -> {
            if (sql.contains(fragment)) {
                throw new SQLException("Injected failure for " + fragment, sqlState);
            }
        });
    }

    /**
     * Wraps a source so every writer waits at {@code barrier} just before its first write statement
     * <p>
     * This is the window that matters: both writers have already read the revision and neither has
     * written, so releasing them together produces a genuine primary key or row conflict rather than
     * two writes that merely happened on different threads.
     */
    @NotNull
    static MetadataConnectionSource barrierBeforeWrite(
        @NotNull MetadataConnectionSource target,
        @NotNull CyclicBarrier barrier
    ) {
        return () -> {
            boolean[] tripped = {false};
            return intercept(target.openConnection(), sql -> {
                if (!tripped[0] && isWrite(sql)) {
                    tripped[0] = true;
                    awaitBarrier(barrier);
                }
            });
        };
    }

    /**
     * A connection source that fails one statement and then fails every rollback, counting everything
     * <p>
     * Built for the one scenario that decides whether a half-written state can be stored: the current
     * row is written, the history insert fails, and the rollback that should undo the write fails too.
     * What happens next is not a matter of opinion - JDBC specifies that putting a connection with a
     * pending transaction into auto-commit mode commits that work - so the counters here record
     * whether anything did that.
     * <p>
     * The counters are the evidence. Asserting only on the final row counts would pass a build that
     * happened to lose the write for some other reason.
     */
    static final class RollbackFailureProbe implements MetadataConnectionSource {

        /** How many connections were handed out; more than one means a poisoned one was replaced. */
        final AtomicInteger opened = new AtomicInteger();

        /** How many times rollback was attempted; a poisoned transaction must not be retried. */
        final AtomicInteger rollbacks = new AtomicInteger();

        /** Any call here can commit the pending write, so it must stay at zero. */
        final AtomicInteger autoCommitTrue = new AtomicInteger();

        final AtomicInteger commits = new AtomicInteger();
        final AtomicInteger aborts = new AtomicInteger();
        final AtomicInteger closes = new AtomicInteger();

        /** Writes to the current table; more than one means a new compare-and-set was attempted. */
        final AtomicInteger currentWrites = new AtomicInteger();

        private final MetadataConnectionSource target;
        private final String failFragment;
        private final String failState;
        private final Supplier<Throwable> rollbackFailure;

        RollbackFailureProbe(
            @NotNull MetadataConnectionSource target,
            @NotNull String failFragment,
            @NotNull String failState
        ) {
            this(target, failFragment, failState,
                () -> new SQLException("Injected rollback failure", "08006"));
        }

        /**
         * A probe whose rollback fails in a way the test chooses
         * <p>
         * Parameterised because the guarantee under test must not depend on the exception class. A
         * driver that fails a rollback with an unchecked exception, or a JVM that fails it with an
         * {@code Error}, has to reach the same terminal state as a {@code SQLException} - and an
         * earlier version of this code reached it only for {@code SQLException}, so the partial write
         * was committed on every other route.
         *
         * @param rollbackFailure what {@code rollback()} throws
         */
        RollbackFailureProbe(
            @NotNull MetadataConnectionSource target,
            @NotNull String failFragment,
            @NotNull String failState,
            @NotNull Supplier<Throwable> rollbackFailure
        ) {
            this.target = target;
            this.failFragment = failFragment;
            this.failState = failState;
            this.rollbackFailure = rollbackFailure;
        }

        @NotNull
        @Override
        public Connection openConnection() throws SQLException {
            opened.incrementAndGet();
            Connection real = target.openConnection();
            return (Connection) Proxy.newProxyInstance(
                TempWriteTestSupport.class.getClassLoader(),
                new Class<?>[]{Connection.class},
                (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "rollback" -> {
                            rollbacks.incrementAndGet();
                            throw rollbackFailure.get();
                        }
                        case "setAutoCommit" -> {
                            if (Boolean.TRUE.equals(args[0])) {
                                autoCommitTrue.incrementAndGet();
                            }
                        }
                        case "commit" -> commits.incrementAndGet();
                        case "abort" -> aborts.incrementAndGet();
                        case "close" -> closes.incrementAndGet();
                        case "prepareStatement" -> {
                            String sql = String.valueOf(args[0]);
                            if (sql.startsWith("INSERT INTO " + CURRENT_TABLE)
                                || sql.startsWith("UPDATE " + CURRENT_TABLE)
                            ) {
                                currentWrites.incrementAndGet();
                            }
                            if (sql.contains(failFragment)) {
                                throw new SQLException("Injected statement failure", failState);
                            }
                        }
                        default -> { }
                    }
                    return invoke(real, method, args);
                });
        }

        @NotNull
        String describe() {
            return "opened=" + opened.get() + " rollbacks=" + rollbacks.get()
                + " setAutoCommit(true)=" + autoCommitTrue.get() + " commits=" + commits.get()
                + " aborts=" + aborts.get() + " closes=" + closes.get()
                + " currentWrites=" + currentWrites.get();
        }
    }

    /**
     * Wraps a source so any statement containing {@code fragment} throws an unchecked exception
     * <p>
     * Exists to reach the one path no {@code catch (SQLException)} can see. If the coordinator ever
     * lost its {@code finally} guard, an unchecked failure raised after a write and before the commit
     * would reach {@code JDBCTransaction.close()} with the transaction still open - and that method
     * only restores auto-commit, which JDBC turns into a commit of the pending work. The half-written
     * state would be stored. A test that only injects {@link SQLException} cannot detect that.
     */
    @NotNull
    static MetadataConnectionSource failingUncheckedOn(
        @NotNull MetadataConnectionSource target,
        @NotNull String fragment
    ) {
        return () -> intercept(target.openConnection(), sql -> {
            if (sql.contains(fragment)) {
                throw new IllegalStateException("Injected unchecked failure for " + fragment);
            }
        });
    }

    /**
     * Wraps a source so a writer announces that it has read, then waits to be let through
     * <p>
     * Both halves of the ordering are forced, which a single barrier cannot do. The hook fires on the
     * first write statement, and a writer only reaches one after it has read the revision - so
     * counting {@code hasRead} down there tells the other thread the read really happened. It then
     * blocks on {@code mayWrite} until that thread has committed whatever it wanted to commit first.
     * <p>
     * Without the first half, a slow writer could read the already-changed revision and be refused
     * before ever reaching the barrier. That still fails the test rather than passing it wrongly, but
     * it fails for the wrong reason.
     */
    @NotNull
    static MetadataConnectionSource pauseBeforeWrite(
        @NotNull MetadataConnectionSource target,
        @NotNull CountDownLatch hasRead,
        @NotNull CountDownLatch mayWrite
    ) {
        return () -> {
            boolean[] paused = {false};
            return intercept(target.openConnection(), sql -> {
                if (!paused[0] && isWrite(sql)) {
                    paused[0] = true;
                    hasRead.countDown();
                    awaitLatch(mayWrite);
                }
            });
        };
    }

    private static void awaitLatch(@NotNull CountDownLatch latch) throws SQLException {
        try {
            if (!latch.await(BARRIER_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                throw new SQLException("The write latch never released; the race was not reproduced");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new SQLException("Interrupted while waiting for the write latch", e);
        }
    }

    private static boolean isWrite(@NotNull String sql) {
        String upper = sql.toUpperCase(java.util.Locale.ROOT);
        return upper.startsWith("INSERT INTO") || upper.startsWith("UPDATE ");
    }

    private static void awaitBarrier(@NotNull CyclicBarrier barrier) throws SQLException {
        try {
            barrier.await(BARRIER_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new SQLException("Interrupted while waiting for the write barrier", e);
        } catch (BrokenBarrierException | TimeoutException e) {
            throw new SQLException("The write barrier never released; the race was not reproduced", e);
        }
    }

    /**
     * Returns a connection that runs {@code hook} with the SQL of every statement it prepares
     * <p>
     * Only {@code prepareStatement} is intercepted, which is every statement the repository issues -
     * it binds parameters everywhere and never uses a plain {@code Statement}.
     */
    @NotNull
    private static Connection intercept(@NotNull Connection target, @NotNull SqlHook hook) {
        return (Connection) Proxy.newProxyInstance(
            TempWriteTestSupport.class.getClassLoader(),
            new Class<?>[]{Connection.class},
            (proxy, method, args) -> {
                if ("prepareStatement".equals(method.getName()) && args != null && args.length > 0) {
                    hook.beforeStatement(String.valueOf(args[0]));
                }
                return invoke(target, method, args);
            });
    }

    @Nullable
    private static Object invoke(
        @NotNull Object target,
        @NotNull java.lang.reflect.Method method,
        @Nullable Object[] args
    ) throws Throwable {
        try {
            return method.invoke(target, args);
        } catch (InvocationTargetException e) {
            throw e.getTargetException();
        }
    }

    /**
     * What a wrapped connection does before preparing a statement
     */
    @FunctionalInterface
    interface SqlHook {

        /**
         * Called with the SQL about to be prepared
         *
         * @throws SQLException to make that statement fail
         */
        void beforeStatement(@NotNull String sql) throws SQLException;
    }

    // ---------------------------------------------------------------- misc

    /**
     * Runs a statement, for test setup that has to bypass the repository
     */
    static void execute(@NotNull Connection connection, @NotNull String sql) throws SQLException {
        try (Statement dbStat = connection.createStatement()) {
            dbStat.execute(sql);
        }
    }
}
