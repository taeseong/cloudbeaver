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
import io.cloudbeaver.server.CBApplicationCE;
import io.cloudbeaver.service.security.CBEmbeddedSecurityController;
import io.cloudbeaver.service.security.EmbeddedSecurityControllerFactory;
import io.cloudbeaver.service.security.db.CBDatabase;
import io.cloudbeaver.test.platform.util.DBTestConstants;
import org.jkiss.code.NotNull;
import org.jkiss.dbeaver.DBException;
import org.jkiss.dbeaver.ModelPreferences;
import org.jkiss.dbeaver.model.DBPExclusiveResource;
import org.jkiss.dbeaver.model.connection.DBPConnectionConfiguration;
import org.jkiss.dbeaver.model.connection.DBPDriver;
import org.jkiss.dbeaver.model.exec.DBCExecutionContext;
import org.jkiss.dbeaver.model.exec.DBCExecutionPurpose;
import org.jkiss.dbeaver.model.exec.DBCInvalidatePhase;
import org.jkiss.dbeaver.model.exec.DBCSession;
import org.jkiss.dbeaver.model.exec.DBExecUtils;
import org.jkiss.dbeaver.model.impl.jdbc.JDBCExecutionContext;
import org.jkiss.dbeaver.model.preferences.DBPPreferenceStore;
import org.jkiss.dbeaver.model.qm.QMExecutionHandler;
import org.jkiss.dbeaver.model.qm.QMUtils;
import org.jkiss.dbeaver.model.runtime.DBRProgressMonitor;
import org.jkiss.dbeaver.model.runtime.LoggingProgressMonitor;
import org.jkiss.dbeaver.model.security.SMController;
import org.jkiss.dbeaver.registry.DataSourceProviderRegistry;
import org.jkiss.dbeaver.runtime.qm.DefaultExecutionHandler;
import org.jkiss.dbeaver.runtime.qm.QMRegistryImpl;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.lang.management.LockInfo;
import java.lang.management.ManagementFactory;
import java.lang.management.ThreadInfo;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * What Slice 4a assumes about the platform, pinned before anything is built on it
 * <p>
 * Every test here passes against today's code. Each one is the executable form of a claim the
 * Slice 4a design cites by file and line - that {@code setAutoCommit} returns early on its cache,
 * that closing a context waits on the context monitor, that a context reconnect keeps the endpoint
 * it was opened with - so that an upstream merge which changes one of them fails here, by name,
 * instead of silently removing a guarantee the enforcement code relies on.
 * <p>
 * The PostgreSQL cases use a scratch schema on the test target; nothing here touches a real
 * database.
 */
public class DbacPlatformContractTest {

    /**
     * CH-13: the public user-state methods of the embedded security controller, as of this fork
     * <p>
     * Full signatures - return type, name and parameter types - so that a new overload, a changed
     * parameter list or a changed return type is caught as well as a new name.
     */
    private static final Set<String> USER_STATE_SIGNATURES = new TreeSet<>(Set.of(
        "void deleteUser(java.lang.String)",
        "void deleteUserCredentials(java.lang.String,java.lang.String)",
        "void deleteUserTeams(java.lang.String,java.lang.String[])",
        "void enableUser(java.lang.String,boolean,java.lang.String,java.lang.String)",
        "java.util.List findActiveUserSessions(java.lang.String,java.time.LocalDateTime,boolean)"));
    private static final Pattern USER_STATE_NAME = Pattern.compile("(?i).*(enable|disable|delete).*user.*|.*active.*");

    private static EnforcementTestSupport.Fixtures fixtures;

    private final DBRProgressMonitor monitor = new LoggingProgressMonitor();

    @BeforeAll
    public static void startServer() throws Exception {
        CEAppStarter.startServerIfNotStarted();
        fixtures = EnforcementTestSupport.fixtures("ch", new LoggingProgressMonitor());
    }

    @AfterAll
    public static void deleteUsers() throws Exception {
        fixtures.afterAll();
    }

    /** A target owned by an ordinary user; the contract tests judge the platform, not a subject */
    @NotNull
    private EnforcementTestSupport.Target openTarget() throws Exception {
        EnforcementTestSupport.requirePostgres(monitor);
        return EnforcementTestSupport.openTarget(fixtures.user, monitor);
    }

    @NotNull
    private JDBCExecutionContext isolated(@NotNull EnforcementTestSupport.Target target) throws DBException {
        DBCExecutionContext context = target.instance().openIsolatedContext(monitor, "DBAC contract probe", null);
        return (JDBCExecutionContext) context;
    }

    // ---------------------------------------------------------------- autoCommit cache

    /**
     * CH-1: with the cache at true and JDBC at false, {@code setAutoCommit(true)} changes nothing
     * <p>
     * {@code JDBCExecutionContext:392-394}. This is why the Slice 4a autoCommit gate may not treat
     * a normal return as success and has to read the JDBC value again afterwards.
     */
    @Test
    public void ch01SetAutoCommitReturnsEarlyWhenTheCacheAlreadyAgrees() throws Exception {
        try (EnforcementTestSupport.Target target = openTarget()) {
            JDBCExecutionContext context = isolated(target);
            try {
                Connection jdbc = context.getConnection(monitor);
                Assertions.assertTrue(context.isAutoCommit(), "FIXTURE: a fresh context starts in auto-commit");
                jdbc.setAutoCommit(false);
                Assertions.assertTrue(context.isAutoCommit(), "CH-1: the cache must not follow a direct JDBC change");

                context.setAutoCommit(monitor, true);

                Assertions.assertFalse(jdbc.getAutoCommit(),
                    "CH-1: setAutoCommit(true) must return on the cached value and leave JDBC auto-commit at false");
            } finally {
                context.close();
            }
        }
    }

    /**
     * CH-2: rollback reaches JDBC whatever the cache says
     * <p>
     * {@code JDBCExecutionContext:474, :484}. The autoCommit postcondition failure path rolls back
     * before severing precisely because this call does not consult the cache.
     */
    @Test
    public void ch02RollbackReachesJdbcEvenWhenTheCacheSaysAutoCommit() throws Exception {
        try (EnforcementTestSupport.Target target = openTarget()) {
            JDBCExecutionContext context = isolated(target);
            try {
                Connection jdbc = context.getConnection(monitor);
                jdbc.setAutoCommit(false);
                EnforcementTestSupport.execute(jdbc, "UPDATE " + target.table() + " SET v = 2 WHERE id = 1");
                Assertions.assertEquals(2, EnforcementTestSupport.readValue(jdbc, target.schema),
                    "FIXTURE: the transaction must see its own change");
                Assertions.assertTrue(context.isAutoCommit(), "FIXTURE: the cache must still say auto-commit");

                try (DBCSession session = context.openSession(monitor, DBCExecutionPurpose.UTIL, "CH-2")) {
                    context.rollback(session, null);
                }

                Assertions.assertEquals(0, EnforcementTestSupport.readValue(jdbc, target.schema),
                    "CH-2: rollback must undo the change even though the cache says auto-commit");
            } finally {
                context.close();
            }
        }
    }

    /**
     * CH-3: a reconnect makes the cache and JDBC agree again
     * <p>
     * {@code JDBCExecutionContext:134-146, :259-265}. This is what lets a BLOCKED context recover
     * after a sever: the reconnect re-reads the auto-commit state rather than trusting the old one.
     */
    @Test
    public void ch03ReconnectReconcilesTheCacheWithJdbc() throws Exception {
        try (EnforcementTestSupport.Target target = openTarget()) {
            JDBCExecutionContext context = isolated(target);
            try {
                Connection before = context.getConnection(monitor);
                before.setAutoCommit(false);

                context.invalidateContext(monitor, DBCInvalidatePhase.BEFORE_INVALIDATE);
                context.invalidateContext(monitor, DBCInvalidatePhase.INVALIDATE);

                Connection after = context.getConnectionOrNull();
                Assertions.assertNotNull(after, "CH-3: the reconnect must produce a connection");
                Assertions.assertNotSame(before, after, "CH-3: the reconnect must replace the JDBC connection");
                Assertions.assertEquals(context.isAutoCommit(), after.getAutoCommit(),
                    "CH-3: after a reconnect the cache and JDBC must agree");
            } finally {
                context.close();
            }
        }
    }

    // ---------------------------------------------------------------- locks

    /**
     * CH-4: closing a context waits for whoever holds the context monitor
     * <p>
     * {@code JDBCExecutionContext:197}. The M lock in the Slice 4a design is this monitor.
     */
    @Test
    public void ch04CloseBlocksOnTheContextMonitor() throws Exception {
        try (EnforcementTestSupport.Target target = openTarget()) {
            JDBCExecutionContext context = isolated(target);
            CountDownLatch holding = new CountDownLatch(1);
            CountDownLatch release = new CountDownLatch(1);
            Thread holder = new Thread(() -> {
                synchronized (context) {
                    holding.countDown();
                    try {
                        release.await(30, TimeUnit.SECONDS);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }
            }, "dbac-ch4-holder");
            holder.start();
            Assertions.assertTrue(holding.await(10, TimeUnit.SECONDS), "FIXTURE: the holder did not take the monitor");

            Thread closer = new Thread(context::close, "dbac-ch4-closer");
            closer.start();
            final boolean blockedOnContext = awaitBlockedOn(closer, context);
            final boolean stillConnected = context.getConnectionOrNull() != null;
            release.countDown();
            closer.join(TimeUnit.SECONDS.toMillis(30));
            holder.join(TimeUnit.SECONDS.toMillis(5));

            Assertions.assertTrue(blockedOnContext, "CH-4: close must block on the context monitor");
            Assertions.assertTrue(stillConnected, "CH-4: the connection must survive while the monitor is held");
            Assertions.assertFalse(closer.isAlive(), "CH-4: close must finish once the monitor is released");
            Assertions.assertNull(context.getConnectionOrNull(), "CH-4: close must drop the connection");
        }
    }

    private static boolean awaitBlockedOn(@NotNull Thread thread, @NotNull Object monitorObject) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        int wanted = System.identityHashCode(monitorObject);
        while (System.nanoTime() < deadline) {
            if (thread.getState() == Thread.State.BLOCKED) {
                ThreadInfo info = ManagementFactory.getThreadMXBean().getThreadInfo(thread.threadId());
                LockInfo lock = info == null ? null : info.getLockInfo();
                if (lock != null && lock.getIdentityHashCode() == wanted) {
                    return true;
                }
            }
            Thread.sleep(10);
        }
        return false;
    }

    /**
     * CH-5: the instance exclusive lock is re-entrant for its holder and exclusive for everyone else
     * <p>
     * {@code SimpleExclusiveLock:52-58}. The X lock in the Slice 4a design is this lock, and the
     * sever path re-enters it from the thread that already holds it.
     */
    @Test
    public void ch05InstanceExclusiveLockIsReentrantAndExclusive() throws Exception {
        try (EnforcementTestSupport.Target target = openTarget()) {
            DBPExclusiveResource lock = target.instance().getExclusiveLock();
            ExecutorService owner = Executors.newSingleThreadExecutor();
            ExecutorService other = Executors.newSingleThreadExecutor();
            try {
                final Object first = owner.submit(lock::acquireExclusiveLock).get(10, TimeUnit.SECONDS);
                Object second = owner.submit(lock::acquireExclusiveLock).get(10, TimeUnit.SECONDS);

                Future<Object> contender = other.submit(lock::acquireExclusiveLock);
                Thread.sleep(500);
                final boolean excludedWhileHeldTwice = !contender.isDone();
                owner.submit(() -> lock.releaseExclusiveLock(second)).get(10, TimeUnit.SECONDS);
                Thread.sleep(300);
                final boolean excludedWhileHeldOnce = !contender.isDone();
                owner.submit(() -> lock.releaseExclusiveLock(first)).get(10, TimeUnit.SECONDS);
                Object acquired = contender.get(10, TimeUnit.SECONDS);
                other.submit(() -> lock.releaseExclusiveLock(acquired)).get(10, TimeUnit.SECONDS);

                Assertions.assertTrue(excludedWhileHeldTwice, "CH-5: another thread must not get the lock while it is held");
                Assertions.assertTrue(excludedWhileHeldOnce, "CH-5: releasing one of two holds must not free the lock");
            } finally {
                owner.shutdownNow();
                other.shutdownNow();
            }
        }
    }

    // ---------------------------------------------------------------- context identity

    /**
     * CH-6: a sever keeps the same context object and id, with no connection
     * <p>
     * {@code JDBCExecutionContext:254-257, :272-282}. BLOCKED state is keyed by context id, so a
     * sever must not produce a new context that escapes it.
     */
    @Test
    public void ch06SeverKeepsTheSameContextAndIdWithoutAConnection() throws Exception {
        try (EnforcementTestSupport.Target target = openTarget()) {
            JDBCExecutionContext context = isolated(target);
            try {
                final long id = context.getContextId();

                context.invalidateContext(monitor, DBCInvalidatePhase.BEFORE_INVALIDATE);

                Assertions.assertNull(context.getConnectionOrNull(), "CH-6: a sever must drop the connection");
                Assertions.assertTrue(Arrays.stream(target.instance().getAllContexts()).anyMatch(c -> c == context),
                    "CH-6: a severed context must stay in the instance's context list");
                Assertions.assertEquals(id, context.getContextId(), "CH-6: a sever must keep the context id");

                context.invalidateContext(monitor, DBCInvalidatePhase.INVALIDATE);
                Assertions.assertNotNull(context.getConnectionOrNull(), "CH-6: the same object must reconnect");
                Assertions.assertEquals(id, context.getContextId(), "CH-6: a reconnect must keep the context id");
            } finally {
                context.close();
            }
        }
    }

    /**
     * CH-7: a registered QM handler hears a real close, and not a sever or a reconnect
     * <p>
     * {@code AbstractExecutionContext:145-147}, {@code JDBCExecutionContext:204-207}. The taint
     * registry is cleaned by exactly this notification, so it has to fire on close and only on
     * close. If this fails the Slice 4a design stops for a decision (acceptance criterion 9).
     */
    @Test
    public void ch07QmHandlerHearsCloseButNotSeverOrReconnect() throws Exception {
        ConcurrentHashMap<Long, AtomicInteger> closes = new ConcurrentHashMap<>();
        QMExecutionHandler handler = new DefaultExecutionHandler() {
            @NotNull
            @Override
            public String getHandlerName() {
                return "DBAC contract probe";
            }

            @Override
            public void handleContextClose(@NotNull DBCExecutionContext context) {
                closes.computeIfAbsent(context.getContextId(), id -> new AtomicInteger()).incrementAndGet();
            }
        };
        QMUtils.registerHandler(handler);
        try (EnforcementTestSupport.Target target = openTarget()) {
            JDBCExecutionContext context = isolated(target);
            long id = context.getContextId();

            context.invalidateContext(monitor, DBCInvalidatePhase.BEFORE_INVALIDATE);
            context.invalidateContext(monitor, DBCInvalidatePhase.INVALIDATE);
            int afterSeverAndReconnect = closes.getOrDefault(id, new AtomicInteger()).get();

            context.close();
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (closes.getOrDefault(id, new AtomicInteger()).get() == 0 && System.nanoTime() < deadline) {
                Thread.sleep(10);
            }

            Assertions.assertEquals(0, afterSeverAndReconnect, "CH-7: a sever or reconnect must not be reported as a close");
            Assertions.assertEquals(1, closes.getOrDefault(id, new AtomicInteger()).get(),
                "CH-7: a real close must reach a handler registered through QMUtils exactly once");
        } finally {
            QMUtils.unregisterHandler(handler);
        }
    }

    /**
     * CH-8: context ids only grow
     * <p>
     * {@code AbstractExecutionContext:45, :66-67}. A registry keyed by id relies on an id never
     * being handed to a second context in the same JVM.
     */
    @Test
    public void ch08ContextIdsAreUniqueAndIncreasing() throws Exception {
        try (EnforcementTestSupport.Target target = openTarget()) {
            JDBCExecutionContext first = isolated(target);
            JDBCExecutionContext second = isolated(target);
            try {
                Assertions.assertTrue(second.getContextId() > first.getContextId(),
                    "CH-8: a later context must get a larger id");
            } finally {
                second.close();
                first.close();
            }
        }
    }

    // ---------------------------------------------------------------- recovery

    /**
     * CH-9: an error that is not a lost connection or aborted transaction is not retried
     * <p>
     * {@code DBExecUtils:229-233}. A Slice 4a denial must be this kind of error, or the Explain
     * gate would be re-run - and re-audited - by the platform's own retry loop.
     * <p>
     * A single attempt proves nothing if recovery happens to be off, so recovery is switched on
     * explicitly with one retry, a lost connection ({@code SQLState 08006},
     * {@code JDBCDataSource:793-798}) is shown to be retried under that same setting, and the
     * previous preferences are put back afterwards.
     */
    @Test
    public void ch09RecoveryDoesNotRetryAnOrdinaryError() throws Exception {
        try (EnforcementTestSupport.Target target = openTarget()) {
            DBPPreferenceStore store = target.container.getPreferenceStore();
            final boolean enabledWasDefault = store.isDefault(ModelPreferences.EXECUTE_RECOVER_ENABLED);
            final boolean enabledBefore = store.getBoolean(ModelPreferences.EXECUTE_RECOVER_ENABLED);
            final boolean retriesWereDefault = store.isDefault(ModelPreferences.EXECUTE_RECOVER_RETRY_COUNT);
            final int retriesBefore = store.getInt(ModelPreferences.EXECUTE_RECOVER_RETRY_COUNT);
            store.setValue(ModelPreferences.EXECUTE_RECOVER_ENABLED, true);
            store.setValue(ModelPreferences.EXECUTE_RECOVER_RETRY_COUNT, 1);
            try {
                Assertions.assertTrue(store.getBoolean(ModelPreferences.EXECUTE_RECOVER_ENABLED),
                    "FIXTURE CH-9: recovery could not be enabled");

                AtomicInteger recoverable = new AtomicInteger();
                EnforcementTestSupport.Outcome control = EnforcementTestSupport.run(() ->
                    DBExecUtils.tryExecuteRecover(monitor, target.container.getDataSource(), param -> {
                        if (recoverable.incrementAndGet() == 1) {
                            throw new InvocationTargetException(
                                new SQLException("DBAC contract probe: simulated connection loss", "08006"));
                        }
                    }));
                Assertions.assertEquals(2, recoverable.get(), "FIXTURE CH-9: with recovery on, a lost connection must be"
                    + " retried once, or this run cannot show that recovery was active: "
                    + EnforcementTestSupport.describe(control.error()));

                AtomicInteger attempts = new AtomicInteger();
                EnforcementTestSupport.Outcome outcome = EnforcementTestSupport.run(() ->
                    DBExecUtils.tryExecuteRecover(monitor, target.container.getDataSource(), param -> {
                        attempts.incrementAndGet();
                        throw new InvocationTargetException(new DBException("DBAC contract probe: not a recoverable error"));
                    }));

                Assertions.assertNotNull(outcome.error(), "CH-9: the ordinary error must propagate");
                Assertions.assertEquals(1, attempts.get(),
                    "CH-9: with recovery on and a retry available, an ordinary error must still be attempted once");
            } finally {
                if (enabledWasDefault) {
                    store.setToDefault(ModelPreferences.EXECUTE_RECOVER_ENABLED);
                } else {
                    store.setValue(ModelPreferences.EXECUTE_RECOVER_ENABLED, enabledBefore);
                }
                if (retriesWereDefault) {
                    store.setToDefault(ModelPreferences.EXECUTE_RECOVER_RETRY_COUNT);
                } else {
                    store.setValue(ModelPreferences.EXECUTE_RECOVER_RETRY_COUNT, retriesBefore);
                }
            }
            Assertions.assertEquals(enabledBefore, store.getBoolean(ModelPreferences.EXECUTE_RECOVER_ENABLED),
                "FIXTURE CH-9: the recovery preference was not restored");
            Assertions.assertEquals(retriesBefore, store.getInt(ModelPreferences.EXECUTE_RECOVER_RETRY_COUNT),
                "FIXTURE CH-9: the retry-count preference was not restored");
        }
    }

    /**
     * CH-10: a context reconnect keeps the endpoint the container connected with
     * <p>
     * {@code JDBCDataSource.openConnection:127-135}. This is the whole basis of the A5 revision (D1):
     * a declared-only configuration change cannot move a live context to a new endpoint, because
     * even a reconnect reads the resolved copy taken when the container connected.
     */
    @Test
    public void ch10ContextReconnectKeepsTheResolvedEndpoint() throws Exception {
        try (EnforcementTestSupport.Target target = openTarget()) {
            DBPConnectionConfiguration declared = target.container.getConnectionConfiguration();
            String declaredPort = declared.getHostPort();
            String resolvedPort = target.container.getActualConnectionConfiguration().getHostPort();
            JDBCExecutionContext context = isolated(target);
            try {
                declared.setHostPort("1");

                EnforcementTestSupport.Outcome reconnect = EnforcementTestSupport.run(() -> {
                    context.invalidateContext(monitor, DBCInvalidatePhase.BEFORE_INVALIDATE);
                    context.invalidateContext(monitor, DBCInvalidatePhase.INVALIDATE);
                    return null;
                });

                Assertions.assertNull(reconnect.error(), "CH-10: the reconnect must not use the changed declared port: "
                    + EnforcementTestSupport.describe(reconnect.error()));
                Connection after = context.getConnectionOrNull();
                Assertions.assertNotNull(after, "CH-10: the reconnect must succeed on the resolved endpoint");
                EnforcementTestSupport.execute(after, "SELECT 1");
                Assertions.assertEquals("1", target.container.getConnectionConfiguration().getHostPort(),
                    "FIXTURE: the declared configuration must carry the change");
                Assertions.assertEquals(resolvedPort, target.container.getActualConnectionConfiguration().getHostPort(),
                    "CH-10: the resolved configuration must be the one taken at connect time");
            } finally {
                declared.setHostPort(declaredPort);
                context.close();
            }
        }
    }

    // ---------------------------------------------------------------- server behaviour

    /**
     * CH-11: PostgreSQL aborts an open transaction when its session ends
     * <p>
     * Server behaviour, not driver behaviour, and assumed nowhere: a sever is only a safe way to
     * end a BLOCKED transaction because of this.
     */
    @Test
    public void ch11PostgresAbortsAnOpenTransactionOnClose() throws Exception {
        try (EnforcementTestSupport.Target target = openTarget();
             Connection observer = EnforcementTestSupport.openRawPostgres(monitor)) {
            Connection writer = EnforcementTestSupport.openRawPostgres(monitor);
            writer.setAutoCommit(false);
            EnforcementTestSupport.execute(writer, "UPDATE " + target.table() + " SET v = 11 WHERE id = 1");
            int pid = EnforcementTestSupport.backendPid(writer);
            writer.close();

            EnforcementTestSupport.awaitBackendGone(observer, pid);
            Assertions.assertEquals(0, EnforcementTestSupport.readValue(observer, target.schema),
                "CH-11: an uncommitted change must not survive the end of its session");
        }
    }

    /**
     * CH-12: an embedded H2 file cannot be opened by a second process under the default file lock
     * <p>
     * H2 documents this; nothing in this repository had measured it. The Slice 4a deployment guard
     * accepts an embedded-file H2 metadata database as single-process on the strength of it.
     */
    @Test
    public void ch12H2DefaultFileLockRefusesASecondProcess() throws Exception {
        DBPDriver h2 = DataSourceProviderRegistry.getInstance().findDriver(DBTestConstants.H2_EMBEDDED_DRIVER_ID_FULL);
        Assertions.assertNotNull(h2, "FIXTURE: the embedded H2 driver is not registered");
        Driver driver = h2.getDefaultDriverLoader().getDriverInstance(monitor);
        File jar = new File(driver.getClass().getProtectionDomain().getCodeSource().getLocation().toURI());
        Assertions.assertTrue(jar.isFile(), "FIXTURE: the H2 driver was not loaded from a jar file: " + jar);
        String java = ProcessHandle.current().info().command().orElse(null);
        Assertions.assertNotNull(java, "FIXTURE: cannot locate the running java executable");

        Path directory = Files.createTempDirectory("dbac-ch12");
        String url = "jdbc:h2:" + directory.resolve("probe").toAbsolutePath().toString().replace('\\', '/');
        Properties credentials = new Properties();
        credentials.setProperty("user", "sa");
        credentials.setProperty("password", "dbacch12");

        String[] locked;
        try (Connection held = driver.connect(url, credentials)) {
            Assertions.assertNotNull(held, "FIXTURE: H2 did not accept " + url);
            EnforcementTestSupport.execute(held, "CREATE TABLE IF NOT EXISTS probe (id INT)");
            locked = openInSecondJvm(java, jar, url);
        }
        String[] free = openInSecondJvm(java, jar, url);

        Assertions.assertNotEquals("0", locked[0], "CH-12: a second process must not open a locked H2 file: " + locked[1]);
        Assertions.assertTrue(locked[1].contains("90020") || locked[1].toLowerCase().contains("already in use"),
            "CH-12: the second process must fail because the file is locked: " + locked[1]);
        Assertions.assertEquals("0", free[0], "FIXTURE: the second process must open the file once it is free: " + free[1]);
    }

    @NotNull
    private static String[] openInSecondJvm(@NotNull String java, @NotNull File jar, @NotNull String url) throws Exception {
        Process process = new ProcessBuilder(java, "-cp", jar.getAbsolutePath(), "org.h2.tools.Shell",
            "-url", url, "-user", "sa", "-password", "dbacch12", "-sql", "SELECT 1")
            .redirectErrorStream(true)
            .start();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (InputStream stream = process.getInputStream()) {
            stream.transferTo(output);
        }
        if (!process.waitFor(60, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            return new String[]{"timeout", output.toString(StandardCharsets.UTF_8)};
        }
        return new String[]{String.valueOf(process.exitValue()), output.toString(StandardCharsets.UTF_8)};
    }

    // ---------------------------------------------------------------- security controller

    /**
     * CH-13: the signatures of the public user-state methods on the embedded security controller
     * <p>
     * The USER_INACTIVE hook overrides the disable and delete paths. A new public method that can
     * change whether a user is active - including a new overload of an existing name, or an
     * existing method whose parameters change - would bypass the hook, so a change to this set has
     * to fail loudly and be reviewed rather than be inherited silently in an upstream merge.
     */
    @Test
    public void ch13UserStateMethodSignaturesOfTheSecurityControllerAreKnown() {
        Set<String> actual = Arrays.stream(CBEmbeddedSecurityController.class.getMethods())
            .filter(method -> USER_STATE_NAME.matcher(method.getName()).matches())
            .map(DbacPlatformContractTest::signature)
            .collect(Collectors.toCollection(TreeSet::new));

        Assertions.assertEquals(USER_STATE_SIGNATURES, actual,
            "CH-13: the public user-state method signatures changed; review them against the USER_INACTIVE hook");
    }

    @NotNull
    private static String signature(@NotNull Method method) {
        return method.getReturnType().getTypeName() + " " + method.getName() + "("
            + Arrays.stream(method.getParameterTypes()).map(Class::getTypeName).collect(Collectors.joining(",")) + ")";
    }

    /**
     * CH-14: every security controller request builds a new controller over the one database
     * <p>
     * {@code EmbeddedSecurityControllerFactory:64, :69, :84}. There is no controller that owns the
     * database, which is why Slice 4a ties its lifecycle to the database object instead.
     */
    @Test
    public void ch14ControllersAreCreatedPerRequestOverOneDatabase() throws Exception {
        CBApplicationCE application = (CBApplicationCE) CEAppStarter.getTestApp();
        SMController first = application.createSecurityController(fixtures.user.session());
        SMController second = application.createSecurityController(fixtures.user.session());
        CBDatabase database = EmbeddedSecurityControllerFactory.getDbInstance();

        Assertions.assertNotSame(first, second, "CH-14: each request must build its own controller");
        Assertions.assertSame(database, databaseOf(first), "CH-14: the first controller must use the shared database");
        Assertions.assertSame(database, databaseOf(second), "CH-14: the second controller must use the shared database");
    }

    @NotNull
    private static Object databaseOf(@NotNull SMController controller) throws Exception {
        Assertions.assertTrue(controller instanceof CBEmbeddedSecurityController<?>,
            "FIXTURE: unexpected controller type " + controller.getClass().getName());
        Field field = CBEmbeddedSecurityController.class.getDeclaredField("database");
        field.setAccessible(true);
        return field.get(controller);
    }

    /**
     * CH-15: the database instance is initialised once and then kept
     * <p>
     * {@code EmbeddedSecurityControllerFactory:50-54}. Slice 4a's lifecycle holder can only reach
     * READY through the one initialisation, which this shows is the only one that happens.
     */
    @Test
    public void ch15DatabaseInstanceIsInitialisedOnce() throws Exception {
        CBDatabase before = EmbeddedSecurityControllerFactory.getDbInstance();
        ((CBApplicationCE) CEAppStarter.getTestApp()).createSecurityController(fixtures.user.session());
        CBDatabase after = EmbeddedSecurityControllerFactory.getDbInstance();

        Assertions.assertNotNull(before, "CH-15: the database must exist once the server is up");
        Assertions.assertSame(before, after, "CH-15: a later controller request must not initialise another database");
    }

    // ---------------------------------------------------------------- QM registry lifecycle

    /**
     * CH-16: unregistering never throws, before or after the registry is disposed
     * <p>
     * {@code QMRegistryImpl:67-87, :127-133}. Shutdown order between the QM registry and the
     * metadata database is not fixed, so the Slice 4a handler has to be removable in either order.
     */
    @Test
    public void ch16QmRegistryUnregisterIsSafeInEitherShutdownOrder() {
        QMRegistryImpl registry = new QMRegistryImpl(false);
        QMExecutionHandler handler = new DefaultExecutionHandler() {
            @NotNull
            @Override
            public String getHandlerName() {
                return "DBAC contract probe";
            }
        };

        Assertions.assertDoesNotThrow(() -> registry.unregisterHandler(handler),
            "CH-16: unregistering a handler that was never registered must not throw");
        registry.registerHandler(handler);
        registry.dispose();

        Assertions.assertNull(registry.getDefaultHandler(), "CH-16: dispose must drop the default handler");
        Assertions.assertDoesNotThrow(() -> registry.unregisterHandler(handler),
            "CH-16: unregistering after dispose must not throw");
    }

    /**
     * CH-17: a sever under a stale auto-commit cache still does not persist the open transaction
     * <p>
     * {@code JDBCExecutionContext:199} passes {@code doRollback = !isAutoCommit(false)} to
     * {@code JDBCDataSource.closeConnection:427-432}, so with the cache at true the platform closes
     * without rolling back. Whether it skipped the rollback cannot be observed from outside; what
     * can is that the change does not survive, which here depends on CH-11. The autoCommit
     * postcondition failure path rolls back explicitly before severing so that it does not depend on
     * this at all.
     */
    @Test
    public void ch17SeverUnderAStaleCacheDoesNotPersistTheTransaction() throws Exception {
        try (EnforcementTestSupport.Target target = openTarget();
             Connection observer = EnforcementTestSupport.openRawPostgres(monitor)) {
            JDBCExecutionContext context = isolated(target);
            try {
                Connection jdbc = context.getConnection(monitor);
                jdbc.setAutoCommit(false);
                EnforcementTestSupport.execute(jdbc, "UPDATE " + target.table() + " SET v = 17 WHERE id = 1");
                int pid = EnforcementTestSupport.backendPid(jdbc);
                Assertions.assertTrue(context.isAutoCommit(), "FIXTURE: the cache must still say auto-commit");

                context.invalidateContext(monitor, DBCInvalidatePhase.BEFORE_INVALIDATE);

                EnforcementTestSupport.awaitBackendGone(observer, pid);
                Assertions.assertEquals(0, EnforcementTestSupport.readValue(observer, target.schema),
                    "CH-17: a sever must not persist the open transaction");
            } finally {
                context.close();
            }
        }
    }
}
