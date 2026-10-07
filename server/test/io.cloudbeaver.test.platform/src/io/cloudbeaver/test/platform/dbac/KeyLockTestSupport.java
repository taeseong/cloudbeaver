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

import io.cloudbeaver.auth.NoAuthCredentialsProvider;
import io.cloudbeaver.model.app.ServletApplication;
import io.cloudbeaver.model.app.ServletAuthApplication;
import io.cloudbeaver.model.config.SMControllerConfiguration;
import io.cloudbeaver.model.config.WebDatabaseConfig;
import io.cloudbeaver.service.dbac.db.DbacCBDatabase;
import io.cloudbeaver.service.dbac.db.DbacSchema;
import io.cloudbeaver.service.dbac.db.DbacSchemaConstants;
import io.cloudbeaver.service.dbac.db.DbacSchemaVersionManager;
import io.cloudbeaver.service.dbac.policy.DbAccessKey;
import io.cloudbeaver.service.dbac.policy.enforcement.EnforcementKeyLocks;
import io.cloudbeaver.service.dbac.tempwrite.MetadataConnectionSource;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteGrantRepository;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteMutationCoordinator;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteMutationResult;
import io.cloudbeaver.service.dbac.tempwrite.TempWritePermissionKey;
import io.cloudbeaver.service.security.CBEmbeddedSecurityController;
import io.cloudbeaver.service.security.db.CBDatabase;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.jkiss.dbeaver.ext.postgresql.model.PostgreDialect;
import org.jkiss.dbeaver.model.DBPExclusiveResource;
import org.jkiss.dbeaver.model.connection.InternalDatabaseConfig;
import org.jkiss.dbeaver.model.runtime.DBRProgressMonitor;
import org.jkiss.dbeaver.model.runtime.LoggingProgressMonitor;
import org.jkiss.dbeaver.model.sql.db.InternalProxyConnection;
import org.jkiss.dbeaver.model.sql.schema.SQLSchemaManager;
import org.junit.jupiter.api.Assertions;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Fixtures shared by the P4 lock tests
 * <p>
 * The tests decide by latches, barriers, thread states, lock probes and what a second connection
 * sees, never by how long something took. Everything that holds a lock in a test does it on a
 * thread of its own and releases it in a {@code finally}, because the registry is the one global
 * instance the production code uses: a lock leaked by one test would be seen by every later one
 * that used the same key. Keys and users are therefore unique per test.
 */
final class KeyLockTestSupport {

    static final long TIMEOUT_SECONDS = 30;
    /** How long a probe waits for a lock that is expected to be held by somebody else */
    static final Duration PROBE = Duration.ofMillis(200);
    /** How long a reader waits to get its lock in the first place */
    static final Duration READER_WAIT = Duration.ofSeconds(10);

    private static final int PARKED_POLLS = 10;
    private static final long POLL_MILLIS = 20;

    static final DBRProgressMonitor MONITOR = new LoggingProgressMonitor();

    private KeyLockTestSupport() {
    }

    // ---------------------------------------------------------------- threads

    /** Something to run on a worker thread */
    @FunctionalInterface
    interface Task<V> {
        @Nullable
        V run() throws Throwable;
    }

    /**
     * A task on its own thread, with what it returned or threw and its interrupt status on return
     */
    static final class Worker<V> {
        final Thread thread;
        final CountDownLatch done = new CountDownLatch(1);
        volatile V result;
        volatile Throwable error;
        volatile boolean interruptedOnReturn;

        Worker(@NotNull String name, @NotNull Task<V> task) {
            this.thread = new Thread(() -> {
                try {
                    result = task.run();
                } catch (Throwable e) {
                    error = e;
                } finally {
                    interruptedOnReturn = Thread.currentThread().isInterrupted();
                    done.countDown();
                }
            }, name);
        }

        @NotNull
        static <V> Worker<V> start(@NotNull String name, @NotNull Task<V> task) {
            Worker<V> worker = new Worker<>(name, task);
            worker.thread.start();
            return worker;
        }

        boolean finished() {
            return done.getCount() == 0;
        }

        /** Waits for the task; false when it did not finish in time */
        boolean awaitDone() throws InterruptedException {
            return done.await(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        }

        /** The result, after asserting the task finished without throwing */
        @Nullable
        V get(@NotNull String label) throws InterruptedException {
            Assertions.assertTrue(awaitDone(), label + ": the task did not finish - deadlock or lost wake-up");
            if (error != null) {
                Assertions.fail(label + ": the task threw " + error.getClass().getName(), error);
            }
            return result;
        }
    }

    /**
     * Whether {@code thread} is waiting - seen parked {@code PARKED_POLLS} times in a row - rather than finished
     */
    static boolean awaitParked(@NotNull Thread thread) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(TIMEOUT_SECONDS);
        int parked = 0;
        while (System.nanoTime() < deadline) {
            Thread.State state = thread.getState();
            if (state == Thread.State.TERMINATED) {
                return false;
            }
            parked = state == Thread.State.WAITING || state == Thread.State.TIMED_WAITING ? parked + 1 : 0;
            if (parked >= PARKED_POLLS) {
                return true;
            }
            Thread.sleep(POLL_MILLIS);
        }
        return false;
    }

    static void await(@NotNull CountDownLatch latch, @NotNull String what) throws SQLException {
        try {
            if (!latch.await(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                throw new SQLException("FIXTURE: " + what + " was never released");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new SQLException("FIXTURE: interrupted while waiting for " + what, e);
        }
    }

    // ---------------------------------------------------------------- lock probes

    /** Whether a timed read of the grant key succeeds now, from the calling thread */
    static boolean grantReadable(@NotNull DbAccessKey key) throws InterruptedException {
        try (EnforcementKeyLocks.Held held = EnforcementKeyLocks.global().tryLockGrantForRead(key, PROBE)) {
            return held != null;
        }
    }

    /** Whether a timed read of the user lock succeeds now, from the calling thread */
    static boolean userReadable(@NotNull String userId) throws InterruptedException {
        try (EnforcementKeyLocks.Held held = EnforcementKeyLocks.global().tryLockUserForRead(userId, PROBE)) {
            return held != null;
        }
    }

    /**
     * Whether a timed read of the grant key succeeds on another thread
     * <p>
     * The writer's own thread would get it by re-entry - a write holder may also read - so a probe of
     * whether a writer still holds its lock has to come from elsewhere.
     */
    static boolean grantReadableElsewhere(@NotNull DbAccessKey key) throws InterruptedException {
        Worker<Boolean> worker = Worker.start("dbac-p4-probe-grant-read", () -> grantReadable(key));
        Assertions.assertTrue(worker.awaitDone(), "FIXTURE: the read probe did not finish");
        return Boolean.TRUE.equals(worker.result);
    }

    /** Whether a timed read of the user lock succeeds on another thread */
    static boolean userReadableElsewhere(@NotNull String userId) throws InterruptedException {
        Worker<Boolean> worker = Worker.start("dbac-p4-probe-user-read", () -> userReadable(userId));
        Assertions.assertTrue(worker.awaitDone(), "FIXTURE: the read probe did not finish");
        return Boolean.TRUE.equals(worker.result);
    }

    /** Whether another thread can take and release the grant key's write lock within the probe time */
    static boolean grantWritableElsewhere(@NotNull DbAccessKey key) throws InterruptedException {
        Worker<Object> worker = Worker.start("dbac-p4-probe-grant-write", () -> {
            try (EnforcementKeyLocks.Held ignored = EnforcementKeyLocks.global().lockGrantForWrite(key)) {
                return Boolean.TRUE;
            }
        });
        return worker.done.await(PROBE.toMillis() * 5, TimeUnit.MILLISECONDS) && worker.error == null;
    }

    /** Whether another thread can take and release the user's write lock within the probe time */
    static boolean userWritableElsewhere(@NotNull String userId) throws InterruptedException {
        Worker<Object> worker = Worker.start("dbac-p4-probe-user-write", () -> {
            try (EnforcementKeyLocks.Held ignored = EnforcementKeyLocks.global().lockUserForWrite(userId)) {
                return Boolean.TRUE;
            }
        });
        return worker.done.await(PROBE.toMillis() * 5, TimeUnit.MILLISECONDS) && worker.error == null;
    }

    @NotNull
    static DbAccessKey accessKey(@NotNull TempWritePermissionKey key) {
        return new DbAccessKey(key.userId(), key.projectId(), key.connectionId());
    }

    /**
     * A future enforcement reader: holds a timed read lock on a thread of its own until released
     */
    static final class Reader implements AutoCloseable {
        private final CountDownLatch held = new CountDownLatch(1);
        private final CountDownLatch release = new CountDownLatch(1);
        private final Worker<Object> worker;
        private volatile boolean acquired;

        private Reader(@NotNull String name, @NotNull Task<EnforcementKeyLocks.Held> acquire) {
            this.worker = Worker.start(name, () -> {
                try (EnforcementKeyLocks.Held lock = acquire.run()) {
                    acquired = lock != null;
                    held.countDown();
                    if (lock != null) {
                        release.await(TIMEOUT_SECONDS * 4, TimeUnit.SECONDS);
                    }
                } finally {
                    held.countDown();
                }
                return null;
            });
        }

        @NotNull
        static Reader ofGrant(@NotNull DbAccessKey key) throws InterruptedException {
            Reader reader = new Reader("dbac-p4-reader-grant",
                () -> EnforcementKeyLocks.global().tryLockGrantForRead(key, READER_WAIT));
            reader.requireHeld();
            return reader;
        }

        @NotNull
        static Reader ofUser(@NotNull String userId) throws InterruptedException {
            Reader reader = new Reader("dbac-p4-reader-user",
                () -> EnforcementKeyLocks.global().tryLockUserForRead(userId, READER_WAIT));
            reader.requireHeld();
            return reader;
        }

        private void requireHeld() throws InterruptedException {
            Assertions.assertTrue(held.await(TIMEOUT_SECONDS, TimeUnit.SECONDS) && acquired,
                "FIXTURE: the simulated reader could not take its read lock");
        }

        void release() throws InterruptedException {
            release.countDown();
            Assertions.assertTrue(worker.awaitDone(), "FIXTURE: the simulated reader did not finish");
        }

        @Override
        public void close() throws InterruptedException {
            release();
        }
    }

    // ---------------------------------------------------------------- connection hooks

    /** What a hooked connection does around a statement */
    @FunctionalInterface
    interface Hook {
        Hook NONE = sql -> {
        };

        void on(@NotNull String sql) throws SQLException;
    }

    /** What a hooked connection does around a commit */
    @FunctionalInterface
    interface CommitHook {
        CommitHook NONE = () -> {
        };

        void on() throws SQLException;
    }

    /**
     * Records every statement a hooked connection runs and lets a test act before or after it
     */
    static final class Hooks {
        final AtomicInteger opened = new AtomicInteger();
        final List<String> statements = Collections.synchronizedList(new ArrayList<>());
        final List<Boolean> interruptedAtStatement = Collections.synchronizedList(new ArrayList<>());
        volatile Hook before = Hook.NONE;
        volatile Hook after = Hook.NONE;
        volatile CommitHook beforeCommit = CommitHook.NONE;
        volatile CommitHook afterCommit = CommitHook.NONE;

        @NotNull
        List<String> statements() {
            synchronized (statements) {
                return new ArrayList<>(statements);
            }
        }

        void reset() {
            opened.set(0);
            statements.clear();
            interruptedAtStatement.clear();
            before = Hook.NONE;
            after = Hook.NONE;
            beforeCommit = CommitHook.NONE;
            afterCommit = CommitHook.NONE;
        }

        long count(@NotNull String prefix) {
            return statements().stream().filter(sql -> normalized(sql).startsWith(prefix)).count();
        }

        boolean anyInterrupted() {
            synchronized (interruptedAtStatement) {
                return interruptedAtStatement.contains(Boolean.TRUE);
            }
        }
    }

    @NotNull
    static String normalized(@NotNull String sql) {
        return sql.trim().toUpperCase(Locale.ROOT).replace("{TABLE_PREFIX}", "");
    }

    static boolean isWrite(@NotNull String sql) {
        String upper = normalized(sql);
        return upper.startsWith("INSERT") || upper.startsWith("UPDATE") || upper.startsWith("DELETE");
    }

    @NotNull
    static MetadataConnectionSource hooked(@NotNull MetadataConnectionSource source, @NotNull Hooks hooks) {
        return () -> {
            hooks.opened.incrementAndGet();
            return hooked(source.openConnection(), hooks);
        };
    }

    @NotNull
    static Connection hooked(@NotNull Connection target, @NotNull Hooks hooks) {
        return (Connection) Proxy.newProxyInstance(
            KeyLockTestSupport.class.getClassLoader(),
            new Class<?>[]{Connection.class},
            (proxy, method, args) -> {
                String name = method.getName();
                if ("prepareStatement".equals(name) && args != null && args.length > 0 && args[0] instanceof String sql) {
                    PreparedStatement statement = (PreparedStatement) invoke(target, method, args);
                    return hookedStatement(statement, sql, hooks);
                }
                if ("commit".equals(name)) {
                    hooks.beforeCommit.on();
                    Object result = invoke(target, method, args);
                    hooks.afterCommit.on();
                    return result;
                }
                return invoke(target, method, args);
            });
    }

    @NotNull
    private static PreparedStatement hookedStatement(@NotNull PreparedStatement target, @NotNull String sql, @NotNull Hooks hooks) {
        return (PreparedStatement) Proxy.newProxyInstance(
            KeyLockTestSupport.class.getClassLoader(),
            new Class<?>[]{PreparedStatement.class},
            (proxy, method, args) -> {
                String name = method.getName();
                if (name.startsWith("execute") && (args == null || args.length == 0)) {
                    hooks.statements.add(sql);
                    hooks.interruptedAtStatement.add(Thread.currentThread().isInterrupted());
                    hooks.before.on(sql);
                    Object result = invoke(target, method, args);
                    hooks.after.on(sql);
                    return result;
                }
                return invoke(target, method, args);
            });
    }

    @Nullable
    private static Object invoke(@NotNull Object target, @NotNull Method method, @Nullable Object[] args) throws Throwable {
        try {
            return method.invoke(target, args);
        } catch (InvocationTargetException e) {
            throw e.getTargetException();
        }
    }

    /**
     * A place a hooked connection stops at, once, until the test lets it go
     */
    static final class Pause {
        final CountDownLatch reached = new CountDownLatch(1);
        final CountDownLatch release = new CountDownLatch(1);
        private final AtomicBoolean used = new AtomicBoolean();

        /** Stops the calling thread here the first time only */
        void hit() throws SQLException {
            if (used.compareAndSet(false, true)) {
                reached.countDown();
                await(release, "a pause");
            }
        }

        void awaitReached(@NotNull String label) throws InterruptedException {
            Assertions.assertTrue(reached.await(TIMEOUT_SECONDS, TimeUnit.SECONDS), "FIXTURE: " + label + " was never reached");
        }

        void release() {
            release.countDown();
        }
    }

    // ---------------------------------------------------------------- two mutations of one key

    /** One coordinator call */
    @FunctionalInterface
    interface Mutation {
        @NotNull
        TempWriteMutationResult run(@NotNull TempWriteMutationCoordinator coordinator) throws SQLException;
    }

    /**
     * What two mutations of one key did when the second started while the first was held at its write
     *
     * @param secondWaited whether the second was seen waiting while the first held the key
     * @param secondOpened how many metadata connections the second had opened by then
     */
    record Serialized(
        @NotNull TempWriteMutationResult first,
        @NotNull TempWriteMutationResult second,
        boolean secondWaited,
        int secondOpened
    ) {
        void assertSerialized() {
            Assertions.assertTrue(secondWaited, "the second writer must wait on the key lock while the first holds it");
            Assertions.assertEquals(0, secondOpened, "the waiting writer must not reach the database");
        }
    }

    /**
     * Holds {@code first} just before its first write, starts {@code second}, watches it, then lets both finish
     */
    @NotNull
    static Serialized serialize(
        @NotNull MetadataConnectionSource source,
        @NotNull TempWriteGrantRepository repository,
        @NotNull Mutation first,
        @NotNull Mutation second
    ) throws Exception {
        Pause pause = new Pause();
        Hooks firstHooks = new Hooks();
        firstHooks.before = sql -> {
            if (isWrite(sql)) {
                pause.hit();
            }
        };
        Hooks secondHooks = new Hooks();
        Worker<TempWriteMutationResult> a = Worker.start("dbac-p4-first",
            () -> first.run(TempWriteMutationCoordinator.withoutAuditing(hooked(source, firstHooks), repository)));
        Worker<TempWriteMutationResult> b = null;
        boolean waited;
        int opened;
        try {
            pause.awaitReached("the first writer's write");
            b = Worker.start("dbac-p4-second",
                () -> second.run(TempWriteMutationCoordinator.withoutAuditing(hooked(source, secondHooks), repository)));
            waited = awaitParked(b.thread);
            opened = secondHooks.opened.get();
        } finally {
            pause.release();
        }
        TempWriteMutationResult firstResult = a.get("the first writer");
        TempWriteMutationResult secondResult = b.get("the second writer");
        Assertions.assertNotNull(firstResult, "FIXTURE: the first writer returned nothing");
        Assertions.assertNotNull(secondResult, "FIXTURE: the second writer returned nothing");
        return new Serialized(firstResult, secondResult, waited, opened);
    }

    // ---------------------------------------------------------------- the isolated user database

    /**
     * A metadata database whose connections can be hooked once the test arms it
     */
    static final class HookedDatabase extends DbacCBDatabase {
        final Hooks hooks;
        volatile boolean armed;

        HookedDatabase(
            @NotNull ServletApplication application,
            @NotNull WebDatabaseConfig config,
            @NotNull ShutdownLifecycle lifecycle,
            @NotNull Hooks hooks
        ) {
            super(application, config, DbacSchema.getSchemaConfigs(), lifecycle);
            this.hooks = hooks;
        }

        @Override
        @NotNull
        public Connection openConnection() throws SQLException {
            Connection connection = super.openConnection();
            if (!armed) {
                return connection;
            }
            hooks.opened.incrementAndGet();
            return hooked(connection, hooks);
        }

        /** A connection the hooks never see, for setting up and for reading what happened */
        @NotNull
        Connection plain() throws SQLException {
            return super.openConnection();
        }
    }

    /**
     * An isolated factory that hands out its embedded controller, the one production would build
     */
    static final class UserLockFactory extends LifecycleTestSupport.TestFactory {
        UserLockFactory(@NotNull LifecycleTestSupport.Fixture fixture) {
            super(fixture, fixture.seams());
        }

        @NotNull
        CBEmbeddedSecurityController<ServletAuthApplication> controller(@NotNull CBDatabase database) {
            return createEmbeddedSecurityController(
                LifecycleTestSupport.application(), database, new NoAuthCredentialsProvider(), new SMControllerConfiguration());
        }
    }

    /**
     * A real H2 metadata database with the CloudBeaver and DBAC schemas, of its own, and its controller
     */
    static final class UserDb implements AutoCloseable {
        final HookedDatabase database;
        final CBEmbeddedSecurityController<ServletAuthApplication> controller;

        private UserDb(@NotNull HookedDatabase database, @NotNull CBEmbeddedSecurityController<ServletAuthApplication> controller) {
            this.database = database;
            this.controller = controller;
        }

        @NotNull
        static UserDb open() throws Exception {
            Hooks hooks = new Hooks();
            UserLockFactory factory = new UserLockFactory(new LifecycleTestSupport.Fixture());
            factory.databaseMaker = (application, config, lifecycle) -> new HookedDatabase(application, config, lifecycle, hooks);
            HookedDatabase database = (HookedDatabase) factory.init();
            return new UserDb(database, factory.controller(database));
        }

        @NotNull
        Hooks hooks() {
            return database.hooks;
        }

        /** Starts recording and hooking every connection the controller opens from now on */
        void arm() {
            database.armed = true;
        }

        @NotNull
        String newUser(@NotNull String tag, boolean active) throws SQLException {
            String userId = "dbac-p4-" + tag + "-" + Long.toHexString(System.nanoTime());
            insertUser(userId, active);
            return userId;
        }

        void insertUser(@NotNull String userId, boolean active) throws SQLException {
            try (Connection connection = database.plain()) {
                insertSubject(connection, userId, "U");
                try (PreparedStatement dbStat = connection.prepareStatement(
                    "INSERT INTO {table_prefix}CB_USER(USER_ID,IS_ACTIVE,CREATE_TIME) VALUES(?,?,CURRENT_TIMESTAMP)")) {
                    dbStat.setString(1, userId);
                    dbStat.setString(2, active ? "Y" : "N");
                    dbStat.executeUpdate();
                }
            }
        }

        @NotNull
        String newTeam(@NotNull String tag) throws SQLException {
            String teamId = "dbac-p4-team-" + tag + "-" + Long.toHexString(System.nanoTime());
            try (Connection connection = database.plain()) {
                insertSubject(connection, teamId, "R");
                try (PreparedStatement dbStat = connection.prepareStatement(
                    "INSERT INTO {table_prefix}CB_TEAM(TEAM_ID,TEAM_NAME,CREATE_TIME) VALUES(?,?,CURRENT_TIMESTAMP)")) {
                    dbStat.setString(1, teamId);
                    dbStat.setString(2, teamId);
                    dbStat.executeUpdate();
                }
            }
            return teamId;
        }

        void insertSubject(@NotNull Connection connection, @NotNull String subjectId, @NotNull String type) throws SQLException {
            try (PreparedStatement dbStat = connection.prepareStatement(
                "INSERT INTO {table_prefix}CB_AUTH_SUBJECT(SUBJECT_ID,SUBJECT_TYPE,IS_SECRET_STORAGE) VALUES(?,?,'N')")) {
                dbStat.setString(1, subjectId);
                dbStat.setString(2, type);
                dbStat.executeUpdate();
            }
        }

        void insertRawSubject(@NotNull String subjectId, @NotNull String type) throws SQLException {
            try (Connection connection = database.plain()) {
                insertSubject(connection, subjectId, type);
            }
        }

        void assignTeam(@NotNull String userId, @NotNull String teamId) throws SQLException {
            try (Connection connection = database.plain();
                 PreparedStatement dbStat = connection.prepareStatement(
                     "INSERT INTO {table_prefix}CB_USER_TEAM(USER_ID,TEAM_ID,GRANT_TIME,GRANTED_BY) VALUES(?,?,CURRENT_TIMESTAMP,?)")) {
                dbStat.setString(1, userId);
                dbStat.setString(2, teamId);
                dbStat.setString(3, "dbac-p4-admin");
                dbStat.executeUpdate();
            }
        }

        /** A stored session and access token for the user, so that their survival can be checked */
        void insertSessionAndToken(@NotNull String userId) throws SQLException {
            String sessionId = "s" + Long.toHexString(System.nanoTime());
            try (Connection connection = database.plain()) {
                try (PreparedStatement dbStat = connection.prepareStatement(
                    "INSERT INTO {table_prefix}CB_SESSION(SESSION_ID,USER_ID,CREATE_TIME,LAST_ACCESS_TIME)"
                        + " VALUES(?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)")) {
                    dbStat.setString(1, sessionId);
                    dbStat.setString(2, userId);
                    dbStat.executeUpdate();
                }
                try (PreparedStatement dbStat = connection.prepareStatement(
                    "INSERT INTO {table_prefix}CB_AUTH_TOKEN(TOKEN_ID,SESSION_ID,USER_ID,EXPIRATION_TIME)"
                        + " VALUES(?,?,?,CURRENT_TIMESTAMP)")) {
                    dbStat.setString(1, "t" + sessionId);
                    dbStat.setString(2, sessionId);
                    dbStat.setString(3, userId);
                    dbStat.executeUpdate();
                }
            }
        }

        /** {@code Y}, {@code N}, or null when the user row does not exist */
        @Nullable
        String activeFlag(@NotNull String userId) throws SQLException {
            try (Connection connection = database.plain();
                 PreparedStatement dbStat = connection.prepareStatement(
                     "SELECT IS_ACTIVE FROM {table_prefix}CB_USER WHERE USER_ID=?")) {
                dbStat.setString(1, userId);
                try (ResultSet dbResult = dbStat.executeQuery()) {
                    return dbResult.next() ? dbResult.getString(1) : null;
                }
            }
        }

        int count(@NotNull String table, @NotNull String column, @NotNull String value) throws SQLException {
            try (Connection connection = database.plain();
                 PreparedStatement dbStat = connection.prepareStatement(
                     "SELECT COUNT(*) FROM {table_prefix}" + table + " WHERE " + column + "=?")) {
                dbStat.setString(1, value);
                try (ResultSet dbResult = dbStat.executeQuery()) {
                    dbResult.next();
                    return dbResult.getInt(1);
                }
            }
        }

        /** Everything about a subject that a deletion could touch */
        @NotNull
        String snapshot(@NotNull String subjectId) throws SQLException {
            return "subject=" + count("CB_AUTH_SUBJECT", "SUBJECT_ID", subjectId)
                + " user=" + count("CB_USER", "USER_ID", subjectId)
                + " active=" + activeFlag(subjectId)
                + " team=" + count("CB_TEAM", "TEAM_ID", subjectId)
                + " memberships=" + count("CB_USER_TEAM", "USER_ID", subjectId)
                + " sessions=" + count("CB_SESSION", "USER_ID", subjectId)
                + " tokens=" + count("CB_AUTH_TOKEN", "USER_ID", subjectId);
        }

        /** Calls the controller's protected {@code enableUser(Connection, ...)} - the overload {@code importUsers} uses */
        void enableUserOn(@NotNull Connection connection, @Nullable String userId, boolean enabled) throws Throwable {
            Method method = CBEmbeddedSecurityController.class.getDeclaredMethod(
                "enableUser", Connection.class, String.class, boolean.class, String.class, String.class);
            method.setAccessible(true);
            try {
                method.invoke(controller, connection, userId, enabled, "dbac-p4-admin", "dbac-p4");
            } catch (InvocationTargetException e) {
                throw e.getTargetException();
            }
        }

        @Override
        public void close() {
            database.shutdown();
        }
    }

    // ---------------------------------------------------------------- the application event pool

    /**
     * The list the application's event controller queues events in, which is also the monitor it queues them under
     */
    @NotNull
    static List<?> eventPool() throws Exception {
        Object application = LifecycleTestSupport.application();
        Object controller = application.getClass().getMethod("getEventController").invoke(application);
        Field field = controller.getClass().getDeclaredField("eventsPool");
        field.setAccessible(true);
        return (List<?>) field.get(controller);
    }

    // ---------------------------------------------------------------- PostgreSQL

    /** A PostgreSQL connection whose {@code {table_prefix}} is {@code schema} - usable as a metadata connection source */
    @NotNull
    static Connection openPostgres(@NotNull String schema) throws SQLException {
        Connection raw;
        try {
            raw = EnforcementTestSupport.openRawPostgres(MONITOR);
        } catch (SQLException e) {
            throw e;
        } catch (Exception e) {
            throw new SQLException("FIXTURE: the PostgreSQL connection could not be opened", e);
        }
        return new InternalProxyConnection(raw, DbacTestSupport.config(null, schema));
    }

    static void createSchema(@NotNull String schema) throws Exception {
        try (Connection raw = EnforcementTestSupport.openRawPostgres(MONITOR); Statement dbStat = raw.createStatement()) {
            dbStat.execute("DROP SCHEMA IF EXISTS " + schema + " CASCADE");
            dbStat.execute("CREATE SCHEMA " + schema);
        }
    }

    static void dropSchema(@NotNull String schema) throws Exception {
        try (Connection raw = EnforcementTestSupport.openRawPostgres(MONITOR); Statement dbStat = raw.createStatement()) {
            dbStat.execute("DROP SCHEMA IF EXISTS " + schema + " CASCADE");
        }
    }

    static int countSchemas(@NotNull String schema) throws Exception {
        try (Connection raw = EnforcementTestSupport.openRawPostgres(MONITOR);
             PreparedStatement dbStat = raw.prepareStatement("SELECT COUNT(*) FROM pg_namespace WHERE nspname = ?")) {
            dbStat.setString(1, schema);
            try (ResultSet dbResult = dbStat.executeQuery()) {
                dbResult.next();
                return dbResult.getInt(1);
            }
        }
    }

    /** Installs the DBAC schema in {@code schema} with the real migration, as the repository PostgreSQL test does */
    static void installDbacSchema(@NotNull String schema) throws Exception {
        createSchema(schema);
        InternalDatabaseConfig config = DbacTestSupport.config(null, schema);
        try (Connection raw = EnforcementTestSupport.openRawPostgres(MONITOR)) {
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
                new PostgreDialect(),
                DbacSchemaConstants.CURRENT_SCHEMA_VERSION,
                DbacSchemaConstants.OBSOLETE_SCHEMA_VERSION,
                config,
                null).updateSchema(MONITOR);
        }
    }

    // ---------------------------------------------------------------- X and M of a real target

    /**
     * Runs {@code action} while another thread holds the target's instance exclusive lock (X) and its context monitor (M)
     *
     * @return whether the action finished while both were held
     */
    static boolean finishesWhileXAndMHeld(@NotNull EnforcementTestSupport.Target target, @NotNull Task<?> action) throws Exception {
        DBPExclusiveResource exclusive = target.instance().getExclusiveLock();
        Object context = target.context();
        CountDownLatch holding = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        Worker<Object> holder = Worker.start("dbac-p4-x-m-holder", () -> {
            Object token = exclusive.acquireExclusiveLock();
            try {
                synchronized (context) {
                    holding.countDown();
                    release.await(TIMEOUT_SECONDS * 2, TimeUnit.SECONDS);
                }
            } finally {
                exclusive.releaseExclusiveLock(token);
            }
            return null;
        });
        try {
            Assertions.assertTrue(holding.await(TIMEOUT_SECONDS, TimeUnit.SECONDS), "FIXTURE: X and M were not taken");
            Worker<Object> worker = Worker.start("dbac-p4-under-x-m", () -> {
                action.run();
                return null;
            });
            boolean finished = worker.awaitDone();
            if (worker.error != null) {
                Assertions.fail("the action under X and M threw " + worker.error.getClass().getName(), worker.error);
            }
            return finished;
        } finally {
            release.countDown();
            holder.awaitDone();
        }
    }
}
