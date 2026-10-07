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
import io.cloudbeaver.model.app.ServletAuthApplication;
import io.cloudbeaver.model.config.SMControllerConfiguration;
import io.cloudbeaver.model.config.WebDatabaseConfig;
import io.cloudbeaver.service.dbac.DbacSecurityControllerFactory;
import io.cloudbeaver.service.dbac.PolicyServiceHolder;
import io.cloudbeaver.service.dbac.PolicyServiceHolder.FailureCode;
import io.cloudbeaver.service.dbac.PolicyServiceHolder.State;
import io.cloudbeaver.service.dbac.db.DbacCBDatabase;
import io.cloudbeaver.service.dbac.db.DbacSchema;
import io.cloudbeaver.service.dbac.policy.DbAccessPolicyConfig;
import io.cloudbeaver.service.dbac.policy.DbAccessPolicyService;
import io.cloudbeaver.service.dbac.policy.enforcement.DeploymentGuard;
import io.cloudbeaver.service.dbac.policy.enforcement.TaintContextCloseHandler;
import io.cloudbeaver.service.security.CBEmbeddedSecurityController;
import io.cloudbeaver.service.security.db.CBDatabase;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.jkiss.dbeaver.DBException;
import org.jkiss.dbeaver.Log;
import org.jkiss.dbeaver.model.auth.SMCredentialsProvider;
import org.jkiss.dbeaver.model.exec.DBCExecutionContext;
import org.jkiss.dbeaver.model.qm.QMExecutionHandler;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import java.util.regex.Pattern;

/**
 * Fixtures shared by the P3 lifecycle and deployment-guard tests
 * <p>
 * Everything here builds an <em>isolated</em> policy lifecycle: the factory is created through its
 * seam constructor, which always makes a new holder, so nothing here can reach the server's global
 * holder or {@code EmbeddedSecurityControllerFactory.DB_INSTANCE}. Each collaborator records what it
 * was asked to do into one shared {@link Journal}, so that a test can check the order across them,
 * and each can be told to fail with a {@link RuntimeException} or an {@link Error} on demand.
 */
final class LifecycleTestSupport {

    /** Put into every injected failure's message; it must never reach a log */
    static final String SECRET_MARKER = "dbac-lifecycle-secret-91f3";
    /** A credential-looking fragment, also in every injected failure's message */
    static final String CREDENTIAL_FRAGMENT = "password=dbac-pw-5e1c";

    static final Pattern EVENT_ID_PATTERN =
        Pattern.compile("(?i)EVENT_ID=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\b");

    private static final AtomicLong DATABASE_SEQUENCE = new AtomicLong();

    private LifecycleTestSupport() {
    }

    // ---------------------------------------------------------------- failures

    /** How a collaborator fails when it is called */
    enum Fault {
        NONE,
        RUNTIME,
        ERROR
    }

    /** An injected {@link RuntimeException}, distinguishable from anything the code under test throws */
    static final class InjectedRuntimeException extends RuntimeException {
        InjectedRuntimeException(@NotNull String where) {
            super("injected at " + where + " " + SECRET_MARKER + " jdbc:postgresql://secret-host.internal.example/db?user=dbac&"
                + CREDENTIAL_FRAGMENT);
        }
    }

    /** An injected {@link Error} */
    static final class InjectedError extends Error {
        InjectedError(@NotNull String where) {
            super("injected at " + where + " " + SECRET_MARKER + " jdbc:postgresql://secret-host.internal.example/db?user=dbac&"
                + CREDENTIAL_FRAGMENT);
        }
    }

    /** Throws the failure {@code fault} names, recording the thrown object in the journal under {@code where} */
    static void raise(@NotNull Fault fault, @NotNull String where, @NotNull Journal journal) {
        switch (fault) {
            case RUNTIME -> throw journal.injected(where, new InjectedRuntimeException(where));
            case ERROR -> throw journal.injected(where, new InjectedError(where));
            default -> {
                // no failure
            }
        }
    }

    // ---------------------------------------------------------------- recording

    /** One ordered record of what every collaborator was asked to do */
    static final class Journal {
        private final List<String> events = Collections.synchronizedList(new ArrayList<>());
        private final Map<String, Throwable> injected = new ConcurrentHashMap<>();

        /** Remembers the last failure thrown at {@code where}, so a test can check what reached it is that object */
        @NotNull
        <X extends Throwable> X injected(@NotNull String where, @NotNull X failure) {
            injected.put(where, failure);
            return failure;
        }

        @Nullable
        Throwable lastInjected(@NotNull String where) {
            return injected.get(where);
        }

        void add(@NotNull String event) {
            events.add(event);
        }

        @NotNull
        List<String> snapshot() {
            synchronized (events) {
                return new ArrayList<>(events);
            }
        }

        int count(@NotNull String event) {
            synchronized (events) {
                return (int) events.stream().filter(event::equals).count();
            }
        }
    }

    /** One transition the holder reported */
    record Transition(@NotNull State from, @NotNull State to) {
        @NotNull
        String name() {
            return stateName(from) + "->" + stateName(to);
        }
    }

    @NotNull
    static String stateName(@NotNull State state) {
        return state.getClass().getSimpleName();
    }

    /** Records every transition, from whichever thread made it */
    static final class RecordingObserver implements PolicyServiceHolder.TransitionObserver {
        private final List<Transition> transitions = Collections.synchronizedList(new ArrayList<>());
        @NotNull
        private final Journal journal;
        /** Thrown after each transition is recorded; the holder must log it and carry on */
        volatile Fault fault = Fault.NONE;

        RecordingObserver(@NotNull Journal journal) {
            this.journal = journal;
        }

        @Override
        public void transitioned(@NotNull State from, @NotNull State to) {
            transitions.add(new Transition(from, to));
            journal.add("state:" + stateName(to));
            raise(fault, "observer", journal);
        }

        @NotNull
        List<Transition> transitions() {
            synchronized (transitions) {
                return new ArrayList<>(transitions);
            }
        }

        @NotNull
        List<String> names() {
            return transitions().stream().map(Transition::name).toList();
        }

        long countTo(@NotNull Class<? extends State> type) {
            return transitions().stream().filter(t -> type.isInstance(t.to())).count();
        }

        /** Whether {@code Ready} was entered more than once; once left, it can only be entered again */
        boolean readyReentered() {
            return countTo(PolicyServiceHolder.Ready.class) > 1;
        }
    }

    /** Adds and removes handlers, recording each call; the real query manager is never touched */
    static final class RecordingRegistrar implements TaintContextCloseHandler.HandlerRegistrar {
        final Journal journal;
        final List<QMExecutionHandler> registered = Collections.synchronizedList(new ArrayList<>());
        final List<QMExecutionHandler> unregistered = Collections.synchronizedList(new ArrayList<>());
        final List<String> statesAtRegister = Collections.synchronizedList(new ArrayList<>());
        volatile Fault registerFault = Fault.NONE;
        volatile Fault unregisterFault = Fault.NONE;
        @Nullable
        volatile Supplier<State> stateProbe;
        @Nullable
        volatile Runnable onUnregister;

        RecordingRegistrar(@NotNull Journal journal) {
            this.journal = journal;
        }

        @Override
        public void register(@NotNull QMExecutionHandler handler) {
            journal.add("register");
            Supplier<State> probe = stateProbe;
            statesAtRegister.add(probe == null ? "?" : stateName(probe.get()));
            registered.add(handler);
            raise(registerFault, "register", journal);
        }

        @Override
        public void unregister(@NotNull QMExecutionHandler handler) {
            journal.add("unregister");
            unregistered.add(handler);
            Runnable hook = onUnregister;
            if (hook != null) {
                hook.run();
            }
            raise(unregisterFault, "unregister", journal);
        }
    }

    /** Records closes and clears */
    static final class RecordingSink implements TaintContextCloseHandler.TaintSink {
        final Journal journal;
        final AtomicInteger closes = new AtomicInteger();
        final AtomicInteger clears = new AtomicInteger();
        volatile Fault clearFault = Fault.NONE;
        volatile Fault closeFault = Fault.NONE;

        RecordingSink(@NotNull Journal journal) {
            this.journal = journal;
        }

        @Override
        public void contextClosed(long contextId) {
            journal.add("contextClosed");
            closes.incrementAndGet();
            raise(closeFault, "contextClosed", journal);
        }

        @Override
        public void clear() {
            journal.add("clear");
            clears.incrementAndGet();
            raise(clearFault, "clear", journal);
        }
    }

    /** Stands for the advisory lock lease; counts releases */
    static final class RecordingLease implements Runnable {
        final Journal journal;
        final AtomicInteger releases = new AtomicInteger();
        volatile Fault fault = Fault.NONE;

        RecordingLease(@NotNull Journal journal) {
            this.journal = journal;
        }

        @Override
        public void run() {
            journal.add("lease");
            releases.incrementAndGet();
            raise(fault, "lease", journal);
        }
    }

    /** An admission that always lets the caller proceed */
    static final class StubAdmission implements DeploymentGuard.Admission {
        @NotNull
        @Override
        public String deploymentMode() {
            return DeploymentGuard.MODE_TEST;
        }

        @Override
        public boolean assertSingleProcess() {
            return true;
        }
    }

    /** What the stub deployment guard does */
    enum AdmitMode {
        ADMIT,
        REFUSE,
        THROW_RUNTIME,
        THROW_ERROR
    }

    /** A deployment guard that admits with a recording lease, refuses, or fails, as told */
    static final class StubAdmitter implements DbacSecurityControllerFactory.Admitter {
        final RecordingLease lease;
        final AtomicInteger calls = new AtomicInteger();
        final AtomicReference<DeploymentGuard.Revocation> revocation = new AtomicReference<>();
        volatile AdmitMode mode = AdmitMode.ADMIT;
        volatile FailureCode refusal = FailureCode.DEPLOYMENT_NOT_ACKNOWLEDGED;

        StubAdmitter(@NotNull RecordingLease lease) {
            this.lease = lease;
        }

        @NotNull
        @Override
        public DeploymentGuard.Result admit(@NotNull DbacCBDatabase database, @NotNull DeploymentGuard.Revocation revocation) {
            calls.incrementAndGet();
            this.revocation.set(revocation);
            lease.journal.add("admit");
            return switch (mode) {
                case ADMIT -> new DeploymentGuard.Admitted(new StubAdmission(), lease);
                case REFUSE -> new DeploymentGuard.Refused(refusal);
                case THROW_RUNTIME -> throw lease.journal.injected("admit", new InjectedRuntimeException("admit"));
                case THROW_ERROR -> throw lease.journal.injected("admit", new InjectedError("admit"));
            };
        }
    }

    /** Builds a real policy service, unless told to fail */
    static final class StubServiceFactory implements DbacSecurityControllerFactory.ServiceFactory {
        final Journal journal;
        final AtomicInteger calls = new AtomicInteger();
        volatile Fault fault = Fault.NONE;

        StubServiceFactory(@NotNull Journal journal) {
            this.journal = journal;
        }

        @NotNull
        @Override
        public DbAccessPolicyService create(@NotNull DbacCBDatabase database) {
            calls.incrementAndGet();
            journal.add("service");
            raise(fault, "service", journal);
            return new DbAccessPolicyService(database.metadataLeases(), DbAccessPolicyConfig.defaults());
        }
    }

    // ---------------------------------------------------------------- database

    /** How {@link StubDb#initialize()} behaves */
    enum InitMode {
        OK,
        DB_EXCEPTION,
        RUNTIME,
        ERROR
    }

    /**
     * A metadata database that never opens a pool
     * <p>
     * {@link #initialize()} does what it is told and {@link #closeConnection()} - what
     * {@code CBDatabase.shutdown()} calls, and so what {@code super.shutdown()} reaches - is counted
     * and can fail. {@code shutdown()} itself is final in {@code DbacCBDatabase} and is not touched.
     */
    static final class StubDb extends DbacCBDatabase {
        final Journal journal;
        final AtomicInteger closes = new AtomicInteger();
        final List<Thread> closingThreads = Collections.synchronizedList(new ArrayList<>());
        volatile InitMode initMode = InitMode.OK;
        volatile Fault closeFault = Fault.NONE;
        @Nullable
        volatile Runnable onInitialize;

        StubDb(
            @NotNull ServletApplication application,
            @NotNull WebDatabaseConfig config,
            @NotNull ShutdownLifecycle lifecycle,
            @NotNull Journal journal
        ) {
            super(application, config, DbacSchema.getSchemaConfigs(), lifecycle);
            this.journal = journal;
        }

        @Override
        public void initialize() throws DBException {
            journal.add("initialize");
            Runnable hook = onInitialize;
            if (hook != null) {
                hook.run();
            }
            switch (initMode) {
                case DB_EXCEPTION -> throw journal.injected("initialize", new DBException("injected initialize failure " + SECRET_MARKER));
                case RUNTIME -> throw journal.injected("initialize", new InjectedRuntimeException("initialize"));
                case ERROR -> throw journal.injected("initialize", new InjectedError("initialize"));
                default -> {
                    // initialized
                }
            }
        }

        @Override
        protected void closeConnection() {
            journal.add("close");
            closes.incrementAndGet();
            closingThreads.add(Thread.currentThread());
            raise(closeFault, "close", journal);
        }
    }

    /** A fresh in-memory H2 configuration with a name no other test uses */
    @NotNull
    static WebDatabaseConfig h2Config() {
        WebDatabaseConfig config = new WebDatabaseConfig();
        config.setDriver("h2_embedded_v2");
        config.setUrl("jdbc:h2:mem:dbac_lc_" + DATABASE_SEQUENCE.incrementAndGet() + "_" + Long.toHexString(System.nanoTime()));
        return config;
    }

    @NotNull
    static ServletAuthApplication application() {
        ServletAuthApplication application = CEAppStarter.getTestApp();
        if (application == null) {
            throw new IllegalStateException("FIXTURE: the test server is not running");
        }
        return application;
    }

    // ---------------------------------------------------------------- factory

    /** The collaborators of one isolated lifecycle */
    static final class Fixture {
        final Journal journal = new Journal();
        final RecordingObserver observer = new RecordingObserver(journal);
        final RecordingRegistrar registrar = new RecordingRegistrar(journal);
        final RecordingSink sink = new RecordingSink(journal);
        final RecordingLease lease = new RecordingLease(journal);
        final StubAdmitter admitter = new StubAdmitter(lease);
        final StubServiceFactory serviceFactory = new StubServiceFactory(journal);

        @NotNull
        DbacSecurityControllerFactory.LifecycleSeams seams() {
            return new DbacSecurityControllerFactory.LifecycleSeams(admitter, registrar, sink, serviceFactory);
        }

        @NotNull
        DbacSecurityControllerFactory.LifecycleSeams seams(@NotNull DbacSecurityControllerFactory.Admitter admitter) {
            return new DbacSecurityControllerFactory.LifecycleSeams(admitter, registrar, sink, serviceFactory);
        }

        @NotNull
        TestFactory factory() {
            return new TestFactory(this, seams());
        }

        @NotNull
        TestFactory factory(@NotNull DbacSecurityControllerFactory.Admitter admitter) {
            return new TestFactory(this, seams(admitter));
        }
    }

    /**
     * An isolated factory that creates stub databases, or real ones when asked
     * <p>
     * It exposes the protected initialization so a test can drive it directly, exactly as
     * {@code createSecurityService} would on the first request.
     */
    static class TestFactory extends DbacSecurityControllerFactory<ServletAuthApplication> {
        /** Makes the database instead of a {@link StubDb} */
        @FunctionalInterface
        interface DatabaseMaker {
            @NotNull
            DbacCBDatabase make(
                @NotNull ServletApplication application,
                @NotNull WebDatabaseConfig config,
                @NotNull DbacCBDatabase.ShutdownLifecycle lifecycle
            );
        }

        final Fixture fixture;
        final AtomicInteger newDatabaseCalls = new AtomicInteger();
        final List<Thread> newDatabaseThreads = Collections.synchronizedList(new ArrayList<>());
        final List<DbacCBDatabase> databases = Collections.synchronizedList(new ArrayList<>());
        volatile boolean realDatabase;
        volatile Fault newDatabaseFault = Fault.NONE;
        volatile Fault controllerFault = Fault.NONE;
        volatile InitMode initMode = InitMode.OK;
        volatile Fault closeFault = Fault.NONE;
        @Nullable
        volatile Runnable onInitialize;
        @Nullable
        volatile DatabaseMaker databaseMaker;
        volatile WebDatabaseConfig config = h2Config();

        TestFactory(@NotNull Fixture fixture, @NotNull LifecycleSeams seams) {
            super(fixture.observer, seams);
            this.fixture = fixture;
            fixture.registrar.stateProbe = this::state;
        }

        @NotNull
        @Override
        protected DbacCBDatabase newDatabase(
            @NotNull ServletApplication application,
            @NotNull WebDatabaseConfig databaseConfig,
            @NotNull DbacCBDatabase.ShutdownLifecycle lifecycle
        ) {
            newDatabaseCalls.incrementAndGet();
            newDatabaseThreads.add(Thread.currentThread());
            fixture.journal.add("newDatabase");
            raise(newDatabaseFault, "newDatabase", fixture.journal);
            DbacCBDatabase database;
            DatabaseMaker maker = databaseMaker;
            if (maker != null) {
                database = maker.make(application, databaseConfig, lifecycle);
            } else if (realDatabase) {
                database = super.newDatabase(application, databaseConfig, lifecycle);
            } else {
                StubDb stub = new StubDb(application, databaseConfig, lifecycle, fixture.journal);
                stub.initMode = initMode;
                stub.closeFault = closeFault;
                stub.onInitialize = onInitialize;
                database = stub;
            }
            databases.add(database);
            return database;
        }

        @NotNull
        @Override
        protected CBEmbeddedSecurityController<ServletAuthApplication> createEmbeddedSecurityController(
            @NotNull ServletAuthApplication application,
            @NotNull CBDatabase database,
            @NotNull SMCredentialsProvider credentialsProvider,
            @NotNull SMControllerConfiguration smConfig
        ) {
            raise(controllerFault, "controller", fixture.journal);
            return super.createEmbeddedSecurityController(application, database, credentialsProvider, smConfig);
        }

        /** Runs the initialization the first request would run */
        @NotNull
        CBDatabase init() throws DBException {
            return createAndInitDatabaseInstance(application(), config, new SMControllerConfiguration());
        }

        /** Calls the database factory method directly, outside any initialization */
        @NotNull
        CBDatabase makeDirectly() {
            return makeDatabase(application(), config);
        }

        @NotNull
        State state() {
            return holder().current();
        }

        @NotNull
        PolicyServiceHolder holderForTest() {
            return holder();
        }

        @Nullable
        StubDb lastStub() {
            synchronized (databases) {
                return databases.isEmpty() || !(databases.get(databases.size() - 1) instanceof StubDb stub) ? null : stub;
            }
        }
    }

    /** What one call to the initialization did */
    record InitOutcome(@Nullable CBDatabase database, @Nullable Throwable thrown) {
    }

    @NotNull
    static InitOutcome initCatching(@NotNull TestFactory factory) {
        try {
            return new InitOutcome(factory.init(), null);
        } catch (DBException | RuntimeException | Error e) {
            return new InitOutcome(null, e);
        }
    }

    /** Runs a shutdown and returns whatever it threw */
    @Nullable
    static Throwable shutdownCatching(@NotNull CBDatabase database) {
        try {
            database.shutdown();
            return null;
        } catch (RuntimeException | Error e) {
            return e;
        }
    }

    /** An execution context that only knows its id, for driving the close handler directly */
    @NotNull
    static DBCExecutionContext context(long id) {
        return (DBCExecutionContext) Proxy.newProxyInstance(
            LifecycleTestSupport.class.getClassLoader(),
            new Class<?>[]{DBCExecutionContext.class},
            (proxy, method, args) -> switch (method.getName()) {
                case "getContextId" -> id;
                case "hashCode" -> System.identityHashCode(proxy);
                case "equals" -> proxy == args[0];
                case "toString" -> "context#" + id;
                default -> throw new UnsupportedOperationException(method.getName());
            });
    }

    // ---------------------------------------------------------------- logs

    /** What the platform log received on the calling thread while a body ran */
    record Captured(@NotNull String text, @NotNull List<String> dbacMessages, @NotNull List<Throwable> dbacThrowables) {
    }

    /** A body that may throw anything */
    @FunctionalInterface
    interface Body {
        void run() throws Throwable;
    }

    /**
     * Runs {@code body} with the calling thread's log captured, returning the capture
     * <p>
     * Whatever the body throws is rethrown after the capture is removed.
     */
    @NotNull
    static Captured captureLogs(@NotNull Body body) throws Throwable {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        Thread caller = Thread.currentThread();
        List<String> messages = Collections.synchronizedList(new ArrayList<>());
        List<Throwable> throwables = Collections.synchronizedList(new ArrayList<>());
        Log.Listener listener = (message, t) -> {
            if (Thread.currentThread() == caller && message != null && String.valueOf(message).contains("DBAC")) {
                messages.add(String.valueOf(message));
                throwables.add(t);
            }
        };
        PrintStream previous = Log.getLogWriter();
        Log.setLogWriter(new PrintStream(buffer, true, StandardCharsets.UTF_8));
        Log.addListener(listener);
        try {
            body.run();
        } finally {
            Log.removeListener(listener);
            Log.setLogWriter(previous);
        }
        return new Captured(buffer.toString(StandardCharsets.UTF_8), new ArrayList<>(messages), new ArrayList<>(throwables));
    }

    /**
     * Runs {@code body} with every DBAC message logged on the calling thread failing with {@code fault}
     * <p>
     * The platform log hands a message to its listeners on the logging thread and lets what a listener
     * throws reach the caller of {@code log.error}, so this is a log write that fails.
     *
     * @return how many times the log failed, so a test can tell that it really did
     */
    static int withFailingLog(@NotNull Fault fault, @NotNull Body body) throws Throwable {
        Thread caller = Thread.currentThread();
        AtomicInteger raised = new AtomicInteger();
        Log.Listener failing = (message, t) -> {
            if (Thread.currentThread() == caller && message != null && String.valueOf(message).contains("DBAC")) {
                raised.incrementAndGet();
                if (fault == Fault.ERROR) {
                    throw new InjectedError("log");
                }
                throw new InjectedRuntimeException("log");
            }
        };
        PrintStream previous = Log.getLogWriter();
        Log.setLogWriter(new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8));
        Log.addListener(failing);
        try {
            body.run();
        } finally {
            Log.removeListener(failing);
            Log.setLogWriter(previous);
        }
        return raised.get();
    }

    /**
     * Every clause of the P1 log contract the captured DBAC messages break
     *
     * @param forbidden fragments that must appear nowhere in the captured text
     */
    @NotNull
    static List<String> logContractViolations(@NotNull Captured captured, @NotNull List<String> forbidden) {
        List<String> violations = new ArrayList<>();
        for (String fragment : forbidden) {
            if (captured.text().contains(fragment)) {
                violations.add("the log contains '" + fragment + "'");
            }
        }
        if (captured.text().contains("\tat ")) {
            violations.add("a stack trace is written");
        }
        for (int i = 0; i < captured.dbacMessages().size(); i++) {
            String message = captured.dbacMessages().get(i);
            if (captured.dbacThrowables().get(i) != null) {
                violations.add("an exception object is handed to the logger: " + message);
            }
            if (!message.contains("event=DBAC_")) {
                violations.add("no fixed event code: " + message);
            }
            if (!EVENT_ID_PATTERN.matcher(message).find()) {
                violations.add("no EVENT_ID=<UUID>: " + message);
            }
            if (message.indexOf('\n') >= 0 || message.indexOf('\r') >= 0) {
                violations.add("the message is not one line: " + message);
            }
        }
        return violations;
    }
}
