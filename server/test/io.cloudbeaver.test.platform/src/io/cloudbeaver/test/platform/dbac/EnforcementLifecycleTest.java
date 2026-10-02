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
import io.cloudbeaver.service.dbac.DbacSecurityControllerFactory;
import io.cloudbeaver.service.dbac.PolicyServiceHolder;
import io.cloudbeaver.service.dbac.PolicyServiceHolder.Disposed;
import io.cloudbeaver.service.dbac.PolicyServiceHolder.Failed;
import io.cloudbeaver.service.dbac.PolicyServiceHolder.FailureCode;
import io.cloudbeaver.service.dbac.PolicyServiceHolder.Initializing;
import io.cloudbeaver.service.dbac.PolicyServiceHolder.Ready;
import io.cloudbeaver.service.dbac.PolicyServiceHolder.StartupFailed;
import io.cloudbeaver.service.dbac.PolicyServiceHolder.State;
import io.cloudbeaver.service.dbac.PolicyServiceHolder.Stopping;
import io.cloudbeaver.service.dbac.db.DbacCBDatabase;
import io.cloudbeaver.service.dbac.policy.enforcement.DeploymentGuard;
import io.cloudbeaver.service.dbac.policy.enforcement.TaintContextCloseHandler;
import io.cloudbeaver.service.security.db.CBDatabase;
import io.cloudbeaver.test.platform.dbac.LifecycleTestSupport.AdmitMode;
import io.cloudbeaver.test.platform.dbac.LifecycleTestSupport.Captured;
import io.cloudbeaver.test.platform.dbac.LifecycleTestSupport.Fault;
import io.cloudbeaver.test.platform.dbac.LifecycleTestSupport.Fixture;
import io.cloudbeaver.test.platform.dbac.LifecycleTestSupport.InitMode;
import io.cloudbeaver.test.platform.dbac.LifecycleTestSupport.InitOutcome;
import io.cloudbeaver.test.platform.dbac.LifecycleTestSupport.StubDb;
import io.cloudbeaver.test.platform.dbac.LifecycleTestSupport.TestFactory;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.jkiss.dbeaver.DBException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.stream.Collectors;

/**
 * P3: the lifecycle of the policy service, driven through isolated factories
 * <p>
 * Every test builds its own factory through the seam constructor, so it owns its own holder and
 * never touches the server's global one or {@code DB_INSTANCE}. Collaborators record into one
 * journal and fail on demand with a {@code RuntimeException} or an {@code Error}, which is how the
 * cleanup error policy (C15) is exercised: every cleanup step is attempted, the state always
 * reaches its terminal value, an original throwable is never replaced, and {@code Ready} is never
 * entered twice.
 * <p>
 * Tagged L (lifecycle), LC (lifecycle cleanup) and TR (taint registry) as in the P3 preflight.
 */
@Timeout(value = 120, unit = TimeUnit.SECONDS, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
public class EnforcementLifecycleTest {

    private static final long TIMEOUT_SECONDS = 30;
    private static final int THREADS = 8;
    /** A thread counts as waiting once seen parked this many polls in a row */
    private static final int PARKED_POLLS = 10;
    private static final long PARKED_POLL_MILLIS = 20;

    /** What a run's logs must never contain: injected messages carry all three */
    private static final List<String> FORBIDDEN_LOG_FRAGMENTS = List.of(LifecycleTestSupport.SECRET_MARKER,
        "secret-host.internal.example", "jdbc:postgresql://", LifecycleTestSupport.CREDENTIAL_FRAGMENT, "injected at");

    @BeforeAll
    public static void startServer() throws Exception {
        CEAppStarter.startServerIfNotStarted();
    }

    // ---------------------------------------------------------------- L

    /**
     * L1: a real initialization goes New, Initializing, Ready and publishes the database it returns
     */
    @Test
    public void l1RealInitializationReachesReadyWithTheReturnedDatabase() throws Exception {
        Fixture fixture = new Fixture();
        DeploymentGuard guard = new DeploymentGuard(new DeploymentGuard.Environment(
            () -> DeploymentGuard.MODE_TEST, () -> null, () -> true, () -> false, () -> false));
        TestFactory factory = fixture.factory((database, revocation) ->
            guard.admit(DeploymentGuard.MetadataTarget.of(database), revocation));
        factory.realDatabase = true;
        CBDatabase database = factory.init();
        try {
            Assertions.assertEquals(List.of("New->Initializing", "Initializing->Ready"), fixture.observer.names(),
                "L1: a real initialization must go New -> Initializing -> Ready and nothing else");
            Ready ready = Assertions.assertInstanceOf(Ready.class, factory.state(), "L1: the holder must be Ready");
            Assertions.assertSame(database, ready.database(), "L1: Ready must hold the database the factory returned");
            Assertions.assertNotNull(ready.service(), "L1: Ready must hold a policy service");
            Assertions.assertEquals(DeploymentGuard.MODE_TEST, ready.admission().deploymentMode(),
                "L1: Ready must keep the admitted deployment mode");
            try (Connection connection = database.openConnection();
                 Statement statement = connection.createStatement();
                 ResultSet result = statement.executeQuery("SELECT 1")) {
                Assertions.assertTrue(result.next(), "L1: the ready database must serve a read");
            }
        } finally {
            database.shutdown();
        }
        Assertions.assertEquals(
            List.of("New->Initializing", "Initializing->Ready", "Ready->Stopping", "Stopping->Disposed"),
            fixture.observer.names(), "L1: shutting the ready database down must go Stopping -> Disposed");
        Assertions.assertThrows(Exception.class, database::openConnection, "L1: the pool must be closed after shutdown");
    }

    /**
     * L2: Ready is published once, last, after the close handler was registered - and nobody else can publish it
     */
    @Test
    public void l2ReadyIsPublishedOnceAfterTheHandlerIsRegistered() throws Throwable {
        Fixture fixture = new Fixture();
        TestFactory factory = fixture.factory();
        CBDatabase database = factory.init();
        try {
            Assertions.assertEquals(1, fixture.observer.countTo(Ready.class), "L2: Ready must be published exactly once");
            List<String> names = fixture.observer.names();
            Assertions.assertEquals("Initializing->Ready", names.get(names.size() - 1),
                "L2: publishing Ready must be the last transition of the initialization");
            Assertions.assertEquals(List.of("Initializing"), fixture.registrar.statesAtRegister,
                "L2: the close handler must be registered while the holder is still Initializing");
            List<String> journal = fixture.journal.snapshot();
            Assertions.assertTrue(journal.indexOf("register") >= 0 && journal.indexOf("register") < journal.indexOf("state:Ready"),
                "L2: registration must come before Ready, journal " + journal);
        } finally {
            database.shutdown();
        }

        List<String> violations = new ArrayList<>();
        Set<String> holderPublic = Arrays.stream(PolicyServiceHolder.class.getDeclaredMethods())
            .filter(m -> Modifier.isPublic(m.getModifiers()))
            .map(Method::getName)
            .collect(Collectors.toCollection(TreeSet::new));
        if (!holderPublic.equals(new TreeSet<>(List.of("current", "global")))) {
            violations.add("the holder's public methods are " + holderPublic + ", expected only [current, global]");
        }
        if (PolicyServiceHolder.class.getConstructors().length != 0) {
            violations.add("the holder has a public constructor");
        }
        for (Class<?> type : PolicyServiceHolder.class.getDeclaredClasses()) {
            if (!State.class.isAssignableFrom(type) || type.isInterface()) {
                continue;
            }
            for (Constructor<?> constructor : type.getDeclaredConstructors()) {
                if (Modifier.isPublic(constructor.getModifiers()) || Modifier.isProtected(constructor.getModifiers())) {
                    violations.add(type.getSimpleName() + " has a public or protected constructor");
                }
            }
            if (type.isRecord()) {
                violations.add(type.getSimpleName() + " is a record, whose canonical constructor is as visible as the type");
            }
            for (Method method : type.getDeclaredMethods()) {
                if (Modifier.isPublic(method.getModifiers()) && method.getParameterCount() > 0) {
                    violations.add(type.getSimpleName() + "." + method.getName() + " is public and takes arguments");
                }
            }
        }
        Assertions.assertEquals(List.of(), violations, "L2: the holder must have no public mutator");

        for (Fault fault : List.of(Fault.RUNTIME, Fault.ERROR)) {
            Fixture observed = new Fixture();
            observed.observer.fault = fault;
            TestFactory observedFactory = observed.factory();
            CBDatabase[] made = new CBDatabase[1];
            State[] afterInit = new State[1];
            Throwable[] shutdownThrew = new Throwable[1];
            Captured captured = LifecycleTestSupport.captureLogs(() -> {
                made[0] = observedFactory.init();
                afterInit[0] = observedFactory.state();
                shutdownThrew[0] = LifecycleTestSupport.shutdownCatching(made[0]);
            });
            Assertions.assertInstanceOf(Ready.class, afterInit[0], "L2: an observer " + fault + " must not stop Ready being published");
            Assertions.assertNull(shutdownThrew[0], "L2: an observer " + fault + " must not make the shutdown throw");
            Assertions.assertInstanceOf(Disposed.class, observedFactory.state(), "L2: an observer " + fault + " must not stop Disposed");
            Assertions.assertEquals(4, captured.dbacMessages().stream()
                    .filter(m -> m.contains("event=DBAC_LIFECYCLE_OBSERVER_FAILED")).count(),
                "L2: each of the four transitions must log the observer " + fault + " once, got " + captured.dbacMessages());
            Assertions.assertEquals(List.of(), LifecycleTestSupport.logContractViolations(captured, FORBIDDEN_LOG_FRAGMENTS),
                "L2: the observer failure log must follow the P1 contract");
        }
    }

    /**
     * L3: when the database cannot be created, the original throwable comes back and the holder is StartupFailed
     */
    @Test
    public void l3DatabaseCreationFailureKeepsTheOriginalThrowable() {
        List<String> violations = new ArrayList<>();
        for (Fault fault : List.of(Fault.RUNTIME, Fault.ERROR)) {
            Fixture fixture = new Fixture();
            TestFactory factory = fixture.factory();
            factory.newDatabaseFault = fault;
            InitOutcome outcome = LifecycleTestSupport.initCatching(factory);
            Throwable injected = fixture.journal.lastInjected("newDatabase");
            if (injected == null || outcome.thrown() != injected) {
                violations.add("newDatabase " + fault + ": expected the injected object back, got " + describe(outcome.thrown()));
            }
            if (!(factory.state() instanceof StartupFailed)) {
                violations.add("newDatabase " + fault + ": the holder is " + factory.state() + ", expected StartupFailed");
            }
            if (!factory.databases.isEmpty()) {
                violations.add("newDatabase " + fault + ": a database exists");
            }
        }

        Fixture fixture = new Fixture();
        TestFactory factory = fixture.factory();
        factory.controllerFault = Fault.ERROR;
        factory.closeFault = Fault.ERROR;
        InitOutcome outcome = LifecycleTestSupport.initCatching(factory);
        Throwable injected = fixture.journal.lastInjected("controller");
        if (injected == null || outcome.thrown() != injected) {
            violations.add("controller Error + close Error: expected the controller Error object back, got " + describe(outcome.thrown()));
        }
        if (!(factory.state() instanceof StartupFailed)) {
            violations.add("controller Error: the holder is " + factory.state() + ", expected StartupFailed");
        }
        StubDb created = factory.lastStub();
        if (created == null || created.closes.get() != 1) {
            violations.add("controller Error: the created database must be closed once, closes="
                + (created == null ? "no database" : created.closes.get()));
        }
        if (created != null) {
            Throwable later = LifecycleTestSupport.shutdownCatching(created);
            if (later != null || created.closes.get() != 1) {
                violations.add("controller Error: a later shutdown of the unpublished database must do nothing, threw "
                    + describe(later) + ", closes=" + created.closes.get());
            }
        }
        Assertions.assertEquals(List.of(), violations, "L3: F1 must keep the original throwable and end StartupFailed");
    }

    /**
     * L4: when the database cannot be initialized, the pool is closed once - also when shut down again - nothing stops,
     * and the original comes back
     */
    @Test
    public void l4InitializeFailureClosesThePoolAndKeepsTheOriginalThrowable() {
        List<String> violations = new ArrayList<>();
        for (InitMode mode : List.of(InitMode.DB_EXCEPTION, InitMode.RUNTIME, InitMode.ERROR)) {
            Fixture fixture = new Fixture();
            TestFactory factory = fixture.factory();
            factory.initMode = mode;
            if (mode == InitMode.ERROR) {
                factory.closeFault = Fault.ERROR;
            }
            InitOutcome outcome = LifecycleTestSupport.initCatching(factory);
            Throwable injected = fixture.journal.lastInjected("initialize");
            if (injected == null || outcome.thrown() != injected) {
                violations.add(mode + ": expected the injected initialize failure back, got " + describe(outcome.thrown()));
            }
            if (!(factory.state() instanceof StartupFailed)) {
                violations.add(mode + ": the holder is " + factory.state() + ", expected StartupFailed");
            }
            StubDb created = factory.lastStub();
            if (created == null || created.closes.get() != 1) {
                violations.add(mode + ": the pool must be closed exactly once, closes="
                    + (created == null ? "no database" : created.closes.get()));
            }
            if (fixture.observer.countTo(Stopping.class) != 0) {
                violations.add(mode + ": an initialize failure must not make the holder Stopping");
            }
            if (created != null) {
                Throwable later = LifecycleTestSupport.shutdownCatching(created);
                if (later != null || created.closes.get() != 1) {
                    violations.add(mode + ": a later shutdown must not close the pool again, threw " + describe(later)
                        + ", closes=" + created.closes.get());
                }
            }
        }
        Assertions.assertEquals(List.of(), violations, "L4: F2/F3 must close the pool once and keep the original throwable");
    }

    /**
     * L5: stopping a ready service runs unregister, clear, lease, close in that order, each once, then Disposed
     */
    @Test
    public void l5ShutdownOfReadyRunsTheCleanupInOrderOnce() throws Exception {
        Fixture fixture = new Fixture();
        TestFactory factory = fixture.factory();
        CBDatabase database = factory.init();
        Assertions.assertInstanceOf(Ready.class, factory.state(), "L5: the holder must be Ready before the shutdown");
        int start = fixture.journal.snapshot().size();

        Assertions.assertNull(LifecycleTestSupport.shutdownCatching(database), "L5: a clean shutdown must not throw");

        List<String> shutdown = fixture.journal.snapshot().subList(start, fixture.journal.snapshot().size());
        Assertions.assertEquals(List.of("state:Stopping", "unregister", "clear", "lease", "close", "state:Disposed"), shutdown,
            "L5: the shutdown must publish Stopping, run the plan in order, close the pool, then publish Disposed");
        Assertions.assertSame(fixture.registrar.registered.get(0), fixture.registrar.unregistered.get(0),
            "L5: the handler unregistered must be the one registered");
        Assertions.assertEquals(1, fixture.lease.releases.get(), "L5: the lease must be released once");
        Assertions.assertInstanceOf(Disposed.class, factory.state(), "L5: the holder must end Disposed");
    }

    /**
     * L6: a failed service stops with the plan it owns - none when it failed initializing, Ready's when it was revoked
     */
    @Test
    public void l6FailedShutsDownWithTheCleanupItOwns() throws Exception {
        Fixture early = new Fixture();
        TestFactory earlyFactory = early.factory();
        early.serviceFactory.fault = Fault.RUNTIME;
        CBDatabase earlyDatabase = earlyFactory.init();
        Failed failed = Assertions.assertInstanceOf(Failed.class, earlyFactory.state(),
            "L6: a service failure must leave the holder Failed");
        Assertions.assertEquals(FailureCode.SERVICE_UNAVAILABLE, failed.code(), "L6: the failure code");
        Assertions.assertSame(earlyDatabase, failed.database(), "L6: Failed must hold the returned database");
        Assertions.assertEquals(1, early.lease.releases.get(), "L6: the lease acquired before the failure must be released at once");
        Assertions.assertEquals(0, early.journal.count("unregister"), "L6: no handler was registered, so none is unregistered");
        Assertions.assertNull(LifecycleTestSupport.shutdownCatching(earlyDatabase), "L6: the shutdown must not throw");
        Assertions.assertEquals(1, early.lease.releases.get(),
            "L6: Failed from Initializing owns no plan; the lease is not released again");
        Assertions.assertEquals(0, early.journal.count("clear"), "L6: Failed from Initializing owns no plan; nothing is cleared");
        Assertions.assertEquals(List.of("New->Initializing", "Initializing->Failed", "Failed->Stopping", "Stopping->Disposed"),
            early.observer.names(), "L6: Failed must stop through Stopping to Disposed");

        Fixture revoked = new Fixture();
        TestFactory revokedFactory = revoked.factory();
        CBDatabase revokedDatabase = revokedFactory.init();
        Assertions.assertInstanceOf(Ready.class, revokedFactory.state(), "L6: the holder must be Ready before the revocation");
        DeploymentGuard.Revocation revocation = revoked.admitter.revocation.get();
        Assertions.assertNotNull(revocation, "FIXTURE: the guard stub did not receive a revocation");
        Assertions.assertTrue(revocation.revoke(FailureCode.DEPLOYMENT_PROPERTY_CHANGED), "L6: revoking a ready service must succeed");
        Assertions.assertFalse(revocation.revoke(FailureCode.ADVISORY_LOCK_LOST), "L6: a second revocation must change nothing");
        Failed afterRevoke = Assertions.assertInstanceOf(Failed.class, revokedFactory.state(), "L6: revocation must make it Failed");
        Assertions.assertEquals(FailureCode.DEPLOYMENT_PROPERTY_CHANGED, afterRevoke.code(), "L6: the first revocation's code is kept");
        Assertions.assertEquals(0, revoked.lease.releases.get(), "L6: revocation moves the plan; it does not run it");
        Assertions.assertNull(LifecycleTestSupport.shutdownCatching(revokedDatabase), "L6: the shutdown must not throw");
        Assertions.assertEquals(1, revoked.journal.count("unregister"), "L6: Ready's plan must run once from Failed");
        Assertions.assertEquals(1, revoked.journal.count("clear"), "L6: Ready's plan must run once from Failed");
        Assertions.assertEquals(1, revoked.lease.releases.get(), "L6: Ready's plan must run once from Failed");
        Assertions.assertInstanceOf(Disposed.class, revokedFactory.state(), "L6: the holder must end Disposed");
        Assertions.assertFalse(revocation.revoke(FailureCode.ADVISORY_LOCK_LOST), "L6: a revocation after disposal must change nothing");
    }

    /**
     * L7: one shutdown wins the CAS, runs the plan and closes the pool, once; the others wait for it, also when the close
     * fails, and only the winner rethrows its Error (C16); another holder is untouched
     */
    @Test
    public void l7ConcurrentShutdownRunsTheCleanupAndClosesThePoolOnce() throws Exception {
        for (Fault closeFault : List.of(Fault.NONE, Fault.RUNTIME, Fault.ERROR)) {
            raceShutdowns(closeFault);
        }

        Fixture first = new Fixture();
        TestFactory firstFactory = first.factory();
        CBDatabase firstDatabase = firstFactory.init();
        Fixture other = new Fixture();
        TestFactory otherFactory = other.factory();
        final CBDatabase otherDatabase = otherFactory.init();
        Assertions.assertInstanceOf(Ready.class, firstFactory.state(), "L7: the first holder must be Ready");
        Assertions.assertInstanceOf(Ready.class, otherFactory.state(), "L7: the other holder must be Ready");
        int otherJournal = other.journal.snapshot().size();

        firstDatabase.shutdown();
        Assertions.assertInstanceOf(Ready.class, otherFactory.state(), "L7: shutting one database down must not touch another holder");
        Assertions.assertEquals(otherJournal, other.journal.snapshot().size(), "L7: nothing of the other lifecycle may run");
        int afterFirst = first.journal.snapshot().size();
        firstDatabase.shutdown();
        StubDb firstStub = (StubDb) firstDatabase;
        Assertions.assertEquals(1, firstStub.closes.get(), "L7: a shutdown after Disposed must not close the pool again");
        Assertions.assertEquals(afterFirst, first.journal.snapshot().size(), "L7: a shutdown after Disposed must do nothing");
        Assertions.assertEquals(1, first.journal.count("unregister"), "L7: a second shutdown must not run the plan again");
        Assertions.assertEquals(1, first.observer.countTo(Disposed.class), "L7: Disposed is entered once");
        otherDatabase.shutdown();
    }

    /** One L7 race: eight shutdowns of a ready database at once, the winner held in its unregister */
    private static void raceShutdowns(@NotNull Fault closeFault) throws Exception {
        String label = "L7 [close " + closeFault + "]: ";
        Fixture raced = new Fixture();
        TestFactory racedFactory = raced.factory();
        CBDatabase racedDatabase = racedFactory.init();
        StubDb racedStub = (StubDb) racedDatabase;
        Assertions.assertInstanceOf(Ready.class, racedFactory.state(), label + "the raced holder must be Ready");
        racedStub.closeFault = closeFault;
        CountDownLatch inside = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicReference<Thread> winner = new AtomicReference<>();
        raced.registrar.onUnregister = () -> {
            winner.set(Thread.currentThread());
            inside.countDown();
            await(release);
        };
        CyclicBarrier barrier = new CyclicBarrier(THREADS);
        Map<Thread, Throwable> thrown = new ConcurrentHashMap<>();
        List<Thread> threads = new ArrayList<>();
        for (int i = 0; i < THREADS; i++) {
            Thread thread = new Thread(() -> {
                try {
                    barrier.await(TIMEOUT_SECONDS, TimeUnit.SECONDS);
                    racedDatabase.shutdown();
                } catch (Throwable e) {
                    thrown.put(Thread.currentThread(), e);
                } finally {
                    raced.journal.add("returned");
                }
            }, "dbac-l7-shutdown-" + closeFault + "-" + i);
            threads.add(thread);
            thread.start();
        }
        try {
            Assertions.assertTrue(inside.await(TIMEOUT_SECONDS, TimeUnit.SECONDS), "FIXTURE: " + label + "no shutdown reached the cleanup");
            List<String> returnedEarly = new ArrayList<>();
            for (Thread thread : threads) {
                if (thread != winner.get() && !awaitParked(thread)) {
                    returnedEarly.add(thread.getName());
                }
            }
            Assertions.assertEquals(List.of(), returnedEarly,
                label + "a losing shutdown must wait for the winner, not return while the cleanup is still held");
            Assertions.assertEquals(0, racedStub.closes.get(), label + "the pool must not be closed while the cleanup is held");
        } finally {
            release.countDown();
            for (Thread thread : threads) {
                thread.join(TimeUnit.SECONDS.toMillis(TIMEOUT_SECONDS));
            }
        }
        Assertions.assertEquals(List.of(), threads.stream().filter(Thread::isAlive).map(Thread::getName).toList(),
            label + "every shutdown must finish - no deadlock");
        // C16 #18, #19: whatever the close throws, every waiter is released; only the winner sees the Error
        Map<Thread, Throwable> expectedThrown = closeFault == Fault.ERROR
            ? Map.of(winner.get(), raced.journal.lastInjected("close"))
            : Map.of();
        Assertions.assertEquals(expectedThrown, thrown, label + "only the winner may throw, and only the close Error");
        Assertions.assertEquals(1, raced.observer.countTo(Stopping.class), label + "exactly one shutdown wins Stopping");
        Assertions.assertEquals(1, raced.observer.countTo(Disposed.class), label + "exactly one shutdown publishes Disposed");
        Assertions.assertEquals(1, raced.journal.count("unregister"), label + "the plan's unregister runs once");
        Assertions.assertEquals(1, raced.journal.count("clear"), label + "the plan's clear runs once");
        Assertions.assertEquals(1, raced.lease.releases.get(), label + "the plan's lease runs once");
        Assertions.assertEquals(1, racedStub.closes.get(), label + "the pool is closed exactly once, however many shutdowns race");
        Assertions.assertEquals(List.of(winner.get()), racedStub.closingThreads,
            label + "only the shutdown that won Stopping closes the pool");
        List<String> journal = raced.journal.snapshot();
        Assertions.assertEquals(THREADS, raced.journal.count("returned"), "FIXTURE: " + label + "not every shutdown recorded its return");
        List<String> order = List.of("unregister", "clear", "lease", "close", "state:Disposed", "returned");
        Assertions.assertEquals(order, journal.stream().filter(order::contains).distinct().toList(),
            label + "no shutdown may return before unregister, clear, lease, the pool close and Disposed, journal " + journal);
        Assertions.assertInstanceOf(Disposed.class, racedFactory.state(), label + "the raced holder must end Disposed");
    }

    /**
     * L8: two concurrent initializations - exactly one proceeds, the other is refused before the database is made
     */
    @Test
    public void l8ConcurrentInitializationLetsExactlyOneProceed() throws Exception {
        Fixture fixture = new Fixture();
        TestFactory factory = fixture.factory();
        List<InitOutcome> outcomes = race(factory, 2);
        try {
            long proceeded = outcomes.stream().filter(o -> o.database() != null).count();
            long refused = outcomes.stream().filter(o -> o.thrown() instanceof DBException).count();
            Assertions.assertEquals(1, proceeded, "L8: exactly one initialization must proceed, outcomes " + outcomes);
            Assertions.assertEquals(1, refused, "L8: the other must be refused with DBException, outcomes " + outcomes);
            Assertions.assertInstanceOf(Ready.class, factory.state(), "L8: the winner makes the holder Ready");
        } finally {
            shutdownAll(outcomes);
        }
    }

    /**
     * L9: the database is created once, on the winning thread, and never outside its initialization
     */
    @Test
    public void l9TheDatabaseIsCreatedOnlyInsideTheWinningInitialization() throws Exception {
        Fixture fixture = new Fixture();
        TestFactory factory = fixture.factory();
        List<InitOutcome> outcomes = race(factory, THREADS);
        try {
            Assertions.assertEquals(1, factory.newDatabaseCalls.get(), "L9: the database must be created exactly once");
            Assertions.assertEquals(1, factory.newDatabaseThreads.size(), "FIXTURE: the creating thread was not recorded");
            Assertions.assertThrows(IllegalStateException.class, factory::makeDirectly,
                "L9: making a database outside an initialization must be refused");
            Assertions.assertEquals(1, factory.newDatabaseCalls.get(), "L9: a refused direct call must not create a database");
        } finally {
            shutdownAll(outcomes);
        }

        Fixture fresh = new Fixture();
        TestFactory freshFactory = fresh.factory();
        Assertions.assertThrows(IllegalStateException.class, freshFactory::makeDirectly,
            "L9: making a database before any initialization must be refused");
        Assertions.assertEquals(0, freshFactory.newDatabaseCalls.get(), "L9: nothing may be created before an initialization");
        Assertions.assertEquals("New", LifecycleTestSupport.stateName(freshFactory.state()),
            "L9: a refused call must not change the state");

        CountDownLatch inside = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        freshFactory.onInitialize = () -> {
            inside.countDown();
            await(release);
        };
        List<InitOutcome> paused = Collections.synchronizedList(new ArrayList<>());
        Thread initializer = new Thread(() -> paused.add(LifecycleTestSupport.initCatching(freshFactory)), "dbac-l9-init");
        initializer.start();
        try {
            Assertions.assertTrue(inside.await(TIMEOUT_SECONDS, TimeUnit.SECONDS), "FIXTURE: the initialization did not start");
            Assertions.assertInstanceOf(Initializing.class, freshFactory.state(), "L9: the holder must be Initializing meanwhile");
            Assertions.assertThrows(IllegalStateException.class, freshFactory::makeDirectly,
                "L9: another thread must not be able to make a database during the initialization");
            Assertions.assertEquals(1, freshFactory.newDatabaseCalls.get(), "L9: the other thread must not create a database");
            StubDb inProgress = freshFactory.lastStub();
            Assertions.assertNotNull(inProgress, "FIXTURE: the paused initialization made no database");
            Assertions.assertThrows(IllegalStateException.class, inProgress::shutdown,
                "L9: another thread must not be able to shut the database down during the initialization (C16)");
            Assertions.assertEquals(0, inProgress.closes.get(), "L9: a refused shutdown must not close the pool");
            Assertions.assertInstanceOf(Initializing.class, freshFactory.state(), "L9: a refused shutdown must not change the state");
        } finally {
            release.countDown();
            initializer.join(TimeUnit.SECONDS.toMillis(TIMEOUT_SECONDS));
            shutdownAll(paused);
        }
        StubDb pausedDatabase = freshFactory.lastStub();
        Assertions.assertNotNull(pausedDatabase, "FIXTURE: the paused initialization made no database");
        Assertions.assertEquals(1, pausedDatabase.closes.get(), "L9: the database is closed once, by its shutdown after Ready");
        Assertions.assertInstanceOf(Disposed.class, freshFactory.state(), "L9: the paused lifecycle must end Disposed");
        Assertions.assertSame(initializer, freshFactory.newDatabaseThreads.get(0),
            "L9: the database is created on the initializing thread");

        List<String> getters = new ArrayList<>();
        List<Class<?>> types = new ArrayList<>(List.of(PolicyServiceHolder.class, DbacCBDatabase.class,
            DbacSecurityControllerFactory.class, DeploymentGuard.class, DeploymentGuard.Admission.class,
            TaintContextCloseHandler.class));
        types.addAll(List.of(PolicyServiceHolder.class.getDeclaredClasses()));
        Set<Class<?>> capabilities = Set.of(DbacCBDatabase.ShutdownLifecycle.class, DeploymentGuard.Revocation.class);
        for (Class<?> type : types) {
            for (Method method : type.getDeclaredMethods()) {
                int modifiers = method.getModifiers();
                if ((Modifier.isPublic(modifiers) || Modifier.isProtected(modifiers)) && capabilities.contains(method.getReturnType())) {
                    getters.add(type.getSimpleName() + "." + method.getName());
                }
            }
            for (Field field : type.getDeclaredFields()) {
                int modifiers = field.getModifiers();
                if ((Modifier.isPublic(modifiers) || Modifier.isProtected(modifiers)) && capabilities.contains(field.getType())) {
                    getters.add(type.getSimpleName() + "#" + field.getName());
                }
            }
        }
        Assertions.assertEquals(List.of(), getters, "L9: no public or protected member may hand out a lifecycle capability");
    }

    /**
     * L10: concurrent initializations build one policy service
     */
    @Test
    public void l10ConcurrentInitializationBuildsOneService() throws Exception {
        Fixture fixture = new Fixture();
        TestFactory factory = fixture.factory();
        List<InitOutcome> outcomes = race(factory, THREADS);
        try {
            Assertions.assertEquals(1, fixture.serviceFactory.calls.get(), "L10: exactly one policy service must be built");
            Assertions.assertEquals(1, fixture.admitter.calls.get(), "L10: the guard must run exactly once");
            Assertions.assertInstanceOf(Ready.class, factory.state(), "L10: the holder must be Ready");
        } finally {
            shutdownAll(outcomes);
        }
    }

    /**
     * L11: after StartupFailed, Failed or Disposed nothing initializes again, and the database is not even made
     */
    @Test
    public void l11NoInitializationAfterAFailureOrDisposal() throws Exception {
        List<String> violations = new ArrayList<>();

        Fixture startupFailed = new Fixture();
        TestFactory startupFailedFactory = startupFailed.factory();
        startupFailedFactory.initMode = InitMode.RUNTIME;
        LifecycleTestSupport.initCatching(startupFailedFactory);
        checkRefusedAgain("StartupFailed", startupFailedFactory, violations);

        Fixture failed = new Fixture();
        TestFactory failedFactory = failed.factory();
        failed.admitter.mode = AdmitMode.REFUSE;
        final CBDatabase failedDatabase = LifecycleTestSupport.initCatching(failedFactory).database();
        checkRefusedAgain("Failed", failedFactory, violations);

        Fixture disposed = new Fixture();
        TestFactory disposedFactory = disposed.factory();
        CBDatabase disposedDatabase = LifecycleTestSupport.initCatching(disposedFactory).database();
        if (disposedDatabase != null) {
            LifecycleTestSupport.shutdownCatching(disposedDatabase);
        }
        checkRefusedAgain("Disposed", disposedFactory, violations);
        if (failedDatabase != null) {
            LifecycleTestSupport.shutdownCatching(failedDatabase);
        }
        Assertions.assertEquals(List.of(), violations, "L11: a finished lifecycle must refuse to initialize again before super");
    }

    private static void checkRefusedAgain(@NotNull String label, @NotNull TestFactory factory, @NotNull List<String> violations) {
        String before = LifecycleTestSupport.stateName(factory.state());
        int made = factory.newDatabaseCalls.get();
        InitOutcome again = LifecycleTestSupport.initCatching(factory);
        if (!(again.thrown() instanceof DBException)) {
            violations.add(label + ": a second initialization must be refused with DBException, got "
                + (again.database() != null ? "a database" : describe(again.thrown())));
            if (again.database() != null) {
                LifecycleTestSupport.shutdownCatching(again.database());
            }
        }
        if (factory.newDatabaseCalls.get() != made) {
            violations.add(label + ": the refused initialization made a database");
        }
        if (!before.equals(LifecycleTestSupport.stateName(factory.state()))) {
            violations.add(label + ": the refused initialization changed the state from " + before + " to " + factory.state());
        }
    }

    // ---------------------------------------------------------------- LC

    /**
     * LC-1: a registration failure leaves Failed, releases what was held before returning, and never reaches Ready
     */
    @Test
    public void lc1HandlerRegistrationFailureFailsTheServiceAndReleasesWhatItHeld() throws Exception {
        Fixture fixture = new Fixture();
        TestFactory factory = fixture.factory();
        fixture.registrar.registerFault = Fault.RUNTIME;
        CBDatabase database = factory.init();

        Failed failed = Assertions.assertInstanceOf(Failed.class, factory.state(), "LC-1: a registration failure must leave Failed");
        Assertions.assertEquals(FailureCode.QM_HANDLER_UNAVAILABLE, failed.code(), "LC-1: the failure code");
        Assertions.assertSame(database, failed.database(), "LC-1: the database is returned and kept");
        Assertions.assertEquals(0, fixture.observer.countTo(Ready.class), "LC-1: Ready must never be published");
        Assertions.assertEquals(1, fixture.registrar.unregistered.size(), "LC-1: the handler must be unregistered at once");
        Assertions.assertSame(fixture.registrar.registered.get(0), fixture.registrar.unregistered.get(0),
            "LC-1: the handler unregistered must be the one whose registration failed");
        Assertions.assertEquals(1, fixture.sink.clears.get(), "LC-1: the sink must be cleared at once");
        Assertions.assertEquals(1, fixture.lease.releases.get(), "LC-1: the lease must be released at once");

        Assertions.assertNull(LifecycleTestSupport.shutdownCatching(database), "LC-1: the shutdown must not throw");
        Assertions.assertEquals(1, fixture.registrar.unregistered.size(), "LC-1: the shutdown must not unregister again");
        Assertions.assertEquals(1, fixture.sink.clears.get(), "LC-1: the shutdown must not clear again");
        Assertions.assertEquals(1, fixture.lease.releases.get(), "LC-1: the shutdown must not release again");
        Assertions.assertEquals(1, ((StubDb) database).closes.get(), "LC-1: the shutdown closes the pool");
        Assertions.assertInstanceOf(Disposed.class, factory.state(), "LC-1: the holder must end Disposed");
    }

    /**
     * LC-2: a real database refused by the guard is returned, keeps serving reads, and is closed at shutdown
     */
    @Test
    public void lc2RealDatabaseStaysReadableWhenTheGuardRefuses() throws Exception {
        Fixture fixture = new Fixture();
        TestFactory factory = fixture.factory();
        factory.realDatabase = true;
        fixture.admitter.mode = AdmitMode.REFUSE;
        fixture.admitter.refusal = FailureCode.DEPLOYMENT_NOT_ACKNOWLEDGED;
        CBDatabase database = factory.init();
        try {
            Failed failed = Assertions.assertInstanceOf(Failed.class, factory.state(), "LC-2: a refused guard must leave Failed");
            Assertions.assertEquals(FailureCode.DEPLOYMENT_NOT_ACKNOWLEDGED, failed.code(), "LC-2: the guard's code is kept");
            Assertions.assertSame(database, failed.database(), "LC-2: the database is returned and kept");
            try (Connection connection = database.openConnection();
                 Statement statement = connection.createStatement();
                 ResultSet result = statement.executeQuery("SELECT 1")) {
                Assertions.assertTrue(result.next(), "LC-2: the refused database must keep serving reads");
            }
        } finally {
            database.shutdown();
        }
        Assertions.assertInstanceOf(Disposed.class, factory.state(), "LC-2: the holder must end Disposed");
        Assertions.assertThrows(Exception.class, database::openConnection, "LC-2: the pool must be closed after shutdown");
    }

    /**
     * LC-3: Stopping is visible as soon as the shutdown's CAS wins, before any cleanup step finishes; a second shutdown
     * meanwhile closes nothing and returns only once the first has cleaned up, closed the pool and reached Disposed (C16)
     */
    @Test
    public void lc3StoppingIsPublishedBeforeTheCleanupRuns() throws Exception {
        Fixture fixture = new Fixture();
        TestFactory factory = fixture.factory();
        CBDatabase database = factory.init();
        StubDb stub = (StubDb) database;
        Assertions.assertInstanceOf(Ready.class, factory.state(), "LC-3: the holder must be Ready before the shutdown");
        CountDownLatch inside = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        fixture.registrar.onUnregister = () -> {
            inside.countDown();
            await(release);
        };
        List<Throwable> thrown = Collections.synchronizedList(new ArrayList<>());
        Thread stopper = new Thread(() -> {
            Throwable failure = LifecycleTestSupport.shutdownCatching(database);
            if (failure != null) {
                thrown.add(failure);
            }
        }, "dbac-lc3-shutdown");
        boolean[] interruptedOnReturn = new boolean[1];
        Thread second = new Thread(() -> {
            Throwable failure = LifecycleTestSupport.shutdownCatching(database);
            interruptedOnReturn[0] = Thread.currentThread().isInterrupted();
            fixture.journal.add("second-returned");
            if (failure != null) {
                thrown.add(failure);
            }
        }, "dbac-lc3-second-shutdown");
        stopper.start();
        try {
            Assertions.assertTrue(inside.await(TIMEOUT_SECONDS, TimeUnit.SECONDS), "FIXTURE: the shutdown did not reach the cleanup");
            Assertions.assertInstanceOf(Stopping.class, factory.state(), "LC-3: the holder must be Stopping while the cleanup runs");
            DeploymentGuard.Revocation revocation = fixture.admitter.revocation.get();
            Assertions.assertNotNull(revocation, "FIXTURE: the guard stub did not receive a revocation");
            Assertions.assertFalse(revocation.revoke(FailureCode.ADVISORY_LOCK_LOST),
                "LC-3: a revocation while Stopping must change nothing");
            second.start();
            Assertions.assertTrue(awaitParked(second),
                "LC-3: a second shutdown must wait for the first, not return while the cleanup is still held");
            Assertions.assertEquals(0, stub.closes.get(), "LC-3: the pool must not be closed before the cleanup finished");
            second.interrupt();
            Assertions.assertTrue(awaitParked(second),
                "LC-3: an interrupt must not make the second shutdown return before the first finished");
            Assertions.assertEquals(0, stub.closes.get(), "LC-3: an interrupted second shutdown must not close the pool");
            Assertions.assertInstanceOf(Stopping.class, factory.state(), "LC-3: the second shutdown must not change Stopping");
        } finally {
            release.countDown();
            stopper.join(TimeUnit.SECONDS.toMillis(TIMEOUT_SECONDS));
            second.join(TimeUnit.SECONDS.toMillis(TIMEOUT_SECONDS));
        }
        Assertions.assertFalse(stopper.isAlive() || second.isAlive(), "LC-3: both shutdowns must finish - no deadlock");
        Assertions.assertEquals(List.of(), thrown, "LC-3: neither shutdown may throw");
        Assertions.assertTrue(interruptedOnReturn[0], "LC-3: the second shutdown must restore the interrupt once it returns");
        Assertions.assertInstanceOf(Disposed.class, factory.state(), "LC-3: the holder must end Disposed");
        Assertions.assertEquals(1, stub.closes.get(), "LC-3: the pool is closed exactly once");
        Assertions.assertEquals(List.of(stopper), stub.closingThreads, "LC-3: only the shutdown that won Stopping closes the pool");
        Assertions.assertEquals(1, fixture.journal.count("unregister"), "LC-3: the plan runs once");
        List<String> order = List.of("unregister", "clear", "lease", "close", "state:Disposed", "second-returned");
        List<String> journal = fixture.journal.snapshot();
        Assertions.assertEquals(order, journal.stream().filter(order::contains).toList(),
            "LC-3: the second shutdown must return after unregister, clear, lease, the pool close and Disposed, journal " + journal);
    }

    /**
     * LC-4: an unregister failure is logged by class only and the rest of the cleanup still runs; an Error is rethrown after
     */
    @Test
    public void lc4UnregisterFailureDoesNotStopTheRestOfTheCleanup() throws Throwable {
        Fixture runtime = new Fixture();
        TestFactory runtimeFactory = runtime.factory();
        CBDatabase runtimeDatabase = runtimeFactory.init();
        Assertions.assertInstanceOf(Ready.class, runtimeFactory.state(), "LC-4: the holder must be Ready before the shutdown");
        runtime.registrar.unregisterFault = Fault.RUNTIME;
        Throwable[] runtimeThrown = new Throwable[1];
        Captured captured = LifecycleTestSupport.captureLogs(
            () -> runtimeThrown[0] = LifecycleTestSupport.shutdownCatching(runtimeDatabase));
        Assertions.assertNull(runtimeThrown[0], "LC-4: an unregister RuntimeException must be suppressed");
        Assertions.assertEquals(1, runtime.sink.clears.get(), "LC-4: clear must still run");
        Assertions.assertEquals(1, runtime.lease.releases.get(), "LC-4: the lease must still be released");
        Assertions.assertEquals(1, ((StubDb) runtimeDatabase).closes.get(), "LC-4: the pool must still be closed");
        Assertions.assertInstanceOf(Disposed.class, runtimeFactory.state(), "LC-4: the holder must end Disposed");
        Assertions.assertTrue(captured.dbacMessages().stream().anyMatch(m -> m.contains("event=DBAC_LIFECYCLE_HANDLER_UNREGISTER_FAILED")
                && m.contains(LifecycleTestSupport.InjectedRuntimeException.class.getName())),
            "LC-4: the unregister failure must be logged with its fixed code and exception class, got " + captured.dbacMessages());
        Assertions.assertEquals(List.of(), LifecycleTestSupport.logContractViolations(captured, FORBIDDEN_LOG_FRAGMENTS),
            "LC-4: the log must follow the P1 contract");

        Fixture error = new Fixture();
        TestFactory errorFactory = error.factory();
        CBDatabase errorDatabase = errorFactory.init();
        Assertions.assertInstanceOf(Ready.class, errorFactory.state(), "LC-4: the holder must be Ready before the shutdown");
        error.registrar.unregisterFault = Fault.ERROR;
        Throwable[] errorThrown = new Throwable[1];
        LifecycleTestSupport.captureLogs(() -> errorThrown[0] = LifecycleTestSupport.shutdownCatching(errorDatabase));
        Assertions.assertSame(error.journal.lastInjected("unregister"), errorThrown[0],
            "LC-4: the unregister Error must be rethrown, the same object, after the shutdown completed");
        Assertions.assertEquals(1, error.sink.clears.get(), "LC-4: clear must still run after an unregister Error");
        Assertions.assertEquals(1, error.lease.releases.get(), "LC-4: the lease must still be released after an unregister Error");
        Assertions.assertEquals(1, ((StubDb) errorDatabase).closes.get(), "LC-4: the pool must still be closed after an unregister Error");
        Assertions.assertInstanceOf(Disposed.class, errorFactory.state(), "LC-4: the holder must be Disposed before the Error is rethrown");
    }

    /**
     * LC-5: the close handler reports while Ready or Failed and is silent once Stopping or Disposed; whatever it hits
     * - a sink or accepting-check RuntimeException or Error, a failing log - stays inside it, logged by class only (C16)
     */
    @Test
    public void lc5TheCloseHandlerIsSilentOnceStopping() throws Throwable {
        Fixture fixture = new Fixture();
        TestFactory factory = fixture.factory();
        final CBDatabase database = factory.init();
        Assertions.assertInstanceOf(Ready.class, factory.state(), "LC-5: the holder must be Ready");
        Assertions.assertEquals(1, fixture.registrar.registered.size(), "LC-5: one close handler must be registered");
        TaintContextCloseHandler handler = Assertions.assertInstanceOf(TaintContextCloseHandler.class,
            fixture.registrar.registered.get(0), "LC-5: the registered handler must be the taint close handler");
        handler.handleContextClose(LifecycleTestSupport.context(1));
        Assertions.assertEquals(1, fixture.sink.closes.get(), "LC-5: a close while Ready must be reported");

        CountDownLatch inside = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        fixture.registrar.onUnregister = () -> {
            inside.countDown();
            await(release);
        };
        Thread stopper = new Thread(() -> LifecycleTestSupport.shutdownCatching(database), "dbac-lc5-shutdown");
        stopper.start();
        try {
            Assertions.assertTrue(inside.await(TIMEOUT_SECONDS, TimeUnit.SECONDS), "FIXTURE: the shutdown did not reach the cleanup");
            handler.handleContextClose(LifecycleTestSupport.context(2));
            Assertions.assertEquals(1, fixture.sink.closes.get(), "LC-5: a close while Stopping must not be reported");
        } finally {
            release.countDown();
            stopper.join(TimeUnit.SECONDS.toMillis(TIMEOUT_SECONDS));
        }
        Assertions.assertInstanceOf(Disposed.class, factory.state(), "LC-5: the holder must be Disposed");
        handler.handleContextClose(LifecycleTestSupport.context(3));
        Assertions.assertEquals(1, fixture.sink.closes.get(), "LC-5: a close after Disposed must not be reported");

        Fixture revoked = new Fixture();
        TestFactory revokedFactory = revoked.factory();
        final CBDatabase revokedDatabase = revokedFactory.init();
        Assertions.assertInstanceOf(Ready.class, revokedFactory.state(), "LC-5: the second holder must be Ready");
        DeploymentGuard.Revocation revocation = revoked.admitter.revocation.get();
        Assertions.assertNotNull(revocation, "FIXTURE: the guard stub did not receive a revocation");
        revocation.revoke(FailureCode.ADVISORY_LOCK_LOST);
        TaintContextCloseHandler revokedHandler = (TaintContextCloseHandler) revoked.registrar.registered.get(0);
        revokedHandler.handleContextClose(LifecycleTestSupport.context(4));
        Assertions.assertEquals(1, revoked.sink.closes.get(), "LC-5: a close while Failed must still be reported");
        revokedDatabase.shutdown();

        // C16: a sink failure, RuntimeException or Error, never reaches the query manager's dispatcher
        Set<String> eventIds = new TreeSet<>();
        for (Fault fault : List.of(Fault.RUNTIME, Fault.ERROR)) {
            Fixture failing = new Fixture();
            failing.sink.closeFault = fault;
            TaintContextCloseHandler sinkFails = new TaintContextCloseHandler(failing.sink, () -> true);
            Captured captured = LifecycleTestSupport.captureLogs(() -> Assertions.assertDoesNotThrow(
                () -> sinkFails.handleContextClose(LifecycleTestSupport.context(5)),
                "LC-5: a sink " + fault + " must not escape the close handler"));
            Assertions.assertEquals(1, failing.sink.closes.get(), "FIXTURE: the failing sink was not called");
            eventIds.add(checkCloseHandlerLog("sink " + fault, fault, captured));
        }
        // C16 #12: the accepting check is inside the same catch; production's is the holder's read-only accepting()
        for (Fault fault : List.of(Fault.RUNTIME, Fault.ERROR)) {
            Fixture failing = new Fixture();
            TaintContextCloseHandler acceptingFails = new TaintContextCloseHandler(failing.sink, () -> {
                LifecycleTestSupport.raise(fault, "accepting", failing.journal);
                return true;
            });
            Captured captured = LifecycleTestSupport.captureLogs(() -> Assertions.assertDoesNotThrow(
                () -> acceptingFails.handleContextClose(LifecycleTestSupport.context(6)),
                "LC-5: an accepting-check " + fault + " must not escape the close handler"));
            Assertions.assertEquals(0, failing.sink.closes.get(), "LC-5: a failed accepting check must not report the close");
            eventIds.add(checkCloseHandlerLog("accepting " + fault, fault, captured));
        }
        Assertions.assertEquals(4, eventIds.size(), "LC-5: every failure must be logged under a new EVENT_ID, got " + eventIds);
        // C16 #10: a log that cannot be written does not fail the close either
        for (Fault logFault : List.of(Fault.RUNTIME, Fault.ERROR)) {
            Fixture failing = new Fixture();
            failing.sink.closeFault = Fault.ERROR;
            TaintContextCloseHandler sinkFails = new TaintContextCloseHandler(failing.sink, () -> true);
            int logFailures = LifecycleTestSupport.withFailingLog(logFault, () -> Assertions.assertDoesNotThrow(
                () -> sinkFails.handleContextClose(LifecycleTestSupport.context(7)),
                "LC-5: a log " + logFault + " while logging a sink Error must not escape the close handler"));
            Assertions.assertEquals(1, logFailures, "FIXTURE: the log " + logFault + " was not raised while the close was logged");
        }
    }

    /** One close handler failure: one P1-safe line with the fixed code and the exception class; returns its EVENT_ID */
    @NotNull
    private static String checkCloseHandlerLog(@NotNull String label, @NotNull Fault fault, @NotNull Captured captured) {
        Assertions.assertEquals(List.of(), LifecycleTestSupport.logContractViolations(captured, FORBIDDEN_LOG_FRAGMENTS),
            "LC-5: a " + label + " must be logged by the P1 contract - no message, trace, URL, host or credential");
        Assertions.assertEquals(1, captured.dbacMessages().size(), "LC-5: a " + label + " must be logged once, got "
            + captured.dbacMessages());
        String message = captured.dbacMessages().get(0);
        String exception = fault == Fault.ERROR
            ? LifecycleTestSupport.InjectedError.class.getName()
            : LifecycleTestSupport.InjectedRuntimeException.class.getName();
        Assertions.assertTrue(message.contains("event=DBAC_TAINT_SINK_CLOSE_FAILED ") && message.endsWith(" exception=" + exception + "]"),
            "LC-5: a " + label + " must be logged with the fixed code and the exception class only, got " + message);
        Assertions.assertNull(captured.dbacThrowables().get(0), "LC-5: the logger must not be handed the " + label + " object");
        Matcher id = LifecycleTestSupport.EVENT_ID_PATTERN.matcher(message);
        Assertions.assertTrue(id.find(), "LC-5: a " + label + " must carry an EVENT_ID, got " + message);
        return id.group();
    }

    /** How one LC-6 initialization ends */
    private enum InitCase {
        OK,
        REFUSED,
        SERVICE_RUNTIME,
        SERVICE_ERROR,
        REGISTER_RUNTIME,
        REGISTER_ERROR,
        GUARD_RUNTIME,
        GUARD_ERROR
    }

    /** The log entries one LC-6 run must produce: event code -> how many, and the fault each was injected with */
    private record ExpectedEvents(@NotNull Map<String, Integer> counts, @NotNull Map<String, Fault> faults) {
    }

    /**
     * LC-6: the C15 failure matrix - every init outcome against every cleanup-step failure, shut down once and twice
     * <p>
     * 8 initialization outcomes x {none, RuntimeException, Error} for each of unregister, sink clear,
     * lease release and the pool close x one or two shutdowns: 1296 runs. In every run Ready is entered
     * at most once, every acquired resource is released exactly once, the pool is closed exactly once -
     * by the failed startup or by the first shutdown, a later shutdown being a no-op (C16) - every cleanup step is attempted,
     * the state reaches its terminal value, the original throwable of a failed startup is the one
     * thrown, the first Error of a shutdown is rethrown after Disposed, every injected failure is
     * logged once per occurrence under its own fixed event code with its exception class, and the
     * logs carry nothing of the injected messages.
     */
    @Test
    public void lc6CleanupFailureMatrixNeverRevivesReadyAndAlwaysTerminates() throws Throwable {
        List<String> violations = new ArrayList<>();
        int runs = 0;
        Fault[] faults = Fault.values();
        for (InitCase initCase : InitCase.values()) {
            for (Fault unregister : faults) {
                for (Fault clear : faults) {
                    for (Fault lease : faults) {
                        for (Fault close : faults) {
                            for (int shutdowns = 1; shutdowns <= 2; shutdowns++) {
                                runs++;
                                String label = initCase + " unregister=" + unregister + " clear=" + clear + " lease=" + lease
                                    + " close=" + close + " shutdowns=" + shutdowns;
                                int count = shutdowns;
                                ExpectedEvents[] expected = new ExpectedEvents[1];
                                Captured captured = LifecycleTestSupport.captureLogs(() ->
                                    expected[0] = runMatrixCase(label, initCase, unregister, clear, lease, close, count, violations));
                                for (String violation : LifecycleTestSupport.logContractViolations(captured, FORBIDDEN_LOG_FRAGMENTS)) {
                                    violations.add(label + ": " + violation);
                                }
                                if (expected[0] != null) {
                                    checkEvents(label, captured, expected[0], violations);
                                }
                            }
                        }
                    }
                }
            }
        }
        System.out.println("[DBAC P3] LC-6 failure matrix: runs=" + runs + " violations=" + violations.size());
        Assertions.assertEquals(1296, runs, "FIXTURE: the matrix must run 1296 cases");
        Assertions.assertEquals(List.of(), violations.size() > 25 ? violations.subList(0, 25) : violations,
            "LC-6: " + violations.size() + " violations of the cleanup error policy (first 25 shown)");
    }

    @Nullable
    private static ExpectedEvents runMatrixCase(
        @NotNull String label,
        @NotNull InitCase initCase,
        @NotNull Fault unregister,
        @NotNull Fault clear,
        @NotNull Fault lease,
        @NotNull Fault close,
        int shutdowns,
        @NotNull List<String> violations
    ) {
        Fixture fixture = new Fixture();
        final TestFactory factory = fixture.factory();
        fixture.registrar.unregisterFault = unregister;
        fixture.sink.clearFault = clear;
        fixture.lease.fault = lease;
        factory.closeFault = close;
        switch (initCase) {
            case REFUSED -> fixture.admitter.mode = AdmitMode.REFUSE;
            case SERVICE_RUNTIME -> fixture.serviceFactory.fault = Fault.RUNTIME;
            case SERVICE_ERROR -> fixture.serviceFactory.fault = Fault.ERROR;
            case REGISTER_RUNTIME -> fixture.registrar.registerFault = Fault.RUNTIME;
            case REGISTER_ERROR -> fixture.registrar.registerFault = Fault.ERROR;
            case GUARD_RUNTIME -> fixture.admitter.mode = AdmitMode.THROW_RUNTIME;
            case GUARD_ERROR -> fixture.admitter.mode = AdmitMode.THROW_ERROR;
            default -> {
                // succeeds
            }
        }
        boolean startupError = initCase == InitCase.SERVICE_ERROR || initCase == InitCase.REGISTER_ERROR
            || initCase == InitCase.GUARD_ERROR;
        final boolean leaseAcquired = initCase != InitCase.REFUSED && initCase != InitCase.GUARD_RUNTIME
            && initCase != InitCase.GUARD_ERROR;
        final boolean registerAttempted = initCase == InitCase.OK || initCase == InitCase.REGISTER_RUNTIME
            || initCase == InitCase.REGISTER_ERROR;

        InitOutcome outcome = LifecycleTestSupport.initCatching(factory);
        State afterInit = factory.state();
        StubDb database = factory.lastStub();
        if (database == null) {
            violations.add(label + ": FIXTURE no database was created");
            return null;
        }
        if (startupError) {
            Throwable original = fixture.journal.lastInjected(switch (initCase) {
                case SERVICE_ERROR -> "service";
                case REGISTER_ERROR -> "register";
                default -> "admit";
            });
            if (original == null || outcome.thrown() != original) {
                violations.add(label + ": the startup must rethrow the original Error, got " + describe(outcome.thrown()));
            }
            if (!(afterInit instanceof StartupFailed)) {
                violations.add(label + ": after a startup Error the holder is " + afterInit + ", expected StartupFailed");
            }
            if (database.closes.get() != 1) {
                violations.add(label + ": the created database must be closed once during the failed startup, closes="
                    + database.closes.get());
            }
        } else {
            if (outcome.database() != database) {
                violations.add(label + ": the database must be returned, got " + describe(outcome.thrown()));
            }
            FailureCode expected = switch (initCase) {
                case REFUSED -> FailureCode.DEPLOYMENT_NOT_ACKNOWLEDGED;
                case SERVICE_RUNTIME -> FailureCode.SERVICE_UNAVAILABLE;
                case REGISTER_RUNTIME -> FailureCode.QM_HANDLER_UNAVAILABLE;
                case GUARD_RUNTIME -> FailureCode.DEPLOYMENT_CHECK_FAILED;
                default -> null;
            };
            if (expected == null && !(afterInit instanceof Ready)) {
                violations.add(label + ": the holder is " + afterInit + ", expected Ready");
            }
            if (expected != null && !(afterInit instanceof Failed failed && failed.code() == expected)) {
                violations.add(label + ": the holder is " + afterInit + ", expected Failed(" + expected + ")");
            }
        }

        for (int i = 1; i <= shutdowns; i++) {
            Throwable thrown = LifecycleTestSupport.shutdownCatching(database);
            String expectedWhere = null;
            if (i == 1 && afterInit instanceof Ready) {
                expectedWhere = firstError(List.of("unregister", "clear", "lease", "close"), List.of(unregister, clear, lease, close));
            } else if (i == 1 && !startupError && close == Fault.ERROR) {
                expectedWhere = "close";
            }
            if (expectedWhere == null && thrown != null) {
                violations.add(label + ": shutdown " + i + " must not throw, got " + describe(thrown));
            }
            if (expectedWhere != null && thrown != fixture.journal.lastInjected(expectedWhere)) {
                violations.add(label + ": shutdown " + i + " must rethrow the first Error (" + expectedWhere + "), got "
                    + describe(thrown));
            }
            if (i == 1 && !startupError && !(factory.state() instanceof Disposed)) {
                violations.add(label + ": after the shutdown the holder is " + factory.state() + ", expected Disposed");
            }
        }

        int expectedSteps = registerAttempted ? 1 : 0;
        if (fixture.journal.count("unregister") != expectedSteps) {
            violations.add(label + ": unregister ran " + fixture.journal.count("unregister") + " times, expected " + expectedSteps);
        }
        if (fixture.journal.count("clear") != expectedSteps) {
            violations.add(label + ": clear ran " + fixture.journal.count("clear") + " times, expected " + expectedSteps);
        }
        if (fixture.lease.releases.get() != (leaseAcquired ? 1 : 0)) {
            violations.add(label + ": the lease was released " + fixture.lease.releases.get() + " times, expected "
                + (leaseAcquired ? 1 : 0));
        }
        // C16: one pool close per initialization - the failed startup's, or the first shutdown's
        int expectedCloses = 1;
        if (database.closes.get() != expectedCloses) {
            violations.add(label + ": the pool was closed " + database.closes.get() + " times, expected " + expectedCloses);
        }
        if (fixture.observer.readyReentered()) {
            violations.add(label + ": Ready was entered more than once");
        }
        if (fixture.observer.countTo(Ready.class) != (initCase == InitCase.OK ? 1 : 0)) {
            violations.add(label + ": Ready was entered " + fixture.observer.countTo(Ready.class) + " times");
        }
        long expectedTerminal = startupError ? 0 : 1;
        if (fixture.observer.countTo(Stopping.class) != expectedTerminal || fixture.observer.countTo(Disposed.class) != expectedTerminal) {
            violations.add(label + ": Stopping/Disposed were entered " + fixture.observer.countTo(Stopping.class) + "/"
                + fixture.observer.countTo(Disposed.class) + " times, expected " + expectedTerminal);
        }
        State terminal = factory.state();
        if (startupError ? !(terminal instanceof StartupFailed) : !(terminal instanceof Disposed)) {
            violations.add(label + ": the final state is " + terminal);
        }

        Map<String, Integer> counts = new LinkedHashMap<>();
        Map<String, Fault> injectedAs = new LinkedHashMap<>();
        expectEvent(counts, injectedAs, "DBAC_LIFECYCLE_HANDLER_UNREGISTER_FAILED", unregister, registerAttempted ? 1 : 0);
        expectEvent(counts, injectedAs, "DBAC_LIFECYCLE_SINK_CLEAR_FAILED", clear, registerAttempted ? 1 : 0);
        expectEvent(counts, injectedAs, "DBAC_LIFECYCLE_LEASE_RELEASE_FAILED", lease, leaseAcquired ? 1 : 0);
        expectEvent(counts, injectedAs, "DBAC_LIFECYCLE_DATABASE_CLOSE_FAILED", close, expectedCloses);
        Fault admission = switch (initCase) {
            case SERVICE_RUNTIME, REGISTER_RUNTIME, GUARD_RUNTIME -> Fault.RUNTIME;
            case SERVICE_ERROR, REGISTER_ERROR, GUARD_ERROR -> Fault.ERROR;
            default -> Fault.NONE;
        };
        expectEvent(counts, injectedAs, "DBAC_LIFECYCLE_ADMISSION_FAILED", admission, 1);
        expectEvent(counts, injectedAs, "DBAC_LIFECYCLE_OBSERVER_FAILED", Fault.NONE, 0);
        return new ExpectedEvents(counts, injectedAs);
    }

    private static void expectEvent(
        @NotNull Map<String, Integer> counts,
        @NotNull Map<String, Fault> injectedAs,
        @NotNull String code,
        @NotNull Fault fault,
        int occurrences
    ) {
        counts.put(code, fault == Fault.NONE ? 0 : occurrences);
        injectedAs.put(code, fault);
    }

    /** C15 #3: each injected failure is logged once per occurrence, under its own code, with its exception class */
    private static void checkEvents(
        @NotNull String label,
        @NotNull Captured captured,
        @NotNull ExpectedEvents expected,
        @NotNull List<String> violations
    ) {
        for (Map.Entry<String, Integer> entry : expected.counts().entrySet()) {
            String code = entry.getKey();
            List<String> logged = captured.dbacMessages().stream().filter(m -> m.contains("event=" + code + " ")).toList();
            if (logged.size() != entry.getValue()) {
                violations.add(label + ": " + code + " was logged " + logged.size() + " times, expected " + entry.getValue());
            }
            Fault fault = expected.faults().get(code);
            String exception = "exception=" + (fault == Fault.ERROR
                ? LifecycleTestSupport.InjectedError.class.getName()
                : LifecycleTestSupport.InjectedRuntimeException.class.getName());
            for (String message : logged) {
                if (!message.contains(exception)) {
                    violations.add(label + ": " + code + " does not name the injected exception class: " + message);
                }
            }
        }
    }

    @Nullable
    private static String firstError(@NotNull List<String> steps, @NotNull List<Fault> faults) {
        for (int i = 0; i < steps.size(); i++) {
            if (faults.get(i) == Fault.ERROR) {
                return steps.get(i);
            }
        }
        return null;
    }

    // ---------------------------------------------------------------- TR

    /**
     * TR-5: disposal clears the taint sink and unregisters the close handler, once each
     */
    @Test
    public void tr5DisposalClearsTheSinkAndUnregistersTheHandlerOnce() throws Exception {
        Fixture fixture = new Fixture();
        TestFactory factory = fixture.factory();
        CBDatabase database = factory.init();
        Assertions.assertInstanceOf(Ready.class, factory.state(), "TR-5: the holder must be Ready");
        database.shutdown();
        database.shutdown();
        Assertions.assertEquals(1, fixture.sink.clears.get(), "TR-5: the sink must be cleared exactly once");
        Assertions.assertEquals(fixture.registrar.registered, fixture.registrar.unregistered,
            "TR-5: exactly the registered handler must be unregistered, once");
        Assertions.assertInstanceOf(Disposed.class, factory.state(), "TR-5: the holder must end Disposed");
    }

    // ---------------------------------------------------------------- helpers

    /** Starts {@code threads} initializations at once and returns what each did */
    @NotNull
    private static List<InitOutcome> race(@NotNull TestFactory factory, int threads) throws InterruptedException {
        CyclicBarrier barrier = new CyclicBarrier(threads);
        List<InitOutcome> outcomes = Collections.synchronizedList(new ArrayList<>());
        List<Thread> started = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            Thread thread = new Thread(() -> {
                try {
                    barrier.await(TIMEOUT_SECONDS, TimeUnit.SECONDS);
                } catch (Exception e) {
                    outcomes.add(new InitOutcome(null, e));
                    return;
                }
                outcomes.add(LifecycleTestSupport.initCatching(factory));
            }, "dbac-init-race-" + i);
            started.add(thread);
            thread.start();
        }
        for (Thread thread : started) {
            thread.join(TimeUnit.SECONDS.toMillis(TIMEOUT_SECONDS));
        }
        Assertions.assertEquals(threads, outcomes.size(), "FIXTURE: not every racing initialization finished");
        return new ArrayList<>(outcomes);
    }

    private static void shutdownAll(@NotNull List<InitOutcome> outcomes) {
        synchronized (outcomes) {
            for (InitOutcome outcome : outcomes) {
                if (outcome.database() != null) {
                    LifecycleTestSupport.shutdownCatching(outcome.database());
                }
            }
        }
    }

    /**
     * Whether {@code thread} is waiting - seen parked {@code PARKED_POLLS} times in a row - rather than finished
     */
    private static boolean awaitParked(@NotNull Thread thread) throws InterruptedException {
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
            Thread.sleep(PARKED_POLL_MILLIS);
        }
        return false;
    }

    private static void await(@NotNull CountDownLatch latch) {
        try {
            if (!latch.await(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                throw new IllegalStateException("FIXTURE: a latch was never released");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("FIXTURE: interrupted", e);
        }
    }

    @NotNull
    private static String describe(@Nullable Throwable thrown) {
        if (thrown == null) {
            return "nothing";
        }
        return thrown.getClass().getSimpleName() + "@" + Integer.toHexString(System.identityHashCode(thrown));
    }
}
