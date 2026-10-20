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
import io.cloudbeaver.service.dbac.PolicyServiceHolder;
import io.cloudbeaver.service.dbac.PolicyServiceHolder.Disposed;
import io.cloudbeaver.service.dbac.PolicyServiceHolder.Ready;
import io.cloudbeaver.service.dbac.db.DbacCBDatabase;
import io.cloudbeaver.service.dbac.db.DbacSchema;
import io.cloudbeaver.service.dbac.policy.BoundedMetadataConnections;
import io.cloudbeaver.service.dbac.policy.DbAccessPolicyConfig;
import io.cloudbeaver.service.dbac.policy.DbAccessPolicyService;
import io.cloudbeaver.service.dbac.policy.DbOperationCategory;
import io.cloudbeaver.service.dbac.policy.LeaseState;
import io.cloudbeaver.service.dbac.policy.MetadataLease;
import io.cloudbeaver.service.dbac.policy.MetadataLeaseSource;
import io.cloudbeaver.service.dbac.policy.MetadataPurpose;
import io.cloudbeaver.service.dbac.policy.MetadataUnavailableException;
import io.cloudbeaver.service.dbac.policy.WriteAuthorizationRequest;
import io.cloudbeaver.service.dbac.tempwrite.MetadataConnectionSource;
import io.cloudbeaver.service.security.EmbeddedSecurityControllerFactory;
import io.cloudbeaver.service.security.db.CBDatabase;
import io.cloudbeaver.test.platform.dbac.LifecycleTestSupport.Fault;
import io.cloudbeaver.test.platform.dbac.MetadataTestSupport.FakeConnection;
import io.cloudbeaver.test.platform.dbac.MetadataTestSupport.FakeSource;
import io.cloudbeaver.test.platform.dbac.MetadataTestSupport.InjectedSqlException;
import io.cloudbeaver.test.platform.dbac.MetadataTestSupport.Outcome;
import io.cloudbeaver.test.platform.dbac.MetadataTestSupport.Pending;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.lang.ref.WeakReference;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.SQLException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

/**
 * P5-1a: who owns a bounded source, how it shuts down, and what outlives it
 * <p>
 * SD runs the two-phase shutdown on its own. EX runs it inside the real policy lifecycle, the way the
 * server does: the metadata database's close runnable - {@code beginClose}, the pool, {@code finishClose} -
 * with a failure put into any of the three. OWN pins who may create a source and that both halves are
 * kept; RS pins that a connection nobody could release is held for the rest of the process.
 */
public class MetadataShutdownTest {

    private static final Duration WAIT = Duration.ofSeconds(10);
    private static final Duration SHORT_FINISH = Duration.ofMillis(500);
    private static final String BEGIN_CODE = "event=DBAC_METADATA_BEGIN_CLOSE_FAILED ";
    private static final String POOL_CODE = "event=DBAC_LIFECYCLE_DATABASE_CLOSE_FAILED ";
    private static final String FINISH_CODE = "event=DBAC_METADATA_FINISH_CLOSE_FAILED ";
    private static final List<String> FORBIDDEN = List.of(LifecycleTestSupport.SECRET_MARKER, "secret-host.internal.example",
        "jdbc:postgresql://", LifecycleTestSupport.CREDENTIAL_FRAGMENT, "injected at");

    private final MetadataLeaseFixture leases = new MetadataLeaseFixture();

    @AfterEach
    public void closeLeases() {
        leases.close();
    }

    @BeforeAll
    public static void startServer() throws Exception {
        CEAppStarter.startServerIfNotStarted();
    }

    // ---------------------------------------------------------------- SD: two-phase shutdown

    /**
     * SD-1: after beginClose a borrow is refused at once and nothing is submitted
     */
    @Test
    public void sd1BeginCloseRefusesNewBorrows() {
        FakeSource raw = new FakeSource();
        BoundedMetadataConnections.Owned owned = leases.owned(raw, BoundedMetadataConnections.Tuning.PRODUCTION);
        owned.shutdown().beginClose();
        Outcome<MetadataLease> outcome = MetadataTestSupport.open(owned.leases(), MetadataTestSupport.budget(WAIT), WAIT);
        Assertions.assertEquals(MetadataUnavailableException.Reason.CLOSED, MetadataTestSupport.refusal(outcome), "SD-1");
        Assertions.assertTrue(outcome.elapsedNanos() < TimeUnit.MILLISECONDS.toNanos(500), "SD-1: at once");
        Assertions.assertEquals(0, owned.leases().submittedTasks(), "SD-1: nothing submitted");
        Assertions.assertEquals(0, raw.calls.get(), "SD-1: nothing borrowed");
    }

    /**
     * SD-2: the pool close wakes the workers still waiting on it; they free their slots, and a connection
     * already handed out is disposed afterwards like any other
     */
    @Test
    public void sd2ThePoolCloseWakesWaitingWorkers() {
        FakeSource raw = new FakeSource();
        BoundedMetadataConnections.Owned owned = leases.owned(raw, MetadataTestSupport.tuning(Duration.ofSeconds(5),
            BoundedMetadataConnections.Probe.NONE));
        final MetadataLease held = MetadataTestSupport.open(owned.leases(), MetadataTestSupport.budget(WAIT), WAIT).get();
        raw.gate = new CountDownLatch(1);
        for (int i = 0; i < 2; i++) {
            Assertions.assertEquals(MetadataUnavailableException.Reason.TIMEOUT, MetadataTestSupport.refusal(
                MetadataTestSupport.open(owned.leases(), MetadataTestSupport.budget(Duration.ofMillis(300)), WAIT)),
                "SD-2: the callers give up");
        }
        Assertions.assertEquals(2, owned.leases().runningWorkers(), "SD-2: two workers wait on the pool");

        owned.shutdown().beginClose();
        raw.fails = new SQLException("pool closed");
        raw.gate.countDown();
        owned.shutdown().finishClose();

        BoundedMetadataConnections.ShutdownReport report = owned.leases().lastShutdownReport();
        Assertions.assertNotNull(report, "SD-2: a report");
        Assertions.assertEquals(List.of(0, true), List.of(report.stuckWorkers(), report.executorTerminated()),
            "SD-2: the woken workers finished within the wait");
        Assertions.assertEquals(BoundedMetadataConnections.Health.CLOSED, owned.leases().health(), "SD-2: closed");
        Assertions.assertEquals(BoundedMetadataConnections.CAPACITY - 1, owned.leases().availableSlots(),
            "SD-2: the two failed borrows freed their slots; the held lease keeps its own");
        held.close();
        Assertions.assertEquals(LeaseState.RETURNED, held.state(), "SD-2: a lease closed after shutdown is disposed normally");
        Assertions.assertEquals(BoundedMetadataConnections.CAPACITY, owned.leases().availableSlots(), "SD-2: every slot back");
    }

    /**
     * SD-3: a pool close that fails still lets finishClose run; an Error is rethrown, and the failure is logged once
     */
    @Test
    public void sd3APoolCloseFailureStillFinishes() throws Throwable {
        for (Fault pool : List.of(Fault.RUNTIME, Fault.ERROR)) {
            ShutdownRun run = shutdown(Fault.NONE, pool, Fault.NONE);
            Assertions.assertEquals(List.of("begin", "pool", "finish"), run.phases(), "SD-3 " + pool + ": every phase, in order");
            Assertions.assertEquals(BoundedMetadataConnections.Health.CLOSED, run.health(), "SD-3 " + pool + ": finished");
            Assertions.assertSame(pool == Fault.ERROR ? run.injected("pool") : null, run.thrown(), "SD-3 " + pool + ": what is rethrown");
            Assertions.assertEquals(1, run.count(POOL_CODE), "SD-3 " + pool + ": the pool failure logged once");
        }
    }

    /**
     * SD-4: a beginClose that fails still lets the pool close and finishClose run, and finishClose stops borrowing itself
     */
    @Test
    public void sd4ABeginCloseFailureStillClosesEverything() throws Throwable {
        for (Fault begin : List.of(Fault.RUNTIME, Fault.ERROR)) {
            ShutdownRun run = shutdown(begin, Fault.NONE, Fault.NONE);
            Assertions.assertEquals(List.of("begin", "pool", "finish"), run.phases(), "SD-4 " + begin + ": every phase, in order");
            Assertions.assertEquals(BoundedMetadataConnections.Health.CLOSED, run.health(), "SD-4 " + begin + ": closed regardless");
            Assertions.assertTrue(run.report() != null && run.report().executorTerminated(),
                "SD-4 " + begin + ": finishClose shut the workers down itself, got " + run.report());
            Assertions.assertSame(begin == Fault.ERROR ? run.injected("begin") : null, run.thrown(), "SD-4 " + begin);
        }
    }

    /**
     * SD-5: a finishClose that fails comes after the pool close; an Error is rethrown
     */
    @Test
    public void sd5AFinishCloseFailureComesAfterThePool() throws Throwable {
        for (Fault finish : List.of(Fault.RUNTIME, Fault.ERROR)) {
            ShutdownRun run = shutdown(Fault.NONE, Fault.NONE, finish);
            Assertions.assertEquals(List.of("begin", "pool", "finish"), run.phases(), "SD-5 " + finish + ": the pool closed first");
            Assertions.assertSame(finish == Fault.ERROR ? run.injected("finish") : null, run.thrown(), "SD-5 " + finish);
            Assertions.assertEquals(1, run.count(FINISH_CODE), "SD-5 " + finish + ": logged once");
        }
    }

    /**
     * SD-6: four shutdowns at once run each phase exactly once, and none returns before the close is over
     */
    @Test
    public void sd6ConcurrentShutdownsRunEachPhaseOnce() throws Exception {
        LifecycleTestSupport.Fixture fixture = new LifecycleTestSupport.Fixture();
        LifecycleTestSupport.TestFactory factory = fixture.factory();
        factory.databaseMaker = (application, config, lifecycle) ->
            new ProbedDb(application, config, lifecycle, fixture.journal, Fault.NONE, Fault.NONE, Fault.NONE, 200);
        CBDatabase database = factory.init();
        Assertions.assertInstanceOf(Ready.class, factory.state(), "FIXTURE SD-6: Ready");
        CyclicBarrier barrier = new CyclicBarrier(4);
        List<Pending<String>> callers = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            callers.add(MetadataTestSupport.start("dbac-sd6-shutdown-" + i, () -> {
                barrier.await(10, TimeUnit.SECONDS);
                database.shutdown();
                return fixture.journal.count("finish") + "/" + (factory.state() instanceof Disposed);
            }));
        }
        for (Pending<String> caller : callers) {
            Assertions.assertEquals("1/true", caller.await(WAIT).get(), "SD-6: every shutdown returns after the close is over");
        }
        Assertions.assertEquals(List.of("begin", "pool", "finish"), phases(fixture.journal), "SD-6: each phase once, in order");
    }

    /**
     * SD-7: after finishClose, a connection nobody can release is kept for the process, not quarantined, and logged by numbers
     */
    @Test
    public void sd7ALateUnreleasableConnectionIsKeptNotQuarantined() throws Throwable {
        leases.allowResidue();
        FakeSource raw = new FakeSource();
        BoundedMetadataConnections.Owned owned = leases.owned(raw, MetadataTestSupport.tuning(SHORT_FINISH,
            BoundedMetadataConnections.Probe.NONE));
        MetadataLease held = MetadataTestSupport.open(owned.leases(), MetadataTestSupport.budget(WAIT), WAIT).get();
        held.query(MetadataTestSupport.valueQuery());
        FakeConnection connection = raw.only();
        connection.closeFails = new InjectedSqlException("close");
        connection.abortFails = new InjectedSqlException("abort");
        owned.shutdown().beginClose();
        owned.shutdown().finishClose();

        LifecycleTestSupport.Captured captured = LifecycleTestSupport.captureLogs(held::close);
        Assertions.assertEquals(LeaseState.RESIDUAL, held.state(), "SD-7: kept");
        Assertions.assertEquals(List.of(0, 1), List.of(owned.leases().quarantined(), owned.leases().residualHeld()),
            "SD-7: not quarantined, one kept");
        Assertions.assertTrue(captured.dbacMessages().stream().anyMatch(message -> message.contains("event=DBAC_METADATA_RESIDUAL ")
            && message.contains("kept=1")), "SD-7: logged by number, got " + captured.dbacMessages());
        Assertions.assertEquals(List.of(), LifecycleTestSupport.logContractViolations(captured, MetadataTestSupport.SECRET_FRAGMENTS),
            "SD-7: the P1 log contract");
    }

    /**
     * SD-8: four workers stuck for good: finishClose returns after its wait and reports exactly four; none is interrupted
     */
    @Test
    public void sd8StuckWorkersAreReportedNotInterrupted() {
        leases.allowResidue();
        FakeSource raw = new FakeSource();
        raw.gate = new CountDownLatch(1);
        BoundedMetadataConnections.Owned owned = leases.owned(raw, MetadataTestSupport.tuning(SHORT_FINISH,
            BoundedMetadataConnections.Probe.NONE));
        for (int i = 0; i < BoundedMetadataConnections.CAPACITY; i++) {
            Assertions.assertEquals(MetadataUnavailableException.Reason.TIMEOUT, MetadataTestSupport.refusal(
                MetadataTestSupport.open(owned.leases(), MetadataTestSupport.budget(Duration.ofMillis(300)), WAIT)),
                "SD-8: the caller leaves");
        }
        Assertions.assertEquals(MetadataUnavailableException.Reason.CAPACITY, MetadataTestSupport.refusal(
            MetadataTestSupport.open(owned.leases(), MetadataTestSupport.budget(WAIT), WAIT)), "SD-8: a fifth cannot get stuck");
        owned.shutdown().beginClose();
        Outcome<Object> finish = MetadataTestSupport.within(WAIT, () -> {
            owned.shutdown().finishClose();
            return null;
        });
        Assertions.assertTrue(finish.finished(), "SD-8: finishClose must return");
        long millis = TimeUnit.NANOSECONDS.toMillis(finish.elapsedNanos());
        Assertions.assertTrue(millis >= SHORT_FINISH.toMillis() - 50 && millis < SHORT_FINISH.toMillis() + 3000,
            "SD-8: after its wait, took " + millis + "ms");
        BoundedMetadataConnections.ShutdownReport report = owned.leases().lastShutdownReport();
        Assertions.assertEquals(List.of(BoundedMetadataConnections.CAPACITY, false),
            List.of(report.stuckWorkers(), report.executorTerminated()),
            "SD-8: exactly four stuck workers reported");
        Assertions.assertTrue(raw.borrowingThreads.stream().allMatch(Thread::isDaemon), "SD-8: daemon threads");
        raw.gate.countDown();
        Assertions.assertTrue(MetadataTestSupport.eventually(() -> raw.made.size() == BoundedMetadataConnections.CAPACITY
            && raw.made.stream().allMatch(connection -> connection.closes.get() == 1)), "SD-8: released, each late connection closed once");
        Assertions.assertEquals(0, raw.interruptedWorkers.get(), "SD-8: no worker was interrupted");
        Assertions.assertEquals(0, MetadataLeaseFixture.awaitThreadsGone(owned.leases().serial()), "SD-8: and the threads end");
    }

    /**
     * SD-9: a disposal that saw the source still closing, but quarantines only after finishClose has passed its slot,
     * moves the connection to the keeper itself - nothing is left only in the source
     */
    @Test
    public void sd9AQuarantineAfterTheFinalScanStillReachesTheKeeper() throws Exception {
        leases.allowResidue();
        CountDownLatch reached = new CountDownLatch(1);
        CountDownLatch hold = new CountDownLatch(1);
        FakeSource raw = new FakeSource();
        BoundedMetadataConnections.Owned owned = leases.owned(raw, MetadataTestSupport.tuning(SHORT_FINISH, point -> {
            if (point == BoundedMetadataConnections.ProbePoint.DISPOSAL_RETAINING) {
                reached.countDown();
                try {
                    hold.await(30, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }));
        final MetadataLease lease = MetadataTestSupport.open(owned.leases(), MetadataTestSupport.budget(WAIT), WAIT).get();
        FakeConnection connection = raw.only();
        connection.closeFails = new InjectedSqlException("close");
        connection.abortFails = new InjectedSqlException("abort");
        owned.shutdown().beginClose();
        final Pending<Object> disposal = MetadataTestSupport.start("dbac-sd9-dispose", () -> {
            lease.close();
            return null;
        });
        Assertions.assertTrue(reached.await(10, TimeUnit.SECONDS), "SD-9: the disposal must reach the quarantine");
        owned.shutdown().finishClose();
        Assertions.assertEquals(0, owned.leases().lastShutdownReport().transferredToKeeper(),
            "FIXTURE SD-9: finishClose passed the slot before the quarantine");
        hold.countDown();
        Assertions.assertTrue(disposal.await(WAIT).finished(), "SD-9: the disposal completes");
        Assertions.assertEquals(List.of(LeaseState.RESIDUAL, 0, 1), List.of(lease.state(), owned.leases().quarantined(),
            owned.leases().residualHeld()), "SD-9: kept for the process, not left in a slot of a closed source");
    }

    /**
     * SD-10: finishClose drops the keeper registration only when every slot is settled - a connection a disposal has just
     * quarantined, but not yet handed to the keeper, keeps it registered, so the keeper still holds it for the process
     */
    @Test
    public void sd10TheKeeperRegistrationOutlivesAQuarantineInFlight() throws Exception {
        leases.allowResidue();
        CountDownLatch retaining = new CountDownLatch(1);
        CountDownLatch scanned = new CountDownLatch(1);
        CountDownLatch quarantined = new CountDownLatch(1);
        CountDownLatch releaseRetaining = new CountDownLatch(1);
        CountDownLatch releaseScanned = new CountDownLatch(1);
        CountDownLatch releaseQuarantined = new CountDownLatch(1);
        FakeSource raw = new FakeSource();
        BoundedMetadataConnections.Owned owned = leases.owned(raw, MetadataTestSupport.tuning(SHORT_FINISH, point -> {
            switch (point) {
                case DISPOSAL_RETAINING -> stop(retaining, releaseRetaining);
                case FINISH_SCANNED -> stop(scanned, releaseScanned);
                case DISPOSAL_QUARANTINED -> stop(quarantined, releaseQuarantined);
                default -> {
                    // not stopped here
                }
            }
        }));
        final MetadataLease lease = MetadataTestSupport.open(owned.leases(), MetadataTestSupport.budget(WAIT), WAIT).get();
        FakeConnection connection = raw.only();
        connection.closeFails = new InjectedSqlException("close");
        connection.abortFails = new InjectedSqlException("abort");
        final int residualsBefore = BoundedMetadataConnections.processResidualCount();
        owned.shutdown().beginClose();
        final Pending<Object> disposal = MetadataTestSupport.start("dbac-sd10-dispose", () -> {
            lease.close();
            return null;
        });
        Assertions.assertTrue(retaining.await(10, TimeUnit.SECONDS), "SD-10: the disposal reaches the quarantine while closing");
        final Pending<Object> finish = MetadataTestSupport.start("dbac-sd10-finish", () -> {
            owned.shutdown().finishClose();
            return null;
        });
        Assertions.assertTrue(scanned.await(10, TimeUnit.SECONDS), "SD-10: finishClose scans before the connection is in the slot");
        releaseRetaining.countDown();
        Assertions.assertTrue(quarantined.await(10, TimeUnit.SECONDS), "SD-10: the disposal quarantines after the scan");
        releaseScanned.countDown();
        Assertions.assertTrue(finish.await(WAIT).finished(), "SD-10: finishClose completes");
        releaseQuarantined.countDown();
        Assertions.assertTrue(disposal.await(WAIT).finished(), "SD-10: the disposal completes");
        Assertions.assertEquals(LeaseState.RESIDUAL, lease.state(), "SD-10: kept for the process");
        Assertions.assertEquals(residualsBefore + 1, BoundedMetadataConnections.processResidualCount(),
            "SD-10: the keeper registration survived, so the process-wide keeper counts the kept connection");
    }

    /** Signals that a probe point was reached, then waits there until released */
    private static void stop(@NotNull CountDownLatch reached, @NotNull CountDownLatch release) {
        reached.countDown();
        try {
            release.await(30, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    // ---------------------------------------------------------------- EX: the close runnable's exception policy

    /**
     * EX-1: a RuntimeException from beginClose does not hide the pool's Error, which is rethrown after Disposed
     */
    @Test
    public void ex1APoolErrorWinsOverAnEarlierRuntimeException() throws Throwable {
        ShutdownRun run = shutdown(Fault.RUNTIME, Fault.ERROR, Fault.NONE);
        Assertions.assertSame(run.injected("pool"), run.thrown(), "EX-1: the pool Error");
        Assertions.assertEquals(List.of(1, 1, 0), List.of(run.count(BEGIN_CODE), run.count(POOL_CODE), run.count(FINISH_CODE)),
            "EX-1: begin logged once, the pool Error logged once");
        Assertions.assertTrue(run.disposed(), "EX-1: Disposed before the Error reaches the caller");
    }

    /**
     * EX-2: three Errors - the first is rethrown; every one is logged
     */
    @Test
    public void ex2TheFirstOfThreeErrorsIsRethrown() throws Throwable {
        ShutdownRun run = shutdown(Fault.ERROR, Fault.ERROR, Fault.ERROR);
        Assertions.assertSame(run.injected("begin"), run.thrown(), "EX-2: the begin Error");
        Assertions.assertEquals(List.of(1, 2, 1), List.of(run.count(BEGIN_CODE), run.count(POOL_CODE), run.count(FINISH_CODE)),
            "EX-2: each step logged, and the lifecycle logs the rethrown Error once more");
        Assertions.assertTrue(run.disposed(), "EX-2: Disposed");
    }

    /**
     * EX-3: a RuntimeException from the pool alone is logged once and goes no further
     */
    @Test
    public void ex3APoolRuntimeExceptionIsLoggedAndSuppressed() throws Throwable {
        ShutdownRun run = shutdown(Fault.NONE, Fault.RUNTIME, Fault.NONE);
        Assertions.assertNull(run.thrown(), "EX-3: nothing rethrown");
        Assertions.assertEquals(List.of(0, 1, 0), List.of(run.count(BEGIN_CODE), run.count(POOL_CODE), run.count(FINISH_CODE)),
            "EX-3: logged once");
        Assertions.assertEquals(BoundedMetadataConnections.Health.CLOSED, run.health(), "EX-3: finished");
    }

    /**
     * EX-4: RuntimeExceptions from both metadata phases are logged and suppressed
     */
    @Test
    public void ex4MetadataRuntimeExceptionsAreLoggedAndSuppressed() throws Throwable {
        ShutdownRun run = shutdown(Fault.RUNTIME, Fault.NONE, Fault.RUNTIME);
        Assertions.assertNull(run.thrown(), "EX-4: nothing rethrown");
        Assertions.assertEquals(List.of(1, 0, 1), List.of(run.count(BEGIN_CODE), run.count(POOL_CODE), run.count(FINISH_CODE)),
            "EX-4: two logs");
    }

    /**
     * EX-5: every combination: each phase once, Disposed once, the first Error rethrown, each failure logged once,
     * and the rethrown Error once more by the lifecycle
     */
    @Test
    public void ex5EveryCombinationKeepsTheRules() throws Throwable {
        List<String> violations = new ArrayList<>();
        int combinations = 0;
        for (Fault begin : Fault.values()) {
            for (Fault pool : Fault.values()) {
                for (Fault finish : Fault.values()) {
                    combinations++;
                    String label = "begin " + begin + ", pool " + pool + ", finish " + finish;
                    ShutdownRun run = shutdown(begin, pool, finish);
                    if (!List.of("begin", "pool", "finish").equals(run.phases())) {
                        violations.add(label + ": phases " + run.phases());
                    }
                    if (!run.disposed() || run.disposals() != 1) {
                        violations.add(label + ": Disposed " + run.disposals() + " times");
                    }
                    String firstError = begin == Fault.ERROR ? "begin"
                        : pool == Fault.ERROR ? "pool"
                        : finish == Fault.ERROR ? "finish" : null;
                    Throwable expected = firstError == null ? null : run.injected(firstError);
                    if (run.thrown() != expected) {
                        violations.add(label + ": rethrown " + (run.thrown() == null ? "nothing" : run.thrown().getClass().getSimpleName())
                            + ", expected " + firstError);
                    }
                    int poolLogs = (pool == Fault.NONE ? 0 : 1) + (firstError != null && !firstError.equals("pool") ? 1 : 0);
                    List<Integer> expectedLogs = List.of(begin == Fault.NONE ? 0 : 1, poolLogs, finish == Fault.NONE ? 0 : 1);
                    List<Integer> logs = List.of(run.count(BEGIN_CODE), run.count(POOL_CODE), run.count(FINISH_CODE));
                    if (!expectedLogs.equals(logs)) {
                        violations.add(label + ": logs " + logs + ", expected " + expectedLogs);
                    }
                    violations.addAll(LifecycleTestSupport.logContractViolations(run.captured(), FORBIDDEN).stream()
                        .map(violation -> label + ": " + violation).toList());
                }
            }
        }
        Assertions.assertEquals(27, combinations, "FIXTURE EX-5");
        Assertions.assertEquals(List.of(), violations, "EX-5");
    }

    // ---------------------------------------------------------------- OWN: ownership

    /**
     * OWN-1: production creates a bounded source only in the metadata database, tests only in the fixture,
     * and both keep the whole of what create returns
     */
    @Test
    public void own1EveryCreatorKeepsBothHalves() throws Exception {
        Map<String, Integer> production = callers(dbacSourceRoot());
        Assertions.assertEquals(Map.of("DbacCBDatabase.java", 1), production, "OWN-1: production creators");
        Map<String, Integer> tests = callers(MetadataLeaseTest.repositoryRoot().resolve(
            "server/test/io.cloudbeaver.test.platform/src/io/cloudbeaver/test/platform"));
        Assertions.assertEquals(Map.of("MetadataLeaseFixture.java", 1), tests, "OWN-1: test creators");

        Field kept = DbacCBDatabase.class.getDeclaredField("metadata");
        Assertions.assertEquals(BoundedMetadataConnections.Owned.class, kept.getType(), "OWN-1: the database keeps the Owned pair");
        Assertions.assertTrue(Modifier.isPrivate(kept.getModifiers()) && Modifier.isFinal(kept.getModifiers()), "OWN-1: private and final");
        String fixture = Files.readString(MetadataLeaseTest.repositoryRoot().resolve(
            "server/test/io.cloudbeaver.test.platform/src/io/cloudbeaver/test/platform/dbac/MetadataLeaseFixture.java"),
            StandardCharsets.UTF_8);
        Assertions.assertTrue(fixture.contains("List<BoundedMetadataConnections.Owned> owned"), "OWN-1: the fixture keeps the Owned pair");
        Assertions.assertEquals(0, BoundedMetadataConnections.class.getConstructors().length, "OWN-1: no public constructor");
        for (Constructor<?> constructor : DbAccessPolicyService.class.getConstructors()) {
            for (Class<?> parameter : constructor.getParameterTypes()) {
                Assertions.assertNotEquals(MetadataConnectionSource.class, parameter,
                    "OWN-1: a policy service must not be built on a raw connection source: " + constructor);
            }
        }
    }

    /**
     * OWN-2: a service used and its fixture closed leave no worker, quarantine or residual
     */
    @Test
    public void own2AClosedFixtureLeavesNothingRunning() {
        CBDatabase database = EmbeddedSecurityControllerFactory.getDbInstance();
        MetadataLeaseFixture local = new MetadataLeaseFixture();
        BoundedMetadataConnections source = local.bounded(database::openConnection, BoundedMetadataConnections.Tuning.PRODUCTION);
        DbAccessPolicyService service = new DbAccessPolicyService(source, DbAccessPolicyConfig.defaults());
        service.authorize(WriteAuthorizationRequest.of("dbac-own2-user",
            PolicyTestSupport.container("own2-project", "own2-connection", "db.internal.example", "customer_prod"),
            DbOperationCategory.TRANSACTION_COMMIT));
        Assertions.assertTrue(source.submittedTasks() >= 1, "FIXTURE OWN-2: the service must have borrowed");
        local.close();
        Assertions.assertEquals(List.of(0, 0, 0, 0),
            List.of(source.runningWorkers(), source.quarantined(), source.residualHeld(),
                MetadataLeaseFixture.workerThreads(source.serial())),
            "OWN-2: workers, quarantine, residual, threads");
    }

    /**
     * OWN-3: fifty services made and closed leave no worker thread and no keeper registration behind
     */
    @Test
    public void own3RepeatedCreationLeavesNoThreads() {
        final int registeredBefore = BoundedMetadataConnections.registeredKeeperShares();
        List<Long> serials = new ArrayList<>();
        for (int i = 0; i < 50; i++) {
            MetadataLeaseFixture local = new MetadataLeaseFixture();
            FakeSource raw = new FakeSource();
            BoundedMetadataConnections source = local.bounded(raw, BoundedMetadataConnections.Tuning.PRODUCTION);
            try (MetadataLease lease = MetadataTestSupport.open(source, MetadataTestSupport.budget(WAIT), WAIT).get()) {
                lease.query(MetadataTestSupport.valueQuery());
            }
            serials.add(source.serial());
            local.close();
        }
        int alive = 0;
        for (long serial : serials) {
            alive += MetadataLeaseFixture.awaitThreadsGone(serial);
        }
        Assertions.assertEquals(0, alive, "OWN-3: no borrow thread left");
        Assertions.assertEquals(registeredBefore, BoundedMetadataConnections.registeredKeeperShares(),
            "OWN-3: no keeper registration left");
    }

    /**
     * OWN-4: in production the policy service borrows from the metadata database's own source, the one the database shuts down
     */
    @Test
    public void own4ProductionUsesTheDatabaseOwnedSource() throws Exception {
        PolicyServiceHolder.State state = PolicyServiceHolder.global().current();
        Ready ready = Assertions.assertInstanceOf(Ready.class, state, "FIXTURE OWN-4: the server's policy service is ready");
        CBDatabase instance = EmbeddedSecurityControllerFactory.getDbInstance();
        Assertions.assertSame(instance, ready.database(), "OWN-4: the ready service's database is the server's");
        MetadataLeaseSource owned = ready.database().metadataLeases();
        Assertions.assertSame(owned, ready.database().metadataLeases(), "OWN-4: one source for the life of the database");
        Field leasesField = DbAccessPolicyService.class.getDeclaredField("leases");
        leasesField.setAccessible(true);
        Assertions.assertSame(owned, leasesField.get(ready.service()), "OWN-4: the service borrows from the database's source");
        Assertions.assertInstanceOf(BoundedMetadataConnections.class, owned, "OWN-4: and it is bounded");
    }

    // ---------------------------------------------------------------- RS: what outlives the source

    /**
     * RS-1: a kept connection stays reachable after its source is collected
     */
    @Test
    public void rs1AKeptConnectionOutlivesItsSource() {
        leases.allowResidue();
        Forgotten forgotten = keepOneAndForgetTheSource();
        final int residualsBefore = BoundedMetadataConnections.processResidualCount();
        WeakReference<Object> source = forgotten.source();
        WeakReference<Object> kept = forgotten.kept();
        for (int i = 0; i < 50 && source.get() != null; i++) {
            System.gc();
            byte[][] pressure = new byte[16][];
            for (int j = 0; j < pressure.length; j++) {
                pressure[j] = new byte[1 << 16];
            }
            sleep(20);
        }
        Assertions.assertNull(source.get(), "FIXTURE RS-1: the source itself must be collectable");
        Assertions.assertNotNull(kept.get(), "RS-1: the kept connection must still be held");
        Assertions.assertEquals(residualsBefore, BoundedMetadataConnections.processResidualCount(), "RS-1: and still counted");
    }

    /** Weak references to a source that has been shut down and dropped, and to the connection it kept */
    private record Forgotten(@NotNull WeakReference<Object> source, @NotNull WeakReference<Object> kept) {
    }

    /** Leaves one connection in the keeper, shuts its source down and keeps nothing strong to either */
    @NotNull
    private Forgotten keepOneAndForgetTheSource() {
        FakeSource raw = new FakeSource();
        BoundedMetadataConnections.Owned owned = leases.owned(raw, MetadataTestSupport.tuning(SHORT_FINISH,
            BoundedMetadataConnections.Probe.NONE));
        final MetadataLease lease = MetadataTestSupport.open(owned.leases(), MetadataTestSupport.budget(WAIT), WAIT).get();
        FakeConnection connection = raw.only();
        connection.closeFails = new InjectedSqlException("close");
        connection.abortFails = new InjectedSqlException("abort");
        leases.closeAndForget(owned);
        lease.close();
        Assertions.assertEquals(LeaseState.RESIDUAL, lease.state(), "RS-1: kept");
        Forgotten forgotten = new Forgotten(new WeakReference<>(owned.leases()), new WeakReference<>(connection.proxy));
        raw.made.clear();
        return forgotten;
    }

    /**
     * RS-2: one source can keep at most as many connections as it has slots
     */
    @Test
    public void rs2TheKeeperShareIsBoundedBySlots() {
        leases.allowResidue();
        FakeSource raw = new FakeSource();
        BoundedMetadataConnections.Owned owned = leases.owned(raw, MetadataTestSupport.tuning(SHORT_FINISH,
            BoundedMetadataConnections.Probe.NONE));
        List<MetadataLease> held = new ArrayList<>();
        for (int i = 0; i < BoundedMetadataConnections.CAPACITY; i++) {
            held.add(MetadataTestSupport.open(owned.leases(), MetadataTestSupport.budget(WAIT), WAIT).get());
        }
        Assertions.assertEquals(MetadataUnavailableException.Reason.CAPACITY, MetadataTestSupport.refusal(
            MetadataTestSupport.open(owned.leases(), MetadataTestSupport.budget(WAIT), WAIT)), "RS-2: no fifth borrow");
        for (FakeConnection connection : raw.made) {
            connection.closeFails = new InjectedSqlException("close");
            connection.abortFails = new InjectedSqlException("abort");
        }
        owned.shutdown().beginClose();
        owned.shutdown().finishClose();
        held.forEach(MetadataLease::close);
        Assertions.assertEquals(BoundedMetadataConnections.CAPACITY, owned.leases().residualHeld(), "RS-2: four kept, and no more");
        Assertions.assertEquals(MetadataUnavailableException.Reason.CLOSED, MetadataTestSupport.refusal(
            MetadataTestSupport.open(owned.leases(), MetadataTestSupport.budget(WAIT), WAIT)), "RS-2: nothing new after shutdown");
    }

    /**
     * RS-3: the production source is reachable from the factory's static database for the life of the process
     */
    @Test
    public void rs3TheProductionSourceIsReachableFromTheStaticDatabase() throws Exception {
        Field instance = EmbeddedSecurityControllerFactory.class.getDeclaredField("DB_INSTANCE");
        Assertions.assertTrue(Modifier.isStatic(instance.getModifiers()), "RS-3: the database is held by a static field");
        instance.setAccessible(true);
        DbacCBDatabase database = Assertions.assertInstanceOf(DbacCBDatabase.class, instance.get(null), "RS-3: the DBAC database");
        Field metadata = DbacCBDatabase.class.getDeclaredField("metadata");
        metadata.setAccessible(true);
        BoundedMetadataConnections.Owned owned = (BoundedMetadataConnections.Owned) metadata.get(database);
        Assertions.assertSame(database.metadataLeases(), owned.leases(), "RS-3: the field holds the source consumers borrow from");
        Assertions.assertNotNull(owned.shutdown(), "RS-3: and its shutdown");
        Assertions.assertEquals(BoundedMetadataConnections.Health.OPEN, owned.leases().health(), "RS-3: open while the server runs");
        Assertions.assertTrue(BoundedMetadataConnections.registeredKeeperShares() >= 1, "RS-3: its keeper share is registered");
    }

    // ---------------------------------------------------------------- helpers

    /** The DBAC bundle's production sources */
    @NotNull
    static Path dbacSourceRoot() {
        return MetadataLeaseTest.repositoryRoot().resolve("server/bundles/io.cloudbeaver.service.dbac/src");
    }

    /** A call or method reference to create, however it is spaced or broken over lines */
    private static final java.util.regex.Pattern CREATE_CALL =
        java.util.regex.Pattern.compile("BoundedMetadataConnections\\s*(\\.|::)\\s*create\\b");
    /** A static import of create, or of everything, that would let a bare create( through */
    private static final java.util.regex.Pattern STATIC_IMPORT =
        java.util.regex.Pattern.compile("import\\s+static\\s+[\\w.]*BoundedMetadataConnections\\s*\\.\\s*(create|\\*)");

    /** Files that call the bounded source's {@code create}, and how often, under {@code root}; a static import counts 1000 */
    @NotNull
    private static Map<String, Integer> callers(@NotNull Path root) throws IOException {
        Map<String, Integer> found = new TreeMap<>();
        try (Stream<Path> files = Files.walk(root)) {
            for (Path file : files.filter(path -> path.toString().endsWith(".java")).toList()) {
                String name = file.getFileName().toString();
                if (name.equals("BoundedMetadataConnections.java")) {
                    continue;
                }
                String text = Files.readString(file, StandardCharsets.UTF_8);
                int count = 0;
                java.util.regex.Matcher call = CREATE_CALL.matcher(text);
                while (call.find()) {
                    count++;
                }
                if (STATIC_IMPORT.matcher(text).find()) {
                    count += 1000;
                }
                if (count > 0) {
                    found.put(name, count);
                }
            }
        }
        return found;
    }

    /** What one shutdown through the real lifecycle did */
    private record ShutdownRun(
        @NotNull LifecycleTestSupport.Fixture fixture,
        @NotNull LifecycleTestSupport.TestFactory factory,
        @NotNull ProbedDb database,
        @Nullable Throwable thrown,
        @NotNull LifecycleTestSupport.Captured captured
    ) {
        @NotNull
        List<String> phases() {
            return MetadataShutdownTest.phases(fixture.journal);
        }

        @Nullable
        Throwable injected(@NotNull String where) {
            return fixture.journal.lastInjected(where);
        }

        int count(@NotNull String code) {
            return (int) captured.dbacMessages().stream().filter(message -> message.contains(code)).count();
        }

        boolean disposed() {
            return factory.state() instanceof Disposed;
        }

        long disposals() {
            return fixture.observer.countTo(Disposed.class);
        }

        @NotNull
        BoundedMetadataConnections.Health health() {
            return ((BoundedMetadataConnections) database.metadataLeases()).health();
        }

        @Nullable
        BoundedMetadataConnections.ShutdownReport report() {
            return ((BoundedMetadataConnections) database.metadataLeases()).lastShutdownReport();
        }
    }

    /** Initializes a Ready lifecycle on a probed database, then shuts it down once, capturing the calling thread's log */
    @NotNull
    private static ShutdownRun shutdown(@NotNull Fault begin, @NotNull Fault pool, @NotNull Fault finish) throws Throwable {
        LifecycleTestSupport.Fixture fixture = new LifecycleTestSupport.Fixture();
        LifecycleTestSupport.TestFactory factory = fixture.factory();
        ProbedDb[] made = new ProbedDb[1];
        factory.databaseMaker = (application, config, lifecycle) -> {
            made[0] = new ProbedDb(application, config, lifecycle, fixture.journal, begin, pool, finish, 0);
            return made[0];
        };
        CBDatabase database = factory.init();
        Assertions.assertInstanceOf(Ready.class, factory.state(), "FIXTURE: the lifecycle must be Ready");
        Throwable[] thrown = new Throwable[1];
        LifecycleTestSupport.Captured captured = LifecycleTestSupport.captureLogs(
            () -> thrown[0] = LifecycleTestSupport.shutdownCatching(database));
        return new ShutdownRun(fixture, factory, made[0], thrown[0], captured);
    }

    @NotNull
    private static List<String> phases(@NotNull LifecycleTestSupport.Journal journal) {
        return journal.snapshot().stream()
            .filter(event -> event.equals("begin") || event.equals("pool") || event.equals("finish")).toList();
    }

    /**
     * A metadata database with no pool, whose close runnable's three phases record themselves and fail on demand
     */
    static final class ProbedDb extends DbacCBDatabase {
        private final LifecycleTestSupport.Journal journal;
        private final Fault pool;

        ProbedDb(
            @NotNull ServletApplication application,
            @NotNull WebDatabaseConfig config,
            @NotNull ShutdownLifecycle lifecycle,
            @NotNull LifecycleTestSupport.Journal journal,
            @NotNull Fault begin,
            @NotNull Fault pool,
            @NotNull Fault finish,
            long finishDelayMillis
        ) {
            super(application, config, DbacSchema.getSchemaConfigs(), lifecycle, MetadataTestSupport.tuning(SHORT_FINISH, point -> {
                if (point == BoundedMetadataConnections.ProbePoint.BEGIN_CLOSE) {
                    journal.add("begin");
                    LifecycleTestSupport.raise(begin, "begin", journal);
                } else if (point == BoundedMetadataConnections.ProbePoint.FINISH_CLOSE) {
                    journal.add("finish");
                    sleep(finishDelayMillis);
                    LifecycleTestSupport.raise(finish, "finish", journal);
                }
            }));
            this.journal = journal;
            this.pool = pool;
        }

        @Override
        public void initialize() {
            journal.add("initialize");
        }

        @Override
        protected void closeConnection() {
            journal.add("pool");
            LifecycleTestSupport.raise(pool, "pool", journal);
        }
    }

    private static void sleep(long millis) {
        if (millis <= 0) {
            return;
        }
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
