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
import io.cloudbeaver.service.dbac.policy.AuthorizationDecision;
import io.cloudbeaver.service.dbac.policy.BoundedMetadataConnections;
import io.cloudbeaver.service.dbac.policy.DbAccessPolicyConfig;
import io.cloudbeaver.service.dbac.policy.DbAccessPolicyService;
import io.cloudbeaver.service.dbac.policy.DbOperationCategory;
import io.cloudbeaver.service.dbac.policy.DenialReason;
import io.cloudbeaver.service.dbac.policy.LeaseState;
import io.cloudbeaver.service.dbac.policy.MetadataLease;
import io.cloudbeaver.service.dbac.policy.MetadataPurpose;
import io.cloudbeaver.service.dbac.policy.MetadataQuery;
import io.cloudbeaver.service.dbac.policy.MetadataUnavailableException;
import io.cloudbeaver.service.dbac.policy.UnusableCause;
import io.cloudbeaver.service.dbac.policy.WriteAuthorizationRequest;
import io.cloudbeaver.service.dbac.tempwrite.MetadataConnectionSource;
import io.cloudbeaver.service.security.EmbeddedSecurityControllerFactory;
import io.cloudbeaver.service.security.db.CBDatabase;
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

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * P5-1a: disposal - every connection ends returned, invalidated, quarantined or kept, and nothing is dropped
 * <p>
 * QZ and DS run on scripted connections, so every failure can be put exactly where the matrix needs it.
 * CC runs on the test server's real metadata pool (H2 behind DBCP), because what "invalidated" means is
 * the pool's business: an aborted and closed connection must never be handed out again.
 */
public class MetadataDisposalTest {

    private static final Duration WAIT = Duration.ofSeconds(10);
    private static final Duration SHORT_FINISH = Duration.ofMillis(300);

    private final MetadataLeaseFixture leases = new MetadataLeaseFixture();

    @AfterEach
    public void closeLeases() {
        leases.close();
    }

    @BeforeAll
    public static void startServer() throws Exception {
        CEAppStarter.startServerIfNotStarted();
    }

    // ---------------------------------------------------------------- QZ: quarantine capacity

    /** What eight callers failing together left behind */
    private record Stampede(@NotNull BoundedMetadataConnections source, @NotNull FakeSource raw, @NotNull List<String> results) {
    }

    /** Eight callers at once, every connection failing its restore and its abort */
    @NotNull
    private Stampede stampede() {
        leases.allowResidue();
        FakeSource raw = new FakeSource(connection -> {
            connection.restoreSetFails = new InjectedSqlException("restore");
            connection.abortFails = new InjectedSqlException("abort");
        });
        BoundedMetadataConnections source = leases.bounded(raw, BoundedMetadataConnections.Tuning.PRODUCTION);
        CyclicBarrier barrier = new CyclicBarrier(8);
        List<Pending<String>> callers = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            callers.add(MetadataTestSupport.start("dbac-qz-caller-" + i, () -> {
                barrier.await(10, TimeUnit.SECONDS);
                try (MetadataLease lease = source.open(MetadataTestSupport.budget(Duration.ofSeconds(5)), MetadataPurpose.SNAPSHOT)) {
                    lease.query(MetadataTestSupport.valueQuery());
                    return "leased";
                } catch (MetadataUnavailableException e) {
                    return e.reason().name();
                }
            }));
        }
        List<String> results = new ArrayList<>();
        for (Pending<String> caller : callers) {
            results.add(caller.await(WAIT).get());
        }
        Collections.sort(results);
        return new Stampede(source, raw, results);
    }

    /**
     * QZ-1: eight callers failing together quarantine exactly four connections, and the source refuses from then on
     */
    @Test
    public void qz1EightFailuresQuarantineExactlyFour() {
        Stampede run = stampede();
        Assertions.assertEquals(4, run.results().stream().filter("leased"::equals).count(), "QZ-1: four leases, got " + run.results());
        Assertions.assertEquals(BoundedMetadataConnections.CAPACITY, run.source().quarantined(), "QZ-1: four quarantined");
        Assertions.assertEquals(BoundedMetadataConnections.Health.REFUSING, run.source().health(), "QZ-1: refusing");
    }

    /**
     * QZ-2: the four refused callers submitted nothing
     */
    @Test
    public void qz2RefusedCallersSubmitNothing() {
        Stampede run = stampede();
        Assertions.assertEquals(4, run.results().stream().filter(result -> !result.equals("leased")).count(), "QZ-2: four refused");
        Assertions.assertTrue(run.results().stream().filter(result -> !result.equals("leased"))
            .allMatch(result -> result.equals("CAPACITY") || result.equals("REFUSING")),
            "QZ-2: refused for capacity, got " + run.results());
        Assertions.assertEquals(4, run.source().submittedTasks(), "QZ-2: only the four leases were submitted");
    }

    /**
     * QZ-3: every connection made is accounted for: here all four quarantined, none dropped
     */
    @Test
    public void qz3EveryConnectionIsAccountedFor() {
        Stampede run = stampede();
        BoundedMetadataConnections source = run.source();
        long accounted = source.disposedAs(LeaseState.RETURNED) + source.disposedAs(LeaseState.INVALIDATED)
            + source.disposedAs(LeaseState.QUARANTINED) + source.disposedAs(LeaseState.RESIDUAL);
        Assertions.assertEquals(run.raw().made.size(), accounted, "QZ-3: made == returned + invalidated + quarantined + kept");
        Assertions.assertEquals(4, source.disposedAs(LeaseState.QUARANTINED), "QZ-3: all four quarantined");
        Assertions.assertEquals(0, run.raw().made.stream().mapToInt(connection -> connection.count("close")).sum(),
            "QZ-3: none closed normally");
    }

    /**
     * QZ-4: abort and close succeed - the slot comes back
     */
    @Test
    public void qz4AbortAndCloseReturnTheSlot() {
        FakeSource raw = new FakeSource(connection -> connection.restoreSetFails = new InjectedSqlException("restore"));
        BoundedMetadataConnections source = leases.bounded(raw, BoundedMetadataConnections.Tuning.PRODUCTION);
        try (MetadataLease lease = lease(source)) {
            lease.query(MetadataTestSupport.valueQuery());
        }
        Assertions.assertEquals(1, source.disposedAs(LeaseState.INVALIDATED), "QZ-4: invalidated");
        Assertions.assertEquals(BoundedMetadataConnections.CAPACITY, source.availableSlots(), "QZ-4: the slot is back");
    }

    /**
     * QZ-5: abort fails - the slot is consumed by the connection it holds
     */
    @Test
    public void qz5AbortFailureConsumesTheSlot() {
        leases.allowResidue();
        FakeSource raw = new FakeSource(connection -> {
            connection.restoreSetFails = new InjectedSqlException("restore");
            connection.abortFails = new InjectedSqlException("abort");
        });
        BoundedMetadataConnections source = leases.bounded(raw, BoundedMetadataConnections.Tuning.PRODUCTION);
        try (MetadataLease lease = lease(source)) {
            lease.query(MetadataTestSupport.valueQuery());
        }
        Assertions.assertEquals(1, source.quarantined(), "QZ-5: one quarantined");
        Assertions.assertEquals(BoundedMetadataConnections.CAPACITY - 1, source.availableSlots(), "QZ-5: its slot is consumed");
    }

    /**
     * QZ-6: a refusing source refuses at once and submits nothing
     */
    @Test
    public void qz6ARefusingSourceRefusesAtOnce() {
        Stampede run = stampede();
        long submitted = run.source().submittedTasks();
        Outcome<MetadataLease> next = MetadataTestSupport.open(run.source(), MetadataTestSupport.budget(Duration.ofSeconds(5)), WAIT);
        Assertions.assertEquals(MetadataUnavailableException.Reason.REFUSING, MetadataTestSupport.refusal(next), "QZ-6");
        Assertions.assertTrue(next.elapsedNanos() < TimeUnit.MILLISECONDS.toNanos(500), "QZ-6: at once");
        Assertions.assertEquals(submitted, run.source().submittedTasks(), "QZ-6: nothing submitted");
    }

    /**
     * QZ-7: closing a quarantined lease again changes nothing and logs nothing
     */
    @Test
    public void qz7AQuarantinedLeaseIsInert() throws Throwable {
        leases.allowResidue();
        FakeSource raw = new FakeSource(connection -> {
            connection.restoreSetFails = new InjectedSqlException("restore");
            connection.abortFails = new InjectedSqlException("abort");
        });
        BoundedMetadataConnections source = leases.bounded(raw, BoundedMetadataConnections.Tuning.PRODUCTION);
        MetadataLease lease = lease(source);
        lease.query(MetadataTestSupport.valueQuery());
        lease.close();
        Assertions.assertEquals(LeaseState.QUARANTINED, lease.state(), "QZ-7: quarantined first");
        int calls = raw.only().calls().size();
        LifecycleTestSupport.Captured captured = LifecycleTestSupport.captureLogs(() -> {
            lease.close();
            lease.close();
        });
        Assertions.assertEquals(List.of(1, BoundedMetadataConnections.CAPACITY - 1, LeaseState.QUARANTINED, calls, 1L),
            List.of(source.quarantined(), source.availableSlots(), lease.state(), raw.only().calls().size(),
                source.disposedAs(LeaseState.QUARANTINED)),
            "QZ-7: quarantine, free slots, state, connection calls and disposals unchanged");
        Assertions.assertEquals(List.of(), captured.dbacMessages(), "QZ-7: nothing logged, no tripwire");
    }

    // ---------------------------------------------------------------- DS: the disposal matrix

    /** Where in the disposal a failure is put */
    private enum Column {
        /** The first step works */
        A_FIRST_WORKS,
        /** The first step fails */
        B_FIRST_FAILS,
        /** The step after the abort fails */
        C_SECOND_FAILS,
        /** The disposal happens after finishClose, and cannot release the connection */
        D_AFTER_CLOSED
    }

    /** The knobs for a column; contaminated rows skip the ordinary close, so their first step is the abort */
    private static void arm(@NotNull FakeConnection connection, @NotNull Column column, boolean contaminated) {
        switch (column) {
            case B_FIRST_FAILS -> {
                if (contaminated) {
                    connection.abortFails = new InjectedSqlException("abort");
                } else {
                    connection.closeFails = new InjectedSqlException("close");
                }
            }
            case C_SECOND_FAILS -> {
                connection.closeFails = new InjectedSqlException("close");
                connection.closeAfterAbortFails = new InjectedSqlException("close after abort");
            }
            case D_AFTER_CLOSED -> {
                connection.closeFails = new InjectedSqlException("close");
                connection.abortFails = new InjectedSqlException("abort");
            }
            default -> {
                // nothing fails
            }
        }
    }

    @NotNull
    private static LeaseState expectedEnd(@NotNull Column column, boolean contaminated) {
        return switch (column) {
            case A_FIRST_WORKS -> contaminated ? LeaseState.INVALIDATED : LeaseState.RETURNED;
            case B_FIRST_FAILS -> contaminated ? LeaseState.QUARANTINED : LeaseState.INVALIDATED;
            case C_SECOND_FAILS -> LeaseState.QUARANTINED;
            case D_AFTER_CLOSED -> LeaseState.RESIDUAL;
        };
    }

    @NotNull
    private static List<String> expectedCalls(@NotNull Column column, boolean contaminated) {
        if (contaminated) {
            return switch (column) {
                case A_FIRST_WORKS, C_SECOND_FAILS -> List.of("abort", "close-after-abort");
                case B_FIRST_FAILS, D_AFTER_CLOSED -> List.of("abort");
            };
        }
        return switch (column) {
            case A_FIRST_WORKS -> List.of("close");
            case B_FIRST_FAILS, C_SECOND_FAILS -> List.of("close", "abort", "close-after-abort");
            case D_AFTER_CLOSED -> List.of("close", "abort");
        };
    }

    /** One cell's result against its expectation */
    private static void checkCell(
        @NotNull List<String> violations,
        @NotNull String cell,
        @NotNull BoundedMetadataConnections source,
        @NotNull FakeSource raw,
        @NotNull Column column,
        boolean contaminated
    ) {
        LeaseState end = expectedEnd(column, contaminated);
        if (!MetadataTestSupport.eventually(() -> source.disposedAs(end) == 1)) {
            violations.add(cell + ": expected one " + end + ", got returned=" + source.disposedAs(LeaseState.RETURNED)
                + " invalidated=" + source.disposedAs(LeaseState.INVALIDATED) + " quarantined=" + source.disposedAs(LeaseState.QUARANTINED)
                + " residual=" + source.disposedAs(LeaseState.RESIDUAL));
            return;
        }
        long others = 0;
        for (LeaseState state : List.of(LeaseState.RETURNED, LeaseState.INVALIDATED, LeaseState.QUARANTINED, LeaseState.RESIDUAL)) {
            if (state != end) {
                others += source.disposedAs(state);
            }
        }
        if (others != 0) {
            violations.add(cell + ": other disposals " + others);
        }
        List<String> calls = raw.only().calls().stream()
            .filter(call -> call.equals("close") || call.equals("abort") || call.equals("close-after-abort")).toList();
        if (!expectedCalls(column, contaminated).equals(calls)) {
            violations.add(cell + ": expected the connection calls " + expectedCalls(column, contaminated) + ", got " + calls);
        }
        int quarantined = end == LeaseState.QUARANTINED ? 1 : 0;
        int kept = end == LeaseState.RESIDUAL ? 1 : 0;
        if (source.quarantined() != quarantined || source.residualHeld() != kept) {
            violations.add(cell + ": quarantined " + source.quarantined() + " kept " + source.residualHeld()
                + ", expected " + quarantined + " and " + kept);
        }
        if (column != Column.D_AFTER_CLOSED) {
            int free = BoundedMetadataConnections.CAPACITY - quarantined;
            if (source.availableSlots() != free) {
                violations.add(cell + ": " + source.availableSlots() + " free slots, expected " + free);
            }
        }
    }

    /**
     * DS-1a-d: the caller closes a lease whose statement left the session clean
     */
    @Test
    public void ds1NormalDisposalMatrix() {
        leases.allowResidue();
        List<String> violations = new ArrayList<>();
        for (Column column : Column.values()) {
            FakeSource raw = new FakeSource();
            BoundedMetadataConnections.Owned owned = leases.owned(raw, shortFinish());
            MetadataLease lease = lease(owned.leases());
            lease.query(MetadataTestSupport.valueQuery());
            arm(raw.only(), column, false);
            if (column == Column.D_AFTER_CLOSED) {
                owned.shutdown().beginClose();
                owned.shutdown().finishClose();
            }
            lease.close();
            checkCell(violations, "DS-1" + column, owned.leases(), raw, column, false);
        }
        Assertions.assertEquals(List.of(), violations, "DS-1");
    }

    /**
     * DS-2a-d: a delivered lease found after the deadline is disposed by the caller, unused
     */
    @Test
    public void ds2OverBudgetDisposalMatrix() {
        leases.allowResidue();
        List<String> violations = new ArrayList<>();
        for (Column column : Column.values()) {
            CountDownLatch hold = new CountDownLatch(1);
            FakeSource raw = new FakeSource(connection -> arm(connection, column, false));
            BoundedMetadataConnections.Owned owned = leases.owned(raw, MetadataTestSupport.tuning(SHORT_FINISH, holdAt(hold,
                BoundedMetadataConnections.ProbePoint.WORKER_PUBLISHED)));
            Duration budget = column == Column.D_AFTER_CLOSED ? Duration.ofSeconds(3) : Duration.ofSeconds(1);
            Pending<MetadataLease> caller = MetadataTestSupport.start("dbac-ds2-caller",
                () -> owned.leases().open(MetadataTestSupport.budget(budget), MetadataPurpose.SNAPSHOT));
            if (column == Column.D_AFTER_CLOSED) {
                MetadataTestSupport.eventually(() -> raw.made.size() == 1);
                owned.shutdown().beginClose();
                owned.shutdown().finishClose();
            }
            Outcome<MetadataLease> outcome = caller.await(WAIT);
            if (MetadataTestSupport.refusal(outcome) != MetadataUnavailableException.Reason.TIMEOUT) {
                violations.add("DS-2" + column + ": the caller must be refused for time");
            }
            checkCell(violations, "DS-2" + column, owned.leases(), raw, column, false);
            hold.countDown();
        }
        Assertions.assertEquals(List.of(), violations, "DS-2");
    }

    /**
     * DS-3a-d: the caller closes a contaminated lease - abort first, never an ordinary close
     */
    @Test
    public void ds3ContaminatedDisposalMatrix() {
        leases.allowResidue();
        List<String> violations = new ArrayList<>();
        for (Column column : Column.values()) {
            FakeSource raw = new FakeSource(connection -> connection.restoreSetFails = new InjectedSqlException("restore"));
            BoundedMetadataConnections.Owned owned = leases.owned(raw, shortFinish());
            MetadataLease lease = lease(owned.leases());
            lease.query(MetadataTestSupport.valueQuery());
            if (lease.state() != LeaseState.CONTAMINATED) {
                violations.add("DS-3" + column + ": the lease must be contaminated, is " + lease.state());
            }
            arm(raw.only(), column, true);
            if (column == Column.D_AFTER_CLOSED) {
                owned.shutdown().beginClose();
                owned.shutdown().finishClose();
            }
            lease.close();
            checkCell(violations, "DS-3" + column, owned.leases(), raw, column, true);
        }
        Assertions.assertEquals(List.of(), violations, "DS-3");
    }

    /**
     * DS-4a-d: a connection delivered after its caller gave up is disposed by the worker
     */
    @Test
    public void ds4LateDisposalMatrix() {
        leases.allowResidue();
        List<String> violations = new ArrayList<>();
        for (Column column : Column.values()) {
            FakeSource raw = new FakeSource(connection -> arm(connection, column, false));
            raw.gate = new CountDownLatch(1);
            BoundedMetadataConnections.Owned owned = leases.owned(raw, shortFinish());
            Outcome<MetadataLease> outcome = MetadataTestSupport.open(
                owned.leases(), MetadataTestSupport.budget(Duration.ofMillis(500)), WAIT);
            if (MetadataTestSupport.refusal(outcome) != MetadataUnavailableException.Reason.TIMEOUT) {
                violations.add("DS-4" + column + ": the caller must be refused for time");
            }
            if (column == Column.D_AFTER_CLOSED) {
                owned.shutdown().beginClose();
                owned.shutdown().finishClose();
            }
            raw.gate.countDown();
            checkCell(violations, "DS-4" + column, owned.leases(), raw, column, false);
        }
        Assertions.assertEquals(List.of(), violations, "DS-4");
    }

    /**
     * DS-5a-d: a delivered lease whose caller was interrupted is disposed by that caller, unused
     */
    @Test
    public void ds5InterruptedDisposalMatrix() {
        leases.allowResidue();
        List<String> violations = new ArrayList<>();
        for (Column column : Column.values()) {
            CountDownLatch hold = new CountDownLatch(1);
            FakeSource raw = new FakeSource(connection -> arm(connection, column, false));
            BoundedMetadataConnections.Owned owned = leases.owned(raw, MetadataTestSupport.tuning(SHORT_FINISH, holdAt(hold,
                BoundedMetadataConnections.ProbePoint.WORKER_PUBLISHED)));
            Pending<MetadataLease> caller = MetadataTestSupport.start("dbac-ds5-caller",
                () -> owned.leases().open(MetadataTestSupport.budget(Duration.ofSeconds(8)), MetadataPurpose.SNAPSHOT));
            MetadataTestSupport.eventually(() -> raw.made.size() == 1);
            if (column == Column.D_AFTER_CLOSED) {
                owned.shutdown().beginClose();
                owned.shutdown().finishClose();
            }
            caller.thread().interrupt();
            Outcome<MetadataLease> outcome = caller.await(WAIT);
            if (MetadataTestSupport.refusal(outcome) != MetadataUnavailableException.Reason.INTERRUPTED) {
                violations.add("DS-5" + column + ": the caller must be refused as interrupted");
            }
            checkCell(violations, "DS-5" + column, owned.leases(), raw, column, false);
            hold.countDown();
        }
        Assertions.assertEquals(List.of(), violations, "DS-5");
    }

    /**
     * DS-6: a borrow that ends without a connection frees its slot, whoever saw it end
     */
    @Test
    public void ds6ABorrowWithoutAConnectionFreesItsSlot() {
        List<String> violations = new ArrayList<>();
        FakeSource failing = new FakeSource();
        failing.fails = new InjectedSqlException("borrow");
        BoundedMetadataConnections first = leases.bounded(failing, BoundedMetadataConnections.Tuning.PRODUCTION);
        if (MetadataTestSupport.refusal(MetadataTestSupport.open(first, MetadataTestSupport.budget(Duration.ofSeconds(5)), WAIT))
            != MetadataUnavailableException.Reason.BORROW_FAILED) {
            violations.add("a failed borrow must be refused as such");
        }
        if (first.availableSlots() != BoundedMetadataConnections.CAPACITY) {
            violations.add("a failed borrow left " + first.availableSlots() + " free slots");
        }

        FakeSource lateFailure = new FakeSource();
        lateFailure.gate = new CountDownLatch(1);
        lateFailure.fails = new InjectedSqlException("late borrow");
        BoundedMetadataConnections second = leases.bounded(lateFailure, BoundedMetadataConnections.Tuning.PRODUCTION);
        MetadataTestSupport.open(second, MetadataTestSupport.budget(Duration.ofMillis(300)), WAIT);
        lateFailure.gate.countDown();
        if (!MetadataTestSupport.eventually(() -> second.availableSlots() == BoundedMetadataConnections.CAPACITY)) {
            violations.add("a borrow that failed after its caller gave up left " + second.availableSlots() + " free slots");
        }
        Assertions.assertEquals(List.of(), violations, "DS-6");
    }

    /**
     * DS-7: an abort that returns but leaves the connection open - H2's - is not trusted: nothing is closed after it,
     * the connection is kept, and shutdown keeps it too rather than closing it into a pool
     */
    @Test
    public void ds7AnUnconfirmedAbortIsNeverFollowedByAClose() {
        leases.allowResidue();
        List<String> violations = new ArrayList<>();

        FakeSource contaminated = new FakeSource(connection -> {
            connection.restoreSetFails = new InjectedSqlException("restore");
            connection.abortIneffective = true;
        });
        BoundedMetadataConnections.Owned first = leases.owned(contaminated, shortFinish());
        try (MetadataLease lease = lease(first.leases())) {
            lease.query(MetadataTestSupport.valueQuery());
        }
        checkCell(violations, "DS-7 contaminated", first.leases(), contaminated, Column.B_FIRST_FAILS, true);

        FakeSource closeFails = new FakeSource(connection -> {
            connection.closeFails = new InjectedSqlException("close");
            connection.abortIneffective = true;
        });
        BoundedMetadataConnections.Owned second = leases.owned(closeFails, shortFinish());
        try (MetadataLease lease = lease(second.leases())) {
            lease.query(MetadataTestSupport.valueQuery());
        }
        if (second.leases().disposedAs(LeaseState.QUARANTINED) != 1) {
            violations.add("DS-7 close fails: expected a quarantine");
        }
        if (!List.of("close", "abort").equals(disposalCalls(closeFails.only()))) {
            violations.add("DS-7 close fails: expected close then abort only, got " + disposalCalls(closeFails.only()));
        }

        first.shutdown().beginClose();
        first.shutdown().finishClose();
        BoundedMetadataConnections.ShutdownReport report = first.leases().lastShutdownReport();
        if (report == null || report.quarantineReleased() != 0 || report.transferredToKeeper() != 1) {
            violations.add("DS-7 shutdown: the unconfirmed abort must leave the connection to the keeper, got " + report);
        }
        if (contaminated.only().count("close") + contaminated.only().count("close-after-abort") != 0) {
            violations.add("DS-7 shutdown: nothing may close a connection whose abort was not seen to close it");
        }
        Assertions.assertEquals(List.of(), violations, "DS-7");
    }

    // ---------------------------------------------------------------- CC: on the real metadata pool

    /**
     * CC-7: H2 2.4's abort does nothing - the fact the disposal is built around
     * <p>
     * A connection from the real metadata pool is still open after {@code abort}. Closing it then would
     * return its session to the pool, so the lease never closes after an abort it has not seen work.
     * If a later H2 makes abort real, this fails and the H2 expectations below can be revisited.
     */
    @Test
    public void cc7H2AbortLeavesTheSessionOpen() throws Exception {
        CBDatabase database = metadataDatabase();
        try (Connection connection = database.openConnection()) {
            connection.abort(Runnable::run);
            Assertions.assertFalse(connection.isClosed(), "CC-7: on H2 2.4 abort is a no-op and the connection stays open");
        }
    }

    /**
     * CC-1, CC-2, CC-6: a restore that fails on the real pool never puts its session back in the pool:
     * the abort is not seen to work, so nothing closes it and the lease keeps it; the decision is
     * store-unavailable, every connection the pool hands out carries no timeout, and the logs carry
     * nothing from the failure
     */
    @Test
    public void cc1RestoreFailureOnTheRealPoolNeverReturnsTheSession() throws Throwable {
        leases.allowResidue();
        CBDatabase database = metadataDatabase();
        RealSource raw = new RealSource(database);
        raw.restoreFails = true;
        try {
            BoundedMetadataConnections source = leases.bounded(raw, BoundedMetadataConnections.Tuning.PRODUCTION);
            DbAccessPolicyService service = new DbAccessPolicyService(source, DbAccessPolicyConfig.defaults());
            final LifecycleTestSupport.Captured captured = LifecycleTestSupport.captureLogs(() -> {
                AuthorizationDecision decision = service.authorize(WriteAuthorizationRequest.of("dbac-cc1-user",
                    PolicyTestSupport.container("cc1-project", "cc1-connection", "db.internal.example", "customer_prod"),
                    DbOperationCategory.TRANSACTION_COMMIT));
                Assertions.assertEquals(DenialReason.PERMISSION_STORE_UNAVAILABLE, decision.denialReason(), "CC-1: store unavailable");
            });
            Assertions.assertTrue(
                captured.dbacMessages().stream().anyMatch(message -> message.contains("detail=" + UnusableCause.RESTORE_FAILED)),
                "CC-1: the denial must come from the failed restore, got " + captured.dbacMessages());
            RealConnection connection = raw.only();
            Assertions.assertEquals(List.of("abort"), connection.disposalCalls(), "CC-1: aborted, and never closed after it");
            Assertions.assertEquals(1, source.disposedAs(LeaseState.QUARANTINED), "CC-1: kept, out of the pool");
            Assertions.assertTrue(sessionAlive(database, connection.session), "CC-1: H2 keeps the session open, which is why it is kept");
            assertNeverHandedOut(database, connection.session, "CC-2");
            Assertions.assertTrue(
                captured.dbacMessages().stream().anyMatch(message -> message.contains("event=DBAC_METADATA_ABORT_UNCONFIRMED ")),
                "CC-6: the unconfirmed abort is logged");
            Assertions.assertEquals(List.of(), LifecycleTestSupport.logContractViolations(captured, MetadataTestSupport.SECRET_FRAGMENTS),
                "CC-6: the P1 log contract");
        } finally {
            raw.cleanUp();
        }
    }

    /**
     * CC-3, CC-6: an abort that throws keeps the real connection out of the pool; shutdown cannot confirm an abort on H2 either,
     * so it hands the connection to the keeper instead of closing it into the pool
     */
    @Test
    public void cc3AbortFailureKeepsTheRealConnectionOutOfThePool() throws Throwable {
        leases.allowResidue();
        CBDatabase database = metadataDatabase();
        RealSource raw = new RealSource(database);
        raw.restoreFails = true;
        raw.abortFailures = 1;
        try {
            BoundedMetadataConnections.Owned owned = leases.owned(raw, BoundedMetadataConnections.Tuning.PRODUCTION);
            final LifecycleTestSupport.Captured captured = LifecycleTestSupport.captureLogs(() -> {
                try (MetadataLease lease = lease(owned.leases())) {
                    lease.query(MetadataQuery.sql("SELECT 1 AS V").columnInt("V").expectRows(1, 1).build());
                }
            });
            RealConnection connection = raw.only();
            Assertions.assertEquals(List.of("abort"), connection.disposalCalls(), "CC-3: aborted once, never closed");
            Assertions.assertEquals(1, owned.leases().quarantined(), "CC-3: quarantined");
            Assertions.assertTrue(sessionAlive(database, connection.session), "CC-3: the session is held, not returned and not closed");
            assertNeverHandedOut(database, connection.session, "CC-3");
            owned.shutdown().beginClose();
            owned.shutdown().finishClose();
            BoundedMetadataConnections.ShutdownReport report = owned.leases().lastShutdownReport();
            Assertions.assertNotNull(report, "CC-3: shutdown must report");
            Assertions.assertEquals(List.of(0, 1, 0),
                List.of(report.quarantineReleased(), report.transferredToKeeper(), report.quarantineHeld()),
                "CC-3: on H2 the retry cannot confirm its abort, so the connection goes to the keeper");
            Assertions.assertEquals(List.of("abort", "abort"), connection.disposalCalls(), "CC-3: the retry aborted and closed nothing");
            Assertions.assertEquals(List.of(), LifecycleTestSupport.logContractViolations(captured, MetadataTestSupport.SECRET_FRAGMENTS),
                "CC-6: the P1 log contract");
        } finally {
            raw.cleanUp();
        }
    }

    /**
     * CC-4: four contaminated real sessions - quarantined because H2's abort cannot close them - make the source refuse at once
     */
    @Test
    public void cc4AFullQuarantineRefusesAtOnce() throws SQLException {
        leases.allowResidue();
        CBDatabase database = metadataDatabase();
        RealSource raw = new RealSource(database);
        raw.restoreFails = true;
        try {
            BoundedMetadataConnections.Owned owned = leases.owned(raw, BoundedMetadataConnections.Tuning.PRODUCTION);
            for (int i = 0; i < BoundedMetadataConnections.CAPACITY; i++) {
                try (MetadataLease lease = lease(owned.leases())) {
                    lease.query(MetadataQuery.sql("SELECT 1 AS V").columnInt("V").expectRows(1, 1).build());
                }
            }
            Assertions.assertEquals(BoundedMetadataConnections.Health.REFUSING, owned.leases().health(), "CC-4: refusing");
            long submitted = owned.leases().submittedTasks();
            Outcome<MetadataLease> next = MetadataTestSupport.open(owned.leases(), MetadataTestSupport.budget(Duration.ofSeconds(5)), WAIT);
            Assertions.assertEquals(MetadataUnavailableException.Reason.REFUSING, MetadataTestSupport.refusal(next), "CC-4");
            Assertions.assertTrue(next.elapsedNanos() < TimeUnit.MILLISECONDS.toNanos(500), "CC-4: no wait");
            Assertions.assertEquals(submitted, owned.leases().submittedTasks(), "CC-4: nothing submitted");
            for (RealConnection connection : raw.made) {
                assertNeverHandedOut(database, connection.session, "CC-4 session " + connection.session);
            }
            owned.shutdown().beginClose();
            owned.shutdown().finishClose();
            Assertions.assertEquals(BoundedMetadataConnections.CAPACITY, owned.leases().lastShutdownReport().transferredToKeeper(),
                "CC-4: shutdown keeps all four rather than closing them into the pool");
        } finally {
            raw.cleanUp();
        }
    }

    /**
     * CC-5: the ordinary path on the real pool: restored, closed once, the session kept and handed out again clean
     */
    @Test
    public void cc5TheOrdinaryPathReturnsAReusableSession() throws Exception {
        CBDatabase database = metadataDatabase();
        RealSource raw = new RealSource(database);
        BoundedMetadataConnections source = leases.bounded(raw, BoundedMetadataConnections.Tuning.PRODUCTION);
        try (MetadataLease lease = lease(source)) {
            lease.query(MetadataQuery.sql("SELECT 1 AS V").columnInt("V").expectRows(1, 1).build());
        }
        RealConnection connection = raw.only();
        Assertions.assertEquals(List.of("close"), connection.disposalCalls(), "CC-5: closed once, no abort");
        Assertions.assertTrue(sessionAlive(database, connection.session), "CC-5: the session stays in the pool");
        List<Connection> borrowed = new ArrayList<>();
        try {
            Connection same = null;
            for (int i = 0; i < 20 && same == null; i++) {
                Connection next = database.openConnection();
                borrowed.add(next);
                if (MetadataLeaseTest.sessionId(next) == connection.session) {
                    same = next;
                }
            }
            Assertions.assertNotNull(same, "FIXTURE CC-5: the pool must hand the session out again");
            try (Statement statement = same.createStatement()) {
                Assertions.assertEquals(0, statement.getQueryTimeout(), "CC-5: with no timeout left on it");
            }
        } finally {
            for (Connection one : borrowed) {
                one.close();
            }
        }
    }

    /** Twenty connections from the pool: none is {@code session}, and none carries a query timeout */
    private static void assertNeverHandedOut(@NotNull CBDatabase database, long session, @NotNull String id) throws SQLException {
        List<Connection> borrowed = new ArrayList<>();
        try {
            for (int i = 0; i < 20; i++) {
                Connection next = database.openConnection();
                borrowed.add(next);
                Assertions.assertNotEquals(session, MetadataLeaseTest.sessionId(next), id + ": the kept session must never be handed out");
                try (Statement statement = next.createStatement()) {
                    Assertions.assertEquals(0, statement.getQueryTimeout(), id + ": a connection from the pool carries a timeout");
                }
            }
        } finally {
            for (Connection one : borrowed) {
                one.close();
            }
        }
    }

    @NotNull
    private static List<String> disposalCalls(@NotNull FakeConnection connection) {
        return connection.calls().stream()
            .filter(call -> call.equals("close") || call.equals("abort") || call.equals("close-after-abort")).toList();
    }

    // ---------------------------------------------------------------- helpers

    @NotNull
    private static MetadataLease lease(@NotNull BoundedMetadataConnections source) {
        return MetadataTestSupport.open(source, MetadataTestSupport.budget(MetadataTestSupport.LONG), WAIT).get();
    }

    @NotNull
    private static BoundedMetadataConnections.Probe holdAt(
        @NotNull CountDownLatch hold,
        @NotNull BoundedMetadataConnections.ProbePoint at
    ) {
        return point -> {
            if (point == at) {
                try {
                    hold.await(30, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        };
    }

    @NotNull
    private static BoundedMetadataConnections.Tuning shortFinish() {
        return MetadataTestSupport.tuning(SHORT_FINISH, BoundedMetadataConnections.Probe.NONE);
    }

    @NotNull
    private static CBDatabase metadataDatabase() {
        CBDatabase database = EmbeddedSecurityControllerFactory.getDbInstance();
        Assertions.assertNotNull(database, "FIXTURE: the server metadata database must exist");
        return database;
    }

    /** Whether H2 still has a session with this id, read on a connection of its own */
    static boolean sessionAlive(@NotNull CBDatabase database, long session) throws SQLException {
        try (Connection probe = database.openConnection();
             Statement statement = probe.createStatement();
             ResultSet result = statement.executeQuery("SELECT * FROM INFORMATION_SCHEMA.SESSIONS")
        ) {
            ResultSetMetaData meta = result.getMetaData();
            int column = -1;
            for (int i = 1; i <= meta.getColumnCount(); i++) {
                String name = meta.getColumnLabel(i);
                if (name.equalsIgnoreCase("SESSION_ID") || name.equalsIgnoreCase("ID")) {
                    column = i;
                    break;
                }
            }
            Assertions.assertTrue(column > 0, "FIXTURE: INFORMATION_SCHEMA.SESSIONS must name its session id column");
            while (result.next()) {
                if (result.getLong(column) == session) {
                    return true;
                }
            }
            return false;
        }
    }

    /** Real pooled connections with restore and abort failures put in front of them */
    private static final class RealSource implements MetadataConnectionSource {
        final List<RealConnection> made = Collections.synchronizedList(new ArrayList<>());
        private final CBDatabase database;
        volatile boolean restoreFails;
        /** How many aborts, across every connection, fail before the real abort runs */
        volatile int abortFailures;
        private final AtomicInteger abortsFailed = new AtomicInteger();

        RealSource(@NotNull CBDatabase database) {
            this.database = database;
        }

        @NotNull
        @Override
        public Connection openConnection() throws SQLException {
            Connection real = database.openConnection();
            RealConnection wrapped = new RealConnection(real, MetadataLeaseTest.sessionId(real), this);
            made.add(wrapped);
            return wrapped.proxy;
        }

        @NotNull
        RealConnection only() {
            Assertions.assertEquals(1, made.size(), "FIXTURE: one real connection");
            return made.get(0);
        }

        boolean failThisAbort() {
            return abortsFailed.getAndIncrement() < abortFailures;
        }

        /**
         * Test cleanup, after the assertions: a session the lease kept is reset and closed, so the shared pool gets a clean one back
         */
        void cleanUp() throws SQLException {
            for (RealConnection connection : made) {
                connection.cleanUp();
            }
        }
    }

    /** One real connection behind a recording, failure-injecting proxy */
    private static final class RealConnection {
        final long session;
        final Connection proxy;
        private final Connection delegate;
        private final List<String> calls = Collections.synchronizedList(new ArrayList<>());
        private volatile boolean aborted;

        RealConnection(@NotNull Connection delegate, long session, @NotNull RealSource source) {
            this.session = session;
            this.delegate = delegate;
            this.proxy = MetadataTestSupport.proxy(Connection.class, (self, method, args) -> switch (method.getName()) {
                case "createStatement" -> restoreStatement((Statement) invoke(delegate, method, args), source);
                case "abort" -> {
                    calls.add("abort");
                    if (source.failThisAbort()) {
                        throw new InjectedSqlException("abort");
                    }
                    aborted = true;
                    yield invoke(delegate, method, args);
                }
                case "close" -> {
                    calls.add(aborted ? "close-after-abort" : "close");
                    yield invoke(delegate, method, args);
                }
                default -> invoke(delegate, method, args);
            });
        }

        @NotNull
        private static Statement restoreStatement(@NotNull Statement delegate, @NotNull RealSource source) {
            return MetadataTestSupport.proxy(Statement.class, (self, method, args) -> {
                if (method.getName().equals("setQueryTimeout") && source.restoreFails) {
                    throw new InjectedSqlException("restore");
                }
                return invoke(delegate, method, args);
            });
        }

        void cleanUp() throws SQLException {
            if (!delegate.isClosed()) {
                try (Statement statement = delegate.createStatement()) {
                    statement.setQueryTimeout(0);
                }
                delegate.close();
            }
        }

        @NotNull
        List<String> disposalCalls() {
            synchronized (calls) {
                return new ArrayList<>(calls);
            }
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
}
