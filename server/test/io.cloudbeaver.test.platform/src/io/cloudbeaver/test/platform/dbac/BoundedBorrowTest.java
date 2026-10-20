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
import io.cloudbeaver.service.dbac.policy.BoundedMetadataConnections;
import io.cloudbeaver.service.dbac.policy.LeaseState;
import io.cloudbeaver.service.dbac.policy.MetadataBudget;
import io.cloudbeaver.service.dbac.policy.MetadataLease;
import io.cloudbeaver.service.dbac.policy.MetadataOutcome;
import io.cloudbeaver.service.dbac.policy.MetadataPurpose;
import io.cloudbeaver.service.dbac.policy.MetadataUnavailableException;
import io.cloudbeaver.test.platform.dbac.MetadataTestSupport.FakeConnection;
import io.cloudbeaver.test.platform.dbac.MetadataTestSupport.FakeSource;
import io.cloudbeaver.test.platform.dbac.MetadataTestSupport.InjectedSqlException;
import io.cloudbeaver.test.platform.dbac.MetadataTestSupport.ManualClock;
import io.cloudbeaver.test.platform.dbac.MetadataTestSupport.Outcome;
import io.cloudbeaver.test.platform.dbac.MetadataTestSupport.Pending;
import org.jkiss.code.NotNull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * P5-1a: the bounded borrow - a caller waits only as long as its budget, and every connection has exactly one owner
 * <p>
 * The raw source here waits on a gate the test opens, uninterruptibly, the way a metadata pool waits
 * for a connection; probes stop a worker at a chosen point. Whatever the interleaving, a connection
 * is closed exactly once, by whoever owns it, and the caller is never kept past its budget.
 */
public class BoundedBorrowTest {

    private static final Duration ONE_SECOND = Duration.ofSeconds(1);
    private static final Duration WAIT = Duration.ofSeconds(10);

    private final MetadataLeaseFixture leases = new MetadataLeaseFixture();

    @AfterEach
    public void closeLeases() {
        leases.close();
    }

    @BeforeAll
    public static void startServer() throws Exception {
        CEAppStarter.startServerIfNotStarted();
    }

    /**
     * BB-1: a connection that arrives before the deadline is the caller's: it is used and closed once, by the caller
     */
    @Test
    public void bb1ArrivalBeforeTheDeadlineBelongsToTheCaller() {
        FakeSource raw = new FakeSource();
        raw.gate = new CountDownLatch(1);
        BoundedMetadataConnections source = source(raw);
        final Pending<String> caller = MetadataTestSupport.start("dbac-bb1-caller", () -> {
            try (MetadataLease lease = source.open(MetadataTestSupport.budget(Duration.ofSeconds(5)), MetadataPurpose.SNAPSHOT)) {
                return String.valueOf(lease.query(MetadataTestSupport.valueQuery()) instanceof MetadataOutcome.Done);
            }
        });
        Assertions.assertTrue(MetadataTestSupport.eventually(() -> raw.atGate.get() == 1), "FIXTURE BB-1: the worker must reach the pool");
        sleep(200);
        raw.gate.countDown();
        Outcome<String> outcome = caller.await(WAIT);
        Assertions.assertEquals("true", outcome.get(), "BB-1: the caller must use the connection");
        FakeConnection connection = raw.only();
        Assertions.assertEquals(1, connection.closes.get(), "BB-1: closed once");
        Assertions.assertSame(caller.thread(), connection.closedBy.get(), "BB-1: by the caller");
        Assertions.assertEquals(BoundedMetadataConnections.CAPACITY, source.availableSlots(), "BB-1: the slot is free again");
    }

    /**
     * BB-2: a connection that arrives after the deadline belongs to the worker, which closes it once; the caller was refused in time
     */
    @Test
    public void bb2ArrivalAfterTheDeadlineIsClosedByTheWorker() {
        FakeSource raw = new FakeSource();
        raw.gate = new CountDownLatch(1);
        BoundedMetadataConnections source = source(raw);
        Outcome<MetadataLease> outcome = MetadataTestSupport.open(source, MetadataTestSupport.budget(ONE_SECOND), WAIT);
        Assertions.assertEquals(MetadataUnavailableException.Reason.TIMEOUT, MetadataTestSupport.refusal(outcome), "BB-2: timed out");
        assertWithin(outcome, ONE_SECOND, "BB-2");
        raw.gate.countDown();
        Assertions.assertTrue(MetadataTestSupport.eventually(() -> raw.made.size() == 1 && raw.only().closes.get() == 1),
            "BB-2: the late connection must be closed once");
        Assertions.assertTrue(raw.only().closedBy.get().getName().startsWith(BoundedMetadataConnections.THREAD_PREFIX),
            "BB-2: by the worker, got " + raw.only().closedBy.get().getName());
        Assertions.assertTrue(MetadataTestSupport.eventually(() -> source.availableSlots() == BoundedMetadataConnections.CAPACITY),
            "BB-2: and the slot comes back");
        Assertions.assertEquals(1, source.disposedAs(LeaseState.RETURNED), "BB-2: one disposal");
    }

    /**
     * BB-3: a source that ignores interrupts holds one worker, never the caller; the worker is never interrupted
     */
    @Test
    public void bb3ASourceThatIgnoresInterruptsHoldsOnlyItsWorker() {
        FakeSource raw = new FakeSource();
        raw.gate = new CountDownLatch(1);
        BoundedMetadataConnections source = source(raw);
        Outcome<MetadataLease> outcome = MetadataTestSupport.open(source, MetadataTestSupport.budget(ONE_SECOND), WAIT);
        Assertions.assertEquals(MetadataUnavailableException.Reason.TIMEOUT, MetadataTestSupport.refusal(outcome), "BB-3");
        assertWithin(outcome, ONE_SECOND, "BB-3");
        Assertions.assertEquals(1, source.runningWorkers(), "BB-3: one worker stays in the borrow");
        Thread worker = raw.borrowingThreads.get(0);
        Assertions.assertTrue(worker.isDaemon(), "BB-3: workers are daemon threads");
        Assertions.assertTrue(worker.getName().startsWith(BoundedMetadataConnections.THREAD_PREFIX + source.serial() + "-"),
            "BB-3: worker thread name " + worker.getName());
        raw.gate.countDown();
        Assertions.assertTrue(MetadataTestSupport.eventually(() -> raw.made.size() == 1 && raw.only().closes.get() == 1),
            "BB-3: released, the worker closes its connection once");
        Assertions.assertEquals(0, raw.interruptedWorkers.get(), "BB-3: no worker may be interrupted");
    }

    /**
     * BB-4: with every worker held after its caller gave up, the next caller is refused at once, and nothing is submitted
     */
    @Test
    public void bb4EveryWorkerStuckRefusesTheNextCallerAtOnce() {
        FakeSource raw = new FakeSource();
        raw.gate = new CountDownLatch(1);
        BoundedMetadataConnections source = source(raw);
        List<Pending<MetadataLease>> callers = new ArrayList<>();
        for (int i = 0; i < BoundedMetadataConnections.CAPACITY; i++) {
            callers.add(MetadataTestSupport.start("dbac-bb4-caller-" + i,
                () -> source.open(MetadataTestSupport.budget(ONE_SECOND), MetadataPurpose.SNAPSHOT)));
        }
        for (Pending<MetadataLease> caller : callers) {
            Assertions.assertEquals(MetadataUnavailableException.Reason.TIMEOUT, MetadataTestSupport.refusal(caller.await(WAIT)), "BB-4");
        }
        Assertions.assertEquals(BoundedMetadataConnections.CAPACITY, source.runningWorkers(), "BB-4: every worker is held");
        long submitted = source.submittedTasks();
        Outcome<MetadataLease> next = MetadataTestSupport.open(source, MetadataTestSupport.budget(ONE_SECOND), WAIT);
        Assertions.assertEquals(MetadataUnavailableException.Reason.CAPACITY, MetadataTestSupport.refusal(next), "BB-4: refused");
        Assertions.assertTrue(next.elapsedNanos() < TimeUnit.MILLISECONDS.toNanos(500),
            "BB-4: refused at once, took " + TimeUnit.NANOSECONDS.toMillis(next.elapsedNanos()) + "ms");
        Assertions.assertEquals(submitted, source.submittedTasks(), "BB-4: nothing submitted for it");
        raw.gate.countDown();
        Assertions.assertTrue(MetadataTestSupport.eventually(() -> raw.made.size() == BoundedMetadataConnections.CAPACITY
            && raw.made.stream().allMatch(connection -> connection.closes.get() == 1)), "BB-4: every late connection closed once");
        Assertions.assertTrue(MetadataTestSupport.eventually(() -> source.availableSlots() == BoundedMetadataConnections.CAPACITY),
            "BB-4: every slot back");
        Assertions.assertEquals(0, raw.interruptedWorkers.get(), "BB-4: no worker interrupted");
    }

    /**
     * BB-5: at capacity, while the four are still waiting, a fifth caller is refused at once without a submission
     */
    @Test
    public void bb5SaturationIsRefusedImmediately() {
        FakeSource raw = new FakeSource();
        raw.gate = new CountDownLatch(1);
        BoundedMetadataConnections source = source(raw);
        List<Pending<String>> callers = new ArrayList<>();
        for (int i = 0; i < BoundedMetadataConnections.CAPACITY; i++) {
            callers.add(MetadataTestSupport.start("dbac-bb5-caller-" + i, () -> {
                try (MetadataLease lease = source.open(MetadataTestSupport.budget(Duration.ofSeconds(8)), MetadataPurpose.SNAPSHOT)) {
                    return String.valueOf(lease.query(MetadataTestSupport.valueQuery()) instanceof MetadataOutcome.Done);
                }
            }));
        }
        Assertions.assertTrue(MetadataTestSupport.eventually(() -> raw.atGate.get() == BoundedMetadataConnections.CAPACITY),
            "FIXTURE BB-5: four borrows must be in flight");
        Outcome<MetadataLease> fifth = MetadataTestSupport.open(source, MetadataTestSupport.budget(ONE_SECOND), WAIT);
        Assertions.assertEquals(MetadataUnavailableException.Reason.CAPACITY, MetadataTestSupport.refusal(fifth), "BB-5");
        Assertions.assertTrue(fifth.elapsedNanos() < TimeUnit.MILLISECONDS.toNanos(500), "BB-5: refused at once");
        Assertions.assertEquals(BoundedMetadataConnections.CAPACITY, source.submittedTasks(), "BB-5: only the four were submitted");
        raw.gate.countDown();
        for (Pending<String> caller : callers) {
            Assertions.assertEquals("true", caller.await(WAIT).get(), "BB-5: the four complete");
        }
    }

    /**
     * BB-6: an interrupted caller gives up at once with its interrupt kept; the late connection is the worker's
     */
    @Test
    public void bb6AnInterruptedCallerGivesUpAndKeepsItsInterrupt() {
        FakeSource raw = new FakeSource();
        raw.gate = new CountDownLatch(1);
        BoundedMetadataConnections source = source(raw);
        Pending<String> caller = MetadataTestSupport.start("dbac-bb6-caller", () -> {
            try {
                source.open(MetadataTestSupport.budget(Duration.ofSeconds(8)), MetadataPurpose.SNAPSHOT).close();
                return "lease";
            } catch (MetadataUnavailableException e) {
                return e.reason() + " interrupted=" + Thread.currentThread().isInterrupted();
            }
        });
        Assertions.assertTrue(MetadataTestSupport.eventually(() -> raw.atGate.get() == 1), "FIXTURE BB-6: the worker must reach the pool");
        caller.thread().interrupt();
        Outcome<String> outcome = caller.await(WAIT);
        Assertions.assertEquals("INTERRUPTED interrupted=true", outcome.get(), "BB-6: refused, interrupt kept");
        Assertions.assertTrue(outcome.elapsedNanos() < TimeUnit.SECONDS.toNanos(5), "BB-6: at once");
        raw.gate.countDown();
        Assertions.assertTrue(MetadataTestSupport.eventually(() -> raw.made.size() == 1 && raw.only().closes.get() == 1),
            "BB-6: the worker closes the late connection once");
        Assertions.assertEquals(0, raw.interruptedWorkers.get(), "BB-6: the worker is not interrupted");
    }

    /**
     * BB-7: a close that fails is logged once by the P1 contract, never thrown, and the connection is aborted instead
     */
    @Test
    public void bb7ACloseFailureIsLoggedOnceAndAborted() throws Throwable {
        FakeSource raw = new FakeSource(connection -> connection.closeFails = new InjectedSqlException("close"));
        BoundedMetadataConnections source = source(raw);
        MetadataLease lease = MetadataTestSupport.open(source, MetadataTestSupport.budget(WAIT), WAIT).get();
        lease.query(MetadataTestSupport.valueQuery());
        LifecycleTestSupport.Captured captured = LifecycleTestSupport.captureLogs(() -> Assertions.assertDoesNotThrow(lease::close));
        Assertions.assertEquals(List.of(), LifecycleTestSupport.logContractViolations(captured, MetadataTestSupport.SECRET_FRAGMENTS),
            "BB-7: the P1 log contract");
        List<String> closeFailures = captured.dbacMessages().stream()
            .filter(message -> message.contains("event=DBAC_METADATA_CLOSE_FAILED ")).toList();
        Assertions.assertEquals(1, closeFailures.size(), "BB-7: logged once, got " + captured.dbacMessages());
        Assertions.assertTrue(closeFailures.get(0).contains("exception=" + InjectedSqlException.class.getName()),
            "BB-7: by class " + closeFailures.get(0));
        FakeConnection connection = raw.only();
        Assertions.assertEquals(List.of(1, 1, 1),
            List.of(connection.count("close"), connection.count("abort"), connection.count("close-after-abort")),
            "BB-7: one close, then one abort and one close");
        Assertions.assertEquals(LeaseState.INVALIDATED, lease.state(), "BB-7: invalidated");
    }

    /**
     * BB-8: across a mix of timely and late borrows, every connection made is closed exactly once and every slot comes back
     */
    @Test
    public void bb8EveryConnectionMadeIsClosedExactlyOnce() {
        FakeSource raw = new FakeSource();
        java.util.concurrent.atomic.AtomicInteger round = new java.util.concurrent.atomic.AtomicInteger();
        raw.onBorrow = () -> sleep(List.of(0, 50, 1500, 0).get(Math.floorMod(round.getAndIncrement(), 4)));
        BoundedMetadataConnections source = source(raw);
        int maxRunning = 0;
        for (int wave = 0; wave < 5; wave++) {
            List<Pending<String>> callers = new ArrayList<>();
            for (int i = 0; i < BoundedMetadataConnections.CAPACITY; i++) {
                callers.add(MetadataTestSupport.start("dbac-bb8-caller-" + wave + "-" + i, () -> {
                    try (MetadataLease lease = source.open(MetadataTestSupport.budget(Duration.ofMillis(1200)), MetadataPurpose.SNAPSHOT)) {
                        lease.query(MetadataTestSupport.valueQuery());
                        return "used";
                    } catch (MetadataUnavailableException e) {
                        return e.reason().name();
                    }
                }));
            }
            for (Pending<String> caller : callers) {
                caller.await(WAIT);
                maxRunning = Math.max(maxRunning, source.runningWorkers());
            }
            MetadataTestSupport.eventually(() -> source.availableSlots() == BoundedMetadataConnections.CAPACITY);
        }
        Assertions.assertTrue(MetadataTestSupport.eventually(() -> raw.made.stream().allMatch(connection -> connection.closes.get() == 1)),
            "BB-8: every connection closed once");
        Assertions.assertEquals(raw.made.size(), raw.made.stream().mapToInt(connection -> connection.closes.get()).sum(),
            "BB-8: opened == closed");
        Assertions.assertTrue(maxRunning <= BoundedMetadataConnections.WORKERS, "BB-8: never more than the workers, saw " + maxRunning);
        Assertions.assertEquals(BoundedMetadataConnections.CAPACITY, source.availableSlots(), "BB-8: every slot back");
    }

    /**
     * BB-9: the worker stopped just before publishing; the caller gives up first, so the worker owns and closes the connection
     */
    @Test
    public void bb9GivingUpBeforeThePublicationLeavesTheConnectionToTheWorker() {
        CountDownLatch hold = new CountDownLatch(1);
        FakeSource raw = new FakeSource();
        BoundedMetadataConnections source = leases.bounded(raw, MetadataTestSupport.tuning(BoundedMetadataConnections.FINISH_WAIT,
            point -> {
                if (point == BoundedMetadataConnections.ProbePoint.WORKER_BORROWED) {
                    await(hold);
                }
            }));
        Outcome<MetadataLease> outcome = MetadataTestSupport.open(source, MetadataTestSupport.budget(ONE_SECOND), WAIT);
        Assertions.assertEquals(MetadataUnavailableException.Reason.TIMEOUT, MetadataTestSupport.refusal(outcome), "BB-9");
        hold.countDown();
        Assertions.assertTrue(MetadataTestSupport.eventually(() -> raw.made.size() == 1 && raw.only().closes.get() == 1),
            "BB-9: closed once");
        Assertions.assertTrue(raw.only().closedBy.get().getName().startsWith(BoundedMetadataConnections.THREAD_PREFIX),
            "BB-9: by the worker");
        Assertions.assertEquals(0, raw.only().executes.get(), "BB-9: never used");
    }

    /**
     * BB-10: published but not yet signalled; the caller, past its deadline, finds the lease, owns it and disposes it unused
     */
    @Test
    public void bb10APublishedLeaseFoundAfterTheDeadlineIsDisposedByTheCaller() {
        CountDownLatch hold = new CountDownLatch(1);
        FakeSource raw = new FakeSource();
        BoundedMetadataConnections source = leases.bounded(raw, MetadataTestSupport.tuning(BoundedMetadataConnections.FINISH_WAIT,
            point -> {
                if (point == BoundedMetadataConnections.ProbePoint.WORKER_PUBLISHED) {
                    await(hold);
                }
            }));
        Pending<MetadataLease> caller = MetadataTestSupport.start("dbac-bb10-caller",
            () -> source.open(MetadataTestSupport.budget(ONE_SECOND), MetadataPurpose.SNAPSHOT));
        Outcome<MetadataLease> outcome = caller.await(WAIT);
        Assertions.assertEquals(MetadataUnavailableException.Reason.TIMEOUT, MetadataTestSupport.refusal(outcome), "BB-10");
        Assertions.assertTrue(MetadataTestSupport.eventually(() -> raw.made.size() == 1 && raw.only().closes.get() == 1),
            "BB-10: the caller closes the published connection once");
        Assertions.assertSame(caller.thread(), raw.only().closedBy.get(), "BB-10: the caller is the one closing it");
        hold.countDown();
        sleep(200);
        Assertions.assertEquals(1, raw.only().closes.get(), "BB-10: the worker, released, only signals");
        Assertions.assertEquals(0, raw.only().executes.get(), "BB-10: never used");
    }

    /**
     * BB-11: whenever a caller receives a lease, the lease already holds the connection the worker made
     */
    @Test
    public void bb11ADeliveredLeaseAlwaysHoldsItsConnection() {
        FakeSource raw = new FakeSource();
        BoundedMetadataConnections source = leases.bounded(raw, MetadataTestSupport.tuning(BoundedMetadataConnections.FINISH_WAIT,
            point -> {
                if (point == BoundedMetadataConnections.ProbePoint.WORKER_PUBLISHED) {
                    sleep(50);
                }
            }));
        List<String> violations = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            Outcome<String> outcome = MetadataTestSupport.within(WAIT, () -> {
                try (MetadataLease lease = source.open(MetadataTestSupport.budget(Duration.ofSeconds(5)), MetadataPurpose.SNAPSHOT)) {
                    MetadataOutcome<?> result = lease.query(MetadataTestSupport.valueQuery());
                    return result instanceof MetadataOutcome.Done ? "done" : String.valueOf(result);
                }
            });
            if (!"done".equals(outcome.value())) {
                violations.add("round " + i + ": " + (outcome.thrown() != null ? outcome.thrown().getClass().getName() : outcome.value()));
            }
        }
        Assertions.assertEquals(List.of(), violations, "BB-11: a delivered lease must already carry its connection");
        Assertions.assertTrue(raw.made.stream().allMatch(connection -> connection.executes.get() == 1 && connection.closes.get() == 1),
            "BB-11: each connection used and closed once");
    }

    /**
     * BB-12: a failed borrow reports the failure's class and nothing else, and its slot is free before the caller hears of it
     */
    @Test
    public void bb12AFailedBorrowCarriesOnlyItsClass() {
        FakeSource raw = new FakeSource();
        raw.fails = new InjectedSqlException("borrow");
        BoundedMetadataConnections source = source(raw);
        Outcome<String> outcome = MetadataTestSupport.within(WAIT, () -> {
            try {
                source.open(MetadataTestSupport.budget(Duration.ofSeconds(5)), MetadataPurpose.SNAPSHOT).close();
                return "lease";
            } catch (MetadataUnavailableException e) {
                return e.reason() + "|" + e.failureClass() + "|" + source.availableSlots() + "|" + (e.getCause() == null)
                    + "|" + e.getMessage().contains("secret") + "|" + e.getStackTrace().length;
            }
        });
        Assertions.assertEquals("BORROW_FAILED|" + InjectedSqlException.class.getName() + "|" + BoundedMetadataConnections.CAPACITY
            + "|true|false|0", outcome.get(), "BB-12: reason, class, slot free, no cause, no message from the failure, no trace");
    }

    /**
     * BB-13: a budget already spent is refused before anything is submitted or borrowed
     */
    @Test
    public void bb13ASpentBudgetIsRefusedBeforeAnyBorrow() {
        FakeSource raw = new FakeSource();
        BoundedMetadataConnections source = source(raw);
        ManualClock clock = new ManualClock(Long.MAX_VALUE - 5);
        MetadataBudget budget = MetadataBudget.startingNow(clock, ONE_SECOND);
        clock.advance(ONE_SECOND);
        Outcome<MetadataLease> outcome = MetadataTestSupport.open(source, budget, WAIT);
        Assertions.assertEquals(MetadataUnavailableException.Reason.BUDGET_EXHAUSTED, MetadataTestSupport.refusal(outcome), "BB-13");
        Assertions.assertEquals(0, source.submittedTasks(), "BB-13: nothing submitted");
        Assertions.assertEquals(0, raw.calls.get(), "BB-13: nothing borrowed");
    }

    /**
     * BB-14: a budget clock that fails after the lease is delivered strands nothing: the caller is refused and the connection closed once
     */
    @Test
    public void bb14AFailingBudgetClockStrandsNothing() {
        FakeSource raw = new FakeSource();
        BoundedMetadataConnections source = source(raw);
        java.util.concurrent.atomic.AtomicBoolean broken = new java.util.concurrent.atomic.AtomicBoolean();
        MetadataBudget budget = MetadataBudget.startingNow(() -> {
            if (broken.get()) {
                throw new IllegalStateException("budget clock failed");
            }
            return System.nanoTime();
        }, Duration.ofSeconds(5));
        raw.onBorrow = () -> broken.set(true);
        Outcome<MetadataLease> outcome = MetadataTestSupport.open(source, budget, WAIT);
        Assertions.assertEquals(MetadataUnavailableException.Reason.TIMEOUT, MetadataTestSupport.refusal(outcome),
            "BB-14: a budget that cannot be read is a spent one");
        Assertions.assertTrue(MetadataTestSupport.eventually(() -> raw.made.size() == 1 && raw.only().closes.get() == 1),
            "BB-14: the delivered connection is closed once");
        Assertions.assertTrue(MetadataTestSupport.eventually(() -> source.availableSlots() == BoundedMetadataConnections.CAPACITY),
            "BB-14: and its slot comes back");
    }

    /**
     * BB-15: a borrow given up before any worker claimed it frees its slot at once, and is never borrowed afterwards
     */
    @Test
    public void bb15ABorrowGivenUpBeforeItStartedFreesItsSlot() {
        CountDownLatch hold = new CountDownLatch(1);
        FakeSource raw = new FakeSource();
        BoundedMetadataConnections source = leases.bounded(raw, MetadataTestSupport.tuning(BoundedMetadataConnections.FINISH_WAIT,
            point -> {
                if (point == BoundedMetadataConnections.ProbePoint.WORKER_CLAIMING) {
                    await(hold);
                }
            }));
        Outcome<MetadataLease> outcome = MetadataTestSupport.open(source, MetadataTestSupport.budget(Duration.ofMillis(500)), WAIT);
        Assertions.assertEquals(MetadataUnavailableException.Reason.TIMEOUT, MetadataTestSupport.refusal(outcome), "BB-15");
        Assertions.assertEquals(BoundedMetadataConnections.CAPACITY, source.availableSlots(),
            "BB-15: the caller frees the slot of a borrow nobody started");
        hold.countDown();
        sleep(300);
        Assertions.assertEquals(0, raw.calls.get(), "BB-15: the abandoned borrow never reaches the pool");
        Assertions.assertEquals(BoundedMetadataConnections.CAPACITY, source.availableSlots(), "BB-15: and the slot is freed once");
    }

    /** What BB-16's budget clock throws: an Error of its own, so the very object can be checked */
    private static final class BudgetClockError extends Error {
        BudgetClockError() {
            super("budget clock failed");
        }
    }

    /**
     * BB-16: an Error from the budget clock after the lease is delivered still leaves the connection with an owner:
     * it is disposed, its slot comes back, and the very Error reaches the caller
     */
    @Test
    public void bb16AnErrorWhileWaitingStillSettlesTheBorrow() {
        FakeSource raw = new FakeSource();
        BudgetClockError failure = new BudgetClockError();
        java.util.concurrent.atomic.AtomicBoolean broken = new java.util.concurrent.atomic.AtomicBoolean();
        MetadataBudget budget = MetadataBudget.startingNow(() -> {
            if (broken.get()) {
                throw failure;
            }
            return System.nanoTime();
        }, Duration.ofSeconds(5));
        BoundedMetadataConnections probed = leases.bounded(raw, MetadataTestSupport.tuning(BoundedMetadataConnections.FINISH_WAIT,
            point -> {
                if (point == BoundedMetadataConnections.ProbePoint.WORKER_PUBLISHED) {
                    broken.set(true);
                }
            }));
        Outcome<MetadataLease> outcome = MetadataTestSupport.open(probed, budget, WAIT);
        Assertions.assertTrue(outcome.finished(), "BB-16: the caller returns");
        Assertions.assertSame(failure, outcome.thrown(), "BB-16: the budget clock's Error reaches the caller as it is");
        Assertions.assertTrue(MetadataTestSupport.eventually(() -> raw.made.size() == 1 && raw.only().closes.get() == 1),
            "BB-16: the delivered connection is closed once");
        Assertions.assertEquals(BoundedMetadataConnections.CAPACITY, probed.availableSlots(), "BB-16: and its slot is back");
    }

    // ---------------------------------------------------------------- helpers

    @NotNull
    private BoundedMetadataConnections source(@NotNull FakeSource raw) {
        return leases.bounded(raw, BoundedMetadataConnections.Tuning.PRODUCTION);
    }

    /** The refusal came no earlier than the budget and not much later */
    private static void assertWithin(@NotNull Outcome<?> outcome, @NotNull Duration budget, @NotNull String id) {
        long millis = TimeUnit.NANOSECONDS.toMillis(outcome.elapsedNanos());
        Assertions.assertTrue(millis >= budget.toMillis() - 50 && millis < budget.toMillis() + 3000,
            id + ": the caller must return at its deadline, took " + millis + "ms");
    }

    private static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static void await(@NotNull CountDownLatch latch) {
        try {
            if (!latch.await(30, TimeUnit.SECONDS)) {
                throw new IllegalStateException("FIXTURE: a probe was never released");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
