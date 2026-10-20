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
package io.cloudbeaver.service.dbac.policy;

import io.cloudbeaver.service.dbac.tempwrite.MetadataConnectionSource;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.jkiss.dbeaver.Log;

import java.sql.Connection;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.AtomicReferenceArray;

/**
 * Metadata connections with a bound on how long, and how many
 * <p>
 * The metadata pool waits for a connection without limit. Holding the policy locks while waiting
 * without limit would let a pool outage stall revocation, so the policy core never borrows from the
 * pool on its own thread: a borrow runs on one of {@link #WORKERS} daemon workers, and the caller
 * waits for it only as long as its {@link MetadataBudget} allows.
 * <p>
 * <b>Slots.</b> There are {@link #CAPACITY} slots. A caller reserves one before anything is submitted,
 * and a caller that finds none free is refused at once - nothing is queued behind it. The slot stays
 * with the borrow until its connection is disposed, so the number of borrows in flight, and the
 * number of connections that can ever be quarantined, is bounded by the same number.
 * <p>
 * <b>Exactly one owner.</b> A borrow's completion is published as one immutable object by one
 * compare-and-set: {@code Delivered} carries the lease, {@code Failed} the failure's class name. The
 * caller that gives up and the worker that delivers race on that same reference, so either the caller
 * owns the connection or the worker does, never both and never neither. Workers are never interrupted;
 * a worker interrupted in the middle of H2 file I/O can close the whole metadata database.
 * <p>
 * <b>Shutdown is two calls</b>, made by whoever owns the {@link Shutdown} capability around the pool
 * close: {@code beginClose} stops new borrows; the pool close wakes any worker still waiting on the
 * pool; {@code finishClose} waits a bounded time for the workers, retries the quarantine once - an
 * abort that is seen to close the connection, then a close - and moves what it cannot release to the
 * process-lifetime keeper. On H2, whose abort does nothing, that is every quarantined connection.
 * <p>
 * <b>Nothing is ever dropped.</b> A connection that can be neither closed nor aborted is held
 * strongly: in its slot while the source runs, and in a static keeper once it has shut down - so even
 * this object being collected does not release it. The keeper is bounded by the slots: at most
 * {@link #CAPACITY} connections per instance, and there is one instance per metadata database.
 * <p>
 * The only way to make one is {@link #create}, which hands back the source together with its shutdown
 * capability; whoever creates one owns both.
 */
public final class BoundedMetadataConnections implements MetadataLeaseSource {

    private static final Log log = Log.getLog(BoundedMetadataConnections.class);

    /** Borrows in flight, and connections that can be quarantined, per instance */
    public static final int CAPACITY = 4;
    /** Borrowing threads per instance */
    public static final int WORKERS = 4;
    /** How long {@code finishClose} waits for the workers */
    public static final Duration FINISH_WAIT = Duration.ofSeconds(5);
    /** How long an idle worker thread lives */
    public static final Duration KEEP_ALIVE = Duration.ofSeconds(30);
    /** The worker thread name prefix; the instance serial and a counter follow */
    public static final String THREAD_PREFIX = "dbac-metadata-borrow-";

    static final String EVENT_BORROW_FAILED = "DBAC_METADATA_BORROW_FAILED";
    static final String EVENT_REFUSING = "DBAC_METADATA_REFUSING";
    static final String EVENT_QUARANTINED = "DBAC_METADATA_QUARANTINED";
    static final String EVENT_RESIDUAL = "DBAC_METADATA_RESIDUAL";
    static final String EVENT_QUARANTINE_RELEASE_FAILED = "DBAC_METADATA_QUARANTINE_RELEASE_FAILED";
    static final String EVENT_SHUTDOWN_REPORT = "DBAC_METADATA_SHUTDOWN_REPORT";
    static final String EVENT_SLOT_TRIPWIRE = "DBAC_METADATA_SLOT_TRIPWIRE";

    private static final AtomicLong SERIALS = new AtomicLong();
    /** Holds, for the rest of the process, every connection that could not be released after shutdown */
    private static final ProcessResidualKeeper RESIDUALS = new ProcessResidualKeeper();

    /** Where the source is; {@code REFUSING} and {@code CLOSED} are terminal */
    public enum Health {
        OPEN,
        /** Every slot is quarantined; every borrow is refused until the process restarts */
        REFUSING,
        /** {@code beginClose} has run; no new borrow */
        CLOSING,
        /** {@code finishClose} has run */
        CLOSED
    }

    /** Points a test can stop at; production passes {@link Probe#NONE} */
    public enum ProbePoint {
        /** A worker has taken the borrow off the queue and is about to claim it */
        WORKER_CLAIMING,
        /** A worker has claimed its borrow and is about to open the connection */
        WORKER_STARTED,
        /** A worker has the connection and is about to publish it */
        WORKER_BORROWED,
        /** A worker has published the connection and is about to wake the caller */
        WORKER_PUBLISHED,
        /** A caller has stopped waiting and is about to read the completion */
        CALLER_WAITED,
        /** A disposal that cannot release its connection has seen the source not yet closed, and is about to quarantine it */
        DISPOSAL_RETAINING,
        /** That disposal has put the connection in its slot and is about to look at the source's health again */
        DISPOSAL_QUARANTINED,
        /** {@code beginClose} is starting; a probe that throws here makes it fail */
        BEGIN_CLOSE,
        /** {@code finishClose} is starting; a probe that throws here makes it fail */
        FINISH_CLOSE,
        /** {@code finishClose} has dealt with the quarantine and is about to drop the keeper registration if it can */
        FINISH_SCANNED
    }

    /**
     * A test seam: called at each {@link ProbePoint}, with nothing but the point
     */
    @FunctionalInterface
    public interface Probe {
        /** Does nothing */
        Probe NONE = point -> {
        };

        /**
         * Called at {@code point}; may block, and at the close points may throw
         */
        void at(@NotNull ProbePoint point);
    }

    /**
     * The timings and the test seam
     *
     * @param finishWait how long {@code finishClose} waits for the workers
     * @param keepAlive  how long an idle worker thread lives
     * @param probe      {@link Probe#NONE} in production
     */
    public record Tuning(@NotNull Duration finishWait, @NotNull Duration keepAlive, @NotNull Probe probe) {
        /** What production runs with */
        public static final Tuning PRODUCTION = new Tuning(FINISH_WAIT, KEEP_ALIVE, Probe.NONE);

        /**
         * Refuses timings that are not positive
         */
        public Tuning {
            if (finishWait == null || finishWait.isNegative() || finishWait.isZero()
                || keepAlive == null || keepAlive.isNegative() || keepAlive.isZero() || probe == null) {
                throw new IllegalArgumentException("Metadata tuning needs positive timings and a probe");
            }
        }
    }

    /**
     * The source and its shutdown, which belong together
     *
     * @param leases   what consumers borrow from
     * @param shutdown what only the owner keeps
     */
    public record Owned(@NotNull BoundedMetadataConnections leases, @NotNull Shutdown shutdown) {
    }

    /**
     * Shuts one source down, in the two calls that go around the pool close
     */
    public interface Shutdown {
        /**
         * Stops new borrows and new tasks; running workers are not interrupted
         */
        void beginClose();

        /**
         * Waits a bounded time for the workers, retries the quarantine once and hands what is left to the keeper
         */
        void finishClose();
    }

    /**
     * What {@code finishClose} found, in numbers only
     *
     * @param stuckWorkers        workers still running when the wait ended
     * @param quarantineReleased  quarantined connections the retry released
     * @param transferredToKeeper quarantined connections the retry could not release, now in the keeper
     * @param quarantineHeld      quarantined connections still in their slots
     * @param executorTerminated  whether every worker had finished
     */
    public record ShutdownReport(
        int stuckWorkers,
        int quarantineReleased,
        int transferredToKeeper,
        int quarantineHeld,
        boolean executorTerminated
    ) {
        /**
         * Whether there is anything to report
         */
        public boolean clean() {
            return stuckWorkers == 0 && transferredToKeeper == 0 && quarantineHeld == 0 && executorTerminated;
        }
    }

    /** The value of a slot that holds no connection */
    private static final class Sentinel {
        private final String name;

        private Sentinel(@NotNull String name) {
            this.name = name;
        }

        @NotNull
        @Override
        public String toString() {
            return name;
        }
    }

    private static final Sentinel FREE = new Sentinel("FREE");
    private static final Sentinel RESERVED = new Sentinel("RESERVED");
    /** Taken by {@code finishClose} or a late disposal while it decides where the connection goes */
    private static final Sentinel CLAIMED = new Sentinel("CLAIMED");
    /** The quarantined connection was released at shutdown */
    private static final Sentinel RELEASED = new Sentinel("RELEASED");
    /** The connection is in the keeper */
    private static final Sentinel KEPT = new Sentinel("KEPT");

    private final long serial;
    private final MetadataConnectionSource raw;
    private final Tuning tuning;
    private final ThreadPoolExecutor executor;
    /** Each value is a {@link Sentinel} or a quarantined connection */
    private final AtomicReferenceArray<Object> slots = new AtomicReferenceArray<>(CAPACITY);
    /** This instance's part of the keeper; the keeper holds the same array */
    private final AtomicReferenceArray<Object> keeperShare;
    private final AtomicReference<Health> health = new AtomicReference<>(Health.OPEN);
    private final AtomicInteger quarantined = new AtomicInteger();
    private final AtomicInteger running = new AtomicInteger();
    private final AtomicLong submitted = new AtomicLong();
    private final AtomicBoolean finishing = new AtomicBoolean();
    private final Map<LeaseState, AtomicLong> disposals = new ConcurrentHashMap<>();
    @Nullable
    private volatile ShutdownReport lastReport;

    private BoundedMetadataConnections(@NotNull MetadataConnectionSource raw, @NotNull Tuning tuning) {
        this.serial = SERIALS.incrementAndGet();
        this.raw = raw;
        this.tuning = tuning;
        for (int i = 0; i < CAPACITY; i++) {
            slots.set(i, FREE);
        }
        for (LeaseState end : LeaseState.values()) {
            if (end.isTerminal()) {
                disposals.put(end, new AtomicLong());
            }
        }
        AtomicInteger threads = new AtomicInteger();
        this.executor = new ThreadPoolExecutor(
            WORKERS, WORKERS, tuning.keepAlive().toNanos(), TimeUnit.NANOSECONDS,
            new ArrayBlockingQueue<>(CAPACITY),
            runnable -> {
                Thread thread = new Thread(runnable, THREAD_PREFIX + serial + "-" + threads.incrementAndGet());
                thread.setDaemon(true);
                return thread;
            },
            new ThreadPoolExecutor.AbortPolicy());
        this.executor.allowCoreThreadTimeOut(true);
        this.keeperShare = RESIDUALS.register(serial);
    }

    /**
     * Wraps {@code raw} with the production timings
     */
    @NotNull
    public static Owned create(@NotNull MetadataConnectionSource raw) {
        return create(raw, Tuning.PRODUCTION);
    }

    /**
     * Wraps {@code raw}; the caller owns both halves of what comes back, and must keep the shutdown
     */
    @NotNull
    public static Owned create(@NotNull MetadataConnectionSource raw, @NotNull Tuning tuning) {
        if (raw == null || tuning == null) {
            throw new IllegalArgumentException("A metadata connection source and its tuning are required");
        }
        BoundedMetadataConnections leases = new BoundedMetadataConnections(raw, tuning);
        return new Owned(leases, leases.new Closer());
    }

    // ---------------------------------------------------------------- borrowing

    /**
     * Borrows one connection, waiting for it no longer than the budget allows
     * <p>
     * Refused at once, with nothing submitted, when the source is not open, the budget is already
     * spent or no slot is free.
     */
    @NotNull
    @Override
    public MetadataLease open(@NotNull MetadataBudget budget, @NotNull MetadataPurpose purpose) throws MetadataUnavailableException {
        if (budget == null || purpose == null) {
            throw new IllegalArgumentException("A metadata budget and purpose are required");
        }
        refuseUnlessOpen();
        if (remainingNanos(budget) <= 0) {
            throw new MetadataUnavailableException(MetadataUnavailableException.Reason.BUDGET_EXHAUSTED);
        }
        int slot = reserve();
        if (slot < 0) {
            throw new MetadataUnavailableException(MetadataUnavailableException.Reason.CAPACITY);
        }
        Borrow borrow;
        try {
            borrow = new Borrow(slot, budget, purpose);
        } catch (RuntimeException | Error e) {
            freeSlot(slot);
            throw e;
        }
        Health now = health.get();
        if (now != Health.OPEN) {
            // beginClose ran between the first look and the reservation.
            freeSlot(slot);
            throw new MetadataUnavailableException(now == Health.REFUSING
                ? MetadataUnavailableException.Reason.REFUSING
                : MetadataUnavailableException.Reason.CLOSED);
        }
        try {
            executor.execute(borrow);
            submitted.incrementAndGet();
        } catch (RuntimeException | Error e) {
            if (borrow.state.compareAndSet(State.PENDING, State.ABANDONED)) {
                freeSlot(slot);
                if (e instanceof RejectedExecutionException) {
                    throw new MetadataUnavailableException(MetadataUnavailableException.Reason.REJECTED);
                }
                throw e;
            }
            // The task was taken after all; wait for it like any other.
        }
        return borrow.await(budget);
    }

    private void refuseUnlessOpen() throws MetadataUnavailableException {
        Health now = health.get();
        if (now == Health.REFUSING) {
            throw new MetadataUnavailableException(MetadataUnavailableException.Reason.REFUSING);
        }
        if (now != Health.OPEN) {
            throw new MetadataUnavailableException(MetadataUnavailableException.Reason.CLOSED);
        }
    }

    /**
     * What is left of the budget; a budget clock that fails leaves nothing, so a lease is never stranded by it
     */
    private static long remainingNanos(@NotNull MetadataBudget budget) {
        try {
            return budget.remainingNanos();
        } catch (RuntimeException e) {
            return -1;
        }
    }

    private int reserve() {
        for (int i = 0; i < CAPACITY; i++) {
            if (slots.compareAndSet(i, FREE, RESERVED)) {
                return i;
            }
        }
        return -1;
    }

    /** A slot whose borrow ended without a connection to keep */
    void freeSlot(int slot) {
        if (!slots.compareAndSet(slot, RESERVED, FREE)) {
            logEvent(EVENT_SLOT_TRIPWIRE, null, null, "slot", slot, null, 0);
        }
        if (health.get() == Health.CLOSED) {
            releaseKeeperShareIfIdle();
        }
    }

    /**
     * Keeps a connection that could be neither closed nor aborted
     * <p>
     * Before shutdown it stays in its own slot, which was reserved for it, so nothing is allocated and
     * nothing can fail on the way. After shutdown it goes to the keeper. A disposal that read the
     * source as still closing but lands after {@code finishClose} has passed its slot moves it to the
     * keeper itself, so no connection is left only in this object.
     */
    @NotNull
    LeaseState retain(int slot, @NotNull Connection connection, @NotNull MetadataLease.DisposalCause cause) {
        if (health.get() == Health.CLOSED) {
            return keep(slot, connection, RESERVED, cause);
        }
        probe(ProbePoint.DISPOSAL_RETAINING);
        if (!slots.compareAndSet(slot, RESERVED, connection)) {
            logEvent(EVENT_SLOT_TRIPWIRE, null, null, "slot", slot, null, 0);
            return keep(slot, connection, slots.get(slot), cause);
        }
        int held = quarantined.incrementAndGet();
        boolean refusing = held == CAPACITY && health.compareAndSet(Health.OPEN, Health.REFUSING);
        logEvent(EVENT_QUARANTINED, null, cause.name(), "quarantined", held, null, 0);
        if (refusing) {
            logEvent(EVENT_REFUSING, null, null, "quarantined", held, null, 0);
        }
        probe(ProbePoint.DISPOSAL_QUARANTINED);
        if (health.get() == Health.CLOSED && slots.compareAndSet(slot, connection, CLAIMED)) {
            quarantined.decrementAndGet();
            return keep(slot, connection, CLAIMED, cause);
        }
        return LeaseState.QUARANTINED;
    }

    @NotNull
    private LeaseState keep(
        int slot,
        @NotNull Connection connection,
        @Nullable Object expected,
        @NotNull MetadataLease.DisposalCause cause
    ) {
        keeperShare.set(slot, connection);
        if (!slots.compareAndSet(slot, expected, KEPT)) {
            slots.set(slot, KEPT);
        }
        logEvent(EVENT_RESIDUAL, null, cause.name(), "instance", serial, "kept", residualHeld());
        return LeaseState.RESIDUAL;
    }

    void disposed(@NotNull LeaseState end) {
        AtomicLong count = disposals.get(end);
        if (count != null) {
            count.incrementAndGet();
        }
    }

    // ---------------------------------------------------------------- what a test or a report can read

    /**
     * This instance's number, which is also part of its worker thread names
     */
    public long serial() {
        return serial;
    }

    /**
     * Where the source is
     */
    @NotNull
    public Health health() {
        return health.get();
    }

    /**
     * Slots no borrow holds
     */
    public int availableSlots() {
        int free = 0;
        for (int i = 0; i < CAPACITY; i++) {
            if (slots.get(i) == FREE) {
                free++;
            }
        }
        return free;
    }

    /**
     * Connections held in their slots because they could not be released
     */
    public int quarantined() {
        return quarantined.get();
    }

    /**
     * This instance's connections in the process-lifetime keeper
     */
    public int residualHeld() {
        return ProcessResidualKeeper.count(keeperShare);
    }

    /**
     * Workers inside a borrow right now
     */
    public int runningWorkers() {
        return running.get();
    }

    /**
     * Borrows handed to the executor, ever
     */
    public long submittedTasks() {
        return submitted.get();
    }

    /**
     * Leases that ended in {@code end}, ever
     */
    public long disposedAs(@NotNull LeaseState end) {
        AtomicLong count = disposals.get(end);
        return count == null ? 0 : count.get();
    }

    /**
     * What the last {@code finishClose} found, or null before it ran
     */
    @Nullable
    public ShutdownReport lastShutdownReport() {
        return lastReport;
    }

    /**
     * Connections in the keeper, across every instance in this process
     */
    public static int processResidualCount() {
        return RESIDUALS.total();
    }

    /**
     * Instances whose keeper share is still registered: open ones, and closed ones holding a residual or a borrow
     */
    public static int registeredKeeperShares() {
        return RESIDUALS.registered();
    }

    // ---------------------------------------------------------------- shutdown

    /** The capability {@link #create} hands out; only its holder can close this source */
    private final class Closer implements Shutdown {
        @Override
        public void beginClose() {
            tuning.probe().at(ProbePoint.BEGIN_CLOSE);
            moveToClosing();
        }

        @Override
        public void finishClose() {
            tuning.probe().at(ProbePoint.FINISH_CLOSE);
            finish();
        }
    }

    private void moveToClosing() {
        while (true) {
            Health now = health.get();
            if (now == Health.CLOSING || now == Health.CLOSED) {
                break;
            }
            if (health.compareAndSet(now, Health.CLOSING)) {
                break;
            }
        }
        executor.shutdown();
    }

    private void finish() {
        if (!finishing.compareAndSet(false, true)) {
            return;
        }
        // Whatever beginClose did or did not get to, no new borrow starts from here.
        moveToClosing();
        boolean interrupted = false;
        boolean terminated;
        try {
            terminated = executor.awaitTermination(tuning.finishWait().toNanos(), TimeUnit.NANOSECONDS);
        } catch (InterruptedException e) {
            interrupted = true;
            terminated = executor.isTerminated();
        }
        health.set(Health.CLOSED);
        int released = 0;
        int transferred = 0;
        for (int i = 0; i < CAPACITY; i++) {
            Object value = slots.get(i);
            if (value instanceof Sentinel || value == null || !slots.compareAndSet(i, value, CLAIMED)) {
                continue;
            }
            quarantined.decrementAndGet();
            Connection connection = (Connection) value;
            boolean closed = false;
            try {
                // Closed only after an abort that is seen to have closed it; anything less could hand it to a pool.
                connection.abort(Runnable::run);
                if (connection.isClosed()) {
                    connection.close();
                    closed = true;
                } else {
                    logEvent(EVENT_QUARANTINE_RELEASE_FAILED, null, "ABORT_UNCONFIRMED", null, 0, null, 0);
                }
            } catch (Throwable t) {
                logEvent(EVENT_QUARANTINE_RELEASE_FAILED, t, null, null, 0, null, 0);
            } finally {
                if (closed) {
                    slots.set(i, RELEASED);
                    released++;
                } else {
                    keeperShare.set(i, connection);
                    slots.set(i, KEPT);
                    transferred++;
                }
            }
        }
        ShutdownReport report = new ShutdownReport(running.get(), released, transferred, quarantinedInSlots(), terminated);
        lastReport = report;
        if (!report.clean() || released > 0) {
            logReport(report);
        }
        probe(ProbePoint.FINISH_SCANNED);
        releaseKeeperShareIfIdle();
        if (interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    /** Quarantined connections still in their slots, counted from the slots themselves */
    private int quarantinedInSlots() {
        int held = 0;
        for (int i = 0; i < CAPACITY; i++) {
            if (!(slots.get(i) instanceof Sentinel)) {
                held++;
            }
        }
        return held;
    }

    /**
     * Drops this instance's keeper registration once nothing can reach the keeper through it any more
     * <p>
     * Only settled slots - free, released, kept - count as idle. A slot still reserved, claimed, or
     * holding a connection a disposal has just quarantined may yet send that connection to the keeper,
     * so the registration stays.
     */
    private void releaseKeeperShareIfIdle() {
        for (int i = 0; i < CAPACITY; i++) {
            Object value = slots.get(i);
            if (value != FREE && value != RELEASED && value != KEPT) {
                return;
            }
        }
        RESIDUALS.releaseIfEmpty(serial, keeperShare);
    }

    // ---------------------------------------------------------------- one borrow

    /** How a borrow ended; published once, as a whole */
    private sealed interface Completion permits State, Delivered, Failed {
    }

    /** The completions that carry nothing */
    private enum State implements Completion {
        PENDING,
        RUNNING,
        ABANDONED
    }

    /** The worker has the connection, inside the lease the caller receives */
    private record Delivered(@NotNull MetadataLease lease) implements Completion {
    }

    /** Opening the connection failed; only the failure's class name is kept */
    private record Failed(@NotNull String failureClass) implements Completion {
        private static final Failed UNKNOWN = new Failed(Throwable.class.getName());

        @NotNull
        static Failed of(@NotNull Throwable failure) {
            try {
                return new Failed(failure.getClass().getName());
            } catch (Throwable t) {
                return UNKNOWN;
            }
        }
    }

    private final class Borrow implements Runnable {
        private final int slot;
        private final MetadataLease lease;
        private final Delivered delivered;
        private final AtomicReference<Completion> state = new AtomicReference<>(State.PENDING);
        /** Only shortens the caller's wait; what it sees comes from {@code state} */
        private final CountDownLatch signal = new CountDownLatch(1);

        private Borrow(int slot, @NotNull MetadataBudget budget, @NotNull MetadataPurpose purpose) {
            this.slot = slot;
            // Made before the borrow, so nothing has to be allocated between getting the connection and handing it over.
            this.lease = new MetadataLease(BoundedMetadataConnections.this, slot, budget, purpose);
            this.delivered = new Delivered(lease);
        }

        @Override
        public void run() {
            probe(ProbePoint.WORKER_CLAIMING);
            if (!state.compareAndSet(State.PENDING, State.RUNNING)) {
                // Given up before it started: the caller has already freed the slot.
                return;
            }
            running.incrementAndGet();
            try {
                probe(ProbePoint.WORKER_STARTED);
                Connection connection;
                try {
                    connection = raw.openConnection();
                    if (connection == null) {
                        throw new IllegalStateException("The metadata connection source returned no connection");
                    }
                } catch (Throwable t) {
                    logEvent(EVENT_BORROW_FAILED, t, null, null, 0, null, 0);
                    // No connection: the slot is the worker's to free, whoever won the completion.
                    freeSlot(slot);
                    state.compareAndSet(State.RUNNING, Failed.of(t));
                    signal.countDown();
                    return;
                }
                lease.attach(connection);
                probe(ProbePoint.WORKER_BORROWED);
                if (state.compareAndSet(State.RUNNING, delivered)) {
                    probe(ProbePoint.WORKER_PUBLISHED);
                    signal.countDown();
                } else {
                    // The caller gave up first; this worker owns the connection.
                    lease.disposeLate(MetadataLease.DisposalCause.LATE);
                }
            } finally {
                running.decrementAndGet();
            }
        }

        /**
         * Waits for the borrow; whatever happens, including an {@code Error}, the borrow ends with an owner
         */
        @NotNull
        private MetadataLease await(@NotNull MetadataBudget budget) throws MetadataUnavailableException {
            try {
                return awaitOwned(budget);
            } catch (Error e) {
                settleAfterError();
                throw e;
            }
        }

        /**
         * After an {@code Error} in the wait: a delivered lease is disposed, a borrow still in flight is given up
         * <p>
         * Disposal is idempotent, so a lease the wait had already disposed is left as it is.
         */
        private void settleAfterError() {
            while (true) {
                Completion seen = state.get();
                if (seen instanceof Delivered done) {
                    done.lease().disposeLate(MetadataLease.DisposalCause.OVER_BUDGET);
                    return;
                }
                if (seen instanceof Failed || seen == State.ABANDONED) {
                    return;
                }
                if (state.compareAndSet(seen, State.ABANDONED)) {
                    if (seen == State.PENDING) {
                        freeSlot(slot);
                    }
                    return;
                }
            }
        }

        @NotNull
        private MetadataLease awaitOwned(@NotNull MetadataBudget budget) throws MetadataUnavailableException {
            boolean interrupted = false;
            try {
                long wait = remainingNanos(budget);
                if (wait > 0) {
                    signal.await(wait, TimeUnit.NANOSECONDS);
                }
            } catch (InterruptedException e) {
                interrupted = true;
            }
            probe(ProbePoint.CALLER_WAITED);
            Completion seen;
            while (true) {
                seen = state.get();
                if (seen instanceof Delivered || seen instanceof Failed) {
                    break;
                }
                if (state.compareAndSet(seen, State.ABANDONED)) {
                    if (seen == State.PENDING) {
                        // The worker will never start it, so the slot is the caller's to free.
                        freeSlot(slot);
                    }
                    restoreInterrupt(interrupted);
                    throw new MetadataUnavailableException(interrupted
                        ? MetadataUnavailableException.Reason.INTERRUPTED
                        : MetadataUnavailableException.Reason.TIMEOUT);
                }
            }
            if (seen instanceof Failed failed) {
                restoreInterrupt(interrupted);
                throw new MetadataUnavailableException(MetadataUnavailableException.Reason.BORROW_FAILED, failed.failureClass());
            }
            MetadataLease received = ((Delivered) seen).lease();
            if (interrupted || remainingNanos(budget) <= 0) {
                received.disposeLate(interrupted
                    ? MetadataLease.DisposalCause.INTERRUPTED_LATE
                    : MetadataLease.DisposalCause.OVER_BUDGET);
                restoreInterrupt(interrupted);
                throw new MetadataUnavailableException(interrupted
                    ? MetadataUnavailableException.Reason.INTERRUPTED
                    : MetadataUnavailableException.Reason.TIMEOUT);
            }
            return received;
        }
    }

    private static void restoreInterrupt(boolean interrupted) {
        if (interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    /** A probe that throws on a worker or caller path is ignored; only the close points let it through */
    private void probe(@NotNull ProbePoint point) {
        try {
            tuning.probe().at(point);
        } catch (Throwable ignored) {
            // Deliberately nothing: a test seam must not change who owns a connection.
        }
    }

    /**
     * Logs by event code, a new correlation id, the exception class, an enum name and up to two numbers - never a message or a trace
     * <p>
     * Every argument is a constant, a name the JVM already holds or a primitive, so nothing is built before
     * the {@code try}: a disposal that runs out of memory here still completes.
     */
    private static void logEvent(
        @NotNull String eventCode,
        @Nullable Throwable failure,
        @Nullable String detail,
        @Nullable String firstName,
        long firstValue,
        @Nullable String secondName,
        long secondValue
    ) {
        try {
            log.error("DBAC metadata connections [event=" + eventCode
                + " EVENT_ID=" + UUID.randomUUID()
                + (failure == null ? "" : " exception=" + failure.getClass().getName())
                + (detail == null ? "" : " detail=" + detail)
                + (firstName == null ? "" : " " + firstName + "=" + firstValue)
                + (secondName == null ? "" : " " + secondName + "=" + secondValue) + "]");
        } catch (Throwable ignored) {
            // Deliberately nothing: borrowing and disposal must not depend on whether they could be logged.
        }
    }

    /**
     * Logs what finishClose found, in numbers only
     */
    private void logReport(@NotNull ShutdownReport report) {
        try {
            log.error("DBAC metadata connections [event=" + EVENT_SHUTDOWN_REPORT
                + " EVENT_ID=" + UUID.randomUUID()
                + " instance=" + serial
                + " stuckWorkers=" + report.stuckWorkers()
                + " quarantineReleased=" + report.quarantineReleased()
                + " transferredToKeeper=" + report.transferredToKeeper()
                + " quarantineHeld=" + report.quarantineHeld()
                + " executorTerminated=" + report.executorTerminated() + "]");
        } catch (Throwable ignored) {
            // Deliberately nothing: shutdown must not depend on whether it could be logged.
        }
    }

    // ---------------------------------------------------------------- the keeper

    /**
     * Connections that outlived their source's shutdown, held until the process ends
     * <p>
     * Each instance registers a fixed array of {@link #CAPACITY} places when it is created, so moving a
     * connection here allocates nothing, and the static map keeps the array reachable after the
     * instance itself is gone. There is no way to take a connection back out.
     */
    private static final class ProcessResidualKeeper {
        private final Map<Long, AtomicReferenceArray<Object>> shares = new ConcurrentHashMap<>();

        @NotNull
        AtomicReferenceArray<Object> register(long serial) {
            AtomicReferenceArray<Object> share = new AtomicReferenceArray<>(CAPACITY);
            shares.put(serial, share);
            return share;
        }

        void releaseIfEmpty(long serial, @NotNull AtomicReferenceArray<Object> share) {
            if (count(share) == 0) {
                shares.remove(serial, share);
            }
        }

        static int count(@NotNull AtomicReferenceArray<Object> share) {
            int held = 0;
            for (int i = 0; i < share.length(); i++) {
                if (share.get(i) != null) {
                    held++;
                }
            }
            return held;
        }

        int total() {
            int held = 0;
            for (AtomicReferenceArray<Object> share : shares.values()) {
                held += count(share);
            }
            return held;
        }

        int registered() {
            return shares.size();
        }
    }
}
