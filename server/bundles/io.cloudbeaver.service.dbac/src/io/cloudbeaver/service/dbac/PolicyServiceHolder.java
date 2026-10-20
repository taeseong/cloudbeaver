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
package io.cloudbeaver.service.dbac;

import io.cloudbeaver.service.dbac.db.DbacCBDatabase;
import io.cloudbeaver.service.dbac.policy.DbAccessPolicyService;
import io.cloudbeaver.service.dbac.policy.enforcement.DeploymentGuard;
import io.cloudbeaver.service.dbac.policy.enforcement.TaintContextCloseHandler;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.jkiss.dbeaver.Log;
import org.jkiss.dbeaver.model.qm.QMExecutionHandler;

import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Owns the lifecycle of the DBAC policy service, from the creation of the metadata database to its shutdown
 * <p>
 * The state is one of seven, held in an {@link AtomicReference} and changed only by compare-and-set:
 * <pre>
 * New --beginInit--&gt; Initializing --+-- super failed / admission Error --&gt; StartupFailed
 *                                    +-- guard refused / service or handler failed --&gt; Failed(db, code, NONE)
 *                                    +-- ready --&gt; Ready(db, service, admission, plan)
 * Ready --revoke--&gt; Failed(db, code, same plan)
 * Ready | Failed --shutdown, CAS winner--&gt; Stopping(db, same plan) --finally--&gt; Disposed
 * </pre>
 * Nothing returns to {@code New}, so a second initialization is always refused, and the only way
 * into {@code Ready} is the one compare-and-set in {@link #ready}.
 * <p>
 * <b>Who can change it.</b> The holder has no public mutator. Its transitions are package-private
 * and called only by {@link DbacSecurityControllerFactory}, which lives in this package. Code in
 * other packages receives, per initialization, two capabilities and nothing else: the metadata
 * database gets a {@link DbacCBDatabase.ShutdownLifecycle} that can only stop that initialization,
 * and the deployment guard gets a {@link DeploymentGuard.Revocation} that can only move that
 * initialization from ready to failed. Both are created with the {@link Initializing} token and
 * there is no way to obtain them again.
 * <p>
 * <b>Cleanup.</b> {@code Ready} owns an immutable {@link CleanupPlan}: unregister the close handler,
 * clear the taint sink, release the advisory lock lease. The same plan instance moves to
 * {@code Failed} on revocation and to {@code Stopping} on shutdown, and only the shutdown that wins
 * the compare-and-set into {@code Stopping} runs it, so it runs exactly once. What an initialization
 * acquired before it could publish {@code Ready} is released by the factory at once, through the
 * same plan type, and {@code Failed} then carries {@link CleanupPlan#NONE}. The pool is closed once
 * per initialization, after the plan, by that same winner - or, when nothing was published, by the
 * first shutdown of the unpublished database; a shutdown arriving while another one is stopping
 * waits for it to finish and closes nothing (C16).
 * <p>
 * <b>Failures while cleaning up (C15).</b> Every step is attempted. A {@code RuntimeException} is
 * logged and suppressed; an {@code Error} is logged and the first one is handed back, to be rethrown
 * only once the state is terminal. Logs carry a fixed event code, a correlation id that is new for
 * each event and the exception class - never a message or a stack trace.
 */
public final class PolicyServiceHolder {

    /**
     * Why the policy service is not ready
     */
    public enum FailureCode {
        DATABASE_INIT_FAILED,
        DEPLOYMENT_NOT_ACKNOWLEDGED,
        DEPLOYMENT_PROPERTY_CHANGED,
        TEST_MODE_WITHOUT_TEST_BUNDLE,
        MULTI_NODE_DECLARED,
        METADATA_ENGINE_UNSUPPORTED,
        H2_URL_REMAPPED,
        H2_URL_UNSUPPORTED,
        H2_IN_MEMORY,
        H2_REMOTE,
        H2_NETWORK_PATH,
        H2_SUBPROTOCOL_UNSUPPORTED,
        H2_SETTING_UNSUPPORTED,
        H2_FILE_LOCK_UNSUPPORTED,
        POOL_TOO_SMALL,
        ADVISORY_LOCK_HELD,
        ADVISORY_LOCK_UNAVAILABLE,
        ADVISORY_LOCK_LOST,
        DEPLOYMENT_CHECK_FAILED,
        SERVICE_UNAVAILABLE,
        QM_HANDLER_UNAVAILABLE
    }

    /**
     * Sees every lifecycle transition, after it happened
     * <p>
     * Called once per successful compare-and-set, on the thread that made it. What it does cannot
     * undo the transition, and if it fails that is logged and ignored. It must not shut down the
     * database it observes: called inside the transition to {@code Stopping}, that shutdown would
     * wait for the very call that is running it. The global holder's observer is {@link #NONE} and
     * cannot be changed.
     */
    @FunctionalInterface
    public interface TransitionObserver {
        /** Sees nothing; the global holder's observer */
        TransitionObserver NONE = (from, to) -> {
        };

        /**
         * The holder moved from {@code from} to {@code to}
         */
        void transitioned(@NotNull State from, @NotNull State to);
    }

    /**
     * One lifecycle state
     * <p>
     * Every state class has non-public constructors, so a state cannot be made outside the holder.
     */
    public sealed interface State permits New, Initializing, Ready, Failed, StartupFailed, Stopping, Disposed {
    }

    /**
     * Nothing has been tried yet
     */
    public static final class New implements State {
        static final New INSTANCE = new New();

        private New() {
        }

        @NotNull
        @Override
        public String toString() {
            return "New";
        }
    }

    /**
     * The token of the one initialization in progress
     * <p>
     * Not a record: it is compared by identity, and the database it created is recorded in it while
     * the initialization runs. The two capabilities are made here, once per initialization, and are
     * only reachable from this package.
     */
    public static final class Initializing implements State {
        final Thread owner;
        final AtomicReference<DbacCBDatabase> created = new AtomicReference<>();
        final DbacCBDatabase.ShutdownLifecycle shutdownLifecycle;
        final DeploymentGuard.Revocation revocation;

        Initializing(@NotNull PolicyServiceHolder holder, @NotNull Thread owner) {
            this.owner = owner;
            this.shutdownLifecycle = new HolderShutdownLifecycle(holder, this);
            this.revocation = new HolderRevocation(holder, this);
        }

        @NotNull
        @Override
        public String toString() {
            return "Initializing";
        }
    }

    /**
     * The policy service is running
     */
    public static final class Ready implements State {
        final Initializing token;
        private final DbacCBDatabase database;
        private final DbAccessPolicyService service;
        private final DeploymentGuard.Admission admission;
        final CleanupPlan plan;

        Ready(
            @NotNull Initializing token,
            @NotNull DbacCBDatabase database,
            @NotNull DbAccessPolicyService service,
            @NotNull DeploymentGuard.Admission admission,
            @NotNull CleanupPlan plan
        ) {
            this.token = token;
            this.database = database;
            this.service = service;
            this.admission = admission;
            this.plan = plan;
        }

        /**
         * The metadata database
         */
        @NotNull
        public DbacCBDatabase database() {
            return database;
        }

        /**
         * The policy service
         */
        @NotNull
        public DbAccessPolicyService service() {
            return service;
        }

        /**
         * What the deployment guard admitted, to be checked again on every enforcement entry
         */
        @NotNull
        public DeploymentGuard.Admission admission() {
            return admission;
        }

        @NotNull
        @Override
        public String toString() {
            return "Ready";
        }
    }

    /**
     * The database is up, the policy service is not; every write-gated operation is denied
     */
    public static final class Failed implements State {
        final Initializing token;
        private final DbacCBDatabase database;
        private final FailureCode code;
        final CleanupPlan plan;

        Failed(@NotNull Initializing token, @NotNull DbacCBDatabase database, @NotNull FailureCode code, @NotNull CleanupPlan plan) {
            this.token = token;
            this.database = database;
            this.code = code;
            this.plan = plan;
        }

        /**
         * The metadata database, which keeps serving authentication and reads
         */
        @NotNull
        public DbacCBDatabase database() {
            return database;
        }

        /**
         * Why
         */
        @NotNull
        public FailureCode code() {
            return code;
        }

        @NotNull
        @Override
        public String toString() {
            return "Failed(" + code + ")";
        }
    }

    /**
     * The metadata database could not be created; there is no database to hold
     */
    public static final class StartupFailed implements State {
        private final FailureCode code;

        StartupFailed(@NotNull FailureCode code) {
            this.code = code;
        }

        /**
         * Why
         */
        @NotNull
        public FailureCode code() {
            return code;
        }

        @NotNull
        @Override
        public String toString() {
            return "StartupFailed(" + code + ")";
        }
    }

    /**
     * The policy service is being stopped; every write-gated operation is denied
     */
    public static final class Stopping implements State {
        final Initializing token;
        private final DbacCBDatabase database;
        final CleanupPlan plan;

        Stopping(@NotNull Initializing token, @NotNull DbacCBDatabase database, @NotNull CleanupPlan plan) {
            this.token = token;
            this.database = database;
            this.plan = plan;
        }

        /**
         * The metadata database being closed
         */
        @NotNull
        public DbacCBDatabase database() {
            return database;
        }

        @NotNull
        @Override
        public String toString() {
            return "Stopping";
        }
    }

    /**
     * Stopped for good
     */
    public static final class Disposed implements State {
        static final Disposed INSTANCE = new Disposed();

        private Disposed() {
        }

        @NotNull
        @Override
        public String toString() {
            return "Disposed";
        }
    }

    /**
     * What a stopping policy service releases: unregister the close handler, clear the sink, release the lease
     * <p>
     * Immutable, and without any record of having run: it runs exactly once because only the state
     * machine's compare-and-set winner runs it, not because it remembers.
     */
    static final class CleanupPlan {
        static final CleanupPlan NONE = new CleanupPlan(null, null, null, null);

        @Nullable
        private final TaintContextCloseHandler.HandlerRegistrar registrar;
        @Nullable
        private final QMExecutionHandler handler;
        @Nullable
        private final TaintContextCloseHandler.TaintSink sink;
        @Nullable
        private final Runnable leaseRelease;

        private CleanupPlan(
            @Nullable TaintContextCloseHandler.HandlerRegistrar registrar,
            @Nullable QMExecutionHandler handler,
            @Nullable TaintContextCloseHandler.TaintSink sink,
            @Nullable Runnable leaseRelease
        ) {
            this.registrar = registrar;
            this.handler = handler;
            this.sink = sink;
            this.leaseRelease = leaseRelease;
        }

        /**
         * Attempts unregister, clear and release, in that order, and throws nothing
         *
         * @return the first {@code Error} a step threw, already logged, or null
         */
        @Nullable
        Error runAll() {
            Error first = null;
            TaintContextCloseHandler.HandlerRegistrar unregisterFrom = registrar;
            QMExecutionHandler registered = handler;
            if (unregisterFrom != null && registered != null) {
                first = attempt(EVENT_HANDLER_UNREGISTER_FAILED, () -> unregisterFrom.unregister(registered), first);
            }
            if (sink != null) {
                first = attempt(EVENT_SINK_CLEAR_FAILED, sink::clear, first);
            }
            if (leaseRelease != null) {
                first = attempt(EVENT_LEASE_RELEASE_FAILED, leaseRelease, first);
            }
            return first;
        }

        @NotNull
        static Builder builder() {
            return new Builder();
        }

        /**
         * Collects what an initialization has acquired so far
         */
        static final class Builder {
            @Nullable
            private TaintContextCloseHandler.HandlerRegistrar registrar;
            @Nullable
            private QMExecutionHandler handler;
            @Nullable
            private TaintContextCloseHandler.TaintSink sink;
            @Nullable
            private Runnable leaseRelease;

            /**
             * Records the handler before its registration is attempted, so a failed registration is still undone
             */
            void handler(
                @NotNull TaintContextCloseHandler.HandlerRegistrar registrar,
                @NotNull QMExecutionHandler handler,
                @NotNull TaintContextCloseHandler.TaintSink sink
            ) {
                this.registrar = registrar;
                this.handler = handler;
                this.sink = sink;
            }

            void lease(@NotNull Runnable release) {
                this.leaseRelease = release;
            }

            @NotNull
            CleanupPlan seal() {
                return new CleanupPlan(registrar, handler, sink, leaseRelease);
            }
        }
    }

    /** Logged when unregistering the close handler failed */
    static final String EVENT_HANDLER_UNREGISTER_FAILED = "DBAC_LIFECYCLE_HANDLER_UNREGISTER_FAILED";
    /** Logged when clearing the taint sink failed */
    static final String EVENT_SINK_CLEAR_FAILED = "DBAC_LIFECYCLE_SINK_CLEAR_FAILED";
    /** Logged when releasing the advisory lock lease failed */
    static final String EVENT_LEASE_RELEASE_FAILED = "DBAC_LIFECYCLE_LEASE_RELEASE_FAILED";
    /** Logged when closing the metadata database pool failed */
    static final String EVENT_DATABASE_CLOSE_FAILED = "DBAC_LIFECYCLE_DATABASE_CLOSE_FAILED";
    /** Logged when the guard, the service or the close handler failed while the service was starting */
    static final String EVENT_ADMISSION_FAILED = "DBAC_LIFECYCLE_ADMISSION_FAILED";
    /** Logged when Ready could not be published although everything it needed was in place */
    static final String EVENT_READY_PUBLISH_FAILED = "DBAC_LIFECYCLE_READY_PUBLISH_FAILED";
    /** Logged when a transition observer failed */
    static final String EVENT_OBSERVER_FAILED = "DBAC_LIFECYCLE_OBSERVER_FAILED";

    private static final Log log = Log.getLog(PolicyServiceHolder.class);

    private static final PolicyServiceHolder GLOBAL = new PolicyServiceHolder(TransitionObserver.NONE);

    private final AtomicReference<State> state = new AtomicReference<>(New.INSTANCE);
    private final TransitionObserver observer;

    PolicyServiceHolder(@NotNull TransitionObserver observer) {
        this.observer = observer;
    }

    /**
     * The holder of the server's policy service
     */
    @NotNull
    public static PolicyServiceHolder global() {
        return GLOBAL;
    }

    /**
     * The current state
     */
    @NotNull
    public State current() {
        return state.get();
    }

    /**
     * Starts the one initialization, or returns null when one was ever started before
     */
    @Nullable
    Initializing beginInit() {
        Initializing token = new Initializing(this, Thread.currentThread());
        return transition(New.INSTANCE, token) ? token : null;
    }

    boolean startupFailed(@NotNull Initializing token, @NotNull FailureCode code) {
        return transition(token, new StartupFailed(code));
    }

    boolean failed(@NotNull Initializing token, @NotNull DbacCBDatabase database, @NotNull FailureCode code) {
        return transition(token, new Failed(token, database, code, CleanupPlan.NONE));
    }

    /**
     * The only way into Ready
     */
    boolean ready(
        @NotNull Initializing token,
        @NotNull DbacCBDatabase database,
        @NotNull DbAccessPolicyService service,
        @NotNull DeploymentGuard.Admission admission,
        @NotNull CleanupPlan plan
    ) {
        if (token.created.get() != database) {
            return false;
        }
        return transition(token, new Ready(token, database, service, admission, plan));
    }

    /**
     * Whether the initialization {@code token} started is ready or failed, which is when closes are reported
     */
    boolean accepting(@NotNull Initializing token) {
        State current = state.get();
        return current instanceof Ready ready && ready.token == token
            || current instanceof Failed failed && failed.token == token;
    }

    private boolean transition(@NotNull State from, @NotNull State to) {
        if (!state.compareAndSet(from, to)) {
            return false;
        }
        try {
            observer.transitioned(from, to);
        } catch (RuntimeException | Error e) {
            logFailure(EVENT_OBSERVER_FAILED, "DBAC lifecycle observer failed", e);
        }
        return true;
    }

    /** Moves the token's Ready state to Failed with the same plan */
    private boolean revoke(@NotNull Initializing token, @NotNull FailureCode code) {
        while (true) {
            State current = state.get();
            if (!(current instanceof Ready ready) || ready.token != token) {
                return false;
            }
            if (transition(ready, new Failed(token, ready.database, code, ready.plan))) {
                return true;
            }
        }
    }

    /**
     * Runs one cleanup step: a {@code RuntimeException} is logged and suppressed, an {@code Error} is logged and kept
     *
     * @return {@code first}, or the step's {@code Error} when {@code first} is null
     */
    @Nullable
    static Error attempt(@NotNull String eventCode, @NotNull Runnable step, @Nullable Error first) {
        try {
            step.run();
        } catch (RuntimeException e) {
            logFailure(eventCode, "DBAC lifecycle cleanup step failed", e);
        } catch (Error e) {
            logFailure(eventCode, "DBAC lifecycle cleanup step failed", e);
            return first == null ? e : first;
        }
        return first;
    }

    /**
     * Records a failure by event code, a new correlation id and the exception class, never its message or trace
     * <p>
     * This never throws: the lifecycle must not depend on whether it could be logged.
     */
    static void logFailure(@NotNull String eventCode, @NotNull String summary, @NotNull Throwable failure) {
        try {
            log.error(summary + " [event=" + eventCode
                + " EVENT_ID=" + UUID.randomUUID()
                + " exception=" + failure.getClass().getName() + "]");
        } catch (RuntimeException | Error ignored) {
            // Deliberately nothing: the lifecycle must not depend on whether it could be logged.
        }
    }

    /**
     * Records an event that has no exception
     */
    static void logEvent(@NotNull String eventCode, @NotNull String summary) {
        try {
            log.error(summary + " [event=" + eventCode + " EVENT_ID=" + UUID.randomUUID() + "]");
        } catch (RuntimeException | Error ignored) {
            // Deliberately nothing: the lifecycle must not depend on whether it could be logged.
        }
    }

    /**
     * Stops one initialization's policy service, then closes its database - the pool exactly once (C15 #9, #10; C16)
     * <p>
     * Which call closes the pool is decided once. If a service was published, it is the shutdown that
     * wins Ready or Failed -&gt; Stopping, after it has run the plan; if none was, it is the first
     * shutdown of the unpublished database - the database closing its own pool after a failed
     * initialize, or the factory closing what a failed startup created. Every other call closes
     * nothing:
     * <ul>
     *     <li>one made while another call is stopping the service waits until that call has run the
     *     plan, closed the pool and published Disposed, so no shutdown returns before the pool is
     *     closed; once Disposed it returns at once;</li>
     *     <li>one made after the unpublished database's close waits for that close to be over.</li>
     * </ul>
     * An interrupt does not cut a wait short; it is restored once the wait is over. Only the call that
     * closes rethrows the first {@code Error}; a call that waited returns normally. While
     * {@code Initializing}, only the initializing thread may shut the database down - it alone can
     * leave that state, so its view of it cannot change under it; another thread's call is refused
     * with an {@code IllegalStateException} and closes nothing.
     */
    private static final class HolderShutdownLifecycle implements DbacCBDatabase.ShutdownLifecycle {
        private final PolicyServiceHolder holder;
        private final Initializing token;
        /** Taken by the one call that closes this initialization's pool, and never given back */
        private final AtomicBoolean poolCloseOwned = new AtomicBoolean();
        /** Released, in a finally, once that call's close attempt is over - whatever the close threw */
        private final CountDownLatch poolClosed = new CountDownLatch(1);
        /** Released, in a finally, once the call that won Stopping has run the plan, closed the pool and published Disposed */
        private final CountDownLatch stopped = new CountDownLatch(1);
        /** The thread running this lifecycle's cleanup or pool close, while it does */
        @Nullable
        private volatile Thread closing;

        private HolderShutdownLifecycle(@NotNull PolicyServiceHolder holder, @NotNull Initializing token) {
            this.holder = holder;
            this.token = token;
        }

        @Override
        public void shutdown(@NotNull Runnable closeDatabase) {
            if (closing == Thread.currentThread()) {
                // Called again from inside its own cleanup or close: the call already running finishes the job,
                // and waiting here would wait for itself.
                return;
            }
            // Every decision is taken on one snapshot of the state, so it cannot change between the look and the act.
            State current;
            Stopping stopping;
            do {
                current = holder.current();
                stopping = stoppingOf(current);
            } while (stopping != null && !holder.transition(current, stopping));
            if (stopping != null) {
                stopAndClose(stopping, closeDatabase);
                return;
            }
            if (current instanceof Stopping || current instanceof Disposed) {
                // Another call won Stopping: it owns the cleanup and the pool close.
                awaitUninterruptibly(stopped);
                return;
            }
            if (current == token && Thread.currentThread() != token.owner) {
                // Only the initializing thread can leave Initializing, so only its view of it holds while it closes;
                // any other thread would close a pool that might be published the next moment.
                throw new IllegalStateException("DBAC metadata database is still being initialized by another thread");
            }
            // No service was published: the first call closes the pool, a later one waits for that close.
            if (!poolCloseOwned.compareAndSet(false, true)) {
                awaitUninterruptibly(poolClosed);
                return;
            }
            Error error;
            closing = Thread.currentThread();
            try {
                error = closePool(closeDatabase, null);
            } finally {
                closing = null;
            }
            if (error != null) {
                throw error;
            }
        }

        /** The Stopping that replaces {@code current} when it is this token's Ready or Failed, with the same plan; else null */
        @Nullable
        private Stopping stoppingOf(@NotNull State current) {
            if (current instanceof Ready ready && ready.token == token) {
                return new Stopping(token, ready.database, ready.plan);
            }
            if (current instanceof Failed failed && failed.token == token) {
                return new Stopping(token, failed.database, failed.plan);
            }
            return null;
        }

        /** The Stopping winner: the plan, then the pool close, then Disposed, then the waiters are released */
        private void stopAndClose(@NotNull Stopping stopping, @NotNull Runnable closeDatabase) {
            Error first = null;
            closing = Thread.currentThread();
            try {
                first = stopping.plan.runAll();
                if (poolCloseOwned.compareAndSet(false, true)) {
                    first = closePool(closeDatabase, first);
                } else {
                    // The pool was closed before a service was published; that close is over or about to be.
                    awaitUninterruptibly(poolClosed);
                }
            } finally {
                try {
                    holder.transition(stopping, Disposed.INSTANCE);
                } finally {
                    closing = null;
                    stopped.countDown();
                }
            }
            if (first != null) {
                throw first;
            }
        }

        /** The one pool close; whoever waits for it is released whatever the close threw (C16 #18) */
        @Nullable
        private Error closePool(@NotNull Runnable closeDatabase, @Nullable Error first) {
            try {
                return attempt(EVENT_DATABASE_CLOSE_FAILED, closeDatabase, first);
            } finally {
                poolClosed.countDown();
            }
        }

        /** Waits until {@code latch} is released; an interrupt does not end the wait and is restored afterwards */
        private static void awaitUninterruptibly(@NotNull CountDownLatch latch) {
            boolean interrupted = false;
            boolean released = false;
            while (!released) {
                try {
                    latch.await();
                    released = true;
                } catch (InterruptedException e) {
                    interrupted = true;
                }
            }
            if (interrupted) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /**
     * Fails one initialization's ready policy service, and nothing else
     */
    private static final class HolderRevocation implements DeploymentGuard.Revocation {
        private final PolicyServiceHolder holder;
        private final Initializing token;

        private HolderRevocation(@NotNull PolicyServiceHolder holder, @NotNull Initializing token) {
            this.holder = holder;
            this.token = token;
        }

        @Override
        public boolean revoke(@NotNull FailureCode code) {
            return holder.revoke(token, code);
        }
    }
}
