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
package io.cloudbeaver.service.dbac.policy.enforcement;

import io.cloudbeaver.service.dbac.PolicyServiceHolder;
import io.cloudbeaver.service.dbac.policy.AuthorizationAuditPayload;
import io.cloudbeaver.service.dbac.policy.AuthorizationDecision;
import io.cloudbeaver.service.dbac.policy.DbAccessDecision;
import io.cloudbeaver.service.dbac.policy.DbAccessKey;
import io.cloudbeaver.service.dbac.policy.DbAccessPolicyService;
import io.cloudbeaver.service.dbac.policy.DenialReason;
import io.cloudbeaver.service.dbac.policy.MetadataBudget;
import io.cloudbeaver.service.dbac.policy.WriteAuthorizationRequest;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.jkiss.dbeaver.Log;

import java.time.Duration;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * The one place a write-gated operation is decided, recorded and either run or refused
 * <p>
 * <b>Two calls, one attempt.</b> The caller - an entry point that knows the platform - calls
 * {@link #enter()} before it takes the instance and context locks, then {@link Entry#run} once it holds
 * them. Whatever {@code enter()} found, the caller must call {@code run()}: a refusal there still has to
 * roll back a transaction the context already has open, and only {@code run()} does that. The entry
 * says nothing about what {@code enter()} found, so there is no way to answer a write without it.
 * <p>
 * <b>The order inside {@code run()} is fixed.</b> The key is resolved without touching the metadata
 * database; the grant key's read lock is taken, then the user's, each within {@code T_k}; the
 * context's taint state is read; the attempt opens its expiry window, authorizes through it and
 * refuses a decision about any key other than the one it locked; check-1; the audit budget check-1
 * reserved; the {@code WRITE_ALLOWED} row; check-2; the policy service must still be the one
 * {@code enter()} saw; the caller's own final confirmation; and only then the operation, exactly
 * once. The locks are released user first, then grant key, on every way out.
 * <p>
 * <b>Every refusal takes the same way out.</b> Whatever refused - the admission, the key, a lock
 * timeout or interrupt, the taint state, the decision, a check, the audit, the policy service
 * changing, the confirmation - the attempt asks once whether a transaction is open (an exception
 * counts as yes), and if one is, marks the context tainted, rolls back, and records the outcome: clean
 * after a rollback that worked, blocked after severing one that did not. A context that was already
 * blocked stays blocked; only an explicit rollback releases it, and that is not this gate's to do.
 * Then a {@code WRITE_DENIED} row is written when the key is known, and the reason that refused is
 * returned unchanged. An interrupt that ended a lock wait is held back while the rollback and the
 * audit run, and set again before returning.
 * <p>
 * <b>Corrections.</b> Once a {@code WRITE_ALLOWED} row has been attempted, a refusal after it is
 * recorded as a {@code WRITE_DENIED} row of its own, under a new id, for the same key, grant and
 * category - also when the allowed row was reported failed, since it may have committed. After the
 * operation has been called nothing is written: a {@code WRITE_DENIED} row always means the platform
 * was not called.
 * <p>
 * <b>What the gate does not know.</b> No platform type: the context is a {@link ContextRef} and the
 * platform's side of the attempt an {@link Execution} the caller implements. The one production caller is
 * {@code io.cloudbeaver.service.sql.DbacEnforcedExecution}, for the transaction entry points and Explain; the
 * other mutation paths are not wired yet.
 * <p>
 * <b>Failures of its collaborators deny.</b> An exception or {@code Error} - a
 * {@code VirtualMachineError} included - from the admission, the resolver, a lock, the registry, the
 * policy service, its window, the audit writer or any callback but {@code execute()} is logged by class
 * and becomes a refusal, so nothing unexpected runs the operation (accepted risk R28). What
 * {@code execute()} throws reaches the caller unchanged, after the locks are released.
 */
public final class EnforcementGate {

    private static final Log log = Log.getLog(EnforcementGate.class);

    /** Logged when one of the gate's own steps failed */
    static final String EVENT_STEP_FAILED = "DBAC_GATE_STEP_FAILED";
    /** Logged when one of the caller's callbacks failed */
    static final String EVENT_CALLBACK_FAILED = "DBAC_GATE_CALLBACK_FAILED";

    private static final EnforcementGate GLOBAL = new EnforcementGate(
        PolicyServiceHolder.global(), KeyLockSource.of(EnforcementKeyLocks.global()), TransactionTaintRegistry.global());

    private final PolicyServiceHolder holder;
    private final KeyLockSource locks;
    private final TransactionTaintRegistry registry;

    private EnforcementGate(
        @NotNull PolicyServiceHolder holder,
        @NotNull KeyLockSource locks,
        @NotNull TransactionTaintRegistry registry
    ) {
        this.holder = holder;
        this.locks = locks;
        this.registry = registry;
    }

    /**
     * The gate over the server's policy service, the shared key locks and the shared taint registry
     */
    @NotNull
    public static EnforcementGate global() {
        return GLOBAL;
    }

    /**
     * A gate over the given collaborators
     * <p>
     * For tests, which need a lifecycle, locks and a registry of their own. Production uses
     * {@link #global()} only.
     */
    @NotNull
    public static EnforcementGate of(
        @NotNull PolicyServiceHolder holder,
        @NotNull KeyLockSource locks,
        @NotNull TransactionTaintRegistry registry
    ) {
        return new EnforcementGate(
            Objects.requireNonNull(holder, "holder"), Objects.requireNonNull(locks, "locks"),
            Objects.requireNonNull(registry, "registry"));
    }

    /**
     * Starts one attempt, before the caller takes any lock of its own
     * <p>
     * Checks that the policy service is ready, that its deployment is still the one admitted, and that
     * it is still the same service afterwards. Takes no lock and opens no metadata connection; the
     * admission check may use its own. Never throws: anything that fails here makes the entry one that
     * {@code run()} will refuse.
     *
     * @return the entry the caller must run once it holds its locks; never null
     */
    @NotNull
    public Entry enter() {
        return new Entry(this, Thread.currentThread(), admitted());
    }

    @Nullable
    private PolicyServiceHolder.Ready admitted() {
        try {
            if (!(holder.current() instanceof PolicyServiceHolder.Ready ready)) {
                return null;
            }
            if (!ready.admission().assertSingleProcess()) {
                return null;
            }
            return holder.current() == ready ? ready : null;
        } catch (Throwable t) {
            logEvent(EVENT_STEP_FAILED, Step.ADMISSION, t);
            return null;
        }
    }

    /**
     * One attempt, as {@link #enter()} left it
     * <p>
     * Belongs to the thread that entered and runs once. Its only method is {@link #run}; it does not
     * say what {@code enter()} found.
     */
    public static final class Entry {
        private final EnforcementGate gate;
        private final Thread owner;
        @Nullable
        private final PolicyServiceHolder.Ready ready;
        private boolean used;

        private Entry(@NotNull EnforcementGate gate, @NotNull Thread owner, @Nullable PolicyServiceHolder.Ready ready) {
            this.gate = gate;
            this.owner = owner;
            this.ready = ready;
        }

        /**
         * Decides the attempt and runs the operation if, and only if, everything allows it
         * <p>
         * The caller holds its instance and context locks throughout. When this returns, the gate's own
         * locks are released.
         *
         * @return {@link Executed} with what {@code execute()} returned, or {@link Denied} with the reason
         * @throws Exception exactly what {@code execute()} threw, after the gate's locks are released
         * @throws IllegalStateException on another thread than the one that entered, or a second time -
         *     a defect of the caller; nothing is done then
         * @throws IllegalArgumentException when an argument is missing; nothing is done then
         */
        @NotNull
        public <T> Result<T> run(
            @NotNull WriteAuthorizationRequest request,
            @NotNull ContextRef context,
            @NotNull Execution<T> execution
        ) throws Exception {
            if (Thread.currentThread() != owner) {
                throw new IllegalStateException("An enforcement entry runs only on the thread that entered the gate");
            }
            if (used) {
                throw new IllegalStateException("An enforcement entry runs once; a retry enters the gate again");
            }
            used = true;
            if (request == null || context == null || execution == null) {
                throw new IllegalArgumentException("An enforcement attempt needs a request, a context and an execution");
            }
            return new Attempt<>(gate, ready, request, context, execution).run();
        }
    }

    /**
     * The context a write runs on, as the gate sees it
     * <p>
     * {@link #identity()} must be the long-lived execution context object itself - never a wrapper, a
     * generation object or anything made for the call - because the taint registry tells contexts apart
     * by that object. Neither method may throw: one that does still refuses the attempt and rolls it back,
     * but the registry can then record nothing about the context, not even that it is blocked.
     */
    public interface ContextRef {
        /**
         * The platform's id of the context
         */
        long contextId();

        /**
         * The context object itself
         */
        @NotNull
        Object identity();
    }

    /**
     * The platform's side of one attempt, implemented by the caller
     *
     * @param <T> what the operation returns
     */
    public interface Execution<T> {
        /**
         * Whether the context has a transaction open; an exception counts as yes
         */
        boolean transactionActive();

        /**
         * The caller's last word before the operation: null to proceed, otherwise why not
         * <p>
         * An exception refuses with {@code PERMISSION_STORE_UNAVAILABLE}.
         */
        @Nullable
        DenialReason confirm();

        /**
         * Rolls back the open transaction; false or an exception means it did not
         */
        boolean rollback();

        /**
         * Cuts the context off from its connection after a rollback that did not work; an exception is logged
         */
        void sever();

        /**
         * The operation; called at most once, and only when everything allowed it
         */
        @Nullable
        T execute() throws Exception;
    }

    /**
     * What an attempt came to
     *
     * @param <T> what the operation returns
     */
    public sealed interface Result<T> permits Executed, Denied {
    }

    /**
     * The operation ran; made in exactly one place, after the operation returned
     *
     * @param <T> what the operation returns
     */
    public static final class Executed<T> implements Result<T> {
        @Nullable
        private final T value;

        private Executed(@Nullable T value) {
            this.value = value;
        }

        /**
         * What the operation returned
         */
        @Nullable
        public T value() {
            return value;
        }
    }

    /**
     * The operation did not run, and why
     *
     * @param <T> what the operation would have returned
     */
    public static final class Denied<T> implements Result<T> {
        private final DenialReason reason;

        private Denied(@NotNull DenialReason reason) {
            this.reason = reason;
        }

        /**
         * Why the attempt was refused
         */
        @NotNull
        public DenialReason reason() {
            return reason;
        }
    }

    /**
     * Where the gate takes its timed read locks; production is {@link EnforcementKeyLocks#global()}
     */
    public interface KeyLockSource {
        /**
         * The grant key's read lock within {@code timeout}, or null when it did not come in time
         */
        @Nullable
        EnforcementKeyLocks.Held grant(@NotNull DbAccessKey key, @NotNull Duration timeout) throws InterruptedException;

        /**
         * The user's read lock within {@code timeout}, or null when it did not come in time
         */
        @Nullable
        EnforcementKeyLocks.Held user(@NotNull String userId, @NotNull Duration timeout) throws InterruptedException;

        /**
         * The timed reads of {@code locks}
         */
        @NotNull
        static KeyLockSource of(@NotNull EnforcementKeyLocks locks) {
            Objects.requireNonNull(locks, "locks");
            return new KeyLockSource() {
                @Nullable
                @Override
                public EnforcementKeyLocks.Held grant(
                    @NotNull DbAccessKey key,
                    @NotNull Duration timeout
                ) throws InterruptedException {
                    return locks.tryLockGrantForRead(key, timeout);
                }

                @Nullable
                @Override
                public EnforcementKeyLocks.Held user(
                    @NotNull String userId,
                    @NotNull Duration timeout
                ) throws InterruptedException {
                    return locks.tryLockUserForRead(userId, timeout);
                }
            };
        }
    }

    /** What a log line names as the step that failed */
    private enum Step {
        ADMISSION, CONTEXT, KEY, GRANT_LOCK, USER_LOCK, TAINT_STATE, AUTHORIZE, CHECK_1, CLAIM, CHECK_2, HOLDER,
        AUDIT, MARK_TAINTED, ROLLBACK_SUCCEEDED, MARK_BLOCKED, TRANSACTION_ACTIVE, ROLLBACK, SEVER, CONFIRM,
        RELEASE_USER, RELEASE_GRANT
    }

    /**
     * One run of one entry
     */
    private static final class Attempt<T> {
        private final EnforcementGate gate;
        @Nullable
        private final PolicyServiceHolder.Ready ready;
        private final WriteAuthorizationRequest request;
        private final ContextRef context;
        private final Execution<T> execution;
        private long contextId;
        /** The context object, read once; null when it could not be read, and then the registry is not touched */
        @Nullable
        private Object identity;
        @Nullable
        private DbAccessPolicyService service;
        @Nullable
        private AccessAuditWriter writer;
        @Nullable
        private EnforcementKeyLocks.Held grantLock;
        @Nullable
        private EnforcementKeyLocks.Held userLock;
        /** A lock wait ended by an interrupt; set again before returning */
        private boolean interrupted;

        private Attempt(
            @NotNull EnforcementGate gate,
            @Nullable PolicyServiceHolder.Ready ready,
            @NotNull WriteAuthorizationRequest request,
            @NotNull ContextRef context,
            @NotNull Execution<T> execution
        ) {
            this.gate = gate;
            this.ready = ready;
            this.request = request;
            this.context = context;
            this.execution = execution;
        }

        @NotNull
        private Result<T> run() throws Exception {
            try {
                return decide();
            } finally {
                release(userLock, Step.RELEASE_USER);
                release(grantLock, Step.RELEASE_GRANT);
            }
        }

        @NotNull
        private Result<T> decide() throws Exception {
            if (!readContext() || ready == null) {
                return deny(DenialReason.PERMISSION_STORE_UNAVAILABLE, null);
            }
            DbAccessPolicyService.KeyResolution resolution;
            Duration lockTimeout;
            try {
                service = ready.service();
                resolution = service.resolveKey(request);
                lockTimeout = service.config().keyLockTimeout();
            } catch (Throwable t) {
                logEvent(EVENT_STEP_FAILED, Step.KEY, t);
                return deny(DenialReason.PERMISSION_STORE_UNAVAILABLE, null);
            }
            DbAccessKey key = resolution.key();
            if (key == null) {
                DenialReason failure = resolution.failure();
                return deny(failure == null ? DenialReason.PERMISSION_STORE_UNAVAILABLE : failure, null);
            }

            grantLock = lock(Step.GRANT_LOCK, key, lockTimeout);
            if (grantLock == null) {
                return deny(DenialReason.PERMISSION_STORE_UNAVAILABLE, keyed(key, DenialReason.PERMISSION_STORE_UNAVAILABLE));
            }
            userLock = lock(Step.USER_LOCK, key, lockTimeout);
            if (userLock == null) {
                return deny(DenialReason.PERMISSION_STORE_UNAVAILABLE, keyed(key, DenialReason.PERMISSION_STORE_UNAVAILABLE));
            }

            TransactionTaintRegistry.State taint;
            try {
                taint = gate.registry.state(contextId, Objects.requireNonNull(identity));
            } catch (Throwable t) {
                logEvent(EVENT_STEP_FAILED, Step.TAINT_STATE, t);
                return deny(DenialReason.PERMISSION_STORE_UNAVAILABLE, keyed(key, DenialReason.PERMISSION_STORE_UNAVAILABLE));
            }
            if (taint == TransactionTaintRegistry.State.TAINTED) {
                return deny(DenialReason.TRANSACTION_TAINTED, keyed(key, DenialReason.TRANSACTION_TAINTED));
            }
            if (taint == TransactionTaintRegistry.State.BLOCKED) {
                return deny(DenialReason.CONNECTION_BLOCKED, keyed(key, DenialReason.CONNECTION_BLOCKED));
            }

            DbAccessPolicyService.ExpiryWindow window;
            AuthorizationDecision decision;
            try {
                window = service.openExpiryWindow();
                decision = window.authorize(request);
            } catch (Throwable t) {
                logEvent(EVENT_STEP_FAILED, Step.AUTHORIZE, t);
                return deny(DenialReason.PERMISSION_STORE_UNAVAILABLE, keyed(key, DenialReason.PERMISSION_STORE_UNAVAILABLE));
            }
            if (!key.equals(decision.key())) {
                // The decision is about something the lock does not cover: a container or an identity
                // that changed since the key was resolved.
                return deny(DenialReason.PERMISSION_STORE_UNAVAILABLE, keyed(key, DenialReason.PERMISSION_STORE_UNAVAILABLE));
            }
            if (!decision.isAllowed()) {
                return deny(decision.denialReason(), denied(decision, key));
            }
            try {
                decision = window.requireMarginBeforeAudit();
            } catch (Throwable t) {
                logEvent(EVENT_STEP_FAILED, Step.CHECK_1, t);
                return deny(DenialReason.PERMISSION_STORE_UNAVAILABLE, keyed(key, DenialReason.PERMISSION_STORE_UNAVAILABLE));
            }
            if (!decision.isAllowed()) {
                return deny(decision.denialReason(), denied(decision, key));
            }
            MetadataBudget budget;
            try {
                budget = window.claimAuditBudget();
            } catch (Throwable t) {
                logEvent(EVENT_STEP_FAILED, Step.CLAIM, t);
                return deny(DenialReason.PERMISSION_STORE_UNAVAILABLE, keyed(key, DenialReason.PERMISSION_STORE_UNAVAILABLE));
            }

            // From here on a WRITE_ALLOWED row may exist, so every refusal is recorded as its correction.
            AuthorizationAuditPayload allowed = decision.auditPayload();
            if (recordAllowed(allowed, budget) != AuditOutcome.RECORDED) {
                return deny(DenialReason.AUDIT_WRITE_FAILED, correction(allowed, DenialReason.AUDIT_WRITE_FAILED));
            }
            try {
                decision = window.requireMarginBeforeExecute();
            } catch (Throwable t) {
                logEvent(EVENT_STEP_FAILED, Step.CHECK_2, t);
                return deny(DenialReason.PERMISSION_STORE_UNAVAILABLE, correction(allowed, DenialReason.PERMISSION_STORE_UNAVAILABLE));
            }
            if (!decision.isAllowed()) {
                DenialReason expired = decision.denialReason();
                return deny(expired, correction(allowed, expired));
            }
            if (!stillReady()) {
                return deny(DenialReason.PERMISSION_STORE_UNAVAILABLE, correction(allowed, DenialReason.PERMISSION_STORE_UNAVAILABLE));
            }
            DenialReason refused;
            try {
                refused = execution.confirm();
            } catch (Throwable t) {
                logEvent(EVENT_CALLBACK_FAILED, Step.CONFIRM, t);
                return deny(DenialReason.PERMISSION_STORE_UNAVAILABLE, correction(allowed, DenialReason.PERMISSION_STORE_UNAVAILABLE));
            }
            if (refused != null) {
                return deny(refused, correction(allowed, refused));
            }
            // The one place the operation runs. Nothing is written after it.
            return new Executed<>(execution.execute());
        }

        /** Reads the context once; false when it cannot be read */
        private boolean readContext() {
            try {
                contextId = context.contextId();
                identity = Objects.requireNonNull(context.identity());
                return true;
            } catch (Throwable t) {
                identity = null;
                logEvent(EVENT_CALLBACK_FAILED, Step.CONTEXT, t);
                return false;
            }
        }

        @Nullable
        private EnforcementKeyLocks.Held lock(@NotNull Step step, @NotNull DbAccessKey key, @NotNull Duration timeout) {
            try {
                return step == Step.GRANT_LOCK ? gate.locks.grant(key, timeout) : gate.locks.user(key.userId(), timeout);
            } catch (InterruptedException e) {
                // The wait cleared the flag; it is set again once the refusal has been rolled back and recorded.
                interrupted = true;
                return null;
            } catch (Throwable t) {
                logEvent(EVENT_STEP_FAILED, step, t);
                return null;
            }
        }

        private boolean stillReady() {
            try {
                return gate.holder.current() == ready;
            } catch (Throwable t) {
                logEvent(EVENT_STEP_FAILED, Step.HOLDER, t);
                return false;
            }
        }

        @NotNull
        private AuditOutcome recordAllowed(@NotNull AuthorizationAuditPayload allowed, @NotNull MetadataBudget budget) {
            try {
                return writer().recordAllowedBeforeExecution(AuditEventId.next(), allowed, budget);
            } catch (Throwable t) {
                logEvent(EVENT_STEP_FAILED, Step.AUDIT, t);
                return AuditOutcome.FAILED;
            }
        }

        /**
         * The common way out of every refusal: roll back what the context has open, record, and say why
         */
        @NotNull
        private Result<T> deny(@NotNull DenialReason reason, @Nullable Supplier<AuthorizationAuditPayload> denied) {
            boolean active;
            try {
                active = execution.transactionActive();
            } catch (Throwable t) {
                logEvent(EVENT_CALLBACK_FAILED, Step.TRANSACTION_ACTIVE, t);
                active = true;
            }
            if (active) {
                registryStep(Step.MARK_TAINTED);
                boolean rolledBack = false;
                try {
                    rolledBack = execution.rollback();
                    if (!rolledBack) {
                        logEvent(EVENT_CALLBACK_FAILED, Step.ROLLBACK, null);
                    }
                } catch (Throwable t) {
                    logEvent(EVENT_CALLBACK_FAILED, Step.ROLLBACK, t);
                }
                if (rolledBack) {
                    registryStep(Step.ROLLBACK_SUCCEEDED);
                } else {
                    try {
                        execution.sever();
                    } catch (Throwable t) {
                        logEvent(EVENT_CALLBACK_FAILED, Step.SEVER, t);
                    }
                    registryStep(Step.MARK_BLOCKED);
                }
            }
            if (denied != null) {
                try {
                    writer().recordDenied(AuditEventId.next(), denied.get());
                } catch (Throwable t) {
                    logEvent(EVENT_STEP_FAILED, Step.AUDIT, t);
                }
            }
            if (interrupted) {
                // Given back only now, so that neither the rollback nor the audit saw it.
                Thread.currentThread().interrupt();
            }
            return new Denied<>(reason);
        }

        /** One registry transition for this context; a failure is logged and the refusal goes on */
        private void registryStep(@NotNull Step step) {
            Object held = identity;
            if (held == null) {
                return;
            }
            try {
                TransactionTaintRegistry registry = gate.registry;
                switch (step) {
                    case MARK_TAINTED -> registry.markTainted(contextId, held);
                    case ROLLBACK_SUCCEEDED -> registry.rollbackSucceeded(contextId, held);
                    default -> registry.markBlocked(contextId, held);
                }
            } catch (Throwable t) {
                logEvent(EVENT_STEP_FAILED, step, t);
            }
        }

        @NotNull
        private AccessAuditWriter writer() {
            AccessAuditWriter made = writer;
            if (made == null) {
                PolicyServiceHolder.Ready admitted = Objects.requireNonNull(ready);
                made = new AccessAuditWriter(admitted.database().metadataLeases(), Objects.requireNonNull(service).config());
                writer = made;
            }
            return made;
        }

        /** A denial about the locked key, before any decision named a grant */
        @NotNull
        private Supplier<AuthorizationAuditPayload> keyed(@NotNull DbAccessKey key, @NotNull DenialReason reason) {
            return () -> new AuthorizationAuditPayload(DbAccessDecision.DENY, reason, key.userId(), key.projectId(),
                key.connectionId(), null, request.operationCategory(), null);
        }

        /** The decision's own denial, or one about the locked key when it carries none */
        @NotNull
        private Supplier<AuthorizationAuditPayload> denied(@NotNull AuthorizationDecision decision, @NotNull DbAccessKey key) {
            AuthorizationAuditPayload own = decision.auditPayload();
            return own != null ? () -> own : keyed(key, decision.denialReason());
        }

        /** A refusal after the allowed row: the same key, grant, expiry and category, the new reason */
        @NotNull
        private static Supplier<AuthorizationAuditPayload> correction(
            @NotNull AuthorizationAuditPayload allowed,
            @NotNull DenialReason reason
        ) {
            return () -> new AuthorizationAuditPayload(DbAccessDecision.DENY, reason, allowed.userId(), allowed.projectId(),
                allowed.connectionId(), allowed.grantId(), allowed.operationCategory(), allowed.expiresAt());
        }

        private static void release(@Nullable EnforcementKeyLocks.Held held, @NotNull Step step) {
            if (held == null) {
                return;
            }
            try {
                held.close();
            } catch (Throwable t) {
                logEvent(EVENT_STEP_FAILED, step, t);
            }
        }
    }

    /**
     * Logs a failed step by event code, a new correlation id, the step and the exception class - never a message or a trace
     * <p>
     * Never throws: what the attempt does must not depend on whether it could be logged.
     */
    private static void logEvent(@NotNull String eventCode, @NotNull Step step, @Nullable Throwable failure) {
        try {
            log.error("DBAC enforcement gate [event=" + eventCode
                + " EVENT_ID=" + UUID.randomUUID()
                + " step=" + step.name()
                + (failure == null ? "" : " exception=" + failure.getClass().getName()) + "]");
        } catch (Throwable ignored) {
            // Deliberately nothing.
        }
    }
}
