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
package io.cloudbeaver.service.sql;

import io.cloudbeaver.service.dbac.policy.DbOperationCategory;
import io.cloudbeaver.service.dbac.policy.DenialReason;
import io.cloudbeaver.service.dbac.policy.WriteAuthorizationRequest;
import io.cloudbeaver.service.dbac.policy.enforcement.EnforcementGate;
import io.cloudbeaver.service.dbac.policy.enforcement.TransactionTaintRegistry;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.jkiss.dbeaver.DBException;
import org.jkiss.dbeaver.Log;
import org.jkiss.dbeaver.model.DBPExclusiveResource;
import org.jkiss.dbeaver.model.DBUtils;
import org.jkiss.dbeaver.model.exec.DBCException;
import org.jkiss.dbeaver.model.exec.DBCExecutionContext;
import org.jkiss.dbeaver.model.exec.DBCExecutionPurpose;
import org.jkiss.dbeaver.model.exec.DBCInvalidatePhase;
import org.jkiss.dbeaver.model.exec.DBCSession;
import org.jkiss.dbeaver.model.exec.DBCTransactionManager;
import org.jkiss.dbeaver.model.impl.jdbc.JDBCExecutionContext;
import org.jkiss.dbeaver.model.qm.QMTransactionState;
import org.jkiss.dbeaver.model.qm.QMUtils;
import org.jkiss.dbeaver.model.runtime.DBRProgressMonitor;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.UUID;

/**
 * DBAC enforcement of the transaction entry points: commit, auto-commit on, and the explicit rollback
 * <p>
 * The one production class that knows both the platform and the enforcement gate. Each call is made from inside the
 * entry point's async task, and finds everything it works on afresh there: the execution context comes from the
 * caller's {@link Source} on every call, never from a capture made when the task was created.
 * <p>
 * <b>Commit and auto-commit on</b> go through {@link EnforcementGate#global()}: the gate is entered before anything
 * is locked; the context must be a JDBC one; then the instance's exclusive lock X and the context's monitor M are
 * taken, in that order, and held until the gate has returned; under them the JDBC connection - the generation - is
 * read, with its auto-commit flag read from JDBC itself, never from the platform's cache; and the gate decides with a
 * request made from the session's user and the context's own container. The platform operation runs only inside the
 * gate's {@code execute()}. Afterwards the connection must still be the same generation - and for auto-commit on,
 * JDBC must really say auto-commit - or the call does not succeed: the context is rolled back where it can be,
 * severed and blocked, and the caller is told {@code CONNECTION_BLOCKED}. The platform has been called by then, so
 * no correcting audit row is written. A refusal is a {@link Refusal}: never a lost connection or an aborted
 * transaction, which the platform's recovery would retry.
 * <p>
 * <b>Auto-commit on when JDBC already is</b> succeeds without the gate or the platform: there is no open
 * transaction, so nothing can be committed.
 * <p>
 * <b>The explicit rollback</b> is recovery. It takes X and M, and nothing of the policy: no gate, grant key or user
 * lock, metadata database or audit row, so it works while the policy service is failed or stopping and while a
 * revoke or a deactivation waits. Rolled back on a live connection, it releases a blocked context; one that fails
 * severs the context and blocks it.
 * <p>
 * <b>Bounded rollbacks.</b> Every rollback this class runs - the gate's on a refusal, the one after a failed
 * postcondition, the explicit one - runs on the same thread, under the same X and M, with the connection's network
 * timeout set to {@link #ROLLBACK_NETWORK_TIMEOUT_MILLIS} and put back afterwards. A timeout that cannot be set or
 * put back, a rollback that fails or runs out of time, or a connection that changed counts as a rollback that did
 * not work: the connection is aborted rather than handed back, the context severed and blocked.
 * <p>
 * Logged with a fixed event code, a new {@code EVENT_ID} and at most an exception's class - never SQL, a URL, a host,
 * a credential or a driver's message.
 */
public final class DbacEnforcedExecution {

    private static final Log log = Log.getLog(DbacEnforcedExecution.class);

    /** Logged when an operation ran but its postcondition failed, and the context was blocked */
    static final String EVENT_POSTCONDITION_FAILED = "DBAC_POSTCONDITION_FAILED";
    /** Logged when a rollback did not work */
    static final String EVENT_ROLLBACK_FAILED = "DBAC_ROLLBACK_FAILED";
    /** Logged when severing or marking a context failed */
    static final String EVENT_CONTEXT_STEP_FAILED = "DBAC_CONTEXT_STEP_FAILED";
    /** Logged when an entry point refused before the gate could judge */
    static final String EVENT_ENTRY_REFUSED = "DBAC_ENTRY_REFUSED";

    /** The longest a rollback may wait on the database, through the connection's network timeout */
    static final int ROLLBACK_NETWORK_TIMEOUT_MILLIS = 10_000;

    private DbacEnforcedExecution() {
    }

    /**
     * Where an entry point's call finds its context and who asks - read afresh by every call
     */
    public interface Source {
        /**
         * The context the call works on, looked up now
         */
        @Nullable
        DBCExecutionContext executionContext();

        /**
         * The user the call is made for, now
         */
        @Nullable
        String userId();
    }

    /**
     * A refused call: carries the reason, and no SQL state - it is never a lost connection or an aborted transaction
     */
    public static final class Refusal extends DBException {
        private final DenialReason reason;

        private Refusal(@NotNull DenialReason reason) {
            super(reason.userMessage() + " [" + reason.messageCode() + "]");
            this.reason = reason;
        }

        /**
         * Why the call was refused
         */
        @NotNull
        public DenialReason reason() {
            return reason;
        }

        /**
         * None: a refusal is not an internal failure, and what the user is shown of it has no internal frames
         */
        @NotNull
        @Override
        public synchronized Throwable fillInStackTrace() {
            return this;
        }
    }

    // ---------------------------------------------------------------- commit

    /**
     * Commits the context's transaction, if the gate allows it
     *
     * @return the transaction as it was just before the commit, or null when the context offers no transactions
     * @throws Refusal when the commit was refused, or ran but left the connection blocked
     * @throws DBException what the platform's commit threw
     */
    @Nullable
    public static QMTransactionState commit(@NotNull DBRProgressMonitor monitor, @NotNull Source source) throws DBException {
        EnforcementGate.Entry entry = EnforcementGate.global().enter();
        DBCExecutionContext context = source.executionContext();
        JDBCExecutionContext jdbc = gatedContext(context);
        if (jdbc == null) {
            return null;
        }
        DBPExclusiveResource exclusive = jdbc.getOwnerInstance().getExclusiveLock();
        Object instanceLock = exclusive.acquireExclusiveLock();
        try {
            synchronized (jdbc) {
                Connection generation = generationOf(jdbc);
                Boolean autoCommit = autoCommitOf(generation);
                requireSameGeneration(jdbc, generation);
                Commit commit = new Commit(monitor, jdbc, generation);
                return decide(entry, request(source, commit.ref, DbOperationCategory.TRANSACTION_COMMIT, autoCommit), commit);
            }
        } finally {
            exclusive.releaseExclusiveLock(instanceLock);
        }
    }

    /** The commit itself, and the generation it must find unchanged afterwards */
    private static final class Commit extends Attempt<QMTransactionState> {
        Commit(@NotNull DBRProgressMonitor monitor, @NotNull JDBCExecutionContext context, @NotNull Connection generation) {
            super(monitor, context, generation);
        }

        @NotNull
        @Override
        public Done<QMTransactionState> execute() throws DBException {
            QMTransactionState before = QMUtils.getTransactionState(context);
            try (DBCSession session = context.openSession(monitor, DBCExecutionPurpose.UTIL, "Commit transaction")) {
                context.commit(session);
            }
            if (context.getConnectionOrNull() != generation) {
                blockAfterOperation(this, "COMMIT_GENERATION_CHANGED", null);
                return Done.block();
            }
            return Done.of(before);
        }
    }

    // ---------------------------------------------------------------- auto-commit on

    /**
     * Turns auto-commit on - which commits the open transaction - if the gate allows it
     *
     * @return true once JDBC says auto-commit, or null when the context offers no transactions
     * @throws Refusal when it was refused, or the call left JDBC in manual commit or the connection changed
     */
    @Nullable
    public static Boolean autoCommitOn(@NotNull DBRProgressMonitor monitor, @NotNull Source source) throws DBException {
        EnforcementGate.Entry entry = EnforcementGate.global().enter();
        DBCExecutionContext context = source.executionContext();
        JDBCExecutionContext jdbc = gatedContext(context);
        if (jdbc == null) {
            return null;
        }
        DBPExclusiveResource exclusive = jdbc.getOwnerInstance().getExclusiveLock();
        Object instanceLock = exclusive.acquireExclusiveLock();
        try {
            synchronized (jdbc) {
                Connection generation = generationOf(jdbc);
                Boolean autoCommit = autoCommitOf(generation);
                requireSameGeneration(jdbc, generation);
                if (Boolean.TRUE.equals(autoCommit)) {
                    // JDBC is in auto-commit already: no transaction is open, so nothing could be committed.
                    return Boolean.TRUE;
                }
                AutoCommitOn on = new AutoCommitOn(monitor, jdbc, generation);
                return decide(entry, request(source, on.ref, DbOperationCategory.TRANSACTION_AUTOCOMMIT_ON, false), on);
            }
        } finally {
            exclusive.releaseExclusiveLock(instanceLock);
        }
    }

    /** The platform's auto-commit switch, judged by what JDBC says afterwards rather than by its return */
    private static final class AutoCommitOn extends Attempt<Boolean> {
        AutoCommitOn(@NotNull DBRProgressMonitor monitor, @NotNull JDBCExecutionContext context, @NotNull Connection generation) {
            super(monitor, context, generation);
        }

        @NotNull
        @Override
        public Done<Boolean> execute() {
            try {
                context.setAutoCommit(monitor, true);
            } catch (DBException | RuntimeException e) {
                blockAfterOperation(this, "AUTOCOMMIT_CALL_FAILED", e);
                return Done.block();
            }
            if (context.getConnectionOrNull() != generation) {
                blockAfterOperation(this, "AUTOCOMMIT_GENERATION_CHANGED", null);
                return Done.block();
            }
            if (!Boolean.TRUE.equals(autoCommitOf(generation))) {
                // The platform's cache may have said auto-commit already and done nothing at all.
                blockAfterOperation(this, "AUTOCOMMIT_POSTCONDITION_FAILED", null);
                return Done.block();
            }
            return Done.of(Boolean.TRUE);
        }
    }

    // ---------------------------------------------------------------- explicit rollback

    /**
     * Rolls the context's transaction back - recovery, which no policy judges
     *
     * @return the transaction as it was just before the rollback, or null when the context offers no transactions
     * @throws DBException what the rollback threw, or why it could not be bounded; the context is severed and blocked then
     */
    @Nullable
    public static QMTransactionState rollback(@NotNull DBRProgressMonitor monitor, @NotNull Source source) throws DBException {
        DBCExecutionContext context = source.executionContext();
        if (!(context instanceof JDBCExecutionContext jdbc)) {
            return ExplicitRollback.upstream(monitor, context);
        }
        return ExplicitRollback.jdbc(monitor, jdbc);
    }

    /**
     * The explicit rollback: X and M, and nothing of the policy
     */
    private static final class ExplicitRollback {
        private ExplicitRollback() {
        }

        /** A context that is not JDBC: as the platform always did it - its transaction cannot be tracked */
        @Nullable
        static QMTransactionState upstream(@NotNull DBRProgressMonitor monitor, @Nullable DBCExecutionContext context) throws DBException {
            DBCTransactionManager txn = DBUtils.getTransactionManager(context);
            if (context == null || txn == null) {
                return null;
            }
            QMTransactionState before = QMUtils.getTransactionState(context);
            try (DBCSession session = context.openSession(monitor, DBCExecutionPurpose.UTIL, "Rollback transaction")) {
                txn.rollback(session, null);
            }
            return before;
        }

        @NotNull
        static QMTransactionState jdbc(@NotNull DBRProgressMonitor monitor, @NotNull JDBCExecutionContext context) throws DBException {
            DBPExclusiveResource exclusive = context.getOwnerInstance().getExclusiveLock();
            Object instanceLock = exclusive.acquireExclusiveLock();
            try {
                synchronized (context) {
                    Connection generation = context.getConnectionOrNull();
                    QMTransactionState before = QMUtils.getTransactionState(context);
                    DBException failure = generation == null
                        ? new DBCException("Disconnected")
                        : boundedRollback(monitor, context, generation, "Rollback transaction");
                    if (failure == null) {
                        record(Mark.RELEASED, context);
                        return before;
                    }
                    sever(monitor, context, generation);
                    record(Mark.BLOCKED, context);
                    throw failure;
                }
            } finally {
                exclusive.releaseExclusiveLock(instanceLock);
            }
        }
    }

    // ---------------------------------------------------------------- the gate's side

    /** What the operation came to: its value, or that it ran but left the connection blocked */
    private record Done<T>(@Nullable T value, boolean blocked) {
        @NotNull
        static <T> Done<T> of(@Nullable T value) {
            return new Done<>(value, false);
        }

        @NotNull
        static <T> Done<T> block() {
            return new Done<>(null, true);
        }
    }

    /** The context as the gate sees it: the platform's id and the long-lived context object itself */
    private record Ref(@NotNull JDBCExecutionContext context) implements EnforcementGate.ContextRef {
        @Override
        public long contextId() {
            return context.getContextId();
        }

        @NotNull
        @Override
        public Object identity() {
            return context;
        }
    }

    /**
     * The platform's side of one gated attempt, on one generation of the context's connection
     */
    private abstract static class Attempt<T> implements EnforcementGate.Execution<Done<T>> {
        final DBRProgressMonitor monitor;
        final JDBCExecutionContext context;
        final Connection generation;
        final Ref ref;

        Attempt(@NotNull DBRProgressMonitor monitor, @NotNull JDBCExecutionContext context, @NotNull Connection generation) {
            this.monitor = monitor;
            this.context = context;
            this.generation = generation;
            this.ref = new Ref(context);
        }

        @Override
        public boolean transactionActive() {
            // A flag that cannot be read counts as an open transaction.
            return !Boolean.TRUE.equals(autoCommitOf(generation));
        }

        @Nullable
        @Override
        public DenialReason confirm() {
            return context.getConnectionOrNull() == generation ? null : DenialReason.GRANT_STALE;
        }

        @Override
        public boolean rollback() {
            return boundedRollback(monitor, context, generation, "DBAC rollback") == null;
        }

        @Override
        public void sever() {
            DbacEnforcedExecution.sever(monitor, context, generation);
        }
    }

    @NotNull
    private static <T> T decide(
        @NotNull EnforcementGate.Entry entry,
        @NotNull WriteAuthorizationRequest request,
        @NotNull Attempt<T> attempt
    ) throws DBException {
        EnforcementGate.Result<Done<T>> result;
        try {
            result = entry.run(request, attempt.ref, attempt);
        } catch (DBException | RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new DBException("The operation failed", e);
        }
        if (result instanceof EnforcementGate.Denied<Done<T>> denied) {
            throw new Refusal(denied.reason());
        }
        Done<T> done = ((EnforcementGate.Executed<Done<T>>) result).value();
        if (done == null || done.blocked() || done.value() == null) {
            throw new Refusal(DenialReason.CONNECTION_BLOCKED);
        }
        return done.value();
    }

    @NotNull
    private static WriteAuthorizationRequest request(
        @NotNull Source source,
        @NotNull Ref ref,
        @NotNull DbOperationCategory category,
        @Nullable Boolean autoCommit
    ) {
        return new WriteAuthorizationRequest(source.userId(), ref.context().getDataSource().getContainer(), category,
            String.valueOf(ref.contextId()), Boolean.TRUE.equals(autoCommit));
    }

    // ---------------------------------------------------------------- before the gate

    /**
     * The JDBC context a gated call works on, or null when the context offers no transactions at all, as the platform always allowed
     *
     * @throws Refusal for no context, or a context with transactions that is not a JDBC one
     */
    @Nullable
    private static JDBCExecutionContext gatedContext(@Nullable DBCExecutionContext context) throws Refusal {
        if (context instanceof JDBCExecutionContext jdbc) {
            return jdbc;
        }
        if (context == null) {
            throw refuse(DenialReason.CONNECTION_UNKNOWN);
        }
        if (DBUtils.getTransactionManager(context) == null) {
            return null;
        }
        throw refuse(DenialReason.ENDPOINT_UNSUPPORTED);
    }

    @NotNull
    private static Connection generationOf(@NotNull JDBCExecutionContext context) throws Refusal {
        Connection generation = context.getConnectionOrNull();
        if (generation == null) {
            throw refuse(DenialReason.CONNECTION_UNKNOWN);
        }
        return generation;
    }

    private static void requireSameGeneration(@NotNull JDBCExecutionContext context, @NotNull Connection generation) throws Refusal {
        if (context.getConnectionOrNull() != generation) {
            throw refuse(DenialReason.GRANT_STALE);
        }
    }

    @NotNull
    private static Refusal refuse(@NotNull DenialReason reason) {
        logEvent(EVENT_ENTRY_REFUSED, "DBAC refused a transaction call before it could be judged", reason.name(), null);
        return new Refusal(reason);
    }

    // ---------------------------------------------------------------- the connection

    /** What JDBC itself says about auto-commit, or null when it cannot say - which counts as an open transaction */
    @Nullable
    private static Boolean autoCommitOf(@Nullable Connection generation) {
        if (generation == null) {
            return null;
        }
        try {
            return generation.getAutoCommit();
        } catch (SQLException | RuntimeException e) {
            return null;
        }
    }

    /**
     * Rolls back through the platform with the connection's network timeout bounding the wait, and puts the timeout back
     *
     * @return null when the rollback returned, the timeout was put back and the context still has this connection;
     *     otherwise why not
     */
    @Nullable
    private static DBException boundedRollback(
        @NotNull DBRProgressMonitor monitor,
        @NotNull JDBCExecutionContext context,
        @NotNull Connection generation,
        @NotNull String title
    ) {
        if (context.getConnectionOrNull() != generation) {
            logEvent(EVENT_ROLLBACK_FAILED, "DBAC did not roll back a connection the context no longer has", "GENERATION_CHANGED", null);
            return new DBCException("The connection changed");
        }
        int previous;
        try {
            previous = generation.getNetworkTimeout();
            generation.setNetworkTimeout(Runnable::run, ROLLBACK_NETWORK_TIMEOUT_MILLIS);
        } catch (SQLException | RuntimeException e) {
            logEvent(EVENT_ROLLBACK_FAILED, "DBAC could not bound a rollback", "TIMEOUT_NOT_SET", e);
            return new DBCException("The rollback could not be bounded");
        }
        DBException failure = null;
        try (DBCSession session = context.openSession(monitor, DBCExecutionPurpose.UTIL, title)) {
            context.rollback(session, null);
        } catch (DBException e) {
            logEvent(EVENT_ROLLBACK_FAILED, "DBAC rollback failed", "ROLLBACK_FAILED", e);
            failure = e;
        } catch (RuntimeException e) {
            logEvent(EVENT_ROLLBACK_FAILED, "DBAC rollback failed", "ROLLBACK_FAILED", e);
            failure = new DBCException("The rollback failed");
        }
        try {
            generation.setNetworkTimeout(Runnable::run, previous);
        } catch (SQLException | RuntimeException e) {
            logEvent(EVENT_ROLLBACK_FAILED, "DBAC could not restore a network timeout after a rollback", "TIMEOUT_NOT_RESTORED", e);
            return failure != null ? failure : new DBCException("The connection's network timeout could not be restored");
        }
        if (failure == null && context.getConnectionOrNull() != generation) {
            logEvent(EVENT_ROLLBACK_FAILED, "DBAC rolled back a connection that is no longer the context's", "GENERATION_CHANGED", null);
            return new DBCException("The connection changed");
        }
        return failure;
    }

    /**
     * Cuts the context off from its connection: the generation is aborted - never handed back - and the context invalidated
     */
    private static void sever(@NotNull DBRProgressMonitor monitor, @NotNull JDBCExecutionContext context, @Nullable Connection generation) {
        if (generation != null) {
            try {
                generation.abort(Runnable::run);
            } catch (SQLException | RuntimeException e) {
                logEvent(EVENT_CONTEXT_STEP_FAILED, "DBAC could not abort a connection", "ABORT", e);
            }
        }
        try {
            context.invalidateContext(monitor, DBCInvalidatePhase.BEFORE_INVALIDATE);
        } catch (DBException | RuntimeException e) {
            logEvent(EVENT_CONTEXT_STEP_FAILED, "DBAC could not sever a context", "SEVER", e);
        }
    }

    /**
     * After the platform was called and its postcondition failed: taint, try a rollback, sever, block
     * <p>
     * The platform has been called, so no correcting audit row is written.
     */
    private static void blockAfterOperation(@NotNull Attempt<?> attempt, @NotNull String detail, @Nullable Throwable failure) {
        logEvent(EVENT_POSTCONDITION_FAILED, "DBAC blocked a context whose operation left its connection in doubt", detail, failure);
        JDBCExecutionContext context = attempt.context;
        record(Mark.TAINTED, context);
        boundedRollback(attempt.monitor, context, attempt.generation, "DBAC rollback");
        sever(attempt.monitor, context, attempt.generation);
        record(Mark.BLOCKED, context);
    }

    /** What this class records in the taint registry, and only after the platform was called or for an explicit rollback */
    private enum Mark {
        /** Before the rollback that follows a failed postcondition */
        TAINTED,
        /** After a failed postcondition, or a failed explicit rollback */
        BLOCKED,
        /** After an explicit rollback that worked on a live connection */
        RELEASED
    }

    /** One registry change, made by a thread that holds X and M; a failure is logged and changes nothing else */
    private static void record(@NotNull Mark mark, @NotNull JDBCExecutionContext context) {
        TransactionTaintRegistry registry = TransactionTaintRegistry.global();
        try {
            switch (mark) {
                case TAINTED -> registry.markTainted(context.getContextId(), context);
                case BLOCKED -> registry.markBlocked(context.getContextId(), context);
                default -> registry.releaseAfterExplicitRollback(context.getContextId(), context);
            }
        } catch (RuntimeException | Error e) {
            logEvent(EVENT_CONTEXT_STEP_FAILED, "DBAC could not record a context's transaction state", mark.name(), e);
        }
    }

    private static void logEvent(@NotNull String event, @NotNull String summary, @NotNull String detail, @Nullable Throwable failure) {
        try {
            log.error(summary + " [event=" + event + " EVENT_ID=" + UUID.randomUUID() + " detail=" + detail
                + (failure == null ? "" : " exception=" + failure.getClass().getName()) + "]");
        } catch (RuntimeException | Error ignored) {
            // Deliberately nothing: what happens to the context must not depend on whether it could be logged.
        }
    }
}
