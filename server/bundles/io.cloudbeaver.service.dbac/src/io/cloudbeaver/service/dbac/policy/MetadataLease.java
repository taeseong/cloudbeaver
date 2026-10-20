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

import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.jkiss.dbeaver.Log;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

/**
 * One borrowed metadata connection, good for exactly one statement
 * <p>
 * <b>Nothing JDBC leaves it.</b> The caller hands in a {@link MetadataQuery} or {@link MetadataUpdate}
 * and gets back a {@link MetadataOutcome} holding values already copied out of the driver. There is no
 * way to reach the connection, a statement or a result set, so there is no way to run a second
 * statement on it, to set a query timeout that is not put back, or to return it to the pool behind
 * this object's back.
 * <p>
 * <b>One statement, one template.</b> {@link #query} and {@link #update} run the same private
 * sequence, once per lease: claim the lease, take the remaining budget in whole seconds, prepare, read
 * the statement's query timeout, set the budget as the timeout, bind, execute, read the declared
 * result in full, close the result and the statement, put the timeout back on a new statement, check
 * the budget again. {@code Done} comes back only when every one of those steps succeeded. On H2 the
 * timeout belongs to the session and outlives the statement, which is why it is put back on a new
 * statement; on PostgreSQL it belongs to the statement and the restore is harmless. The same sequence
 * runs on both - telling the engines apart is a way to get the H2 case wrong.
 * <p>
 * <b>Closing.</b> {@link #close()} disposes the connection exactly once. A lease whose session can no
 * longer be trusted is {@link LeaseState#CONTAMINATED} and is never closed normally - closing would
 * hand the session, with whatever it still carries, to the next borrower. It is aborted and then
 * closed, which makes the pool discard it - but only once the abort is seen to have closed it. An
 * abort is not taken on trust: H2 2.4's {@code abort} does nothing at all, and closing a connection
 * that is still open after one returns its session to the pool exactly as an ordinary close would.
 * When the abort cannot be confirmed, or anything after it fails, the connection is kept, strongly,
 * in its slot ({@code QUARANTINED}) or for the rest of the process ({@code RESIDUAL}); no failure
 * path drops the reference.
 * <p>
 * Used by one thread at a time. Only {@link BoundedMetadataConnections} creates one.
 */
public final class MetadataLease implements AutoCloseable {

    private static final Log log = Log.getLog(MetadataLease.class);

    /** An {@code Error} escaped the statement; the lease is contaminated and the Error rethrown */
    static final String EVENT_STATEMENT_ERROR = "DBAC_METADATA_STATEMENT_ERROR";
    /** A result set or statement could not be closed */
    static final String EVENT_STATEMENT_CLOSE_FAILED = "DBAC_METADATA_STATEMENT_CLOSE_FAILED";
    /** The session's query timeout could not be put back */
    static final String EVENT_TIMEOUT_RESTORE_FAILED = "DBAC_METADATA_TIMEOUT_RESTORE_FAILED";
    /** The ordinary close of the connection failed; it is aborted instead */
    static final String EVENT_CLOSE_FAILED = "DBAC_METADATA_CLOSE_FAILED";
    /** The abort failed; the connection is kept */
    static final String EVENT_ABORT_FAILED = "DBAC_METADATA_ABORT_FAILED";
    /** The abort returned but the connection is not closed - H2's abort is a no-op; the connection is kept */
    static final String EVENT_ABORT_UNCONFIRMED = "DBAC_METADATA_ABORT_UNCONFIRMED";
    /** The close after a successful abort failed; the connection is kept */
    static final String EVENT_CLOSE_AFTER_ABORT_FAILED = "DBAC_METADATA_CLOSE_AFTER_ABORT_FAILED";
    /** A disposal found no connection; nothing was there to keep */
    static final String EVENT_DISPOSAL_TRIPWIRE = "DBAC_METADATA_DISPOSAL_TRIPWIRE";

    /** Why a lease is being disposed; only the contaminated one skips the ordinary close */
    enum DisposalCause {
        /** The owner closed it */
        NORMAL,
        /** Delivered after the caller had given up; the worker disposes it */
        LATE,
        /** Delivered after the budget was spent; the caller disposes it without using it */
        OVER_BUDGET,
        /** Delivered to a caller that was interrupted while waiting */
        INTERRUPTED_LATE
    }

    private final BoundedMetadataConnections owner;
    private final int slot;
    private final MetadataBudget budget;
    private final MetadataPurpose purpose;
    private final AtomicReference<LeaseState> state = new AtomicReference<>(LeaseState.OPEN);
    /**
     * Set once, by the worker, before the lease is published. The compare-and-set that publishes it
     * orders this write before any read by the thread that receives it.
     */
    @Nullable
    private Connection raw;

    MetadataLease(
        @NotNull BoundedMetadataConnections owner,
        int slot,
        @NotNull MetadataBudget budget,
        @NotNull MetadataPurpose purpose
    ) {
        this.owner = owner;
        this.slot = slot;
        this.budget = budget;
        this.purpose = purpose;
    }

    void attach(@NotNull Connection connection) {
        this.raw = connection;
    }

    /**
     * Runs this lease's one statement, a SELECT, and returns its rows read in full
     *
     * @return {@code Done} with the rows, or {@code Unusable}; never null. A second call on the same
     *     lease - of either kind - is {@code SECOND_STATEMENT} and runs nothing.
     * @throws Error only an {@code Error} the statement itself threw; the lease is then contaminated
     */
    @NotNull
    public MetadataOutcome<MetadataRows> query(@NotNull MetadataQuery query) {
        if (query == null) {
            throw new IllegalArgumentException("A metadata query is required");
        }
        return run(query.text(), query.bindings(), (statement, open) -> {
            ResultSet result;
            try {
                bind(statement, query.bindings());
                result = statement.executeQuery();
            } catch (Exception e) {
                return unusable(UnusableCause.EXECUTION_FAILED);
            }
            open.result = result;
            try {
                return materialize(result, query);
            } catch (Exception e) {
                return unusable(UnusableCause.MATERIALIZATION_FAILED);
            }
        });
    }

    /**
     * Runs this lease's one statement, an INSERT, UPDATE or DELETE, and returns its update count
     *
     * @return {@code Done} with the count, which is the declared one, or {@code Unusable}; never null.
     *     A second call on the same lease is {@code SECOND_STATEMENT} and runs nothing.
     * @throws Error only an {@code Error} the statement itself threw; the lease is then contaminated
     */
    @NotNull
    public MetadataOutcome<Long> update(@NotNull MetadataUpdate update) {
        if (update == null) {
            throw new IllegalArgumentException("A metadata update is required");
        }
        return run(update.text(), update.bindings(), (statement, open) -> {
            long count;
            try {
                bind(statement, update.bindings());
                count = statement.executeUpdate();
            } catch (Exception e) {
                return unusable(UnusableCause.EXECUTION_FAILED);
            }
            return count == update.expectedCount()
                ? new MetadataOutcome.Done<>(count)
                : unusable(UnusableCause.CARDINALITY);
        });
    }

    /**
     * Where this lease is in its life
     */
    @NotNull
    public LeaseState state() {
        return state.get();
    }

    /**
     * Disposes the connection, exactly once; a second call does nothing
     * <p>
     * Never throws. A lease that ran no statement or whose statement left the session as it found it
     * is closed normally; a contaminated one is aborted first.
     */
    @Override
    public void close() {
        dispose(DisposalCause.NORMAL);
    }

    /** What the statement body still has open when it returns, and the first Error seen, for the template */
    private static final class Open {
        @Nullable
        private ResultSet result;
        @Nullable
        private Error error;

        /** Keeps the first Error; a later one is only logged */
        private void error(@NotNull Error e) {
            if (error == null) {
                error = e;
            }
        }
    }

    /** The part of the template that differs between a query and an update */
    @FunctionalInterface
    private interface Body<T> {
        /**
         * Binds, executes and reads; every {@code Exception} becomes an {@code Unusable}, an {@code Error} propagates
         */
        @NotNull
        MetadataOutcome<T> run(@NotNull PreparedStatement statement, @NotNull Open open);
    }

    /**
     * The template: the only place a statement is prepared, a timeout set, and a timeout put back
     */
    @NotNull
    private <T> MetadataOutcome<T> run(@NotNull String text, @NotNull List<MetadataBinding> bindings, @NotNull Body<T> body) {
        if (!state.compareAndSet(LeaseState.OPEN, LeaseState.USED)) {
            return unusable(UnusableCause.SECOND_STATEMENT);
        }
        Connection connection = raw;
        MetadataOutcome<T> outcome = null;
        boolean contaminated = false;
        boolean touched = false;
        int previous = 0;
        PreparedStatement statement = null;
        Open open = new Open();
        try {
            int seconds = wholeSecondsLeft();
            if (seconds < 1) {
                outcome = unusable(UnusableCause.BUDGET_EXHAUSTED);
            } else if (!inAutoCommit(connection)) {
                outcome = unusable(UnusableCause.STATEMENT_FAILED);
            } else {
                try {
                    statement = connection.prepareStatement(text);
                } catch (Exception e) {
                    outcome = unusable(UnusableCause.STATEMENT_FAILED);
                }
                if (statement != null) {
                    try {
                        previous = statement.getQueryTimeout();
                    } catch (Exception e) {
                        outcome = unusable(UnusableCause.TIMEOUT_SETUP_FAILED);
                    }
                    if (outcome == null) {
                        // From here on the session may carry the timeout, whether or not the call succeeded.
                        touched = true;
                        try {
                            statement.setQueryTimeout(seconds);
                        } catch (Exception e) {
                            outcome = unusable(UnusableCause.TIMEOUT_SETUP_FAILED);
                        }
                    }
                    if (outcome == null) {
                        outcome = body.run(statement, open);
                    }
                }
            }
        } catch (Error e) {
            open.error(e);
        } finally {
            if (open.result != null && !closeStatementPart(open.result, open)) {
                outcome = unusable(UnusableCause.CLOSE_FAILED);
                contaminated = true;
            }
            if (statement != null && !closeStatementPart(statement, open)) {
                outcome = unusable(UnusableCause.CLOSE_FAILED);
                contaminated = true;
            }
            if (touched && !restoreTimeout(connection, previous, open)) {
                outcome = unusable(UnusableCause.RESTORE_FAILED);
                contaminated = true;
            }
            if (outcome instanceof MetadataOutcome.Done && overspent()) {
                outcome = unusable(UnusableCause.OVER_BUDGET);
            }
            if (contaminated || open.error != null) {
                // Whatever state an Error left the session in is unknown, so it is treated as contaminated too.
                state.compareAndSet(LeaseState.USED, LeaseState.CONTAMINATED);
            }
        }
        if (open.error != null) {
            logEvent(EVENT_STATEMENT_ERROR, open.error);
            throw open.error;
        }
        return outcome == null ? unusable(UnusableCause.EXECUTION_FAILED) : outcome;
    }

    /** The whole seconds left; a budget clock that fails leaves none */
    private int wholeSecondsLeft() {
        try {
            return budget.wholeSeconds();
        } catch (RuntimeException e) {
            return 0;
        }
    }

    /** Whether the budget is spent; a budget clock that fails counts as spent */
    private boolean overspent() {
        try {
            return budget.isOverspent();
        } catch (RuntimeException e) {
            return true;
        }
    }

    private static boolean inAutoCommit(@Nullable Connection connection) {
        try {
            return connection != null && connection.getAutoCommit();
        } catch (Exception e) {
            return false;
        }
    }

    /** Closes a result set or a statement; false when that failed, and the session's state is then unknown */
    private boolean closeStatementPart(@NotNull AutoCloseable part, @NotNull Open open) {
        try {
            part.close();
            return true;
        } catch (Throwable t) {
            failed(EVENT_STATEMENT_CLOSE_FAILED, t, open);
            return false;
        }
    }

    /**
     * Puts the session's query timeout back, on a statement of its own
     * <p>
     * The statement that set it is closed by now. On H2 the timeout outlives it, so it has to be set
     * back through the connection; the three calls must all succeed for the session to count as restored.
     */
    private boolean restoreTimeout(@Nullable Connection connection, int previous, @NotNull Open open) {
        if (connection == null) {
            return false;
        }
        Statement restore = null;
        boolean restored = false;
        try {
            restore = connection.createStatement();
            restore.setQueryTimeout(previous);
            restored = true;
        } catch (Throwable t) {
            failed(EVENT_TIMEOUT_RESTORE_FAILED, t, open);
        } finally {
            if (restore != null) {
                try {
                    restore.close();
                } catch (Throwable t) {
                    restored = false;
                    failed(EVENT_TIMEOUT_RESTORE_FAILED, t, open);
                }
            }
        }
        return restored;
    }

    /** Logs a cleanup failure and keeps an Error among them for the template to rethrow */
    private void failed(@NotNull String eventCode, @NotNull Throwable failure, @NotNull Open open) {
        logEvent(eventCode, failure);
        if (failure instanceof Error e) {
            open.error(e);
        }
    }

    private static void bind(@NotNull PreparedStatement statement, @NotNull List<MetadataBinding> bindings) throws SQLException {
        int index = 1;
        for (MetadataBinding binding : bindings) {
            Object value = binding.value();
            switch (binding.kind()) {
                case STRING -> {
                    if (value == null) {
                        statement.setNull(index, Types.VARCHAR);
                    } else {
                        statement.setString(index, (String) value);
                    }
                }
                case TIMESTAMP_TZ -> {
                    if (value == null) {
                        statement.setNull(index, Types.TIMESTAMP_WITH_TIMEZONE);
                    } else {
                        statement.setObject(index, value);
                    }
                }
                default -> throw new SQLException("Unsupported metadata binding");
            }
            index++;
        }
    }

    /**
     * Reads the declared columns of every row into plain values, and checks the row count
     */
    @NotNull
    private static MetadataOutcome<MetadataRows> materialize(
        @NotNull ResultSet result,
        @NotNull MetadataQuery query
    ) throws SQLException {
        Map<String, MetadataColumn.Kind> kinds = new HashMap<>();
        for (MetadataColumn column : query.columns()) {
            kinds.put(column.label(), column.kind());
        }
        Map<String, MetadataColumn.Kind> declared = Map.copyOf(kinds);
        List<MetadataRow> rows = new ArrayList<>();
        while (result.next()) {
            if (rows.size() == query.maxRows()) {
                return unusable(UnusableCause.CARDINALITY);
            }
            Map<String, Object> values = new HashMap<>();
            for (MetadataColumn column : query.columns()) {
                Object value = switch (column.kind()) {
                    case STRING -> result.getString(column.label());
                    case TIMESTAMP -> result.getObject(column.label(), OffsetDateTime.class);
                    case INT -> {
                        int read = result.getInt(column.label());
                        yield result.wasNull() ? null : read;
                    }
                    case LONG -> {
                        long read = result.getLong(column.label());
                        yield result.wasNull() ? null : read;
                    }
                };
                if (value == null && !column.nullable()) {
                    return unusable(UnusableCause.MATERIALIZATION_FAILED);
                }
                values.put(column.label(), value);
            }
            rows.add(new MetadataRow(declared, values));
        }
        if (rows.size() < query.minRows()) {
            return unusable(UnusableCause.CARDINALITY);
        }
        return new MetadataOutcome.Done<>(new MetadataRows(rows));
    }

    void disposeLate(@NotNull DisposalCause cause) {
        dispose(cause);
    }

    /**
     * The one disposal: whoever moves the lease to {@code DISPOSING} does it, everyone else does nothing
     */
    private void dispose(@NotNull DisposalCause cause) {
        LeaseState from;
        while (true) {
            from = state.get();
            if (from != LeaseState.OPEN && from != LeaseState.USED && from != LeaseState.CONTAMINATED) {
                return;
            }
            if (state.compareAndSet(from, LeaseState.DISPOSING)) {
                break;
            }
        }
        Connection connection = raw;
        if (connection == null) {
            // Unreachable: a lease is published only after its connection is attached.
            logEvent(EVENT_DISPOSAL_TRIPWIRE, null);
            owner.freeSlot(slot);
            state.set(LeaseState.RETURNED);
            return;
        }
        LeaseState end;
        if (from != LeaseState.CONTAMINATED && closeQuietly(connection, EVENT_CLOSE_FAILED)) {
            end = LeaseState.RETURNED;
        } else if (abortQuietly(connection) && closeQuietly(connection, EVENT_CLOSE_AFTER_ABORT_FAILED)) {
            end = LeaseState.INVALIDATED;
        } else {
            end = owner.retain(slot, connection, cause);
        }
        if (end == LeaseState.RETURNED || end == LeaseState.INVALIDATED) {
            owner.freeSlot(slot);
        }
        state.set(end);
        owner.disposed(end);
    }

    private boolean closeQuietly(@NotNull Connection connection, @NotNull String failureEvent) {
        try {
            connection.close();
            return true;
        } catch (Throwable t) {
            logEvent(failureEvent, t);
            return false;
        }
    }

    /**
     * Aborts, and reports success only when the connection then says it is closed
     * <p>
     * Closing a connection the driver did not really abort hands it back to the pool like any other
     * close, so an abort that leaves it open - H2's, which is a no-op - counts as a failed one.
     */
    private boolean abortQuietly(@NotNull Connection connection) {
        try {
            connection.abort(Runnable::run);
        } catch (Throwable t) {
            logEvent(EVENT_ABORT_FAILED, t);
            return false;
        }
        try {
            if (connection.isClosed()) {
                return true;
            }
            logEvent(EVENT_ABORT_UNCONFIRMED, null);
        } catch (Throwable t) {
            logEvent(EVENT_ABORT_UNCONFIRMED, t);
        }
        return false;
    }

    @NotNull
    private static <T> MetadataOutcome<T> unusable(@NotNull UnusableCause cause) {
        return new MetadataOutcome.Unusable<>(cause);
    }

    /**
     * Logs an event by code, a new correlation id, the purpose and the exception class - never a message or a trace
     */
    private void logEvent(@NotNull String eventCode, @Nullable Throwable failure) {
        try {
            log.error("DBAC metadata lease event [event=" + eventCode
                + " EVENT_ID=" + UUID.randomUUID()
                + " purpose=" + purpose.name()
                + (failure == null ? "" : " exception=" + failure.getClass().getName()) + "]");
        } catch (Throwable ignored) {
            // Deliberately nothing: disposal must not depend on whether it could be logged.
        }
    }
}
