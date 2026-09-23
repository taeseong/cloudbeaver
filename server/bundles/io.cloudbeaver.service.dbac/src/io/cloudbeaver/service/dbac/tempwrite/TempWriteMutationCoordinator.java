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
package io.cloudbeaver.service.dbac.tempwrite;

import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.jkiss.dbeaver.Log;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Applies a grant or a revoke to the metadata database under compare-and-set
 * <p>
 * This is the layer that decides, and the only one that opens transactions. It contains no policy:
 * whether the caller may grant, whether the duration is acceptable and whether the target is a real
 * connection are all decided above it.
 * <p>
 * <b>The fixed start revision.</b> Every request carries the revision its caller observed when the
 * request was accepted, and that value is never refreshed - not between attempts, not after a lost
 * race. Each attempt re-reads the stored revision and refuses the request outright if it has moved.
 * This is what stops a grant transaction that was overtaken by a revoke from committing afterwards
 * and bringing the old permission back: to succeed it would have to adopt the revision the revoke
 * produced, and it is not allowed to.
 * <p>
 * <b>Retrying.</b> A lost compare-and-set is normally not retried, because losing means the revision
 * moved, which is a refusal. Retrying is reserved for the narrow case where the write failed while
 * the revision is still the value the request started from: a competing writer that rolled back, a
 * lock timeout, a deadlock. Even then the retry happens in a new transaction - never inside the
 * failed one, which PostgreSQL leaves aborted so that every later statement fails - and the new
 * transaction re-checks the fixed start revision before writing anything. Past
 * {@link #MAX_TRANSIENT_RETRIES} the request fails with nothing applied.
 * <p>
 * <b>Atomicity, including when the rollback fails.</b> The current row and its history events are
 * written in one transaction and committed together. The catch covers unchecked failures as well as
 * {@code SQLException}, because an unchecked one would otherwise leave the transaction open. And a
 * rollback that itself fails is terminal: {@link MetadataTransaction} marks the connection poisoned,
 * the failure is attached to the exception the caller receives rather than logged and dropped, and
 * the request is not retried. See {@link MetadataTransaction} for why the platform's
 * {@code JDBCTransaction} is not used - its {@code close()} restores auto-commit unconditionally,
 * which JDBC turns into a commit of exactly the half-written state that must not be stored.
 */
public class TempWriteMutationCoordinator {

    /**
     * How many extra attempts a request gets while the revision it started from still stands
     * <p>
     * The limit exists so contention cannot turn into an unbounded loop against the metadata
     * database. Exceeding it fails the request rather than forcing a write through.
     */
    public static final int MAX_TRANSIENT_RETRIES = 3;

    /**
     * States that mean "this write lost a race", not "this write is wrong"
     * <p>
     * These are the states the earlier slice measured while forcing concurrent writers against real
     * H2 and PostgreSQL, not a guess at what a driver might raise. Losing the first insert on a key
     * surfaces as a unique violation; losing a row that another transaction holds surfaces as a
     * deadlock, a serialization failure, a lock timeout or H2's concurrent-update error, depending on
     * which engine noticed and when.
     * <p>
     * Listing a state here only permits another look. Whether the request may then proceed is still
     * decided by the fixed start revision, so treating some unrelated failure as contention costs a
     * few wasted attempts and ends in a fail-closed refusal - it cannot let a write through. A state
     * left out of the list is the riskier mistake: it would propagate as an error where the right
     * answer was a conflict.
     */
    private static final Set<String> TRANSIENT_SQL_STATES = Set.of(
        "23505", // unique_violation - both engines, a concurrent first insert on the same key
        "40001", // serialization_failure on PostgreSQL, deadlock on H2
        "40P01", // deadlock_detected - PostgreSQL
        "55P03", // lock_not_available - PostgreSQL
        "90131", // concurrent update in table - H2
        "HYT00"  // lock timeout - H2
    );

    /** Bound on how far a driver may nest or chain exceptions before the walk gives up. */
    private static final int MAX_EXCEPTION_CHAIN_DEPTH = 16;

    private static final Log log = Log.getLog(TempWriteMutationCoordinator.class);

    private final MetadataConnectionSource connectionSource;
    private final TempWriteGrantRepository repository;
    private final TempWriteAuditSink auditSink;

    /**
     * Builds a coordinator that records nothing, which every caller has to ask for by name
     * <p>
     * A two-argument constructor used to do this silently. That is a trap worth removing before it
     * can be walked into: once an audit layer exists, a production caller reaching for the shortest
     * constructor would get a coordinator that grants and revokes TEMP_WRITE with no record of it,
     * and nothing at the call site would say so. Naming it makes the absence of auditing a decision
     * somebody wrote down.
     */
    @NotNull
    public static TempWriteMutationCoordinator withoutAuditing(
        @NotNull MetadataConnectionSource connectionSource,
        @NotNull TempWriteGrantRepository repository
    ) {
        return new TempWriteMutationCoordinator(connectionSource, repository, TempWriteAuditSink.NONE);
    }

    /**
     * Builds a coordinator that audits every committed transition in the transition's own transaction
     *
     * @param auditSink called after the row and its history are written and before the commit, so a
     *     failure to audit rolls the transition back instead of leaving it unrecorded
     */
    public TempWriteMutationCoordinator(
        @NotNull MetadataConnectionSource connectionSource,
        @NotNull TempWriteGrantRepository repository,
        @NotNull TempWriteAuditSink auditSink
    ) {
        this.connectionSource = connectionSource;
        this.repository = repository;
        this.auditSink = auditSink;
    }

    /**
     * Makes a grant the current state of its key
     * <p>
     * Inserts at revision 1 when the key has no row, otherwise replaces the row conditionally on the
     * revision. Replacing a grant that was still active also records a {@code SUPERSEDED} event for
     * it, in the same transaction as the {@code GRANTED} event of the new one, so the two are never
     * seen apart.
     *
     * @return what happened; a refusal is a value, not an exception
     * @throws SQLException if the metadata database fails for a reason that is not contention
     */
    @NotNull
    public TempWriteMutationResult grant(@NotNull TempWriteGrantRequest request) throws SQLException {
        int attempt = 0;
        while (true) {
            attempt++;
            Optional<TempWriteMutationResult> outcome = attemptGrant(request, attempt);
            if (outcome.isPresent()) {
                return outcome.get();
            }
            if (attempt > MAX_TRANSIENT_RETRIES) {
                log.warn("TEMP_WRITE grant gave up after " + attempt + " attempts on unchanged revision "
                    + request.observedRevisionAtRequestStart());
                return TempWriteMutationResult.retryExhausted(attempt);
            }
        }
    }

    /**
     * Ends an active grant before its expiry
     * <p>
     * Revoking a key with no row, or one already revoked, is a successful no-op that writes nothing
     * and appends no history - there was no transition to record. That makes a duplicated or retried
     * revoke harmless and keeps the first revoke as the one on record.
     *
     * @return what happened; a refusal is a value, not an exception
     * @throws SQLException if the metadata database fails for a reason that is not contention
     */
    @NotNull
    public TempWriteMutationResult revoke(@NotNull TempWriteRevokeRequest request) throws SQLException {
        int attempt = 0;
        while (true) {
            attempt++;
            Optional<TempWriteMutationResult> outcome = attemptRevoke(request, attempt);
            if (outcome.isPresent()) {
                return outcome.get();
            }
            if (attempt > MAX_TRANSIENT_RETRIES) {
                log.warn("TEMP_WRITE revoke gave up after " + attempt + " attempts on unchanged revision "
                    + request.observedRevisionAtRequestStart());
                return TempWriteMutationResult.retryExhausted(attempt);
            }
        }
    }

    /**
     * One grant transaction
     *
     * @return the outcome, or empty when the write lost a race and the caller should look again
     */
    @NotNull
    private Optional<TempWriteMutationResult> attemptGrant(
        @NotNull TempWriteGrantRequest request,
        int attempt
    ) throws SQLException {
        try (Connection connection = connectionSource.openConnection();
             MetadataTransaction txn = new MetadataTransaction(connection)
        ) {
            try {
                Optional<TempWriteGrant> current = repository.findCurrent(connection, request.key());
                long observed = observedRevision(current);
                if (observed != request.observedRevisionAtRequestStart()) {
                    txn.rollback();
                    return Optional.of(TempWriteMutationResult.superseded(attempt));
                }
                MetadataDbTime dbNow = MetadataDbClock.readNow(connection);
                long newRevision = observed + 1;
                TempWriteGrant grant = grantRow(request, newRevision, dbNow);
                int affected = current.isPresent()
                    ? repository.updateCurrentWithRevision(connection, grant, observed)
                    : repository.insertCurrent(connection, grant);
                if (affected != 1) {
                    txn.rollback();
                    return Optional.empty();
                }
                if (current.isPresent() && !current.get().isRevoked()) {
                    repository.appendHistory(
                        connection, supersededEvent(current.get(), request.grantedBy(), dbNow, newRevision));
                }
                repository.appendHistory(connection, grantedEvent(grant, dbNow));
                auditSink.record(
                    connection, TempWriteChangeType.GRANTED, grant, request.grantedBy(), dbNow);
                txn.commit();
                return Optional.of(
                    TempWriteMutationResult.committed(newRevision, request.grantId(), attempt));
            } catch (SQLException | RuntimeException | Error e) {
                if (!txn.rollbackRecording(e)) {
                    throw e;
                }
                if (e instanceof SQLException sqlFailure && isTransientConflict(sqlFailure)) {
                    return Optional.empty();
                }
                throw e;
            }
        }
    }

    /**
     * One revoke transaction
     *
     * @return the outcome, or empty when the write lost a race and the caller should look again
     */
    @NotNull
    private Optional<TempWriteMutationResult> attemptRevoke(
        @NotNull TempWriteRevokeRequest request,
        int attempt
    ) throws SQLException {
        try (Connection connection = connectionSource.openConnection();
             MetadataTransaction txn = new MetadataTransaction(connection)
        ) {
            try {
                Optional<TempWriteGrant> current = repository.findCurrent(connection, request.key());
                long observed = observedRevision(current);
                if (observed != request.observedRevisionAtRequestStart()) {
                    txn.rollback();
                    return Optional.of(TempWriteMutationResult.superseded(attempt));
                }
                if (current.isEmpty() || current.get().isRevoked()) {
                    txn.rollback();
                    return Optional.of(TempWriteMutationResult.noOp(attempt));
                }
                MetadataDbTime dbNow = MetadataDbClock.readNow(connection);
                long newRevision = observed + 1;
                int affected = repository.revokeCurrentWithRevision(
                    connection, request.key(), observed, newRevision, dbNow,
                    request.revokedBy(), request.revokeReason());
                if (affected != 1) {
                    txn.rollback();
                    return Optional.empty();
                }
                repository.appendHistory(
                    connection, revokedEvent(current.get(), request, dbNow, newRevision));
                TempWriteGrant revoked = current.get().asRevoked(
                    newRevision, dbNow, request.revokedBy(), request.revokeReason());
                auditSink.record(
                    connection, TempWriteChangeType.REVOKED, revoked, request.revokedBy(), dbNow);
                txn.commit();
                return Optional.of(
                    TempWriteMutationResult.committed(newRevision, current.get().grantId(), attempt));
            } catch (SQLException | RuntimeException | Error e) {
                if (!txn.rollbackRecording(e)) {
                    throw e;
                }
                if (e instanceof SQLException sqlFailure && isTransientConflict(sqlFailure)) {
                    return Optional.empty();
                }
                throw e;
            }
        }
    }

    private static long observedRevision(@NotNull Optional<TempWriteGrant> current) {
        return current.map(TempWriteGrant::revision).orElse(TempWriteGrant.NO_ROW_REVISION);
    }

    @NotNull
    private static TempWriteGrant grantRow(
        @NotNull TempWriteGrantRequest request,
        long revision,
        @NotNull MetadataDbTime dbNow
    ) {
        return new TempWriteGrant(
            request.key(),
            request.grantId(),
            revision,
            request.grantedBy(),
            dbNow,
            dbNow.plus(request.duration()),
            request.reason(),
            null,
            null,
            null,
            request.endpoint());
    }

    /**
     * Builds the {@code GRANTED} event of a committed grant
     * <p>
     * Carries the revision the current row now holds, which is what lets a reader order events
     * without trusting the clock.
     */
    @NotNull
    private static TempWriteHistoryEvent grantedEvent(
        @NotNull TempWriteGrant grant,
        @NotNull MetadataDbTime dbNow
    ) {
        return new TempWriteHistoryEvent(
            newEventId(),
            grant.grantId(),
            TempWriteChangeType.GRANTED,
            dbNow,
            grant.key(),
            grant.grantedBy(),
            grant.expiresAt(),
            grant.reason(),
            grant.revision());
    }

    /**
     * Builds the {@code SUPERSEDED} event of the grant a new one replaced
     * <p>
     * Recorded with the revision of the transition that replaced it, the same one the accompanying
     * {@code GRANTED} event carries, so both rows of a replacement share a revision and are read as
     * one transition.
     */
    @NotNull
    private static TempWriteHistoryEvent supersededEvent(
        @NotNull TempWriteGrant replaced,
        @NotNull String actorId,
        @NotNull MetadataDbTime dbNow,
        long revision
    ) {
        return new TempWriteHistoryEvent(
            newEventId(),
            replaced.grantId(),
            TempWriteChangeType.SUPERSEDED,
            dbNow,
            replaced.key(),
            actorId,
            replaced.expiresAt(),
            replaced.reason(),
            revision);
    }

    @NotNull
    private static TempWriteHistoryEvent revokedEvent(
        @NotNull TempWriteGrant revoked,
        @NotNull TempWriteRevokeRequest request,
        @NotNull MetadataDbTime dbNow,
        long revision
    ) {
        return new TempWriteHistoryEvent(
            newEventId(),
            revoked.grantId(),
            TempWriteChangeType.REVOKED,
            dbNow,
            revoked.key(),
            request.revokedBy(),
            revoked.expiresAt(),
            request.revokeReason(),
            revision);
    }

    @NotNull
    private static String newEventId() {
        return UUID.randomUUID().toString();
    }

    /**
     * Whether a failure means the write lost a race rather than that it was invalid
     * <p>
     * Checks the whole chain, because a driver may wrap the state-carrying exception. A true answer
     * only permits another look: the request still has to pass the fixed start revision check, so
     * mistaking some other integrity violation for contention costs a few wasted attempts and then
     * fails closed - it cannot let a write through.
     */
    private static boolean isTransientConflict(@Nullable SQLException error) {
        SQLException current = error;
        for (int depth = 0; current != null && depth < MAX_EXCEPTION_CHAIN_DEPTH; depth++) {
            if (TRANSIENT_SQL_STATES.contains(current.getSQLState())) {
                return true;
            }
            SQLException next = current.getNextException();
            if (next == null && current.getCause() instanceof SQLException nested) {
                next = nested;
            }
            current = next == current ? null : next;
        }
        return false;
    }
}
