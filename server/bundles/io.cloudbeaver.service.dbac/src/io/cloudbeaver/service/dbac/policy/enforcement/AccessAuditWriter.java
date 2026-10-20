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

import io.cloudbeaver.service.dbac.policy.AuthorizationAuditPayload;
import io.cloudbeaver.service.dbac.policy.DbAccessDecision;
import io.cloudbeaver.service.dbac.policy.DbAccessPolicyConfig;
import io.cloudbeaver.service.dbac.policy.MetadataBudget;
import io.cloudbeaver.service.dbac.policy.MetadataLease;
import io.cloudbeaver.service.dbac.policy.MetadataLeaseSource;
import io.cloudbeaver.service.dbac.policy.MetadataOutcome;
import io.cloudbeaver.service.dbac.policy.MetadataPurpose;
import io.cloudbeaver.service.dbac.policy.MetadataUnavailableException;
import io.cloudbeaver.service.dbac.policy.MetadataUpdate;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.jkiss.dbeaver.Log;

import java.time.Duration;
import java.util.Objects;
import java.util.UUID;
import java.util.function.LongSupplier;

/**
 * Writes the pre-execution audit row: {@code WRITE_ALLOWED} before a write, {@code WRITE_DENIED} for one refused
 * <p>
 * <b>One row, one auto-commit {@code INSERT}, through a metadata lease.</b> The lease is the only way
 * in: it refuses a connection that is not in auto-commit, sets the remaining budget as the query
 * timeout and puts it back, and hands back {@code Done} only for exactly the declared count within the
 * budget. So {@link AuditOutcome#RECORDED} means the row was committed and is visible to every other
 * connection before this returns - and nothing more: whether it is on disk is the metadata database's
 * setting. Anything else is {@link AuditOutcome#FAILED}.
 * <p>
 * <b>What a row says.</b> {@code WRITE_ALLOWED} records that authorization and this audit passed
 * before the write was handed to the platform. It says nothing about whether, or how, the operation
 * then ran: the writer is called before it, and nothing here can record what happened after.
 * {@code WRITE_DENIED} records an attempt refused before the platform was called - also when it
 * corrects an earlier {@code WRITE_ALLOWED} of the same attempt, under an id of its own. The writer
 * cannot know whether the platform was called; deciding that a correction is due is the enforcement
 * gate's job, and so is never calling the writer once the platform has been.
 * <p>
 * <b>Nothing but the payload reaches a row.</b> The columns are the {@link AuditEventId}, the event
 * type, the database's own {@code CURRENT_TIMESTAMP} and the payload's fields; {@code ACTOR_ID} is the
 * payload's user and {@code STATEMENT_TYPE} is {@code NULL}. There is no parameter through which a
 * statement, a parameter value, a URL, a host, a user name, a password, a token or a message could
 * arrive.
 * <p>
 * <b>Nothing escapes.</b> Neither method throws. A refused borrow, an unusable statement, a
 * {@code RuntimeException} and an {@code Error} - a {@code VirtualMachineError} included - all become
 * {@code FAILED}, logged with a fixed event code, a new {@code EVENT_ID}, the row's id and a fixed
 * failure name or an exception class: never the exception, its message or its stack trace. Swallowing
 * a {@code VirtualMachineError} is a deliberate trade, recorded as accepted risk R27 apart from the
 * taint handler's R25: the attempt is refused - an unrecorded allow is never acted on - but the JVM
 * carries on after an {@code OutOfMemoryError} its caller does not see. A log write that fails is
 * ignored and changes no outcome.
 * <p>
 * <b>No locks, no callbacks.</b> The writer holds no grant, user, context or instance lock and runs
 * no code it was handed; it takes only the lease the source gives it. Thread-safe: it keeps nothing
 * between calls.
 */
public final class AccessAuditWriter {

    private static final Log log = Log.getLog(AccessAuditWriter.class);

    /** Logged when a row was not recorded; fixed, so it can be searched for */
    static final String EVENT_AUDIT_WRITE_FAILED = "DBAC_AUDIT_WRITE_FAILED";

    /** {@code EVENT_TYPE} of a row recorded before a write */
    static final String WRITE_ALLOWED = "WRITE_ALLOWED";
    /** {@code EVENT_TYPE} of a row recorded for a refused attempt */
    static final String WRITE_DENIED = "WRITE_DENIED";

    private static final String INSERT = "INSERT INTO {table_prefix}DBAC_AUDIT_EVENT"
        + " (EVENT_ID, EVENT_TYPE, EVENT_TIME, USER_ID, ACTOR_ID, PROJECT_ID, CONNECTION_ID, GRANT_ID,"
        + " OPERATION_CATEGORY, STATEMENT_TYPE, DECISION, DENIAL_REASON, EXPIRES_AT)"
        + " VALUES (?, ?, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)";

    /** Why a row was not recorded, as the log names it */
    private enum Failure {
        /** An argument was missing; nothing was attempted */
        MISSING_ARGUMENT,
        /** The payload records the other decision; nothing was attempted */
        WRONG_DECISION,
        /** The budget is not {@code T_audit}, so it is not the one check-1 reserved; nothing was attempted */
        NOT_THE_AUDIT_BUDGET,
        /** No lease could be had */
        NO_LEASE,
        /** The lease's statement produced nothing usable */
        NOT_DONE,
        /** Something threw */
        THREW
    }

    private final MetadataLeaseSource leases;
    private final Duration auditTimeout;
    private final LongSupplier deniedClock;

    /**
     * A writer over the metadata database's leases, measuring a denial's budget with {@code System::nanoTime}
     */
    public AccessAuditWriter(@NotNull MetadataLeaseSource leases, @NotNull DbAccessPolicyConfig config) {
        this(leases, config, System::nanoTime);
    }

    /**
     * The same, measuring a denial's budget with {@code deniedClock}
     *
     * @param deniedClock a monotonic nanosecond counter for the budget {@link #recordDenied} gives itself.
     *     An allow's budget comes from the expiry window and carries the window's clock.
     */
    public AccessAuditWriter(
        @NotNull MetadataLeaseSource leases,
        @NotNull DbAccessPolicyConfig config,
        @NotNull LongSupplier deniedClock
    ) {
        this.leases = Objects.requireNonNull(leases, "leases");
        this.auditTimeout = Objects.requireNonNull(config, "config").auditTimeout();
        this.deniedClock = Objects.requireNonNull(deniedClock, "deniedClock");
    }

    /**
     * Records {@code WRITE_ALLOWED}, before the write is handed to the platform
     * <p>
     * Authorization and this audit passed before execution; the row says nothing about whether or how
     * the operation ran. Only {@code RECORDED} lets the attempt go on to check-2.
     *
     * @param auditBudget the attempt's budget, as {@code ExpiryWindow.claimAuditBudget()} hands it out:
     *     {@code T_audit} from check-1's reading, for the borrow and the insert together. A budget of
     *     any other size is refused without trying.
     * @return {@code RECORDED} only when the row is committed and visible; never null, never thrown
     */
    @NotNull
    public AuditOutcome recordAllowedBeforeExecution(
        @NotNull AuditEventId eventId,
        @NotNull AuthorizationAuditPayload payload,
        @NotNull MetadataBudget auditBudget
    ) {
        try {
            if (eventId == null || payload == null || auditBudget == null) {
                return failed(eventId, WRITE_ALLOWED, Failure.MISSING_ARGUMENT, null, null);
            }
            if (payload.decision() != DbAccessDecision.ALLOW) {
                return failed(eventId, WRITE_ALLOWED, Failure.WRONG_DECISION, null, null);
            }
            if (!auditTimeout.equals(auditBudget.total())) {
                return failed(eventId, WRITE_ALLOWED, Failure.NOT_THE_AUDIT_BUDGET, null, null);
            }
            return insert(eventId, WRITE_ALLOWED, payload, auditBudget);
        } catch (Throwable t) {
            return failed(eventId, WRITE_ALLOWED, Failure.THREW, null, t.getClass().getName());
        }
    }

    /**
     * Records {@code WRITE_DENIED} for an attempt refused before the platform was called
     * <p>
     * Within a budget of {@code T_audit} of its own, from now. A {@code FAILED} here changes nothing
     * about the denial: the caller keeps the decision it already has.
     *
     * @return {@code RECORDED} only when the row is committed and visible; never null, never thrown
     */
    @NotNull
    public AuditOutcome recordDenied(@NotNull AuditEventId eventId, @NotNull AuthorizationAuditPayload payload) {
        try {
            if (eventId == null || payload == null) {
                return failed(eventId, WRITE_DENIED, Failure.MISSING_ARGUMENT, null, null);
            }
            if (payload.decision() != DbAccessDecision.DENY) {
                return failed(eventId, WRITE_DENIED, Failure.WRONG_DECISION, null, null);
            }
            return insert(eventId, WRITE_DENIED, payload, MetadataBudget.startingNow(deniedClock, auditTimeout));
        } catch (Throwable t) {
            return failed(eventId, WRITE_DENIED, Failure.THREW, null, t.getClass().getName());
        }
    }

    /**
     * The one insert; the verdict is settled inside the lease's block, before the lease is closed
     */
    @NotNull
    private AuditOutcome insert(
        @NotNull AuditEventId eventId,
        @NotNull String eventType,
        @NotNull AuthorizationAuditPayload payload,
        @NotNull MetadataBudget budget
    ) {
        MetadataUpdate update = MetadataUpdate.sql(INSERT)
            .bindString(eventId.value())
            .bindString(eventType)
            .bindString(payload.userId())
            // ACTOR_ID: the user the decision is about is the one acting; there is no other actor yet.
            .bindString(payload.userId())
            .bindString(payload.projectId())
            .bindString(payload.connectionId())
            .bindString(payload.grantId())
            .bindString(payload.operationCategory().name())
            .bindString(payload.decision().name())
            .bindString(payload.denialReason() == null ? null : payload.denialReason().name())
            .bindTimestamp(payload.expiresAt())
            .expectUpdateCount(1)
            .build();
        try (MetadataLease lease = leases.open(budget, MetadataPurpose.AUDIT)) {
            MetadataOutcome<Long> outcome = lease.update(update);
            // Only Done counts; anything else - Unusable today, whatever else tomorrow - is not a recorded row.
            if (outcome instanceof MetadataOutcome.Done<Long>) {
                return AuditOutcome.RECORDED;
            }
            String cause = outcome instanceof MetadataOutcome.Unusable<Long> unusable ? unusable.cause().name() : null;
            return failed(eventId, eventType, Failure.NOT_DONE, cause, null);
        } catch (MetadataUnavailableException e) {
            return failed(eventId, eventType, Failure.NO_LEASE, e.reason().name(), e.failureClass());
        }
    }

    /**
     * Logs a row that was not recorded, and says so
     * <p>
     * A fixed event code, a correlation id new for this log entry, the row's own id, which row it was,
     * a fixed failure name and, at most, a fixed detail name and an exception class. Never the
     * exception, its message, a stack trace, a key, a user, a statement or a URL. Never throws: the
     * outcome must not depend on whether it could be logged.
     */
    @NotNull
    private static AuditOutcome failed(
        @Nullable AuditEventId eventId,
        @NotNull String eventType,
        @NotNull Failure failure,
        @Nullable String detail,
        @Nullable String exceptionClass
    ) {
        try {
            log.error("DBAC audit row not recorded [event=" + EVENT_AUDIT_WRITE_FAILED
                + " EVENT_ID=" + UUID.randomUUID()
                + " AUDIT_EVENT_ID=" + (eventId == null ? "<none>" : eventId.value())
                + " record=" + eventType
                + " failure=" + failure.name()
                + (detail == null ? "" : " detail=" + detail)
                + (exceptionClass == null ? "" : " exception=" + exceptionClass) + "]");
        } catch (Throwable ignored) {
            // Deliberately nothing: the outcome is FAILED whether or not it could be logged.
        }
        return AuditOutcome.FAILED;
    }
}
