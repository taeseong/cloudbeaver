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

import io.cloudbeaver.service.dbac.tempwrite.EndpointSnapshot;
import io.cloudbeaver.service.dbac.tempwrite.MetadataConnectionSource;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.jkiss.dbeaver.Log;
import org.jkiss.dbeaver.model.DBPDataSourceContainer;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.time.Clock;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.UUID;
import java.util.function.LongSupplier;

/**
 * Decides whether one write may proceed
 * <p>
 * The single entry point Phase 2 section 6 specifies. It answers a question and returns a value; it
 * does not throw for a denial, does not write anything, and does not remember anything between calls.
 * <p>
 * <b>No cache, deliberately.</b> Every call reads the metadata database again. Phase 2 section 12.4
 * forbids a permission cache in the first Phase 3 implementation, and section 8.2 explains what that
 * buys: because there is no cached answer, the first operation after a revoke commits is denied - in
 * the same session, the same editor, the same connection, with no reconnect and no re-login. A cache
 * would turn "immediately" into "eventually", and there is no correct TTL for a security decision.
 * <p>
 * <b>What this slice does not decide.</b> Transaction state (Phase 2 section 9) and the pre-execution
 * audit (section 11) are later slices. The corresponding denial reasons exist in {@link DenialReason}
 * so their arrival does not reshape this API, but nothing here evaluates them, and this class does
 * not claim to. {@code executionContextId} and {@code autoCommit} travel on the request unread.
 * <p>
 * <b>The expiry margin is not applied by {@code authorize}.</b> It answers whether the grant is
 * unexpired by the database's own comparison, and reports how long it has left. Whether that is
 * enough for the write to reach the target is decided by an {@link ExpiryWindow}: an enforcement
 * point opens one with {@link #openExpiryWindow}, authorizes through it with
 * {@link ExpiryWindow#authorize}, and runs its two checks. That is the only route that applies the
 * margin, and every enforcement point must take it.
 * <p>
 * <b>Nothing calls this yet.</b> No production path invokes {@code authorize} or
 * {@code openExpiryWindow}. Until an enforcement point does, a running server behaves exactly as it
 * did before: this class decides nothing that anybody acts on.
 */
public final class DbAccessPolicyService {

    private static final Log log = Log.getLog(DbAccessPolicyService.class);

    /** Logged when the permission store could not be read; fixed, so it can be searched for */
    private static final String EVENT_STORE_READ_FAILED = "DBAC_PERMISSION_STORE_READ_FAILED";
    /** Logged when anything else failed while authorizing */
    private static final String EVENT_AUTHORIZATION_FAILED = "DBAC_AUTHORIZATION_FAILED";
    /** Stands in for the key when the failure came before identity was resolved */
    private static final String KEY_UNRESOLVED = "<unresolved>";

    private final MetadataConnectionSource connectionSource;
    private final DbAccessPolicyConfig config;
    private final Clock localClock;
    private final LongSupplier monotonicClock;

    /**
     * Builds a service that takes every fact it decides on from the metadata database
     *
     * @param connectionSource where a metadata connection comes from. Must hand out connections from
     *     {@code CBDatabase.openConnection()} so that {@code {table_prefix}} is substituted and the
     *     connection is in auto-commit.
     * @param localClock this node's clock. Used <b>only</b> to measure how far it has drifted from
     *     the database's, never to decide whether a grant has expired or how long it has left.
     * @param monotonicClock a monotonic nanosecond counter, {@code System::nanoTime} in production.
     *     Used <b>only</b> by {@link ExpiryWindow} to measure elapsed time, and never
     *     read by {@code authorize}.
     */
    public DbAccessPolicyService(
        @NotNull MetadataConnectionSource connectionSource,
        @NotNull DbAccessPolicyConfig config,
        @NotNull Clock localClock,
        @NotNull LongSupplier monotonicClock
    ) {
        this.connectionSource = connectionSource;
        this.config = config;
        this.localClock = localClock;
        this.monotonicClock = monotonicClock;
    }

    /**
     * The same, measuring elapsed time with {@code System::nanoTime}
     */
    public DbAccessPolicyService(
        @NotNull MetadataConnectionSource connectionSource,
        @NotNull DbAccessPolicyConfig config,
        @NotNull Clock localClock
    ) {
        this(connectionSource, config, localClock, System::nanoTime);
    }

    public DbAccessPolicyService(
        @NotNull MetadataConnectionSource connectionSource,
        @NotNull DbAccessPolicyConfig config
    ) {
        this(connectionSource, config, Clock.systemUTC(), System::nanoTime);
    }

    /**
     * The decision
     * <p>
     * The order below is fixed and pinned by tests, because it is not only about which answer comes
     * out - it is about what work happens before an answer is refused. Everything that can be
     * decided from the request alone is decided first, so a request with no identity, an
     * unauthorized category or an unsupported database never opens a metadata connection, and never
     * touches the customer's database either.
     * <ol>
     *   <li>Rollback is allowed without any evaluation (Phase 2 section 12.3)</li>
     *   <li>The category must be one this gate authorizes</li>
     *   <li>Identity and container: user, project, connection, not anonymous, still in the registry</li>
     *   <li>The target database must be PostgreSQL or MySQL</li>
     *   <li>One metadata statement: clock, user, grant, revocation, expiry, snapshot</li>
     *   <li>The user must exist and be active</li>
     *   <li>A current grant must exist</li>
     *   <li>It must not have expired, by the database's own comparison</li>
     *   <li>It must not have been revoked</li>
     *   <li>Its connection snapshot must still match</li>
     *   <li>This node's clock must be close enough to the database's</li>
     *   <li>The grant must have time left by the database's own two values</li>
     * </ol>
     * Steps 8 and 9 are in that order because Phase 2 section 4 marks expiry as taking precedence
     * ("만료 우선") when a grant is both expired and revoked. Both deny; only the reported reason
     * differs. The slice instructions suggested the opposite order, so the choice is written down
     * here and pinned by a test rather than left to whichever branch was typed first.
     * <p>
     * An allow carries {@code EXPIRES_AT - DB_NOW} as its remaining lifetime, and nothing more is
     * asked of it here: a grant with a microsecond left is allowed. The margin that makes a
     * microsecond not enough is the {@link ExpiryWindow}'s to apply.
     * <p>
     * <b>An enforcement point must not call this directly.</b> It authorizes through
     * {@link ExpiryWindow#authorize} on a window opened for that attempt, which calls this method and
     * keeps the answer for its checks. Called on its own, this applies no margin at all.
     *
     * @return never null, never an exception for an ordinary denial
     */
    @NotNull
    public AuthorizationDecision authorize(@NotNull WriteAuthorizationRequest request) {
        if (request == null) {
            // Not a denial. A caller that has no request has not asked a question, and answering
            // "denied" would let a wiring mistake read as a policy outcome that could be logged,
            // audited and explained to a user as though a real attempt had been refused.
            throw new IllegalArgumentException("An authorization request is required");
        }
        DbOperationCategory category = request.operationCategory();
        if (category == null) {
            // The request type refuses this at construction, so reaching it means the request is not
            // one of ours. Thrown rather than denied for the same reason as a null request, and
            // because every shape rule a decision is checked against is expressed in terms of the
            // category - there is no decision that could be built to carry this failure.
            throw new IllegalArgumentException("An authorization request must say what is being attempted");
        }
        // Held outside the try so that an unexpected failure after identity was established can
        // still say who it was about. An audit row with no subject is the least useful kind.
        DbAccessKey resolvedKey = null;
        try {
            // 1. Rollback is how a caller escapes trouble; it is never judged.
            if (category.gate() == DbOperationCategory.Gate.RECOVERY) {
                return AuthorizationDecision.allowRecovery(category);
            }
            // 2. A category that is not write-gated has no business reaching the write gate. Saying
            //    "allowed" here would let a wiring mistake read as a permission.
            if (!category.requiresWriteAuthorization()) {
                return AuthorizationDecision.denyBeforeKey(DenialReason.OPERATION_UNSUPPORTED, category);
            }

            // 3. Identity and container, before any lookup.
            ContainerIdentityResolver.Resolved resolved =
                ContainerIdentityResolver.resolve(request.userId(), request.container());
            if (!resolved.ok()) {
                return AuthorizationDecision.denyBeforeKey(resolved.failure(), category);
            }
            DbAccessKey key = resolved.key();
            resolvedKey = key;
            DBPDataSourceContainer container = request.container();

            // 4. Target database. Checked before the metadata read so an unsupported connection
            //    costs nothing. The key is carried into the denial rather than dropped: "this user
            //    tried to write to a database outside the supported set, on this connection" is
            //    exactly the event an operator needs to see, and it is already known here.
            if (!SupportedTargetDatabase.isSupported(container.getDriver())) {
                return AuthorizationDecision.deny(
                    DenialReason.DBMS_UNSUPPORTED, key, category, null, null);
            }

            // 5. The connection has to be one whose physical target can be identified from stored
            //    configuration. A custom URL, an enabled network handler, a config profile, a driver
            //    substitution, a routing property, a variable expression or a missing host, port or
            //    database all make that impossible, and are refused rather than guessed at.
            EndpointFingerprints.Result endpoint = EndpointFingerprints.of(container);
            if (!endpoint.ok()) {
                return AuthorizationDecision.deny(endpoint.failure(), key, category, null, null);
            }

            // 6. One statement, one linearization point.
            PolicySnapshot snapshot;
            try (Connection connection = connectionSource.openConnection()) {
                snapshot = PolicySnapshotRepository.read(connection, key);
            } catch (Exception e) {
                // Every failure to read is the same answer. An outage must never be mistaken for
                // "this user has no grant", so it is not allowed to fall through to step 7.
                logFailure(EVENT_STORE_READ_FAILED, "DBAC could not read the permission store", key, e);
                return AuthorizationDecision.deny(
                    DenialReason.PERMISSION_STORE_UNAVAILABLE, key, category, null, null);
            }

            // 7. The user must exist and be enabled.
            if (!snapshot.userRowPresent() || !snapshot.userActive()) {
                return AuthorizationDecision.deny(DenialReason.USER_INACTIVE, key, category, null, null);
            }
            // 8. A grant must exist at all.
            if (!snapshot.hasGrant()) {
                return AuthorizationDecision.deny(DenialReason.NO_GRANT, key, category, null, null);
            }

            String grantId = snapshot.grantId();
            OffsetDateTime expiresAt = snapshot.expiresAt();

            // 9. Expiry, decided by the database.
            if (!snapshot.notExpired()) {
                return AuthorizationDecision.deny(DenialReason.GRANT_EXPIRED, key, category, grantId, expiresAt);
            }
            // 10. Revocation.
            if (snapshot.revoked()) {
                return AuthorizationDecision.deny(DenialReason.GRANT_REVOKED, key, category, grantId, expiresAt);
            }
            // 11. The grant must still describe this endpoint - both the stored configuration and
            //     the one the connection was actually opened against. A stored side that cannot say -
            //     a row written before schema version 3 - is a mismatch, not a wildcard.
            EndpointSnapshot stored = snapshot.storedSnapshot();
            if (stored == null || !endpoint.matches(stored)) {
                return AuthorizationDecision.deny(DenialReason.GRANT_STALE, key, category, grantId, expiresAt);
            }
            // 12. This node's clock must be usable.
            if (skewExceeded(snapshot.dbNow())) {
                return AuthorizationDecision.deny(
                    DenialReason.CLOCK_SKEW_EXCEEDED, key, category, grantId, expiresAt);
            }

            if (expiresAt == null) {
                // Unreachable against the schema, which makes EXPIRES_AT NOT NULL. Denied rather
                // than dereferenced, because an allow has to name when it stops being valid.
                return AuthorizationDecision.deny(
                    DenialReason.PERMISSION_STORE_UNAVAILABLE, key, category, grantId, null);
            }
            // 13. How long the grant has left, from the same two values step 9's comparison was made on
            //     - never from this node's clock and never from the monotonic one. Step 9 found
            //     EXPIRES_AT > DB_NOW, so this is positive unless the statement's verdict and its own
            //     values disagree. A store that contradicts itself is a store that cannot be relied on.
            Duration remaining = Duration.between(snapshot.dbNow(), expiresAt);
            if (remaining.isNegative() || remaining.isZero()) {
                return AuthorizationDecision.deny(
                    DenialReason.PERMISSION_STORE_UNAVAILABLE, key, category, grantId, expiresAt);
            }
            return AuthorizationDecision.allow(key, category, grantId, expiresAt, remaining);
        } catch (RuntimeException | Error e) {
            // Nothing unexpected is allowed to become an allow, and nothing is allowed to escape
            // and be caught by a caller that might carry on. Both become the same denial - but the
            // denial keeps the key when one was already established, so the event is auditable
            // against a subject. A failure inside a driver accessor or a clock, after identity was
            // resolved, is exactly the event worth attributing.
            logFailure(EVENT_AUTHORIZATION_FAILED, "DBAC authorization failed unexpectedly", resolvedKey, e);
            return resolvedKey == null
                ? AuthorizationDecision.denyBeforeKey(DenialReason.PERMISSION_STORE_UNAVAILABLE, category)
                : AuthorizationDecision.deny(
                    DenialReason.PERMISSION_STORE_UNAVAILABLE, resolvedKey, category, null, null);
        }
    }

    /**
     * Whether this node's clock has drifted too far from the database's
     * <p>
     * Expiry does not depend on this - the database decided that already. What the guard protects is
     * everything else a node does with its own clock, and the fact that a node whose clock is wrong
     * is a node whose operator has lost track of something. Phase 2 section 8.1 fixes the formula as
     * {@code |localNow - dbNow| > threshold}; equal to the threshold is inside it, so exactly five
     * seconds of drift is still allowed and five seconds plus a nanosecond is not.
     */
    private boolean skewExceeded(@NotNull OffsetDateTime dbNow) {
        Duration skew = Duration.between(dbNow.toInstant(), localClock.instant()).abs();
        return skew.compareTo(config.clockSkewThreshold()) > 0;
    }

    /**
     * Records a failure without anything the failure itself carries
     * <p>
     * The exception's message and stack trace are exactly what must not be written: a metadata pool
     * or driver message routinely names a JDBC URL, a host, a user or a property value. What is
     * written instead is a fixed event code, a correlation id that is new for this one event, the
     * exception's class name, and the key when one was already established - never anything read
     * from the failing objects to build one.
     * <p>
     * The key's three ids come from the caller and from connection configuration, and nothing
     * forbids a line break, a {@code ]} or an {@code EVENT_ID=} inside one. Each id is therefore
     * URL-encoded on its own before the three are joined with {@code /}, so the entry stays one line
     * and its fields cannot be forged. Letters, digits and hyphens are left as they are, so an
     * ordinary key reads exactly as {@link DbAccessKey#describe()} would.
     * <p>
     * This never throws. The caller is about to return a denial, and neither the encoding nor the
     * logger may turn that into an exception the caller's own caller did not expect.
     */
    private static void logFailure(
        @NotNull String eventCode,
        @NotNull String summary,
        @Nullable DbAccessKey key,
        @NotNull Throwable failure
    ) {
        try {
            String keyText = key == null
                ? KEY_UNRESOLVED
                : logSafe(key.userId()) + "/" + logSafe(key.projectId()) + "/" + logSafe(key.connectionId());
            log.error(summary + " [event=" + eventCode
                + " EVENT_ID=" + UUID.randomUUID()
                + " exception=" + failure.getClass().getName()
                + " key=" + keyText + "]");
        } catch (RuntimeException | Error ignored) {
            // Deliberately nothing: the decision must not depend on whether it could be logged.
        }
    }

    /** One key id in a form that cannot break the log line or its field syntax */
    @NotNull
    private static String logSafe(@NotNull String id) {
        return URLEncoder.encode(id, StandardCharsets.UTF_8);
    }

    /**
     * Starts one write attempt
     * <p>
     * The window reads the monotonic clock now, and that reading is where everything it subtracts
     * starts: waiting for a metadata connection, the snapshot statement, and whatever happens after
     * the authorization returns. The attempt then authorizes through the window, never before it
     * was opened, because the database reads its clock somewhere inside that call and counting from
     * any later point would leave out time the grant has already spent.
     * <p>
     * One window per attempt, used by one thread. A retry is a new attempt and opens a new window.
     */
    @NotNull
    public ExpiryWindow openExpiryWindow() {
        return new ExpiryWindow(this);
    }

    /**
     * The configuration in force, so a caller or a test can report it without re-deriving it
     */
    @NotNull
    public DbAccessPolicyConfig config() {
        return config;
    }

    /**
     * One write attempt, from just before its authorization to just before the write
     * <p>
     * An allow says the grant was unexpired when the database looked, and how long it had left then.
     * Between that look and the write reaching the target, time passes: the rest of the metadata
     * round trip, the pre-execution audit insert, the call into the platform. This window measures
     * that time on the monotonic clock from the moment it was opened, and lets the attempt's allow
     * through only while the database's remaining lifetime exceeds it by a margin:
     * <ul>
     *   <li>check-1, {@link #requireMarginBeforeAudit}, before the audit insert:
     *       {@code remaining - elapsed > T_audit + δ}</li>
     *   <li>check-2, {@link #requireMarginBeforeExecute}, after it:
     *       {@code remaining - elapsed > δ}</li>
     * </ul>
     * Both are strict, so exactly on the margin is refused, and a refusal is {@code GRANT_EXPIRED}
     * for the same grant. A denial or a recovery allow is carried through both checks as the same
     * object: the window can take an allow away, never grant one.
     * <p>
     * <b>The window owns its attempt.</b> It authorizes through the service that opened it -
     * {@link #authorize} - and judges only the decision that call produced, which it keeps as the
     * attempt's current decision. Each check reads that decision and replaces it with its own answer.
     * The checks take no argument, so nothing can hand one a decision from another attempt, measured
     * from another start, or the original allow after check-1 has refused it: once refused, the
     * attempt stays refused. Every enforcement point must authorize through a window;
     * {@link DbAccessPolicyService#authorize} called on its own applies no margin.
     * <p>
     * <b>Only check-2's answer permits the write.</b> What {@link #authorize} and
     * {@link #requireMarginBeforeAudit} return is the attempt's decision so far - an allow there has
     * not yet been held to the margin that comes after it. The platform may be called only when
     * {@link #requireMarginBeforeExecute} has returned normally and its result is an allow; if it
     * throws, or was never reached, the write does not happen.
     * <p>
     * <b>The calls go one way, each exactly once:</b>
     * <ul>
     *   <li>{@code OPEN}, as {@link DbAccessPolicyService#openExpiryWindow} returns it - only
     *       {@link #authorize}</li>
     *   <li>{@code AUTHORIZED} - only {@link #requireMarginBeforeAudit}</li>
     *   <li>{@code AUDIT_CHECKED} - only {@link #requireMarginBeforeExecute}</li>
     *   <li>{@code EXECUTE_CHECKED} - nothing; the attempt is over</li>
     * </ul>
     * Any other call is refused with {@link IllegalStateException} and ends the attempt: every later
     * call is refused too. So does a call that fails part way - a request the service refuses, or a
     * monotonic clock that throws. Its exception propagates as it is, nothing is made into an answer,
     * and the window accepts no further call. Turning such an exception into a denial is the
     * enforcement gate's job. A retry is a new attempt and opens a new window.
     * <p>
     * <b>Elapsed time only grows.</b> Each reading is taken as {@code now - start}, never compared
     * as an absolute value, so the clock may start anywhere and wrap. It is floored at zero, so a
     * clock that runs backwards cannot hand time back, and it never falls below the largest value
     * this window has already measured. The remaining lifetime is never converted to nanoseconds,
     * which a lifetime past about 292 years would overflow.
     * <p>
     * <b>What this does not guarantee.</b> A write reaches the platform before the database's
     * {@code EXPIRES_AT} only if nothing stalls for longer than {@code δ} between check-2 and that
     * call. This is a conservative margin, not a real-time bound.
     * <p>
     * Not thread-safe. Only {@link DbAccessPolicyService#openExpiryWindow} creates one.
     */
    public static final class ExpiryWindow {

        /** Where the attempt is; see the class comment for which call each state accepts */
        private enum State {
            OPEN, AUTHORIZED, AUDIT_CHECKED, EXECUTE_CHECKED,
            /** A call was refused or failed; nothing more is accepted */
            FAILED
        }

        private final DbAccessPolicyService service;
        private final long startNanos;
        private State state = State.OPEN;
        /** The attempt's decision: what authorize returned, then what each check made of it */
        @Nullable
        private AuthorizationDecision current;
        /** The largest elapsed time this window has measured; no later measurement is smaller */
        private long elapsedFloorNanos;

        private ExpiryWindow(@NotNull DbAccessPolicyService service) {
            this.service = service;
            this.startNanos = service.monotonicClock.getAsLong();
        }

        /**
         * Authorizes this attempt's write, through the service that opened the window
         * <p>
         * Exactly {@link DbAccessPolicyService#authorize}'s answer, which the window keeps for its
         * checks. The monotonic clock is not read here. An allow returned here is <b>not</b> leave to
         * write: neither check has run yet.
         *
         * @throws IllegalStateException if this window has already authorized, or its attempt is over
         */
        @NotNull
        public AuthorizationDecision authorize(@NotNull WriteAuthorizationRequest request) {
            leave(State.OPEN, "authorize");
            current = service.authorize(request);
            state = State.AUTHORIZED;
            return current;
        }

        /**
         * check-1: enough left to spend {@code T_audit} on the audit insert and still have {@code δ}
         *
         * @return the attempt's decision after the check: the same object when it is not a
         *     write-gated allow or when the margin holds, otherwise the {@code GRANT_EXPIRED} denial
         *     for the same grant. An allow returned here is still not leave to write; check-2 decides.
         * @throws IllegalStateException unless this is the first call after {@link #authorize}
         */
        @NotNull
        public AuthorizationDecision requireMarginBeforeAudit() {
            leave(State.AUTHORIZED, "check-1");
            current = requireMargin(current, service.config.auditTimeout().plus(service.config.expiryGuardMargin()));
            state = State.AUDIT_CHECKED;
            return current;
        }

        /**
         * check-2: enough left, after the audit insert, to reach the platform with {@code δ} to spare
         * <p>
         * Judges what check-1 left, so a refusal from check-1 comes back as the very same object.
         *
         * @return the attempt's final decision - the only one the platform call may act on
         * @throws IllegalStateException unless this is the first call after
         *     {@link #requireMarginBeforeAudit}
         */
        @NotNull
        public AuthorizationDecision requireMarginBeforeExecute() {
            leave(State.AUDIT_CHECKED, "check-2");
            current = requireMargin(current, service.config.expiryGuardMargin());
            state = State.EXECUTE_CHECKED;
            return current;
        }

        /**
         * Leaves {@code expected} for good, or refuses the call and ends the attempt
         * <p>
         * The window is marked failed before the call does any work, and only a call that completes
         * moves it on. So a call that throws part way - whatever throws - leaves nothing a later
         * call could pick up.
         */
        private void leave(@NotNull State expected, @NotNull String call) {
            State was = state;
            state = State.FAILED;
            if (was != expected) {
                throw new IllegalStateException(
                    "An expiry window accepts " + call + " only when " + expected + ", this one was " + was
                        + "; the attempt is over, and a retry needs a new window");
            }
        }

        @NotNull
        private AuthorizationDecision requireMargin(
            @NotNull AuthorizationDecision decision,
            @NotNull Duration margin
        ) {
            // A denial is already a denial, and a recovery allow was never measured against a grant.
            if (!decision.isAllowed() || AuthorizationDecision.RECOVERY_GRANT_ID.equals(decision.appliedGrantId())) {
                return decision;
            }
            // Never null here: the decision's constructor refuses a write-gated allow without one.
            Duration left = decision.remainingLifetime().minus(Duration.ofNanos(elapsedNanos()));
            if (left.compareTo(margin) > 0) {
                return decision;
            }
            return AuthorizationDecision.deny(
                DenialReason.GRANT_EXPIRED, decision.key(), decision.operationCategory(),
                decision.appliedGrantId(), decision.expiresAt());
        }

        /**
         * Elapsed time since the window opened: {@code max(largest so far, max(0, now - start))}
         */
        private long elapsedNanos() {
            long sinceStart = service.monotonicClock.getAsLong() - startNanos;
            elapsedFloorNanos = Math.max(elapsedFloorNanos, Math.max(0L, sinceStart));
            return elapsedFloorNanos;
        }
    }
}
