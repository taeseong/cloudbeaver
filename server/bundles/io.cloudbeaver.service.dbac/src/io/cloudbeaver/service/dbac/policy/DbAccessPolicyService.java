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
import org.jkiss.dbeaver.Log;
import org.jkiss.dbeaver.model.DBPDataSourceContainer;

import java.sql.Connection;
import java.time.Clock;
import java.time.Duration;
import java.time.OffsetDateTime;

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
 * <b>Nothing calls this yet.</b> No production path invokes {@code authorize}. Until an enforcement
 * point does, a running server behaves exactly as it did before: this class decides nothing that
 * anybody acts on.
 */
public final class DbAccessPolicyService {

    private static final Log log = Log.getLog(DbAccessPolicyService.class);

    private final MetadataConnectionSource connectionSource;
    private final DbAccessPolicyConfig config;
    private final Clock localClock;

    /**
     * Builds a service that takes every fact it decides on from the metadata database
     *
     * @param connectionSource where a metadata connection comes from. Must hand out connections from
     *     {@code CBDatabase.openConnection()} so that {@code {table_prefix}} is substituted and the
     *     connection is in auto-commit.
     * @param localClock this node's clock. Used <b>only</b> to measure how far it has drifted from
     *     the database's, never to decide whether a grant has expired.
     */
    public DbAccessPolicyService(
        @NotNull MetadataConnectionSource connectionSource,
        @NotNull DbAccessPolicyConfig config,
        @NotNull Clock localClock
    ) {
        this.connectionSource = connectionSource;
        this.config = config;
        this.localClock = localClock;
    }

    public DbAccessPolicyService(
        @NotNull MetadataConnectionSource connectionSource,
        @NotNull DbAccessPolicyConfig config
    ) {
        this(connectionSource, config, Clock.systemUTC());
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
     * </ol>
     * Steps 8 and 9 are in that order because Phase 2 section 4 marks expiry as taking precedence
     * ("만료 우선") when a grant is both expired and revoked. Both deny; only the reported reason
     * differs. The slice instructions suggested the opposite order, so the choice is written down
     * here and pinned by a test rather than left to whichever branch was typed first.
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
                log.error("DBAC could not read the permission store for " + key.describe(), e);
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
            return AuthorizationDecision.allow(key, category, grantId, expiresAt);
        } catch (RuntimeException | Error e) {
            // Nothing unexpected is allowed to become an allow, and nothing is allowed to escape
            // and be caught by a caller that might carry on. Both become the same denial - but the
            // denial keeps the key when one was already established, so the event is auditable
            // against a subject. A failure inside a driver accessor or a clock, after identity was
            // resolved, is exactly the event worth attributing.
            log.error("DBAC authorization failed unexpectedly", e);
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
     * The configuration in force, so a caller or a test can report it without re-deriving it
     */
    @NotNull
    public DbAccessPolicyConfig config() {
        return config;
    }
}
