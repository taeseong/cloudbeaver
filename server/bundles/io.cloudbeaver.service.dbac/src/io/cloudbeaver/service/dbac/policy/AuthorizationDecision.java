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

import java.time.OffsetDateTime;
import java.util.Objects;

/**
 * What the write gate decided, and everything derived from that one evaluation
 * <p>
 * Phase 2 section 6: "boolean만 반환하지 않는다" - the audit entry and the user-facing message must
 * come from the same decision, not be reconstructed afterwards by a caller who might reach a
 * different conclusion. So the reason, the grant that was applied, when it expires and the audit
 * payload all travel together.
 * <p>
 * <b>The invariants are enforced, not documented.</b> An ALLOW cannot carry a denial reason and a
 * DENY cannot be built without one. That is checked in the constructor so a wrong pairing fails
 * where it is created rather than where it is read.
 * <p>
 * <b>This type does not throw.</b> Phase 2 suggests denials be raised as
 * {@code DBWebExceptionAccessDenied}, but that class lives in {@code io.cloudbeaver.server}, a bundle
 * this one must not depend on (Phase 2 section 12.4 fixes the dependency direction). The mapping from
 * DENY to a web exception belongs at the enforcement call site, which already sees that bundle.
 */
public record AuthorizationDecision(
    @NotNull DbAccessDecision decision,
    @Nullable DenialReason denialReason,
    @Nullable DbAccessKey key,
    @NotNull DbOperationCategory operationCategory,
    @Nullable String appliedGrantId,
    @Nullable OffsetDateTime expiresAt,
    @Nullable AuthorizationAuditPayload auditPayload
) {
    /**
     * Rejects every combination that is not one of the three legal shapes
     * <p>
     * There are exactly three, and they are checked here rather than trusted from the factories,
     * because the canonical constructor of a public record is itself a public entry point: an
     * enforcement bundle can call it directly, and a partially-populated allow assembled that way
     * would be indistinguishable from one this class produced. A shape check in the factories alone
     * would be a convention, not an invariant.
     * <ol>
     *   <li><b>A write-gated allow</b> names its key, its grant and its expiry, and carries an audit
     *       payload that agrees with all of them. Nothing may be missing: an allow that cannot say
     *       when it stops being valid is not an authorization, and an allow with no payload cannot
     *       be recorded.</li>
     *   <li><b>A recovery allow</b> is a rollback and nothing else. It carries the recovery
     *       sentinel, no key, no expiry and no payload, because no permission was consulted. The
     *       sentinel is refused on every other category, so a rollback cannot be forged into an
     *       allow for a write by relabelling the category.</li>
     *   <li><b>A denial</b> says why. Once a key is known it must also carry a payload that agrees
     *       with the decision; only a denial taken before the key exists may omit both.</li>
     * </ol>
     */
    public AuthorizationDecision {
        if (decision == null) {
            throw new IllegalArgumentException("A decision must say whether it is an allow or a denial");
        }
        if (operationCategory == null) {
            throw new IllegalArgumentException("A decision must say what was being attempted");
        }
        if (decision == DbAccessDecision.ALLOW) {
            if (denialReason != null) {
                throw new IllegalArgumentException("An allow cannot carry a denial reason, got " + denialReason);
            }
            if (RECOVERY_GRANT_ID.equals(appliedGrantId)) {
                requireRecoveryShape(operationCategory, key, expiresAt, auditPayload);
            } else {
                requireWriteAllowShape(decision, denialReason, key, operationCategory,
                    appliedGrantId, expiresAt, auditPayload);
            }
        } else {
            if (denialReason == null) {
                throw new IllegalArgumentException("A denial must say why");
            }
            if (RECOVERY_GRANT_ID.equals(appliedGrantId)) {
                throw new IllegalArgumentException("A denial cannot claim the recovery grant");
            }
            requireDenialShape(decision, denialReason, key, operationCategory,
                appliedGrantId, expiresAt, auditPayload);
        }
    }

    private static void requireRecoveryShape(
        @NotNull DbOperationCategory category,
        @Nullable DbAccessKey key,
        @Nullable OffsetDateTime expiresAt,
        @Nullable AuthorizationAuditPayload payload
    ) {
        if (category != DbOperationCategory.TRANSACTION_ROLLBACK) {
            throw new IllegalArgumentException(
                "The recovery grant belongs to TRANSACTION_ROLLBACK alone, got " + category);
        }
        if (key != null || expiresAt != null || payload != null) {
            throw new IllegalArgumentException(
                "A recovery allow consults no permission, so it carries no key, expiry or audit payload");
        }
    }

    private static void requireWriteAllowShape(
        @NotNull DbAccessDecision decision,
        @Nullable DenialReason reason,
        @Nullable DbAccessKey key,
        @NotNull DbOperationCategory category,
        @Nullable String grantId,
        @Nullable OffsetDateTime expiresAt,
        @Nullable AuthorizationAuditPayload payload
    ) {
        // A grant only ever permits a category the write gate governs. An allow on a category that
        // never needed one - a container read, a grouping query - would be a permission granted for
        // something no permission was consulted about, and a caller that saw it would believe a
        // grant had been checked. TRANSACTION_ROLLBACK is excluded here too: it is allowed by
        // category, through the recovery shape, and must never arrive backed by a grant.
        if (!category.requiresWriteAuthorization()) {
            throw new IllegalArgumentException(
                "A grant-backed allow belongs to a write-gated category, got " + category);
        }
        if (key == null) {
            throw new IllegalArgumentException("An allow must name the key it applies to");
        }
        // The blank half of this is unreachable through a constructible payload, and is kept as
        // defence in depth rather than pinned by a test that could only be vacuous. Proof: an allow
        // whose grant id is blank must, to get past requireAgreement below, carry a payload whose
        // grant id is the same blank string - and AuthorizationAuditPayload refuses a blank grant id
        // on an allow, so no such payload exists. A clause sweep reports this clause as surviving its
        // deletion for exactly that reason. It stays because it is the barrier if that payload rule
        // ever loosens, and because a null grant id - the other half - is reachable and is pinned.
        if (grantId == null || grantId.isBlank()) {
            throw new IllegalArgumentException("An allow must name the grant it applied");
        }
        if (expiresAt == null) {
            throw new IllegalArgumentException("An allow must say when it stops being valid");
        }
        if (payload == null) {
            throw new IllegalArgumentException("An allow must carry the audit payload that records it");
        }
        requireAgreement(payload, decision, reason, key, grantId, category, expiresAt);
    }

    private static void requireDenialShape(
        @NotNull DbAccessDecision decision,
        @NotNull DenialReason reason,
        @Nullable DbAccessKey key,
        @NotNull DbOperationCategory category,
        @Nullable String grantId,
        @Nullable OffsetDateTime expiresAt,
        @Nullable AuthorizationAuditPayload payload
    ) {
        if (key == null) {
            if (payload != null) {
                throw new IllegalArgumentException(
                    "A denial with no key cannot carry an audit payload, which is keyed by user,"
                        + " project and connection");
            }
            // Nothing was looked up, so there is nothing to report about a grant. A grant id or an
            // expiry here would name a permission the decision never established the subject of.
            if (grantId != null || expiresAt != null) {
                throw new IllegalArgumentException(
                    "A denial taken before the key exists cannot name a grant or an expiry");
            }
            return;
        }
        if (payload == null) {
            throw new IllegalArgumentException(
                "A denial about a known key must carry the audit payload that records it");
        }
        requireAgreement(payload, decision, reason, key, grantId, category, expiresAt);
    }

    /**
     * The payload has to describe this decision, not a neighbouring one
     * <p>
     * Without this an audit row could disagree with the decision that produced it, and the row is
     * the only thing that survives. Compared field by field rather than by rebuilding the payload,
     * so a payload assembled elsewhere is checked rather than replaced.
     */
    private static void requireAgreement(
        @NotNull AuthorizationAuditPayload payload,
        @NotNull DbAccessDecision decision,
        @Nullable DenialReason reason,
        @NotNull DbAccessKey key,
        @Nullable String grantId,
        @NotNull DbOperationCategory category,
        @Nullable OffsetDateTime expiresAt
    ) {
        // The first comparison is unreachable given the payload's own invariant, and is kept for the
        // same reason as the blank grant id above. Proof: a payload's decision and denial reason are
        // locked to each other - DENY carries a reason, ALLOW carries none - and so are this
        // decision's, so a payload that disagrees about the decision necessarily disagrees about the
        // reason as well, and the second comparison refuses it first. The second comparison is the
        // one that had no test until a clause sweep found it: deleting it let a denial record one
        // reason in the audit row while having been taken for another.
        if (payload.decision() != decision
            || payload.denialReason() != reason
            || !key.userId().equals(payload.userId())
            || !key.projectId().equals(payload.projectId())
            || !key.connectionId().equals(payload.connectionId())
            || !Objects.equals(payload.grantId(), grantId)
            || payload.operationCategory() != category
            || !Objects.equals(payload.expiresAt(), expiresAt)
        ) {
            throw new IllegalArgumentException(
                "The audit payload must describe this decision; it describes a different one");
        }
    }

    public boolean isAllowed() {
        return decision == DbAccessDecision.ALLOW;
    }

    /**
     * A stable code for a client to localise, or null when the request was allowed
     */
    @Nullable
    public String messageCode() {
        return denialReason == null ? null : denialReason.messageCode();
    }

    /**
     * A short sentence safe to show a user, or null when the request was allowed
     * <p>
     * Safe means it contains no host, database, table, statement, exception text or internal path.
     */
    @Nullable
    public String userMessage() {
        return denialReason == null ? null : denialReason.userMessage();
    }

    // ---------------------------------------------------------------- factories

    /**
     * A denial taken before the key could be established
     * <p>
     * Used for a missing identity, an unresolvable connection and an unauthorized category - the
     * checks that run before there is a key at all. There is no audit payload for the same reason:
     * the audit table is keyed by user, project and connection, and this decision has no
     * trustworthy value for them.
     * <p>
     * An unsupported database or an unsupported connection configuration deliberately does
     * <b>not</b> come through here even though neither opens a metadata connection. Both are decided
     * after the key is known, and a refused attempt to write to an out-of-scope database is
     * precisely the event worth recording, so they use {@link #deny} and keep the key.
     */
    @NotNull
    static AuthorizationDecision denyBeforeKey(
        @NotNull DenialReason reason,
        @NotNull DbOperationCategory category
    ) {
        return new AuthorizationDecision(DbAccessDecision.DENY, reason, null, category, null, null, null);
    }

    /**
     * A denial about a known key
     */
    @NotNull
    static AuthorizationDecision deny(
        @NotNull DenialReason reason,
        @NotNull DbAccessKey key,
        @NotNull DbOperationCategory category,
        @Nullable String grantId,
        @Nullable OffsetDateTime expiresAt
    ) {
        return new AuthorizationDecision(
            DbAccessDecision.DENY, reason, key, category, grantId, expiresAt,
            AuthorizationAuditPayload.of(DbAccessDecision.DENY, reason, key, grantId, category, expiresAt));
    }

    /**
     * The single allow
     */
    @NotNull
    static AuthorizationDecision allow(
        @NotNull DbAccessKey key,
        @NotNull DbOperationCategory category,
        @NotNull String grantId,
        @NotNull OffsetDateTime expiresAt
    ) {
        return new AuthorizationDecision(
            DbAccessDecision.ALLOW, null, key, category, grantId, expiresAt,
            AuthorizationAuditPayload.of(DbAccessDecision.ALLOW, null, key, grantId, category, expiresAt));
    }

    /**
     * The recovery allow: a rollback, which is never judged
     * <p>
     * Phase 2 section 12.3. It carries no grant because none was consulted, so it does not go through
     * {@link #allow} - which would demand one - and produces no audit payload, because nothing about
     * a permission was decided.
     */
    @NotNull
    static AuthorizationDecision allowRecovery(@NotNull DbOperationCategory category) {
        return new AuthorizationDecision(
            DbAccessDecision.ALLOW, null, null, category, RECOVERY_GRANT_ID, null, null);
    }

    /**
     * The placeholder recorded as the applied grant for a rollback
     * <p>
     * Not a real grant id and never matches one: rollback is permitted by category, not by permission.
     */
    public static final String RECOVERY_GRANT_ID = "<recovery>";
}
