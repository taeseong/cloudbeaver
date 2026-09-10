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

/**
 * Everything an audit layer needs about a decision, and nothing else
 * <p>
 * The fields here line up with the columns {@code DBAC_AUDIT_EVENT} actually has. That table was
 * created in slice 1 with no free-text column, on purpose: a column that can hold anything ends up
 * holding a SQL statement. This record inherits that constraint - there is no {@code detail} field
 * and adding one would be a schema change with its own justification, not a convenience.
 * <p>
 * <b>Nothing is written yet.</b> This slice builds no audit writer; Phase 2's pre-execution audit is
 * a later slice. What exists here is the shape, so that when the writer arrives it consumes a value
 * the decision already produced rather than re-deriving one and risking a different answer.
 * <p>
 * <b>What is excluded, restated because it is the point.</b> No SQL text, no statement parameters,
 * no database credentials, no host credentials, no session token, no connection URL. The host name
 * is not here either - it is compared inside the decision and then dropped, because an audit trail
 * of who was denied does not need to record where.
 */
public record AuthorizationAuditPayload(
    @NotNull DbAccessDecision decision,
    @Nullable DenialReason denialReason,
    @NotNull String userId,
    @NotNull String projectId,
    @NotNull String connectionId,
    @Nullable String grantId,
    @NotNull DbOperationCategory operationCategory,
    @Nullable OffsetDateTime expiresAt
) {
    /**
     * Refuses a payload that could not describe a decision this service can take
     * <p>
     * Checked here rather than only at the one factory, because this record is public and an
     * enforcement bundle can build one directly. An audit row is the only part of a decision that
     * outlives the request, so a payload that contradicts itself is worse than a missing one: it is
     * evidence of something that never happened.
     * <p>
     * {@code @NotNull} is documentation to a reader and a hint to an IDE. Nothing enforces it at
     * runtime in this build, so every component that must be present is checked explicitly.
     */
    public AuthorizationAuditPayload {
        if (decision == null) {
            throw new IllegalArgumentException("An audit payload must say what was decided");
        }
        if (operationCategory == null) {
            throw new IllegalArgumentException("An audit payload must say what was being attempted");
        }
        if (userId == null || projectId == null || connectionId == null
            || userId.isBlank() || projectId.isBlank() || connectionId.isBlank()
        ) {
            throw new IllegalArgumentException("An audit payload requires the permission key");
        }
        if ((decision == DbAccessDecision.DENY) != (denialReason != null)) {
            throw new IllegalArgumentException(
                "A denial must carry a reason and an allow must not, got " + decision + " with " + denialReason);
        }
        if (decision == DbAccessDecision.ALLOW) {
            // The only allow that reaches an audit payload is a grant-backed write. A rollback is
            // allowed by category rather than by permission and produces no payload at all, so an
            // allow payload for a category the write gate does not govern describes nothing real.
            if (!operationCategory.requiresWriteAuthorization()) {
                throw new IllegalArgumentException(
                    "An allow payload belongs to a write-gated category, got " + operationCategory);
            }
            if (grantId == null || grantId.isBlank()) {
                throw new IllegalArgumentException("An allow payload must name the grant that permitted it");
            }
            if (expiresAt == null) {
                throw new IllegalArgumentException("An allow payload must say when the grant stops being valid");
            }
        }
    }

    /**
     * Builds the payload for a decision about a fully identified key
     */
    @NotNull
    static AuthorizationAuditPayload of(
        @NotNull DbAccessDecision decision,
        @Nullable DenialReason denialReason,
        @NotNull DbAccessKey key,
        @Nullable String grantId,
        @NotNull DbOperationCategory operationCategory,
        @Nullable OffsetDateTime expiresAt
    ) {
        return new AuthorizationAuditPayload(
            decision, denialReason, key.userId(), key.projectId(), key.connectionId(),
            grantId, operationCategory, expiresAt);
    }
}
