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

/**
 * One row of {@code DBAC_TW_CURRENT}: the current TEMP_WRITE state of a permission key
 * <p>
 * There is at most one of these per key, enforced by the primary key. A revoked grant stays in the
 * table with {@code revokedAt} set rather than being deleted, so the current row and the history can
 * never disagree about what happened, and a later request can still see which grant it is racing.
 * <p>
 * Times are {@link MetadataDbTime} rather than {@code Instant} on purpose: they belong to the
 * metadata database's clock domain, which is the only clock Phase 2 trusts. Nothing in this record
 * holds a password, a token, a connection secret or any SQL text. The connection is described only
 * by the identifiers and the snapshots needed to notice that a reused id now points elsewhere.
 */
public record TempWriteGrant(
    @NotNull TempWritePermissionKey key,
    @NotNull String grantId,
    long revision,
    @NotNull String grantedBy,
    @NotNull MetadataDbTime grantedAt,
    @NotNull MetadataDbTime expiresAt,
    @NotNull String reason,
    @Nullable MetadataDbTime revokedAt,
    @Nullable String revokedBy,
    @Nullable String revokeReason,
    @Nullable EndpointSnapshot endpoint
) {

    /** Lowest revision a stored row may carry. */
    public static final long FIRST_REVISION = 1L;

    /** Revision observed for a key that has no current row at all. */
    public static final long NO_ROW_REVISION = 0L;

    public TempWriteGrant {
        if (grantId.isBlank()) {
            throw new IllegalArgumentException("A TEMP_WRITE grant requires a grant id");
        }
        if (revision < FIRST_REVISION) {
            throw new IllegalArgumentException(
                "A stored TEMP_WRITE grant requires a revision of at least " + FIRST_REVISION
                    + ", got " + revision);
        }
        if (grantedBy.isBlank()) {
            throw new IllegalArgumentException("A TEMP_WRITE grant requires the granting actor");
        }
    }

    /**
     * Whether this row records which physical database it was granted for
     * <p>
     * False for a row written under schema version 2, which had no provider, configuration type or
     * port column. Version 3 added them as nullable and the migration deliberately leaves them
     * empty, so such a row cannot be matched against any connection and must be denied until the
     * grant is issued again. A write gate that treated an absent endpoint as "matches anything"
     * would reinstate exactly the succession the endpoint columns exist to catch.
     */
    public boolean hasEndpoint() {
        return endpoint != null;
    }

    /**
     * Whether this grant was ended before its expiry
     * <p>
     * This is not an authorisation decision. Expiry is compared by the database clock inside the
     * authorising query, which is a later slice; this only reports the revoke column.
     */
    public boolean isRevoked() {
        return revokedAt != null;
    }

    /**
     * This row as the revoke will commit it
     * <p>
     * Exists so that whatever observes a committed transition - today the audit sink, later a cache
     * invalidation - is handed the state that is actually being stored rather than the state being
     * replaced. Passing the pre-revoke row instead would make every observer reconstruct the revoke
     * for itself, and an observer that got it wrong would be recording a grant that never existed.
     *
     * @param newRevision the revision the revoke writes, which must be above this one
     * @param revokedAtValue the reading taken once for this transaction
     */
    @NotNull
    public TempWriteGrant asRevoked(
        long newRevision,
        @NotNull MetadataDbTime revokedAtValue,
        @NotNull String revokedByValue,
        @NotNull String revokeReasonValue
    ) {
        if (newRevision <= revision) {
            throw new IllegalArgumentException(
                "A revoke must raise the revision, got " + newRevision + " against " + revision);
        }
        return new TempWriteGrant(
            key, grantId, newRevision, grantedBy, grantedAt, expiresAt, reason,
            revokedAtValue, revokedByValue, revokeReasonValue, endpoint);
    }
}
