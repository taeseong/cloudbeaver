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
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;

import java.time.OffsetDateTime;

/**
 * Everything the metadata database said, read in one statement
 * <p>
 * The point of reading it all at once is that the pieces cannot disagree with each other. If the
 * grant were read by one statement and the clock by another, a revoke committing between them would
 * produce a decision assembled from two different versions of the world. One statement is one
 * linearization point: the answer describes the database as it was at that instant, and a revoke is
 * either wholly before it or wholly after.
 *
 * @param dbNow the database clock at the moment the statement ran - the only time authority for
 *     expiry. Never a JVM value.
 * @param userRowPresent whether the user has a row in {@code CB_USER} at all
 * @param userActive whether that row says {@code IS_ACTIVE = 'Y'}
 * @param grantId null when there is no current row for this key
 * @param expiresAt the grant's expiry, or null when there is no grant
 * @param revokedAt non-null when the grant was revoked
 * @param notExpired the comparison {@code EXPIRES_AT > CURRENT_TIMESTAMP} <b>as the database
 *     evaluated it</b>. Carried separately from the two timestamps so that the decision uses the
 *     database's own comparison rather than re-doing it in Java, which is what Phase 2 section 8.1
 *     requires. The timestamps are still returned so a test can check the boundary independently.
 * @param storedSnapshot which physical database the grant was issued for, or null when there is no
 *     grant <b>or the stored row cannot say</b>. The second case is a row written by schema
 *     version 2, which had no provider, configuration type or port column; it is null rather than
 *     partially populated so that a caller cannot accidentally compare a subset of the identity.
 */
record PolicySnapshot(
    @NotNull OffsetDateTime dbNow,
    boolean userRowPresent,
    boolean userActive,
    @Nullable String grantId,
    @Nullable OffsetDateTime expiresAt,
    @Nullable OffsetDateTime revokedAt,
    boolean notExpired,
    @Nullable EndpointSnapshot storedSnapshot
) {
    /**
     * Whether a current row exists for the key at all
     */
    boolean hasGrant() {
        return grantId != null;
    }

    /**
     * Whether the grant was revoked, regardless of whether it has also expired
     */
    boolean revoked() {
        return revokedAt != null;
    }
}
