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

/**
 * A request to end an active TEMP_WRITE grant before its expiry
 * <p>
 * Carries the same fixed {@code observedRevisionAtRequestStart} contract as
 * {@link TempWriteGrantRequest}: a revoke that was overtaken by another change is refused rather
 * than applied to whatever the row happens to hold now.
 * <p>
 * Revoking a key with no row, or one already revoked, is a successful no-op. That keeps a retried
 * or duplicated revoke safe, and it means the caller never has to look before asking.
 */
public record TempWriteRevokeRequest(
    @NotNull TempWritePermissionKey key,
    @NotNull String revokedBy,
    @NotNull String revokeReason,
    long observedRevisionAtRequestStart
) {

    public TempWriteRevokeRequest {
        if (revokedBy.isBlank()) {
            throw new IllegalArgumentException("A TEMP_WRITE revoke request requires the revoking actor");
        }
        // Same rule as a grant's reason, from the same place - a revoke is stored in the same
        // VARCHAR(1000) column and deserves the same rejection rather than a truncation.
        revokeReason = TempWriteRequestLimits.checkReason(revokeReason);
        if (observedRevisionAtRequestStart < TempWriteGrant.NO_ROW_REVISION) {
            throw new IllegalArgumentException(
                "An observed revision cannot be negative, got " + observedRevisionAtRequestStart);
        }
    }
}
