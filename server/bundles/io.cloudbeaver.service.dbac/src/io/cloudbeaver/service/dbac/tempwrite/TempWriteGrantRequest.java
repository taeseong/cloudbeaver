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

import java.time.Duration;

/**
 * A request to make a TEMP_WRITE grant current on one key
 * <p>
 * {@code observedRevisionAtRequestStart} is the whole point of this type. It is the revision the
 * caller saw when the request was accepted, it is fixed for the life of the request, and it is never
 * refreshed - not even across a retry. Everything the coordinator does is conditional on the stored
 * revision still being that value, which is what stops a request that was overtaken from taking
 * effect late.
 * <p>
 * Duration bounds, preset periods and who is allowed to ask are an admin-API concern and are
 * deliberately not checked here.
 */
public record TempWriteGrantRequest(
    @NotNull TempWritePermissionKey key,
    @NotNull String grantId,
    @NotNull String grantedBy,
    @NotNull Duration duration,
    @NotNull String reason,
    @NotNull EndpointSnapshot endpoint,
    long observedRevisionAtRequestStart
) {

    public TempWriteGrantRequest {
        // Checked, not merely annotated: nothing enforces org.jkiss.code.NotNull at runtime here, and
        // a request with no endpoint would be stored as a grant that can never match a connection.
        if (key == null) {
            throw new IllegalArgumentException("A TEMP_WRITE grant request requires a permission key");
        }
        if (endpoint == null) {
            throw new IllegalArgumentException(
                "A TEMP_WRITE grant request requires the endpoint it is issued for");
        }
        if (grantId == null || grantedBy == null) {
            throw new IllegalArgumentException(
                "A TEMP_WRITE grant request requires a grant id and a granting actor");
        }
        if (grantId.isBlank()) {
            throw new IllegalArgumentException("A TEMP_WRITE grant request requires a grant id");
        }
        if (grantedBy.isBlank()) {
            throw new IllegalArgumentException("A TEMP_WRITE grant request requires the granting actor");
        }
        // Delegated so the admin API of a later slice validates identically rather than growing its
        // own copy of these rules. The reason is normalised here, at the edge, so what is stored is
        // what was checked.
        reason = TempWriteRequestLimits.checkReason(reason);
        TempWriteRequestLimits.checkDuration(duration, null);
        if (observedRevisionAtRequestStart < TempWriteGrant.NO_ROW_REVISION) {
            throw new IllegalArgumentException(
                "An observed revision cannot be negative, got " + observedRevisionAtRequestStart);
        }
    }
}
