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
    @NotNull String driverId,
    @Nullable String hostSnapshot,
    @Nullable String databaseSnapshot,
    long observedRevisionAtRequestStart
) {

    public TempWriteGrantRequest {
        if (grantId.isBlank()) {
            throw new IllegalArgumentException("A TEMP_WRITE grant request requires a grant id");
        }
        if (grantedBy.isBlank()) {
            throw new IllegalArgumentException("A TEMP_WRITE grant request requires the granting actor");
        }
        if (driverId.isBlank()) {
            throw new IllegalArgumentException("A TEMP_WRITE grant request requires a driver id");
        }
        if (reason.isBlank()) {
            throw new IllegalArgumentException("A TEMP_WRITE grant request requires a reason");
        }
        if (duration.isZero() || duration.isNegative()) {
            throw new IllegalArgumentException("A TEMP_WRITE grant requires a positive duration, got " + duration);
        }
        if (observedRevisionAtRequestStart < TempWriteGrant.NO_ROW_REVISION) {
            throw new IllegalArgumentException(
                "An observed revision cannot be negative, got " + observedRevisionAtRequestStart);
        }
    }
}
