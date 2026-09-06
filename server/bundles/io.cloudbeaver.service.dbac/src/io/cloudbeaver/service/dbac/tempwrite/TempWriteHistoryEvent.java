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
 * One append-only row of {@code DBAC_TW_HISTORY}
 * <p>
 * Written in the same transaction as the current-row change it describes, so the two can never
 * disagree. {@code revision} is the revision the current row carries after that change, which is
 * what lets a reader order events without trusting timestamps.
 * <p>
 * History records committed transitions only. A request refused as superseded leaves nothing here;
 * that belongs to the audit trail. So the rows for a key replay exactly the states it passed
 * through, with no rejected attempts mixed in.
 * <p>
 * Holds no SQL text, no credentials and no free-form detail column.
 */
public record TempWriteHistoryEvent(
    @NotNull String eventId,
    @NotNull String grantId,
    @NotNull TempWriteChangeType changeType,
    @NotNull MetadataDbTime changeTime,
    @NotNull TempWritePermissionKey key,
    @NotNull String actorId,
    @Nullable MetadataDbTime expiresAt,
    @Nullable String reason,
    long revision
) {

    public TempWriteHistoryEvent {
        if (eventId.isBlank()) {
            throw new IllegalArgumentException("A TEMP_WRITE history event requires an event id");
        }
        if (grantId.isBlank()) {
            throw new IllegalArgumentException("A TEMP_WRITE history event requires a grant id");
        }
        if (actorId.isBlank()) {
            throw new IllegalArgumentException("A TEMP_WRITE history event requires an actor id");
        }
        if (revision < TempWriteGrant.FIRST_REVISION) {
            throw new IllegalArgumentException(
                "A TEMP_WRITE history event requires a revision of at least "
                    + TempWriteGrant.FIRST_REVISION + ", got " + revision);
        }
    }
}
