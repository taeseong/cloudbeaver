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
 * Identity a TEMP_WRITE grant is scoped to: one user, on one connection, inside one project
 * <p>
 * Phase 2 scoped the key to the triple rather than to the user alone, so a grant on one production
 * database can never authorise a write on another. This type exists so the triple cannot be
 * assembled partially or incorrectly - the canonical constructor is the only way in, and it refuses
 * anything unusable.
 * <p>
 * The rejections are repeated here even though a future admin API will check them too. Storage is
 * the last layer that can still say no, and a row written with a blank or anonymous id would be a
 * grant nobody can attribute or revoke.
 */
public record TempWritePermissionKey(
    @NotNull String userId,
    @NotNull String projectId,
    @NotNull String connectionId
) {

    /**
     * Project id CloudBeaver uses for the anonymous session
     * <p>
     * A grant here would apply to whoever happens to be unauthenticated, which is the opposite of a
     * per-user permission. Phase 2 rule 9 denies it when authorising; this refuses to store it.
     */
    public static final String ANONYMOUS_PROJECT_ID = "anonymous";

    public TempWritePermissionKey {
        requirePresent(userId, "userId");
        requirePresent(projectId, "projectId");
        requirePresent(connectionId, "connectionId");
        if (ANONYMOUS_PROJECT_ID.equals(projectId)) {
            throw new IllegalArgumentException(
                "A TEMP_WRITE grant cannot be stored for the anonymous project");
        }
    }

    private static void requirePresent(@Nullable String value, @NotNull String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(
                "A TEMP_WRITE permission key requires a non-blank " + field);
        }
    }
}
