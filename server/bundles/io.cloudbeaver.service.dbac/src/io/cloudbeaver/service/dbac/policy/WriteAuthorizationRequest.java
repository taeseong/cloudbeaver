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
import org.jkiss.dbeaver.model.DBPDataSourceContainer;

/**
 * One question for the write gate
 * <p>
 * <b>The container is the input, not its id.</b> Phase 2 section 3.2 is emphatic about this and the
 * reason is worth restating where a future caller will read it:
 * {@code WebDataSourceUtils.getWebConnectionInfo} accepts a null {@code projectId} and then resolves
 * the connection by scanning every accessible project for an id that <em>contains</em> the argument,
 * taking the first hit. Most SQL operations declare {@code projectId} as nullable. So a permission
 * looked up from the GraphQL arguments can describe a different physical connection than the one the
 * statement will run on. Taking the resolved container closes that gap: the key is read from the
 * object that is about to be used.
 * <p>
 * <b>What must never be put here.</b> No SQL text, no statement parameters, no credentials, no
 * connection secrets. A decision is derived from who is asking and what they are asking about, and
 * anything else would only create a value that has to be kept out of logs and audit rows later.
 */
public record WriteAuthorizationRequest(
    @Nullable String userId,
    @Nullable DBPDataSourceContainer container,
    @NotNull DbOperationCategory operationCategory,
    @Nullable String executionContextId,
    boolean autoCommit
) {
    /**
     * Builds a request
     * <p>
     * {@code userId} and {@code container} are deliberately nullable even though a valid request has
     * both. Phase 2 section 4 rules 9 and 6 require a missing identity and an unresolvable connection
     * to produce a decision - {@code IDENTITY_MISSING} and {@code CONNECTION_UNKNOWN} - not an
     * exception. A record that refused to hold null would turn both into a throw at the call site,
     * where a caller might catch it and carry on.
     *
     * @param executionContextId carried for the transaction state machine of a later slice. This
     *     slice does not read it and does not implement any transaction state check; it is here so
     *     that adding those checks does not change this type's shape.
     * @param autoCommit likewise carried, not consulted in this slice.
     */
    public WriteAuthorizationRequest {
        // Checked, not merely annotated. Nothing enforces org.jkiss.code.NotNull at runtime in this
        // build, and a null category would travel all the way into a decision, where the category is
        // what every shape rule is expressed in terms of - producing a malformed decision from a
        // caller's omission rather than a clear refusal at the edge.
        if (operationCategory == null) {
            throw new IllegalArgumentException("An authorization request must say what is being attempted");
        }
    }

    /**
     * A request for the common case
     */
    @NotNull
    public static WriteAuthorizationRequest of(
        @Nullable String userId,
        @Nullable DBPDataSourceContainer container,
        @NotNull DbOperationCategory operationCategory
    ) {
        return new WriteAuthorizationRequest(userId, container, operationCategory, null, true);
    }
}
