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

/**
 * Who, where: the three values a permission is keyed by
 * <p>
 * This is the policy layer's own copy of the key rather than
 * {@code io.cloudbeaver.service.dbac.tempwrite.TempWritePermissionKey}, and the reason is narrow.
 * The tempwrite package is exported only to the test bundle. Enforcement call sites will live in
 * other bundles, so anything that appears in this package's public signatures has to be reachable
 * from them - and putting a tempwrite type in {@link AuthorizationDecision} would force that
 * package open as a side effect of wiring enforcement. The two records hold the same three strings
 * and the policy service converts between them internally.
 * <p>
 * <b>These values never come from a GraphQL argument.</b> They are extracted from a resolved
 * {@code DBPDataSourceContainer} by {@link ContainerIdentityResolver}. Phase 2 section 3.2 explains
 * why: {@code WebDataSourceUtils.getWebConnectionInfo} resolves a connection id by substring match
 * across every project the caller can see, so a permission looked up from the raw argument can
 * belong to a different physical connection than the one that executes.
 */
public record DbAccessKey(
    @NotNull String userId,
    @NotNull String projectId,
    @NotNull String connectionId
) {
    public DbAccessKey {
        if (userId.isBlank() || projectId.isBlank() || connectionId.isBlank()) {
            throw new IllegalArgumentException("A DBAC access key requires user, project and connection ids");
        }
    }

    /**
     * A form safe to put in a log or an audit row
     * <p>
     * All three parts are identifiers the server already stores in plain text; none of them is a
     * credential or a host address.
     */
    @NotNull
    public String describe() {
        return userId + "/" + projectId + "/" + connectionId;
    }
}
