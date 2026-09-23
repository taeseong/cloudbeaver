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
import org.jkiss.dbeaver.model.app.DBPDataSourceRegistry;
import org.jkiss.dbeaver.model.app.DBPProject;

/**
 * Turns a resolved connection into the two things a decision needs: a key and a snapshot
 * <p>
 * Everything here reads from the container object itself. Nothing is taken from a request argument,
 * which is the rule Phase 2 section 3.2 sets and the reason it sets it:
 * {@code WebDataSourceUtils.getWebConnectionInfo} will accept a null project id and then match a
 * connection id by <em>substring</em> across every project the caller can see, returning the first
 * hit. A permission checked against those arguments can therefore belong to a different connection
 * than the one the statement runs on. Reading the key off the resolved object removes the gap
 * entirely - there is nothing left to disagree with.
 * <p>
 * <b>The registry check is the second half of that.</b> Holding a container is not the same as
 * holding the container the project currently has: it could have been deleted and replaced, or it
 * could be a detached copy. So the project's registry is asked for the container with this id and the
 * answer must be <em>the same object</em>. Reference identity is used rather than id equality
 * because id equality is exactly what a replaced connection would still satisfy.
 */
final class ContainerIdentityResolver {

    /**
     * The project id every anonymous session shares
     * <p>
     * A grant there would apply to whoever is unauthenticated at the time, so it is refused on both
     * sides - here, and in {@code TempWritePermissionKey}, which throws rather than build one.
     */
    static final String ANONYMOUS_PROJECT_ID = "anonymous";

    /**
     * What resolution produced: either a key, or the reason there is none
     * <p>
     * The endpoint identity is deliberately not part of this. It is read separately, after the
     * driver allowlist has been checked, so that an unsupported database and an unsupported
     * configuration report as themselves and so that both denials can carry this key.
     */
    record Resolved(
        @Nullable DbAccessKey key,
        @Nullable DenialReason failure
    ) {
        Resolved {
            if ((key == null) == (failure == null)) {
                throw new IllegalArgumentException(
                    "A resolution is either a key or a failure, never both and never neither");
            }
        }

        boolean ok() {
            return failure == null;
        }
    }

    private ContainerIdentityResolver() {
    }

    /**
     * Extracts the key and the current connection snapshot, or says why it cannot
     * <p>
     * Order matters: identity is checked before the registry, so a request with no user never causes
     * a registry lookup, and neither ever causes a metadata query. Phase 2 section 4 rule 9 requires
     * the identity refusal to happen "조회 전" - before any lookup at all.
     */
    @NotNull
    static Resolved resolve(@Nullable String userId, @Nullable DBPDataSourceContainer container) {
        if (userId == null || userId.isBlank()) {
            return failed(DenialReason.IDENTITY_MISSING);
        }
        if (container == null) {
            return failed(DenialReason.CONNECTION_UNKNOWN);
        }

        String connectionId = container.getId();
        if (connectionId == null || connectionId.isBlank()) {
            return failed(DenialReason.CONNECTION_UNKNOWN);
        }

        DBPProject project = container.getProject();
        if (project == null) {
            return failed(DenialReason.CONNECTION_UNKNOWN);
        }
        String projectId = project.getId();
        if (projectId == null || projectId.isBlank()) {
            return failed(DenialReason.CONNECTION_UNKNOWN);
        }
        if (ANONYMOUS_PROJECT_ID.equals(projectId)) {
            // Not CONNECTION_UNKNOWN: the connection is fine, the identity is not.
            return failed(DenialReason.IDENTITY_MISSING);
        }

        if (!isRegistryCurrent(project, container, connectionId)) {
            return failed(DenialReason.CONNECTION_UNKNOWN);
        }

        DbAccessKey key;
        try {
            key = new DbAccessKey(userId, projectId, connectionId);
        } catch (IllegalArgumentException e) {
            // Belt and braces. Every field was checked above, so reaching here means an accessor
            // returned something the checks did not anticipate - which is a denial, not a throw.
            return failed(DenialReason.IDENTITY_MISSING);
        }
        return new Resolved(key, null);
    }

    /**
     * Whether the project's registry still holds this exact container under this id
     * <p>
     * Compared by reference. A connection that was deleted and recreated with the same id would pass
     * an equality check and fail this one, which is the point.
     */
    private static boolean isRegistryCurrent(
        @NotNull DBPProject project,
        @NotNull DBPDataSourceContainer container,
        @NotNull String connectionId
    ) {
        DBPDataSourceRegistry registry;
        try {
            registry = project.getDataSourceRegistry();
        } catch (RuntimeException e) {
            // A project being torn down can fail here. Unresolvable is a denial.
            return false;
        }
        if (registry == null) {
            return false;
        }
        DBPDataSourceContainer current;
        try {
            current = registry.getDataSource(connectionId);
        } catch (RuntimeException e) {
            return false;
        }
        return current == container;
    }

    @NotNull
    private static Resolved failed(@NotNull DenialReason reason) {
        return new Resolved(null, reason);
    }
}
