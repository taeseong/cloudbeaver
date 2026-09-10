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

import java.util.Locale;

/**
 * Which physical database a TEMP_WRITE grant was issued for
 * <p>
 * A grant is keyed by {@code (userId, projectId, connectionId)}, but a connection id is a file key:
 * restore a backup, edit a configuration, or delete and recreate a connection, and the same id can
 * point at a different server. So a grant also records what it was issued for, and every
 * authorization compares the recorded values against the connection resolved now. A difference is
 * {@code GRANT_STALE}.
 * <p>
 * <b>Why six fields and not three.</b> The first version of this recorded driver, host and database
 * only. That let a grant survive a port change - same host, same database, different server
 * instance - and it let a connection be switched to a custom JDBC URL, at which point the host and
 * database fields stop describing the target at all. Both were reachable without touching the
 * connection id or replacing the container object, so neither the key nor the registry
 * reference-identity check noticed. See {@code docs/db-access-control-endpoint-identity.md}.
 * <p>
 * <b>What is deliberately absent.</b> No user name, no password, no token, no SSH or SSL material,
 * no JDBC URL. The URL is excluded on purpose rather than by omission: DBeaver's own generic URL
 * template is {@code [jdbc:]{driver}://[{user}:{password}@]{host}...} and its URL parser has an
 * explicit password capture, so storing or even hashing a URL wholesale would put a credential into
 * the permission store. A configuration whose target can only be read off its URL is refused
 * instead - see {@code EndpointFingerprints}.
 * <p>
 * <b>Every field is required.</b> A configuration that cannot supply all six is refused before a
 * snapshot is built, so there is no partially-populated snapshot to reason about and no null to
 * compare. The one place a missing value is expected is a grant stored by schema version 2, which
 * predates three of these columns; {@link #ofStored} returns null for such a row and the caller
 * denies.
 */
public record EndpointSnapshot(
    @NotNull String providerId,
    @NotNull String driverId,
    @NotNull String configurationType,
    @NotNull String host,
    @NotNull String port,
    @NotNull String database
) {

    /**
     * Refuses an incomplete endpoint
     * <p>
     * Null is checked as well as blank. {@code @NotNull} here is documentation and an IDE hint -
     * nothing in this build enforces it at runtime - so a null would otherwise reach
     * {@link #matches} and throw a {@code NullPointerException} from inside a comparison, which a
     * caller would see as an infrastructure failure rather than as a bad snapshot.
     */
    public EndpointSnapshot {
        require(providerId, "provider id");
        require(driverId, "driver id");
        require(configurationType, "configuration type");
        require(host, "host");
        require(port, "port");
        require(database, "database");
    }

    private static void require(@Nullable String value, @NotNull String what) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("An endpoint snapshot requires a " + what);
        }
    }

    /**
     * Rebuilds a snapshot from stored columns, or returns null when the row cannot supply one
     * <p>
     * Returns null when any column is missing. That is not a defensive flourish: a grant written
     * under schema version 2 has no provider, configuration type or port, because those columns did
     * not exist. Version 3 adds them as nullable and the migration does <b>not</b> fill them in from
     * the connection's current configuration - doing so would let a migration bless exactly the
     * succession this record exists to catch. Such a row therefore compares unequal to every live
     * connection and denies until the grant is issued again.
     */
    @Nullable
    public static EndpointSnapshot ofStored(
        @Nullable String providerId,
        @Nullable String driverId,
        @Nullable String configurationType,
        @Nullable String host,
        @Nullable String port,
        @Nullable String database
    ) {
        if (isBlank(providerId) || isBlank(driverId) || isBlank(configurationType)
            || isBlank(host) || isBlank(port) || isBlank(database)
        ) {
            return null;
        }
        return new EndpointSnapshot(providerId, driverId, configurationType, host, port, database);
    }

    private static boolean isBlank(@Nullable String value) {
        return value == null || value.isBlank();
    }

    /**
     * Whether a grant recorded for {@code stored} still describes this endpoint
     * <p>
     * Provider, driver and configuration type are identifiers and compare exactly. The host is
     * compared case-insensitively because DNS names are case-insensitive by definition, and nothing
     * else about it is normalised: no port is split off, no IPv6 form is canonicalised, no trailing
     * dot is removed. Two spellings of one address that this method calls different will deny, which
     * is the intended direction - the alternative is a normaliser whose bugs silently approve the
     * wrong server.
     * <p>
     * The port compares as an exact string. It is not parsed to an integer, not trimmed, not
     * stripped of leading zeros, and above all an empty port is never equated with the driver's
     * default port: nothing in the platform substitutes a default, so "empty means 5432" is a
     * property of a vendor JAR that is not version-pinned. A configuration with no port is refused
     * rather than assumed.
     * <p>
     * The database compares case-sensitively. PostgreSQL folds unquoted identifiers to lower case
     * but a quoted name can differ only by case, and MySQL's behaviour depends on
     * {@code lower_case_table_names} and the host filesystem, so the answer is not the same on every
     * deployment.
     */
    public boolean matches(@NotNull EndpointSnapshot stored) {
        return providerId.equals(stored.providerId)
            && driverId.equals(stored.driverId)
            && configurationType.equals(stored.configurationType)
            && host.toLowerCase(Locale.ROOT).equals(stored.host.toLowerCase(Locale.ROOT))
            && port.equals(stored.port)
            && database.equals(stored.database);
    }

    /**
     * A one-line rendering, used in test diagnostics
     * <p>
     * Host and database are in it because a failing comparison is unreadable without them, and
     * neither is a credential. <b>No production code calls this.</b> Denials are logged by key, not
     * by endpoint - a host and database name identify a customer in a per-customer estate, and that
     * is a decision to take deliberately rather than as a side effect of a diagnostic helper.
     */
    @NotNull
    public String describe() {
        return providerId + ":" + driverId + "/" + configurationType + "/" + host + ":" + port + "/" + database;
    }
}
