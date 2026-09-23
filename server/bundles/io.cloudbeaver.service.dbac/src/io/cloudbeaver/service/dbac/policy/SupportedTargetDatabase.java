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
import org.jkiss.dbeaver.model.connection.DBPDriver;

import java.util.Set;

/**
 * Which target databases this fork will authorise a write to
 * <p>
 * Phase 2 section 12.4 scopes write enforcement to PostgreSQL and MySQL. Everything else is refused,
 * because a statement classifier and a write-detection story tuned for one dialect make no promise
 * about another - and this project's rule is that an unverified database gets no safety claim.
 * <p>
 * <b>Why this is an exact provider-and-driver allowlist and not a substring test.</b> The obvious
 * shortcut - does the driver id contain "postgres" or "mysql" - was measured against the shipped
 * plugin definitions and is wrong in three separate ways:
 * <ul>
 *   <li><b>The PostgreSQL provider ships fourteen drivers and only two of them are PostgreSQL.</b>
 *       Under {@code datasource id="postgresql"} sit {@code postgres-redshift-jdbc} (Redshift),
 *       {@code postgres-cockroach-jdbc} (CockroachDB), {@code postgres-yugabytedb-jdbc},
 *       {@code postgres-materialize-jdbc}, {@code postgres-cratedb-jdbc},
 *       {@code postgres-risingwave-jdbc}, {@code postgres-timescale-jdbc},
 *       {@code postgres-greenplum-jdbc}, {@code postgres-edb-jdbc}, {@code postgres-gcloud-jdbc}
 *       and two Yellowbrick entries. A provider-level check would authorise every one of them.</li>
 *   <li><b>The JDBC driver class does not discriminate either.</b> CockroachDB, YugabyteDB,
 *       Materialize, CrateDB, RisingWave, TimescaleDB, Greenplum and Google Cloud SQL all declare
 *       {@code org.postgresql.Driver}. Matching on the class would authorise all of them too.</li>
 *   <li><b>A driver id is not unique across providers.</b> The {@code generic} provider defines a
 *       driver with id {@code mysql3} and keeps {@code postgresql} as a bare id under its
 *       "Deprecated drivers ... We leave just IDs to allow correct driver migration" block, so both
 *       ids exist under {@code generic} as well as under the real providers. A generic JDBC
 *       connection can point at anything, so an id-only allowlist would authorise an arbitrary
 *       server.</li>
 * </ul>
 * The MySQL provider has the same shape: {@code datasource id="mysql"} also carries
 * {@code mariaDB}, {@code starRocks} and {@code mysql_ndb}.
 * <p>
 * <b>Why {@code DBPDriver.matchesId} must not be used.</b> It compares against a driver's declared
 * replacements and <em>ignores the provider</em>. The real PostgreSQL driver declares
 * {@code <replace provider="generic" driver="postgresql"/>}, so {@code matchesId("postgresql")}
 * answers true for it - and a replacement declaration elsewhere could make some other driver answer
 * true for an id on this list. Identity here is the pair as declared, nothing else.
 * <p>
 * <b>Why custom drivers are refused.</b> A user-defined driver carries whatever provider its author
 * put it under while pointing its URL anywhere. {@code isCustom()} is checked so that the allowlist
 * describes shipped definitions only.
 */
public final class SupportedTargetDatabase {

    /**
     * One shipped driver definition, identified the only way that is unambiguous
     *
     * @param providerId {@code DBPDriver.getProviderId()} - the enclosing {@code <datasource id=...>}
     * @param driverId {@code DBPDriver.getId()} - the {@code <driver id=...>}
     */
    private record DriverIdentity(@NotNull String providerId, @NotNull String driverId) {
    }

    /**
     * The allowlist, with the label each entry carries in its plugin definition
     * <p>
     * Four entries, deliberately: the two drivers labelled PostgreSQL and the two labelled MySQL.
     * {@code mysql_ndb} (NDB Cluster), {@code mariaDB} and {@code starRocks} are different products
     * that happen to share a provider. {@code mysql3} is excluded twice over - it has no label in
     * the MySQL provider and its id collides with the generic provider's.
     */
    private static final Set<DriverIdentity> ALLOWED = Set.of(
        new DriverIdentity("postgresql", "postgres-jdbc"),   // label "PostgreSQL"
        new DriverIdentity("postgresql", "postgresql"),      // label "PostgreSQL (Old)"
        new DriverIdentity("mysql", "mysql8"),               // label "MySQL"
        new DriverIdentity("mysql", "mysql5")                // label "MySQL 5 (Legacy)"
    );

    private SupportedTargetDatabase() {
    }

    /**
     * Whether writes to this driver's databases may be authorised at all
     * <p>
     * Returns false for a null driver, a driver missing either identifier, a custom driver, and any
     * pair not on the list. There is no fallback and no partial match.
     */
    public static boolean isSupported(@Nullable DBPDriver driver) {
        if (driver == null) {
            return false;
        }
        if (driver.isCustom()) {
            return false;
        }
        String providerId = driver.getProviderId();
        String driverId = driver.getId();
        if (providerId == null || providerId.isBlank() || driverId == null || driverId.isBlank()) {
            return false;
        }
        return ALLOWED.contains(new DriverIdentity(providerId, driverId));
    }

    /**
     * The same allowlist test against a pair of strings
     * <p>
     * <b>Not an authorization gate.</b> It cannot see whether the driver is user-defined, so it
     * answers true for a custom driver whose author put it under a supported provider with a
     * supported id - and a custom driver's URL can point anywhere. A decision must go through
     * {@link #isSupported(DBPDriver)}, which refuses those. This overload exists so a test can
     * enumerate the list without building a driver, and it is the only caller today.
     */
    public static boolean isSupported(@Nullable String providerId, @Nullable String driverId) {
        if (providerId == null || providerId.isBlank() || driverId == null || driverId.isBlank()) {
            return false;
        }
        return ALLOWED.contains(new DriverIdentity(providerId, driverId));
    }

    /**
     * How many driver pairs the allowlist holds
     *
     * @return the size of the allowlist - pinned by a test so the list cannot grow unnoticed
     */
    public static int allowedCount() {
        return ALLOWED.size();
    }
}
