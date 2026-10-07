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

import io.cloudbeaver.service.dbac.db.DbacSchemaConstants;
import io.cloudbeaver.service.dbac.tempwrite.EndpointSnapshot;
import org.jkiss.code.NotNull;

import java.time.OffsetDateTime;

/**
 * The one statement the write gate runs
 * <p>
 * Reads, in a single round trip: the database clock, whether the user exists and is active, whether
 * a current grant exists, whether it is revoked, whether the database considers it unexpired, and
 * what connection it was granted for.
 * <p>
 * <b>Why one statement.</b> Splitting the clock from the grant would let a revoke commit between the
 * two reads, producing a decision that never described any real state of the database. With one
 * statement the read is the linearization point Phase 2 section 8.2 talks about: an authorization is
 * either entirely before a revoke's commit or entirely after it, never half of each.
 * <p>
 * <b>Why it always returns exactly one row.</b> The statement is anchored on a one-row derived table
 * carrying {@code CURRENT_TIMESTAMP} and left-joins everything else onto it. That distinction is
 * what lets the caller tell "this user has no grant" from "this user does not exist" from "the store
 * could not be read" - three different facts that a {@code WHERE ... AND EXPIRES_AT > ...} query
 * would flatten into one empty result set. Phase 2 section 4 shows such a query but labels it
 * "논리 형태(구현 코드 아님)"; taken literally it cannot produce the distinct denial reasons the same
 * section requires.
 * <p>
 * <b>Why the expiry comparison is a column.</b> {@code EXPIRES_AT > CURRENT_TIMESTAMP} is evaluated
 * by the database, not in Java, because Phase 2 section 8.1 makes the metadata database the sole
 * time authority. The two timestamps come back as well, but only so a test can check the boundary -
 * the decision reads the flag.
 * <p>
 * <b>Autocommit matters here.</b> Both supported engines pin {@code CURRENT_TIMESTAMP} to the start
 * of the enclosing transaction. That is measured on each of them rather than assumed, by a test of
 * the same name in both suites - {@code DbAccessPolicyTest.currentTimestampIsPinnedInsideATransaction}
 * for H2 and {@code DbAccessPolicyPostgresTest.currentTimestampIsPinnedInsideATransaction} for
 * PostgreSQL. Each reads the clock twice on one transaction-bound connection and requires the two
 * readings to be equal, then reads it on two separate connections and requires it to have moved, so
 * neither can pass on a database whose clock simply stood still.
 * <p>
 * So running this statement inside a long transaction would hand it the instant that transaction
 * began, and an expired grant would stay alive for as long as the transaction did. It is issued on a
 * connection in auto-commit, and a lease refuses to run it on one that is not. If either engine's
 * behaviour ever changes, the test named above fails and this requirement can be revisited - which
 * is the point of measuring it rather than writing it down.
 * <p>
 * <b>Portability.</b> Only constructs common to H2 and PostgreSQL are used: a derived table with an
 * alias, {@code LEFT JOIN}, {@code CASE}, and {@code CURRENT_TIMESTAMP}. No dialect functions, no
 * interval arithmetic, and every key value is bound as a parameter rather than concatenated.
 * <p>
 * <b>Through a lease, within a budget.</b> The statement runs on a {@link MetadataLease}: its whole
 * budget, borrow included, is the query timeout, the timeout is put back before a value is returned,
 * and the decision is taken from values already copied out of the driver, inside the {@code try}
 * block, before the lease is closed.
 */
final class PolicySnapshotRepository {

    /**
     * The CloudBeaver user table
     * <p>
     * Owned by {@code io.cloudbeaver.service.security}, not by this bundle, and named here as a
     * literal rather than imported: taking a compile-time dependency on that bundle to read one
     * table name would point the dependency arrow the wrong way (Phase 2 section 12.4). The coupling
     * is real either way - if upstream renames the table or its {@code IS_ACTIVE} column, this query
     * fails and every write is denied, which is the direction a coupling should fail in.
     */
    private static final String CB_USER_TABLE = "CB_USER";

    /**
     * The single authorization statement
     * <p>
     * {@code {table_prefix}} is substituted by {@code InternalProxyConnection.prepareStatement}, which
     * is why the leases must wrap {@code CBDatabase.openConnection()} and not a raw data source.
     */
    private static final String SNAPSHOT_QUERY =
        "SELECT n.DB_NOW,"
            + " u.USER_ID AS FOUND_USER, u.IS_ACTIVE,"
            + " g.GRANT_ID, g.EXPIRES_AT, g.REVOKED_AT,"
            + " g.PROVIDER_ID, g.DRIVER_ID, g.CONFIGURATION_TYPE,"
            + " g.HOST_SNAPSHOT, g.PORT_SNAPSHOT, g.DATABASE_SNAPSHOT,"
            + " CASE WHEN g.GRANT_ID IS NOT NULL AND g.EXPIRES_AT > n.DB_NOW THEN 1 ELSE 0 END AS NOT_EXPIRED"
            + " FROM (SELECT CURRENT_TIMESTAMP AS DB_NOW) n"
            + " LEFT JOIN {table_prefix}" + CB_USER_TABLE + " u ON u.USER_ID = ?"
            + " LEFT JOIN {table_prefix}" + DbacSchemaConstants.TABLE_TW_CURRENT + " g"
            + " ON g.USER_ID = ? AND g.PROJECT_ID = ? AND g.CONNECTION_ID = ?";

    /**
     * The value {@code CB_USER.IS_ACTIVE} carries for an enabled account
     * <p>
     * Anything else - {@code 'N'}, null, or a value nobody expected - is read as not active. The
     * comparison is written that way round on purpose: a new value added upstream should stop writes,
     * not permit them.
     */
    private static final String ACTIVE_FLAG = "Y";

    private PolicySnapshotRepository() {
    }

    /**
     * What one read produced: a snapshot, or a reason there is none
     */
    sealed interface SnapshotRead permits SnapshotRead.Read, SnapshotRead.Unusable {
        /**
         * The snapshot
         *
         * @param snapshot what the statement returned
         */
        record Read(@NotNull PolicySnapshot snapshot) implements SnapshotRead {
        }

        /**
         * No snapshot; the store could not be read
         *
         * @param cause which step of the lease failed
         */
        record Unusable(@NotNull UnusableCause cause) implements SnapshotRead {
        }
    }

    /**
     * Reads the snapshot for one key, on one lease from {@code leases}, within {@code budget}
     *
     * @return the snapshot, or {@code Unusable} - never "nothing found". The caller turns an unusable
     *     read into {@code PERMISSION_STORE_UNAVAILABLE}; a repository that returned "no grant" for an
     *     outage would make an outage indistinguishable from a revocation.
     * @throws MetadataUnavailableException when no lease could be had
     */
    @NotNull
    static SnapshotRead read(
        @NotNull MetadataLeaseSource leases,
        @NotNull MetadataBudget budget,
        @NotNull DbAccessKey key
    ) throws MetadataUnavailableException {
        try (MetadataLease lease = leases.open(budget, MetadataPurpose.SNAPSHOT)) {
            MetadataOutcome<MetadataRows> outcome = lease.query(query(key));
            if (outcome instanceof MetadataOutcome.Done<MetadataRows> done) {
                return new SnapshotRead.Read(toSnapshot(done.value().row(0)));
            }
            return new SnapshotRead.Unusable(((MetadataOutcome.Unusable<MetadataRows>) outcome).cause());
        }
    }

    /**
     * The statement for one key, with the columns it is read as
     * <p>
     * Exactly one row: the anchor is a one-row derived table, so anything else is a store failure, never
     * "no grant". {@code DB_NOW} cannot be null for the same reason.
     */
    @NotNull
    private static MetadataQuery query(@NotNull DbAccessKey key) {
        return MetadataQuery.sql(SNAPSHOT_QUERY)
            .bindString(key.userId())
            .bindString(key.userId())
            .bindString(key.projectId())
            .bindString(key.connectionId())
            .columnTimestamp("DB_NOW", false)
            .columnString("FOUND_USER", true)
            .columnString("IS_ACTIVE", true)
            .columnString("GRANT_ID", true)
            .columnTimestamp("EXPIRES_AT", true)
            .columnTimestamp("REVOKED_AT", true)
            .columnString("PROVIDER_ID", true)
            .columnString("DRIVER_ID", true)
            .columnString("CONFIGURATION_TYPE", true)
            .columnString("HOST_SNAPSHOT", true)
            .columnString("PORT_SNAPSHOT", true)
            .columnString("DATABASE_SNAPSHOT", true)
            .columnInt("NOT_EXPIRED")
            .expectRows(1, 1)
            .build();
    }

    @NotNull
    private static PolicySnapshot toSnapshot(@NotNull MetadataRow row) {
        OffsetDateTime dbNow = row.timestamp("DB_NOW");
        boolean userRowPresent = row.string("FOUND_USER") != null;
        boolean userActive = ACTIVE_FLAG.equals(row.string("IS_ACTIVE"));
        String grantId = row.string("GRANT_ID");
        OffsetDateTime expiresAt = row.timestamp("EXPIRES_AT");
        OffsetDateTime revokedAt = row.timestamp("REVOKED_AT");
        boolean notExpired = row.integer("NOT_EXPIRED") == 1;
        // Null whenever any part is missing, which is what a row written by schema
        // version 2 looks like. Never partially populated: comparing a subset of the
        // identity is how the port succession this column set exists to catch got through.
        EndpointSnapshot stored = grantId == null ? null : EndpointSnapshot.ofStored(
            row.string("PROVIDER_ID"),
            row.string("DRIVER_ID"),
            row.string("CONFIGURATION_TYPE"),
            row.string("HOST_SNAPSHOT"),
            row.string("PORT_SNAPSHOT"),
            row.string("DATABASE_SNAPSHOT"));
        return new PolicySnapshot(dbNow, userRowPresent, userActive, grantId, expiresAt, revokedAt, notExpired, stored);
    }

}
