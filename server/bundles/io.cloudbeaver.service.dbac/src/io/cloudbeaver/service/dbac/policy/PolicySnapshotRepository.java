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

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
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
 * connection in auto-commit, and the caller is refused if that is not the case. If either engine's
 * behaviour ever changes, the test named above fails and this requirement can be revisited - which
 * is the point of measuring it rather than writing it down.
 * <p>
 * <b>Portability.</b> Only constructs common to H2 and PostgreSQL are used: a derived table with an
 * alias, {@code LEFT JOIN}, {@code CASE}, and {@code CURRENT_TIMESTAMP}. No dialect functions, no
 * interval arithmetic, and every key value is bound as a parameter rather than concatenated.
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
     * is why the connection must come from {@code CBDatabase.openConnection()} and not from a raw
     * data source.
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
     * Reads the snapshot for one key
     *
     * @throws SQLException propagated, never converted to an empty snapshot. The caller turns it
     *     into {@code PERMISSION_STORE_UNAVAILABLE}; a repository that returned "nothing found" for
     *     an outage would make an outage indistinguishable from a revocation.
     * @throws IllegalStateException if the connection is not in auto-commit, because the clock this
     *     statement returns would then belong to a transaction that started at an unknown time
     */
    @NotNull
    static PolicySnapshot read(@NotNull Connection connection, @NotNull DbAccessKey key) throws SQLException {
        if (!connection.getAutoCommit()) {
            throw new IllegalStateException(
                "The authorization snapshot must run in auto-commit; on both supported engines"
                    + " CURRENT_TIMESTAMP is pinned to the start of an enclosing transaction, which would"
                    + " hand this statement a clock older than the decision it is about");
        }
        try (PreparedStatement dbStat = connection.prepareStatement(SNAPSHOT_QUERY)) {
            dbStat.setString(1, key.userId());
            dbStat.setString(2, key.userId());
            dbStat.setString(3, key.projectId());
            dbStat.setString(4, key.connectionId());
            try (ResultSet dbResult = dbStat.executeQuery()) {
                if (!dbResult.next()) {
                    // The anchor is a one-row derived table, so this cannot happen against a healthy
                    // database. Treated as a store failure rather than as "no grant".
                    throw new SQLException("The DBAC authorization snapshot returned no row");
                }
                OffsetDateTime dbNow = dbResult.getObject("DB_NOW", OffsetDateTime.class);
                if (dbNow == null) {
                    throw new SQLException("The DBAC authorization snapshot returned no database clock");
                }
                boolean userRowPresent = dbResult.getString("FOUND_USER") != null;
                boolean userActive = ACTIVE_FLAG.equals(dbResult.getString("IS_ACTIVE"));
                String grantId = dbResult.getString("GRANT_ID");
                OffsetDateTime expiresAt = dbResult.getObject("EXPIRES_AT", OffsetDateTime.class);
                OffsetDateTime revokedAt = dbResult.getObject("REVOKED_AT", OffsetDateTime.class);
                boolean notExpired = dbResult.getInt("NOT_EXPIRED") == 1;
                // Null whenever any part is missing, which is what a row written by schema
                // version 2 looks like. Never partially populated: comparing a subset of the
                // identity is how the port succession this column set exists to catch got through.
                EndpointSnapshot stored = grantId == null ? null : EndpointSnapshot.ofStored(
                    dbResult.getString("PROVIDER_ID"),
                    dbResult.getString("DRIVER_ID"),
                    dbResult.getString("CONFIGURATION_TYPE"),
                    dbResult.getString("HOST_SNAPSHOT"),
                    dbResult.getString("PORT_SNAPSHOT"),
                    dbResult.getString("DATABASE_SNAPSHOT"));
                return new PolicySnapshot(
                    dbNow, userRowPresent, userActive, grantId, expiresAt, revokedAt, notExpired, stored);
            }
        }
    }

}
