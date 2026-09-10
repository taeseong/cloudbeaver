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

import io.cloudbeaver.service.dbac.db.DbacSchemaConstants;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * SQL for the TEMP_WRITE current-state and history tables, and nothing else
 * <p>
 * No policy lives here. This layer does not decide whether a grant is allowed, whether the caller is
 * an administrator, or whether a duration is acceptable; it reads and writes rows exactly as asked
 * and reports what the database did. {@link TempWriteMutationCoordinator} owns the transaction, the
 * compare-and-set decision and the retry policy.
 * <p>
 * Every method takes the caller's {@link Connection} rather than opening its own, so that a current
 * row and its history event are written in one transaction. The connection must come from
 * {@code CBDatabase.openConnection()}: that path wraps the connection in the proxy which substitutes
 * {@code {table_prefix}}, so bypassing it and using the pooled {@code DataSource} directly would send
 * the literal placeholder to the server.
 * <p>
 * Absence is an {@link Optional} or an empty list. A failure is a thrown {@link SQLException} and is
 * never converted into "no rows": a caller that cannot tell a broken metadata database from an empty
 * one would treat an outage as "this user has no grant", which is the wrong answer in the wrong
 * direction. Only {@code H2}- and {@code PostgreSQL}-portable SQL is used - no {@code MERGE}, no
 * {@code ON CONFLICT}, no vendor upsert, no locking hints.
 */
public class TempWriteGrantRepository {

    private static final String CURRENT_TABLE = "{table_prefix}" + DbacSchemaConstants.TABLE_TW_CURRENT;
    private static final String HISTORY_TABLE = "{table_prefix}" + DbacSchemaConstants.TABLE_TW_HISTORY;

    private static final String CURRENT_COLUMNS =
        "USER_ID, PROJECT_ID, CONNECTION_ID, GRANT_ID, REVISION, GRANTED_BY, GRANTED_AT, EXPIRES_AT, REASON,"
            + " REVOKED_AT, REVOKED_BY, REVOKE_REASON,"
            + " PROVIDER_ID, DRIVER_ID, CONFIGURATION_TYPE, HOST_SNAPSHOT, PORT_SNAPSHOT, DATABASE_SNAPSHOT";

    private static final String SELECT_CURRENT =
        "SELECT " + CURRENT_COLUMNS + " FROM " + CURRENT_TABLE
            + " WHERE USER_ID=? AND PROJECT_ID=? AND CONNECTION_ID=?";

    private static final String SELECT_BY_USER =
        "SELECT " + CURRENT_COLUMNS + " FROM " + CURRENT_TABLE
            + " WHERE USER_ID=? ORDER BY PROJECT_ID, CONNECTION_ID";

    private static final String SELECT_BY_CONNECTION =
        "SELECT " + CURRENT_COLUMNS + " FROM " + CURRENT_TABLE
            + " WHERE PROJECT_ID=? AND CONNECTION_ID=? ORDER BY USER_ID";

    private static final String INSERT_CURRENT =
        "INSERT INTO " + CURRENT_TABLE + " (" + CURRENT_COLUMNS + ")"
            + " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

    private static final String UPDATE_CURRENT =
        "UPDATE " + CURRENT_TABLE
            + " SET GRANT_ID=?, REVISION=?, GRANTED_BY=?, GRANTED_AT=?, EXPIRES_AT=?, REASON=?,"
            + " REVOKED_AT=NULL, REVOKED_BY=NULL, REVOKE_REASON=NULL,"
            + " PROVIDER_ID=?, DRIVER_ID=?, CONFIGURATION_TYPE=?,"
            + " HOST_SNAPSHOT=?, PORT_SNAPSHOT=?, DATABASE_SNAPSHOT=?"
            + " WHERE USER_ID=? AND PROJECT_ID=? AND CONNECTION_ID=? AND REVISION=?";

    private static final String REVOKE_CURRENT =
        "UPDATE " + CURRENT_TABLE
            + " SET REVISION=?, REVOKED_AT=?, REVOKED_BY=?, REVOKE_REASON=?"
            + " WHERE USER_ID=? AND PROJECT_ID=? AND CONNECTION_ID=? AND REVISION=? AND REVOKED_AT IS NULL";

    private static final String INSERT_HISTORY =
        "INSERT INTO " + HISTORY_TABLE
            + " (EVENT_ID, GRANT_ID, CHANGE_TYPE, CHANGE_TIME, USER_ID, PROJECT_ID, CONNECTION_ID,"
            + " ACTOR_ID, EXPIRES_AT, REASON, REVISION)"
            + " VALUES(?,?,?,?,?,?,?,?,?,?,?)";

    /**
     * Reads the current row of one key
     *
     * @return the row, or empty when this key has never been granted
     * @throws SQLException if the metadata database cannot be read
     */
    @NotNull
    public Optional<TempWriteGrant> findCurrent(
        @NotNull Connection connection,
        @NotNull TempWritePermissionKey key
    ) throws SQLException {
        try (PreparedStatement dbStat = connection.prepareStatement(SELECT_CURRENT)) {
            bindKey(dbStat, 1, key);
            try (ResultSet dbResult = dbStat.executeQuery()) {
                if (!dbResult.next()) {
                    return Optional.empty();
                }
                return Optional.of(readGrant(dbResult));
            }
        }
    }

    /**
     * Inserts the first current row for a key, at {@link TempWriteGrant#FIRST_REVISION}
     * <p>
     * A concurrent insert on the same key fails on the primary key rather than producing a second
     * active row. That failure is the compare-and-set losing, and the coordinator treats it as such.
     *
     * @return the number of rows inserted, which is 1 on success
     * @throws SQLException if the insert fails, including a primary key violation
     */
    public int insertCurrent(@NotNull Connection connection, @NotNull TempWriteGrant grant) throws SQLException {
        try (PreparedStatement dbStat = connection.prepareStatement(INSERT_CURRENT)) {
            int index = bindKey(dbStat, 1, grant.key());
            dbStat.setString(index++, grant.grantId());
            dbStat.setLong(index++, grant.revision());
            dbStat.setString(index++, grant.grantedBy());
            setTime(dbStat, index++, grant.grantedAt());
            setTime(dbStat, index++, grant.expiresAt());
            dbStat.setString(index++, grant.reason());
            setTime(dbStat, index++, grant.revokedAt());
            setString(dbStat, index++, grant.revokedBy());
            setString(dbStat, index++, grant.revokeReason());
            bindEndpoint(dbStat, index, requireEndpoint(grant));
            return dbStat.executeUpdate();
        }
    }

    /**
     * Replaces the current row of a key, but only while it still carries the expected revision
     * <p>
     * The revision predicate is the compare-and-set. A build that omitted it would let a request
     * that started from an older view overwrite a newer grant, leaving a row that claims a window
     * nobody authorised. Also clears the revoke columns, because the row now describes a live grant.
     *
     * @param expectedRevision the revision the row must still hold, from the request's fixed start value
     * @return 1 when the row was replaced, 0 when another writer moved it first
     * @throws SQLException if the metadata database cannot be written
     */
    public int updateCurrentWithRevision(
        @NotNull Connection connection,
        @NotNull TempWriteGrant grant,
        long expectedRevision
    ) throws SQLException {
        try (PreparedStatement dbStat = connection.prepareStatement(UPDATE_CURRENT)) {
            int index = 1;
            dbStat.setString(index++, grant.grantId());
            dbStat.setLong(index++, grant.revision());
            dbStat.setString(index++, grant.grantedBy());
            setTime(dbStat, index++, grant.grantedAt());
            setTime(dbStat, index++, grant.expiresAt());
            dbStat.setString(index++, grant.reason());
            index = bindEndpoint(dbStat, index, requireEndpoint(grant));
            index = bindKey(dbStat, index, grant.key());
            dbStat.setLong(index, expectedRevision);
            return dbStat.executeUpdate();
        }
    }

    /**
     * Marks the current row revoked, but only while it is still active and carries the expected revision
     * <p>
     * {@code REVOKED_AT IS NULL} in the predicate makes a repeated revoke report 0 rows instead of
     * overwriting the original revoke time, which keeps the first revoke as the one on record.
     *
     * @param expectedRevision the revision the row must still hold, from the request's fixed start value
     * @param revokedAt the database clock reading for this transaction
     * @return 1 when the row was revoked, 0 when it was already revoked or another writer moved it
     * @throws SQLException if the metadata database cannot be written
     */
    public int revokeCurrentWithRevision(
        @NotNull Connection connection,
        @NotNull TempWritePermissionKey key,
        long expectedRevision,
        long newRevision,
        @NotNull MetadataDbTime revokedAt,
        @NotNull String revokedBy,
        @NotNull String revokeReason
    ) throws SQLException {
        try (PreparedStatement dbStat = connection.prepareStatement(REVOKE_CURRENT)) {
            int index = 1;
            dbStat.setLong(index++, newRevision);
            setTime(dbStat, index++, revokedAt);
            dbStat.setString(index++, revokedBy);
            dbStat.setString(index++, revokeReason);
            index = bindKey(dbStat, index, key);
            dbStat.setLong(index, expectedRevision);
            return dbStat.executeUpdate();
        }
    }

    /**
     * Appends one history event
     * <p>
     * Called in the same transaction as the current-row change it describes. If this fails the whole
     * transaction is rolled back, so a state change never lands without its trace.
     *
     * @throws SQLException if the metadata database cannot be written
     */
    public void appendHistory(
        @NotNull Connection connection,
        @NotNull TempWriteHistoryEvent event
    ) throws SQLException {
        try (PreparedStatement dbStat = connection.prepareStatement(INSERT_HISTORY)) {
            int index = 1;
            dbStat.setString(index++, event.eventId());
            dbStat.setString(index++, event.grantId());
            dbStat.setString(index++, event.changeType().name());
            setTime(dbStat, index++, event.changeTime());
            index = bindKey(dbStat, index, event.key());
            dbStat.setString(index++, event.actorId());
            setTime(dbStat, index++, event.expiresAt());
            setString(dbStat, index++, event.reason());
            dbStat.setLong(index, event.revision());
            dbStat.executeUpdate();
        }
    }

    /**
     * Lists every current row of one user, across projects and connections
     *
     * @return the rows, possibly empty
     * @throws SQLException if the metadata database cannot be read
     */
    @NotNull
    public List<TempWriteGrant> listByUser(
        @NotNull Connection connection,
        @NotNull String userId
    ) throws SQLException {
        try (PreparedStatement dbStat = connection.prepareStatement(SELECT_BY_USER)) {
            dbStat.setString(1, userId);
            return readGrants(dbStat);
        }
    }

    /**
     * Lists every current row of one connection, across users
     *
     * @return the rows, possibly empty
     * @throws SQLException if the metadata database cannot be read
     */
    @NotNull
    public List<TempWriteGrant> listByConnection(
        @NotNull Connection connection,
        @NotNull String projectId,
        @NotNull String connectionId
    ) throws SQLException {
        try (PreparedStatement dbStat = connection.prepareStatement(SELECT_BY_CONNECTION)) {
            dbStat.setString(1, projectId);
            dbStat.setString(2, connectionId);
            return readGrants(dbStat);
        }
    }

    @NotNull
    private static List<TempWriteGrant> readGrants(@NotNull PreparedStatement dbStat) throws SQLException {
        List<TempWriteGrant> grants = new ArrayList<>();
        try (ResultSet dbResult = dbStat.executeQuery()) {
            while (dbResult.next()) {
                grants.add(readGrant(dbResult));
            }
        }
        return grants;
    }

    @NotNull
    private static TempWriteGrant readGrant(@NotNull ResultSet dbResult) throws SQLException {
        return new TempWriteGrant(
            new TempWritePermissionKey(
                requireString(dbResult, "USER_ID"),
                requireString(dbResult, "PROJECT_ID"),
                requireString(dbResult, "CONNECTION_ID")),
            requireString(dbResult, "GRANT_ID"),
            dbResult.getLong("REVISION"),
            requireString(dbResult, "GRANTED_BY"),
            requireTime(dbResult, "GRANTED_AT"),
            requireTime(dbResult, "EXPIRES_AT"),
            requireString(dbResult, "REASON"),
            readTime(dbResult, "REVOKED_AT"),
            dbResult.getString("REVOKED_BY"),
            dbResult.getString("REVOKE_REASON"),
            EndpointSnapshot.ofStored(
                dbResult.getString("PROVIDER_ID"),
                dbResult.getString("DRIVER_ID"),
                dbResult.getString("CONFIGURATION_TYPE"),
                dbResult.getString("HOST_SNAPSHOT"),
                dbResult.getString("PORT_SNAPSHOT"),
                dbResult.getString("DATABASE_SNAPSHOT")));
    }

    /**
     * The endpoint a row is about to be written with
     * <p>
     * Throws rather than writing nulls. A grant is only ever stored from a request, and a request
     * cannot carry an absent endpoint, so reaching this with null means a caller assembled a
     * {@link TempWriteGrant} by hand from a row it had read - which would write a grant that
     * authorises nothing identifiable. Failing loudly here beats a constraint violation from three
     * frames deeper, and beats silently storing a row that can never match.
     */
    @NotNull
    private static EndpointSnapshot requireEndpoint(@NotNull TempWriteGrant grant) {
        EndpointSnapshot endpoint = grant.endpoint();
        if (endpoint == null) {
            throw new IllegalStateException(
                "A TEMP_WRITE grant cannot be stored without an endpoint; grant " + grant.grantId());
        }
        return endpoint;
    }

    private static int bindEndpoint(
        @NotNull PreparedStatement dbStat,
        int firstIndex,
        @NotNull EndpointSnapshot endpoint
    ) throws SQLException {
        int index = firstIndex;
        dbStat.setString(index++, endpoint.providerId());
        dbStat.setString(index++, endpoint.driverId());
        dbStat.setString(index++, endpoint.configurationType());
        dbStat.setString(index++, endpoint.host());
        dbStat.setString(index++, endpoint.port());
        dbStat.setString(index++, endpoint.database());
        return index;
    }

    private static int bindKey(
        @NotNull PreparedStatement dbStat,
        int firstIndex,
        @NotNull TempWritePermissionKey key
    ) throws SQLException {
        int index = firstIndex;
        dbStat.setString(index++, key.userId());
        dbStat.setString(index++, key.projectId());
        dbStat.setString(index++, key.connectionId());
        return index;
    }

    private static void setTime(
        @NotNull PreparedStatement dbStat,
        int index,
        @Nullable MetadataDbTime value
    ) throws SQLException {
        if (value == null) {
            dbStat.setNull(index, Types.TIMESTAMP_WITH_TIMEZONE);
        } else {
            dbStat.setObject(index, value.stored());
        }
    }

    private static void setString(
        @NotNull PreparedStatement dbStat,
        int index,
        @Nullable String value
    ) throws SQLException {
        if (value == null) {
            dbStat.setNull(index, Types.VARCHAR);
        } else {
            dbStat.setString(index, value);
        }
    }

    @Nullable
    private static MetadataDbTime readTime(@NotNull ResultSet dbResult, @NotNull String column) throws SQLException {
        OffsetDateTime value = dbResult.getObject(column, OffsetDateTime.class);
        return value == null ? null : MetadataDbTime.ofStored(value);
    }

    @NotNull
    private static MetadataDbTime requireTime(@NotNull ResultSet dbResult, @NotNull String column) throws SQLException {
        MetadataDbTime value = readTime(dbResult, column);
        if (value == null) {
            throw new SQLException("Column " + column + " of " + DbacSchemaConstants.TABLE_TW_CURRENT
                + " is declared NOT NULL but came back null");
        }
        return value;
    }

    @NotNull
    private static String requireString(@NotNull ResultSet dbResult, @NotNull String column) throws SQLException {
        String value = dbResult.getString(column);
        if (value == null) {
            throw new SQLException("Column " + column + " of " + DbacSchemaConstants.TABLE_TW_CURRENT
                + " is declared NOT NULL but came back null");
        }
        return value;
    }
}
