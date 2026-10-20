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
package io.cloudbeaver.test.platform.dbac;

import io.cloudbeaver.service.dbac.db.DbacSchemaConstants;
import io.cloudbeaver.service.dbac.db.DbacSchemaVersionManager;
import io.cloudbeaver.service.dbac.tempwrite.MetadataConnectionSource;
import io.cloudbeaver.service.security.db.CBDatabase;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.jkiss.dbeaver.DBException;
import org.jkiss.dbeaver.ext.postgresql.model.PostgreDialect;
import org.jkiss.dbeaver.model.connection.InternalDatabaseConfig;
import org.jkiss.dbeaver.model.runtime.DBRProgressMonitor;
import org.jkiss.dbeaver.model.sql.SQLDialect;
import org.jkiss.dbeaver.model.sql.db.InternalProxyConnection;
import org.jkiss.dbeaver.model.sql.schema.SQLSchemaManager;
import org.jkiss.dbeaver.model.sql.schema.SQLSchemaScriptSource;
import org.jkiss.dbeaver.model.sql.schema.SQLSchemaVersionManager;
import org.junit.jupiter.api.Assertions;

import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Savepoint;
import java.sql.Statement;
import java.sql.Types;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Fixtures shared by the P5-F tests: schemas at a chosen version, legacy grants, users, and connections that act at a chosen statement
 * <p>
 * Every row here is written with plain SQL, never through the code under test, so a test that reads the
 * result back is not agreeing with itself. A schema is installed by the real migration runner and the
 * real version manager - a "version 3 database" is one a version 3 build installed - and is dropped by
 * the test that made it.
 */
final class FenceTestSupport {

    /** Who the version 4 quarantine records as having revoked a legacy grant - the value the user approved */
    static final String FENCE_ACTOR = "<dbac-fence-v4>";
    /** The reason the version 4 quarantine records */
    static final String FENCE_REASON = "quarantined when the user-incarnation fence was introduced";

    static final String PROJECT = "fence-project";
    static final String CONNECTION = "fence-connection";

    /** The CloudBeaver tables a user needs, taken from the product's own create script */
    private static final List<String> CB_TABLES = List.of("CB_AUTH_SUBJECT", "CB_CREDENTIALS_PROFILE", "CB_USER", "CB_TEAM");
    private static final Pattern CREATE_TABLE = Pattern.compile("^CREATE TABLE \\{table_prefix}(\\w+)\\s*\\(", Pattern.DOTALL);

    private FenceTestSupport() {
    }

    // ---------------------------------------------------------------- engines

    /** A metadata database a migration runs against */
    interface Engine {
        @NotNull
        String name();

        /** The schema name this engine needs for {@code tag}: H2 folds unquoted names up, PostgreSQL down */
        @NotNull
        String schemaName(@NotNull String tag);

        /** A raw connection, outside any schema prefix */
        @NotNull
        Connection raw() throws Exception;

        @NotNull
        SQLDialect dialect();

        /** A connection whose {@code {table_prefix}} is {@code schema} */
        @NotNull
        default Db open(@NotNull String schema) throws Exception {
            Connection raw = raw();
            return new Db(raw, new InternalProxyConnection(raw, DbacTestSupport.config(null, schema)), schema);
        }
    }

    /** The test server's own H2 metadata database, one fresh schema per test */
    @NotNull
    static Engine h2(@NotNull CBDatabase database) {
        return new Engine() {
            @NotNull
            @Override
            public String name() {
                return "H2";
            }

            @NotNull
            @Override
            public String schemaName(@NotNull String tag) {
                return ("DBAC_FENCE_" + tag).toUpperCase(Locale.ROOT);
            }

            @NotNull
            @Override
            public Connection raw() throws Exception {
                return database.openConnection();
            }

            @NotNull
            @Override
            public SQLDialect dialect() {
                return database.getDialect();
            }
        };
    }

    /** The disposable PostgreSQL the DBAC suite requires */
    @NotNull
    static Engine postgres() {
        return new Engine() {
            @NotNull
            @Override
            public String name() {
                return "PostgreSQL";
            }

            @NotNull
            @Override
            public String schemaName(@NotNull String tag) {
                return ("dbac_fence_" + tag).toLowerCase(Locale.ROOT);
            }

            @NotNull
            @Override
            public Connection raw() throws Exception {
                return EnforcementTestSupport.openRawPostgres(KeyLockTestSupport.MONITOR);
            }

            @NotNull
            @Override
            public SQLDialect dialect() {
                return new PostgreDialect();
            }
        };
    }

    /** A metadata connection source over {@code schema} of {@code engine}, as a policy service or a coordinator takes one */
    @NotNull
    static MetadataConnectionSource source(@NotNull Engine engine, @NotNull String schema) {
        return () -> {
            try {
                return engine.open(schema).proxied();
            } catch (SQLException e) {
                throw e;
            } catch (Exception e) {
                throw new SQLException("FIXTURE: a connection to " + engine.name() + " could not be opened", e);
            }
        };
    }

    /** How many rows of {@code table} have {@code column = value} */
    static int count(@NotNull Connection proxied, @NotNull String table, @NotNull String column, @NotNull String value)
            throws SQLException {
        try (PreparedStatement dbStat = proxied.prepareStatement(
            "SELECT COUNT(*) FROM {table_prefix}" + table + " WHERE " + column + " = ?")) {
            dbStat.setString(1, value);
            try (ResultSet dbResult = dbStat.executeQuery()) {
                dbResult.next();
                return dbResult.getInt(1);
            }
        }
    }

    /** A raw connection and its prefixed view; closing it closes the raw one */
    record Db(@NotNull Connection raw, @NotNull Connection proxied, @NotNull String schema) implements AutoCloseable {
        @Override
        public void close() throws SQLException {
            raw.close();
        }
    }

    static void freshSchema(@NotNull Engine engine, @NotNull String schema) throws Exception {
        try (Connection raw = engine.raw(); Statement dbStat = raw.createStatement()) {
            dbStat.execute("DROP SCHEMA IF EXISTS " + schema + " CASCADE");
            dbStat.execute("CREATE SCHEMA " + schema);
        }
    }

    static void dropSchema(@NotNull Engine engine, @NotNull String schema) throws Exception {
        try (Connection raw = engine.raw(); Statement dbStat = raw.createStatement()) {
            dbStat.execute("DROP SCHEMA IF EXISTS " + schema + " CASCADE");
        }
    }

    static int countSchemas(@NotNull Engine engine, @NotNull String schema) throws Exception {
        try (Connection raw = engine.raw();
             PreparedStatement dbStat = raw.prepareStatement(
                 "SELECT COUNT(*) FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = ?")) {
            dbStat.setString(1, schema);
            try (ResultSet dbResult = dbStat.executeQuery()) {
                dbResult.next();
                return dbResult.getInt(1);
            }
        }
    }

    // ---------------------------------------------------------------- migrations

    /**
     * Runs the real migration runner over {@code connection} with a version manager that ships {@code shipped}
     * <p>
     * {@code shipped} below the current version is a build of that version: version 3 installs or upgrades
     * exactly as the P4 build did, which is how a "version 3 database" is made.
     */
    static void migrate(
        @NotNull Connection connection,
        @NotNull String schema,
        @NotNull SQLDialect dialect,
        int shipped,
        @NotNull SQLSchemaScriptSource scripts
    ) throws Exception {
        migrate(connection, schema, dialect, scripts, versionManager(shipped));
    }

    /** Runs the real migration runner over {@code connection} with {@code versionManager}, shipping the version it reports as latest */
    static void migrate(
        @NotNull Connection connection,
        @NotNull String schema,
        @NotNull SQLDialect dialect,
        @NotNull SQLSchemaScriptSource scripts,
        @NotNull SQLSchemaVersionManager versionManager
    ) throws Exception {
        InternalDatabaseConfig config = DbacTestSupport.config(null, schema);
        int shipped = versionManager.getLatestSchemaVersion();
        new SQLSchemaManager(
            DbacSchemaConstants.SCHEMA_ID,
            scripts,
            monitor -> connection,
            versionManager,
            dialect,
            shipped,
            DbacSchemaConstants.OBSOLETE_SCHEMA_VERSION,
            config,
            null).updateSchema(KeyLockTestSupport.MONITOR);
    }

    /**
     * This build's version manager, remembering what recording the fence version threw before the migration runner handled it
     * <p>
     * The runner may end the start with a failure of its own instead - when its rollback fails, say - so a test that needs to know
     * what the fence itself refused with asks this.
     */
    static final class Recording implements SQLSchemaVersionManager {
        private final DbacSchemaVersionManager delegate = versionManager(DbacSchemaConstants.CURRENT_SCHEMA_VERSION);
        /** Whether the fence version was asked to be recorded at all */
        volatile boolean fenceAsked;
        /** What recording it threw, if anything */
        volatile Throwable fenceThrew;

        @Override
        public int getCurrentSchemaVersion(@NotNull DBRProgressMonitor monitor, @NotNull Connection connection, @NotNull String schemaName)
                throws DBException, SQLException {
            return delegate.getCurrentSchemaVersion(monitor, connection, schemaName);
        }

        @Override
        public int getLatestSchemaVersion() {
            return delegate.getLatestSchemaVersion();
        }

        @Override
        public void updateCurrentSchemaVersion(
            @NotNull DBRProgressMonitor monitor,
            @NotNull Connection connection,
            @NotNull String schemaName,
            int version
        ) throws DBException, SQLException {
            if (version != DbacSchemaConstants.USER_FENCE_SINCE_VERSION) {
                delegate.updateCurrentSchemaVersion(monitor, connection, schemaName, version);
                return;
            }
            fenceAsked = true;
            try {
                delegate.updateCurrentSchemaVersion(monitor, connection, schemaName, version);
            } catch (Throwable e) {
                fenceThrew = e;
                throw e;
            }
        }
    }

    /** The version manager a build shipping {@code shipped} has */
    @NotNull
    static DbacSchemaVersionManager versionManager(int shipped) {
        return new DbacSchemaVersionManager(shipped, DbacSchemaConstants.SCHEMA_ID, DbacTestSupport.realScriptSource());
    }

    /** Installs the DBAC schema in a fresh {@code schema} as a version 3 build would, and the CloudBeaver user tables beside it */
    static void installVersionThree(@NotNull Engine engine, @NotNull String schema) throws Exception {
        freshSchema(engine, schema);
        try (Db db = engine.open(schema)) {
            migrate(db.proxied(), schema, engine.dialect(), 3, DbacTestSupport.realScriptSource());
            Assertions.assertEquals(3, DbacTestSupport.readVersion(db.proxied()), "FIXTURE: a version 3 build must record version 3");
            installUserTables(db.proxied());
        }
    }

    /** Upgrades {@code schema} with this build's migration, on its own connection */
    static void upgrade(@NotNull Engine engine, @NotNull String schema) throws Exception {
        try (Db db = engine.open(schema)) {
            migrate(db.proxied(), schema, engine.dialect(), DbacSchemaConstants.CURRENT_SCHEMA_VERSION,
                DbacTestSupport.realScriptSource());
        }
    }

    /**
     * Creates the CloudBeaver tables a user lives in, from the product's own DDL, in the connection's schema
     * <p>
     * The same four tables and the same statements as {@code LockIdentityCharacterizationTest} uses, so
     * {@code CB_USER} has its real key and its cascade from {@code CB_AUTH_SUBJECT}.
     */
    static void installUserTables(@NotNull Connection proxied) throws Exception {
        for (String ddl : userTableDdl()) {
            try (PreparedStatement dbStat = proxied.prepareStatement(ddl)) {
                dbStat.execute();
            }
        }
    }

    @NotNull
    private static List<String> userTableDdl() throws Exception {
        String script;
        try (InputStream in = CBDatabase.class.getClassLoader().getResourceAsStream("db/cb_schema_create.sql")) {
            Assertions.assertNotNull(in, "FIXTURE: cb_schema_create.sql was not found");
            script = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        List<String> statements = new ArrayList<>();
        for (String raw : script.split(";")) {
            String statement = raw.lines()
                .filter(line -> !line.trim().startsWith("--"))
                .collect(Collectors.joining("\n"))
                .trim();
            Matcher matcher = CREATE_TABLE.matcher(statement);
            if (matcher.find() && CB_TABLES.contains(matcher.group(1))) {
                statements.add(statement);
            }
        }
        Assertions.assertEquals(CB_TABLES.size(), statements.size(), "FIXTURE: not every user table was found in cb_schema_create.sql");
        return statements;
    }

    // ---------------------------------------------------------------- rows

    /** A grant row as it is stored */
    record GrantRow(
        @NotNull String userId,
        @NotNull String projectId,
        @NotNull String connectionId,
        @NotNull String grantId,
        long revision,
        @NotNull String grantedBy,
        @NotNull OffsetDateTime grantedAt,
        @NotNull OffsetDateTime expiresAt,
        @NotNull String reason,
        @Nullable OffsetDateTime revokedAt,
        @Nullable String revokedBy,
        @Nullable String revokeReason,
        @NotNull String endpoint
    ) {
        @NotNull
        String key() {
            return userId + "/" + projectId + "/" + connectionId;
        }

        /** Everything but the revocation, with instants rather than offsets */
        @NotNull
        String issued() {
            return key() + " " + grantId + " " + grantedBy + " " + grantedAt.toInstant() + " " + expiresAt.toInstant()
                + " " + reason + " " + endpoint;
        }

        /** The whole row, with instants rather than offsets */
        @NotNull
        String whole() {
            return issued() + " rev=" + revision + " revokedAt=" + (revokedAt == null ? null : revokedAt.toInstant())
                + " revokedBy=" + revokedBy + " revokeReason=" + revokeReason;
        }
    }

    /** A history row as it is stored */
    record HistoryRow(
        @NotNull String eventId,
        @NotNull String grantId,
        @NotNull String changeType,
        @NotNull OffsetDateTime changeTime,
        @NotNull String key,
        @NotNull String actorId,
        @Nullable OffsetDateTime expiresAt,
        @Nullable String reason,
        long revision
    ) {
        @NotNull
        String whole() {
            return eventId + " " + grantId + " " + changeType + " " + changeTime.toInstant() + " " + key + " " + actorId
                + " " + (expiresAt == null ? null : expiresAt.toInstant()) + " " + reason + " " + revision;
        }
    }

    /**
     * Writes a grant row straight into {@code DBAC_TW_CURRENT}
     *
     * @param expiresIn from now; negative for an expired grant
     * @param revokedBy null for a grant that is not revoked
     */
    static void insertGrant(
        @NotNull Connection proxied,
        @NotNull String userId,
        @NotNull String connectionId,
        long revision,
        @NotNull Duration expiresIn,
        @Nullable String revokedBy
    ) throws SQLException {
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        try (PreparedStatement dbStat = proxied.prepareStatement(
            "INSERT INTO {table_prefix}DBAC_TW_CURRENT (USER_ID, PROJECT_ID, CONNECTION_ID, GRANT_ID, REVISION, GRANTED_BY,"
                + " GRANTED_AT, EXPIRES_AT, REASON, REVOKED_AT, REVOKED_BY, REVOKE_REASON,"
                + " PROVIDER_ID, DRIVER_ID, CONFIGURATION_TYPE, HOST_SNAPSHOT, PORT_SNAPSHOT, DATABASE_SNAPSHOT)"
                + " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")) {
            int i = 1;
            dbStat.setString(i++, userId);
            dbStat.setString(i++, PROJECT);
            dbStat.setString(i++, connectionId);
            dbStat.setString(i++, "legacy-" + userId + "-" + connectionId);
            dbStat.setLong(i++, revision);
            dbStat.setString(i++, "admin-1");
            dbStat.setObject(i++, now.minusMinutes(5));
            dbStat.setObject(i++, now.plus(expiresIn));
            dbStat.setString(i++, "issued before the fence");
            if (revokedBy == null) {
                dbStat.setNull(i++, Types.TIMESTAMP_WITH_TIMEZONE);
            } else {
                dbStat.setObject(i++, now.minusMinutes(1));
            }
            dbStat.setString(i++, revokedBy);
            dbStat.setString(i++, revokedBy == null ? null : "revoked before the fence");
            dbStat.setString(i++, TempWriteTestSupport.ENDPOINT.providerId());
            dbStat.setString(i++, TempWriteTestSupport.ENDPOINT.driverId());
            dbStat.setString(i++, TempWriteTestSupport.ENDPOINT.configurationType());
            dbStat.setString(i++, TempWriteTestSupport.ENDPOINT.host());
            dbStat.setString(i++, TempWriteTestSupport.ENDPOINT.port());
            dbStat.setString(i, TempWriteTestSupport.ENDPOINT.database());
            Assertions.assertEquals(1, dbStat.executeUpdate(), "FIXTURE: the grant row was not written");
        }
    }

    /** Writes a history event straight into {@code DBAC_TW_HISTORY} */
    static void insertHistory(
        @NotNull Connection proxied,
        @NotNull String eventId,
        @NotNull String userId,
        @NotNull String connectionId,
        @NotNull String changeType,
        long revision
    ) throws SQLException {
        try (PreparedStatement dbStat = proxied.prepareStatement(
            "INSERT INTO {table_prefix}DBAC_TW_HISTORY (EVENT_ID, GRANT_ID, CHANGE_TYPE, CHANGE_TIME, USER_ID, PROJECT_ID,"
                + " CONNECTION_ID, ACTOR_ID, EXPIRES_AT, REASON, REVISION) VALUES (?,?,?,CURRENT_TIMESTAMP,?,?,?,?,NULL,?,?)")) {
            int i = 1;
            dbStat.setString(i++, eventId);
            dbStat.setString(i++, "legacy-" + userId + "-" + connectionId);
            dbStat.setString(i++, changeType);
            dbStat.setString(i++, userId);
            dbStat.setString(i++, PROJECT);
            dbStat.setString(i++, connectionId);
            dbStat.setString(i++, "admin-1");
            dbStat.setString(i++, "before the fence");
            dbStat.setLong(i, revision);
            Assertions.assertEquals(1, dbStat.executeUpdate(), "FIXTURE: the history row was not written");
        }
    }

    /** Every grant row, keyed and ordered by key */
    @NotNull
    static List<GrantRow> grants(@NotNull Connection proxied) throws SQLException {
        List<GrantRow> rows = new ArrayList<>();
        try (PreparedStatement dbStat = proxied.prepareStatement(
            "SELECT USER_ID, PROJECT_ID, CONNECTION_ID, GRANT_ID, REVISION, GRANTED_BY, GRANTED_AT, EXPIRES_AT, REASON,"
                + " REVOKED_AT, REVOKED_BY, REVOKE_REASON, PROVIDER_ID, DRIVER_ID, CONFIGURATION_TYPE, HOST_SNAPSHOT,"
                + " PORT_SNAPSHOT, DATABASE_SNAPSHOT FROM {table_prefix}DBAC_TW_CURRENT ORDER BY USER_ID, PROJECT_ID, CONNECTION_ID");
             ResultSet dbResult = dbStat.executeQuery()) {
            while (dbResult.next()) {
                rows.add(new GrantRow(
                    dbResult.getString("USER_ID"), dbResult.getString("PROJECT_ID"), dbResult.getString("CONNECTION_ID"),
                    dbResult.getString("GRANT_ID"), dbResult.getLong("REVISION"), dbResult.getString("GRANTED_BY"),
                    dbResult.getObject("GRANTED_AT", OffsetDateTime.class), dbResult.getObject("EXPIRES_AT", OffsetDateTime.class),
                    dbResult.getString("REASON"), dbResult.getObject("REVOKED_AT", OffsetDateTime.class),
                    dbResult.getString("REVOKED_BY"), dbResult.getString("REVOKE_REASON"),
                    dbResult.getString("PROVIDER_ID") + "|" + dbResult.getString("DRIVER_ID") + "|"
                        + dbResult.getString("CONFIGURATION_TYPE") + "|" + dbResult.getString("HOST_SNAPSHOT") + "|"
                        + dbResult.getString("PORT_SNAPSHOT") + "|" + dbResult.getString("DATABASE_SNAPSHOT")));
            }
        }
        return rows;
    }

    /** Every history row, ordered by event id */
    @NotNull
    static List<HistoryRow> history(@NotNull Connection proxied) throws SQLException {
        List<HistoryRow> rows = new ArrayList<>();
        try (PreparedStatement dbStat = proxied.prepareStatement(
            "SELECT EVENT_ID, GRANT_ID, CHANGE_TYPE, CHANGE_TIME, USER_ID, PROJECT_ID, CONNECTION_ID, ACTOR_ID, EXPIRES_AT,"
                + " REASON, REVISION FROM {table_prefix}DBAC_TW_HISTORY ORDER BY EVENT_ID");
             ResultSet dbResult = dbStat.executeQuery()) {
            while (dbResult.next()) {
                rows.add(new HistoryRow(
                    dbResult.getString("EVENT_ID"), dbResult.getString("GRANT_ID"), dbResult.getString("CHANGE_TYPE"),
                    dbResult.getObject("CHANGE_TIME", OffsetDateTime.class),
                    dbResult.getString("USER_ID") + "/" + dbResult.getString("PROJECT_ID") + "/" + dbResult.getString("CONNECTION_ID"),
                    dbResult.getString("ACTOR_ID"), dbResult.getObject("EXPIRES_AT", OffsetDateTime.class),
                    dbResult.getString("REASON"), dbResult.getLong("REVISION")));
            }
        }
        return rows;
    }

    @NotNull
    static List<String> wholeGrants(@NotNull Connection proxied) throws SQLException {
        return grants(proxied).stream().map(GrantRow::whole).toList();
    }

    @NotNull
    static List<String> wholeHistory(@NotNull Connection proxied) throws SQLException {
        return history(proxied).stream().map(HistoryRow::whole).toList();
    }

    static int unrevoked(@NotNull Connection proxied) throws SQLException {
        try (PreparedStatement dbStat = proxied.prepareStatement(
            "SELECT COUNT(*) FROM {table_prefix}DBAC_TW_CURRENT WHERE REVOKED_AT IS NULL AND 1 = 1");
             ResultSet dbResult = dbStat.executeQuery()) {
            dbResult.next();
            return dbResult.getInt(1);
        }
    }

    // ---------------------------------------------------------------- statements at a chosen moment

    /** What an intercepted connection does before a statement whose SQL matches */
    @FunctionalInterface
    interface Action {
        void run(@NotNull Connection target, @NotNull String sql, @NotNull List<Object> parameters) throws SQLException;
    }

    /** What {@link Intercepted#calls} records for a savepoint created, a rollback to a savepoint, a plain rollback and a close */
    static final String CALL_SET_SAVEPOINT = "setSavepoint";
    static final String CALL_ROLLBACK_TO_SAVEPOINT = "rollback(savepoint)";
    static final String CALL_ROLLBACK = "rollback";
    static final String CALL_CLOSE = "close";
    /** What {@link Intercepted#calls} puts before the SQL of a prepared statement */
    static final String CALL_PREPARE = "prepare ";

    /**
     * A connection that records the SQL of every statement it prepares, and runs {@code action} just before a matching one executes
     * <p>
     * The action sees the target connection, so it can act inside the very transaction under test, and the
     * parameters bound so far. The SQL is recorded as prepared - with {@code {table_prefix}} still in it.
     * <p>
     * It also records, in the order they happen, every statement prepared, every savepoint created, every rollback and every close;
     * and it makes creating a savepoint, rolling back to one or a plain rollback fail whenever the matching field is set.
     */
    static final class Intercepted {
        final List<String> prepared = Collections.synchronizedList(new ArrayList<>());
        final List<String> fired = Collections.synchronizedList(new ArrayList<>());
        /** Statements prepared, savepoints created, rollbacks and closes, in order */
        final List<String> calls = Collections.synchronizedList(new ArrayList<>());
        /** Every savepoint created through this connection, in order */
        final List<Savepoint> savepoints = Collections.synchronizedList(new ArrayList<>());
        /** Every savepoint a rollback was asked to return to, in order */
        final List<Savepoint> rolledBackTo = Collections.synchronizedList(new ArrayList<>());
        final Connection connection;
        /** When set, what a plain {@code rollback()} throws instead of rolling back */
        volatile Throwable rollbackFailure;
        /** When set, what {@code rollback(Savepoint)} throws instead of rolling back */
        volatile Throwable savepointRollbackFailure;
        /** When set, what {@code setSavepoint} throws instead of creating one */
        volatile Throwable setSavepointFailure;
        /** When set, a result read through a statement whose SQL starts with it reports every value as SQL NULL */
        volatile String readsNullFrom;
        /** When set, {@code setSavepoint} gives no savepoint at all */
        volatile boolean setSavepointGivesNull;
        /** When set, what {@code close} throws after it has closed the connection */
        volatile Throwable closeFailure;
        /** When set, what {@code getAutoCommit} throws from its {@link #getAutoCommitFailsFrom}th call on */
        volatile Throwable getAutoCommitFailure;
        volatile int getAutoCommitFailsFrom;
        /** How many times {@code getAutoCommit} was asked */
        final AtomicInteger getAutoCommitCalls = new AtomicInteger();

        Intercepted(@NotNull Connection target, @NotNull Predicate<String> matches, @NotNull Action action) {
            this.connection = (Connection) Proxy.newProxyInstance(
                FenceTestSupport.class.getClassLoader(),
                new Class<?>[]{Connection.class},
                (proxy, method, args) -> {
                    String name = method.getName();
                    if ("prepareStatement".equals(name) && args != null && args.length > 0 && args[0] instanceof String sql) {
                        prepared.add(sql);
                        calls.add(CALL_PREPARE + sql);
                        PreparedStatement statement = (PreparedStatement) invoke(target, method, args);
                        String nulls = readsNullFrom;
                        if (nulls != null && sql.startsWith(nulls)) {
                            statement = readingNull(statement);
                        }
                        return matches.test(sql) ? statement(target, statement, sql, action) : statement;
                    }
                    boolean noArgs = args == null || args.length == 0;
                    if ("getAutoCommit".equals(name) && getAutoCommitCalls.incrementAndGet() >= getAutoCommitFailsFrom) {
                        failIfSet(getAutoCommitFailure);
                    }
                    if ("setSavepoint".equals(name)) {
                        calls.add(CALL_SET_SAVEPOINT);
                        failIfSet(setSavepointFailure);
                        if (setSavepointGivesNull) {
                            return null;
                        }
                        Savepoint savepoint = (Savepoint) invoke(target, method, args);
                        savepoints.add(savepoint);
                        return savepoint;
                    }
                    if ("rollback".equals(name) && noArgs) {
                        calls.add(CALL_ROLLBACK);
                        failIfSet(rollbackFailure);
                    }
                    if ("rollback".equals(name) && !noArgs) {
                        calls.add(CALL_ROLLBACK_TO_SAVEPOINT);
                        rolledBackTo.add((Savepoint) args[0]);
                        failIfSet(savepointRollbackFailure);
                    }
                    if ("close".equals(name)) {
                        calls.add(CALL_CLOSE);
                        Object closed = invoke(target, method, args);
                        failIfSet(closeFailure);
                        return closed;
                    }
                    return invoke(target, method, args);
                });
        }

        private static void failIfSet(@Nullable Throwable failure) throws Throwable {
            if (failure != null) {
                throw failure;
            }
        }

        /** A statement whose results report every value as SQL NULL, whatever the row holds */
        @NotNull
        private static PreparedStatement readingNull(@NotNull PreparedStatement statement) {
            return (PreparedStatement) Proxy.newProxyInstance(
                FenceTestSupport.class.getClassLoader(),
                new Class<?>[]{PreparedStatement.class},
                (proxy, method, args) -> {
                    Object result = invoke(statement, method, args);
                    if (!"executeQuery".equals(method.getName()) || !(result instanceof ResultSet rows)) {
                        return result;
                    }
                    return Proxy.newProxyInstance(
                        FenceTestSupport.class.getClassLoader(),
                        new Class<?>[]{ResultSet.class},
                        (rowsProxy, rowsMethod, rowsArgs) -> "wasNull".equals(rowsMethod.getName())
                            ? Boolean.TRUE : invoke(rows, rowsMethod, rowsArgs));
                });
        }

        /** Where the first entry of {@link #calls} at or after {@code from} that {@code test} accepts is; -1 if there is none */
        int indexOf(int from, @NotNull Predicate<String> test) {
            synchronized (calls) {
                for (int i = Math.max(0, from); i < calls.size(); i++) {
                    if (test.test(calls.get(i))) {
                        return i;
                    }
                }
            }
            return -1;
        }

        @NotNull
        private PreparedStatement statement(
            @NotNull Connection target,
            @NotNull PreparedStatement statement,
            @NotNull String sql,
            @NotNull Action action
        ) {
            List<Object> parameters = new ArrayList<>();
            return (PreparedStatement) Proxy.newProxyInstance(
                FenceTestSupport.class.getClassLoader(),
                new Class<?>[]{PreparedStatement.class},
                (proxy, method, args) -> {
                    String name = method.getName();
                    if (name.startsWith("set") && args != null && args.length >= 2 && args[0] instanceof Integer index) {
                        while (parameters.size() < index) {
                            parameters.add(null);
                        }
                        parameters.set(index - 1, args[1]);
                    }
                    if (name.startsWith("execute") && (args == null || args.length == 0)) {
                        fired.add(sql);
                        action.run(target, sql, List.copyOf(parameters));
                    }
                    return invoke(statement, method, args);
                });
        }

        /** How many prepared statements touched a DBAC grant or history table */
        long grantStatements() {
            synchronized (prepared) {
                return prepared.stream().filter(sql -> sql.contains("DBAC_TW_")).count();
            }
        }
    }

    @NotNull
    static Predicate<String> startsWith(@NotNull String prefix) {
        return sql -> sql.trim().startsWith(prefix);
    }

    @Nullable
    private static Object invoke(@NotNull Object target, @NotNull Method method, @Nullable Object[] args) throws Throwable {
        try {
            return method.invoke(target, args);
        } catch (InvocationTargetException e) {
            throw e.getTargetException();
        }
    }

    /** Throws {@code failure} from code that may only declare {@code SQLException}, such as an {@link Action} raising a DBException */
    @SuppressWarnings("unchecked")
    static <X extends Throwable> void sneakyThrow(@NotNull Throwable failure) throws X {
        throw (X) failure;
    }

    /** Runs one statement on {@code connection}, for setup inside a transaction under test */
    static void execute(@NotNull Connection connection, @NotNull String sql) throws SQLException {
        try (Statement dbStat = connection.createStatement()) {
            dbStat.execute(sql);
        }
    }

    /** Whether a string is a canonical UUID */
    static boolean isUuid(@Nullable String value) {
        return value != null && value.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
    }
}
