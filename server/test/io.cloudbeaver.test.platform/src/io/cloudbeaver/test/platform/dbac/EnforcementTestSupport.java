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

import io.cloudbeaver.WebSessionProjectImpl;
import io.cloudbeaver.app.CEAppStarter;
import io.cloudbeaver.auth.provider.local.LocalAuthProvider;
import io.cloudbeaver.model.WebAsyncTaskInfo;
import io.cloudbeaver.model.WebConnectionInfo;
import io.cloudbeaver.model.session.BaseWebSession;
import io.cloudbeaver.model.session.WebSession;
import io.cloudbeaver.server.WebAppUtils;
import io.cloudbeaver.service.dbac.db.DbacCBDatabase;
import io.cloudbeaver.service.dbac.policy.AuthorizationDecision;
import io.cloudbeaver.service.dbac.policy.DbAccessPolicyConfig;
import io.cloudbeaver.service.dbac.policy.DbAccessPolicyService;
import io.cloudbeaver.service.dbac.policy.DbOperationCategory;
import io.cloudbeaver.service.dbac.policy.DenialReason;
import io.cloudbeaver.service.dbac.policy.MetadataLeaseSource;
import io.cloudbeaver.service.dbac.policy.WriteAuthorizationRequest;
import io.cloudbeaver.service.dbac.tempwrite.EndpointSnapshot;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteGrant;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteGrantRepository;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteMutationCoordinator;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteMutationResult;
import io.cloudbeaver.service.dbac.tempwrite.TempWritePermissionKey;
import io.cloudbeaver.service.security.EmbeddedSecurityControllerFactory;
import io.cloudbeaver.service.security.db.CBDatabase;
import io.cloudbeaver.service.sql.WebSQLContextInfo;
import io.cloudbeaver.service.sql.WebSQLProcessor;
import io.cloudbeaver.service.sql.WebServiceBindingSQL;
import io.cloudbeaver.test.WebGQLClient;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.jkiss.dbeaver.DBException;
import org.jkiss.dbeaver.model.connection.DBPConnectionConfiguration;
import org.jkiss.dbeaver.model.connection.DBPDriver;
import org.jkiss.dbeaver.model.connection.DBPDriverConfigurationType;
import org.jkiss.dbeaver.model.impl.jdbc.JDBCDataSource;
import org.jkiss.dbeaver.model.impl.jdbc.JDBCExecutionContext;
import org.jkiss.dbeaver.model.impl.jdbc.JDBCRemoteInstance;
import org.jkiss.dbeaver.model.runtime.DBRProgressMonitor;
import org.jkiss.dbeaver.registry.DataSourceDescriptor;
import org.jkiss.dbeaver.registry.DataSourceProviderDescriptor;
import org.jkiss.dbeaver.registry.DataSourceProviderRegistry;
import org.jkiss.utils.SecurityUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;

import java.sql.Connection;
import java.sql.Driver;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Fixtures for the Slice 4a test-first classes
 * <p>
 * Everything here runs against the live test server, its real metadata database and a real
 * PostgreSQL target. Nothing in it touches a production code path that Slice 4a has not reached
 * yet: the tests that use it are written against the entry points as they exist today, so that the
 * same test goes from red to green when enforcement is wired, without being rewritten.
 * <p>
 * <b>A fixture failure is not a security result.</b> Every check that establishes the premise of a
 * test - the grant really allows, the user really is inactive, the commit really is slow - fails
 * with a message that starts with {@code FIXTURE}, so a broken setup can never be read as evidence
 * that enforcement is missing.
 */
final class EnforcementTestSupport {

    static final String PG_URL = System.getProperty(
        "dbac.test.postgres.url", "jdbc:postgresql://localhost:55432/dbactest");
    static final String PG_USER = System.getProperty("dbac.test.postgres.user", "postgres");
    static final String PG_PASSWORD = System.getProperty("dbac.test.postgres.password", "dbactest");
    static final boolean PG_REQUIRED =
        Boolean.parseBoolean(System.getProperty("dbac.test.postgres.required", "false"));

    static final String PG_PROVIDER = "postgresql";
    static final String PG_DRIVER = "postgres-jdbc";

    /** The value that makes the fixture table's deferred trigger sleep at commit time */
    static final int SLOW_VALUE = 99;
    static final int SLOW_COMMIT_SECONDS = 3;

    static final Duration TASK_TIMEOUT = Duration.ofSeconds(60);
    static final Duration GRANT_DURATION = Duration.ofMinutes(30);

    /** Every user these fixtures create starts with this, so a leftover can be found and counted */
    static final String USER_PREFIX = "dbac-s1-";

    /** Audit event names from CLAUDE.md section 20; nothing writes them before Slice 4a */
    static final String EVENT_WRITE_ALLOWED = "WRITE_ALLOWED";
    static final String EVENT_WRITE_DENIED = "WRITE_DENIED";

    private static final Pattern URL_PARTS =
        Pattern.compile("jdbc:postgresql://([^:/?]+)(?::(\\d+))?/([^?]+).*");

    private static final String GQL_CREATE_USER = """
        query createUser($userId: ID!, $enabled: Boolean!, $authRole: String) {
          result: createUser(userId: $userId, enabled: $enabled, authRole: $authRole) { userId }
        }""";
    private static final String GQL_SET_CREDENTIALS = """
        query setUserCredentials($userId: ID!, $providerId: ID!, $credentials: Object!) {
          result: setUserCredentials(userId: $userId, providerId: $providerId, credentials: $credentials)
        }""";
    static final String GQL_ENABLE_USER = """
        query enableUser($userId: ID!, $enabled: Boolean!) {
          result: enableUser(userId: $userId, enabled: $enabled)
        }""";
    static final String GQL_DELETE_USER = """
        query deleteUser($userId: ID!) {
          result: deleteUser(userId: $userId)
        }""";
    static final String GQL_ACTIVE_USER = """
        query activeUser {
          result: activeUser { userId }
        }""";
    static final String GQL_ASYNC_SQL_EXECUTE = """
        mutation asyncSqlExecuteQuery($projectId: ID, $connectionId: ID!, $contextId: ID!, $sql: String!) {
          result: asyncSqlExecuteQuery(projectId: $projectId, connectionId: $connectionId, contextId: $contextId, sql: $sql) {
            id
          }
        }""";
    static final String GQL_ASYNC_TASK_INFO = """
        mutation asyncTaskInfo($id: String!, $removeOnFinish: Boolean!) {
          result: asyncTaskInfo(id: $id, removeOnFinish: $removeOnFinish) {
            id
            running
            status
            error { message }
          }
        }""";

    private EnforcementTestSupport() {
    }

    // ---------------------------------------------------------------- PostgreSQL target

    /**
     * Stops the test unless the PostgreSQL target is usable
     * <p>
     * Same contract as the Slice 3 PostgreSQL classes: an abort without the required property, a
     * failure with it, so a CI run cannot pass by skipping.
     */
    static void requirePostgres(@NotNull DBRProgressMonitor monitor) {
        String reason;
        try (Connection ignored = openRawPostgres(monitor)) {
            return;
        } catch (Exception e) {
            reason = e.getClass().getName();
        }
        if (PG_REQUIRED) {
            Assertions.fail("POSTGRESQL NOT VERIFIED: the target could not be used and the run required it - " + reason);
        }
        Assumptions.abort("PostgreSQL target unavailable: " + reason);
    }

    @NotNull
    static DBPDriver postgresDriverDescriptor() {
        DataSourceProviderDescriptor provider = DataSourceProviderRegistry.getInstance().getDataSourceProvider(PG_PROVIDER);
        if (provider == null) {
            throw new IllegalStateException("FIXTURE: data source provider '" + PG_PROVIDER + "' is not registered");
        }
        DBPDriver driver = provider.getDriver(PG_DRIVER);
        if (driver == null) {
            throw new IllegalStateException("FIXTURE: driver '" + PG_DRIVER + "' is not registered");
        }
        return driver;
    }

    /**
     * A connection that belongs to no execution context
     * <p>
     * This is the observer: it reads what a separate client would see, so "the row did not change"
     * means committed state rather than what the tested transaction sees of itself.
     */
    @NotNull
    static Connection openRawPostgres(@NotNull DBRProgressMonitor monitor) throws Exception {
        Driver driver = postgresDriverDescriptor().getDefaultDriverLoader().getDriverInstance(monitor);
        Properties properties = new Properties();
        properties.setProperty("user", PG_USER);
        properties.setProperty("password", PG_PASSWORD);
        Connection connection = driver.connect(PG_URL, properties);
        if (connection == null) {
            throw new SQLException("FIXTURE: the PostgreSQL driver did not accept the configured url");
        }
        return connection;
    }

    @NotNull
    static String[] urlParts() {
        Matcher matcher = URL_PARTS.matcher(PG_URL);
        if (!matcher.matches()) {
            throw new IllegalStateException("FIXTURE: the PostgreSQL test url is not host/port/database shaped");
        }
        return new String[]{matcher.group(1), matcher.group(2) == null ? "5432" : matcher.group(2), matcher.group(3)};
    }

    /** The endpoint the target container is configured for, as a grant would record it */
    @NotNull
    static EndpointSnapshot targetEndpoint() {
        String[] parts = urlParts();
        return new EndpointSnapshot(PG_PROVIDER, PG_DRIVER, DBPDriverConfigurationType.MANUAL.name(),
            parts[0], parts[1], parts[2]);
    }

    static int readValue(@NotNull DBRProgressMonitor monitor, @NotNull String schema) throws Exception {
        try (Connection observer = openRawPostgres(monitor)) {
            return readValue(observer, schema);
        }
    }

    static int readValue(@NotNull Connection connection, @NotNull String schema) throws SQLException {
        try (Statement dbStat = connection.createStatement();
             ResultSet dbResult = dbStat.executeQuery("SELECT v FROM " + schema + ".t WHERE id = 1")) {
            if (!dbResult.next()) {
                throw new SQLException("FIXTURE: fixture row is missing");
            }
            return dbResult.getInt(1);
        }
    }

    static void execute(@NotNull Connection connection, @NotNull String sql) throws SQLException {
        try (Statement dbStat = connection.createStatement()) {
            dbStat.execute(sql);
        }
    }

    static int backendPid(@NotNull Connection connection) throws SQLException {
        try (Statement dbStat = connection.createStatement();
             ResultSet dbResult = dbStat.executeQuery("SELECT pg_backend_pid()")) {
            dbResult.next();
            return dbResult.getInt(1);
        }
    }

    /**
     * Waits until a server backend has gone
     * <p>
     * The platform closes connections in a background task with a timeout, so "the close call
     * returned" does not mean the server has ended the session. Reading committed state before that
     * would pass whether the transaction was aborted or not.
     */
    static void awaitBackendGone(@NotNull Connection observer, int pid) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(15).toNanos();
        while (System.nanoTime() < deadline) {
            try (PreparedStatement dbStat = observer.prepareStatement(
                "SELECT COUNT(*) FROM pg_stat_activity WHERE pid = ?")) {
                dbStat.setInt(1, pid);
                try (ResultSet dbResult = dbStat.executeQuery()) {
                    dbResult.next();
                    if (dbResult.getInt(1) == 0) {
                        return;
                    }
                }
            }
            Thread.sleep(50);
        }
        Assertions.fail("FIXTURE: backend " + pid + " was still present after 15s");
    }

    // ---------------------------------------------------------------- subjects

    /** A logged-in web session and the client that holds its cookie */
    record Subject(@NotNull String userId, @NotNull WebGQLClient client, @NotNull WebSession session) {
    }

    @NotNull
    static Subject loginTestAdmin() throws Exception {
        WebGQLClient client = CEAppStarter.createClient();
        CEAppStarter.authenticateTestUser(client);
        WebSession session = resolveSession(client);
        return new Subject(session.getUserId(), client, session);
    }

    /**
     * Creates an ordinary local user ({@code authRole=user}) and logs in as it
     * <p>
     * Every subject whose writes are judged is one of these. The test admin only administers - it
     * creates, deactivates and deletes users - so that no READ_ONLY or TEMP_WRITE result can be an
     * artefact of administrative rights.
     */
    @NotNull
    static Subject createAndLogin(@NotNull Subject admin, @NotNull String userId) throws Exception {
        admin.client().sendQuery(GQL_CREATE_USER, Map.of("userId", userId, "enabled", true, "authRole", "user"));
        String secret = SecurityUtils.makeDigest("dbac-s1-" + UUID.randomUUID());
        Map<String, Object> credentials = new HashMap<>();
        credentials.put(LocalAuthProvider.CRED_PASSWORD, secret);
        admin.client().sendQuery(GQL_SET_CREDENTIALS, Map.of(
            "userId", userId, "providerId", LocalAuthProvider.PROVIDER_ID, "credentials", credentials));
        WebGQLClient client = CEAppStarter.createClient();
        CEAppStarter.authenticateTestUser(client, Map.of(
            LocalAuthProvider.CRED_USER, userId, LocalAuthProvider.CRED_PASSWORD, secret));
        WebSession session = resolveSession(client);
        Assertions.assertEquals(userId, session.getUserId(), "FIXTURE: login did not produce the created user's session");
        return new Subject(userId, client, session);
    }

    static void deleteUserQuietly(@NotNull Subject admin, @NotNull String userId) {
        try {
            admin.client().sendQuery(GQL_DELETE_USER, Map.of("userId", userId));
        } catch (Exception ignored) {
            // Already gone, or the test deleted it itself.
        }
    }

    @NotNull
    static WebSession resolveSession(@NotNull WebGQLClient client) throws DBException {
        BaseWebSession session = WebAppUtils.getWebApplication().getSessionManager()
            .getSession(client.getSessionIdCookie());
        if (!(session instanceof WebSession webSession)) {
            throw new DBException("FIXTURE: no web session behind the client cookie");
        }
        return webSession;
    }

    // ---------------------------------------------------------------- target container

    /**
     * A PostgreSQL connection registered in the subject's session, with its own fixture schema
     * <p>
     * The schema holds one row {@code (1, 0)}, a sequence, and a deferred constraint trigger that
     * sleeps for {@link #SLOW_COMMIT_SECONDS} when a row is committed with {@code v = SLOW_VALUE}. The
     * trigger fires at commit, which is the only way to make the commit itself - rather than the
     * statement before it - take long enough to race against.
     */
    static final class Target implements AutoCloseable {
        final Subject subject;
        final DBRProgressMonitor monitor;
        final WebSessionProjectImpl project;
        final String schema;
        final DataSourceDescriptor container;
        final WebConnectionInfo connection;
        final WebSQLProcessor processor;
        final WebSQLContextInfo sqlContext;

        private Target(
            @NotNull Subject subject,
            @NotNull DBRProgressMonitor monitor,
            @NotNull WebSessionProjectImpl project,
            @NotNull String schema,
            @NotNull DataSourceDescriptor container,
            @NotNull WebConnectionInfo connection,
            @NotNull WebSQLProcessor processor,
            @NotNull WebSQLContextInfo sqlContext
        ) {
            this.subject = subject;
            this.monitor = monitor;
            this.project = project;
            this.schema = schema;
            this.container = container;
            this.connection = connection;
            this.processor = processor;
            this.sqlContext = sqlContext;
        }

        @NotNull
        String table() {
            return schema + ".t";
        }

        @NotNull
        JDBCExecutionContext context() {
            return (JDBCExecutionContext) processor.getExecutionContext();
        }

        /** The JDBC connection behind the context every WebSQLContextInfo call uses */
        @NotNull
        Connection jdbc() throws SQLException {
            return context().getConnection(monitor);
        }

        @NotNull
        JDBCRemoteInstance instance() {
            return ((JDBCDataSource) container.getDataSource()).getDefaultInstance();
        }

        @NotNull
        TempWritePermissionKey key() {
            return new TempWritePermissionKey(subject.userId(), container.getProject().getId(), container.getId());
        }

        /**
         * Changes the fixture row inside the context's current transaction
         * <p>
         * Straight on the context's JDBC connection. SQL_TEXT is outside Slice 4a, so how the change
         * got into the transaction does not affect what the gated entry points must do with it.
         */
        void updateInTransaction(int value) throws SQLException {
            execute(jdbc(), "UPDATE " + table() + " SET v = " + value + " WHERE id = 1");
        }

        int committedValue() throws Exception {
            return readValue(monitor, schema);
        }

        @Override
        public void close() throws Exception {
            try {
                try {
                    Connection jdbc = context().getConnectionOrNull();
                    if (jdbc != null && !jdbc.getAutoCommit()) {
                        jdbc.rollback();
                    }
                } catch (Exception ignored) {
                    // The connection may have been severed by the test; disconnect below still runs.
                }
                container.disconnect(monitor);
                container.getRegistry().removeDataSource(container);
                project.removeConnection(container);
            } finally {
                try (Connection raw = openRawPostgres(monitor)) {
                    execute(raw, "DROP SCHEMA IF EXISTS " + schema + " CASCADE");
                }
            }
        }
    }

    @NotNull
    static Target openTarget(@NotNull Subject subject, @NotNull DBRProgressMonitor monitor) throws Exception {
        String schema = "dbac_s1_" + Long.toHexString(System.nanoTime());
        try (Connection raw = openRawPostgres(monitor)) {
            execute(raw, "CREATE SCHEMA " + schema);
            execute(raw, "CREATE TABLE " + schema + ".t (id INT PRIMARY KEY, v INT NOT NULL)");
            execute(raw, "INSERT INTO " + schema + ".t (id, v) VALUES (1, 0)");
            execute(raw, "CREATE SEQUENCE " + schema + ".seq");
            execute(raw, "CREATE FUNCTION " + schema + ".slow_commit() RETURNS trigger LANGUAGE plpgsql AS"
                + " $$ BEGIN PERFORM pg_sleep(" + SLOW_COMMIT_SECONDS + "); RETURN NULL; END $$");
            execute(raw, "CREATE CONSTRAINT TRIGGER slow_commit AFTER UPDATE ON " + schema + ".t"
                + " DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.v = " + SLOW_VALUE + ")"
                + " EXECUTE PROCEDURE " + schema + ".slow_commit()");
        }

        // The shared project when the session has one, the user's own project otherwise; either way
        // the connection is registered only in this session.
        WebSessionProjectImpl project = subject.session().getGlobalProject() != null
            ? subject.session().getGlobalProject()
            : subject.session().getSingletonProject();
        if (project == null) {
            throw new DBException("FIXTURE: the subject's session has no project to register a connection in");
        }
        String[] parts = urlParts();
        DBPConnectionConfiguration configuration = new DBPConnectionConfiguration();
        configuration.setConfigurationType(DBPDriverConfigurationType.MANUAL);
        configuration.setHostName(parts[0]);
        configuration.setHostPort(parts[1]);
        configuration.setDatabaseName(parts[2]);
        configuration.setUserName(PG_USER);
        configuration.setUserPassword(PG_PASSWORD);

        DBPDriver driver = postgresDriverDescriptor();
        DataSourceDescriptor container = project.getDataSourceRegistry().createDataSource(
            DataSourceDescriptor.generateNewId(driver), driver, configuration);
        container.setName("DBAC S1 " + schema);
        container.setSavePassword(true);
        container.setTemporary(true);
        container.connect(monitor, true, true);
        project.getDataSourceRegistry().addDataSource(container);
        WebConnectionInfo connectionInfo = project.addConnection(container);
        WebSQLProcessor processor = WebServiceBindingSQL.getSQLProcessor(connectionInfo);
        WebSQLContextInfo sqlContext = processor.createContext(null, null, project.getId());
        return new Target(subject, monitor, project, schema, container, connectionInfo, processor, sqlContext);
    }

    // ---------------------------------------------------------------- metadata database

    @NotNull
    static CBDatabase metadata() {
        CBDatabase database = EmbeddedSecurityControllerFactory.getDbInstance();
        Assertions.assertNotNull(database, "FIXTURE: CBDatabase instance must exist after server startup");
        return database;
    }

    /**
     * The server metadata database's own leases, which production builds the policy service on
     */
    @NotNull
    static MetadataLeaseSource metadataLeases() {
        return Assertions.assertInstanceOf(DbacCBDatabase.class, metadata(),
            "FIXTURE: the server metadata database must be the DBAC one").metadataLeases();
    }

    static void grant(@NotNull TempWritePermissionKey key) throws Exception {
        long observed;
        try (Connection connection = metadata().openConnection()) {
            Long current = TempWriteTestSupport.currentRevision(connection, key);
            observed = current == null ? TempWriteGrant.NO_ROW_REVISION : current;
        }
        TempWriteMutationResult result = TempWriteMutationCoordinator
            .withoutAuditing(metadata()::openConnection, new TempWriteGrantRepository())
            .grant(TempWriteTestSupport.grantRequest(key, observed, GRANT_DURATION, "dbac s1 fixture", targetEndpoint()));
        Assertions.assertTrue(result.isCommitted(), "FIXTURE: the fixture grant was not committed: " + result);
    }

    static void revoke(@NotNull TempWritePermissionKey key) throws Exception {
        long observed;
        try (Connection connection = metadata().openConnection()) {
            Long current = TempWriteTestSupport.currentRevision(connection, key);
            Assertions.assertNotNull(current, "FIXTURE: there is no grant to revoke");
            observed = current;
        }
        TempWriteMutationResult result = TempWriteMutationCoordinator
            .withoutAuditing(metadata()::openConnection, new TempWriteGrantRepository())
            .revoke(TempWriteTestSupport.revokeRequest(key, observed));
        Assertions.assertTrue(result.isCommitted(), "FIXTURE: the fixture revoke was not committed: " + result);
    }

    @NotNull
    static OffsetDateTime metadataNow() throws SQLException {
        try (Connection connection = metadata().openConnection();
             Statement dbStat = connection.createStatement();
             ResultSet dbResult = dbStat.executeQuery("SELECT CURRENT_TIMESTAMP")) {
            dbResult.next();
            return dbResult.getObject(1, OffsetDateTime.class);
        }
    }

    /**
     * Moves a stored grant's expiry
     * <p>
     * Test-only SQL against the test metadata database. The coordinator only issues grants that
     * last at least as long as a request allows, so a grant that is about to expire - or already
     * has - can only be produced by editing the row.
     */
    static void setExpiresAt(@NotNull TempWritePermissionKey key, @NotNull OffsetDateTime expiresAt) throws SQLException {
        try (Connection connection = metadata().openConnection();
             PreparedStatement dbStat = connection.prepareStatement(
                 "UPDATE {table_prefix}DBAC_TW_CURRENT SET EXPIRES_AT=?"
                     + " WHERE USER_ID=? AND PROJECT_ID=? AND CONNECTION_ID=?")) {
            dbStat.setObject(1, expiresAt);
            dbStat.setString(2, key.userId());
            dbStat.setString(3, key.projectId());
            dbStat.setString(4, key.connectionId());
            Assertions.assertEquals(1, dbStat.executeUpdate(), "FIXTURE: the grant row to re-date is missing");
        }
    }

    static int countAudit(
        @NotNull TempWritePermissionKey key,
        @NotNull String eventType,
        @NotNull DbOperationCategory category
    ) throws SQLException {
        return countAudit(key, eventType, category, null);
    }

    /** Audit rows for the key, optionally only those that record a particular denial reason */
    static int countAudit(
        @NotNull TempWritePermissionKey key,
        @NotNull String eventType,
        @NotNull DbOperationCategory category,
        @Nullable DenialReason reason
    ) throws SQLException {
        try (Connection connection = metadata().openConnection();
             PreparedStatement dbStat = connection.prepareStatement(
                 "SELECT COUNT(*) FROM {table_prefix}DBAC_AUDIT_EVENT WHERE EVENT_TYPE=? AND USER_ID=?"
                     + " AND PROJECT_ID=? AND CONNECTION_ID=? AND OPERATION_CATEGORY=?"
                     + (reason == null ? "" : " AND DENIAL_REASON=?"))) {
            dbStat.setString(1, eventType);
            dbStat.setString(2, key.userId());
            dbStat.setString(3, key.projectId());
            dbStat.setString(4, key.connectionId());
            dbStat.setString(5, category.name());
            if (reason != null) {
                dbStat.setString(6, reason.name());
            }
            try (ResultSet dbResult = dbStat.executeQuery()) {
                dbResult.next();
                return dbResult.getInt(1);
            }
        }
    }

    @NotNull
    static OffsetDateTime readExpiresAt(@NotNull TempWritePermissionKey key) throws SQLException {
        try (Connection connection = metadata().openConnection();
             PreparedStatement dbStat = connection.prepareStatement(
                 "SELECT EXPIRES_AT FROM {table_prefix}DBAC_TW_CURRENT WHERE USER_ID=? AND PROJECT_ID=? AND CONNECTION_ID=?")) {
            dbStat.setString(1, key.userId());
            dbStat.setString(2, key.projectId());
            dbStat.setString(3, key.connectionId());
            try (ResultSet dbResult = dbStat.executeQuery()) {
                Assertions.assertTrue(dbResult.next(), "FIXTURE: the grant row is missing");
                return dbResult.getObject(1, OffsetDateTime.class);
            }
        }
    }

    /** How many users whose id starts with the prefix still exist in the metadata database */
    static int countUsers(@NotNull String prefix) throws SQLException {
        try (Connection connection = metadata().openConnection();
             PreparedStatement dbStat = connection.prepareStatement(
                 "SELECT COUNT(*) FROM {table_prefix}CB_USER WHERE USER_ID LIKE ?")) {
            dbStat.setString(1, prefix + "%");
            try (ResultSet dbResult = dbStat.executeQuery()) {
                dbResult.next();
                return dbResult.getInt(1);
            }
        }
    }

    static void forget(@NotNull TempWritePermissionKey key) throws SQLException {
        try (Connection connection = metadata().openConnection()) {
            TempWriteTestSupport.deleteKey(connection, key);
            try (PreparedStatement dbStat = connection.prepareStatement(
                "DELETE FROM {table_prefix}DBAC_AUDIT_EVENT WHERE USER_ID=? AND PROJECT_ID=? AND CONNECTION_ID=?")) {
                dbStat.setString(1, key.userId());
                dbStat.setString(2, key.projectId());
                dbStat.setString(3, key.connectionId());
                dbStat.executeUpdate();
            }
        }
    }

    // ---------------------------------------------------------------- policy premise

    /**
     * What the policy core answers for this subject, target and category right now
     * <p>
     * Not enforcement - nothing calls this in production yet. It is how a test proves its own
     * premise: a test that expects a denial for an expired grant first shows that the policy really
     * does see the grant as expired, so the red result is about the missing gate and not about a
     * fixture that granted the wrong thing.
     */
    @NotNull
    static AuthorizationDecision decide(@NotNull Target target, @NotNull DbOperationCategory category) {
        return new DbAccessPolicyService(metadataLeases(), DbAccessPolicyConfig.defaults())
            .authorize(WriteAuthorizationRequest.of(target.subject.userId(), target.container, category));
    }

    static void premiseAllows(@NotNull String id, @NotNull Target target, @NotNull DbOperationCategory category) {
        AuthorizationDecision decision = decide(target, category);
        Assertions.assertTrue(decision.isAllowed(),
            "FIXTURE " + id + ": the policy core should allow " + category + " but denied it with " + decision.denialReason());
    }

    static void premiseDenies(
        @NotNull String id,
        @NotNull Target target,
        @NotNull DbOperationCategory category,
        @NotNull DenialReason expected
    ) {
        AuthorizationDecision decision = decide(target, category);
        Assertions.assertFalse(decision.isAllowed(),
            "FIXTURE " + id + ": the policy core should deny " + category + " with " + expected + " but allowed it");
        Assertions.assertEquals(expected, decision.denialReason(),
            "FIXTURE " + id + ": the policy core denied " + category + " for a different reason");
    }

    // ---------------------------------------------------------------- async tasks

    /** How an async task ended, and when the test observed it */
    record Outcome(boolean completed, @Nullable Object result, @Nullable Throwable error, long observedAtNanos) {
        boolean succeeded() {
            return completed && error == null;
        }
    }

    @NotNull
    static Outcome await(@NotNull WebAsyncTaskInfo task) throws InterruptedException {
        long deadline = System.nanoTime() + TASK_TIMEOUT.toNanos();
        while (task.isRunning()) {
            if (System.nanoTime() > deadline) {
                return new Outcome(false, null, null, System.nanoTime());
            }
            Thread.sleep(10);
        }
        return new Outcome(true, task.getResult(), task.getJobError(), System.nanoTime());
    }

    @NotNull
    static Outcome run(@NotNull ThrowingSupplier<?> call) {
        try {
            Object result = call.get();
            return new Outcome(true, result, null, System.nanoTime());
        } catch (Throwable e) {
            return new Outcome(true, null, e, System.nanoTime());
        }
    }

    @FunctionalInterface
    interface ThrowingSupplier<T> {
        @Nullable
        T get() throws Exception;
    }

    /** What {@code asyncTaskInfo} reported once a GraphQL async task stopped running */
    record GraphQlTask(@NotNull String id, @Nullable String status, @Nullable String error) {
    }

    /**
     * Waits for a GraphQL async task to stop running and returns its final status and error
     * <p>
     * Not running is not the same as finished: a task that failed also stops. The caller decides
     * what the status has to be.
     */
    @NotNull
    static GraphQlTask awaitGraphQlTask(@NotNull WebGQLClient client, @NotNull String taskId) throws Exception {
        long deadline = System.nanoTime() + TASK_TIMEOUT.toNanos();
        while (System.nanoTime() < deadline) {
            Map<String, Object> info = client.sendQuery(GQL_ASYNC_TASK_INFO, Map.of("id", taskId, "removeOnFinish", false));
            if (info != null && Boolean.FALSE.equals(info.get("running"))) {
                Object status = info.get("status");
                Object error = info.get("error");
                return new GraphQlTask(taskId,
                    status == null ? null : String.valueOf(status),
                    error == null ? null : String.valueOf(error));
            }
            Thread.sleep(50);
        }
        Assertions.fail("FIXTURE: GraphQL task " + taskId + " did not finish within " + TASK_TIMEOUT);
        return new GraphQlTask(taskId, null, null);
    }

    // ---------------------------------------------------------------- per-class fixtures

    /**
     * The subjects, targets and grants one test class uses, and their cleanup
     * <p>
     * One ordinary user per class serves every READ_ONLY and TEMP_WRITE case - a grant is per
     * connection and every test opens its own connection, so the cases cannot see each other's
     * grants. Tests that deactivate or delete their subject create one of their own.
     */
    static final class Fixtures {
        final String prefix;
        final DBRProgressMonitor monitor;
        final Subject admin;
        final Subject user;
        private final List<Target> targets = new ArrayList<>();
        private final List<TempWritePermissionKey> keys = new ArrayList<>();
        private final List<String> users = new ArrayList<>();

        private Fixtures(@NotNull String prefix, @NotNull DBRProgressMonitor monitor, @NotNull Subject admin) throws Exception {
            this.prefix = prefix;
            this.monitor = monitor;
            this.admin = admin;
            this.user = newUser();
        }

        /** A fresh ordinary user, deleted with the class */
        @NotNull
        Subject newUser() throws Exception {
            String userId = prefix + Long.toHexString(System.nanoTime());
            users.add(userId);
            return createAndLogin(admin, userId);
        }

        /** A target with no grant: READ_ONLY */
        @NotNull
        Target readOnlyTarget(@NotNull Subject subject) throws Exception {
            requirePostgres(monitor);
            Target target = openTarget(subject, monitor);
            targets.add(target);
            keys.add(target.key());
            return target;
        }

        /** A target with a live TEMP_WRITE grant for exactly this connection */
        @NotNull
        Target writableTarget(@NotNull Subject subject) throws Exception {
            Target target = readOnlyTarget(subject);
            grant(target.key());
            return target;
        }

        /** After each test: connections, fixture schemas, grants and audit rows */
        void afterEach() throws Exception {
            for (Target target : targets) {
                try {
                    target.close();
                } catch (Exception e) {
                    System.out.println("[DBAC S1] target cleanup failed: " + e.getClass().getName());
                }
            }
            targets.clear();
            for (TempWritePermissionKey key : keys) {
                forget(key);
            }
            keys.clear();
        }

        /** After the class: every user it created, and proof that none is left */
        void afterAll() throws Exception {
            afterEach();
            for (String userId : users) {
                deleteUserQuietly(admin, userId);
            }
            users.clear();
            int left = countUsers(prefix);
            System.out.println("[DBAC S1] users left with prefix " + prefix + ": " + left);
            Assertions.assertEquals(0, left, "FIXTURE: users created by this class were not all deleted");
        }
    }

    @NotNull
    static Fixtures fixtures(@NotNull String classTag, @NotNull DBRProgressMonitor monitor) throws Exception {
        return new Fixtures(USER_PREFIX + classTag + "-", monitor, loginTestAdmin());
    }

    // ---------------------------------------------------------------- the four entry points

    @NotNull
    static Outcome setAutoCommit(@NotNull Target target, boolean autoCommit) throws Exception {
        return await(target.sqlContext.setAutoCommit(autoCommit));
    }

    @NotNull
    static Outcome commit(@NotNull Target target) throws Exception {
        return await(target.sqlContext.commitTransaction());
    }

    @NotNull
    static Outcome rollback(@NotNull Target target) throws Exception {
        return await(target.sqlContext.rollbackTransaction());
    }

    @NotNull
    static Outcome explain(@NotNull Target target, @NotNull String sql, @NotNull Map<String, Object> configuration) {
        return run(() -> target.processor.explainExecutionPlan(target.monitor, sql, configuration));
    }

    /** Turns auto-commit off through the entry point, then changes the row inside that transaction */
    static void openTransaction(@NotNull Target target, int value) throws Exception {
        Outcome off = setAutoCommit(target, false);
        Assertions.assertTrue(off.succeeded(), "FIXTURE: auto-commit off must work to open a transaction: " + describe(off.error()));
        target.updateInTransaction(value);
    }

    @NotNull
    static String jdbcAutoCommitState(@NotNull Target target) {
        try {
            Connection jdbc = target.context().getConnectionOrNull();
            return jdbc == null ? "severed" : String.valueOf(jdbc.getAutoCommit());
        } catch (Exception e) {
            return "unreadable (" + e.getClass().getSimpleName() + ")";
        }
    }

    /** The fixture sequence's last issued value as a separate client sees it, 0 before the first */
    static long sequenceValue(@NotNull Target target) throws Exception {
        try (Connection observer = openRawPostgres(target.monitor);
             Statement dbStat = observer.createStatement();
             ResultSet dbResult = dbStat.executeQuery("SELECT last_value, is_called FROM " + target.schema + ".seq")) {
            dbResult.next();
            return dbResult.getBoolean(2) ? dbResult.getLong(1) : 0L;
        }
    }

    /**
     * Collects every clause of a multi-part expectation and fails once, naming all that were broken
     * <p>
     * A red test that stops at its first broken clause hides the others; the Slice 4a review needs
     * to see the whole contract's status in one run.
     */
    static final class Expectations {
        private final String id;
        private final List<String> violations = new ArrayList<>();

        Expectations(@NotNull String id) {
            this.id = id;
        }

        void check(boolean holds, @NotNull String clause) {
            if (!holds) {
                violations.add(clause);
            }
        }

        void verify(@NotNull String observed) {
            if (!violations.isEmpty()) {
                Assertions.fail(id + ": " + String.join("; ", violations) + " [observed: " + observed + "]");
            }
        }
    }

    // ---------------------------------------------------------------- the enforcement contract

    /**
     * Whether a failure carries the denial it is supposed to be
     * <p>
     * The contract Slice 4a has to meet for these tests to go green: a gated entry point that
     * refuses reports the {@link DenialReason}'s message code or user message somewhere in the
     * failure it raises. The exception type is left to the implementation.
     */
    static boolean mentions(@Nullable Throwable error, @NotNull DenialReason reason) {
        int depth = 0;
        for (Throwable t = error; t != null && depth < 20; t = t.getCause(), depth++) {
            String message = t.getMessage();
            if (message != null && (message.contains(reason.messageCode()) || message.contains(reason.userMessage()))) {
                return true;
            }
        }
        return false;
    }

    static void assertDenied(
        @NotNull String id,
        @NotNull Outcome outcome,
        @NotNull DenialReason expected,
        @NotNull String observed
    ) {
        if (!outcome.completed()) {
            Assertions.fail(id + ": the operation did not finish within " + TASK_TIMEOUT + "; " + observed);
        }
        if (outcome.error() == null) {
            Assertions.fail(id + ": expected DENY(" + expected + ") but the operation succeeded (result="
                + outcome.result() + "); " + observed);
        }
        Assertions.assertTrue(mentions(outcome.error(), expected),
            id + ": expected DENY(" + expected + ") but it failed with " + describe(outcome.error()) + "; " + observed);
    }

    @NotNull
    static String describe(@Nullable Throwable error) {
        if (error == null) {
            return "no error";
        }
        StringBuilder text = new StringBuilder();
        int depth = 0;
        for (Throwable t = error; t != null && depth < 5; t = t.getCause(), depth++) {
            if (depth > 0) {
                text.append(" <- ");
            }
            text.append(t.getClass().getSimpleName());
        }
        return text.toString();
    }
}
