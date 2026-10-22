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
package io.cloudbeaver.service.dbac;

import io.cloudbeaver.model.app.ServletApplication;
import io.cloudbeaver.model.session.ServerManagedCredentials;
import io.cloudbeaver.service.dbac.policy.ConnectionPropertyAllowlist;
import io.cloudbeaver.utils.ServletAppUtils;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.jkiss.dbeaver.Log;
import org.jkiss.dbeaver.model.DBPDataSource;
import org.jkiss.dbeaver.model.DBPDataSourceContainer;
import org.jkiss.dbeaver.model.DBUtils;
import org.jkiss.dbeaver.model.connection.DBPConnectionConfiguration;
import org.jkiss.dbeaver.model.connection.DBPConnectionEventType;
import org.jkiss.dbeaver.model.connection.DBPDriverConfigurationType;
import org.jkiss.dbeaver.model.exec.DBCExecutionContext;
import org.jkiss.dbeaver.model.exec.DBCExecutionPurpose;
import org.jkiss.dbeaver.model.exec.DBCResultSet;
import org.jkiss.dbeaver.model.exec.DBCSession;
import org.jkiss.dbeaver.model.exec.DBCStatement;
import org.jkiss.dbeaver.model.exec.DBCStatementType;
import org.jkiss.dbeaver.model.exec.DBCTransactionManager;
import org.jkiss.dbeaver.model.impl.auth.AuthModelDatabaseNative;
import org.jkiss.dbeaver.model.net.DBWHandlerConfiguration;
import org.jkiss.dbeaver.model.runtime.DBRProgressMonitor;
import org.jkiss.dbeaver.model.runtime.DBRShellCommand;
import org.jkiss.dbeaver.runtime.DBWorkbench;
import org.jkiss.utils.CommonUtils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * The server-managed read credential of protected connections
 * <p>
 * A protected connection is named in the {@value #CONFIGURATION_PROPERTY} system property by project id and connection
 * id, with the names of four environment variables: the read user and password, and the writer user and password. Only
 * the read pair is ever read, when a protected connection connects; the writer pair is validated and kept as names
 * only, for a writer channel that does not exist yet.
 * <p>
 * The property holds entries separated by {@code ;}, each
 * {@code projectId,connectionId,READ_USER,READ_PASSWORD,WRITER_USER,WRITER_PASSWORD}. Ids are letters, digits and
 * {@code . _ -}; names are {@code [A-Z_][A-Z0-9_]*}. A key appears once, an entry's four names differ, and no name is
 * both a read and a writer reference. A specification that breaks any of this is not partly used: the provider then
 * governs every connection and refuses every connect, since it cannot tell which ones were meant to be protected.
 * <p>
 * The environment is read at every connect and nothing read is kept, so a value exists only in the connect-time copy
 * of the configuration while the connection is open. The process environment does not change while the server runs:
 * rotating a read credential takes a server restart.
 * <p>
 * A deployment the boundary cannot stand behind - one that allows custom connections, runs in configuration mode,
 * resolves {@code ${...}} variables from the server environment, or cannot be read - is a violation for every connection,
 * not only the protected ones: from the first time it is seen until the server restarts, every connection is governed
 * and refused. On a sound deployment a connection the configuration does not name behaves as it always did.
 * <p>
 * A protected connect is refused with {@link ServerManagedCredentials#REFUSAL_MESSAGE}, and logged by event code, a new
 * EVENT_ID and a {@link Code} only, when
 * <ul>
 *     <li>the deployment is violated, as above</li>
 *     <li>the connection is not in the global project, whose connections only administrators change</li>
 *     <li>the connect does not run inside initConnection, or the client sent credentials for it</li>
 *     <li>a credential is stored with the connection</li>
 *     <li>the connection is anything but a manual, native-auth PostgreSQL configuration whose host, port and database
 *     are plain names and whose stored URL is the one they make, without network handlers, connection events,
 *     profiles, init queries, shared credentials or variables, and with no driver or provider property key the
 *     endpoint-identity allowlist does not allow - for PostgreSQL, none</li>
 *     <li>a read reference is unset or empty</li>
 *     <li>once connected, the session does not run as the read user it was given; it is disconnected again</li>
 * </ul>
 * <p>
 * Only PostgreSQL is supported: the shape checks and the identity check are written for it.
 * <p>
 * Operating notes. A violation is latched from the moment it is first seen, even at startup: a server that starts in
 * configuration mode, or with custom connections allowed, refuses every connection until it is restarted after the
 * setting is fixed. Connections already open when a violation is first seen are not closed - the refusal applies to
 * connects. After a failure while the credential is supplied or checked, closing the connection it opened and clearing
 * the connect-time copy are attempted; if that cleanup fails itself, neither is guaranteed. An Error there is rethrown
 * as it is, not turned into a refusal.
 */
public final class ProtectedConnectionCredentials implements ServerManagedCredentials.Provider {

    private static final Log log = Log.getLog(ProtectedConnectionCredentials.class);

    /** The system property that names the protected connections */
    public static final String CONFIGURATION_PROPERTY = "dbac.protected-connections";

    public static final String EVENT_REFUSED = "DBAC_PROTECTED_CONNECTION_REFUSED";
    public static final String EVENT_CONNECT_FAILED = "DBAC_PROTECTED_CONNECTION_FAILED";
    public static final String EVENT_CONFIGURATION_INVALID = "DBAC_PROTECTED_CONFIGURATION_INVALID";

    /** Why a protected connect was refused: the only detail a log line carries */
    public enum Code {
        CONFIGURATION_INVALID,
        DEPLOYMENT_UNREADABLE,
        CUSTOM_CONNECTIONS_ENABLED,
        CONFIGURATION_MODE,
        NOT_GLOBAL_PROJECT,
        IMPLICIT_CONNECT,
        /** The client sent credentials for a protected connection, or asked to test, copy, change or describe it */
        CLIENT_INPUT,
        STORED_CREDENTIALS,
        UNSUPPORTED_SETTINGS,
        REFERENCE_UNRESOLVED,
        ENVIRONMENT_VARIABLES_ACCESSIBLE,
        IDENTITY_MISMATCH,
        CONNECT_FAILED
    }

    /** What the provider needs to know about the server it runs in */
    public interface Deployment {
        boolean customConnectionsEnabled();

        boolean configurationMode();

        /** Whether connection settings may resolve {@code ${...}} variables from the server's environment */
        boolean environmentVariablesAccessible();

        @NotNull
        String globalProjectId();
    }

    /** The running server */
    public static final Deployment SERVER_DEPLOYMENT = new Deployment() {
        @Override
        public boolean customConnectionsEnabled() {
            return ServletAppUtils.getServletApplication().getAppConfiguration().isSupportsCustomConnections();
        }

        @Override
        public boolean configurationMode() {
            ServletApplication application = ServletAppUtils.getServletApplication();
            return application.isConfigurationMode();
        }

        @Override
        public boolean environmentVariablesAccessible() {
            // What the platform's variable resolver itself asks
            return DBWorkbench.getPlatform().getApplication().isEnvironmentVariablesAccessible();
        }

        @NotNull
        @Override
        public String globalProjectId() {
            return ServletAppUtils.getGlobalProjectId();
        }
    };

    private static final Pattern ID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,127}");
    private static final Pattern REFERENCE = Pattern.compile("[A-Z_][A-Z0-9_]{0,127}");
    /** A host name, an IPv4 address or a bracketed IPv6 address - nothing that can end the URL authority */
    private static final Pattern HOST = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,252}|\\[[0-9A-Fa-f:.]{2,45}]");
    private static final Pattern PORT = Pattern.compile("[0-9]{1,5}");
    /** A database name that cannot carry URL parameters */
    private static final Pattern DATABASE = Pattern.compile("[A-Za-z0-9_][A-Za-z0-9_.$-]{0,62}");
    private static final String POSTGRESQL_PROVIDER = "postgresql";
    /** The one driver the boundary is verified with */
    private static final String POSTGRESQL_DRIVER = "postgres-jdbc";
    private static final String IDENTITY_QUERY = "SELECT session_user, current_user";
    private static final int FIELDS = 6;
    private static final int CAUSE_DEPTH = 20;

    private static final Object INSTALL_LOCK = new Object();
    private static boolean serverInstalled;

    /** A protected connection */
    private record Key(@NotNull String projectId, @NotNull String connectionId) {
    }

    /** The environment variable names of one protected connection - names, never values */
    private record References(
        @NotNull String readUser,
        @NotNull String readPassword,
        @NotNull String writerUser,
        @NotNull String writerPassword
    ) {
        @NotNull
        @Override
        public String toString() {
            return "References[4 names]";
        }
    }

    /** {@code null} when the specification is unusable: then every connection is governed and refused */
    @Nullable
    private final Map<Key, References> protectedConnections;
    private final Function<String, String> environment;
    private final Deployment deployment;
    /** The first deployment violation seen; it refuses every protected connect until the server restarts */
    private final AtomicReference<Code> latchedViolation = new AtomicReference<>();

    private ProtectedConnectionCredentials(
        @Nullable Map<Key, References> protectedConnections,
        @NotNull Function<String, String> environment,
        @NotNull Deployment deployment
    ) {
        this.protectedConnections = protectedConnections == null ? null : Map.copyOf(protectedConnections);
        this.environment = environment;
        this.deployment = deployment;
    }

    /**
     * A provider for a specification
     *
     * @param environment where a reference name is looked up - the process environment on a server
     */
    @NotNull
    public static ProtectedConnectionCredentials parse(
        @Nullable String specification,
        @NotNull Function<String, String> environment,
        @NotNull Deployment deployment
    ) {
        Map<Key, References> parsed = parseSpecification(specification);
        if (parsed == null) {
            logEvent("DBAC protected connection configuration rejected", EVENT_CONFIGURATION_INVALID,
                Code.CONFIGURATION_INVALID, null);
        }
        return new ProtectedConnectionCredentials(parsed, environment, deployment);
    }

    /**
     * Installs the provider for the {@value #CONFIGURATION_PROPERTY} system property, once per server
     * <p>
     * Without the property, or with a blank one, nothing is installed and no connection is governed.
     */
    public static void installForServer() {
        synchronized (INSTALL_LOCK) {
            if (serverInstalled) {
                return;
            }
            ProtectedConnectionCredentials provider = forServer();
            if (provider != null) {
                ServerManagedCredentials.install(provider);
            }
            // Only once it is in place: an installation that failed is tried again, and fails again, by the next factory
            serverInstalled = true;
        }
    }

    /**
     * The provider the server configuration asks for, as {@link #installForServer} installs it
     * <p>
     * It reads the {@value #CONFIGURATION_PROPERTY} system property now and, at every connect, the process environment
     * and the running server. {@code null} when the property is unset or blank: then no connection is governed.
     */
    @Nullable
    public static ProtectedConnectionCredentials forServer() {
        String specification = System.getProperty(CONFIGURATION_PROPERTY);
        if (specification == null || specification.isBlank()) {
            return null;
        }
        return parse(specification, System::getenv, SERVER_DEPLOYMENT);
    }

    @Nullable
    private static Map<Key, References> parseSpecification(@Nullable String specification) {
        Map<Key, References> result = new HashMap<>();
        if (specification == null || specification.isBlank()) {
            return result;
        }
        Set<String> readNames = new HashSet<>();
        Set<String> writerNames = new HashSet<>();
        for (String entry : specification.split(";", -1)) {
            String[] fields = entry.split(",", -1);
            if (fields.length != FIELDS) {
                return null;
            }
            for (int i = 0; i < FIELDS; i++) {
                fields[i] = fields[i].trim();
            }
            if (!ID.matcher(fields[0]).matches() || !ID.matcher(fields[1]).matches()) {
                return null;
            }
            for (int i = 2; i < FIELDS; i++) {
                if (!REFERENCE.matcher(fields[i]).matches()) {
                    return null;
                }
            }
            if (new HashSet<>(List.of(fields[2], fields[3], fields[4], fields[5])).size() != 4) {
                return null;
            }
            Key key = new Key(fields[0], fields[1]);
            if (result.containsKey(key)) {
                return null;
            }
            readNames.add(fields[2]);
            readNames.add(fields[3]);
            writerNames.add(fields[4]);
            writerNames.add(fields[5]);
            result.put(key, new References(fields[2], fields[3], fields[4], fields[5]));
        }
        for (String name : readNames) {
            if (writerNames.contains(name)) {
                return null;
            }
        }
        return result;
    }

    @Override
    public boolean governs(@NotNull DBPDataSourceContainer container) {
        Map<Key, References> connections = protectedConnections;
        if (connections == null) {
            return true;
        }
        if (connections.isEmpty()) {
            return false;
        }
        // A violated deployment is a violation for every connection, listed or not
        return deploymentViolation() != null || connections.containsKey(keyOf(container));
    }

    @Override
    public void supplyReadCredential(
        @NotNull DBPDataSourceContainer container,
        @NotNull DBPConnectionConfiguration connectTimeCopy,
        boolean clientCredentialsPresent,
        boolean explicitConnect
    ) {
        Map<Key, References> connections = protectedConnections;
        if (connections == null) {
            throw refuse(Code.CONFIGURATION_INVALID);
        }
        Code violation = deploymentViolation();
        if (violation != null) {
            throw refuse(violation);
        }
        Key key = keyOf(container);
        References references = connections.get(key);
        if (references == null) {
            throw refuse(Code.CONFIGURATION_INVALID);
        }
        if (!isGlobalProject(key)) {
            throw refuse(Code.NOT_GLOBAL_PROJECT);
        }
        if (!explicitConnect) {
            throw refuse(Code.IMPLICIT_CONNECT);
        }
        if (clientCredentialsPresent) {
            throw refuse(Code.CLIENT_INPUT);
        }
        if (holdsCredential(container.getConnectionConfiguration()) || holdsCredential(connectTimeCopy)) {
            throw refuse(Code.STORED_CREDENTIALS);
        }
        if (container.isSharedCredentials() || !isSupported(container, connectTimeCopy)) {
            throw refuse(Code.UNSUPPORTED_SETTINGS);
        }
        String user = lookUp(references.readUser());
        String password = lookUp(references.readPassword());
        if (user == null || user.isBlank() || password == null || password.isEmpty()) {
            throw refuse(Code.REFERENCE_UNRESOLVED);
        }
        connectTimeCopy.setUserName(user);
        connectTimeCopy.setUserPassword(password);
    }

    /**
     * Reads, on every context the connect opened, which role the session logged in as and which it runs as
     * <p>
     * Both must be the read user that was supplied. Anything that made the driver log in as someone else - a parameter
     * the shape checks did not foresee, a server-side setting, a role switched to at session start - fails here, after
     * the connect but before the connection is used.
     */
    @Override
    public void verifyConnected(@NotNull DBPDataSourceContainer container, @NotNull DBRProgressMonitor monitor) {
        Map<Key, References> connections = protectedConnections;
        References references = connections == null ? null : connections.get(keyOf(container));
        // The read user as the reference resolves it - not as the connect-time copy says, which anything could change
        String expected = references == null ? null : lookUp(references.readUser());
        DBPDataSource dataSource = container.getDataSource();
        if (CommonUtils.isEmpty(expected) || dataSource == null) {
            throw refuse(Code.IDENTITY_MISMATCH);
        }
        DBCExecutionContext main = DBUtils.getDefaultContext(dataSource, false);
        DBCExecutionContext meta = DBUtils.getDefaultContext(dataSource, true);
        List<DBCExecutionContext> contexts = new ArrayList<>();
        contexts.add(main);
        if (meta != main) {
            contexts.add(meta);
        }
        for (DBCExecutionContext context : contexts) {
            if (context == null || !runsAs(context, monitor, expected)) {
                throw refuse(Code.IDENTITY_MISMATCH);
            }
        }
    }

    private static boolean runsAs(@NotNull DBCExecutionContext context, @NotNull DBRProgressMonitor monitor, @NotNull String expected) {
        try (DBCSession session = context.openSession(monitor, DBCExecutionPurpose.META, "Verify the server-managed identity")) {
            boolean matches;
            try (DBCStatement statement = session.prepareStatement(DBCStatementType.QUERY, IDENTITY_QUERY, false, false, false)) {
                if (!statement.executeStatement()) {
                    return false;
                }
                try (DBCResultSet resultSet = statement.openResultSet()) {
                    matches = resultSet.nextRow()
                        && expected.equals(resultSet.getAttributeValue(0))
                        && expected.equals(resultSet.getAttributeValue(1));
                }
            }
            DBCTransactionManager transactions = DBUtils.getTransactionManager(context);
            if (transactions != null && !transactions.isAutoCommit()) {
                // Ends the transaction the check opened in a manual-commit context; a rollback would also undo the
                // session settings the connect made in it
                transactions.commit(session);
            }
            return matches;
        } catch (Exception e) {
            return false;
        }
    }

    @NotNull
    @Override
    public ServerManagedCredentials.Refusal refuseClientInput(@NotNull DBPDataSourceContainer container) {
        return refuse(Code.CLIENT_INPUT);
    }

    /**
     * Removes the read credential a failed connect leaves in the connect-time copy, and logs the failure by its class
     * <p>
     * Clearing the copy comes first and does not depend on the connection being closed; if clearing fails with a
     * RuntimeException, that is not reported and the copy may keep the credential. A refusal raised while the
     * credential was supplied is returned as it is; it was logged when it was raised.
     */
    @NotNull
    @Override
    public ServerManagedCredentials.Refusal connectFailed(@NotNull DBPDataSourceContainer container, @NotNull Throwable failure) {
        scrubConnectTimeCopy(container);
        Throwable cause = failure;
        for (int depth = 0; cause != null && depth < CAUSE_DEPTH; cause = cause.getCause(), depth++) {
            if (cause instanceof ServerManagedCredentials.Refusal refusal) {
                return refusal;
            }
        }
        logEvent("DBAC protected connection failed", EVENT_CONNECT_FAILED, Code.CONNECT_FAILED, failure);
        return new ServerManagedCredentials.Refusal();
    }

    @NotNull
    private static Key keyOf(@NotNull DBPDataSourceContainer container) {
        return new Key(container.getProject().getId(), container.getId());
    }

    /**
     * How the deployment is violated, or null when it is sound
     * <p>
     * Asked for every connection the server connects, so a violation refuses all of them. The first violation seen is
     * kept until the server restarts: resolving it later does not reopen anything.
     */
    @Nullable
    private Code deploymentViolation() {
        Code latched = latchedViolation.get();
        if (latched != null) {
            return latched;
        }
        Code violation;
        try {
            if (deployment.environmentVariablesAccessible()) {
                violation = Code.ENVIRONMENT_VARIABLES_ACCESSIBLE;
            } else if (deployment.customConnectionsEnabled()) {
                violation = Code.CUSTOM_CONNECTIONS_ENABLED;
            } else if (deployment.configurationMode()) {
                violation = Code.CONFIGURATION_MODE;
            } else {
                violation = null;
            }
        } catch (RuntimeException e) {
            violation = Code.DEPLOYMENT_UNREADABLE;
        }
        if (violation == null) {
            return null;
        }
        latchedViolation.compareAndSet(null, violation);
        return latchedViolation.get();
    }

    private boolean isGlobalProject(@NotNull Key key) {
        try {
            return key.projectId().equals(deployment.globalProjectId());
        } catch (RuntimeException e) {
            return false;
        }
    }

    @Nullable
    private String lookUp(@NotNull String name) {
        try {
            return environment.apply(name);
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** Whether a configuration carries a user, a password or an auth property value */
    private static boolean holdsCredential(@NotNull DBPConnectionConfiguration configuration) {
        if (!CommonUtils.isEmpty(configuration.getUserName()) || !CommonUtils.isEmpty(configuration.getUserPassword())) {
            return true;
        }
        Map<String, String> authProperties = configuration.getAuthProperties();
        if (authProperties != null) {
            for (String value : authProperties.values()) {
                if (!CommonUtils.isEmpty(value)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Whether a connection is the one shape the read credential is supplied to
     * <p>
     * A manual native-auth PostgreSQL configuration with nothing that could carry, take or reveal a credential: host,
     * port and database that cannot end the URL or add parameters to it, a stored URL that is exactly the one they make
     * (the platform connects with the stored URL when there is one), no network handler or profile, no connection event
     * command, no init query, no credential driver property and no {@code ${...}} variable - the platform resolves
     * variables from the environment before the credential is supplied.
     */
    private static boolean isSupported(@NotNull DBPDataSourceContainer container, @NotNull DBPConnectionConfiguration copy) {
        if (!POSTGRESQL_PROVIDER.equals(container.getDriver().getProviderId())
            || !POSTGRESQL_DRIVER.equals(container.getDriver().getId())) {
            return false;
        }
        if (copy.getConfigurationType() != DBPDriverConfigurationType.MANUAL) {
            return false;
        }
        if (!matches(HOST, copy.getHostName()) || !CommonUtils.isEmpty(copy.getServerName())
            || !matches(DATABASE, copy.getDatabaseName())
            || (!CommonUtils.isEmpty(copy.getHostPort()) && !matches(PORT, copy.getHostPort()))) {
            return false;
        }
        try {
            String built = container.getDriver().getConnectionURL(copy);
            if (CommonUtils.isEmpty(built) || (!CommonUtils.isEmpty(copy.getUrl()) && !copy.getUrl().equals(built))) {
                return false;
            }
        } catch (Exception e) {
            return false;
        }
        if (!copy.getBootstrap().getInitQueries().isEmpty()) {
            return false;
        }
        String defaultCatalog = copy.getBootstrap().getDefaultCatalogName();
        if (!CommonUtils.isEmpty(defaultCatalog) && !matches(DATABASE, defaultCatalog)) {
            return false;
        }
        // The allowlist the endpoint identity already rests on: keys only, no value is read. For postgres-jdbc it
        // allows no driver and no provider property at all.
        if (!ConnectionPropertyAllowlist.allKeysAllowed(
            container.getDriver().getProviderId(), container.getDriver().getId(), copy.getProperties(), copy.getProviderProperties())
        ) {
            return false;
        }
        String authModel = copy.getAuthModelId();
        if (!CommonUtils.isEmpty(authModel) && !AuthModelDatabaseNative.ID.equals(authModel)) {
            return false;
        }
        if (!CommonUtils.isEmpty(copy.getConfigProfileName())) {
            return false;
        }
        for (DBWHandlerConfiguration handler : copy.getHandlers()) {
            if (handler.isEnabled()) {
                return false;
            }
        }
        DBPConnectionConfiguration declared = container.getConnectionConfiguration();
        for (DBPConnectionEventType eventType : declared.getDeclaredEvents()) {
            DBRShellCommand command = declared.getEvent(eventType);
            if (command != null && command.isEnabled()) {
                return false;
            }
        }
        List<String> values = new ArrayList<>();
        values.add(declared.getHostName());
        values.add(declared.getHostPort());
        values.add(declared.getServerName());
        values.add(declared.getDatabaseName());
        values.add(declared.getUrl());
        values.add(declared.getBootstrap().getDefaultCatalogName());
        values.add(declared.getBootstrap().getDefaultSchemaName());
        for (String value : values) {
            if (value != null && value.contains("${")) {
                return false;
            }
        }
        return true;
    }

    private static boolean matches(@NotNull Pattern pattern, @Nullable String value) {
        return value != null && pattern.matcher(value).matches();
    }

    private static void scrubConnectTimeCopy(@NotNull DBPDataSourceContainer container) {
        try {
            DBPConnectionConfiguration inUse = container.getActualConnectionConfiguration();
            if (inUse != container.getConnectionConfiguration()) {
                inUse.setUserName(null);
                inUse.setUserPassword(null);
            }
        } catch (RuntimeException ignored) {
            // The refusal does not depend on it; a disconnect drops the copy as well.
        }
    }

    @NotNull
    private static ServerManagedCredentials.Refusal refuse(@NotNull Code code) {
        logEvent("DBAC protected connection refused", EVENT_REFUSED, code, null);
        return new ServerManagedCredentials.Refusal();
    }

    /**
     * Logs by event code, a new correlation id, the detail code and an exception class - never a message, a name or a value
     * <p>
     * A log that fails does not change the refusal; a {@link VirtualMachineError} is not hidden behind it.
     */
    private static void logEvent(@NotNull String what, @NotNull String event, @NotNull Code code, @Nullable Throwable failure) {
        try {
            log.warn(what + " [event=" + event + " EVENT_ID=" + UUID.randomUUID() + " detail=" + code
                + " exception=" + (failure == null ? "-" : failure.getClass().getName()) + "]");
        } catch (VirtualMachineError e) {
            throw e;
        } catch (RuntimeException | Error ignored) {
            // Deliberately nothing: a refusal must not depend on whether it could be logged.
        }
    }
}
