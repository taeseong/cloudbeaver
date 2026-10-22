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

import io.cloudbeaver.DBWebException;
import io.cloudbeaver.WebSessionProjectImpl;
import io.cloudbeaver.app.CEAppStarter;
import io.cloudbeaver.auth.provider.local.LocalAuthProvider;
import io.cloudbeaver.model.WebConnectionInfo;
import io.cloudbeaver.model.config.CBAppConfig;
import io.cloudbeaver.model.log.SLF4JLogHandler;
import io.cloudbeaver.model.session.ServerManagedCredentials;
import io.cloudbeaver.model.session.WebSession;
import io.cloudbeaver.server.CBConstants;
import io.cloudbeaver.service.dbac.ProtectedConnectionCredentials;
import io.cloudbeaver.test.WebGQLClient;
import io.cloudbeaver.test.platform.dbac.EnforcementTestSupport.Expectations;
import io.cloudbeaver.test.platform.dbac.EnforcementTestSupport.Outcome;
import io.cloudbeaver.test.platform.dbac.EnforcementTestSupport.Subject;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.jkiss.dbeaver.Log;
import org.jkiss.dbeaver.LogHandler;
import org.jkiss.dbeaver.model.DBPDataSourceContainer;
import org.jkiss.dbeaver.model.connection.DBPConnectionConfiguration;
import org.jkiss.dbeaver.model.navigator.DBNDatabaseNode;
import org.jkiss.dbeaver.model.navigator.DBNModel;
import org.jkiss.dbeaver.model.navigator.DBNProject;
import org.jkiss.dbeaver.model.runtime.DBRProgressMonitor;
import org.jkiss.dbeaver.model.runtime.LoggingProgressMonitor;
import org.jkiss.dbeaver.utils.GeneralUtils;
import org.jkiss.utils.SecurityUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Queue;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Slice 4b P0: a protected connection reaches PostgreSQL only with the server-managed read credential
 * <p>
 * A protected connection is one the server configuration names by project and connection id. Its database
 * credential is read from the server environment when it connects and lives only in the connect-time copy of the
 * connection configuration: nothing the client sends and nothing stored with the connection takes its place, and
 * nothing about it reaches a response, a log line, the saved configuration or the project files.
 * <p>
 * Every case runs on the live test server and a real PostgreSQL target, through the GraphQL API a browser uses. The
 * provider is the production one, built from a specification and an in-memory environment instead of the system
 * property and the process environment. Which role a connect used is read from {@code pg_stat_activity} on a
 * separate superuser connection.
 * <p>
 * Each test creates disposable login roles with random passwords. They, the environment variable names and the
 * values behind them are the markers; an assertion message names a marker by its label, never by its value.
 */
public class ServerManagedCredentialTest {

    private static final String GLOBAL_PROJECT = "g_GlobalConfiguration";
    private static final String DRIVER_ID = EnforcementTestSupport.PG_PROVIDER + ":" + EnforcementTestSupport.PG_DRIVER;
    private static final String REFUSAL = ServerManagedCredentials.REFUSAL_MESSAGE;
    private static final String USER_PREFIX = EnforcementTestSupport.USER_PREFIX + "p0-";
    /** What every line the provider logs starts with */
    private static final String LOG_PREFIX = "DBAC protected connection";
    private static final Duration BACKEND_WAIT = Duration.ofSeconds(15);

    private static final Pattern MESSAGE = Pattern.compile("\"message\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
    private static final Pattern RESULT_ID = Pattern.compile("\"id\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern AUTH_NEEDED = Pattern.compile("\"authNeeded\"\\s*:\\s*(true|false)");

    private static final String GQL_CREATE_USER = """
        query createUser($userId: ID!, $enabled: Boolean!, $authRole: String) {
          result: createUser(userId: $userId, enabled: $enabled, authRole: $authRole) { userId }
        }""";
    private static final String GQL_SET_CREDENTIALS = """
        query setUserCredentials($userId: ID!, $providerId: ID!, $credentials: Object!) {
          result: setUserCredentials(userId: $userId, providerId: $providerId, credentials: $credentials)
        }""";
    private static final String GQL_ADD_ACCESS = """
        query addConnectionsAccess($projectId: ID!, $connectionIds: [ID!]!, $subjects: [ID!]!) {
          result: addConnectionsAccess(projectId: $projectId, connectionIds: $connectionIds, subjects: $subjects)
        }""";
    private static final String GQL_CREATE_CONNECTION = """
        mutation createConnection($config: ConnectionConfig!, $projectId: ID) {
          result: createConnection(config: $config, projectId: $projectId) { id }
        }""";
    private static final String GQL_UPDATE_CONNECTION = """
        mutation updateConnection($config: ConnectionConfig!, $projectId: ID) {
          result: updateConnection(config: $config, projectId: $projectId) { id }
        }""";
    private static final String GQL_TEST_CONNECTION = """
        mutation testConnection($config: ConnectionConfig!, $projectId: ID) {
          result: testConnection(config: $config, projectId: $projectId) { id }
        }""";
    private static final String GQL_COPY_CONNECTION = """
        mutation copyConnectionFromNode($nodePath: String!, $config: ConnectionConfig, $projectId: ID) {
          result: copyConnectionFromNode(nodePath: $nodePath, config: $config, projectId: $projectId) { id }
        }""";
    private static final String GQL_DELETE_CONNECTION = """
        mutation deleteConnection($id: ID!, $projectId: ID) {
          result: deleteConnection(id: $id, projectId: $projectId)
        }""";
    private static final String GQL_INIT_CONNECTION = """
        mutation initConnection(
          $id: ID!, $projectId: ID, $credentials: Object, $networkCredentials: [NetworkHandlerConfigInput!],
          $saveCredentials: Boolean, $sharedCredentials: Boolean, $selectedSecretId: String
        ) {
          result: initConnection(
            id: $id, projectId: $projectId, credentials: $credentials, networkCredentials: $networkCredentials,
            saveCredentials: $saveCredentials, sharedCredentials: $sharedCredentials, selectedSecretId: $selectedSecretId
          ) { id connected }
        }""";
    private static final String GQL_CLOSE_CONNECTION = """
        mutation closeConnection($id: ID!, $projectId: ID) {
          result: closeConnection(id: $id, projectId: $projectId) { id connected }
        }""";
    private static final String GQL_CONNECTION_INFO = """
        query connectionInfo($projectId: ID!, $id: ID!) {
          result: connectionInfo(projectId: $projectId, id: $id) {
            id connected authNeeded credentialsSaved saveCredentials authModel host databaseName url
            properties providerProperties mainPropertyValues expertSettingsValues
            authProperties { id value }
          }
        }""";
    private static final String GQL_DRIVER_PROPERTIES = """
        query listConnectionDriverProperties($projectId: ID!, $config: ConnectionConfig!) {
          result: listConnectionDriverProperties(projectId: $projectId, config: $config) { id }
        }""";
    private static final String GQL_SQL_CONTEXT_CREATE = """
        mutation sqlContextCreate($projectId: ID, $connectionId: ID!) {
          result: sqlContextCreate(projectId: $projectId, connectionId: $connectionId) { id }
        }""";
    private static final String GQL_NAV_CHILDREN = """
        query navNodeChildren($parentPath: ID!) {
          result: navNodeChildren(parentPath: $parentPath) { uri }
        }""";
    private static final String GQL_SESSION_LOG = """
        query readSessionLog($maxEntries: Int, $clearEntries: Boolean) {
          result: readSessionLog(maxEntries: $maxEntries, clearEntries: $clearEntries) { type message stackTrace }
        }""";
    private static final String GQL_USER_CONNECTIONS = """
        query userConnections($projectId: ID) {
          result: userConnections(projectId: $projectId) { id name credentialsSaved authProperties { id value } }
        }""";
    private static final String GQL_LOGOUT = """
        query authLogoutExtended($provider: ID) {
          result: authLogoutExtended(provider: $provider) { redirectLinks { url } }
        }""";

    /** What every connection a scenario creates is named after */
    private static final String CONNECTION_PREFIX = "DBAC P0 ";
    private static final Pattern CONNECTION_NAME = Pattern.compile("\"name\"\\s*:\\s*\"" + Pattern.quote(CONNECTION_PREFIX));
    /** The shapes of the plaintext values the scenarios make, whether a scenario lists them as markers or not */
    private static final Map<String, Pattern> FIXTURE_VALUES = Map.of(
        "role password", Pattern.compile("p0-[a-z]+-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
        "role name", Pattern.compile("dbac_p0_[a-z0-9]+_[0-9a-f]{12}"),
        "environment reference", Pattern.compile("DBAC_P0_[0-9A-F]{12}_"),
        "fixture value", Pattern.compile("dbac-p0-(?:writer-user|writer-password|driver-value|provider-value|input|tunnel|secret)-"),
        "fixture property key", Pattern.compile("dbacP0Driver[0-9a-f]{12}|@dbeaver-dbac-p0-[0-9a-f]{12}@")
    );
    private static final Pattern UNICODE_ESCAPE = Pattern.compile("\\\\u([0-9a-fA-F]{4})");

    private static final DBRProgressMonitor MONITOR = new LoggingProgressMonitor();
    /** Every connection the class's scenarios created */
    private static final Set<String> CREATED_CONNECTIONS = ConcurrentHashMap.newKeySet();
    /** Every marker of the class's scenarios, by value to label */
    private static final Map<String, String> CLASS_MARKERS = new ConcurrentHashMap<>();
    @Nullable
    private static Path globalProjectFolder;
    @Nullable
    private static String encryptedStoresAtStart;

    @BeforeAll
    public static void startServer() throws Exception {
        CEAppStarter.startServerIfNotStarted();
        EnforcementTestSupport.requirePostgres(MONITOR);
        // Only to find the global project's folder: every scenario administers through a session of its own
        Subject finder = EnforcementTestSupport.loginTestAdmin();
        try {
            WebSessionProjectImpl globalProject = finder.session().getProjectById(GLOBAL_PROJECT);
            globalProjectFolder = globalProject == null ? null : globalProject.getAbsolutePath();
        } finally {
            logout(finder);
        }
        if (globalProjectFolder == null || !Files.isDirectory(globalProjectFolder)) {
            Assertions.fail("FIXTURE: the global project has no folder to inspect");
        }
        encryptedStoresAtStart = encryptedStores();
    }

    /**
     * After the last scenario the class has left nothing behind: no connection it created, through a fresh admin
     * session's API or in the persisted global project configuration; no value it made, in any workspace file read as
     * text; no PostgreSQL role, database or backend of its own
     * <p>
     * The encrypted credential stores are not opened: only whether they exist, and their size, is printed - before the
     * first scenario and after the last.
     */
    @AfterAll
    public static void nothingIsLeftBehind() throws Exception {
        List<String> left = new ArrayList<>();
        Subject fresh = EnforcementTestSupport.loginTestAdmin();
        try {
            String listed = raw(fresh.client(), GQL_USER_CONNECTIONS, Map.of("projectId", GLOBAL_PROJECT));
            if (!succeeded(listed)) {
                left.add("a fresh admin session's userConnections did not answer: " + summary(listed));
            }
            left.addAll(fixtureConnections("a fresh admin session's userConnections", listed));
            for (String label : fixtureValuesIn(listed)) {
                left.add(label + " in a fresh admin session's userConnections");
            }
        } finally {
            logout(fresh);
        }
        Path folder = Objects.requireNonNull(globalProjectFolder);
        for (Path configuration : dataSourceConfigurations(folder)) {
            left.addAll(fixtureConnections("persisted " + folder.relativize(configuration), Files.readString(configuration)));
        }
        left.addAll(leftInWorkspace(Objects.requireNonNull(folder.getParent())));
        left.addAll(postgresLeftovers());
        System.out.println("SMC cleanup: encrypted credential stores (content not read) before the first scenario ["
            + encryptedStoresAtStart + "], after the last [" + encryptedStores() + "]");
        if (!left.isEmpty()) {
            Assertions.fail("CLEANUP: the class left " + left.size() + " thing(s) behind: " + String.join("; ", left));
        }
    }

    // ---------------------------------------------------------------- the credential

    /** SMC-1: a protected connect uses the server read credential, asks the client for nothing, never reads a writer reference */
    @Test
    public void smc1ProtectedConnectUsesOnlyTheServerReadCredential() throws Exception {
        try (Scenario s = new Scenario()) {
            Role ro = s.role("ro");
            Conn target = s.connection("protected", null);
            s.login(target);
            s.customConnections(false);
            s.serveReadCredential(ro);
            s.protect(s.spec(target), ProtectedConnectionCredentials.SERVER_DEPLOYMENT);

            String before = raw(s.user().client(), GQL_CONNECTION_INFO, info(target));
            String connect = init(s.user(), target, Map.of());
            boolean connected = isConnected(s.user(), target);
            int readBackends = backends(ro);

            Expectations expect = new Expectations("SMC-1");
            expect.check(succeeded(before) && Boolean.FALSE.equals(authNeeded(before)),
                "a protected connection must not ask the client for credentials");
            expect.check(succeeded(connect), "the connect must succeed with the server read credential");
            expect.check(connected, "the connection must be open");
            expect.check(readBackends > 0, "the backends must belong to the read role");
            expect.check(s.lookedUp.contains(s.readUserEnv) && s.lookedUp.contains(s.readPasswordEnv),
                "the read references must be resolved");
            expect.check(!s.lookedUp.contains(s.writerUserEnv) && !s.lookedUp.contains(s.writerPasswordEnv),
                "the writer references must never be read");
            expect.verify(s.redact("authNeeded=" + authNeeded(before) + "; connect " + summary(connect)
                + "; connected=" + connected + "; read-role backends " + readBackends));
        }
    }

    /** SMC-2: client credentials are refused, with the one fixed message, on every entry point that carries them (P0-1) */
    @Test
    public void smc2ClientCredentialsAreRefusedOnEveryEntryPoint() throws Exception {
        try (Scenario s = new Scenario()) {
            Role ro = s.role("ro");
            final Role client = s.role("client");
            Conn target = s.connection("protected", null);
            s.login(target);
            s.customConnections(false);
            s.serveReadCredential(ro);
            s.protect(s.spec(target), ProtectedConnectionCredentials.SERVER_DEPLOYMENT);

            final Expectations expect = new Expectations("SMC-2");
            final Map<String, String> observed = new LinkedHashMap<>();

            Map<String, Map<String, Object>> inputs = new LinkedHashMap<>();
            inputs.put("credentials", Map.of("credentials", credentials(client)));
            inputs.put("saveCredentials", Map.of("saveCredentials", true));
            inputs.put("sharedCredentials", Map.of("sharedCredentials", true));
            inputs.put("selectedSecretId", Map.of("selectedSecretId", "dbac-p0-secret-" + s.tag));
            inputs.put("networkCredentials", Map.of("networkCredentials", List.of(Map.of(
                "id", "ssh_tunnel", "userName", client.name(), "password", client.password()))));
            for (Map.Entry<String, Map<String, Object>> input : inputs.entrySet()) {
                String body = init(s.user(), target, input.getValue());
                boolean connected = isConnected(s.user(), target);
                s.observe();
                observed.put("init+" + input.getKey(), summary(body) + (connected ? " CONNECTED" : ""));
                expect.check(refused(body), "initConnection with client " + input.getKey() + " must be refused with the fixed message");
                expect.check(!connected, "initConnection with client " + input.getKey() + " must not connect");
                if (connected) {
                    closeQuietly(s.user(), target);
                }
            }
            int clientBackends = s.peak(client);
            expect.check(clientBackends == 0, "no backend may belong to the client role");

            Map<String, Object> testConfig = endpointConfig();
            testConfig.put("connectionId", target.id());
            testConfig.put("credentials", credentials(client));
            String tested = raw(s.admin().client(), GQL_TEST_CONNECTION, Map.of("config", testConfig, "projectId", GLOBAL_PROJECT));
            observed.put("testConnection", summary(tested));
            expect.check(refused(tested), "testConnection of a protected connection must be refused with the fixed message");

            String copied = raw(s.admin().client(), GQL_COPY_CONNECTION, Map.of(
                "nodePath", nodePath(s.admin(), target), "config", Map.of("name", "DBAC P0 copy " + s.tag), "projectId", GLOBAL_PROJECT));
            s.adopt(copied);
            observed.put("copyConnectionFromNode", summary(copied));
            expect.check(refused(copied), "copyConnectionFromNode of a protected connection must be refused with the fixed message");

            Map<String, Object> updateConfig = endpointConfig();
            updateConfig.put("connectionId", target.id());
            updateConfig.put("name", "DBAC P0 updated " + s.tag);
            updateConfig.put("credentials", credentials(client));
            updateConfig.put("saveCredentials", true);
            String updated = raw(s.admin().client(), GQL_UPDATE_CONNECTION, Map.of("config", updateConfig, "projectId", GLOBAL_PROJECT));
            observed.put("updateConnection", summary(updated));
            expect.check(refused(updated), "updateConnection of a protected connection must be refused with the fixed message");

            Map<String, Object> propertiesConfig = endpointConfig();
            propertiesConfig.put("connectionId", target.id());
            propertiesConfig.put("credentials", credentials(client));
            String properties = raw(s.admin().client(), GQL_DRIVER_PROPERTIES,
                Map.of("config", propertiesConfig, "projectId", GLOBAL_PROJECT));
            observed.put("listConnectionDriverProperties", summary(properties));
            expect.check(refused(properties),
                "listConnectionDriverProperties of a protected connection must be refused with the fixed message");

            expect.verify(s.redact(observed + "; client-role backends " + clientBackends));
        }
    }

    /** SMC-3: a credential stored with a protected connection makes it fail closed instead of being used (P0-2) */
    @Test
    public void smc3StoredCredentialsFailClosed() throws Exception {
        try (Scenario s = new Scenario()) {
            Role ro = s.role("ro");
            Role client = s.role("client");
            Conn target = s.connection("protected", client);
            s.login(target);
            s.customConnections(false);
            s.serveReadCredential(ro);
            s.protect(s.spec(target), ProtectedConnectionCredentials.SERVER_DEPLOYMENT);

            String body;
            List<Entry> logged;
            try (LogRecorder log = new LogRecorder(null)) {
                body = init(s.user(), target, Map.of());
                logged = log.entries();
            }
            boolean connected = isConnected(s.user(), target);
            int clientBackends = backends(client);
            int readBackends = backends(ro);

            Expectations expect = new Expectations("SMC-3");
            expect.check(refused(body), "a protected connection with a stored credential must be refused with the fixed message");
            expect.check(!connected, "it must not connect");
            expect.check(clientBackends == 0, "the stored credential must never be used");
            expect.check(readBackends == 0, "the read credential must not be used either - the connection fails closed");
            expect.check(detailLogged(logged, "STORED_CREDENTIALS"), "the refusal must be logged as STORED_CREDENTIALS");
            expect.verify(s.redact("connect " + summary(body) + "; connected=" + connected + "; client-role backends "
                + clientBackends + "; read-role backends " + readBackends));
        }
    }

    /** SMC-4: a missing or empty reference, and every malformed specification, fail closed (P0-3) */
    @Test
    public void smc4UnresolvedOrInvalidReferencesFailClosed() throws Exception {
        try (Scenario s = new Scenario()) {
            Role ro = s.role("ro");
            Role client = s.role("client");
            Conn target = s.connection("protected", null);
            Conn other = s.connection("other", client);
            s.login(target, other);
            s.customConnections(false);

            final Expectations expect = new Expectations("SMC-4");
            final Map<String, String> observed = new LinkedHashMap<>();

            Map<String, String[]> environments = new LinkedHashMap<>();
            environments.put("password reference missing", new String[]{ro.name(), null});
            environments.put("user reference missing", new String[]{null, ro.password()});
            environments.put("password empty", new String[]{ro.name(), ""});
            environments.put("user empty", new String[]{"", ro.password()});
            environments.put("user blank", new String[]{"   ", ro.password()});
            for (Map.Entry<String, String[]> environment : environments.entrySet()) {
                s.putEnvironment(s.readUserEnv, environment.getValue()[0]);
                s.putEnvironment(s.readPasswordEnv, environment.getValue()[1]);
                s.protect(s.spec(target), ProtectedConnectionCredentials.SERVER_DEPLOYMENT);
                Attempt attempt = attempt(s, target, Map.of());
                observed.put(environment.getKey(), attempt.describe());
                expect.check(attempt.refused() && !attempt.connected(), environment.getKey() + ": the connect must be refused");
                expect.check(attempt.detail("REFERENCE_UNRESOLVED"), environment.getKey() + ": logged as REFERENCE_UNRESOLVED");
            }
            int readBackends = s.peak(ro);
            expect.check(readBackends == 0, "no unresolved reference may let the read role connect");

            s.serveReadCredential(ro);
            String key = GLOBAL_PROJECT + "," + target.id();
            String references = "," + s.readUserEnv + "," + s.readPasswordEnv + "," + s.writerUserEnv + "," + s.writerPasswordEnv;
            Map<String, String> invalid = new LinkedHashMap<>();
            invalid.put("one field", "garbage");
            invalid.put("five fields", key + "," + s.readUserEnv + "," + s.readPasswordEnv + "," + s.writerUserEnv);
            invalid.put("seven fields", key + references + ",DBAC_P0_EXTRA");
            invalid.put("lower-case reference", key + "," + s.readUserEnv.toLowerCase(Locale.ROOT) + "," + s.readPasswordEnv
                + "," + s.writerUserEnv + "," + s.writerPasswordEnv);
            invalid.put("reference starting with a digit", key + ",1" + s.readUserEnv + "," + s.readPasswordEnv
                + "," + s.writerUserEnv + "," + s.writerPasswordEnv);
            invalid.put("duplicate key", key + references + ";" + key + references);
            invalid.put("reference used twice in an entry", key + "," + s.readUserEnv + "," + s.readUserEnv
                + "," + s.writerUserEnv + "," + s.writerPasswordEnv);
            invalid.put("read reference reused as a writer reference", key + references + ";" + GLOBAL_PROJECT
                + ",dbac-p0-other-" + s.tag + "," + s.readUserEnv + "_2," + s.readPasswordEnv + "_2," + s.readUserEnv
                + "," + s.writerPasswordEnv + "_2");
            invalid.put("empty entry", key + references + ";;");
            invalid.put("connection id with a separator", GLOBAL_PROJECT + "," + target.id() + "/x" + references);
            invalid.put("empty project id", "," + target.id() + references);
            for (Map.Entry<String, String> specification : invalid.entrySet()) {
                s.protect(specification.getValue(), ProtectedConnectionCredentials.SERVER_DEPLOYMENT);
                Attempt protectedAttempt = attempt(s, target, Map.of());
                Attempt otherAttempt = attempt(s, other, Map.of());
                observed.put(specification.getKey(), protectedAttempt.describe() + " / other " + otherAttempt.describe());
                expect.check(protectedAttempt.refused() && !protectedAttempt.connected(),
                    specification.getKey() + ": the protected connect must be refused");
                expect.check(protectedAttempt.detail("CONFIGURATION_INVALID"),
                    specification.getKey() + ": logged as CONFIGURATION_INVALID");
                expect.check(otherAttempt.refused() && !otherAttempt.connected(),
                    specification.getKey() + ": with an unusable configuration every connect must be refused");
            }
            int clientBackends = s.peak(client);
            expect.check(clientBackends == 0, "no connect may happen while the configuration is unusable");
            expect.check(!s.lookedUp.contains(s.writerUserEnv) && !s.lookedUp.contains(s.writerPasswordEnv),
                "the writer references must never be read");
            expect.verify(s.redact(observed + "; read-role backends " + readBackends + "; client-role backends " + clientBackends));
        }
    }

    /** SMC-5: every connect asks the provider again; a reconnect does not reuse what an earlier connect was given */
    @Test
    public void smc5ReconnectAsksTheProviderAgain() throws Exception {
        try (Scenario s = new Scenario()) {
            Role first = s.role("roa");
            final Role second = s.role("rob");
            Conn target = s.connection("protected", null);
            s.login(target);
            s.customConnections(false);
            s.serveReadCredential(first);
            CountingProvider counting = new CountingProvider(ProtectedConnectionCredentials.parse(
                s.spec(target), s::lookup, ProtectedConnectionCredentials.SERVER_DEPLOYMENT));
            s.install(counting);

            Expectations expect = new Expectations("SMC-5");
            String firstConnect = init(s.user(), target, Map.of());
            int firstBackends = backends(first);
            expect.check(succeeded(firstConnect) && firstBackends > 0, "the first connect must use the first read credential");
            if (!succeeded(firstConnect)) {
                expect.verify(s.redact("first connect " + summary(firstConnect)));
            }

            s.user().client().sendQuery(GQL_CLOSE_CONNECTION, Map.of("id", target.id(), "projectId", GLOBAL_PROJECT));
            if (!awaitNoBackends(first)) {
                Assertions.fail("FIXTURE: closeConnection left backends of the first read role behind");
            }
            s.serveReadCredential(second);
            String secondConnect = init(s.user(), target, Map.of());
            int secondBackends = backends(second);
            int firstBackendsAfter = backends(first);

            expect.check(succeeded(secondConnect), "the reconnect must succeed");
            expect.check(secondBackends > 0, "the reconnect must use the credential the provider supplies now");
            expect.check(firstBackendsAfter == 0, "the reconnect must not reuse the earlier credential");
            expect.check(counting.supplied.get() == 2, "each connect must ask the provider once");
            expect.verify(s.redact("second connect " + summary(secondConnect) + "; backends " + firstBackendsAfter + "/"
                + secondBackends + "; supplied " + counting.supplied.get()));
        }
    }

    /** SMC-6: a connection the configuration does not name keeps the stored and the client credential paths unchanged */
    @Test
    public void smc6UnprotectedConnectionsAreUnchanged() throws Exception {
        try (Scenario s = new Scenario()) {
            Role ro = s.role("ro");
            Role client = s.role("client");
            Conn target = s.connection("protected", null);
            Conn stored = s.connection("stored", client);
            Conn plain = s.connection("plain", null);
            s.login(target, stored, plain);
            s.customConnections(false);
            s.serveReadCredential(ro);
            s.protect(s.spec(target), ProtectedConnectionCredentials.SERVER_DEPLOYMENT);

            String storedConnect = init(s.user(), stored, Map.of());
            boolean storedConnected = isConnected(s.user(), stored);
            int clientAfterStored = backends(client);
            closeQuietly(s.user(), stored);

            String plainInfo = raw(s.user().client(), GQL_CONNECTION_INFO, info(plain));
            String plainConnect = init(s.user(), plain, Map.of("credentials", credentials(client)));
            boolean plainConnected = isConnected(s.user(), plain);
            int readBackends = backends(ro);

            Expectations expect = new Expectations("SMC-6");
            expect.check(succeeded(storedConnect) && storedConnected, "a stored credential must still connect an unprotected connection");
            expect.check(clientAfterStored > 0, "the stored credential must be the one used");
            expect.check(Boolean.TRUE.equals(authNeeded(plainInfo)),
                "an unprotected connection without credentials must still ask for them");
            expect.check(succeeded(plainConnect) && plainConnected, "client credentials must still connect an unprotected connection");
            expect.check(readBackends == 0, "the read credential must never be used for an unprotected connection");
            expect.verify(s.redact("stored " + summary(storedConnect) + " connected=" + storedConnected + "; plain authNeeded="
                + authNeeded(plainInfo) + " " + summary(plainConnect) + " connected=" + plainConnected
                + "; client-role backends after stored " + clientAfterStored + "; read-role backends " + readBackends));
        }
    }

    // ---------------------------------------------------------------- where the credential may be

    /**
     * SMC-7: the credential is only ever in the connect-time copy (P0-4)
     * <p>
     * Not in the session's or the persisted configuration, not in connectionInfo, the saved client input, the session
     * log, the project files or any log line; after close not even in the copy. A client credential sent with
     * saveCredentials is not saved anywhere either.
     */
    @Test
    public void smc7CredentialsStayInTheConnectTimeCopy() throws Exception {
        try (Scenario s = new Scenario()) {
            Role ro = s.role("ro");
            Role client = s.role("client");
            Conn target = s.connection("protected", null);
            s.login(target);
            s.customConnections(false);
            s.serveReadCredential(ro);
            s.protect(s.spec(target), ProtectedConnectionCredentials.SERVER_DEPLOYMENT);

            Expectations expect = new Expectations("SMC-7");
            Map<String, String> observed = new LinkedHashMap<>();
            List<Entry> logged;
            try (LogRecorder log = new LogRecorder(null)) {
                String connect = init(s.user(), target, Map.of());
                observed.put("connect", summary(connect));
                expect.check(succeeded(connect), "the protected connect must succeed");
                DBPDataSourceContainer container = container(s.user(), target);
                expect.check(heldBy(container.getConnectionConfiguration(), s.markers).isEmpty(),
                    "the session's configuration must not hold the read credential");

                String info = raw(s.user().client(), GQL_CONNECTION_INFO, info(target));
                expect.check(succeeded(info), "connectionInfo must answer");
                expect.check(leaked(info, s.markers).isEmpty(), "connectionInfo must carry no marker");
                Map<String, Object> savedInput = connectionInfo(s.user().session(), target).getSavedAuthProperties();
                expect.check(savedInput == null || savedInput.isEmpty(), "no client input may be kept for the connection");

                closeQuietly(s.user(), target);
                expect.check(heldBy(container.getActualConnectionConfiguration(), s.markers).isEmpty(),
                    "after close no configuration of the connection may hold the read credential");

                String saving = init(s.user(), target, Map.of("credentials", credentials(client), "saveCredentials", true));
                observed.put("saveCredentials", summary(saving));
                expect.check(refused(saving), "a client credential sent with saveCredentials must be refused");
                expect.check(heldBy(container.getConnectionConfiguration(), s.markers).isEmpty(),
                    "the client credential must not be saved in the session's configuration");
                closeQuietly(s.user(), target);

                Map<String, Object> updateConfig = endpointConfig();
                updateConfig.put("connectionId", target.id());
                updateConfig.put("credentials", credentials(client));
                updateConfig.put("saveCredentials", true);
                String updated = raw(s.admin().client(), GQL_UPDATE_CONNECTION,
                    Map.of("config", updateConfig, "projectId", GLOBAL_PROJECT));
                observed.put("updateConnection", summary(updated));
                expect.check(refused(updated), "an update that would save a credential must be refused");

                String sessionLog = raw(s.user().client(), GQL_SESSION_LOG, Map.of("maxEntries", 200, "clearEntries", false));
                expect.check(leaked(sessionLog, s.markers).isEmpty(), "the session log must carry no marker");
                logged = log.entries();
            }

            Subject fresh = EnforcementTestSupport.loginTestAdmin();
            WebSessionProjectImpl freshProject = fresh.session().getProjectById(GLOBAL_PROJECT);
            if (freshProject == null) {
                Assertions.fail("FIXTURE: a new admin session has no global project");
            }
            DBPDataSourceContainer reloaded = freshProject.getDataSourceRegistry().getDataSource(target.id());
            if (reloaded == null) {
                Assertions.fail("FIXTURE: a new admin session does not load the connection");
            }
            List<String> persisted = heldBy(reloaded.getConnectionConfiguration(), s.markers);
            expect.check(persisted.isEmpty(), "the persisted configuration must hold no marker " + persisted);
            List<String> inFiles = leakedInFiles(freshProject.getAbsolutePath(), s.markers);
            expect.check(inFiles.isEmpty(), "the project files must hold no marker " + inFiles);
            List<String> inLogs = leakedInLogs(logged, s.markers);
            expect.check(inLogs.isEmpty(), "no log line may carry a marker " + inLogs);
            expect.verify(s.redact(observed.toString()));
        }
    }

    // ---------------------------------------------------------------- deployment

    /** SMC-8: custom connections, configuration mode and a project other than the global one each block a protected connect (P0-5) */
    @Test
    public void smc8DeploymentInvariantsBlockProtectedConnects() throws Exception {
        try (Scenario s = new Scenario()) {
            Role ro = s.role("ro");
            Conn target = s.connection("protected", null);
            s.login(target);
            s.serveReadCredential(ro);

            final Expectations expect = new Expectations("SMC-8");
            final Map<String, String> observed = new LinkedHashMap<>();

            s.customConnections(true);
            s.protect(s.spec(target), ProtectedConnectionCredentials.SERVER_DEPLOYMENT);
            final Attempt enabled = attempt(s, target, Map.of());
            s.customConnections(false);
            final Attempt switchedBack = attempt(s, target, Map.of());
            s.protect(s.spec(target), deployment(true, null));
            final Attempt configurationMode = attempt(s, target, Map.of());
            s.protect(s.spec(target), deployment(false, "g_DbacP0NotGlobal"));
            Attempt notGlobal = attempt(s, target, Map.of());
            final int readBackends = s.peak(ro);

            observed.put("custom connections", enabled.describe());
            observed.put("switched back", switchedBack.describe());
            observed.put("configuration mode", configurationMode.describe());
            observed.put("not the global project", notGlobal.describe());
            expect.check(enabled.refused() && !enabled.connected(), "with custom connections enabled the connect must be refused");
            expect.check(enabled.detail("CUSTOM_CONNECTIONS_ENABLED"), "logged as CUSTOM_CONNECTIONS_ENABLED");
            expect.check(switchedBack.refused() && !switchedBack.connected(),
                "once seen, the violation must keep refusing after custom connections are switched off again");
            expect.check(switchedBack.detail("CUSTOM_CONNECTIONS_ENABLED"), "the latched violation is the one logged");
            expect.check(configurationMode.refused() && !configurationMode.connected(),
                "in configuration mode the connect must be refused");
            expect.check(configurationMode.detail("CONFIGURATION_MODE"), "logged as CONFIGURATION_MODE");
            expect.check(notGlobal.refused() && !notGlobal.connected(), "outside the global project the connect must be refused");
            expect.check(notGlobal.detail("NOT_GLOBAL_PROJECT"), "logged as NOT_GLOBAL_PROJECT");
            expect.check(readBackends == 0, "no violated invariant may let the read role connect");

            s.protect(s.spec(target), ProtectedConnectionCredentials.SERVER_DEPLOYMENT);
            String control = init(s.user(), target, Map.of());
            int controlBackends = backends(ro);
            observed.put("control", summary(control));
            expect.check(succeeded(control) && controlBackends > 0, "with every invariant held the same connect must succeed");
            expect.verify(s.redact(observed + "; read-role backends " + readBackends + "/" + controlBackends));
        }
    }

    // ---------------------------------------------------------------- failures

    /** SMC-9: a failed protected connect answers and logs nothing but fixed text, and a failing log changes nothing (P0-6) */
    @Test
    public void smc9ConnectFailureIsRedactedEvenWhenTheLogFails() throws Exception {
        try (Scenario s = new Scenario()) {
            final Role ro = s.role("ro");
            Conn target = s.connection("protected", null);
            s.login(target);
            s.customConnections(false);
            String wrongPassword = "p0-wrong-" + UUID.randomUUID();
            s.markers.put("wrong-password", wrongPassword);
            s.putEnvironment(s.readUserEnv, ro.name());
            s.putEnvironment(s.readPasswordEnv, wrongPassword);
            s.protect(s.spec(target), ProtectedConnectionCredentials.SERVER_DEPLOYMENT);

            String[] parts = EnforcementTestSupport.urlParts();
            Map<String, String> forLogs = new LinkedHashMap<>(s.markers);
            forLogs.put("url", EnforcementTestSupport.PG_URL);
            forLogs.put("endpoint", parts[0] + ":" + parts[1]);
            forLogs.put("server auth text", "password authentication");
            forLogs.put("client auth text", "SCRAM");
            forLogs.put("driver exception", "PSQLException");
            Map<String, String> forResponses = new LinkedHashMap<>(forLogs);
            forResponses.put("host", parts[0]);
            forResponses.put("server message", "FATAL");

            Expectations expect = new Expectations("SMC-9");
            String body;
            String sessionLog;
            List<Entry> logged;
            try (LogRecorder log = new LogRecorder(null)) {
                body = init(s.user(), target, Map.of());
                sessionLog = raw(s.user().client(), GQL_SESSION_LOG, Map.of("maxEntries", 200, "clearEntries", false));
                logged = log.entries();
            }
            DBPDataSourceContainer container = container(s.user(), target);
            List<String> inBody = leaked(body, forResponses);
            List<String> inSessionLog = leaked(sessionLog, forResponses);
            List<String> inLogs = leakedInLogs(logged, forLogs);
            List<Entry> dbac = logged.stream().filter(e -> e.message().startsWith(LOG_PREFIX)).toList();
            expect.check(refused(body), "a failed protected connect must answer with the fixed message only");
            expect.check(!body.contains("\\tat "), "the refusal must carry no stack trace");
            expect.check(inBody.isEmpty(), "the response must carry no credential, reference, endpoint or driver text " + inBody);
            expect.check(inSessionLog.isEmpty(), "the session log must carry none of them " + inSessionLog);
            expect.check(!container.isConnected(), "the connection must stay closed");
            expect.check(heldBy(container.getActualConnectionConfiguration(), s.markers).isEmpty(),
                "a failed connect must not leave the read credential in the connect-time copy");
            expect.check(dbac.stream().anyMatch(e -> e.message().contains("event=DBAC_PROTECTED_CONNECTION_FAILED")
                    && LifecycleTestSupport.EVENT_ID_PATTERN.matcher(e.message()).find() && e.message().contains("exception=")),
                "the failure must be logged by event code, EVENT_ID and exception class");
            expect.check(dbac.stream().allMatch(e -> e.throwable() == null), "no exception object may reach the logger");
            expect.check(inLogs.isEmpty(), "no log line may carry a credential, reference, endpoint or driver text " + inLogs);

            String failingConnect;
            String failingInput;
            int failures;
            try (LogRecorder failing = new LogRecorder(LOG_PREFIX)) {
                failingConnect = init(s.user(), target, Map.of());
                failingInput = init(s.user(), target, Map.of("credentials", Map.of(
                    "userName", "dbac-p0-input-" + s.tag, "userPassword", "dbac-p0-input-" + s.tag)));
                failures = failing.failures();
            }
            expect.check(refused(failingConnect), "a failing log must not change the refused connect");
            expect.check(refused(failingInput), "a failing log must not change the refused client input");
            expect.check(!container.isConnected(), "the connection must stay closed while the log fails");
            expect.check(failures >= 2, "both refusals must have been logged - and the log must have failed");
            expect.verify(s.redact("connect " + summary(body) + "; DBAC log lines " + dbac.size() + "; failing log "
                + summary(failingConnect) + " / " + summary(failingInput) + " failures " + failures));
        }
    }

    /** SMC-10: a protected connection opens only through initConnection; a platform connect is refused */
    @Test
    public void smc10ImplicitConnectsAreRefused() throws Exception {
        try (Scenario s = new Scenario()) {
            Role ro = s.role("ro");
            Conn target = s.connection("protected", null);
            s.login(target);
            s.customConnections(false);
            s.serveReadCredential(ro);
            s.protect(s.spec(target), ProtectedConnectionCredentials.SERVER_DEPLOYMENT);

            DBPDataSourceContainer container = container(s.user(), target);
            final Outcome direct = EnforcementTestSupport.run(() -> container.connect(MONITOR, true, true));
            boolean connected = container.isConnected();
            s.observe();
            if (connected) {
                container.disconnect(MONITOR);
            }
            final String sqlContext;
            final List<Entry> sqlLogged;
            try (LogRecorder log = new LogRecorder(null)) {
                sqlContext = raw(s.user().client(), GQL_SQL_CONTEXT_CREATE, Map.of(
                    "projectId", GLOBAL_PROJECT, "connectionId", target.id()));
                sqlLogged = log.entries();
            }
            boolean connectedBySql = container.isConnected();
            s.observe();
            if (connectedBySql) {
                container.disconnect(MONITOR);
            }
            String navigatorPath = nodePath(s.user(), target);
            final String children;
            final List<Entry> navigatorLogged;
            try (LogRecorder log = new LogRecorder(null)) {
                children = raw(s.user().client(), GQL_NAV_CHILDREN, Map.of("parentPath", navigatorPath));
                navigatorLogged = log.entries();
            }
            if (children.contains("ValidationError") || children.contains("Validation error")) {
                Assertions.fail("FIXTURE: the navigator request is not valid GraphQL");
            }
            boolean connectedByNavigator = container.isConnected();
            s.observe();
            if (connectedByNavigator) {
                container.disconnect(MONITOR);
            }
            final int readBackends = s.peak(ro);
            String explicit = init(s.user(), target, Map.of());
            int explicitBackends = backends(ro);

            Expectations expect = new Expectations("SMC-10");
            expect.check(direct.error() != null && refusalIn(direct.error()),
                "a platform connect outside initConnection must be refused by the server credential policy");
            expect.check(!connected, "the platform connect must not connect");
            expect.check(!succeeded(sqlContext) && sqlContext.contains(REFUSAL) && leaked(sqlContext, s.markers).isEmpty(),
                "an SQL context on a closed protected connection must be refused by the policy, with no marker");
            expect.check(!connectedBySql, "the SQL context request must not connect");
            expect.check(detailLogged(sqlLogged, "IMPLICIT_CONNECT"), "the SQL context's connect must be refused as IMPLICIT_CONNECT");
            expect.check(leaked(children, s.markers).isEmpty(), "the navigator answer must carry no marker");
            expect.check(!connectedByNavigator, "the navigator must not connect");
            expect.check(detailLogged(navigatorLogged, "IMPLICIT_CONNECT"), "the navigator's connect must be refused as IMPLICIT_CONNECT");
            expect.check(readBackends == 0, "no implicit connect may reach the database with the read credential");
            expect.check(succeeded(explicit) && explicitBackends > 0, "initConnection must still connect");
            expect.verify(s.redact("direct " + EnforcementTestSupport.describe(direct.error()) + " connected=" + connected
                + "; sql " + summary(sqlContext) + " connected=" + connectedBySql
                + "; navigator " + summary(children) + " connected=" + connectedByNavigator
                + "; explicit " + summary(explicit) + "; read-role backends " + readBackends + "/" + explicitBackends));
        }
    }

    /**
     * SMC-11: a protected connection whose host, database or stored URL could carry URL parameters fails closed
     * <p>
     * The platform connects with the stored URL, and pgjdbc lets a parameter in it win over the user and password it is
     * given, so a credential written into the database name or the URL would be the one that logs in.
     */
    @Test
    public void smc11ShapesThatCouldCarryACredentialFailClosed() throws Exception {
        try (Scenario s = new Scenario()) {
            final Role ro = s.role("ro");
            Role client = s.role("client");
            String[] parts = EnforcementTestSupport.urlParts();
            String parameters = "?user=" + client.name() + "&password=" + client.password();
            Map<String, Map<String, Object>> shapes = new LinkedHashMap<>();
            shapes.put("credential in the database name", Map.of("databaseName", parts[2] + parameters));
            shapes.put("credential in the stored URL", Map.of("url", EnforcementTestSupport.PG_URL + parameters));
            shapes.put("credential driver property", Map.of("properties", Map.of("password", client.password())));
            shapes.put("variable in a driver property", Map.of("properties", Map.of("ApplicationName", "${" + s.readPasswordEnv + "}")));
            shapes.put("every database of the server", Map.of("providerProperties", Map.of("@dbeaver-show-non-default-db@", "true")));
            shapes.put("server name", Map.of("serverName", "dbac-p0"));
            shapes.put("URL configuration", Map.of("configurationType", "URL", "url", EnforcementTestSupport.PG_URL));
            shapes.put("network handler", Map.of("networkHandlersConfig", List.of(Map.of(
                "id", "ssh_tunnel", "enabled", true, "userName", "dbac-p0", "password", "dbac-p0-tunnel-" + s.tag,
                "savePassword", true, "properties", Map.of("host", "127.0.0.1", "port", "1")))));
            Map<String, Conn> connections = new LinkedHashMap<>();
            for (Map.Entry<String, Map<String, Object>> shape : shapes.entrySet()) {
                connections.put(shape.getKey(), s.connection("shape" + connections.size(), null, shape.getValue()));
            }
            s.login(connections.values().toArray(new Conn[0]));
            s.customConnections(false);
            s.serveReadCredential(ro);
            s.protect(connections.values().stream().map(s::spec).reduce((a, b) -> a + ";" + b).orElseThrow(),
                ProtectedConnectionCredentials.SERVER_DEPLOYMENT);

            final Expectations expect = new Expectations("SMC-11");
            Map<String, String> observed = new LinkedHashMap<>();
            for (Map.Entry<String, Conn> connection : connections.entrySet()) {
                Attempt attempt = attempt(s, connection.getValue(), Map.of());
                observed.put(connection.getKey(), attempt.describe());
                expect.check(attempt.refused() && !attempt.connected(), connection.getKey() + ": the connect must be refused");
                expect.check(attempt.detail("UNSUPPORTED_SETTINGS"), connection.getKey() + ": logged as UNSUPPORTED_SETTINGS");
            }
            int clientBackends = s.peak(client);
            int readBackends = s.peak(ro);
            expect.check(clientBackends == 0, "a credential carried by the connection settings must never log in");
            expect.check(readBackends == 0, "the read credential must not be used for a connection of an unsupported shape");
            expect.verify(s.redact(observed + "; backends client " + clientBackends + " read " + readBackends));
        }
    }

    /**
     * SMC-12: a session that does not run as the read user it was given is disconnected and refused
     * <p>
     * The read role is made a member of the client role and the server is told to switch to it at every login of the
     * read role ({@code ALTER ROLE ... SET role}) - a database-side setting no connection property shows: the login is
     * the read user, the session is not.
     */
    @Test
    public void smc12SessionThatDoesNotRunAsTheReadUserIsDisconnected() throws Exception {
        try (Scenario s = new Scenario()) {
            Role ro = s.role("ro");
            Role client = s.role("client");
            try (Connection raw = EnforcementTestSupport.openRawPostgres(MONITOR)) {
                EnforcementTestSupport.execute(raw, "GRANT " + client.name() + " TO " + ro.name());
                EnforcementTestSupport.execute(raw, "ALTER ROLE " + ro.name() + " SET role = '" + client.name() + "'");
            }
            Conn target = s.connection("protected", null);
            s.login(target);
            s.customConnections(false);
            s.serveReadCredential(ro);
            s.protect(s.spec(target), ProtectedConnectionCredentials.SERVER_DEPLOYMENT);

            Attempt attempt = attempt(s, target, Map.of());
            boolean readGone = awaitNoBackends(ro);

            Expectations expect = new Expectations("SMC-12");
            expect.check(attempt.refused(), "the connect must be refused with the fixed message");
            expect.check(!attempt.connected(), "the connection must not stay open");
            expect.check(attempt.detail("IDENTITY_MISMATCH"), "logged as IDENTITY_MISMATCH");
            expect.check(readGone, "the session that ran as another role must be closed");
            expect.verify(s.redact(attempt.describe() + "; read-role backends gone=" + readGone));
        }
    }

    /**
     * SMC-13: while connection settings can read the server environment, every connection is refused (M2)
     * <p>
     * A variable in any connection's settings could otherwise read the read and writer references' values. The state
     * is latched: switching the resolution off again does not reopen anything until the server restarts.
     */
    @Test
    public void smc13EnvironmentReadableByVariablesRefusesEveryConnection() throws Exception {
        try (Scenario s = new Scenario()) {
            Role ro = s.role("ro");
            Role client = s.role("client");
            Conn target = s.connection("protected", null);
            Conn other = s.connection("other", client);
            s.login(target, other);
            s.customConnections(false);
            s.serveReadCredential(ro);
            TestDeployment deployment = new TestDeployment();
            deployment.environmentVariablesAccessible = true;
            s.protect(s.spec(target), deployment);

            final Attempt protectedAttempt = attempt(s, target, Map.of());
            final Attempt otherAttempt = attempt(s, other, Map.of());
            deployment.environmentVariablesAccessible = false;
            final Attempt latched = attempt(s, other, Map.of());
            final int clientBackends = s.peak(client);
            final int readBackends = s.peak(ro);

            s.protect(s.spec(target), ProtectedConnectionCredentials.SERVER_DEPLOYMENT);
            String control = init(s.user(), other, Map.of());
            int controlBackends = backends(client);

            Expectations expect = new Expectations("SMC-13");
            expect.check(!ProtectedConnectionCredentials.SERVER_DEPLOYMENT.environmentVariablesAccessible(),
                "the test server must not resolve environment variables (premise of the control)");
            expect.check(protectedAttempt.refused() && !protectedAttempt.connected(), "the protected connect must be refused");
            expect.check(protectedAttempt.detail("ENVIRONMENT_VARIABLES_ACCESSIBLE"), "logged as ENVIRONMENT_VARIABLES_ACCESSIBLE");
            expect.check(otherAttempt.refused() && !otherAttempt.connected(), "an unprotected connect must be refused too");
            expect.check(otherAttempt.detail("ENVIRONMENT_VARIABLES_ACCESSIBLE"), "the unprotected refusal is logged the same way");
            expect.check(latched.refused() && !latched.connected(), "the state must stay latched after the resolution is off");
            expect.check(clientBackends == 0 && readBackends == 0, "nothing may connect while the environment is readable");
            expect.check(succeeded(control) && controlBackends > 0, "a new provider on a safe deployment connects the unprotected one");
            expect.verify(s.redact("protected " + protectedAttempt.describe() + "; other " + otherAttempt.describe()
                + "; latched " + latched.describe() + "; control " + summary(control)));
        }
    }

    /**
     * SMC-14: the server configuration activates the production provider (QA M-1)
     * <p>
     * {@link ProtectedConnectionCredentials#forServer} is what installForServer installs at startup: the system property
     * read now, the process environment and the running server read at every connect. This test sets the property for
     * itself only and installs what forServer returns. The reference names exist in no process environment, so the real
     * lookup resolves nothing and the governed connect fails closed; a client credential is refused before that; an
     * unprotected connection is unchanged. A blank or unset property governs nothing, an unusable one refuses
     * everything.
     */
    @Test
    public void smc14ServerConfigurationActivatesTheProvider() throws Exception {
        try (Scenario s = new Scenario()) {
            Role client = s.role("client");
            Conn target = s.connection("protected", null);
            Conn other = s.connection("other", client);
            s.login(target, other);
            s.customConnections(false);
            final boolean startedUnprotected = ServerManagedCredentials.provider() == ServerManagedCredentials.NONE;
            final String property = ProtectedConnectionCredentials.CONFIGURATION_PROPERTY;
            final String before = System.getProperty(property);
            final Expectations expect = new Expectations("SMC-14");
            final Map<String, String> observed = new LinkedHashMap<>();
            try {
                System.setProperty(property, s.spec(target));
                ProtectedConnectionCredentials configured = ProtectedConnectionCredentials.forServer();
                expect.check(configured != null, "a configured property must produce a provider");
                if (configured != null) {
                    s.install(configured);
                    Attempt governed = attempt(s, target, Map.of());
                    Attempt clientInput = attempt(s, target, Map.of("credentials", credentials(client)));
                    Attempt unprotected = attempt(s, other, Map.of());
                    observed.put("governed", governed.describe());
                    observed.put("client input", clientInput.describe());
                    observed.put("unprotected", unprotected.describe());
                    expect.check(governed.refused() && !governed.connected(), "the configured connection must be governed and fail closed");
                    expect.check(governed.detail("REFERENCE_UNRESOLVED"),
                        "the real environment lookup must resolve nothing for unknown names");
                    expect.check(clientInput.refused() && clientInput.detail("CLIENT_INPUT"), "a client credential must be refused");
                    expect.check(unprotected.connected(), "a connection the property does not name must be unchanged");
                }
                System.setProperty(property, "   ");
                expect.check(ProtectedConnectionCredentials.forServer() == null, "a blank property must govern nothing");
                System.clearProperty(property);
                expect.check(ProtectedConnectionCredentials.forServer() == null, "an unset property must govern nothing");
                System.setProperty(property, "garbage");
                ProtectedConnectionCredentials unusable = ProtectedConnectionCredentials.forServer();
                expect.check(unusable != null, "an unusable property must still produce a provider");
                if (unusable != null) {
                    s.install(unusable);
                    Attempt everything = attempt(s, other, Map.of());
                    observed.put("unusable", everything.describe());
                    expect.check(everything.refused() && everything.detail("CONFIGURATION_INVALID"),
                        "with an unusable property every connection must be refused");
                }
            } finally {
                if (before == null) {
                    System.clearProperty(property);
                } else {
                    System.setProperty(property, before);
                }
            }
            expect.check(startedUnprotected, "the test server, started without the property, must have installed nothing");
            expect.verify(s.redact(observed.toString()));
        }
    }

    /**
     * SMC-15: a deployment violation refuses every connection, not only the protected ones (Codex H1)
     * <p>
     * With custom connections, configuration mode or an unreadable deployment, a connection the configuration does not
     * name is refused too, the violation stays latched when it is resolved, and a new provider on a sound deployment
     * leaves that connection as it always was. While everything is refused the client is not asked for credentials.
     */
    @Test
    public void smc15DeploymentViolationRefusesEveryConnection() throws Exception {
        try (Scenario s = new Scenario()) {
            Role ro = s.role("ro");
            Role client = s.role("client");
            Conn target = s.connection("protected", null);
            Conn other = s.connection("other", client);
            Conn plain = s.connection("plain", null);
            s.login(target, other, plain);
            s.serveReadCredential(ro);

            s.customConnections(true);
            s.protect(s.spec(target), ProtectedConnectionCredentials.SERVER_DEPLOYMENT);
            final Attempt custom = attempt(s, other, Map.of());
            final Boolean refusedAuthNeeded = authNeeded(raw(s.user().client(), GQL_CONNECTION_INFO, info(plain)));
            s.customConnections(false);
            final Attempt customLatched = attempt(s, other, Map.of());

            TestDeployment configurationMode = new TestDeployment();
            configurationMode.configurationMode = true;
            s.protect(s.spec(target), configurationMode);
            final Attempt mode = attempt(s, other, Map.of());
            configurationMode.configurationMode = false;
            final Attempt modeLatched = attempt(s, other, Map.of());

            TestDeployment unreadable = new TestDeployment();
            unreadable.unreadable = true;
            s.protect(s.spec(target), unreadable);
            final Attempt unknown = attempt(s, other, Map.of());

            final int clientPeak = s.peak(client);
            final int readPeak = s.peak(ro);

            s.protect(s.spec(target), ProtectedConnectionCredentials.SERVER_DEPLOYMENT);
            String control = init(s.user(), other, Map.of());
            boolean controlConnected = isConnected(s.user(), other);
            int controlBackends = backends(client);
            Boolean controlAuthNeeded = authNeeded(raw(s.user().client(), GQL_CONNECTION_INFO, info(plain)));

            Expectations expect = new Expectations("SMC-15");
            expect.check(custom.refused() && !custom.connected(), "with custom connections an unlisted connection must be refused");
            expect.check(custom.detail("CUSTOM_CONNECTIONS_ENABLED"), "logged as CUSTOM_CONNECTIONS_ENABLED");
            expect.check(Boolean.FALSE.equals(refusedAuthNeeded),
                "while every connection is refused the client must not be asked for credentials");
            expect.check(customLatched.refused() && !customLatched.connected(), "the violation must stay latched after it is resolved");
            expect.check(mode.refused() && !mode.connected(), "in configuration mode an unlisted connection must be refused");
            expect.check(mode.detail("CONFIGURATION_MODE"), "logged as CONFIGURATION_MODE");
            expect.check(modeLatched.refused() && !modeLatched.connected(), "configuration mode must stay latched after it ends");
            expect.check(unknown.refused() && !unknown.connected(), "an unreadable deployment must refuse an unlisted connection");
            expect.check(unknown.detail("DEPLOYMENT_UNREADABLE"), "logged as DEPLOYMENT_UNREADABLE");
            expect.check(clientPeak == 0, "no backend may belong to the client role while the deployment is violated");
            expect.check(readPeak == 0, "no backend may belong to the read role while the deployment is violated");
            expect.check(succeeded(control) && controlConnected && controlBackends > 0,
                "a new provider on a sound deployment must leave the unlisted connection as it was");
            expect.check(Boolean.TRUE.equals(controlAuthNeeded),
                "on a sound deployment an unlisted connection asks for credentials as before");
            expect.verify(s.redact("custom " + custom.describe() + " authNeeded=" + refusedAuthNeeded + "; latched "
                + customLatched.describe() + "; mode " + mode.describe() + "; latched " + modeLatched.describe()
                + "; unreadable " + unknown.describe() + "; peaks client " + clientPeak + " read " + readPeak
                + "; control " + summary(control) + " authNeeded=" + controlAuthNeeded));
        }
    }

    /**
     * SMC-16: a protected connection with any driver or provider property key fails closed (Codex H2)
     * <p>
     * The keys and values are made up, so no list of dangerous names can know them; the allowlist the enforcement
     * already uses for endpoint identity allows none for PostgreSQL. Neither the key nor the value may appear in what
     * the refusal answers or logs. A protected connection with empty maps still connects.
     */
    @Test
    public void smc16UnclassifiedPropertyKeysFailClosed() throws Exception {
        try (Scenario s = new Scenario()) {
            final Role ro = s.role("ro");
            String driverKey = "dbacP0Driver" + s.tag;
            String driverValue = "dbac-p0-driver-value-" + UUID.randomUUID();
            String providerKey = "@dbeaver-dbac-p0-" + s.tag + "@";
            String providerValue = "dbac-p0-provider-value-" + UUID.randomUUID();
            Map<String, String> properties = new LinkedHashMap<>();
            properties.put("driver-property-key", driverKey);
            properties.put("driver-property-value", driverValue);
            properties.put("provider-property-key", providerKey);
            properties.put("provider-property-value", providerValue);
            s.markers.putAll(properties);
            Conn withDriver = s.connection("driverprop", null, Map.of("properties", Map.of(driverKey, driverValue)));
            Conn withProvider = s.connection("providerprop", null, Map.of("providerProperties", Map.of(providerKey, providerValue)));
            Conn clean = s.connection("clean", null);
            s.login(withDriver, withProvider, clean);
            s.customConnections(false);
            s.serveReadCredential(ro);
            s.protect(s.spec(withDriver) + ";" + s.spec(withProvider) + ";" + s.spec(clean),
                ProtectedConnectionCredentials.SERVER_DEPLOYMENT);

            final Attempt driverAttempt = attempt(s, withDriver, Map.of());
            final Attempt providerAttempt = attempt(s, withProvider, Map.of());
            final int readPeak = s.peak(ro);
            final String sessionLog = raw(s.user().client(), GQL_SESSION_LOG, Map.of("maxEntries", 200, "clearEntries", false));
            List<Entry> logged = new ArrayList<>(driverAttempt.logged());
            logged.addAll(providerAttempt.logged());
            String cleanConnect = init(s.user(), clean, Map.of());
            int cleanBackends = backends(ro);

            Expectations expect = new Expectations("SMC-16");
            expect.check(driverAttempt.refused() && !driverAttempt.connected(), "a driver property must refuse the protected connect");
            expect.check(driverAttempt.detail("UNSUPPORTED_SETTINGS"), "the driver property is logged as UNSUPPORTED_SETTINGS");
            expect.check(providerAttempt.refused() && !providerAttempt.connected(),
                "a provider property must refuse the protected connect");
            expect.check(providerAttempt.detail("UNSUPPORTED_SETTINGS"), "the provider property is logged as UNSUPPORTED_SETTINGS");
            expect.check(readPeak == 0, "no backend may open for a connection with an unclassified property");
            List<String> inResponses = leaked(driverAttempt.body() + providerAttempt.body(), properties);
            expect.check(inResponses.isEmpty(), "the refusals must carry no property key or value " + inResponses);
            List<String> inSessionLog = leaked(sessionLog, properties);
            expect.check(inSessionLog.isEmpty(), "the session log must carry no property key or value " + inSessionLog);
            List<String> inLogs = leakedInLogs(logged, properties);
            expect.check(inLogs.isEmpty(), "no log line may carry a property key or value " + inLogs);
            expect.check(succeeded(cleanConnect) && cleanBackends > 0, "a protected connection with empty maps must still connect");
            expect.verify(s.redact("driver " + driverAttempt.describe() + "; provider " + providerAttempt.describe()
                + "; read peak " + readPeak + "; clean " + summary(cleanConnect)));
        }
    }

    /**
     * SMC-17: an Error during a protected connect is rethrown after the cleanup, not turned into a refusal
     * <p>
     * The failures are thrown by a provider that is otherwise the production one. These cases are checked, and only
     * what is named for each:
     * <p>
     * A RuntimeException right after the identity check: the fixed refusal without its message; the connection closed.
     * An Error right after the identity check: that Error, not the refusal; the connection closed; the configuration
     * the connection holds keeps no credential; the DBAC log names the Error's class.
     * An Error while the credential is supplied, before it is in the copy, inside the platform's connect: that Error;
     * no connection; the configuration the connection holds keeps no credential; the DBAC log names the class.
     * An Error once the credential is in the copy, inside the platform's connect: that Error; no connection; the copy
     * held a user and a password when the Error was thrown and holds no credential after it; the DBAC log names the
     * class.
     * An Error raised by the handling of a RuntimeException, before that handling cleared the copy: that Error; the
     * connection closed; the copy holds no credential after the cleanup's second attempt; the DBAC log names the class.
     * The same, with an Error from the cleanup's second attempt too: the first Error is the one answered, the second
     * attempt ran, the connection is closed. Whether the copy itself was cleared is not checked here.
     * A RuntimeException raised by the handling of a failure: the fixed refusal; the connection closed. Whether the
     * copy itself was cleared is not checked here.
     * <p>
     * The answers to all but the first case, the session log, and every log line recorded around the Error cases carry
     * no credential, reference or role name; that is the platform passing on the injected Errors, nothing a driver
     * raises. Without a failure the same provider connects. Only ordinary injected throwables are used - nothing that
     * would end the JVM.
     */
    @Test
    public void smc17ErrorsAreRethrownAfterCleanup() throws Exception {
        try (Scenario s = new Scenario()) {
            Role ro = s.role("ro");
            Conn target = s.connection("protected", null);
            s.login(target);
            s.customConnections(false);
            s.serveReadCredential(ro);
            FaultingProvider faulting = new FaultingProvider(ProtectedConnectionCredentials.parse(
                s.spec(target), s::lookup, ProtectedConnectionCredentials.SERVER_DEPLOYMENT));
            s.install(faulting);

            faulting.failure = new LifecycleTestSupport.InjectedRuntimeException("verify");
            final String runtime = init(s.user(), target, Map.of());
            final boolean runtimeConnected = isConnected(s.user(), target);
            final boolean runtimeGone = awaitNoBackends(ro);

            faulting.failure = new LifecycleTestSupport.InjectedError("verify");
            final String error;
            final List<Entry> errorLogged;
            try (LogRecorder log = new LogRecorder(null)) {
                error = init(s.user(), target, Map.of());
                errorLogged = log.entries();
            }
            final boolean errorConnected = isConnected(s.user(), target);
            final boolean errorGone = awaitNoBackends(ro);
            final List<String> held = heldBy(container(s.user(), target).getActualConnectionConfiguration(), s.markers);

            faulting.failure = null;
            faulting.supplyFailure = new LifecycleTestSupport.InjectedError("supply");
            final String supplyError;
            final List<Entry> supplyLogged;
            try (LogRecorder log = new LogRecorder(null)) {
                supplyError = init(s.user(), target, Map.of());
                supplyLogged = log.entries();
            }
            final boolean supplyConnected = isConnected(s.user(), target);
            s.observe();
            final List<String> supplyHeld = heldBy(container(s.user(), target).getActualConnectionConfiguration(), s.markers);

            faulting.supplyFailure = null;
            faulting.postSupplyFailure = new LifecycleTestSupport.InjectedError("post-supply");
            final String postSupplyError;
            final List<Entry> postSupplyLogged;
            try (LogRecorder log = new LogRecorder(null)) {
                postSupplyError = init(s.user(), target, Map.of());
                postSupplyLogged = log.entries();
            }
            final int postSupplyBackends = backends(ro);
            final boolean postSupplyConnected = isConnected(s.user(), target);
            final boolean suppliedBeforeFailure = faulting.suppliedBeforeFailure;
            final List<String> postSupplyHeld = heldBy(faulting.suppliedCopy, s.markers);
            final List<String> postSupplyHeldNow = heldBy(
                container(s.user(), target).getActualConnectionConfiguration(), s.markers);

            // The handling of a failure raises an Error before its own cleanup ran; the cleanup is attempted again
            faulting.postSupplyFailure = null;
            faulting.failure = new LifecycleTestSupport.InjectedRuntimeException("verify");
            faulting.failureHandling.add(new LifecycleTestSupport.InjectedError("failure-handling"));
            final String handlingError;
            final List<Entry> handlingLogged;
            try (LogRecorder log = new LogRecorder(null)) {
                handlingError = init(s.user(), target, Map.of());
                handlingLogged = log.entries();
            }
            final boolean handlingConnected = isConnected(s.user(), target);
            final boolean handlingGone = awaitNoBackends(ro);
            final List<String> handlingHeld = heldBy(faulting.suppliedCopy, s.markers);

            // ... and the cleanup raises one as well; then a RuntimeException while the failure is handled
            faulting.failureHandling.add(new LifecycleTestSupport.InjectedError("failure-handling"));
            faulting.failureHandling.add(new LifecycleTestSupport.InjectedError("cleanup"));
            final String cleanupError;
            final String handlingRuntime;
            final List<Entry> restLogged;
            final int cleanupLeft;
            final boolean cleanupConnected;
            final boolean cleanupGone;
            final List<String> cleanupHeld;
            try (LogRecorder log = new LogRecorder(null)) {
                cleanupError = init(s.user(), target, Map.of());
                cleanupLeft = faulting.failureHandling.size();
                cleanupConnected = isConnected(s.user(), target);
                cleanupGone = awaitNoBackends(ro);
                cleanupHeld = heldBy(container(s.user(), target).getActualConnectionConfiguration(), s.markers);
                faulting.failureHandling.clear();
                faulting.failureHandling.add(new LifecycleTestSupport.InjectedRuntimeException("failure-handling"));
                handlingRuntime = init(s.user(), target, Map.of());
                restLogged = log.entries();
            }
            final boolean handlingRuntimeConnected = isConnected(s.user(), target);
            final boolean handlingRuntimeGone = awaitNoBackends(ro);
            final String sessionLog = raw(s.user().client(), GQL_SESSION_LOG, Map.of("maxEntries", 200, "clearEntries", false));

            faulting.failure = null;
            faulting.failureHandling.clear();
            final String control = init(s.user(), target, Map.of());
            final int controlBackends = backends(ro);
            String errorClass = "exception=" + LifecycleTestSupport.InjectedError.class.getName();

            Expectations expect = new Expectations("SMC-17");
            expect.check(refused(runtime), "a RuntimeException must become the fixed refusal");
            expect.check(!runtime.contains(LifecycleTestSupport.SECRET_MARKER), "the refusal must not carry the exception's message");
            expect.check(!runtimeConnected && runtimeGone, "after a RuntimeException the connection must be closed");
            expect.check(!succeeded(error) && !refused(error), "an Error must not be turned into the refusal");
            expect.check(error.contains("InjectedError"), "the original Error must reach the caller");
            expect.check(!errorConnected && errorGone, "after an Error the connection must still be closed");
            expect.check(held.isEmpty(), "after an Error the connect-time copy must hold no credential " + held);
            expect.check(errorLogged.stream().anyMatch(e -> e.message().startsWith(LOG_PREFIX) && e.message().contains(errorClass)),
                "the DBAC log must name the Error's class");
            expect.check(!succeeded(supplyError) && !refused(supplyError) && supplyError.contains("InjectedError"),
                "an Error inside the platform's connect must be rethrown as itself, not turned into the refusal");
            expect.check(!supplyConnected && s.peak(ro) == 0, "an Error while the credential is supplied must not connect");
            expect.check(supplyHeld.isEmpty(), "an Error while the credential is supplied must leave no credential in the copy");
            expect.check(supplyLogged.stream().anyMatch(e -> e.message().startsWith(LOG_PREFIX) && e.message().contains(errorClass)),
                "the DBAC log must name the class of an Error the platform wrapped");
            expect.check(!succeeded(postSupplyError) && !refused(postSupplyError) && postSupplyError.contains("injected at post-supply"),
                "an Error once the credential is in the copy must be rethrown as itself, not turned into the refusal");
            expect.check(!postSupplyConnected && postSupplyBackends == 0, "an Error once the credential is in the copy must not connect");
            expect.check(suppliedBeforeFailure, "the copy must have held the credential when that Error was thrown");
            expect.check(postSupplyHeld.isEmpty() && postSupplyHeldNow.isEmpty(),
                "after that Error the copy must hold no credential " + postSupplyHeld + " " + postSupplyHeldNow);
            expect.check(postSupplyLogged.stream().anyMatch(e -> e.message().startsWith(LOG_PREFIX) && e.message().contains(errorClass)),
                "the DBAC log must name the class of that Error");
            expect.check(!succeeded(handlingError) && !refused(handlingError) && handlingError.contains("injected at failure-handling"),
                "an Error while a failure is handled must be rethrown as itself, not turned into the refusal");
            expect.check(!handlingConnected && handlingGone, "after an Error while a failure is handled the connection must be closed");
            expect.check(handlingHeld.isEmpty(), "after an Error while a failure is handled the copy must be cleared " + handlingHeld);
            expect.check(handlingLogged.stream().anyMatch(e -> e.message().startsWith(LOG_PREFIX) && e.message().contains(errorClass)),
                "the DBAC log must name the class of an Error raised while a failure is handled");
            expect.check(!refused(cleanupError) && cleanupError.contains("injected at failure-handling")
                && !cleanupError.contains("injected at cleanup"), "an Error the cleanup raises must not take the place of the one handled");
            expect.check(cleanupLeft == 0, "the cleanup must have been attempted, and failed, after the Error");
            expect.check(!cleanupConnected && cleanupGone && cleanupHeld.isEmpty(),
                "when the cleanup fails as well the connection must still be closed " + cleanupHeld);
            expect.check(refused(handlingRuntime) && !handlingRuntime.contains(LifecycleTestSupport.SECRET_MARKER),
                "a RuntimeException while a failure is handled must still end in the fixed refusal");
            expect.check(!handlingRuntimeConnected && handlingRuntimeGone,
                "after a RuntimeException while a failure is handled the connection must be closed");
            List<Entry> logged = new ArrayList<>(errorLogged);
            logged.addAll(supplyLogged);
            logged.addAll(postSupplyLogged);
            logged.addAll(handlingLogged);
            logged.addAll(restLogged);
            List<String> inLogs = leakedInLogs(logged, s.markers);
            expect.check(inLogs.isEmpty(), "no log line around an Error may carry a credential, reference or role name " + inLogs);
            List<String> inErrors = leaked(error + supplyError + postSupplyError + handlingError + cleanupError + handlingRuntime
                + sessionLog, s.markers);
            expect.check(inErrors.isEmpty(), "what an Error answers must carry no credential, reference or role name " + inErrors);
            expect.check(succeeded(control) && controlBackends > 0, "without a failure the same provider must connect");
            expect.verify(s.redact("runtime " + summary(runtime) + " connected=" + runtimeConnected + " gone=" + runtimeGone
                + "; error refused=" + refused(error) + " named=" + error.contains("InjectedError") + " connected=" + errorConnected
                + " gone=" + errorGone + "; supply refused=" + refused(supplyError) + " named=" + supplyError.contains("InjectedError")
                + " connected=" + supplyConnected + " logged=" + supplyLogged.stream().map(Entry::message)
                .filter(m -> m.startsWith(LOG_PREFIX)).map(m -> m.substring(m.indexOf("exception="))).toList()
                + "; post-supply refused=" + refused(postSupplyError) + " held-before=" + suppliedBeforeFailure
                + " held-after=" + postSupplyHeld.size() + " connected=" + postSupplyConnected
                + "; handling refused=" + refused(handlingError) + " connected=" + handlingConnected + " gone=" + handlingGone
                + " held=" + handlingHeld.size() + "; cleanup left=" + cleanupLeft
                + " original=" + cleanupError.contains("injected at failure-handling")
                + " replaced=" + cleanupError.contains("injected at cleanup")
                + "; handling runtime " + summary(handlingRuntime) + " connected=" + handlingRuntimeConnected
                + "; log lines " + logged.size() + " leaked " + inLogs.size() + "; control " + summary(control)));
        }
    }

    // ---------------------------------------------------------------- scenario

    /** A disposable PostgreSQL login role; its name and password are both markers */
    private record Role(@NotNull String label, @NotNull String name, @NotNull String password) {
    }

    /** A connection in the global project */
    private record Conn(@NotNull String id) {
    }

    /**
     * One test's admin session, roles, connections, user, environment and provider
     * <p>
     * Closing it puts the global state back first - the provider and the custom-connections flag - and then removes
     * what it created, each step on its own so that one failure does not leave the rest behind. A step that fails is
     * a fixture failure, not something to carry on past.
     * <p>
     * The scenario administers through a session of its own, and that session both creates and deletes its connections.
     * Every web session keeps its own server-side copy of the global project's data sources, and saving any connection
     * writes that whole copy: a connection deleted through another session would come back with the creating session's
     * next save, and a long-lived session would bring back every scenario's connections. Once a fresh admin session
     * finds none of them - through the API and in the saved configuration - the scenario's sessions are logged out.
     */
    private static final class Scenario implements AutoCloseable {
        final String tag = UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        final String readUserEnv = environmentName("RO_USER");
        final String readPasswordEnv = environmentName("RO_PASSWORD");
        final String writerUserEnv = environmentName("WR_USER");
        final String writerPasswordEnv = environmentName("WR_PASSWORD");
        /** label to value of everything that must stay inside the connect-time copy */
        final Map<String, String> markers = new LinkedHashMap<>();
        final Set<String> lookedUp = ConcurrentHashMap.newKeySet();
        private final Map<String, String> environment = new ConcurrentHashMap<>();
        private final List<Role> roles = new ArrayList<>();
        /** The most backends each role had at any observation - taken before a test closes what a connect opened */
        private final Map<String, Integer> peaks = new ConcurrentHashMap<>();
        private final List<String> connectionIds = new ArrayList<>();
        /** The scenario's admin session: it creates, administers and deletes everything the scenario needs */
        private final Subject admin;
        @Nullable
        private String userId;
        @Nullable
        private Subject user;
        @Nullable
        private ServerManagedCredentials.Installation installation;
        @Nullable
        private Boolean customConnectionsBefore;

        Scenario() throws Exception {
            admin = EnforcementTestSupport.loginTestAdmin();
            markers.put("read-user-reference", readUserEnv);
            markers.put("read-password-reference", readPasswordEnv);
            markers.put("writer-user-reference", writerUserEnv);
            markers.put("writer-password-reference", writerPasswordEnv);
            String writerUser = "dbac-p0-writer-user-" + UUID.randomUUID();
            String writerPassword = "dbac-p0-writer-password-" + UUID.randomUUID();
            environment.put(writerUserEnv, writerUser);
            environment.put(writerPasswordEnv, writerPassword);
            markers.put("writer-user-value", writerUser);
            markers.put("writer-password-value", writerPassword);
        }

        @NotNull
        private String environmentName(@NotNull String suffix) {
            return "DBAC_P0_" + tag.toUpperCase(Locale.ROOT) + "_" + suffix;
        }

        @NotNull
        Subject admin() {
            return admin;
        }

        @NotNull
        Role role(@NotNull String label) throws Exception {
            Role role = new Role(label, "dbac_p0_" + label + "_" + tag, "p0-" + label + "-" + UUID.randomUUID());
            try (Connection raw = EnforcementTestSupport.openRawPostgres(MONITOR)) {
                EnforcementTestSupport.execute(raw, "CREATE ROLE " + role.name() + " LOGIN PASSWORD '" + role.password() + "'");
            }
            roles.add(role);
            markers.put(label + "-user", role.name());
            markers.put(label + "-password", role.password());
            return role;
        }

        /** A connection the admin creates in the global project, with a stored credential or none */
        @NotNull
        Conn connection(@NotNull String label, @Nullable Role stored) throws Exception {
            return connection(label, stored, Map.of());
        }

        /** The same, with settings that replace or add to the plain endpoint */
        @NotNull
        Conn connection(@NotNull String label, @Nullable Role stored, @NotNull Map<String, Object> settings) throws Exception {
            Map<String, Object> config = endpointConfig();
            config.putAll(settings);
            config.put("name", "DBAC P0 " + label + " " + tag);
            if (stored != null) {
                config.put("credentials", credentials(stored));
                config.put("saveCredentials", true);
            }
            Map<String, Object> created = admin.client().sendQuery(GQL_CREATE_CONNECTION, Map.of(
                "config", config, "projectId", GLOBAL_PROJECT));
            if (created == null || created.get("id") == null) {
                throw new IllegalStateException("FIXTURE: createConnection returned no id");
            }
            String id = String.valueOf(created.get("id"));
            connectionIds.add(id);
            CREATED_CONNECTIONS.add(id);
            return new Conn(id);
        }

        /** Registers a connection an entry point created when it should have refused, so that it is deleted too */
        void adopt(@NotNull String body) {
            if (succeeded(body)) {
                Matcher matcher = RESULT_ID.matcher(body);
                if (matcher.find()) {
                    connectionIds.add(matcher.group(1));
                    CREATED_CONNECTIONS.add(matcher.group(1));
                }
            }
        }

        /** Creates an ordinary user, grants it the connections and logs it in */
        @NotNull
        Subject login(@NotNull Conn... connections) throws Exception {
            userId = USER_PREFIX + tag;
            admin.client().sendQuery(GQL_CREATE_USER, Map.of("userId", userId, "enabled", true, "authRole", "user"));
            String secret = SecurityUtils.makeDigest("dbac-p0-" + UUID.randomUUID());
            Map<String, Object> credentials = new HashMap<>();
            credentials.put(LocalAuthProvider.CRED_PASSWORD, secret);
            admin.client().sendQuery(GQL_SET_CREDENTIALS, Map.of(
                "userId", userId, "providerId", LocalAuthProvider.PROVIDER_ID, "credentials", credentials));
            admin.client().sendQuery(GQL_ADD_ACCESS, Map.of(
                "projectId", GLOBAL_PROJECT,
                "connectionIds", Arrays.stream(connections).map(Conn::id).toList(),
                "subjects", List.of(userId)));
            WebGQLClient client = CEAppStarter.createClient();
            CEAppStarter.authenticateTestUser(client, Map.of(
                LocalAuthProvider.CRED_USER, userId, LocalAuthProvider.CRED_PASSWORD, secret));
            WebSession session = EnforcementTestSupport.resolveSession(client);
            Assertions.assertEquals(userId, session.getUserId(), "FIXTURE: login did not produce the created user's session");
            // The connection and its grant reach existing sessions through the server's event job, after the login.
            long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
            while (Arrays.stream(connections).anyMatch(c -> connectionInfo(session, c) == null)) {
                if (System.nanoTime() > deadline) {
                    Assertions.fail("FIXTURE: the user's session does not see a granted connection");
                }
                Thread.sleep(50);
            }
            user = new Subject(userId, client, session);
            return user;
        }

        @NotNull
        Subject user() {
            if (user == null) {
                throw new IllegalStateException("FIXTURE: the scenario has no logged-in user");
            }
            return user;
        }

        @NotNull
        String spec(@NotNull Conn connection) {
            return GLOBAL_PROJECT + "," + connection.id() + "," + readUserEnv + "," + readPasswordEnv
                + "," + writerUserEnv + "," + writerPasswordEnv;
        }

        @Nullable
        String lookup(@NotNull String name) {
            lookedUp.add(name);
            return environment.get(name);
        }

        void putEnvironment(@NotNull String name, @Nullable String value) {
            if (value == null) {
                environment.remove(name);
            } else {
                environment.put(name, value);
            }
        }

        /** Records every role's backends now, while whatever the last request opened is still open */
        void observe() throws Exception {
            for (Role role : roles) {
                peaks.merge(role.name(), backends(role), Math::max);
            }
        }

        /** The most backends the role had at any {@link #observe} so far */
        int peak(@NotNull Role role) {
            return peaks.getOrDefault(role.name(), 0);
        }

        void serveReadCredential(@NotNull Role role) {
            environment.put(readUserEnv, role.name());
            environment.put(readPasswordEnv, role.password());
        }

        /** Installs a new production provider over the specification; the one before it is put back first */
        void protect(@NotNull String specification, @NotNull ProtectedConnectionCredentials.Deployment deployment) {
            install(ProtectedConnectionCredentials.parse(specification, this::lookup, deployment));
        }

        void install(@NotNull ServerManagedCredentials.Provider provider) {
            if (installation != null) {
                installation.close();
                installation = null;
            }
            installation = ServerManagedCredentials.swap(provider);
        }

        void customConnections(boolean enabled) {
            CBAppConfig config = appConfig();
            if (customConnectionsBefore == null) {
                customConnectionsBefore = config.isSupportsCustomConnections();
            }
            config.setSupportsCustomConnections(enabled);
        }

        /** The text with every marker value replaced by its label */
        @NotNull
        String redact(@NotNull String text) {
            String result = text;
            for (Map.Entry<String, String> marker : markers.entrySet()) {
                if (!marker.getValue().isEmpty()) {
                    result = result.replace(marker.getValue(), "<" + marker.getKey() + ">");
                }
            }
            return result;
        }

        @Override
        public void close() {
            markers.forEach((label, value) -> CLASS_MARKERS.putIfAbsent(value, label));
            List<String> failed = new ArrayList<>();
            if (installation != null) {
                attempt(failed, "putting the provider back", installation::close);
            }
            if (customConnectionsBefore != null) {
                attempt(failed, "putting the custom-connections flag back",
                    () -> appConfig().setSupportsCustomConnections(customConnectionsBefore));
            }
            if (user != null) {
                for (String id : connectionIds) {
                    try {
                        user.client().sendQuery(GQL_CLOSE_CONNECTION, Map.of("id", id, "projectId", GLOBAL_PROJECT));
                    } catch (Exception notOpen) {
                        // Not connected, or not visible to the user: the user has nothing of it to close
                    }
                }
                attempt(failed, "logging the user out", () -> logout(user));
            }
            String storesBefore = encryptedStores();
            for (String id : connectionIds) {
                attempt(failed, "deleting a connection through the session that created it",
                    () -> admin.client().sendQuery(GQL_DELETE_CONNECTION, Map.of("id", id, "projectId", GLOBAL_PROJECT)));
            }
            attempt(failed, "checking that the connections are gone", () -> failed.addAll(remainingConnections()));
            System.out.println("SMC cleanup: encrypted credential stores (content not read) before the deletes ["
                + storesBefore + "], after [" + encryptedStores() + "]");
            if (userId != null) {
                attempt(failed, "deleting the user",
                    () -> admin.client().sendQuery(EnforcementTestSupport.GQL_DELETE_USER, Map.of("userId", userId)));
            }
            for (Role role : roles) {
                attempt(failed, "dropping a role", () -> dropRole(role));
            }
            attempt(failed, "logging the admin out", () -> logout(admin));
            if (!failed.isEmpty()) {
                throw new IllegalStateException("FIXTURE: the scenario's cleanup failed - " + String.join("; ", failed));
            }
        }

        /**
         * The scenario's connections that are still there - in the creating session's registry, in what a fresh admin
         * session's API lists, or in the saved global project configuration - by count, never by id or name
         */
        @NotNull
        private List<String> remainingConnections() throws Exception {
            List<String> remaining = new ArrayList<>();
            WebSessionProjectImpl own = admin.session().getProjectById(GLOBAL_PROJECT);
            long registered = own == null ? 0 : connectionIds.stream()
                .filter(id -> own.getDataSourceRegistry().getDataSource(id) != null).count();
            if (registered > 0) {
                remaining.add(registered + " connection(s) still in the creating session's registry");
            }
            Subject fresh = EnforcementTestSupport.loginTestAdmin();
            try {
                String listed = raw(fresh.client(), GQL_USER_CONNECTIONS, Map.of("projectId", GLOBAL_PROJECT));
                if (!succeeded(listed)) {
                    remaining.add("a fresh admin session's userConnections did not answer");
                }
                remaining.addAll(ownConnectionsIn("a fresh admin session's userConnections", listed));
            } finally {
                logout(fresh);
            }
            for (Path configuration : dataSourceConfigurations(Objects.requireNonNull(globalProjectFolder))) {
                remaining.addAll(ownConnectionsIn("the saved " + configuration.getFileName(), Files.readString(configuration)));
            }
            return remaining;
        }

        @NotNull
        private List<String> ownConnectionsIn(@NotNull String where, @NotNull String text) {
            long ids = connectionIds.stream().filter(text::contains).count();
            int names = 0;
            Matcher matcher = Pattern.compile(
                "\"name\"\\s*:\\s*\"" + Pattern.quote(CONNECTION_PREFIX) + "[^\"]* " + Pattern.quote(tag) + "\"").matcher(text);
            while (matcher.find()) {
                names++;
            }
            if (ids == 0 && names == 0) {
                return List.of();
            }
            return List.of(where + " still holds " + ids + " of the scenario's connection id(s) and " + names + " name(s)");
        }

        /** Runs one cleanup step; what it throws is recorded as the step having failed, by the step and the class */
        private static void attempt(@NotNull List<String> failed, @NotNull String step, @NotNull Step action) {
            try {
                action.run();
            } catch (Exception | AssertionError e) {
                failed.add(step + " (" + e.getClass().getSimpleName() + ")");
            }
        }

        /** One cleanup step */
        private interface Step {
            void run() throws Exception;
        }
    }

    /** A provider that counts the credentials it was asked for and otherwise is the production one */
    private static final class CountingProvider implements ServerManagedCredentials.Provider {
        final AtomicInteger supplied = new AtomicInteger();
        private final ServerManagedCredentials.Provider delegate;

        CountingProvider(@NotNull ServerManagedCredentials.Provider delegate) {
            this.delegate = delegate;
        }

        @Override
        public boolean governs(@NotNull DBPDataSourceContainer container) {
            return delegate.governs(container);
        }

        @Override
        public void supplyReadCredential(
            @NotNull DBPDataSourceContainer container,
            @NotNull DBPConnectionConfiguration connectTimeCopy,
            boolean clientCredentialsPresent,
            boolean explicitConnect
        ) {
            supplied.incrementAndGet();
            delegate.supplyReadCredential(container, connectTimeCopy, clientCredentialsPresent, explicitConnect);
        }

        @Override
        public void verifyConnected(@NotNull DBPDataSourceContainer container, @NotNull DBRProgressMonitor monitor) {
            delegate.verifyConnected(container, monitor);
        }

        @NotNull
        @Override
        public ServerManagedCredentials.Refusal refuseClientInput(@NotNull DBPDataSourceContainer container) {
            return delegate.refuseClientInput(container);
        }

        @NotNull
        @Override
        public ServerManagedCredentials.Refusal connectFailed(@NotNull DBPDataSourceContainer container, @NotNull Throwable failure) {
            return delegate.connectFailed(container, failure);
        }
    }

    /** The production provider, except for the failures a test injects */
    private static final class FaultingProvider implements ServerManagedCredentials.Provider {
        /** Thrown right after the identity check */
        @Nullable
        volatile Throwable failure;
        /** Thrown while the credential is supplied, inside the platform's connect, before it is in the copy */
        @Nullable
        volatile Throwable supplyFailure;
        /** Thrown while the credential is supplied, inside the platform's connect, once it is in the copy */
        @Nullable
        volatile Throwable postSupplyFailure;
        /** Thrown in order, one by each handling of a failure, before the production handling */
        final Queue<Throwable> failureHandling = new ConcurrentLinkedQueue<>();
        /** The connect-time copy the credential was last supplied into */
        @Nullable
        volatile DBPConnectionConfiguration suppliedCopy;
        /** Whether that copy held the user and the password when {@link #postSupplyFailure} was thrown */
        volatile boolean suppliedBeforeFailure;
        private final ServerManagedCredentials.Provider delegate;

        FaultingProvider(@NotNull ServerManagedCredentials.Provider delegate) {
            this.delegate = delegate;
        }

        @Override
        public boolean governs(@NotNull DBPDataSourceContainer container) {
            return delegate.governs(container);
        }

        @Override
        public void supplyReadCredential(
            @NotNull DBPDataSourceContainer container,
            @NotNull DBPConnectionConfiguration connectTimeCopy,
            boolean clientCredentialsPresent,
            boolean explicitConnect
        ) {
            throwIfSet(supplyFailure);
            delegate.supplyReadCredential(container, connectTimeCopy, clientCredentialsPresent, explicitConnect);
            suppliedCopy = connectTimeCopy;
            Throwable injected = postSupplyFailure;
            if (injected != null) {
                suppliedBeforeFailure = connectTimeCopy.getUserName() != null && connectTimeCopy.getUserPassword() != null;
                throwIfSet(injected);
            }
        }

        @Override
        public void verifyConnected(@NotNull DBPDataSourceContainer container, @NotNull DBRProgressMonitor monitor) {
            delegate.verifyConnected(container, monitor);
            throwIfSet(failure);
        }

        private static void throwIfSet(@Nullable Throwable injected) {
            if (injected instanceof RuntimeException runtimeException) {
                throw runtimeException;
            }
            if (injected instanceof Error error) {
                throw error;
            }
        }

        @NotNull
        @Override
        public ServerManagedCredentials.Refusal refuseClientInput(@NotNull DBPDataSourceContainer container) {
            return delegate.refuseClientInput(container);
        }

        @NotNull
        @Override
        public ServerManagedCredentials.Refusal connectFailed(@NotNull DBPDataSourceContainer container, @NotNull Throwable failure) {
            throwIfSet(failureHandling.poll());
            return delegate.connectFailed(container, failure);
        }
    }

    /** The running server, except for what a test sets */
    private static final class TestDeployment implements ProtectedConnectionCredentials.Deployment {
        private final ProtectedConnectionCredentials.Deployment server = ProtectedConnectionCredentials.SERVER_DEPLOYMENT;
        volatile boolean configurationMode;
        volatile boolean environmentVariablesAccessible;
        /** Every question about the deployment fails */
        volatile boolean unreadable;
        @Nullable
        volatile String globalProjectId;

        @Override
        public boolean customConnectionsEnabled() {
            failIfUnreadable();
            return server.customConnectionsEnabled();
        }

        @Override
        public boolean configurationMode() {
            failIfUnreadable();
            return configurationMode || server.configurationMode();
        }

        @Override
        public boolean environmentVariablesAccessible() {
            failIfUnreadable();
            return environmentVariablesAccessible || server.environmentVariablesAccessible();
        }

        @NotNull
        @Override
        public String globalProjectId() {
            failIfUnreadable();
            String id = globalProjectId;
            return id != null ? id : server.globalProjectId();
        }

        private void failIfUnreadable() {
            if (unreadable) {
                throw new IllegalStateException("deployment unreadable");
            }
        }
    }

    @NotNull
    private static ProtectedConnectionCredentials.Deployment deployment(boolean configurationMode, @Nullable String globalProjectId) {
        TestDeployment deployment = new TestDeployment();
        deployment.configurationMode = configurationMode;
        deployment.globalProjectId = globalProjectId;
        return deployment;
    }

    @NotNull
    private static CBAppConfig appConfig() {
        return CEAppStarter.getTestApp().getAppConfiguration();
    }

    // ---------------------------------------------------------------- connect attempts

    /** One initConnection: what came back, whether it connected and what the provider logged */
    private record Attempt(@NotNull String body, boolean connected, @NotNull List<Entry> logged) {
        boolean refused() {
            return ServerManagedCredentialTest.refused(body);
        }

        boolean detail(@NotNull String code) {
            return detailLogged(logged, code);
        }

        @NotNull
        String describe() {
            return summary(body) + (connected ? " CONNECTED" : "") + " logged=" + logged.stream()
                .map(Entry::message).filter(m -> m.startsWith(LOG_PREFIX)).map(ServerManagedCredentialTest::detailOf).toList();
        }
    }

    @NotNull
    private static Attempt attempt(@NotNull Scenario s, @NotNull Conn connection, @NotNull Map<String, Object> extra) throws Exception {
        String body;
        List<Entry> logged;
        try (LogRecorder log = new LogRecorder(null)) {
            body = init(s.user(), connection, extra);
            logged = log.entries();
        }
        boolean connected = isConnected(s.user(), connection);
        s.observe();
        if (connected) {
            closeQuietly(s.user(), connection);
        }
        return new Attempt(body, connected, logged);
    }

    @NotNull
    private static String init(@NotNull Subject subject, @NotNull Conn connection, @NotNull Map<String, Object> extra) throws Exception {
        Map<String, Object> variables = new LinkedHashMap<>();
        variables.put("id", connection.id());
        variables.put("projectId", GLOBAL_PROJECT);
        variables.putAll(extra);
        return raw(subject.client(), GQL_INIT_CONNECTION, variables);
    }

    private static void closeQuietly(@NotNull Subject subject, @NotNull Conn connection) {
        try {
            subject.client().sendQuery(GQL_CLOSE_CONNECTION, Map.of("id", connection.id(), "projectId", GLOBAL_PROJECT));
        } catch (Exception ignored) {
            // Not connected.
        }
    }

    @NotNull
    private static Map<String, Object> info(@NotNull Conn connection) {
        return Map.of("projectId", GLOBAL_PROJECT, "id", connection.id());
    }

    @NotNull
    private static Map<String, Object> endpointConfig() {
        String[] parts = EnforcementTestSupport.urlParts();
        Map<String, Object> config = new LinkedHashMap<>();
        config.put("driverId", DRIVER_ID);
        config.put("configurationType", "MANUAL");
        config.put("host", parts[0]);
        config.put("port", parts[1]);
        config.put("databaseName", parts[2]);
        return config;
    }

    @NotNull
    private static Map<String, Object> credentials(@NotNull Role role) {
        return Map.of("userName", role.name(), "userPassword", role.password());
    }

    /** The session's entry for the connection, loaded the way initConnection loads it */
    @Nullable
    private static WebConnectionInfo connectionInfo(@NotNull WebSession session, @NotNull Conn connection) {
        WebSessionProjectImpl project = session.getProjectById(GLOBAL_PROJECT);
        if (project == null) {
            return null;
        }
        try {
            return project.getWebConnectionInfo(connection.id());
        } catch (DBWebException e) {
            return null;
        }
    }

    @NotNull
    private static DBPDataSourceContainer container(@NotNull Subject subject, @NotNull Conn connection) {
        WebConnectionInfo info = connectionInfo(subject.session(), connection);
        if (info == null) {
            throw new IllegalStateException("FIXTURE: the user's session has no entry for the connection");
        }
        return info.getDataSourceContainer();
    }

    /**
     * The connection's navigator path in a session
     * <p>
     * createConnection answers before the session's navigator holds the new connection, so its nodePath is empty;
     * reading the project's connections, as the navigator tree does, creates the node.
     */
    @NotNull
    private static String nodePath(@NotNull Subject subject, @NotNull Conn connection) throws Exception {
        WebSessionProjectImpl project = subject.session().getProjectById(GLOBAL_PROJECT);
        DBPDataSourceContainer container = project == null ? null : project.getDataSourceRegistry().getDataSource(connection.id());
        DBNModel model = subject.session().getNavigatorModelOrThrow();
        DBNProject projectNode = project == null ? null : model.getRoot().getProjectNode(project);
        if (projectNode != null) {
            projectNode.getDatabases().getChildren(MONITOR);
        }
        DBNDatabaseNode node = container == null ? null : model.getNodeByObject(container);
        if (node == null) {
            throw new IllegalStateException("FIXTURE: the session's navigator has no node for the connection");
        }
        return node.getNodeUri();
    }

    private static boolean isConnected(@NotNull Subject subject, @NotNull Conn connection) {
        WebConnectionInfo info = connectionInfo(subject.session(), connection);
        return info != null && info.getDataSourceContainer().isConnected();
    }

    private static boolean refusalIn(@NotNull Throwable error) {
        int depth = 0;
        for (Throwable t = error; t != null && depth < 20; t = t.getCause(), depth++) {
            if (t instanceof ServerManagedCredentials.Refusal) {
                return true;
            }
        }
        return false;
    }

    // ---------------------------------------------------------------- PostgreSQL

    private static int backends(@NotNull Role role) throws Exception {
        try (Connection raw = EnforcementTestSupport.openRawPostgres(MONITOR);
             PreparedStatement dbStat = raw.prepareStatement("SELECT COUNT(*) FROM pg_stat_activity WHERE usename = ?")) {
            dbStat.setString(1, role.name());
            try (ResultSet dbResult = dbStat.executeQuery()) {
                dbResult.next();
                return dbResult.getInt(1);
            }
        }
    }

    private static boolean awaitNoBackends(@NotNull Role role) throws Exception {
        long deadline = System.nanoTime() + BACKEND_WAIT.toNanos();
        while (System.nanoTime() < deadline) {
            if (backends(role) == 0) {
                return true;
            }
            Thread.sleep(50);
        }
        return false;
    }

    private static void dropRole(@NotNull Role role) throws Exception {
        try (Connection raw = EnforcementTestSupport.openRawPostgres(MONITOR)) {
            try (PreparedStatement dbStat = raw.prepareStatement(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = ?")) {
                dbStat.setString(1, role.name());
                dbStat.execute();
            }
            awaitNoBackends(role);
            EnforcementTestSupport.execute(raw, "DROP ROLE IF EXISTS " + role.name());
        }
    }

    // ---------------------------------------------------------------- GraphQL bodies

    /** Posts a GraphQL request in the client's session and returns the whole response body, errors included */
    @NotNull
    private static String raw(
        @NotNull WebGQLClient client,
        @NotNull String query,
        @NotNull Map<String, Object> variables
    ) throws Exception {
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("query", query);
        request.put("variables", variables);
        HttpRequest httpRequest = HttpRequest.newBuilder(URI.create(CEAppStarter.SERVER_URL + "/api/gql"))
            .POST(HttpRequest.BodyPublishers.ofString(json(request)))
            .header("Content-Type", "application/json")
            .header("TE-Client-Version", GeneralUtils.getMajorVersion())
            .header("Cookie", CBConstants.CB_SESSION_COOKIE_NAME + "=" + client.getSessionIdCookie())
            .build();
        return HttpClient.newHttpClient().send(httpRequest, HttpResponse.BodyHandlers.ofString()).body();
    }

    private static boolean succeeded(@NotNull String body) {
        return !body.contains("\"errors\"") && body.contains("\"data\"");
    }

    /** Refused means: an error, and the fixed refusal as its only message */
    private static boolean refused(@NotNull String body) {
        return body.contains("\"errors\"") && messages(body).equals(List.of(REFUSAL));
    }

    @NotNull
    private static List<String> messages(@NotNull String body) {
        List<String> messages = new ArrayList<>();
        Matcher matcher = MESSAGE.matcher(body);
        while (matcher.find()) {
            messages.add(unescape(matcher.group(1)));
        }
        return messages;
    }

    @Nullable
    private static Boolean authNeeded(@NotNull String body) {
        Matcher matcher = AUTH_NEEDED.matcher(body);
        return matcher.find() ? Boolean.valueOf(matcher.group(1)) : null;
    }

    /** "ok" or the messages of the errors - redacted by the caller before it is shown */
    @NotNull
    private static String summary(@NotNull String body) {
        return succeeded(body) ? "ok" : "errors " + messages(body);
    }

    @NotNull
    private static String unescape(@NotNull String text) {
        return text.replace("\\n", "\n").replace("\\\"", "\"").replace("\\\\", "\\");
    }

    @NotNull
    private static String json(@Nullable Object value) {
        if (value == null) {
            return "null";
        }
        if (value instanceof Boolean || value instanceof Number) {
            return value.toString();
        }
        if (value instanceof Map<?, ?> map) {
            StringBuilder text = new StringBuilder("{");
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (text.length() > 1) {
                    text.append(',');
                }
                text.append(json(String.valueOf(entry.getKey()))).append(':').append(json(entry.getValue()));
            }
            return text.append('}').toString();
        }
        if (value instanceof Collection<?> collection) {
            StringBuilder text = new StringBuilder("[");
            for (Object item : collection) {
                if (text.length() > 1) {
                    text.append(',');
                }
                text.append(json(item));
            }
            return text.append(']').toString();
        }
        StringBuilder text = new StringBuilder("\"");
        for (char c : value.toString().toCharArray()) {
            switch (c) {
                case '"' -> text.append("\\\"");
                case '\\' -> text.append("\\\\");
                case '\n' -> text.append("\\n");
                case '\r' -> text.append("\\r");
                case '\t' -> text.append("\\t");
                default -> {
                    if (c < 0x20) {
                        text.append(String.format("\\u%04x", (int) c));
                    } else {
                        text.append(c);
                    }
                }
            }
        }
        return text.append('"').toString();
    }

    // ---------------------------------------------------------------- what the class leaves behind

    /** Where the connections the scenarios created still show in a text, by count - never by name or id */
    @NotNull
    private static List<String> fixtureConnections(@NotNull String where, @NotNull String text) {
        int named = 0;
        Matcher matcher = CONNECTION_NAME.matcher(text);
        while (matcher.find()) {
            named++;
        }
        long created = CREATED_CONNECTIONS.stream().filter(text::contains).count();
        if (named == 0 && created == 0) {
            return List.of();
        }
        return List.of(where + " holds " + named + " connection(s) named '" + CONNECTION_PREFIX.trim() + " ...' and "
            + created + " id(s) the scenarios created");
    }

    /** The labels of the class's markers and of the fixture value shapes that occur in a text, JSON escapes undone */
    @NotNull
    private static Set<String> fixtureValuesIn(@NotNull String text) {
        String unescaped = UNICODE_ESCAPE.matcher(text).replaceAll(m -> String.valueOf((char) Integer.parseInt(m.group(1), 16)));
        Set<String> labels = new TreeSet<>();
        for (String candidate : List.of(text, unescaped)) {
            CLASS_MARKERS.forEach((value, label) -> {
                if (!value.isEmpty() && candidate.contains(value)) {
                    labels.add(label);
                }
            });
            FIXTURE_VALUES.forEach((label, shape) -> {
                if (shape.matcher(candidate).find()) {
                    labels.add(label);
                }
            });
        }
        return labels;
    }

    /** The data source configuration files of a project */
    @NotNull
    private static List<Path> dataSourceConfigurations(@NotNull Path projectFolder) throws IOException {
        Path metadata = projectFolder.resolve(".dbeaver");
        if (!Files.isDirectory(metadata)) {
            return List.of();
        }
        try (Stream<Path> files = Files.list(metadata)) {
            return files.filter(f -> f.getFileName().toString().matches("data-sources.*\\.json")).sorted().toList();
        }
    }

    /** Every workspace file, path and content, that holds a value the scenarios made - encrypted stores read as they are */
    @NotNull
    private static List<String> leftInWorkspace(@NotNull Path workspace) throws IOException {
        List<String> found = new ArrayList<>();
        try (Stream<Path> files = Files.walk(workspace)) {
            for (Path file : files.filter(Files::isRegularFile).toList()) {
                if (Files.size(file) > 4 * 1024 * 1024) {
                    found.add("an unscanned file larger than 4 MB: " + workspace.relativize(file));
                    continue;
                }
                String text = workspace.relativize(file) + "\n" + new String(Files.readAllBytes(file), StandardCharsets.ISO_8859_1);
                for (String label : fixtureValuesIn(text)) {
                    found.add(label + " in " + workspace.relativize(file));
                }
            }
        }
        return found;
    }

    /** The scenarios' PostgreSQL roles, databases and backends that are still there, by count */
    @NotNull
    private static List<String> postgresLeftovers() throws Exception {
        String roles = "rolname LIKE 'dbac\\_p0\\_%' OR rolname LIKE 'dbac\\_s4b%'";
        Map<String, String> checks = new LinkedHashMap<>();
        checks.put("PostgreSQL role(s)", "SELECT COUNT(*) FROM pg_roles WHERE " + roles);
        checks.put("PostgreSQL database(s)",
            "SELECT COUNT(*) FROM pg_database WHERE datname LIKE 'dbac\\_p0%' OR datname LIKE 'dbac\\_s4b%'");
        checks.put("PostgreSQL backend(s)", "SELECT COUNT(*) FROM pg_stat_activity WHERE " + roles.replace("rolname", "usename"));
        List<String> left = new ArrayList<>();
        try (Connection raw = EnforcementTestSupport.openRawPostgres(MONITOR)) {
            for (Map.Entry<String, String> check : checks.entrySet()) {
                try (PreparedStatement dbStat = raw.prepareStatement(check.getValue()); ResultSet dbResult = dbStat.executeQuery()) {
                    dbResult.next();
                    if (dbResult.getInt(1) != 0) {
                        left.add(dbResult.getInt(1) + " " + check.getKey());
                    }
                }
            }
        }
        return left;
    }

    /** Whether each encrypted credential store exists, and its size - never its content */
    @NotNull
    private static String encryptedStores() {
        Path folder = globalProjectFolder;
        if (folder == null || folder.getParent() == null) {
            return "unknown";
        }
        List<String> sizes = new ArrayList<>();
        for (Path store : List.of(
            folder.resolve(".dbeaver").resolve("credentials-config.json"),
            folder.getParent().resolve(".data").resolve(".database-credentials.dat")
        )) {
            String size;
            try {
                size = Files.exists(store) ? Files.size(store) + " bytes" : "absent";
            } catch (IOException e) {
                size = "unreadable";
            }
            sizes.add(store.getFileName() + " " + size);
        }
        return String.join(", ", sizes);
    }

    /** Ends a session's login; the session can no longer act for the user */
    private static void logout(@NotNull Subject subject) throws Exception {
        subject.client().sendQuery(GQL_LOGOUT, Map.of("provider", LocalAuthProvider.PROVIDER_ID));
    }

    // ---------------------------------------------------------------- markers

    /** The labels of the markers that occur in the text - never the values */
    @NotNull
    private static List<String> leaked(@Nullable String text, @NotNull Map<String, String> markers) {
        List<String> labels = new ArrayList<>();
        if (text != null) {
            for (Map.Entry<String, String> marker : markers.entrySet()) {
                if (!marker.getValue().isEmpty() && text.contains(marker.getValue())) {
                    labels.add(marker.getKey());
                }
            }
        }
        return labels;
    }

    /** The labels of the markers a configuration holds as user, password, auth property or driver property */
    @NotNull
    private static List<String> heldBy(@Nullable DBPConnectionConfiguration configuration, @NotNull Map<String, String> markers) {
        if (configuration == null) {
            return List.of();
        }
        StringBuilder text = new StringBuilder();
        text.append(configuration.getUserName()).append('\n').append(configuration.getUserPassword()).append('\n');
        Map<String, String> authProperties = configuration.getAuthProperties();
        if (authProperties != null) {
            authProperties.forEach((k, v) -> text.append(k).append('=').append(v).append('\n'));
        }
        configuration.getProperties().forEach((k, v) -> text.append(k).append('=').append(v).append('\n'));
        return leaked(text.toString(), markers);
    }

    @NotNull
    private static List<String> leakedInFiles(@Nullable Path root, @NotNull Map<String, String> markers) throws Exception {
        if (root == null || !Files.isDirectory(root)) {
            Assertions.fail("FIXTURE: the global project has no folder to inspect");
        }
        List<String> found = new ArrayList<>();
        try (Stream<Path> files = Files.walk(root, 4)) {
            for (Path file : files.filter(Files::isRegularFile).toList()) {
                if (Files.size(file) > 4 * 1024 * 1024) {
                    continue;
                }
                String content = new String(Files.readAllBytes(file), StandardCharsets.ISO_8859_1);
                for (String label : leaked(content, markers)) {
                    found.add(label + " in " + root.relativize(file));
                }
            }
        }
        return found;
    }

    @NotNull
    private static List<String> leakedInLogs(@NotNull List<Entry> logged, @NotNull Map<String, String> markers) {
        List<String> found = new ArrayList<>();
        for (Entry entry : logged) {
            for (String label : leaked(entry.message() + "\n" + entry.throwable(), markers)) {
                if (!found.contains(label)) {
                    found.add(label);
                }
            }
        }
        return found;
    }

    private static boolean detailLogged(@NotNull List<Entry> logged, @NotNull String code) {
        return logged.stream().map(Entry::message)
            .anyMatch(m -> m.startsWith(LOG_PREFIX) && m.contains("detail=" + code));
    }

    @NotNull
    private static String detailOf(@NotNull String message) {
        int start = message.indexOf("detail=");
        if (start < 0) {
            return "?";
        }
        int end = message.indexOf(' ', start);
        return message.substring(start + "detail=".length(), end < 0 ? message.length() : end);
    }

    // ---------------------------------------------------------------- logs

    /** One call the platform log received, with the throwable as printed text */
    private record Entry(@NotNull String message, @Nullable String throwable) {
    }

    /**
     * Records every message the platform log receives, from every thread, while it is open
     * <p>
     * The server logs through {@link Log}'s handler, and a GraphQL request runs on a server thread, so the caller
     * thread's writer and listeners do not see it. This replaces the handler and puts the server's own back when it
     * is closed. Every call still reaches the server's handler. With a prefix, a message that starts with it fails
     * instead of being written - a log that is broken for exactly the lines under test.
     */
    private static final class LogRecorder implements AutoCloseable {
        private final List<Entry> entries = Collections.synchronizedList(new ArrayList<>());
        private final AtomicInteger failures = new AtomicInteger();

        LogRecorder(@Nullable String failPrefix) {
            LogHandler server = new SLF4JLogHandler();
            InvocationHandler recorder = (proxy, method, args) -> {
                if (method.getDeclaringClass() == Object.class) {
                    return method.invoke(server, args);
                }
                if (method.getReturnType() == boolean.class) {
                    return true;
                }
                if (method.getReturnType() == void.class && args != null && args.length >= 2) {
                    String message = String.valueOf(args[1]);
                    String throwable = null;
                    if (args.length >= 3 && args[2] instanceof Throwable t) {
                        StringWriter text = new StringWriter();
                        t.printStackTrace(new PrintWriter(text, true));
                        throwable = text.toString();
                    }
                    entries.add(new Entry(message, throwable));
                    if (failPrefix != null && message.startsWith(failPrefix)) {
                        failures.incrementAndGet();
                        throw new IllegalStateException("injected log failure");
                    }
                }
                try {
                    return method.invoke(server, args);
                } catch (InvocationTargetException e) {
                    throw e.getCause();
                }
            };
            Log.setLogHandler((LogHandler) Proxy.newProxyInstance(
                LogHandler.class.getClassLoader(), new Class<?>[]{LogHandler.class}, recorder));
        }

        @NotNull
        List<Entry> entries() {
            synchronized (entries) {
                return new ArrayList<>(entries);
            }
        }

        int failures() {
            return failures.get();
        }

        @Override
        public void close() {
            Log.setLogHandler(new SLF4JLogHandler());
        }
    }
}
