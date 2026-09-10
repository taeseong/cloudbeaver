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

import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.jkiss.dbeaver.model.DBPDataSourceContainer;
import org.jkiss.dbeaver.model.app.DBPDataSourceRegistry;
import org.jkiss.dbeaver.model.app.DBPProject;
import org.jkiss.dbeaver.model.connection.DBPConnectionConfiguration;
import org.jkiss.dbeaver.model.connection.DBPDriver;
import org.jkiss.dbeaver.model.connection.DBPDriverConfigurationType;
import org.jkiss.dbeaver.model.connection.DBPDriverSubstitutionDescriptor;
import org.jkiss.dbeaver.model.net.DBWHandlerConfiguration;
import org.jkiss.dbeaver.model.net.DBWHandlerDescriptor;
import org.jkiss.dbeaver.model.net.DBWHandlerType;
import org.jkiss.utils.CommonUtils;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Fixtures for the write-authorization decision tests
 * <p>
 * The container, its project, its registry and its driver are dynamic proxies rather than real
 * objects. Building a real {@code DataSourceDescriptor} would drag a registry, a project file and a
 * driver descriptor into a unit test and would make it hard to express the cases that matter here -
 * a container the registry no longer holds, a project with no id, a driver from the wrong provider.
 * The proxies answer only the handful of methods the policy code calls and throw for everything
 * else, so a test cannot pass by accident if the production code starts reading something new.
 */
final class PolicyTestSupport {

    /**
     * Planted in every credential-bearing field of the fixture configuration
     * <p>
     * A fingerprint, an audit payload or a log line that contains this string has read something it
     * must not. Asserting on one sentinel is stronger than asserting field by field, because a field
     * added later is covered without anyone remembering to extend the assertion.
     */
    static final String SECRET_SENTINEL = "dbac-must-never-appear-4f2a91";

    /**
     * A secret planted in a network handler, which the policy code must not read either
     */
    static final String HANDLER_SECRET_SENTINEL = "dbac-handler-secret-8b17c3";

    private PolicyTestSupport() {
    }

    // ---------------------------------------------------------------- containers

    /**
     * A container whose registry agrees it is the current one
     * <p>
     * The default shape is a fully supported endpoint: {@code postgresql:postgres-jdbc}, MANUAL
     * configuration, explicit port 5432, no network handlers, no config profile, no driver
     * substitution. Every test that needs an unsupported endpoint asks for it explicitly, so a
     * reader can see which single property is under test.
     */
    @NotNull
    static DBPDataSourceContainer container(
        @NotNull String projectId,
        @NotNull String connectionId,
        @Nullable String host,
        @Nullable String database
    ) {
        return new ContainerBuilder(projectId, connectionId).host(host).database(database).build();
    }

    @NotNull
    static ContainerBuilder builder(@NotNull String projectId, @NotNull String connectionId) {
        return new ContainerBuilder(projectId, connectionId);
    }

    /**
     * Assembles a proxied container
     * <p>
     * Every deviation a test needs is a method here rather than a boolean parameter, so a test reads
     * as what it is testing.
     */
    static final class ContainerBuilder {
        private final String projectId;
        private final String connectionId;
        private String providerId = "postgresql";
        private String driverId = "postgres-jdbc";
        private boolean customDriver;
        private String host = "db.internal.example";
        private String port = "5432";
        private String database = "customer_prod";
        private String serverName;
        private String url;
        private DBPDriverConfigurationType configurationType = DBPDriverConfigurationType.MANUAL;
        private String configProfileName;
        private String configProfileSource;
        private boolean substitutedDriver;
        private final List<DBWHandlerConfiguration> handlers = new ArrayList<>();
        private final Map<String, String> properties = new LinkedHashMap<>();
        private final Map<String, String> providerProperties = new LinkedHashMap<>();
        private String liveHost;
        private String livePort;
        private String liveDatabase;
        private boolean connected;
        private boolean separateActual;
        private String authModelId;
        private boolean registryAgrees = true;
        private boolean projectPresent = true;
        private boolean registryPresent = true;
        private boolean driverPresent = true;
        private boolean registryThrows;
        private boolean identityThrows;
        private boolean driverThrows;
        private String sampleUrl = "jdbc:{provider}://{host}[:{port}]/[{database}]";
        private boolean sampleUrlThrows;
        private boolean sampleUrlErrors;
        private boolean generatedUrlIsNull;
        private boolean generatedUrlThrows;
        private boolean configurationThrows;

        private ContainerBuilder(@NotNull String projectId, @NotNull String connectionId) {
            this.projectId = projectId;
            this.connectionId = connectionId;
        }

        @NotNull
        ContainerBuilder driver(@NotNull String providerId, @NotNull String driverId) {
            this.providerId = providerId;
            this.driverId = driverId;
            return this;
        }

        @NotNull
        ContainerBuilder customDriver() {
            this.customDriver = true;
            return this;
        }

        @NotNull
        ContainerBuilder host(@Nullable String host) {
            this.host = host;
            return this;
        }

        /** The one field the original snapshot left out, which is why the bypass existed. */
        @NotNull
        ContainerBuilder port(@Nullable String port) {
            this.port = port;
            return this;
        }

        @NotNull
        ContainerBuilder serverName(@Nullable String serverName) {
            this.serverName = serverName;
            return this;
        }

        /**
         * A connection that is open against an endpoint other than the one now stored
         * <p>
         * This is not a contrivance. CloudBeaver edits a connection's stored configuration in place
         * and does not disconnect it, and the platform keeps the configuration it connected with
         * until disconnect. So "stored says one thing, the live socket goes somewhere else" is a
         * reachable state, and it is the state a stored-only fingerprint cannot see.
         */
        @NotNull
        ContainerBuilder connectedAt(
            @Nullable String liveHost,
            @Nullable String livePort,
            @Nullable String liveDatabase
        ) {
            this.connected = true;
            this.separateActual = true;
            this.liveHost = liveHost;
            this.livePort = livePort;
            this.liveDatabase = liveDatabase;
            return this;
        }

        /**
         * A closed connection that still carries the copy a failed attempt left behind
         * <p>
         * {@code isConnected()} is false and yet the platform reports a separate configuration, so
         * this is the state that breaks the tempting assumption "closed means the two are the same
         * object". Reached by any connection attempt that threw.
         */
        @NotNull
        ContainerBuilder failedAttemptAt(
            @Nullable String liveHost,
            @Nullable String livePort,
            @Nullable String liveDatabase
        ) {
            this.connected = false;
            this.separateActual = true;
            this.liveHost = liveHost;
            this.livePort = livePort;
            this.liveDatabase = liveDatabase;
            return this;
        }

        /**
         * An authentication model other than the native one
         * <p>
         * An auth model is asked for a complete connection URL before the configuration type is
         * consulted, so one that answers decides the endpoint.
         */
        @NotNull
        ContainerBuilder authModel(@Nullable String authModelId) {
            this.authModelId = authModelId;
            return this;
        }

        /**
         * A URL-mode connection
         * <p>
         * Host, port and database are left exactly as they are rather than cleared, because that is
         * what CloudBeaver does: {@code WebDataSourceUtils.setMainProperties} returns early once a
         * url is present, so their previous values survive as stale leftovers.
         */
        @NotNull
        ContainerBuilder urlMode(@Nullable String url) {
            this.configurationType = DBPDriverConfigurationType.URL;
            this.url = url;
            return this;
        }

        /**
         * A generated URL alongside MANUAL mode
         * <p>
         * This is the ordinary state of a MANUAL connection, not an anomaly: both the desktop UI and
         * CloudBeaver store a driver-generated url on save. A test uses this to prove that the
         * presence of a url is not what decides the mode.
         */
        @NotNull
        ContainerBuilder generatedUrl(@Nullable String url) {
            this.url = url;
            return this;
        }

        @NotNull
        ContainerBuilder configurationType(@Nullable DBPDriverConfigurationType type) {
            this.configurationType = type;
            return this;
        }

        /**
         * An enabled or disabled network handler
         * <p>
         * Built on a proxied {@link DBWHandlerDescriptor} because the real
         * {@code DBWHandlerConfiguration} resolves its descriptor through
         * {@code DBWorkbench.getPlatform()} when it has none, which a unit test has no business
         * reaching. Only {@code getId()} and {@code isEnabled()} are plain fields; anything the
         * policy code reads beyond those two would go through this descriptor and be visible here.
         */
        @NotNull
        ContainerBuilder handler(
            @NotNull String id,
            @NotNull DBWHandlerType type,
            boolean enabled,
            @NotNull Map<String, String> handlerProperties
        ) {
            DBWHandlerDescriptor descriptor = proxy(DBWHandlerDescriptor.class, (p, m, a) -> switch (m.getName()) {
                case "getId" -> id;
                case "getType" -> type;
                case "isSecured" -> false;
                case "getLabel" -> id;
                case "toString" -> "handlerDescriptor:" + id;
                case "hashCode" -> System.identityHashCode(p);
                case "equals" -> p == a[0];
                default -> throw new UnsupportedOperationException("handlerDescriptor." + m.getName());
            });
            DBWHandlerConfiguration handler = new DBWHandlerConfiguration(descriptor, null);
            handler.setEnabled(enabled);
            handlerProperties.forEach(handler::setProperty);
            handler.setPassword(HANDLER_SECRET_SENTINEL);
            handler.setSecureProperty("privateKey", HANDLER_SECRET_SENTINEL);
            this.handlers.add(handler);
            return this;
        }

        /** A config profile, which can inject handlers that the stored handler list does not show. */
        @NotNull
        ContainerBuilder configProfile(@Nullable String source, @Nullable String name) {
            this.configProfileSource = source;
            this.configProfileName = name;
            return this;
        }

        @NotNull
        ContainerBuilder substitutedDriver() {
            this.substitutedDriver = true;
            return this;
        }

        /**
         * A stored driver property
         * <p>
         * The value may be null: {@code setProperty} does a plain {@code put}, so a null value still
         * leaves the key in the map - and the key alone is what decides eligibility.
         */
        @NotNull
        ContainerBuilder property(@NotNull String key, @Nullable String value) {
            this.properties.put(key, value);
            return this;
        }

        @NotNull
        ContainerBuilder providerProperty(@NotNull String key, @Nullable String value) {
            this.providerProperties.put(key, value);
            return this;
        }

        /**
         * A secret in a property value, for the tests that check nothing reads one
         * <p>
         * Such a connection is refused - the keys are not allowlisted - which is the point: the
         * assertion is that the refusal carries no trace of the value. Kept out of the default
         * fixture so that the ordinary case stays ordinary.
         */
        @NotNull
        ContainerBuilder secretInPropertyValues() {
            this.properties.put("password", SECRET_SENTINEL);
            this.providerProperties.put("PvtKeyPath", SECRET_SENTINEL);
            return this;
        }

        @NotNull
        ContainerBuilder database(@Nullable String database) {
            this.database = database;
            return this;
        }

        /** The registry returns a different object for this id - a connection replaced underneath. */
        @NotNull
        ContainerBuilder registryHoldsSomethingElse() {
            this.registryAgrees = false;
            return this;
        }

        @NotNull
        ContainerBuilder withoutProject() {
            this.projectPresent = false;
            return this;
        }

        @NotNull
        ContainerBuilder withoutRegistry() {
            this.registryPresent = false;
            return this;
        }

        /**
         * The driver's URL template, which the endpoint gate requires before comparing anything
         * <p>
         * Pass null, "" or whitespace to reach the refusal; pass a real template to leave the gate
         * satisfied so a test can refuse somewhere else.
         */
        @NotNull
        ContainerBuilder sampleUrl(@Nullable String sampleUrl) {
            this.sampleUrl = sampleUrl;
            return this;
        }

        /** The sample URL accessor throws a RuntimeException. */
        @NotNull
        ContainerBuilder sampleUrlFails() {
            this.sampleUrlThrows = true;
            return this;
        }

        /**
         * The sample URL accessor throws an Error
         * <p>
         * Separate from {@link #sampleUrlFails()} because the two are handled in different places:
         * a RuntimeException is refused by the endpoint gate as ENDPOINT_UNSUPPORTED, while an Error
         * is left to the service's outer handler, which keeps the key and denies. Both are denials
         * and neither escapes, which is the contract worth pinning.
         */
        @NotNull
        ContainerBuilder sampleUrlErrors() {
            this.sampleUrlErrors = true;
            return this;
        }

        /** {@code getConnectionURL} answers null, so nothing can be compared against. */
        @NotNull
        ContainerBuilder generatedUrlIsNull() {
            this.generatedUrlIsNull = true;
            return this;
        }

        /** {@code getConnectionURL} throws, so nothing can be compared against. */
        @NotNull
        ContainerBuilder generatedUrlFails() {
            this.generatedUrlThrows = true;
            return this;
        }

        @NotNull
        ContainerBuilder withoutDriver() {
            this.driverPresent = false;
            return this;
        }

        /** The registry blows up, as one being disposed can. */
        @NotNull
        ContainerBuilder registryFails() {
            this.registryThrows = true;
            return this;
        }

        /**
         * {@code getId()} throws, which happens before a key can be established
         */
        @NotNull
        ContainerBuilder identityFails() {
            this.identityThrows = true;
            return this;
        }

        /**
         * {@code getDriver()} throws, which happens after a key has been established
         * <p>
         * The resolver never asks for the driver, so a key already exists by the time the driver
         * allowlist is consulted. That makes this the shape of an unexpected failure that is worth
         * attributing to a subject.
         */
        @NotNull
        ContainerBuilder driverFails() {
            this.driverThrows = true;
            return this;
        }

        /**
         * {@code getConnectionConfiguration()} throws, likewise after the key exists
         */
        @NotNull
        ContainerBuilder configurationFails() {
            this.configurationThrows = true;
            return this;
        }

        @NotNull
        DBPDataSourceContainer build() {
            DBPConnectionConfiguration configuration = new DBPConnectionConfiguration();
            configuration.setHostName(host);
            configuration.setHostPort(port);
            configuration.setDatabaseName(database);
            configuration.setServerName(serverName);
            configuration.setUrl(url);
            // Assigned unconditionally, so configurationType(null) really produces a null mode.
            // Guarding on non-null left the default MANUAL in place, which meant the "mode not
            // decided" refusal had no test at all even though the production check was correct.
            configuration.setConfigurationType(configurationType);
            configuration.setConfigProfileSource(configProfileSource);
            configuration.setConfigProfileName(configProfileName);
            // updateHandler, not setHandlers. DBPConnectionConfiguration.setHandlers is a no-op
            // when the configuration's handler list is still null, which it is on a fresh instance:
            // "if (this.handlers != null) { clear(); addAll(handlers); }". A fixture built with
            // setHandlers installs nothing, so the handler tests would pass while testing nothing.
            // updateHandler creates the list when it is absent.
            for (DBWHandlerConfiguration handler : handlers) {
                configuration.updateHandler(handler);
            }
            properties.forEach(configuration::setProperty);
            providerProperties.forEach(configuration::setProviderProperty);
            // Not stripped when null: the platform keeps the key, and the key is the whole question.
            // A credential in every surface the fingerprint must never touch. Any test that reads a
            // fingerprint can therefore assert on the sentinel rather than on the absence of a field.
            // A credential in every surface the fingerprint must never touch, so a test can assert
            // on the sentinel rather than on the absence of a field.
            //
            // Deliberately NOT in the two property maps. A property key now decides eligibility, so
            // planting one there would make every fixture connection ineligible - and an ordinary
            // web-created connection stores no driver property at all, so an empty map is also the
            // truthful default. A test that wants a secret in a property value asks for it with
            // secretInPropertyValues().
            configuration.setUserName("fixture-user");
            configuration.setUserPassword(SECRET_SENTINEL);
            configuration.setAuthProperty("token", SECRET_SENTINEL);
            if (authModelId != null) {
                configuration.setAuthModelId(authModelId);
            }

            // The configuration the connection is actually open against, when the test asked for a
            // live connection whose stored settings have since moved.
            DBPConnectionConfiguration live = new DBPConnectionConfiguration(configuration);
            if (separateActual) {
                live.setHostName(liveHost);
                live.setHostPort(livePort);
                live.setDatabaseName(liveDatabase);
            }

            DBPDriver driver = driverPresent
                ? proxy(DBPDriver.class, (p, m, a) -> switch (m.getName()) {
                    case "getId" -> driverId;
                    case "getProviderId" -> providerId;
                    case "isCustom" -> customDriver;
                    case "getDefaultPort" -> "5432";
                    // The endpoint gate refuses a driver with no URL template before it compares
                    // anything, so the template has to be a fixture state of its own. The default is
                    // a non-blank stand-in for the template both supported providers declare, which
                    // keeps every other negative test refusing at the point it is named after
                    // rather than here.
                    case "getSampleURL" -> {
                        if (sampleUrlErrors) {
                            throw new AssertionError("driver sample URL accessor failed");
                        }
                        if (sampleUrlThrows) {
                            throw new IllegalStateException("driver sample URL accessor failed");
                        }
                        yield sampleUrl;
                    }
                    // Mirrors the sample-URL template both supported drivers declare,
                    // jdbc:<provider>://{host}[:{port}]/[{database}], because the gate now compares
                    // the stored url against what the driver would generate. A proxy that threw
                    // here instead would make every connection carrying a url unfingerprintable,
                    // which would hide the very difference the comparison exists to catch.
                    case "getConnectionURL" -> {
                        if (generatedUrlThrows) {
                            throw new IllegalStateException("driver URL generation failed");
                        }
                        if (generatedUrlIsNull) {
                            yield null;
                        }
                        DBPConnectionConfiguration asked = (DBPConnectionConfiguration) a[0];
                        StringBuilder built = new StringBuilder("jdbc:").append(providerId)
                            .append("://").append(CommonUtils.notEmpty(asked.getHostName()));
                        if (!CommonUtils.isEmpty(asked.getHostPort())) {
                            built.append(':').append(asked.getHostPort());
                        }
                        built.append('/').append(CommonUtils.notEmpty(asked.getDatabaseName()));
                        yield built.toString();
                    }
                    case "getFullId" -> providerId + ":" + driverId;
                    case "toString" -> "driver:" + providerId + ":" + driverId;
                    case "hashCode" -> System.identityHashCode(p);
                    case "equals" -> p == a[0];
                    default -> throw new UnsupportedOperationException("DBPDriver." + m.getName());
                })
                : null;

            // The container has to exist before the registry can point at it, so it is held in a
            // one-element array the registry handler closes over.
            DBPDataSourceContainer[] self = new DBPDataSourceContainer[1];

            DBPDataSourceRegistry registry = registryPresent
                ? proxy(DBPDataSourceRegistry.class, (p, m, a) -> switch (m.getName()) {
                    case "getDataSource" -> {
                        if (registryThrows) {
                            throw new IllegalStateException("registry disposed");
                        }
                        yield registryAgrees ? self[0] : otherContainer();
                    }
                    case "toString" -> "registry:" + projectId;
                    case "hashCode" -> System.identityHashCode(p);
                    case "equals" -> p == a[0];
                    default -> throw new UnsupportedOperationException("registry." + m.getName());
                })
                : null;

            DBPProject project = projectPresent
                ? proxy(DBPProject.class, (p, m, a) -> switch (m.getName()) {
                    case "getId" -> projectId;
                    case "getDataSourceRegistry" -> registry;
                    case "toString" -> "project:" + projectId;
                    case "hashCode" -> System.identityHashCode(p);
                    case "equals" -> p == a[0];
                    default -> throw new UnsupportedOperationException("project." + m.getName());
                })
                : null;

            self[0] = proxy(DBPDataSourceContainer.class, (p, m, a) -> switch (m.getName()) {
                case "getId" -> {
                    if (identityThrows) {
                        throw new IllegalStateException("container disposed");
                    }
                    yield connectionId;
                }
                case "getProject" -> project;
                case "getDriver" -> {
                    if (driverThrows) {
                        throw new IllegalStateException("driver registry unavailable");
                    }
                    yield driver;
                }
                case "getConnectionConfiguration" -> {
                    if (configurationThrows) {
                        throw new IllegalStateException("configuration unavailable");
                    }
                    yield configuration;
                }
                // Three states, because the platform has three. Idle and never attempted: the stored
                // configuration itself. Open: the copy taken at connect time. And closed after a
                // failed attempt: still a separate pre-attempt copy, because the failure handler
                // clears the data source without clearing that copy and disconnect returns early
                // once the data source is null. The third one is easy to overlook, which is why the
                // fixture can produce it.
                case "getActualConnectionConfiguration" -> separateActual ? live : configuration;
                case "isConnected" -> connected;
                case "getDriverSubstitution" -> substitutedDriver
                    ? proxy(DBPDriverSubstitutionDescriptor.class, (sp, sm, sa) -> switch (sm.getName()) {
                        case "getId" -> "substitute";
                        case "toString" -> "driverSubstitution";
                        case "hashCode" -> System.identityHashCode(sp);
                        case "equals" -> sp == sa[0];
                        default -> throw new UnsupportedOperationException("substitution." + sm.getName());
                    })
                    : null;
                case "toString" -> "container:" + projectId + "/" + connectionId;
                case "hashCode" -> System.identityHashCode(p);
                case "equals" -> p == a[0];
                default -> throw new UnsupportedOperationException("container." + m.getName());
            });
            return self[0];
        }
    }

    /**
     * A container that is not the one under test, for the registry-replacement case
     */
    @NotNull
    private static DBPDataSourceContainer otherContainer() {
        return proxy(DBPDataSourceContainer.class, (p, m, a) -> switch (m.getName()) {
            case "getId" -> "some-other-container";
            case "toString" -> "container:other";
            case "hashCode" -> System.identityHashCode(p);
            case "equals" -> p == a[0];
            default -> throw new UnsupportedOperationException("otherContainer." + m.getName());
        });
    }

    @SuppressWarnings("unchecked")
    @NotNull
    private static <T> T proxy(@NotNull Class<T> type, @NotNull InvocationHandler handler) {
        return (T) Proxy.newProxyInstance(PolicyTestSupport.class.getClassLoader(), new Class<?>[]{type}, handler);
    }

    // ---------------------------------------------------------------- clocks

    /**
     * A clock fixed at an offset from a reference instant, for the skew boundary cases
     */
    @NotNull
    static Clock clockOffsetFrom(@NotNull Instant reference, @NotNull Duration offset) {
        return Clock.fixed(reference.plus(offset), ZoneOffset.UTC);
    }

    /**
     * A clock that tracks the system clock, for the ordinary case where skew is negligible
     */
    @NotNull
    static Clock systemClock() {
        return Clock.system(ZoneId.of("UTC"));
    }

    /**
     * A clock that fails, for the last step of the decision
     * <p>
     * The skew check is the only place this node's own clock is read, and it runs after everything
     * else has succeeded - so it is the cleanest way to make an unexpected failure happen with a key
     * already in hand. {@code Error} rather than an exception in the second variant, because the
     * catch-all claims to cover both and a claim about {@code Error} is worth testing.
     */
    @NotNull
    static Clock failingClock(boolean asError) {
        return new Clock() {
            @Override
            @NotNull
            public ZoneId getZone() {
                return ZoneId.of("UTC");
            }

            @Override
            @NotNull
            public Clock withZone(@Nullable ZoneId zone) {
                return this;
            }

            @Override
            @NotNull
            public Instant instant() {
                if (asError) {
                    throw new AssertionError("clock unavailable");
                }
                throw new IllegalStateException("clock unavailable");
            }
        };
    }

    // ---------------------------------------------------------------- CB_USER fixtures

    /**
     * Creates or updates a row in the CloudBeaver user table
     * <p>
     * Written directly rather than through the security controller: the policy query reads this
     * table, and a test that used the same code path to create the user as the code under test uses
     * to read it would agree with a broken implementation.
     */
    static void putUser(@NotNull Connection connection, @NotNull String userId, boolean active)
            throws SQLException {
        deleteUser(connection, userId);
        try (PreparedStatement dbStat = connection.prepareStatement(
            "INSERT INTO {table_prefix}CB_AUTH_SUBJECT (SUBJECT_ID, SUBJECT_TYPE) VALUES (?, 'U')")
        ) {
            dbStat.setString(1, userId);
            dbStat.executeUpdate();
        }
        try (PreparedStatement dbStat = connection.prepareStatement(
            "INSERT INTO {table_prefix}CB_USER (USER_ID, IS_ACTIVE, CREATE_TIME) VALUES (?, ?, CURRENT_TIMESTAMP)")
        ) {
            dbStat.setString(1, userId);
            dbStat.setString(2, active ? "Y" : "N");
            dbStat.executeUpdate();
        }
    }

    static void deleteUser(@NotNull Connection connection, @NotNull String userId) throws SQLException {
        try (PreparedStatement dbStat = connection.prepareStatement(
            "DELETE FROM {table_prefix}CB_USER WHERE USER_ID=?")
        ) {
            dbStat.setString(1, userId);
            dbStat.executeUpdate();
        }
        try (PreparedStatement dbStat = connection.prepareStatement(
            "DELETE FROM {table_prefix}CB_AUTH_SUBJECT WHERE SUBJECT_ID=?")
        ) {
            dbStat.setString(1, userId);
            dbStat.executeUpdate();
        }
    }

    /**
     * Reads {@code IS_ACTIVE} straight from the table, so a test can confirm its own fixture
     */
    @Nullable
    static String readUserActiveFlag(@NotNull Connection connection, @NotNull String userId) throws SQLException {
        try (PreparedStatement dbStat = connection.prepareStatement(
            "SELECT IS_ACTIVE FROM {table_prefix}CB_USER WHERE USER_ID=?")
        ) {
            dbStat.setString(1, userId);
            try (ResultSet dbResult = dbStat.executeQuery()) {
                return dbResult.next() ? dbResult.getString(1) : null;
            }
        }
    }
}
