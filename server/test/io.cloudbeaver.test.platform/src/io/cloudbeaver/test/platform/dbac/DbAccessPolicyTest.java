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

import io.cloudbeaver.app.CEAppStarter;
import io.cloudbeaver.service.dbac.policy.AuthorizationDecision;
import io.cloudbeaver.service.dbac.policy.DbAccessPolicyConfig;
import io.cloudbeaver.service.dbac.policy.DbAccessPolicyService;
import io.cloudbeaver.service.dbac.policy.DbOperationCategory;
import io.cloudbeaver.service.dbac.policy.DenialReason;
import io.cloudbeaver.service.dbac.policy.WriteAuthorizationRequest;
import io.cloudbeaver.service.dbac.tempwrite.EndpointSnapshot;
import io.cloudbeaver.service.dbac.tempwrite.MetadataConnectionSource;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteGrant;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteGrantRepository;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteMutationCoordinator;
import io.cloudbeaver.service.dbac.tempwrite.TempWritePermissionKey;
import io.cloudbeaver.service.security.EmbeddedSecurityControllerFactory;
import io.cloudbeaver.service.security.db.CBDatabase;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.jkiss.dbeaver.model.DBPDataSourceContainer;
import org.jkiss.dbeaver.model.net.DBWHandlerType;
import org.jkiss.dbeaver.model.rm.RMUtils;
import org.jkiss.dbeaver.model.sql.db.InternalProxyConnection;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The write-authorization decision, against the real metadata database
 * <p>
 * These are the cases where the answer depends on what is stored, so they run against the embedded
 * H2 the server actually uses rather than a mock: the grant is written by the same coordinator
 * production code would use, the user row is written straight to {@code CB_USER} with SQL, and the
 * decision reads both back through the query it will run in production. A test that stubbed the
 * repository would agree with a broken query.
 * <p>
 * <b>No test here writes to a target database.</b> This slice decides; it does not enforce. What is
 * being checked is which answer comes out and what work happens before it, never what a database
 * would have done afterwards.
 */
public class DbAccessPolicyTest {

    private static final String PROJECT = "policy-project";
    private static final String CONNECTION = "policy-connection";
    private static final String HOST = "db.internal.example";
    private static final String DATABASE = "customer_prod";
    private static final String DRIVER = "postgres-jdbc";

    /**
     * Schemas whose {@code DBAC_TW_CURRENT} is a view pinning {@code EXPIRES_AT} to the clock of
     * whatever statement reads it - see {@link #grantExpiringExactlyNowIsDenied}
     */
    private static final String AT_NOW_SCHEMA = "DBAC_POLICY_AT_NOW";
    private static final String AFTER_NOW_SCHEMA = "DBAC_POLICY_AFTER_NOW";

    private static CBDatabase database;

    private final TempWriteGrantRepository repository = new TempWriteGrantRepository();
    private final List<TempWritePermissionKey> touchedKeys = new ArrayList<>();
    private final List<String> touchedUsers = new ArrayList<>();

    @BeforeAll
    public static void startServer() throws Exception {
        CEAppStarter.startServerIfNotStarted();
        database = EmbeddedSecurityControllerFactory.getDbInstance();
        Assertions.assertNotNull(database, "CBDatabase instance must exist after server startup");

        try (Connection connection = database.openConnection()) {
            createBoundaryViews(connection, AT_NOW_SCHEMA, "CURRENT_TIMESTAMP");
            createBoundaryViews(
                connection, AFTER_NOW_SCHEMA, "DATEADD('MICROSECOND', 1, CURRENT_TIMESTAMP)");
        }
    }

    @AfterAll
    public static void dropBoundarySchemas() throws Exception {
        try (Connection connection = database.openConnection()) {
            for (String target : new String[]{AT_NOW_SCHEMA, AFTER_NOW_SCHEMA}) {
                execute(connection, "DROP SCHEMA IF EXISTS " + target + " CASCADE");
            }
        }
    }

    /**
     * Creates a schema that looks like the real one but reports a chosen expiry
     * <p>
     * The two tables the authorization statement reads are exposed as views over the real ones, with
     * {@code EXPIRES_AT} replaced by an expression. Because that expression is evaluated inside the
     * authorization statement itself, {@code EXPIRES_AT} and the statement's own
     * {@code CURRENT_TIMESTAMP} come from one evaluation - which is the only way to put the
     * comparison exactly on its boundary. Writing {@code EXPIRES_AT = CURRENT_TIMESTAMP} into the
     * table from an earlier statement cannot do it: by the time the authorization runs the clock has
     * moved on and the row is simply in the past, so such a test passes whether the comparison is
     * {@code >} or {@code >=}.
     * <p>
     * Only the columns the authorization statement reads are exposed, so a schema change that adds a
     * column does not silently change what these tests exercise.
     */
    private static void createBoundaryViews(
        @NotNull Connection connection,
        @NotNull String target,
        @NotNull String expiresAtExpression
    ) throws SQLException {
        execute(connection, "DROP SCHEMA IF EXISTS " + target + " CASCADE");
        execute(connection, "CREATE SCHEMA " + target);
        execute(connection, "CREATE VIEW " + target + ".CB_USER AS"
            + " SELECT USER_ID, IS_ACTIVE FROM {table_prefix}CB_USER");
        execute(connection, "CREATE VIEW " + target + ".DBAC_TW_CURRENT AS"
            + " SELECT USER_ID, PROJECT_ID, CONNECTION_ID, GRANT_ID,"
            + " " + expiresAtExpression + " AS EXPIRES_AT,"
            + " REVOKED_AT, PROVIDER_ID, DRIVER_ID, CONFIGURATION_TYPE,"
            + " HOST_SNAPSHOT, PORT_SNAPSHOT, DATABASE_SNAPSHOT"
            + " FROM {table_prefix}DBAC_TW_CURRENT");
    }

    private static void execute(@NotNull Connection connection, @NotNull String sql) throws SQLException {
        try (PreparedStatement dbStat = connection.prepareStatement(sql)) {
            dbStat.execute();
        }
    }

    @BeforeEach
    public void resetFixtures() {
        touchedKeys.clear();
        touchedUsers.clear();
    }

    @AfterEach
    public void cleanUp() throws Exception {
        try (Connection connection = database.openConnection()) {
            for (TempWritePermissionKey key : touchedKeys) {
                TempWriteTestSupport.deleteKey(connection, key);
            }
            for (String userId : touchedUsers) {
                PolicyTestSupport.deleteUser(connection, userId);
            }
        }
    }

    // ---------------------------------------------------------------- the single allow

    @Test
    public void activeGrantOnASupportedDatabaseIsAllowed() throws Exception {
        String user = activeUser("policy-allow");
        grant(user, Duration.ofMinutes(30));

        AuthorizationDecision decision = service().authorize(request(user, container()));

        Assertions.assertTrue(decision.isAllowed(), "an unexpired, unrevoked, matching grant must allow");
        Assertions.assertNull(decision.denialReason());
        Assertions.assertNotNull(decision.appliedGrantId(), "an allow must name the grant it applied");
        Assertions.assertNotNull(decision.expiresAt(), "an allow must say when it stops being valid");
        Assertions.assertNotNull(decision.auditPayload());
        Assertions.assertEquals(user, decision.key().userId());
        Assertions.assertEquals(PROJECT, decision.key().projectId());
        Assertions.assertEquals(CONNECTION, decision.key().connectionId());
    }

    // ---------------------------------------------------------------- absence, expiry, revocation

    @Test
    public void noGrantIsDenied() throws Exception {
        String user = activeUser("policy-nogrant");
        assertDenied(service().authorize(request(user, container())), DenialReason.NO_GRANT);
    }

    @Test
    public void expiredGrantIsDenied() throws Exception {
        String user = activeUser("policy-expired");
        grant(user, Duration.ofMinutes(30));
        expireInThePast(user);

        AuthorizationDecision decision = service().authorize(request(user, container()));
        assertDenied(decision, DenialReason.GRANT_EXPIRED);
        Assertions.assertNotNull(
            decision.appliedGrantId(), "an expiry denial still names the grant it was about");
    }

    /**
     * The boundary is exclusive: expiring at the reading statement's own clock is expired
     * <p>
     * Run against {@link #AT_NOW_SCHEMA}, so {@code EXPIRES_AT} and the statement's
     * {@code CURRENT_TIMESTAMP} are one value rather than two a few microseconds apart. The
     * precondition is asserted first, because a fixture that missed the boundary would make this
     * test pass for the wrong reason - and would keep passing if the comparison were widened to
     * {@code >=}.
     */
    @Test
    public void grantExpiringExactlyNowIsDenied() throws Exception {
        String user = activeUser("policy-boundary-at");
        grant(user, Duration.ofMinutes(30));
        assertBoundaryFixture(AT_NOW_SCHEMA, user, "g.EXPIRES_AT = CURRENT_TIMESTAMP",
            "the fixture must put EXPIRES_AT exactly on the reading statement's own clock");

        assertDenied(
            boundaryService(AT_NOW_SCHEMA).authorize(request(user, container())),
            DenialReason.GRANT_EXPIRED);
    }

    /**
     * One tick past the boundary is still inside the grant
     * <p>
     * The other half of the pair: it fails if the comparison is ever tightened by a fudge factor,
     * which would deny a grant that has not expired.
     */
    @Test
    public void grantExpiringOneTickAfterNowIsAllowed() throws Exception {
        String user = activeUser("policy-boundary-after");
        grant(user, Duration.ofMinutes(30));
        assertBoundaryFixture(AFTER_NOW_SCHEMA, user, "g.EXPIRES_AT > CURRENT_TIMESTAMP",
            "the fixture must put EXPIRES_AT after the reading statement's own clock");

        Assertions.assertTrue(
            boundaryService(AFTER_NOW_SCHEMA).authorize(request(user, container())).isAllowed(),
            "a grant expiring one microsecond from now has not expired");
    }

    @Test
    public void revokedGrantIsDenied() throws Exception {
        String user = activeUser("policy-revoked");
        grant(user, Duration.ofMinutes(30));
        revoke(user);

        assertDenied(service().authorize(request(user, container())), DenialReason.GRANT_REVOKED);
    }

    /**
     * A grant that is both revoked and expired reports expiry
     * <p>
     * Phase 2 section 4 marks expiry as taking precedence ("만료 우선"). Both answers are DENY, so
     * this pins the reported reason rather than the outcome - but an unpinned precedence is one that
     * changes silently when the branches are reordered.
     */
    @Test
    public void expiryIsReportedAheadOfRevocation() throws Exception {
        String user = activeUser("policy-both");
        grant(user, Duration.ofMinutes(30));
        revoke(user);
        expireInThePast(user);

        assertDenied(service().authorize(request(user, container())), DenialReason.GRANT_EXPIRED);
    }

    // ------------------------------------------------- physical endpoint succession

    /**
     * Moving the port must not carry the grant to the new server
     * <p>
     * Everything a connection is keyed and checked by is unchanged here: same project id, same
     * connection id, the very same container object in the registry, same provider and driver, same
     * host, same database. Only the port moved, and a different port on the same host is a different
     * server instance.
     */
    @Test
    public void portChangeIsDenied() throws Exception {
        String user = activeUser("policy-port-move");
        grant(user, Duration.ofMinutes(30));

        assertDenied(
            service().authorize(request(user, PolicyTestSupport.builder(PROJECT, CONNECTION)
                .port("5433")
                .build())),
            DenialReason.GRANT_STALE);
    }

    /**
     * Switching to a custom JDBC URL must not carry the grant
     * <p>
     * In URL mode the host and database fields are not the endpoint - the platform hands the stored
     * url to the driver verbatim - so a grant checked against those fields is checked against
     * something the connection no longer uses.
     */
    @Test
    public void switchToUrlModeIsDenied() throws Exception {
        String user = activeUser("policy-url-mode");
        grant(user, Duration.ofMinutes(30));

        assertDenied(
            service().authorize(request(user, PolicyTestSupport.builder(PROJECT, CONNECTION)
                .urlMode("jdbc:postgresql://other.internal.example:5432/customer_prod")
                .build())),
            DenialReason.ENDPOINT_UNSUPPORTED);
    }

    /**
     * Enabling an SSH tunnel must not carry the grant
     * <p>
     * A tunnel rewrites the host and port at connect time and its own remote endpoint decides which
     * database is reached, so the stored host/port stop describing the target.
     */
    @Test
    public void enabledTunnelIsDenied() throws Exception {
        String user = activeUser("policy-tunnel");
        grant(user, Duration.ofMinutes(30));

        assertDenied(
            service().authorize(request(user, PolicyTestSupport.builder(PROJECT, CONNECTION)
                .handler("ssh_tunnel", DBWHandlerType.TUNNEL, true,
                    Map.of("host", "bastion.example", "port", "22",
                        "remoteHost", "other.internal.example", "remotePort", "5432"))
                .build())),
            DenialReason.ENDPOINT_UNSUPPORTED);
    }

    /**
     * A connection with no explicit port is refused rather than assumed to use the driver default
     * <p>
     * This is the boundary between "empty" and "explicitly the default". Nothing in the platform
     * substitutes {@code DBPDriver.getDefaultPort()} into a connection with an empty port - the URL
     * builder omits the port section entirely - so "empty means 5432" is behaviour inside a vendor
     * JAR that is not in this source tree and is not pinned to a driver version. Treating them as
     * one endpoint would authorise a later explicit-port edit on an unprovable premise, so the
     * unprovable case is refused instead. The driver proxy does report a default port, so this test
     * fails if the code ever starts consulting it.
     */
    @Test
    public void connectionWithNoPortIsRefused() throws Exception {
        String user = activeUser("policy-no-port");
        grant(user, Duration.ofMinutes(30));

        for (String noPort : new String[]{null, "", "   "}) {
            assertDenied(
                service().authorize(request(user,
                    PolicyTestSupport.builder(PROJECT, CONNECTION).port(noPort).build())),
                DenialReason.ENDPOINT_UNSUPPORTED);
        }
    }

    /**
     * A port that is not a plain number in range is refused
     */
    @Test
    public void anUnusablePortIsRefused() throws Exception {
        String user = activeUser("policy-bad-port");
        grant(user, Duration.ofMinutes(30));

        for (String bad : new String[]{"0", "65536", "99999", "-1", "5432 ", "54 32", "port", "${p}", "1e3"}) {
            assertDenied(
                service().authorize(request(user,
                    PolicyTestSupport.builder(PROJECT, CONNECTION).port(bad).build())),
                DenialReason.ENDPOINT_UNSUPPORTED);
        }
    }

    /**
     * Everything that makes the physical target unknowable is refused, one property at a time
     * <p>
     * Each row changes exactly one thing about an otherwise fully supported connection, so a failure
     * names the property that stopped being refused rather than "something in the configuration".
     */
    @Test
    public void everyUnfingerprintableConfigurationIsRefused() throws Exception {
        String user = activeUser("policy-unsupported-config");
        grant(user, Duration.ofMinutes(30));

        Map<String, DBPDataSourceContainer> cases = new LinkedHashMap<>();
        cases.put("URL mode",
            PolicyTestSupport.builder(PROJECT, CONNECTION)
                .urlMode("jdbc:postgresql://db.internal.example:5432/customer_prod").build());
        cases.put("enabled SSH tunnel",
            PolicyTestSupport.builder(PROJECT, CONNECTION)
                .handler("ssh_tunnel", DBWHandlerType.TUNNEL, true, Map.of("host", "bastion")).build());
        cases.put("enabled SOCKS proxy",
            PolicyTestSupport.builder(PROJECT, CONNECTION)
                .handler("socks_proxy", DBWHandlerType.PROXY, true, Map.of("socks-host", "proxy")).build());
        cases.put("enabled SSL config handler",
            PolicyTestSupport.builder(PROJECT, CONNECTION)
                .handler("ssl_config", DBWHandlerType.CONFIG, true, Map.of()).build());
        cases.put("config profile",
            PolicyTestSupport.builder(PROJECT, CONNECTION).configProfile("global", "shared-tunnel").build());
        cases.put("driver substitution",
            PolicyTestSupport.builder(PROJECT, CONNECTION).substitutedDriver().build());
        cases.put("socketFactory property",
            PolicyTestSupport.builder(PROJECT, CONNECTION)
                .property("socketFactory", "com.example.Redirect").build());
        cases.put("socketFactoryArg property",
            PolicyTestSupport.builder(PROJECT, CONNECTION)
                .property("socketFactoryArg", "elsewhere:5432").build());
        cases.put("proxy.source.url provider property",
            PolicyTestSupport.builder(PROJECT, CONNECTION)
                .providerProperty("proxy.source.url", "http://proxy").build());
        cases.put("variable in host",
            PolicyTestSupport.builder(PROJECT, CONNECTION).host("${env.DB_HOST}").build());
        cases.put("variable in database",
            PolicyTestSupport.builder(PROJECT, CONNECTION).database("${env.DB_NAME}").build());
        cases.put("variable in server name",
            PolicyTestSupport.builder(PROJECT, CONNECTION).serverName("${env.SRV}").build());
        cases.put("blank host",
            PolicyTestSupport.builder(PROJECT, CONNECTION).host("  ").build());
        cases.put("blank database",
            PolicyTestSupport.builder(PROJECT, CONNECTION).database(null).build());
        cases.put("configuration mode not decided",
            PolicyTestSupport.builder(PROJECT, CONNECTION).configurationType(null).build());

        for (Map.Entry<String, DBPDataSourceContainer> one : cases.entrySet()) {
            AuthorizationDecision decision = service().authorize(request(user, one.getValue()));
            Assertions.assertFalse(
                decision.isAllowed(), one.getKey() + " must not be authorised");
            Assertions.assertEquals(
                DenialReason.ENDPOINT_UNSUPPORTED, decision.denialReason(),
                one.getKey() + " must be refused as unfingerprintable");
            Assertions.assertNotNull(
                decision.key(), one.getKey() + ": the key is known by this point and must be kept");
            Assertions.assertNotNull(
                decision.auditPayload(), one.getKey() + ": a refused attempt must be recordable");
        }
    }

    /**
     * A disabled handler does not make a connection unfingerprintable
     * <p>
     * The pair to the test above. Only enabled handlers route traffic, so refusing on a disabled one
     * would deny ordinary connections and teach an operator to ignore the reason.
     */
    @Test
    public void disabledHandlerStillAllows() throws Exception {
        String user = activeUser("policy-disabled-handler");
        grant(user, Duration.ofMinutes(30));

        Assertions.assertTrue(
            service().authorize(request(user, PolicyTestSupport.builder(PROJECT, CONNECTION)
                .handler("ssh_tunnel", DBWHandlerType.TUNNEL, false, Map.of("host", "bastion"))
                .build())).isAllowed(),
            "a handler that is switched off changes nothing about the endpoint");
    }

    /**
     * A generated URL alongside MANUAL mode is the ordinary case, not a refusal
     * <p>
     * Both the desktop UI and CloudBeaver store a driver-generated url on every save, so if the
     * presence of a url were taken as URL mode every normal connection would be refused. The mode
     * comes from {@code getConfigurationType()} and from nothing else.
     */
    @Test
    public void generatedUrlDoesNotMakeItUrlMode() throws Exception {
        String user = activeUser("policy-generated-url");
        grant(user, Duration.ofMinutes(30));

        Assertions.assertTrue(
            service().authorize(request(user, PolicyTestSupport.builder(PROJECT, CONNECTION)
                .generatedUrl("jdbc:postgresql://db.internal.example:5432/customer_prod")
                .build())).isAllowed());
    }

    /**
     * A stored url that names a different server is refused, whatever the six fields say
     * <p>
     * <b>This is the case the endpoint gate used to miss entirely.</b> The gate read the mode and
     * the six fields and never looked at {@code getUrl()}, on the stated grounds that "a non-empty
     * url proves nothing" because every saved MANUAL connection carries a generated one. The first
     * half was right and the conclusion was wrong: what opens the socket is
     * {@code JDBCDataSource.getConnectionURL}, which hands the driver
     * {@code connectionInfo.getUrl()} verbatim whenever it is non-empty - the mode is not consulted
     * - and CloudBeaver's connection API stores a client-supplied url while leaving host, port,
     * database and the mode untouched ({@code WebDataSourceUtils.setMainProperties} returns as soon
     * as a url is present).
     * <p>
     * So the six fields could still describe {@code db.internal.example} and match the grant exactly
     * while the connection went to another production server. Independent review found this; the
     * test that existed pinned only the <em>matching</em> url, which is why it never showed.
     */
    @Test
    public void storedUrlThatContradictsTheFieldsIsRefused() throws Exception {
        String user = activeUser("policy-url-elsewhere");
        grant(user, Duration.ofMinutes(30));

        // Six fields unchanged and matching the grant; only the url names somewhere else.
        for (String elsewhere : new String[]{
            "jdbc:postgresql://other-prod.internal.example:5432/customer_prod",
            "jdbc:postgresql://db.internal.example:5433/customer_prod",
            "jdbc:postgresql://db.internal.example:5432/other_db",
            "jdbc:postgresql://db.internal.example:5432/customer_prod?ApplicationName=x"}
        ) {
            assertDenied(
                service().authorize(request(user, PolicyTestSupport.builder(PROJECT, CONNECTION)
                    .generatedUrl(elsewhere).build())),
                DenialReason.ENDPOINT_UNSUPPORTED);
        }
    }

    /**
     * Nothing a decision carries contains a credential, even when every credential field is set
     * <p>
     * The fixture plants one sentinel in the password, in an auth property and inside a URL's
     * userinfo. Asserting on the serialized decision rather than field by field means a field added
     * later is covered without anyone remembering to extend this.
     */
    @Test
    public void noDecisionCarriesACredential() throws Exception {
        String user = activeUser("policy-secrets");
        grant(user, Duration.ofMinutes(30));

        DBPDataSourceContainer withUrlCredential = PolicyTestSupport.builder(PROJECT, CONNECTION)
            .generatedUrl("jdbc:postgresql://someone:" + PolicyTestSupport.SECRET_SENTINEL
                + "@db.internal.example:5432/customer_prod?sslpassword="
                + PolicyTestSupport.SECRET_SENTINEL)
            .build();

        for (DBPDataSourceContainer container : new DBPDataSourceContainer[]{
            container(), withUrlCredential,
            PolicyTestSupport.builder(PROJECT, CONNECTION).port("5433").build(),
            // A secret in a property value. The connection is refused because the keys are not
            // allowlisted, and the assertion is that the refusal carries no trace of the value.
            PolicyTestSupport.builder(PROJECT, CONNECTION).secretInPropertyValues().build()}
        ) {
            AuthorizationDecision decision = service().authorize(request(user, container));
            String rendered = decision.toString()
                + " " + decision.auditPayload()
                + " " + decision.userMessage()
                + " " + decision.messageCode();
            Assertions.assertFalse(
                rendered.contains(PolicyTestSupport.SECRET_SENTINEL),
                "a decision must not carry a credential, got " + rendered);
        }
    }

    /**
     * An unsupported database costs no metadata read but is still recorded against its key
     * <p>
     * Both halves matter. The read must not happen, because refusing an out-of-scope database has to
     * be free; and the key must survive, because "this user tried to write to a database outside the
     * supported set, on this connection" is exactly what an operator needs to see. An earlier build
     * discarded the key here and reported the denial as though no user were known.
     */
    @Test
    public void anUnsupportedDatabaseKeepsItsKeyWithoutReadingTheStore() throws Exception {
        CountingSource source = new CountingSource();
        DbAccessPolicyService service = new DbAccessPolicyService(
            source, DbAccessPolicyConfig.defaults(), PolicyTestSupport.systemClock());

        DBPDataSourceContainer oracle = PolicyTestSupport.builder(PROJECT, CONNECTION)
            .driver("oracle", "oracle_thin").build();
        AuthorizationDecision decision = service.authorize(request("someone", oracle));

        assertDenied(decision, DenialReason.DBMS_UNSUPPORTED);
        Assertions.assertEquals(0, source.opened.get(), "an unsupported database must cost no lookup");
        Assertions.assertNotNull(decision.key(), "the key was resolved before the driver was checked");
        Assertions.assertEquals("someone", decision.key().userId());
        Assertions.assertEquals(PROJECT, decision.key().projectId());
        Assertions.assertEquals(CONNECTION, decision.key().connectionId());
        Assertions.assertNotNull(decision.auditPayload(), "a refused attempt must be recordable");
        Assertions.assertEquals("someone", decision.auditPayload().userId());
        Assertions.assertNull(decision.auditPayload().grantId(), "no grant was consulted");
        Assertions.assertNull(decision.auditPayload().expiresAt(), "no grant was consulted");
        Assertions.assertFalse(
            decision.auditPayload().toString().contains(PolicyTestSupport.SECRET_SENTINEL));
    }

    /**
     * A category refused before the key exists still carries neither key nor payload
     * <p>
     * The counterpart to the test above, so the two kinds of pre-lookup denial stay distinguishable
     * rather than both drifting to one shape.
     */
    @Test
    public void refusedCategoryHasNoKeyOrPayload() throws Exception {
        CountingSource source = new CountingSource();
        DbAccessPolicyService service = new DbAccessPolicyService(
            source, DbAccessPolicyConfig.defaults(), PolicyTestSupport.systemClock());

        AuthorizationDecision decision = service.authorize(new WriteAuthorizationRequest(
            "someone", container(), DbOperationCategory.CONTAINER_READ, null, true));

        assertDenied(decision, DenialReason.OPERATION_UNSUPPORTED);
        Assertions.assertEquals(0, source.opened.get());
        Assertions.assertNull(decision.key(), "the category is refused before identity matters");
        Assertions.assertNull(decision.auditPayload());
    }

    /**
     * A connection open against another endpoint is denied even when the stored settings were put back
     * <p>
     * This is the hole a stored-only fingerprint left, found by independent review after the port
     * field had been added. CloudBeaver edits a connection's stored configuration in place and does
     * not disconnect it, and the platform keeps the configuration it connected with until
     * disconnect. So the sequence is: grant on one endpoint, move the port to a second server,
     * open the connection with a read - reads are not write-gated, so nothing judges that - move the
     * port back, then write. The stored side matches the grant again by then, while the statement
     * would run down the socket attached to the second server.
     * <p>
     * The grant, the key, the container object and the registry are all unchanged throughout, so
     * neither the key nor the reference-identity check notices. Only comparing the configuration the
     * connection is actually using does.
     */
    @Test
    public void liveConnectionAtAnotherEndpointIsDenied() throws Exception {
        String user = activeUser("policy-live-endpoint");
        grant(user, Duration.ofMinutes(30));

        DBPDataSourceContainer movedAndRestored = PolicyTestSupport.builder(PROJECT, CONNECTION)
            .connectedAt(HOST, "5433", DATABASE)
            .build();

        assertDenied(
            service().authorize(request(user, movedAndRestored)),
            DenialReason.GRANT_STALE);
    }

    /**
     * Every field of the live endpoint is compared, not only the port
     */
    @Test
    public void liveConnectionIsComparedOnEveryField() throws Exception {
        String user = activeUser("policy-live-fields");
        grant(user, Duration.ofMinutes(30));

        Map<String, DBPDataSourceContainer> cases = new LinkedHashMap<>();
        cases.put("live host elsewhere",
            PolicyTestSupport.builder(PROJECT, CONNECTION).connectedAt("other.example", "5432", DATABASE).build());
        cases.put("live port elsewhere",
            PolicyTestSupport.builder(PROJECT, CONNECTION).connectedAt(HOST, "5433", DATABASE).build());
        cases.put("live database elsewhere",
            PolicyTestSupport.builder(PROJECT, CONNECTION).connectedAt(HOST, "5432", "other_db").build());

        for (Map.Entry<String, DBPDataSourceContainer> one : cases.entrySet()) {
            AuthorizationDecision decision = service().authorize(request(user, one.getValue()));
            Assertions.assertFalse(decision.isAllowed(), one.getKey() + " must not be authorised");
            Assertions.assertEquals(
                DenialReason.GRANT_STALE, decision.denialReason(), one.getKey() + " must be stale");
        }
    }

    /**
     * A connection open against the endpoint it was granted for is still allowed
     * <p>
     * The pair to the tests above. Without it they would pass on an implementation that denies every
     * connected connection, which would make TEMP_WRITE useless the moment anybody opened a session.
     */
    @Test
    public void liveConnectionAtTheGrantedEndpointIsAllowed() throws Exception {
        String user = activeUser("policy-live-ok");
        grant(user, Duration.ofMinutes(30));

        Assertions.assertTrue(
            service().authorize(request(user, PolicyTestSupport.builder(PROJECT, CONNECTION)
                .connectedAt(HOST, "5432", DATABASE)
                .build())).isAllowed(),
            "an open connection that never moved must still be authorised");
    }

    /**
     * A live endpoint that cannot be fingerprinted at all is refused rather than ignored
     */
    @Test
    public void anUnfingerprintableLiveEndpointIsRefused() throws Exception {
        String user = activeUser("policy-live-unusable");
        grant(user, Duration.ofMinutes(30));

        for (String[] live : new String[][]{{HOST, null, DATABASE}, {HOST, "0", DATABASE}, {null, "5432", DATABASE}}) {
            AuthorizationDecision decision = service().authorize(request(user,
                PolicyTestSupport.builder(PROJECT, CONNECTION)
                    .connectedAt(live[0], live[1], live[2])
                    .build()));
            Assertions.assertEquals(
                DenialReason.ENDPOINT_UNSUPPORTED, decision.denialReason(),
                "a live endpoint of " + live[0] + ":" + live[1] + "/" + live[2] + " must be refused");
        }
    }

    /**
     * An authentication model that can supply its own URL makes the endpoint unfingerprintable
     * <p>
     * The provider asks the auth model for a complete URL before it looks at the configuration type,
     * and returns it verbatim if it gets one - so the host, port and database fields are then never
     * consulted. No shipped auth model does that, which is exactly why this needs a test: the gate
     * is here to stop a later one from opening the hole quietly.
     */
    @Test
    public void nonNativeAuthModelIsRefused() throws Exception {
        String user = activeUser("policy-auth-model");
        grant(user, Duration.ofMinutes(30));

        for (String model : new String[]{"shell_command", "aws_iam", "azure_ad"}) {
            AuthorizationDecision decision = service().authorize(request(user,
                PolicyTestSupport.builder(PROJECT, CONNECTION).authModel(model).build()));
            Assertions.assertEquals(
                DenialReason.ENDPOINT_UNSUPPORTED, decision.denialReason(),
                "auth model " + model + " must be refused");
        }
        Assertions.assertTrue(
            service().authorize(request(user,
                PolicyTestSupport.builder(PROJECT, CONNECTION).authModel("native").build())).isAllowed(),
            "the native model is the one whose configuration cannot redirect the connection");
    }

    /**
     * Every routing property key is refused, and the denial costs no metadata read
     * <p>
     * One row per key, so a key removed from the list fails here rather than silently widening what
     * is accepted. The zero-read assertion is the {@code ENDPOINT_UNSUPPORTED} counterpart of the one
     * that already covers an unsupported database.
     */
    @Test
    public void everyRoutingPropertyIsRefusedWithoutAnyLookup() throws Exception {
        for (String key : new String[]{
            "socketFactory", "socketFactoryArg", "proxy.source.url", "propertiesTransform", "sslfactory"}
        ) {
            CountingSource source = new CountingSource();
            DbAccessPolicyService service = new DbAccessPolicyService(
                source, DbAccessPolicyConfig.defaults(), PolicyTestSupport.systemClock());

            AuthorizationDecision viaProperties = service.authorize(request("someone",
                PolicyTestSupport.builder(PROJECT, CONNECTION).property(key, "com.example.Redirect").build()));
            AuthorizationDecision viaProviderProperties = service.authorize(request("someone",
                PolicyTestSupport.builder(PROJECT, CONNECTION).providerProperty(key, "com.example.Redirect").build()));

            for (AuthorizationDecision decision : new AuthorizationDecision[]{
                viaProperties, viaProviderProperties}
            ) {
                Assertions.assertEquals(
                    DenialReason.ENDPOINT_UNSUPPORTED, decision.denialReason(),
                    key + " must be refused as a routing property");
                Assertions.assertNotNull(decision.key(), key + ": the key must be kept");
                Assertions.assertNotNull(decision.auditPayload(), key + ": the denial must be recordable");
            }
            Assertions.assertEquals(
                0, source.opened.get(),
                key + ": refusing an unfingerprintable connection must cost no lookup");
        }
    }

    /**
     * Nothing a denial carries names a handler secret either
     */
    @Test
    public void noDenialCarriesAHandlerSecret() throws Exception {
        String user = activeUser("policy-handler-secret");
        grant(user, Duration.ofMinutes(30));

        AuthorizationDecision decision = service().authorize(request(user,
            PolicyTestSupport.builder(PROJECT, CONNECTION)
                .handler("ssh_tunnel", DBWHandlerType.TUNNEL, true, Map.of("host", "bastion"))
                .build()));

        String rendered = decision + " " + decision.auditPayload() + " " + decision.userMessage();
        for (String secret : new String[]{
            PolicyTestSupport.SECRET_SENTINEL, PolicyTestSupport.HANDLER_SECRET_SENTINEL}
        ) {
            Assertions.assertFalse(rendered.contains(secret), "a denial must not carry " + secret);
        }
    }

    /**
     * A closed connection whose failed attempt left a copy behind is judged on that copy too
     * <p>
     * The state exists because the platform's connect failure handler clears the data source without
     * clearing the configuration copy it took, and disconnect returns early once the data source is
     * null. So {@code isConnected()} says false while a separate pre-attempt copy is still reported.
     * <p>
     * Both directions are pinned. Nothing moved, so the copy agrees with the grant and the write is
     * allowed - a failed connection attempt must not cost anybody their permission. Move the stored
     * configuration afterwards and the copy disagrees, so the write is refused. The point of the test
     * is that neither answer depends on {@code isConnected()}: an implementation that skipped the
     * second comparison for a closed connection would get the second case wrong.
     */
    @Test
    public void failedAttemptCopyIsStillCompared() throws Exception {
        String user = activeUser("policy-failed-attempt");
        grant(user, Duration.ofMinutes(30));

        Assertions.assertTrue(
            service().authorize(request(user, PolicyTestSupport.builder(PROJECT, CONNECTION)
                .failedAttemptAt(HOST, "5432", DATABASE)
                .build())).isAllowed(),
            "a failed connection attempt against the granted endpoint must not withdraw the grant");

        assertDenied(
            service().authorize(request(user, PolicyTestSupport.builder(PROJECT, CONNECTION)
                .failedAttemptAt(HOST, "5433", DATABASE)
                .build())),
            DenialReason.GRANT_STALE);
    }

    // ------------------------------------------- unexpected failures keep what they know

    /**
     * An unexpected failure before the key exists produces a denial with no subject
     * <p>
     * {@code getId()} throwing is the earliest an accessor can fail. Nothing is known about who was
     * asking at that point, so there is nothing to attribute the event to - and a payload invented
     * from a container that cannot answer would be a fabricated audit row.
     */
    @Test
    public void anUnexpectedFailureBeforeTheKeyHasNoSubject() throws Exception {
        AuthorizationDecision decision = service().authorize(request("someone",
            PolicyTestSupport.builder(PROJECT, CONNECTION).identityFails().build()));

        assertDenied(decision, DenialReason.PERMISSION_STORE_UNAVAILABLE);
        Assertions.assertNull(decision.key(), "nothing was established about the subject");
        Assertions.assertNull(decision.auditPayload());
    }

    /**
     * An unexpected failure after the key exists keeps the key and stays auditable
     * <p>
     * Three ways in, all after identity has been resolved: the driver accessor, the configuration
     * accessor, and this node's own clock in the very last step. An earlier build answered all of
     * them with a subject-less denial, which threw away the one fact worth recording - who was
     * trying to write to what. {@code Error} is included because the catch-all claims to cover it.
     */
    @Test
    public void anUnexpectedFailureAfterTheKeyKeepsIt() throws Exception {
        String user = activeUser("policy-unexpected");
        grant(user, Duration.ofMinutes(30));

        Map<String, AuthorizationDecision> cases = new LinkedHashMap<>();
        cases.put("driver accessor throws", service().authorize(request(user,
            PolicyTestSupport.builder(PROJECT, CONNECTION).driverFails().build())));
        cases.put("configuration accessor throws", service().authorize(request(user,
            PolicyTestSupport.builder(PROJECT, CONNECTION).configurationFails().build())));
        cases.put("clock throws an exception", new DbAccessPolicyService(
            database::openConnection, DbAccessPolicyConfig.defaults(),
            PolicyTestSupport.failingClock(false)).authorize(request(user, container())));
        cases.put("clock throws an Error", new DbAccessPolicyService(
            database::openConnection, DbAccessPolicyConfig.defaults(),
            PolicyTestSupport.failingClock(true)).authorize(request(user, container())));

        for (Map.Entry<String, AuthorizationDecision> one : cases.entrySet()) {
            AuthorizationDecision decision = one.getValue();
            String what = one.getKey();
            Assertions.assertFalse(decision.isAllowed(), what + " must not be authorised");
            Assertions.assertEquals(
                DenialReason.PERMISSION_STORE_UNAVAILABLE, decision.denialReason(),
                what + " must be refused conservatively");
            Assertions.assertNotNull(decision.key(), what + ": the key was known and must be kept");
            Assertions.assertEquals(user, decision.key().userId(), what);
            Assertions.assertEquals(PROJECT, decision.key().projectId(), what);
            Assertions.assertEquals(CONNECTION, decision.key().connectionId(), what);
            Assertions.assertNotNull(
                decision.auditPayload(), what + ": a keyed denial must be recordable");
            Assertions.assertEquals(user, decision.auditPayload().userId(), what);
            Assertions.assertEquals(
                DenialReason.PERMISSION_STORE_UNAVAILABLE, decision.auditPayload().denialReason(), what);
            Assertions.assertNull(
                decision.auditPayload().grantId(),
                what + ": nothing about a grant was established");
            Assertions.assertNull(decision.auditPayload().expiresAt(), what);
            Assertions.assertFalse(
                (decision + " " + decision.auditPayload()).contains(PolicyTestSupport.SECRET_SENTINEL),
                what + ": a failure must not leak a credential");
        }
    }

    /**
     * A request that is not a request is a programming error, not a denial
     * <p>
     * Answering "denied" would let a wiring mistake be logged, audited and explained to a user as
     * though a real attempt had been refused. There is also no category to build a decision around.
     */
    @Test
    public void missingRequestIsRefusedAsAProgrammingError() {
        Assertions.assertThrows(
            IllegalArgumentException.class, () -> service().authorize(null));
    }

    // ------------------------------------------- port spelling

    /**
     * A port with a leading zero is refused rather than normalised
     * <p>
     * The platform copies the string into the URL literally, so what {@code "05432"} connects to is
     * decided inside a vendor driver; and the comparison against a stored grant is textual, so
     * accepting both spellings would give one server two fingerprints. Refusing the odd spelling
     * keeps that mapping single-valued, which is what the design note claims.
     */
    @Test
    public void portWithALeadingZeroIsRefused() throws Exception {
        String user = activeUser("policy-zero-port");
        grant(user, Duration.ofMinutes(30));

        for (String odd : new String[]{"05432", "005432", "00", "01"}) {
            AuthorizationDecision decision = service().authorize(request(user,
                PolicyTestSupport.builder(PROJECT, CONNECTION).port(odd).build()));
            Assertions.assertEquals(
                DenialReason.ENDPOINT_UNSUPPORTED, decision.denialReason(),
                "port " + odd + " must be refused as an ambiguous spelling");
        }
        Assertions.assertTrue(
            service().authorize(request(user,
                PolicyTestSupport.builder(PROJECT, CONNECTION).port("5432").build())).isAllowed(),
            "the plain spelling is still accepted");
        Assertions.assertEquals(
            DenialReason.ENDPOINT_UNSUPPORTED,
            service().authorize(request(user,
                PolicyTestSupport.builder(PROJECT, CONNECTION).port("0").build())).denialReason(),
            "zero is not a port");
    }

    // ------------------------------------------- connection properties, allowlisted

    /**
     * Any connection property key nobody has classified makes the endpoint unidentifiable
     * <p>
     * The rule is an allowlist, so this is not a list of dangerous names - it is a sample of
     * arbitrary ones, including names no driver recognises. The previous design named five known
     * routing keys and accepted everything else, and could not prove the list complete.
     * <p>
     * The value is irrelevant, which is the point of the last three rows: a key with a null value,
     * an empty value and an ordinary value are all refused the same way, because nothing here reads
     * a value.
     */
    @Test
    public void anyUnclassifiedPropertyKeyIsRefused() throws Exception {
        String user = activeUser("policy-unknown-prop");
        grant(user, Duration.ofMinutes(30));

        record Case(String name, DBPDataSourceContainer container) {
        }

        Case[] cases = {
            new Case("driver property, ordinary value",
                PolicyTestSupport.builder(PROJECT, CONNECTION).property("connectTimeout", "10").build()),
            new Case("driver property, null value",
                PolicyTestSupport.builder(PROJECT, CONNECTION).property("connectTimeout", null).build()),
            new Case("driver property, blank value",
                PolicyTestSupport.builder(PROJECT, CONNECTION).property("connectTimeout", "  ").build()),
            new Case("driver property no driver recognises",
                PolicyTestSupport.builder(PROJECT, CONNECTION).property("nobodyKnowsThisKey", "x").build()),
            new Case("a pgjdbc class-loading prefix",
                PolicyTestSupport.builder(PROJECT, CONNECTION).property("datatype.geometry", "com.x.Y").build()),
            new Case("a case variant of an allowed provider key",
                PolicyTestSupport.builder(PROJECT, CONNECTION)
                    .providerProperty("@DBEAVER-SHOW-ALL-DBS@", "false").build()),
            new Case("provider property, ordinary value",
                PolicyTestSupport.builder(PROJECT, CONNECTION)
                    .providerProperty("@dbeaver-serverTimezone@", "UTC").build()),
            new Case("provider property, null value",
                PolicyTestSupport.builder(PROJECT, CONNECTION)
                    .providerProperty("@dbeaver-serverTimezone@", null).build()),
            new Case("provider property nobody has classified",
                PolicyTestSupport.builder(PROJECT, CONNECTION)
                    .providerProperty("some-new-switch", "on").build()),
        };
        for (Case one : cases) {
            AuthorizationDecision decision = service().authorize(request(user, one.container()));
            Assertions.assertFalse(decision.isAllowed(), one.name() + " must not be authorised");
            Assertions.assertEquals(
                DenialReason.ENDPOINT_UNSUPPORTED, decision.denialReason(),
                one.name() + " must be refused as unfingerprintable");
            Assertions.assertNotNull(decision.key(), one.name() + ": the key must be kept");
            Assertions.assertNotNull(decision.auditPayload(), one.name() + ": the denial must be recordable");
            Assertions.assertFalse(
                (decision + " " + decision.auditPayload()).contains(PolicyTestSupport.SECRET_SENTINEL),
                one.name() + ": no credential may leak");
        }
    }

    /**
     * The same key is refused in either map
     * <p>
     * Only the driver-property map reaches {@code Driver.connect}, but a provider key nobody has
     * classified is still a key nobody has thought about, and two of them are translated into
     * driver properties by provider code. Both maps get the same fail-closed rule.
     */
    @Test
    public void theSameUnknownKeyIsRefusedInEitherMap() throws Exception {
        String user = activeUser("policy-both-maps");
        grant(user, Duration.ofMinutes(30));

        for (String key : new String[]{"socketFactory", "propertiesTransform", "someUnknownKey"}) {
            Assertions.assertEquals(
                DenialReason.ENDPOINT_UNSUPPORTED,
                service().authorize(request(user, PolicyTestSupport.builder(PROJECT, CONNECTION)
                    .property(key, "x").build())).denialReason(),
                key + " must be refused in the driver-property map");
            Assertions.assertEquals(
                DenialReason.ENDPOINT_UNSUPPORTED,
                service().authorize(request(user, PolicyTestSupport.builder(PROJECT, CONNECTION)
                    .providerProperty(key, "x").build())).denialReason(),
                key + " must be refused in the provider-property map too");
        }
    }

    /**
     * The one provider property an ordinary connection carries keeps working
     * <p>
     * {@code @dbeaver-show-all-dbs@} is the only provider property in the supported set that
     * declares a default, and CloudBeaver's frontend sends provider-property defaults without
     * stripping them - so an ordinary web-created MySQL connection stores it. If this were refused,
     * every such connection would lose the ability to hold temporary write access. It is safe to
     * ignore on two counts: it never reaches the driver, and what it changes is which databases the
     * navigator lists.
     */
    @Test
    public void anOrdinaryConnectionWithItsDefaultProviderPropertyIsStillAllowed() throws Exception {
        String user = activeUser("policy-allowed-prop");
        // Granted for the MySQL endpoint, because the connection under test is a MySQL one. The
        // first version of this test granted for the default PostgreSQL endpoint and then authorized
        // a MySQL connection, which is a stale grant rather than a property question.
        grant(user, Duration.ofMinutes(30), new EndpointSnapshot(
            "mysql", "mysql8", "MANUAL", HOST, "5432", DATABASE));

        // MySQL, because that is the provider whose extension declares this key with a default the
        // frontend does not strip. Under PostgreSQL the same key is refused, and that asymmetry is
        // the point: the allowlist follows what each provider actually stores.
        Assertions.assertTrue(
            service().authorize(request(user, PolicyTestSupport.builder(PROJECT, CONNECTION)
                .driver("mysql", "mysql8")
                .providerProperty("@dbeaver-show-all-dbs@", "false")
                .build())).isAllowed(),
            "the provider property an ordinary MySQL connection stores must not cost it write access");
        assertDenied(
            service().authorize(request(user, PolicyTestSupport.builder(PROJECT, CONNECTION)
                .providerProperty("@dbeaver-show-all-dbs@", "false")
                .build())),
            DenialReason.ENDPOINT_UNSUPPORTED);
        Assertions.assertTrue(
            service().authorize(request(user, PolicyTestSupport.builder(PROJECT, CONNECTION)
                .driver("mysql", "mysql8")
                .build())).isAllowed(),
            "and the same connection with no properties at all is of course still allowed");
    }

    // ---------------------------------------------------------------- isolation

    @Test
    public void anotherUserIsDenied() throws Exception {
        String owner = activeUser("policy-owner");
        String other = activeUser("policy-other");
        grant(owner, Duration.ofMinutes(30));

        Assertions.assertTrue(service().authorize(request(owner, container())).isAllowed());
        assertDenied(service().authorize(request(other, container())), DenialReason.NO_GRANT);
    }

    @Test
    public void anotherProjectIsDenied() throws Exception {
        String user = activeUser("policy-project-iso");
        grant(user, Duration.ofMinutes(30));

        DBPDataSourceContainer elsewhere =
            PolicyTestSupport.container("other-project", CONNECTION, HOST, DATABASE);
        assertDenied(service().authorize(request(user, elsewhere)), DenialReason.NO_GRANT);
    }

    @Test
    public void anotherConnectionIsDenied() throws Exception {
        String user = activeUser("policy-conn-iso");
        grant(user, Duration.ofMinutes(30));

        DBPDataSourceContainer elsewhere =
            PolicyTestSupport.container(PROJECT, "other-connection", HOST, DATABASE);
        assertDenied(service().authorize(request(user, elsewhere)), DenialReason.NO_GRANT);
    }

    /**
     * A connection id that merely contains the granted one is a different connection
     * <p>
     * This is the shape Phase 2 section 3.2 warns about: CloudBeaver's own resolver matches a
     * connection id by substring. Because the key is taken from the resolved container rather than
     * from a request argument, a longer id simply does not find the grant.
     */
    @Test
    public void connectionIdContainingTheGrantedOneIsDenied() throws Exception {
        String user = activeUser("policy-substring");
        grant(user, Duration.ofMinutes(30));

        DBPDataSourceContainer lookalike =
            PolicyTestSupport.container(PROJECT, CONNECTION + "-replica", HOST, DATABASE);
        assertDenied(service().authorize(request(user, lookalike)), DenialReason.NO_GRANT);
    }

    // ---------------------------------------------------------------- identity and container

    @Test
    public void missingIdentityIsDeniedBeforeAnyLookup() throws Exception {
        CountingSource source = new CountingSource();
        DbAccessPolicyService service = new DbAccessPolicyService(
            source, DbAccessPolicyConfig.defaults(), PolicyTestSupport.systemClock());

        for (String userId : new String[]{null, "", "   "}) {
            AuthorizationDecision decision = service.authorize(request(userId, container()));
            assertDenied(decision, DenialReason.IDENTITY_MISSING);
            Assertions.assertNull(decision.key(), "there is no key when there is no identity");
            Assertions.assertNull(decision.auditPayload());
        }
        Assertions.assertEquals(
            0, source.opened.get(), "a request with no identity must not reach the permission store");
    }

    /**
     * The anonymous project is refused, and the id it is refused by is the platform's own
     * <p>
     * The production check compares against a string constant. A string constant is right only as
     * long as the platform spells it the same way, and nothing in this fork would notice a rename -
     * the connection would simply stop being recognised as anonymous and would start being judged
     * like a real one. So the id is taken from {@code RMUtils.createAnonymousProject()}, the factory
     * {@code WebSession} itself uses for the anonymous project
     * ({@code WebSession.java:342}), rather than written out a second time.
     */
    @Test
    public void theAnonymousProjectIsDeniedBeforeAnyLookup() throws Exception {
        CountingSource source = new CountingSource();
        DbAccessPolicyService service = new DbAccessPolicyService(
            source, DbAccessPolicyConfig.defaults(), PolicyTestSupport.systemClock());

        String platformAnonymousId = RMUtils.createAnonymousProject().getId();
        Assertions.assertEquals(
            "anonymous", platformAnonymousId,
            "the production constant is this literal; if the platform renames its anonymous project"
                + " the constant has to follow, and this is what says so");

        DBPDataSourceContainer anonymous =
            PolicyTestSupport.container(platformAnonymousId, CONNECTION, HOST, DATABASE);
        assertDenied(service.authorize(request("someone", anonymous)), DenialReason.IDENTITY_MISSING);
        Assertions.assertEquals(0, source.opened.get());
    }

    /**
     * A container the registry no longer holds is refused
     * <p>
     * Reference identity, not id equality: a connection deleted and recreated under the same id
     * would satisfy an equality check, and that is exactly the case this rejects.
     */
    @Test
    public void containerTheRegistryDoesNotHoldIsDenied() throws Exception {
        String user = activeUser("policy-registry");
        grant(user, Duration.ofMinutes(30));

        DBPDataSourceContainer replaced = PolicyTestSupport.builder(PROJECT, CONNECTION)
            .host(HOST).database(DATABASE).registryHoldsSomethingElse().build();
        assertDenied(service().authorize(request(user, replaced)), DenialReason.CONNECTION_UNKNOWN);
    }

    @Test
    public void brokenContainerIsDeniedBeforeAnyLookup() throws Exception {
        CountingSource source = new CountingSource();
        DbAccessPolicyService service = new DbAccessPolicyService(
            source, DbAccessPolicyConfig.defaults(), PolicyTestSupport.systemClock());

        List<DBPDataSourceContainer> broken = List.of(
            PolicyTestSupport.builder(PROJECT, CONNECTION).withoutProject().build(),
            PolicyTestSupport.builder(PROJECT, CONNECTION).withoutRegistry().build(),
            PolicyTestSupport.builder(PROJECT, CONNECTION).registryFails().build());
        for (DBPDataSourceContainer container : broken) {
            assertDenied(service.authorize(request("someone", container)), DenialReason.CONNECTION_UNKNOWN);
        }
        assertDenied(service.authorize(request("someone", null)), DenialReason.CONNECTION_UNKNOWN);
        Assertions.assertEquals(0, source.opened.get());
    }

    // ------------------------------------------------- found by the tier-2 clause sweep
    //
    // The five tests below refuse on a clause that nothing else refuses on. They were not written
    // from reading the code - two earlier rounds did that and reported the endpoint gate fully
    // pinned. They come from deleting each clause of each guard in turn and running the real build
    // to see which deletions no test noticed. Section 7 of docs/db-access-control-build-verification.md
    // describes the method and lists the clauses that survive on purpose.

    /**
     * A grant matching the live endpoint does not excuse a stored endpoint that has moved
     * <p>
     * <b>Both fingerprints have to match, and this is the direction that had no test.</b> The gate
     * compares the grant against the stored configuration <em>and</em> against the one the
     * connection was opened with. Every existing test varies them together, because the platform
     * usually hands back the same object for both - so deleting the stored-side comparison left the
     * suite green while the live-side comparison did the same work twice.
     * <p>
     * Here they genuinely differ: the grant was issued for the endpoint the socket goes to, and the
     * stored configuration has since been edited to name a different server. CloudBeaver edits a
     * connection in place without disconnecting, so this is a reachable state and not a contrivance.
     * The answer is a denial, which is the fail-closed reading: an endpoint that two sources
     * describe differently is not an endpoint a grant can be checked against.
     */
    @Test
    public void grantMatchingOnlyTheLiveEndpointIsRefused() throws Exception {
        String user = activeUser("policy-live-only");
        EndpointSnapshot liveEndpoint = new EndpointSnapshot(
            "postgresql", DRIVER, "MANUAL", "live.internal.example", "5432", DATABASE);
        grant(user, Duration.ofMinutes(30), liveEndpoint);

        // Stored says db.internal.example, the open connection went to live.internal.example.
        DBPDataSourceContainer moved = PolicyTestSupport.builder(PROJECT, CONNECTION)
            .connectedAt("live.internal.example", "5432", DATABASE)
            .build();

        assertDenied(service().authorize(request(user, moved)), DenialReason.GRANT_STALE);
    }

    /**
     * A grant for a user the metadata database has no row for is not an allow
     * <p>
     * There is no foreign key from the grant table to {@code CB_USER} (Phase 2 section 5.5), so a
     * grant can outlive the user it was issued to - a deleted account, or a row written directly.
     * That state had no test at all, which is why this one exists: it establishes the behaviour.
     * <p>
     * <b>What it does not establish.</b> It does not pin the {@code !snapshot.userRowPresent()} half
     * of the condition on its own. The snapshot derives both halves from the same query
     * ({@code PolicySnapshotRepository}: {@code userRowPresent} from whether a row came back,
     * {@code userActive} from its flag), so an absent row reports <em>both</em> false and either
     * half alone refuses it. Deleting the existence half leaves this test green - verified by
     * running it, not assumed. The two halves are a redundant pair, recorded as such in section 7
     * of {@code docs/db-access-control-build-verification.md} rather than covered by a test that
     * would only appear to distinguish them.
     */
    @Test
    public void grantForAUserWithNoRowIsDenied() throws Exception {
        String user = "policy-no-user-row";
        touchedUsers.add(user);
        grant(user, Duration.ofMinutes(30));

        assertDenied(service().authorize(request(user, container())), DenialReason.USER_INACTIVE);
    }

    /**
     * A configuration profile is refused whichever of its two fields is set
     * <p>
     * A profile contributes handlers at connect time that the connection's own handler list does not
     * show, so either field means the route cannot be read from the stored configuration. The
     * existing case set both fields at once, which meant neither check was doing anything the other
     * did not.
     */
    @Test
    public void eitherConfigProfileFieldAloneIsRefused() {
        // configProfile(source, name) - the source alone, then the name alone.
        assertDenied(
            service().authorize(request("someone", PolicyTestSupport.builder(PROJECT, CONNECTION)
                .configProfile("global", null).build())),
            DenialReason.ENDPOINT_UNSUPPORTED);
        assertDenied(
            service().authorize(request("someone", PolicyTestSupport.builder(PROJECT, CONNECTION)
                .configProfile(null, "shared-tunnel").build())),
            DenialReason.ENDPOINT_UNSUPPORTED);
    }

    /**
     * A port too long to be a port is refused, not parsed
     * <p>
     * The length check exists so {@code Integer.parseInt} is never handed something that overflows.
     * The range check alone would catch a six-digit port, but an eleven-digit one throws instead,
     * and an exception escaping the gate is a different outcome from a refusal even though both end
     * in a denial. The existing bad-port table stopped at five digits, so the length check had
     * nothing holding it.
     */
    @Test
    public void anOverlongPortIsRefusedRatherThanParsed() {
        for (String tooLong : new String[]{"123456", "99999999999", "999999999999999999999"}) {
            assertDenied(
                service().authorize(request("someone", PolicyTestSupport.builder(PROJECT, CONNECTION)
                    .port(tooLong).build())),
                DenialReason.ENDPOINT_UNSUPPORTED);
        }
    }

    /**
     * A blank identifier is refused as firmly as an absent one
     * <p>
     * Each of the three identity checks is {@code null || isBlank}, and only the null half was
     * exercised. A blank user id, connection id or project id is what an empty form field or a
     * trimmed header produces.
     * <p>
     * <b>Two of the three halves are pinned by this; the user id one is not.</b> Deleting
     * {@code connectionId.isBlank()} or {@code projectId.isBlank()} turns the matching assertion
     * red. Deleting {@code userId.isBlank()} does not: the blank id then reaches
     * {@code new DbAccessKey(...)}, which refuses blank parts, and the resolver's own
     * {@code catch (IllegalArgumentException)} maps that to the same {@code IDENTITY_MISSING} - so
     * the outcome is identical, reason included. That is a redundancy rather than a gap, and it is
     * recorded in section 7 of {@code docs/db-access-control-build-verification.md}. The assertion
     * is kept because the behaviour is worth asserting; the claim about what it discriminates is
     * not made.
     */
    @Test
    public void blankIdentifiersAreRefused() {
        Assertions.assertEquals(
            DenialReason.IDENTITY_MISSING,
            service().authorize(request("   ", container())).denialReason(),
            "a blank user id is no identity");
        Assertions.assertEquals(
            DenialReason.CONNECTION_UNKNOWN,
            service().authorize(request("someone",
                PolicyTestSupport.builder(PROJECT, "  ").build())).denialReason(),
            "a blank connection id names no connection");
        Assertions.assertEquals(
            DenialReason.CONNECTION_UNKNOWN,
            service().authorize(request("someone",
                PolicyTestSupport.builder("  ", CONNECTION).build())).denialReason(),
            "a blank project id names no project");
    }

    // ---------------------------------------------------------------- user state

    @Test
    public void anInactiveUserIsDenied() throws Exception {
        String user = "policy-inactive";
        touchedUsers.add(user);
        try (Connection connection = database.openConnection()) {
            PolicyTestSupport.putUser(connection, user, false);
            Assertions.assertEquals("N", PolicyTestSupport.readUserActiveFlag(connection, user));
        }
        grant(user, Duration.ofMinutes(30));

        assertDenied(service().authorize(request(user, container())), DenialReason.USER_INACTIVE);
    }

    /**
     * A user with no row at all is denied, even holding a grant
     * <p>
     * Fail-closed: an identity the server cannot confirm is not an identity, and a leftover grant
     * row for a deleted account must not outlive it.
     */
    @Test
    public void userWithNoRowIsDenied() throws Exception {
        String user = "policy-ghost";
        grant(user, Duration.ofMinutes(30));

        assertDenied(service().authorize(request(user, container())), DenialReason.USER_INACTIVE);
    }

    // ---------------------------------------------------------------- snapshot

    @Test
    public void eachSnapshotFieldMismatchIsDeniedSeparately() throws Exception {
        String user = activeUser("policy-stale");
        grant(user, Duration.ofMinutes(30));

        assertDenied(
            service().authorize(request(user,
                PolicyTestSupport.builder(PROJECT, CONNECTION)
                    .driver("mysql", "mysql8").host(HOST).database(DATABASE).build())),
            DenialReason.GRANT_STALE);
        assertDenied(
            service().authorize(request(user,
                PolicyTestSupport.container(PROJECT, CONNECTION, "someone-elses-host", DATABASE))),
            DenialReason.GRANT_STALE);
        assertDenied(
            service().authorize(request(user,
                PolicyTestSupport.container(PROJECT, CONNECTION, HOST, "another_database"))),
            DenialReason.GRANT_STALE);
        assertDenied(
            service().authorize(request(user,
                PolicyTestSupport.builder(PROJECT, CONNECTION).port("5433").build())),
            DenialReason.GRANT_STALE);
        assertDenied(
            service().authorize(request(user,
                PolicyTestSupport.builder(PROJECT, CONNECTION).driver("postgresql", "postgresql").build())),
            DenialReason.GRANT_STALE);
    }

    /**
     * A grant carried over from schema version 2 authorises nothing until it is granted again
     * <p>
     * Such a row has a driver, a host and a database but no provider, configuration type or port,
     * because those columns did not exist when it was written. The three values it does have match
     * the connection exactly - which is the point: an incomplete endpoint must be a mismatch, not a
     * wildcard, or the migration would bless the very succession the new columns exist to catch.
     */
    @Test
    public void versionTwoGrantIsDeniedUntilReissued() throws Exception {
        String user = activeUser("policy-v2-row");
        grant(user, Duration.ofMinutes(30));
        Assertions.assertTrue(
            service().authorize(request(user, container())).isAllowed(),
            "precondition: the freshly written grant is honoured");

        degradeToVersionTwoRow(user);

        assertDenied(service().authorize(request(user, container())), DenialReason.GRANT_STALE);
    }

    @Test
    public void hostDifferingOnlyInCaseStillMatches() throws Exception {
        String user = activeUser("policy-hostcase");
        grant(user, Duration.ofMinutes(30));

        Assertions.assertTrue(service().authorize(request(user,
            PolicyTestSupport.container(PROJECT, CONNECTION, HOST.toUpperCase(java.util.Locale.ROOT), DATABASE)
        )).isAllowed());
    }

    // ---------------------------------------------------------------- category and DBMS

    /**
     * Asking the write gate about a category it does not govern is refused, and nothing is opened
     * <p>
     * The category list is derived from the enum rather than written out, so a category that changes
     * side arrives here automatically instead of leaving a stale literal behind. That matters: this
     * test used to name {@code GROUPING} explicitly, and when independent review showed the category
     * had been misclassified, the literal was one more place that had to be found by hand.
     */
    @Test
    public void unsupportedCategoriesAreDeniedBeforeAnyLookup() throws Exception {
        CountingSource source = new CountingSource();
        DbAccessPolicyService service = new DbAccessPolicyService(
            source, DbAccessPolicyConfig.defaults(), PolicyTestSupport.systemClock());

        DbOperationCategory[] notGoverned = java.util.Arrays.stream(DbOperationCategory.values())
            .filter(one -> one.gate() == DbOperationCategory.Gate.NOT_WRITE_GATED)
            .toArray(DbOperationCategory[]::new);
        Assertions.assertEquals(
            1, notGoverned.length, "CONTAINER_READ is the only category the write gate disowns");

        for (DbOperationCategory category : notGoverned) {
            AuthorizationDecision decision = service.authorize(
                new WriteAuthorizationRequest("someone", container(), category, null, true));
            assertDenied(decision, DenialReason.OPERATION_UNSUPPORTED);
        }
        Assertions.assertEquals(0, source.opened.get());
    }

    /**
     * A grouping query is judged like any other write-gated operation
     * <p>
     * The distinction this pins is between {@code OPERATION_UNSUPPORTED} - "do not ask me about this"
     * - and a real judgement. {@code GROUPING} answered the former for three rounds on the strength
     * of a javadoc claim that the UI assembles the query; it does not, the GraphQL field is free text
     * that {@code SQLGroupingQueryGenerator} concatenates verbatim, and this project's own survey had
     * recorded that as HIGH. So a grouping request with no grant must come back denied for the reason
     * a missing grant gives, and with a live grant it must be allowed like any other write.
     */
    @Test
    public void groupingIsJudgedByTheWriteGate() throws Exception {
        AuthorizationDecision refused = service().authorize(WriteAuthorizationRequest.of(
            activeUser("grouping-no-grant"), container(), DbOperationCategory.GROUPING));
        assertDenied(refused, DenialReason.NO_GRANT);
        Assertions.assertNotEquals(
            DenialReason.OPERATION_UNSUPPORTED, refused.denialReason(),
            "a grouping query must be judged, not disowned by the gate");

        String user = activeUser("grouping-granted");
        grant(user, Duration.ofMinutes(30));
        AuthorizationDecision allowed = service().authorize(WriteAuthorizationRequest.of(
            user, container(), DbOperationCategory.GROUPING));
        Assertions.assertTrue(
            allowed.isAllowed(), "a live grant covers a grouping query as it covers any other write");
        Assertions.assertEquals(
            DbOperationCategory.GROUPING, allowed.auditPayload().operationCategory());
    }

    /**
     * Rollback is allowed without consulting anything
     */
    @Test
    public void rollbackIsAllowedWithoutAnyLookup() throws Exception {
        CountingSource source = new CountingSource();
        DbAccessPolicyService service = new DbAccessPolicyService(
            source, DbAccessPolicyConfig.defaults(), PolicyTestSupport.systemClock());

        AuthorizationDecision decision = service.authorize(new WriteAuthorizationRequest(
            null, null, DbOperationCategory.TRANSACTION_ROLLBACK, null, false));
        Assertions.assertTrue(decision.isAllowed(), "rollback must work when everything else is denied");
        Assertions.assertEquals(AuthorizationDecision.RECOVERY_GRANT_ID, decision.appliedGrantId());
        Assertions.assertNull(decision.auditPayload(), "no permission was consulted, so none was decided");
        Assertions.assertEquals(0, source.opened.get());
    }

    @Test
    public void anUnsupportedTargetDatabaseIsDeniedBeforeAnyLookup() throws Exception {
        CountingSource source = new CountingSource();
        DbAccessPolicyService service = new DbAccessPolicyService(
            source, DbAccessPolicyConfig.defaults(), PolicyTestSupport.systemClock());

        List<DBPDataSourceContainer> unsupported = List.of(
            PolicyTestSupport.builder(PROJECT, CONNECTION).driver("postgresql", "postgres-redshift-jdbc").build(),
            PolicyTestSupport.builder(PROJECT, CONNECTION).driver("mysql", "mariaDB").build(),
            PolicyTestSupport.builder(PROJECT, CONNECTION).driver("generic", "postgresql").build(),
            PolicyTestSupport.builder(PROJECT, CONNECTION).driver("postgresql", "postgres-jdbc")
                .customDriver().build(),
            PolicyTestSupport.builder(PROJECT, CONNECTION).withoutDriver().build());
        for (DBPDataSourceContainer container : unsupported) {
            assertDenied(service.authorize(request("someone", container)), DenialReason.DBMS_UNSUPPORTED);
        }
        Assertions.assertEquals(
            0, source.opened.get(), "an unsupported database must cost nothing to refuse");
    }

    // ---------------------------------------------------------------- store failure and clock

    @Test
    public void metadataFailureIsDeniedAndNotMistakenForNoGrant() throws Exception {
        String user = activeUser("policy-storefail");
        grant(user, Duration.ofMinutes(30));

        DbAccessPolicyService service = new DbAccessPolicyService(
            () -> {
                throw new SQLException("Injected metadata outage", "08006");
            },
            DbAccessPolicyConfig.defaults(), PolicyTestSupport.systemClock());

        AuthorizationDecision decision = service.authorize(request(user, container()));
        assertDenied(decision, DenialReason.PERMISSION_STORE_UNAVAILABLE);
        Assertions.assertNotEquals(
            DenialReason.NO_GRANT, decision.denialReason(),
            "an outage and an absent grant are different facts");
    }

    /**
     * Skew below, at, and above the threshold
     * <p>
     * Equal to the threshold is inside it: Phase 2 section 8.1 writes the rule as
     * {@code |localNow - dbNow| > threshold}.
     */
    @Test
    public void clockSkewIsCheckedAtTheStatedBoundary() throws Exception {
        String user = activeUser("policy-skew");
        grant(user, Duration.ofMinutes(30));

        OffsetDateTime dbNow = readDatabaseNow();
        Duration threshold = DbAccessPolicyConfig.defaults().clockSkewThreshold();

        Assertions.assertTrue(
            authorizeWithClock(user, PolicyTestSupport.clockOffsetFrom(
                dbNow.toInstant(), threshold.minusMillis(500))).isAllowed(),
            "below the threshold must still allow");
        Assertions.assertTrue(
            authorizeWithClock(user, PolicyTestSupport.clockOffsetFrom(
                dbNow.toInstant(), threshold)).isAllowed(),
            "exactly the threshold is inside the allowance");
        assertDenied(
            authorizeWithClock(user, PolicyTestSupport.clockOffsetFrom(
                dbNow.toInstant(), threshold.plusSeconds(2))),
            DenialReason.CLOCK_SKEW_EXCEEDED);
        assertDenied(
            authorizeWithClock(user, PolicyTestSupport.clockOffsetFrom(
                dbNow.toInstant(), threshold.plusSeconds(2).negated())),
            DenialReason.CLOCK_SKEW_EXCEEDED);
    }

    // ---------------------------------------------------------------- no cache

    /**
     * Every decision reads the store again, so a revoke lands on the very next call
     * <p>
     * Same service instance, same container, no reconnect: the first call allows, the revoke commits,
     * and the second call denies. That is what "no permission cache" buys, and it is the property
     * Phase 2 section 8.2 promises in place of stopping a statement already in flight.
     */
    @Test
    public void revokingAffectsTheNextDecisionOnTheSameServiceInstance() throws Exception {
        String user = activeUser("policy-nocache");
        grant(user, Duration.ofMinutes(30));

        CountingSource source = new CountingSource();
        DbAccessPolicyService service = new DbAccessPolicyService(
            source, DbAccessPolicyConfig.defaults(), PolicyTestSupport.systemClock());

        Assertions.assertTrue(service.authorize(request(user, container())).isAllowed());
        revoke(user);
        assertDenied(service.authorize(request(user, container())), DenialReason.GRANT_REVOKED);

        Assertions.assertEquals(
            2, source.opened.get(), "each decision must read the store again - there is no cache");
    }

    /**
     * The same holds for expiry
     */
    @Test
    public void expiringAffectsTheNextDecisionOnTheSameServiceInstance() throws Exception {
        String user = activeUser("policy-nocache-expiry");
        grant(user, Duration.ofMinutes(30));

        DbAccessPolicyService service = service();
        Assertions.assertTrue(service.authorize(request(user, container())).isAllowed());
        expireInThePast(user);
        assertDenied(service.authorize(request(user, container())), DenialReason.GRANT_EXPIRED);
    }

    /**
     * H2 really does pin the clock inside a transaction
     * <p>
     * Measured rather than assumed, and the H2 half of the pair whose PostgreSQL half is
     * {@code DbAccessPolicyPostgresTest.currentTimestampIsPinnedInsideATransaction}. The autocommit
     * requirement in {@code PolicySnapshotRepository} exists because of this: a snapshot read inside
     * a long transaction would keep returning the instant that transaction began, and an expired
     * grant would stay alive for as long as the transaction did.
     * <p>
     * The second half is not decoration. Without it this would also pass on a database whose clock
     * simply does not advance over 30ms, which is the reading that would make the first assertion
     * meaningless.
     */
    @Test
    public void currentTimestampIsPinnedInsideATransaction() throws Exception {
        try (Connection connection = database.openConnection()) {
            connection.setAutoCommit(false);
            OffsetDateTime first = readNow(connection);
            Thread.sleep(30);
            OffsetDateTime second = readNow(connection);
            connection.rollback();
            Assertions.assertEquals(
                first, second,
                "CURRENT_TIMESTAMP must be transaction-scoped on H2 too; if this ever changes, the"
                    + " autocommit requirement on the snapshot query can be revisited");
        }
        try (Connection a = database.openConnection(); Connection b = database.openConnection()) {
            OffsetDateTime first = readNow(a);
            Thread.sleep(30);
            OffsetDateTime second = readNow(b);
            Assertions.assertTrue(second.isAfter(first), "separate statements must see the clock move");
        }
    }

    /**
     * The database's clock is seen to move between two reads on separate connections
     * <p>
     * The observable consequence of the test above, and no more than that: this reads the clock the
     * way a decision does - one fresh connection per read - and requires the two readings to differ.
     * It does not call {@code authorize}, so it is not what establishes that each authorization gets
     * a connection of its own; {@link #revokingAffectsTheNextDecisionOnTheSameServiceInstance} is,
     * by counting that two decisions opened two connections.
     */
    @Test
    public void eachDecisionReadsAFreshDatabaseClock() throws Exception {
        OffsetDateTime first = readDatabaseNow();
        Thread.sleep(20);
        OffsetDateTime second = readDatabaseNow();
        Assertions.assertTrue(
            second.isAfter(first),
            "the authorization snapshot must not be pinned to a transaction start, got "
                + first + " then " + second);
    }

    // ---------------------------------------------------------------- helpers

    @NotNull
    private DbAccessPolicyService service() {
        return new DbAccessPolicyService(
            database::openConnection, DbAccessPolicyConfig.defaults(), PolicyTestSupport.systemClock());
    }

    @NotNull
    private AuthorizationDecision authorizeWithClock(@NotNull String user, @NotNull Clock clock) {
        return new DbAccessPolicyService(database::openConnection, DbAccessPolicyConfig.defaults(), clock)
            .authorize(request(user, container()));
    }

    @NotNull
    private static DBPDataSourceContainer container() {
        return PolicyTestSupport.container(PROJECT, CONNECTION, HOST, DATABASE);
    }

    @NotNull
    private static WriteAuthorizationRequest request(
        @Nullable String userId,
        @Nullable DBPDataSourceContainer container
    ) {
        return WriteAuthorizationRequest.of(userId, container, DbOperationCategory.SQL_TEXT);
    }

    private static void assertDenied(
        @NotNull AuthorizationDecision decision,
        @NotNull DenialReason expected
    ) {
        Assertions.assertFalse(decision.isAllowed(), "expected a denial, got an allow");
        Assertions.assertEquals(expected, decision.denialReason());
        Assertions.assertNotNull(decision.messageCode());
        Assertions.assertNotNull(decision.userMessage());
    }

    @NotNull
    private String activeUser(@NotNull String userId) throws Exception {
        touchedUsers.add(userId);
        try (Connection connection = database.openConnection()) {
            PolicyTestSupport.putUser(connection, userId, true);
        }
        return userId;
    }

    private void grant(@NotNull String userId, @NotNull Duration duration) throws Exception {
        grant(userId, duration, TempWriteTestSupport.ENDPOINT);
    }

    /**
     * A grant issued for a chosen endpoint
     * <p>
     * A test whose connection is not the default PostgreSQL one has to grant for that connection's
     * endpoint. Granting for the default and then authorizing a MySQL connection is a mismatch - the
     * six recorded values are the whole point - so it would be refused with {@code GRANT_STALE} and
     * the test would be measuring the wrong rule.
     */
    private void grant(
        @NotNull String userId,
        @NotNull Duration duration,
        @NotNull EndpointSnapshot endpoint
    ) throws Exception {
        TempWritePermissionKey key = new TempWritePermissionKey(userId, PROJECT, CONNECTION);
        touchedKeys.add(key);
        TempWriteMutationCoordinator.withoutAuditing(database::openConnection, repository)
            .grant(TempWriteTestSupport.grantRequest(
                key, TempWriteGrant.NO_ROW_REVISION, duration, "policy test", endpoint));
    }

    private void revoke(@NotNull String userId) throws Exception {
        TempWritePermissionKey key = new TempWritePermissionKey(userId, PROJECT, CONNECTION);
        TempWriteMutationCoordinator.withoutAuditing(database::openConnection, repository)
            .revoke(TempWriteTestSupport.revokeRequest(key, TempWriteGrant.FIRST_REVISION));
    }

    /**
     * Blanks the endpoint columns that schema version 3 added
     * <p>
     * Reproduces a grant written under version 2: driver, host and database are present, the three
     * columns version 3 added are not. The migration deliberately leaves them empty, so this is what
     * a real upgraded row looks like.
     */
    private void degradeToVersionTwoRow(@NotNull String userId) throws Exception {
        try (Connection connection = database.openConnection();
             PreparedStatement dbStat = connection.prepareStatement(
                 "UPDATE {table_prefix}DBAC_TW_CURRENT"
                     + " SET PROVIDER_ID=NULL, CONFIGURATION_TYPE=NULL, PORT_SNAPSHOT=NULL"
                     + " WHERE USER_ID=? AND PROJECT_ID=? AND CONNECTION_ID=?")
        ) {
            dbStat.setString(1, userId);
            dbStat.setString(2, PROJECT);
            dbStat.setString(3, CONNECTION);
            Assertions.assertEquals(1, dbStat.executeUpdate(), "the fixture must have written a grant row");
        }
    }

    /**
     * Moves the expiry an hour before the grant, so it is unambiguously in the past
     * <p>
     * An hour rather than {@code EXPIRES_AT = GRANTED_AT}, which this used to be. On Windows the
     * clock H2 reports advances in ~16ms steps, and the whole fixture-plus-decision sequence fits
     * inside one step, so {@code GRANTED_AT} and the decision's own {@code CURRENT_TIMESTAMP} came
     * out equal - making this an exclusive-boundary case by accident rather than the "expiry already
     * passed" case it is named for. That boundary now has its own test, and this one keeps clear of
     * it so the two cannot be confused.
     */
    private void expireInThePast(@NotNull String userId) throws Exception {
        try (Connection connection = database.openConnection();
             PreparedStatement dbStat = connection.prepareStatement(
                 "UPDATE {table_prefix}DBAC_TW_CURRENT SET EXPIRES_AT = DATEADD('HOUR', -1, GRANTED_AT)"
                     + " WHERE USER_ID=? AND PROJECT_ID=? AND CONNECTION_ID=?")
        ) {
            dbStat.setString(1, userId);
            dbStat.setString(2, PROJECT);
            dbStat.setString(3, CONNECTION);
            Assertions.assertEquals(1, dbStat.executeUpdate());
        }
    }

    /**
     * A service whose {@code {table_prefix}} resolves to one of the boundary schemas
     * <p>
     * The outer proxy substitutes the token first, so the connection the service gets already names
     * the boundary views and the inner substitution finds nothing left to replace.
     */
    @NotNull
    private DbAccessPolicyService boundaryService(@NotNull String target) {
        return new DbAccessPolicyService(
            () -> new InternalProxyConnection(
                database.openConnection(), DbacTestSupport.config(database.getDatabaseConfig(), target)),
            DbAccessPolicyConfig.defaults(),
            PolicyTestSupport.systemClock());
    }

    /**
     * Asserts that a boundary schema really puts the expiry where the test needs it
     *
     * @param predicate compares {@code g.EXPIRES_AT} against the same statement's clock
     */
    private void assertBoundaryFixture(
        @NotNull String target,
        @NotNull String userId,
        @NotNull String predicate,
        @NotNull String message
    ) throws Exception {
        try (Connection connection = database.openConnection();
             PreparedStatement dbStat = connection.prepareStatement(
                 "SELECT CASE WHEN " + predicate + " THEN 1 ELSE 0 END"
                     + " FROM " + target + ".DBAC_TW_CURRENT g WHERE g.USER_ID=?")
        ) {
            dbStat.setString(1, userId);
            try (java.sql.ResultSet dbResult = dbStat.executeQuery()) {
                Assertions.assertTrue(dbResult.next(), "the boundary view must expose the grant row");
                Assertions.assertEquals(1, dbResult.getInt(1), message);
            }
        }
    }

    @NotNull
    private static OffsetDateTime readDatabaseNow() throws Exception {
        try (Connection connection = database.openConnection()) {
            return readNow(connection);
        }
    }

    /**
     * Reads the database's clock on a connection the caller owns
     * <p>
     * Separate from {@link #readDatabaseNow()} so a test can read twice on the <em>same</em>
     * connection, which is the only way to see whether the clock is transaction-scoped.
     */
    @NotNull
    private static OffsetDateTime readNow(@NotNull Connection connection) throws Exception {
        try (PreparedStatement dbStat = connection.prepareStatement("SELECT CURRENT_TIMESTAMP");
             java.sql.ResultSet dbResult = dbStat.executeQuery()
        ) {
            Assertions.assertTrue(dbResult.next());
            OffsetDateTime now = dbResult.getObject(1, OffsetDateTime.class);
            Assertions.assertNotNull(now);
            return now;
        }
    }

    /**
     * A connection source that counts how often the decision reached the store
     */
    private final class CountingSource implements MetadataConnectionSource {
        private final AtomicInteger opened = new AtomicInteger();

        @NotNull
        @Override
        public Connection openConnection() throws SQLException {
            opened.incrementAndGet();
            return database.openConnection();
        }
    }
}
