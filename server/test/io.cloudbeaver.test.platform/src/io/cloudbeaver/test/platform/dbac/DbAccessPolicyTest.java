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
import io.cloudbeaver.service.dbac.policy.DbAccessDecision;
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

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Proxy;
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
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.LongSupplier;

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
     * The url the default fixture's own fields generate, so a test can leave the gate satisfied
     * <p>
     * Named rather than repeated because several tests need "a stored url that is not the variable
     * under test", and a typo in one of them would silently turn that test into a url-mismatch test.
     */
    private static final String MATCHING_URL = "jdbc:postgresql://db.internal.example:5432/customer_prod";

    /**
     * Schemas whose {@code DBAC_TW_CURRENT} is a view pinning {@code EXPIRES_AT} to the clock of
     * whatever statement reads it - see {@link #grantExpiringExactlyNowIsDenied}
     */
    private static final String AT_NOW_SCHEMA = "DBAC_POLICY_AT_NOW";
    private static final String AFTER_NOW_SCHEMA = "DBAC_POLICY_AFTER_NOW";

    /**
     * Schemas whose {@code DBAC_TW_CURRENT} puts {@code EXPIRES_AT} a fixed distance after the reading
     * statement's own clock, for the expiry window cases
     * <p>
     * {@link #MARGIN_AFTER_SCHEMA} leaves exactly {@code T_audit + δ + 1ms}, so check-1's boundary is
     * one millisecond of elapsed time away; {@link #MARGIN_AT_SCHEMA} leaves exactly
     * {@code T_audit + δ}, which check-1 refuses with nothing elapsed; {@link #FAR_FUTURE_SCHEMA}
     * leaves a thousand years, more than a {@code long} of nanoseconds can hold.
     */
    private static final String MARGIN_AFTER_SCHEMA = "DBAC_POLICY_MARGIN_AFTER";
    private static final String MARGIN_AT_SCHEMA = "DBAC_POLICY_MARGIN_AT";
    private static final String FAR_FUTURE_SCHEMA = "DBAC_POLICY_FAR_FUTURE";

    /** check-1's margin, {@code T_audit + δ}, as the default configuration sets it */
    private static final Duration AUDIT_MARGIN =
        DbAccessPolicyConfig.defaults().auditTimeout().plus(DbAccessPolicyConfig.defaults().expiryGuardMargin());

    /** check-2's margin, {@code δ} */
    private static final Duration EXECUTE_MARGIN = DbAccessPolicyConfig.defaults().expiryGuardMargin();

    /** What {@link #MARGIN_AFTER_SCHEMA} leaves: one millisecond more than check-1's margin */
    private static final Duration MARGIN_AFTER_REMAINING = AUDIT_MARGIN.plusMillis(1);

    private static final long ONE_MS = 1_000_000L;
    private static final long ONE_SECOND = 1_000_000_000L;
    private static final long ONE_HOUR = 3_600L * ONE_SECOND;

    /** Where the hand-moved monotonic clock starts, unless where it starts is the point of the case */
    private static final long BASE = 7_000_000_000_000L;

    /** How {@link #call} reports a call the window refused */
    private static final String REFUSED = "refused";

    private static CBDatabase database;

    private final TempWriteGrantRepository repository = new TempWriteGrantRepository();
    private final List<TempWritePermissionKey> touchedKeys = new ArrayList<>();
    private final List<String> touchedUsers = new ArrayList<>();

    /** Owns every bounded metadata source this class makes, and shuts each down after the test */
    private final MetadataLeaseFixture leases = new MetadataLeaseFixture();

    @AfterEach
    public void closeLeases() {
        leases.close();
    }

    @BeforeAll
    public static void startServer() throws Exception {
        CEAppStarter.startServerIfNotStarted();
        database = EmbeddedSecurityControllerFactory.getDbInstance();
        Assertions.assertNotNull(database, "CBDatabase instance must exist after server startup");

        try (Connection connection = database.openConnection()) {
            createBoundaryViews(connection, AT_NOW_SCHEMA, "CURRENT_TIMESTAMP");
            createBoundaryViews(
                connection, AFTER_NOW_SCHEMA, "DATEADD('MICROSECOND', 1, CURRENT_TIMESTAMP)");
            createBoundaryViews(connection, MARGIN_AFTER_SCHEMA,
                "DATEADD('MILLISECOND', " + MARGIN_AFTER_REMAINING.toMillis() + ", CURRENT_TIMESTAMP)");
            createBoundaryViews(connection, MARGIN_AT_SCHEMA,
                "DATEADD('MILLISECOND', " + AUDIT_MARGIN.toMillis() + ", CURRENT_TIMESTAMP)");
            createBoundaryViews(connection, FAR_FUTURE_SCHEMA, "DATEADD('YEAR', 1000, CURRENT_TIMESTAMP)");
        }
    }

    @AfterAll
    public static void dropBoundarySchemas() throws Exception {
        try (Connection connection = database.openConnection()) {
            for (String target : new String[]{
                AT_NOW_SCHEMA, AFTER_NOW_SCHEMA, MARGIN_AFTER_SCHEMA, MARGIN_AT_SCHEMA, FAR_FUTURE_SCHEMA}
            ) {
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
            leases.of(source), DbAccessPolicyConfig.defaults(), PolicyTestSupport.systemClock());

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
            leases.of(source), DbAccessPolicyConfig.defaults(), PolicyTestSupport.systemClock());

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
                leases.of(source), DbAccessPolicyConfig.defaults(), PolicyTestSupport.systemClock());

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
            leases.of(database::openConnection), DbAccessPolicyConfig.defaults(),
            PolicyTestSupport.failingClock(false)).authorize(request(user, container())));
        cases.put("clock throws an Error", new DbAccessPolicyService(
            leases.of(database::openConnection), DbAccessPolicyConfig.defaults(),
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
            leases.of(source), DbAccessPolicyConfig.defaults(), PolicyTestSupport.systemClock());

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
            leases.of(source), DbAccessPolicyConfig.defaults(), PolicyTestSupport.systemClock());

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
            leases.of(source), DbAccessPolicyConfig.defaults(), PolicyTestSupport.systemClock());

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

    // ------------------------------------------------------------- the URL gate
    //
    // The gate compares the stored url against the one the driver would generate. Independent
    // review then asked what happens when the driver has nothing to generate from: the platform
    // picks between several generation routines on per-driver predicates, and one of them
    // (DatabaseURL.generateUrlByTemplate(String, ...)) hands back connectionInfo.getUrl() unchanged
    // when the template is blank. On that route the comparison is storedUrl.equals(storedUrl),
    // which is true for any url, and the six fingerprinted fields stop proving anything.
    //
    // Each negative test below also asserts that the same container without that one deviation is
    // allowed. Every one of these refusals reports ENDPOINT_UNSUPPORTED, so the reason alone cannot
    // say which check fired - the allowed control is what shows the deviation is the cause rather
    // than some earlier gate.

    /**
     * A driver with no URL template cannot describe an endpoint, with or without a stored url
     * <p>
     * A blank template is not a missing detail, it is the endpoint generation rule being absent. So
     * the refusal does not depend on there being a stored url to compare: a connection whose driver
     * cannot say how it builds a URL is refused either way, because the six fields are only
     * meaningful as the inputs to a rule that exists.
     */
    @Test
    public void driverWithNoUrlTemplateCannotDescribeAnEndpoint() throws Exception {
        String user = activeUser("policy-no-template");
        grant(user, Duration.ofMinutes(30));

        // Control: the same connection with a template is allowed, so the template is the variable.
        Assertions.assertTrue(
            service().authorize(request(user, PolicyTestSupport.builder(PROJECT, CONNECTION)
                .generatedUrl(MATCHING_URL).build())).isAllowed(),
            "a driver that has a template must still be allowed");

        for (String blank : new String[]{null, "", "   ", "\t\n"}) {
            assertDenied(
                service().authorize(request(user, PolicyTestSupport.builder(PROJECT, CONNECTION)
                    .sampleUrl(blank).generatedUrl(MATCHING_URL).build())),
                DenialReason.ENDPOINT_UNSUPPORTED);
            // And with no stored url at all - nothing to compare, still refused.
            assertDenied(
                service().authorize(request(user, PolicyTestSupport.builder(PROJECT, CONNECTION)
                    .sampleUrl(blank).build())),
                DenialReason.ENDPOINT_UNSUPPORTED);
        }
    }

    /**
     * A URL template accessor that throws is refused rather than skipped
     */
    @Test
    public void failingUrlTemplateAccessorIsRefused() throws Exception {
        String user = activeUser("policy-template-throws");
        grant(user, Duration.ofMinutes(30));

        Assertions.assertTrue(
            service().authorize(request(user, PolicyTestSupport.builder(PROJECT, CONNECTION)
                .generatedUrl(MATCHING_URL).build())).isAllowed(),
            "the same connection with a working accessor must be allowed");

        assertDenied(
            service().authorize(request(user, PolicyTestSupport.builder(PROJECT, CONNECTION)
                .sampleUrlFails().generatedUrl(MATCHING_URL).build())),
            DenialReason.ENDPOINT_UNSUPPORTED);
    }

    /**
     * An {@code Error} from the template accessor is still a denial, by a different route
     * <p>
     * The gate catches {@code RuntimeException} and not {@code Error}, so an {@code Error} travels
     * to the service's outer handler - which keeps the key and denies with the reason a store
     * failure gives. Both outcomes are denials and neither lets the {@code Error} out of the policy
     * service, which is the contract worth pinning; the assertion names the route so a later change
     * that swallowed the {@code Error} into the endpoint gate would show up here rather than pass
     * silently.
     */
    @Test
    public void errorFromUrlTemplateAccessorStillDenies() throws Exception {
        String user = activeUser("policy-template-errors");
        grant(user, Duration.ofMinutes(30));

        AuthorizationDecision decision = service().authorize(
            request(user, PolicyTestSupport.builder(PROJECT, CONNECTION)
                .sampleUrlErrors().generatedUrl(MATCHING_URL).build()));

        Assertions.assertFalse(decision.isAllowed(), "an Error must never become an allow");
        assertDenied(decision, DenialReason.PERMISSION_STORE_UNAVAILABLE);
        Assertions.assertNotNull(
            decision.key(), "the key was established before the driver was asked, so it is kept");
        Assertions.assertNotNull(decision.auditPayload(), "a keyed denial carries its audit payload");
    }

    /**
     * A generated url that cannot be produced leaves nothing to compare against
     */
    @Test
    public void unusableGeneratedUrlIsRefused() throws Exception {
        String user = activeUser("policy-generated-unusable");
        grant(user, Duration.ofMinutes(30));

        Assertions.assertTrue(
            service().authorize(request(user, PolicyTestSupport.builder(PROJECT, CONNECTION)
                .generatedUrl(MATCHING_URL).build())).isAllowed(),
            "the same connection with a usable generator must be allowed");

        // null answer, and a thrown one - the platform declares a checked DBException here, and a
        // provider can raise an unchecked failure of its own.
        assertDenied(
            service().authorize(request(user, PolicyTestSupport.builder(PROJECT, CONNECTION)
                .generatedUrlIsNull().generatedUrl(MATCHING_URL).build())),
            DenialReason.ENDPOINT_UNSUPPORTED);
        assertDenied(
            service().authorize(request(user, PolicyTestSupport.builder(PROJECT, CONNECTION)
                .generatedUrlFails().generatedUrl(MATCHING_URL).build())),
            DenialReason.ENDPOINT_UNSUPPORTED);
    }

    /**
     * A refusal from the URL gate carries no trace of either url
     * <p>
     * The gate reads two urls and a template, any of which can embed userinfo - a generic driver
     * template carries {@code {user}:{password}@} literally. None of the three may reach a decision,
     * an audit payload, a message or a failure string, so the sentinel is planted in the stored url
     * and in the template and the whole rendered decision is checked.
     */
    @Test
    public void urlGateRefusalsCarryNoCredential() throws Exception {
        String user = activeUser("policy-url-gate-secrets");
        grant(user, Duration.ofMinutes(30));

        String secretUrl = "jdbc:postgresql://someone:" + PolicyTestSupport.SECRET_SENTINEL
            + "@other-prod.internal.example:5432/other_db";
        String secretTemplate = "jdbc:postgresql://{user}:" + PolicyTestSupport.SECRET_SENTINEL
            + "@{host}[:{port}]/[{database}]";

        for (DBPDataSourceContainer container : new DBPDataSourceContainer[]{
            // stored url disagrees with the fields, and carries a credential
            PolicyTestSupport.builder(PROJECT, CONNECTION).generatedUrl(secretUrl).build(),
            // the template itself carries one, and the stored url disagrees
            PolicyTestSupport.builder(PROJECT, CONNECTION)
                .sampleUrl(secretTemplate).generatedUrl(secretUrl).build(),
            // no template, so the refusal happens before any comparison
            PolicyTestSupport.builder(PROJECT, CONNECTION)
                .sampleUrl(null).generatedUrl(secretUrl).build(),
            // the generator fails while a credential-bearing url is stored
            PolicyTestSupport.builder(PROJECT, CONNECTION)
                .generatedUrlFails().generatedUrl(secretUrl).build()}
        ) {
            AuthorizationDecision decision = service().authorize(request(user, container));
            Assertions.assertFalse(decision.isAllowed(), "each of these must be refused");
            String rendered = decision + " " + decision.auditPayload()
                + " " + decision.userMessage() + " " + decision.messageCode();
            Assertions.assertFalse(
                rendered.contains(PolicyTestSupport.SECRET_SENTINEL),
                "the URL gate must not render a credential; reason was " + decision.denialReason());
        }
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
            leases.of(source), DbAccessPolicyConfig.defaults(), PolicyTestSupport.systemClock());

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
            leases.of(source), DbAccessPolicyConfig.defaults(), PolicyTestSupport.systemClock());

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
            leases.of(source), DbAccessPolicyConfig.defaults(), PolicyTestSupport.systemClock());

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
            leases.of(() -> {
                throw new SQLException("Injected metadata outage", "08006");
            }),
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
            leases.of(source), DbAccessPolicyConfig.defaults(), PolicyTestSupport.systemClock());

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

    // ---------------------------------------------------------------- the expiry window
    //
    // authorize() still answers one question - is the grant unexpired right now, by the database's
    // own comparison - and the boundary tests above keep a grant with one microsecond left allowed.
    // The margin is applied afterwards, by an ExpiryWindow the caller opens immediately before
    // authorize. These tests move the window's monotonic clock by hand and read the remaining
    // lifetime from views that put EXPIRES_AT at a known distance from the statement's own clock, so
    // every boundary below is exact rather than approximately where a sleep happened to land.

    /**
     * EX-1: check-1 is strict at {@code T_audit + δ}, and the lifetime it works from is the database's
     * <p>
     * With {@code T_audit + δ + 1ms} left, one millisecond minus a nanosecond of elapsed time leaves a
     * nanosecond of margin and must be kept; exactly one millisecond leaves the remaining lifetime
     * equal to the margin, which is not greater than it, and must be refused; two milliseconds is
     * past it. A refusal is the expiry denial for the same grant, with no remaining lifetime.
     * <p>
     * This node's clock is four seconds ahead of the database throughout - inside the skew allowance,
     * so authorize still allows - and the remaining lifetime must still be exactly what the view put
     * there. One measured against the JVM's clock would be four seconds short, and here negative. The
     * monotonic clock must be read once, when the window opens, and never by authorize.
     */
    @Test
    public void ex1CheckOneIsStrictAtTheAuditMargin() throws Exception {
        String user = activeUser("policy-ex1");
        grant(user, Duration.ofMinutes(30));
        assertMarginFixture(user);
        Clock ahead = PolicyTestSupport.clockOffsetFrom(readDatabaseNow().toInstant(), Duration.ofSeconds(4));

        List<String> violations = new ArrayList<>();
        for (long elapsed : new long[]{0, ONE_MS - 1, ONE_MS, 2 * ONE_MS}) {
            String what = "check-1 at " + elapsed + "ns";
            ManualNanoClock clock = new ManualNanoClock(BASE);
            Attempt attempt = attempt(MARGIN_AFTER_SCHEMA, user, clock, MetadataDelay.NONE, ahead);
            AuthorizationDecision allow = attempt.decision();
            if (attempt.readsAtOpen() != 1 || attempt.readsByAuthorize() != 0) {
                violations.add(what + ": the monotonic clock must be read once when the window opens and never"
                    + " by authorize, read " + attempt.readsAtOpen() + " and " + attempt.readsByAuthorize());
            }
            if (!allow.isAllowed()) {
                violations.add(what + ": authorize must allow a grant with " + MARGIN_AFTER_REMAINING
                    + " left while this node's clock is four seconds ahead, got " + allow.denialReason());
                continue;
            }
            if (!MARGIN_AFTER_REMAINING.equals(allow.remainingLifetime())) {
                violations.add(what + ": the remaining lifetime must be exactly EXPIRES_AT - DB_NOW = "
                    + MARGIN_AFTER_REMAINING + ", got " + allow.remainingLifetime());
            }
            clock.set(BASE + elapsed);
            expectWindow(violations, what, allow, attempt.window().requireMarginBeforeAudit(), elapsed < ONE_MS);
        }
        Assertions.assertTrue(violations.isEmpty(), "EX-1 (H2): " + String.join("; ", violations));
    }

    /**
     * EX-2: check-2 is strict at {@code δ}, counted from before authorize
     * <p>
     * The same view as EX-1, so check-1 passes with nothing elapsed. The clock then moves to where
     * the audit insert would have left it: {@code remaining - δ} minus a nanosecond is kept, exactly
     * {@code remaining - δ} is refused, a millisecond more is refused. The audit itself, and the
     * compensating row a refusal here needs, belong to the enforcement gate and are not tested here.
     */
    @Test
    public void ex2CheckTwoIsStrictAtTheExecuteMargin() throws Exception {
        String user = activeUser("policy-ex2");
        grant(user, Duration.ofMinutes(30));
        assertMarginFixture(user);
        long boundary = MARGIN_AFTER_REMAINING.minus(EXECUTE_MARGIN).toNanos();

        List<String> violations = new ArrayList<>();
        for (long elapsed : new long[]{boundary - 1, boundary, boundary + ONE_MS}) {
            String what = "check-2 at " + elapsed + "ns";
            ManualNanoClock clock = new ManualNanoClock(BASE);
            Attempt attempt = attempt(MARGIN_AFTER_SCHEMA, user, clock, MetadataDelay.NONE, PolicyTestSupport.systemClock());
            AuthorizationDecision allow = attempt.decision();
            if (!allow.isAllowed()) {
                violations.add(what + ": authorize must allow, got " + allow.denialReason());
                continue;
            }
            AuthorizationDecision afterAudit = attempt.window().requireMarginBeforeAudit();
            expectWindow(violations, what + ", check-1 with nothing elapsed", allow, afterAudit, true);
            clock.set(BASE + elapsed);
            expectWindow(violations, what, allow, attempt.window().requireMarginBeforeExecute(), elapsed < boundary);
        }
        Assertions.assertTrue(violations.isEmpty(), "EX-2 (H2): " + String.join("; ", violations));
    }

    /**
     * EX-4: a clock that runs backwards hands no time back, a refusal is final, and a window judges
     * only its own attempt
     * <p>
     * Four parts.
     * <ol>
     *   <li>With exactly {@code T_audit + δ} left, check-1 refuses with nothing elapsed - and a
     *       monotonic clock read a nanosecond or an hour before the start must not turn "nothing
     *       elapsed" into "less than nothing" and allow it.</li>
     *   <li>L-1: with {@code T_audit + δ + 1ms} left, check-1 refuses at one millisecond, exactly on
     *       its margin. check-2 must then return that very denial - with the clock still there, back
     *       at the start, or an hour before it - because it judges what check-1 left. Were it to
     *       judge the original allow, its smaller margin would let the write through.</li>
     *   <li>L-2: nothing can hand a window a decision from anywhere else. Its public methods are
     *       exactly {@code authorize(request)} and the two checks, which take no argument; no method
     *       of the window or the service that is not private takes an {@link AuthorizationDecision} or
     *       a window; its constructors and fields
     *       are private and the class is final; and {@code openExpiryWindow()} is the only way the
     *       service hands one out. So an allow measured in one attempt cannot be judged against a
     *       window opened later, whose count would start at zero.</li>
     *   <li>A denial and a recovery allow are carried through both checks as the same object, even
     *       an hour on.</li>
     * </ol>
     */
    @Test
    public void ex4ElapsedTimeNeverShrinks() throws Exception {
        String user = activeUser("policy-ex4");
        grant(user, Duration.ofMinutes(30));
        assertMarginFixture(user);
        assertBoundaryFixture(MARGIN_AT_SCHEMA, user,
            "g.EXPIRES_AT = DATEADD('MILLISECOND', " + AUDIT_MARGIN.toMillis() + ", CURRENT_TIMESTAMP)",
            "FIXTURE EX-4: the view must leave exactly T_audit + delta");
        List<String> violations = new ArrayList<>();

        for (long reading : new long[]{0, -1, -ONE_HOUR}) {
            ManualNanoClock clock = new ManualNanoClock(BASE);
            Attempt attempt = attempt(MARGIN_AT_SCHEMA, user, clock, MetadataDelay.NONE, PolicyTestSupport.systemClock());
            if (!attempt.decision().isAllowed()) {
                violations.add("exactly the margin left: authorize must allow, got " + attempt.decision().denialReason());
                continue;
            }
            clock.set(BASE + reading);
            expectWindow(violations, "exactly the margin left, clock " + reading + "ns from the start",
                attempt.decision(), attempt.window().requireMarginBeforeAudit(), false);
        }

        for (long back : new long[]{ONE_MS, 0, -ONE_HOUR}) {
            String what = "L-1, check-2 with the clock at " + back + "ns";
            ManualNanoClock clock = new ManualNanoClock(BASE);
            Attempt attempt = attempt(MARGIN_AFTER_SCHEMA, user, clock, MetadataDelay.NONE, PolicyTestSupport.systemClock());
            if (!attempt.decision().isAllowed()) {
                violations.add(what + ": authorize must allow, got " + attempt.decision().denialReason());
                continue;
            }
            clock.set(BASE + ONE_MS);
            AuthorizationDecision refused = attempt.window().requireMarginBeforeAudit();
            expectWindow(violations, what + ", check-1 at 1ms", attempt.decision(), refused, false);
            clock.set(BASE + back);
            AuthorizationDecision afterExecute = attempt.window().requireMarginBeforeExecute();
            if (afterExecute != refused) {
                violations.add(what + ": check-2 must return check-1's refusal itself, got " + outcome(afterExecute));
            }
        }

        Class<DbAccessPolicyService.ExpiryWindow> window = DbAccessPolicyService.ExpiryWindow.class;
        Set<String> publicApi = new TreeSet<>();
        for (Method method : window.getDeclaredMethods()) {
            if (Modifier.isPublic(method.getModifiers())) {
                publicApi.add(signature(method));
            }
        }
        Set<String> expectedApi = new TreeSet<>(List.of(
            "authorize(WriteAuthorizationRequest)", "requireMarginBeforeAudit()", "requireMarginBeforeExecute()"));
        if (!expectedApi.equals(publicApi)) {
            violations.add("L-2: the window's public methods must be exactly " + expectedApi + ", got " + publicApi);
        }
        // Every method anything outside these two classes can call - public, protected or package-private,
        // declared or inherited - must take neither a decision nor a window. Either would be a way to put a
        // decision in front of a window that did not make it, or a window in front of a decision it did
        // not measure.
        List<Method> reachable = new ArrayList<>(List.of(window.getMethods()));
        reachable.addAll(List.of(DbAccessPolicyService.class.getMethods()));
        for (Class<?> owner : List.of(window, DbAccessPolicyService.class)) {
            for (Method method : owner.getDeclaredMethods()) {
                if (!Modifier.isPrivate(method.getModifiers()) && !method.isSynthetic()) {
                    reachable.add(method);
                }
            }
        }
        for (Method method : reachable) {
            for (Class<?> parameter : method.getParameterTypes()) {
                if (AuthorizationDecision.class.isAssignableFrom(parameter) || parameter == window) {
                    violations.add("L-2: " + method.getDeclaringClass().getSimpleName() + "." + signature(method)
                        + " lets a caller put a decision and a window together that do not belong together");
                }
            }
        }
        for (var constructor : window.getDeclaredConstructors()) {
            if (!Modifier.isPrivate(constructor.getModifiers())) {
                violations.add("L-2: constructor " + constructor + " must be private");
            }
        }
        for (var field : window.getDeclaredFields()) {
            if (!Modifier.isPrivate(field.getModifiers())) {
                violations.add("L-2: field " + field.getName() + " must be private");
            }
        }
        if (!Modifier.isFinal(window.getModifiers())) {
            violations.add("L-2: the window class must be final");
        }
        List<String> makers = new ArrayList<>();
        for (Method method : DbAccessPolicyService.class.getMethods()) {
            if (method.getReturnType() == window) {
                makers.add(signature(method));
            }
        }
        if (!List.of("openExpiryWindow()").equals(makers)) {
            violations.add("L-2: openExpiryWindow() must be the only way to get a window, got " + makers);
        }

        ManualNanoClock laterClock = new ManualNanoClock(BASE);
        DbAccessPolicyService service = marginService(
            MARGIN_AFTER_SCHEMA, PolicyTestSupport.systemClock(), laterClock, MetadataDelay.NONE);
        DbAccessPolicyService.ExpiryWindow deniedWindow = service.openExpiryWindow();
        AuthorizationDecision noGrant = deniedWindow.authorize(request(activeUser("policy-ex4-nogrant"), container()));
        DbAccessPolicyService.ExpiryWindow rollbackWindow = service.openExpiryWindow();
        AuthorizationDecision recovery = rollbackWindow.authorize(new WriteAuthorizationRequest(
            null, null, DbOperationCategory.TRANSACTION_ROLLBACK, null, false));
        Assertions.assertEquals(DenialReason.NO_GRANT, noGrant.denialReason(), "FIXTURE EX-4: a user with no grant");
        Assertions.assertEquals(
            AuthorizationDecision.RECOVERY_GRANT_ID, recovery.appliedGrantId(), "FIXTURE EX-4: a recovery allow");
        laterClock.set(BASE + ONE_HOUR);
        for (DbAccessPolicyService.ExpiryWindow one : List.of(deniedWindow, rollbackWindow)) {
            AuthorizationDecision decided = one == deniedWindow ? noGrant : recovery;
            AuthorizationDecision afterAudit = one.requireMarginBeforeAudit();
            AuthorizationDecision afterExecute = one.requireMarginBeforeExecute();
            if (afterAudit != decided || afterExecute != decided) {
                violations.add("a " + outcome(decided) + " must stay the same object through both checks, got "
                    + outcome(afterAudit) + " and " + outcome(afterExecute));
            }
        }
        Assertions.assertTrue(violations.isEmpty(), "EX-4: " + String.join("; ", violations));
    }

    /**
     * EX-M1: time spent on the metadata path is counted, wherever it is spent
     * <p>
     * The window is opened before authorize, so everything authorize waits for is inside the elapsed
     * time check-1 subtracts: the pool handing out a connection (before the database reads its
     * clock), the statement returning (after), and the connection closing (after the result is
     * read). Each is given one millisecond minus a nanosecond, which must be kept, and exactly one
     * millisecond, which must be refused; the last two rows spread the same totals across all three.
     * A window that took its starting reading any later than it is opened - at the first check, or
     * from inside authorize - would miss these delays and keep every row.
     */
    @Test
    public void exM1MetadataDelayIsCounted() throws Exception {
        String user = activeUser("policy-exm1");
        grant(user, Duration.ofMinutes(30));
        assertMarginFixture(user);

        record Case(String name, MetadataDelay delay, boolean kept) {
        }

        Case[] cases = {
            new Case("no delay", MetadataDelay.NONE, true),
            new Case("pool wait 1ms - 1ns", new MetadataDelay(ONE_MS - 1, 0, 0), true),
            new Case("pool wait 1ms", new MetadataDelay(ONE_MS, 0, 0), false),
            new Case("statement 1ms - 1ns", new MetadataDelay(0, ONE_MS - 1, 0), true),
            new Case("statement 1ms", new MetadataDelay(0, ONE_MS, 0), false),
            new Case("close 1ms - 1ns", new MetadataDelay(0, 0, ONE_MS - 1), true),
            new Case("close 1ms", new MetadataDelay(0, 0, ONE_MS), false),
            new Case("spread over all three, 1ms - 1ns", new MetadataDelay(400_000, 300_000, 299_999), true),
            new Case("spread over all three, 1ms", new MetadataDelay(400_000, 300_000, 300_000), false),
        };
        List<String> violations = new ArrayList<>();
        for (Case one : cases) {
            ManualNanoClock clock = new ManualNanoClock(BASE);
            Attempt attempt = attempt(MARGIN_AFTER_SCHEMA, user, clock, one.delay(), PolicyTestSupport.systemClock());
            Assertions.assertEquals(BASE + one.delay().total(), clock.peek(),
                "FIXTURE EX-M1 " + one.name() + ": the metadata path must have moved the clock");
            if (attempt.readsAtOpen() != 1 || attempt.readsByAuthorize() != 0) {
                violations.add(one.name() + ": the monotonic clock must be read once when the window opens and"
                    + " never by authorize, read " + attempt.readsAtOpen() + " and " + attempt.readsByAuthorize());
            }
            if (!attempt.decision().isAllowed()) {
                violations.add(one.name() + ": authorize must allow, got " + attempt.decision().denialReason());
                continue;
            }
            expectWindow(violations, one.name(), attempt.decision(),
                attempt.window().requireMarginBeforeAudit(), one.kept());
        }
        Assertions.assertTrue(violations.isEmpty(), "EX-M1: " + String.join("; ", violations));
    }

    /**
     * EX-M2: the verdict is monotone in the metadata delay
     * <p>
     * A grid of delays from none to a quarter of the {@code long} range, each in its own attempt.
     * Below one millisecond check-1 keeps the allow and check-2 at the same reading keeps it too; at
     * one millisecond and beyond both refuse. Walking the grid upwards, once a delay has been refused
     * no longer delay may be kept.
     */
    @Test
    public void exM2TheVerdictIsMonotoneInTheDelay() throws Exception {
        String user = activeUser("policy-exm2");
        grant(user, Duration.ofMinutes(30));
        assertMarginFixture(user);

        long[] delays = {
            0, 1, ONE_MS / 2, ONE_MS - 1, ONE_MS, ONE_MS + 1, 2 * ONE_MS, ONE_SECOND,
            MARGIN_AFTER_REMAINING.toNanos(), MARGIN_AFTER_REMAINING.plus(AUDIT_MARGIN).toNanos(),
            ONE_HOUR, Long.MAX_VALUE / 4};
        List<String> violations = new ArrayList<>();
        boolean refusedAlready = false;
        for (long delay : delays) {
            String what = "metadata delay " + delay + "ns";
            ManualNanoClock clock = new ManualNanoClock(BASE);
            Attempt attempt = attempt(
                MARGIN_AFTER_SCHEMA, user, clock, MetadataDelay.query(delay), PolicyTestSupport.systemClock());
            Assertions.assertEquals(BASE + delay, clock.peek(), "FIXTURE EX-M2 " + what + ": the clock must have moved");
            AuthorizationDecision allow = attempt.decision();
            if (!allow.isAllowed()) {
                violations.add(what + ": authorize must allow, got " + allow.denialReason());
                continue;
            }
            AuthorizationDecision afterAudit = attempt.window().requireMarginBeforeAudit();
            AuthorizationDecision afterExecute = attempt.window().requireMarginBeforeExecute();
            boolean kept = afterAudit == allow;
            expectWindow(violations, what + ", check-1", allow, afterAudit, delay < ONE_MS);
            if (kept) {
                expectWindow(violations, what + ", check-2", allow, afterExecute, true);
            } else if (afterExecute != afterAudit) {
                violations.add(what + ": check-2 must hand check-1's refusal back unchanged, got " + outcome(afterExecute));
            }
            if (refusedAlready && kept) {
                violations.add(what + ": kept after a shorter delay had been refused");
            }
            refusedAlready |= !kept;
        }
        Assertions.assertTrue(violations.isEmpty(), "EX-M2: " + String.join("; ", violations));
    }

    /**
     * EX-M3: a delay between the checks turns the allow into a denial, measured from before authorize
     * <p>
     * Half a millisecond on the metadata path leaves check-1 standing. The clock then moves to where
     * a slow audit would leave it: {@code remaining - δ} minus a nanosecond, counted from the moment
     * the window opened, is kept, and exactly {@code remaining - δ} is refused. A window that counted
     * check-2's elapsed time from the end of authorize, or from check-1, would be half a millisecond
     * short at the boundary and keep it. Run with the half millisecond both before the database reads
     * its clock (pool) and after (statement).
     */
    @Test
    public void exM3ADelayBetweenTheChecksIsMeasuredFromBeforeAuthorize() throws Exception {
        String user = activeUser("policy-exm3");
        grant(user, Duration.ofMinutes(30));
        assertMarginFixture(user);
        long metadata = ONE_MS / 2;
        long boundary = MARGIN_AFTER_REMAINING.minus(EXECUTE_MARGIN).toNanos();

        List<String> violations = new ArrayList<>();
        for (MetadataDelay delay : new MetadataDelay[]{MetadataDelay.pool(metadata), MetadataDelay.query(metadata)}) {
            for (long total : new long[]{boundary - 1, boundary}) {
                String what = (delay.poolNanos() > 0 ? "pool" : "statement") + " delay, check-2 at " + total + "ns";
                ManualNanoClock clock = new ManualNanoClock(BASE);
                Attempt attempt = attempt(MARGIN_AFTER_SCHEMA, user, clock, delay, PolicyTestSupport.systemClock());
                Assertions.assertEquals(BASE + metadata, clock.peek(), "FIXTURE EX-M3 " + what + ": the clock must have moved");
                AuthorizationDecision allow = attempt.decision();
                if (!allow.isAllowed()) {
                    violations.add(what + ": authorize must allow, got " + allow.denialReason());
                    continue;
                }
                AuthorizationDecision afterAudit = attempt.window().requireMarginBeforeAudit();
                expectWindow(violations, what + ", check-1", allow, afterAudit, true);
                clock.set(BASE + total);
                expectWindow(violations, what, allow,
                    attempt.window().requireMarginBeforeExecute(), total < boundary);
            }
        }
        Assertions.assertTrue(violations.isEmpty(), "EX-M3: " + String.join("; ", violations));
    }

    /**
     * EX-M4: a clock that goes back after a metadata delay gives nothing back
     * <p>
     * Two sequences. In the first the metadata delay alone - one millisecond - crosses check-1's
     * boundary, and the clock then reads a nanosecond less, the start, or an hour before it; check-2
     * must return check-1's refusal, the same object. In the second the metadata delay leaves check-1
     * standing and the audit crosses check-2's boundary; when the clock then goes back to where the
     * metadata path left it, to the start or before it, the attempt is already over - another
     * authorize and either check are refused, and the refusal stands as its last answer.
     */
    @Test
    public void exM4ARegressionAfterAMetadataDelayGivesNothingBack() throws Exception {
        String user = activeUser("policy-exm4");
        grant(user, Duration.ofMinutes(30));
        assertMarginFixture(user);
        List<String> violations = new ArrayList<>();

        for (long back : new long[]{ONE_MS - 1, 0, -ONE_HOUR}) {
            String what = "1ms metadata delay, clock back at " + back + "ns";
            ManualNanoClock clock = new ManualNanoClock(BASE);
            Attempt crossed = attempt(
                MARGIN_AFTER_SCHEMA, user, clock, MetadataDelay.query(ONE_MS), PolicyTestSupport.systemClock());
            if (!crossed.decision().isAllowed()) {
                violations.add(what + ": authorize must allow, got " + crossed.decision().denialReason());
                continue;
            }
            AuthorizationDecision refused = crossed.window().requireMarginBeforeAudit();
            expectWindow(violations, what + ", check-1", crossed.decision(), refused, false);
            clock.set(BASE + back);
            AuthorizationDecision afterExecute = crossed.window().requireMarginBeforeExecute();
            if (afterExecute != refused) {
                violations.add(what + ": check-2 must return check-1's refusal itself, got " + outcome(afterExecute));
            }
        }

        long metadata = ONE_MS - 100_000;
        long boundary = MARGIN_AFTER_REMAINING.minus(EXECUTE_MARGIN).toNanos();
        ManualNanoClock clock = new ManualNanoClock(BASE);
        Attempt audited = attempt(
            MARGIN_AFTER_SCHEMA, user, clock, MetadataDelay.query(metadata), PolicyTestSupport.systemClock());
        AuthorizationDecision allow = audited.decision();
        if (allow.isAllowed()) {
            expectWindow(violations, "check-1 after a " + metadata + "ns metadata delay", allow,
                audited.window().requireMarginBeforeAudit(), true);
            clock.set(BASE + boundary);
            expectWindow(violations, "check-2 at its boundary", allow,
                audited.window().requireMarginBeforeExecute(), false);
            for (long back : new long[]{metadata, 0, -ONE_HOUR}) {
                clock.set(BASE + back);
                for (Call next : Call.values()) {
                    String result = call(audited.window(), next, request(user, container()));
                    if (!REFUSED.equals(result)) {
                        violations.add("with the attempt over and the clock back at " + back + "ns, " + next
                            + " must be refused, got " + result);
                    }
                }
            }
        } else {
            violations.add("second sequence: authorize must allow, got " + allow.denialReason());
        }
        Assertions.assertTrue(violations.isEmpty(), "EX-M4: " + String.join("; ", violations));
    }

    /**
     * EX-M5: the monotonic clock wrapping, and lifetimes no {@code long} of nanoseconds can hold
     * <p>
     * {@code System.nanoTime()} may start anywhere and wrap, so only the difference of two readings
     * means anything. Each row puts the window's start somewhere awkward - just below
     * {@code Long.MAX_VALUE} so the metadata delay wraps, exactly on it, on {@code Long.MIN_VALUE},
     * just below zero - and the verdict must be exactly the one EX-1 gives for the same elapsed time.
     * <p>
     * Then a grant with a thousand years left, more than {@code Long.MAX_VALUE} nanoseconds, checked
     * after {@code Long.MAX_VALUE} nanoseconds - the longest interval the clock can express - has
     * elapsed. Both checks must keep it, and neither may overflow: converting that lifetime to
     * nanoseconds would.
     */
    @Test
    public void exM5TheClockWrapsAndLongLifetimesDoNotOverflow() throws Exception {
        String user = activeUser("policy-exm5");
        grant(user, Duration.ofMinutes(30));
        assertMarginFixture(user);

        record Case(String name, long start, long delay, boolean kept) {
        }

        Case[] cases = {
            new Case("wrapping past Long.MAX_VALUE, 1ms - 1ns", Long.MAX_VALUE - ONE_MS / 2, ONE_MS - 1, true),
            new Case("wrapping past Long.MAX_VALUE, 1ms", Long.MAX_VALUE - ONE_MS / 2, ONE_MS, false),
            new Case("starting on Long.MAX_VALUE, 1ms - 1ns", Long.MAX_VALUE, ONE_MS - 1, true),
            new Case("ending on Long.MAX_VALUE, 1ms", Long.MAX_VALUE - ONE_MS, ONE_MS, false),
            new Case("starting on Long.MIN_VALUE, 1ms - 1ns", Long.MIN_VALUE, ONE_MS - 1, true),
            new Case("starting on Long.MIN_VALUE, 1ms", Long.MIN_VALUE, ONE_MS, false),
            new Case("crossing zero, 1ms - 1ns", -ONE_MS / 2, ONE_MS - 1, true),
            new Case("crossing zero, 1ms", -ONE_MS / 2, ONE_MS, false),
        };
        List<String> violations = new ArrayList<>();
        for (Case one : cases) {
            ManualNanoClock clock = new ManualNanoClock(one.start());
            Attempt attempt = attempt(
                MARGIN_AFTER_SCHEMA, user, clock, MetadataDelay.query(one.delay()), PolicyTestSupport.systemClock());
            if (!attempt.decision().isAllowed()) {
                violations.add(one.name() + ": authorize must allow, got " + attempt.decision().denialReason());
                continue;
            }
            expectWindow(violations, one.name(), attempt.decision(),
                attempt.window().requireMarginBeforeAudit(), one.kept());
        }

        assertBoundaryFixture(FAR_FUTURE_SCHEMA, user, "g.EXPIRES_AT > DATEADD('YEAR', 999, CURRENT_TIMESTAMP)",
            "FIXTURE EX-M5: the view must leave a thousand years");
        ManualNanoClock clock = new ManualNanoClock(0);
        Attempt far = attempt(FAR_FUTURE_SCHEMA, user, clock, MetadataDelay.NONE, PolicyTestSupport.systemClock());
        AuthorizationDecision allow = far.decision();
        if (!allow.isAllowed()) {
            violations.add("a thousand years left: authorize must allow, got " + allow.denialReason());
        } else {
            if (allow.remainingLifetime() == null
                || allow.remainingLifetime().compareTo(Duration.ofNanos(Long.MAX_VALUE)) <= 0
            ) {
                violations.add("a thousand years left must be carried as more than Long.MAX_VALUE nanoseconds, got "
                    + allow.remainingLifetime());
            }
            clock.set(Long.MAX_VALUE);
            try {
                AuthorizationDecision afterAudit = far.window().requireMarginBeforeAudit();
                expectWindow(violations, "a thousand years left, Long.MAX_VALUE ns elapsed, check-1", allow, afterAudit, true);
                expectWindow(violations, "a thousand years left, Long.MAX_VALUE ns elapsed, check-2", allow,
                    far.window().requireMarginBeforeExecute(), true);
            } catch (ArithmeticException e) {
                violations.add("a thousand years left overflowed in the window: " + e.getClass().getName());
            }
        }
        Assertions.assertTrue(violations.isEmpty(), "EX-M5: " + String.join("; ", violations));
    }

    /**
     * EX-M6: no delay, start, regression, call order or clock failure turns a denial into an allow
     * <p>
     * Three parts, all through the window's own state; there is no way left to hand it a decision.
     * <ol>
     *   <li>Every combination of four starting points (both ends of the range among them), four
     *       metadata delays either side of check-1's boundary, and seven readings for check-2 -
     *       either side of its boundary, far past it, and back to or behind the start. Each is one
     *       attempt, authorize then check-1 then check-2, and every verdict is compared with an
     *       oracle that knows the true elapsed time - the test decides it and derives the clock
     *       readings from it - rather than recomputing it from the readings as the window must. A
     *       refusal from check-1 must be what check-2 returns, the same object; a denial followed by
     *       an allow is counted.</li>
     *   <li>The attempt's state machine, exhaustively: from each state a window can be in - just
     *       opened, authorized, after check-1, after check-2 - each of the three calls. Only
     *       authorize, check-1 and check-2, once each and in that order, are accepted. Every other
     *       call is refused and ends the attempt, so the call that would have been next is refused
     *       too. A request the service refuses outright - a null one - ends it the same way.</li>
     *   <li>A monotonic clock that throws. Opening a window fails, so there is no window. At check-1
     *       or check-2 the clock's own exception comes out unchanged, nothing is returned, and every
     *       later call is refused, so no allow can follow it - the same check retried at once, against
     *       a clock that works again, included. The window deliberately does not turn
     *       the failure into a denial of its own: the enforcement gate maps it to
     *       {@code PERMISSION_STORE_UNAVAILABLE}, and that mapping is a later slice's to build and
     *       test.</li>
     * </ol>
     */
    @Test
    public void exM6NoDelayOrRegressionTurnsADenialIntoAnAllow() throws Exception {
        String user = activeUser("policy-exm6");
        grant(user, Duration.ofMinutes(30));
        assertMarginFixture(user);
        long remaining = MARGIN_AFTER_REMAINING.toNanos();
        long auditMargin = AUDIT_MARGIN.toNanos();
        long executeMargin = EXECUTE_MARGIN.toNanos();
        long boundary = remaining - executeMargin;

        List<String> mismatches = new ArrayList<>();
        int attempts = 0;
        int evaluations = 0;
        int transitions = 0;
        for (long start : new long[]{0, Long.MAX_VALUE - ONE_MS / 2, Long.MIN_VALUE, -1}) {
            for (long delay : new long[]{0, ONE_MS - 1, ONE_MS, 5 * ONE_MS}) {
                for (long beforeExecute : new long[]{
                    delay, boundary - 1, boundary, 10 * ONE_SECOND, 0, -ONE_HOUR, -(1L << 62)}
                ) {
                    attempts++;
                    String what = "start " + start + ", metadata " + delay + "ns, check-2 at " + beforeExecute + "ns";
                    ManualNanoClock clock = new ManualNanoClock(start);
                    Attempt attempt = attempt(
                        MARGIN_AFTER_SCHEMA, user, clock, MetadataDelay.query(delay), PolicyTestSupport.systemClock());
                    AuthorizationDecision allow = attempt.decision();
                    Assertions.assertTrue(allow.isAllowed(), "FIXTURE EX-M6 " + what + ": authorize must allow");

                    clock.set(start + delay);
                    AuthorizationDecision first = attempt.window().requireMarginBeforeAudit();
                    long floor = delay;
                    boolean firstKept = remaining - floor > auditMargin;
                    evaluations++;
                    if ((first == allow) != firstKept) {
                        mismatches.add(what + ": check-1 gave " + outcome(first) + ", the oracle "
                            + (firstKept ? "keeps it" : "refuses it"));
                    }
                    clock.set(start + beforeExecute);
                    AuthorizationDecision second = attempt.window().requireMarginBeforeExecute();
                    evaluations++;
                    if (first != allow) {
                        if (second != first) {
                            mismatches.add(what + ": check-2 must return check-1's refusal itself, got " + outcome(second));
                        }
                        if (second != null && second.isAllowed()) {
                            transitions++;
                        }
                    } else {
                        floor = Math.max(floor, Math.max(0, beforeExecute));
                        boolean secondKept = remaining - floor > executeMargin;
                        if ((second == allow) != secondKept) {
                            mismatches.add(what + ": check-2 gave " + outcome(second) + ", the oracle "
                                + (secondKept ? "keeps it" : "refuses it"));
                        }
                    }
                }
            }
        }

        Call[] order = Call.values();
        int stateCases = 0;
        for (int done = 0; done <= order.length; done++) {
            for (Call next : order) {
                stateCases++;
                String where = "after " + done + " valid call(s), " + next;
                DbAccessPolicyService.ExpiryWindow window = marginService(
                    MARGIN_AFTER_SCHEMA, PolicyTestSupport.systemClock(), new ManualNanoClock(BASE), MetadataDelay.NONE)
                    .openExpiryWindow();
                for (int i = 0; i < done; i++) {
                    String result = call(window, order[i], request(user, container()));
                    if (REFUSED.equals(result)) {
                        mismatches.add("state machine, " + where + ": the valid call " + order[i] + " was refused");
                    }
                }
                boolean valid = done < order.length && next == order[done];
                String result = call(window, next, request(user, container()));
                if (valid == REFUSED.equals(result)) {
                    mismatches.add("state machine, " + where + (valid ? " must be accepted" : " must be refused")
                        + ", got " + result);
                }
                if (!valid && done < order.length) {
                    String following = call(window, order[done], request(user, container()));
                    if (!REFUSED.equals(following)) {
                        mismatches.add("state machine, " + where + " was refused, so the attempt is over, but "
                            + order[done] + " then gave " + following);
                    }
                }
            }
        }
        DbAccessPolicyService.ExpiryWindow refusedRequest = marginService(
            MARGIN_AFTER_SCHEMA, PolicyTestSupport.systemClock(), new ManualNanoClock(BASE), MetadataDelay.NONE)
            .openExpiryWindow();
        try {
            AuthorizationDecision result = refusedRequest.authorize(noRequest());
            mismatches.add("a null request must be refused, got " + outcome(result));
        } catch (IllegalArgumentException expected) {
            for (Call next : order) {
                String result = call(refusedRequest, next, request(user, container()));
                if (!REFUSED.equals(result)) {
                    mismatches.add("after a null request, " + next + " must be refused, got " + result);
                }
            }
        }

        Map<Integer, List<String>> expectedWithFailingClock = Map.of(
            2, List.of("AUTHORIZE an allow", "CHECK_1 threw", "CHECK_2 " + REFUSED),
            3, List.of("AUTHORIZE an allow", "CHECK_1 an allow", "CHECK_2 threw"));
        for (int failingRead = 1; failingRead <= 3; failingRead++) {
            String where = "a monotonic clock failing from read " + failingRead;
            DbAccessPolicyService service = new DbAccessPolicyService(
                leases.of(marginSource(MARGIN_AFTER_SCHEMA)), DbAccessPolicyConfig.defaults(), PolicyTestSupport.systemClock(),
                new FailingNanoClock(BASE, failingRead));
            DbAccessPolicyService.ExpiryWindow window;
            try {
                window = service.openExpiryWindow();
            } catch (ClockFailure e) {
                if (failingRead != 1) {
                    mismatches.add(where + ": opening the window must read the clock once, not " + failingRead + " times");
                }
                continue;
            }
            if (failingRead == 1) {
                mismatches.add(where + ": opening the window must read the clock, and so fail");
                continue;
            }
            List<String> outcomes = new ArrayList<>();
            for (Call next : order) {
                try {
                    outcomes.add(next + " " + call(window, next, request(user, container())));
                } catch (ClockFailure e) {
                    outcomes.add(next + " threw");
                }
            }
            if (!expectedWithFailingClock.get(failingRead).equals(outcomes)) {
                mismatches.add(where + ": expected " + expectedWithFailingClock.get(failingRead) + ", got " + outcomes);
            }
            for (Call next : order) {
                String result = call(window, next, request(user, container()));
                if (!REFUSED.equals(result)) {
                    mismatches.add(where + ": after the failure, " + next + " must be refused, got " + result);
                }
            }
        }

        // The same failure with a clock that works again straight afterwards, and the very check that
        // failed retried at once. The retry must be refused: the attempt ended when the check failed.
        Map<Integer, List<String>> expectedWithRecoveringClock = Map.of(
            2, List.of("AUTHORIZE an allow", "CHECK_1 threw", "CHECK_1 again " + REFUSED, "CHECK_2 " + REFUSED),
            3, List.of("AUTHORIZE an allow", "CHECK_1 an allow", "CHECK_2 threw", "CHECK_2 again " + REFUSED));
        for (int failingRead = 2; failingRead <= 3; failingRead++) {
            DbAccessPolicyService.ExpiryWindow window = new DbAccessPolicyService(
                leases.of(marginSource(MARGIN_AFTER_SCHEMA)), DbAccessPolicyConfig.defaults(), PolicyTestSupport.systemClock(),
                FailingNanoClock.once(BASE, failingRead)).openExpiryWindow();
            List<String> outcomes = new ArrayList<>();
            for (Call next : order) {
                try {
                    outcomes.add(next + " " + call(window, next, request(user, container())));
                } catch (ClockFailure e) {
                    outcomes.add(next + " threw");
                    outcomes.add(next + " again " + call(window, next, request(user, container())));
                }
            }
            if (!expectedWithRecoveringClock.get(failingRead).equals(outcomes)) {
                mismatches.add("a monotonic clock failing once, on read " + failingRead + ": expected "
                    + expectedWithRecoveringClock.get(failingRead) + ", got " + outcomes);
            }
        }

        String summary = attempts + " attempts, " + evaluations + " check evaluations, " + stateCases
            + " state-machine cases, " + mismatches.size() + " mismatches, " + transitions + " denial-to-allow transitions";
        Assertions.assertTrue(mismatches.isEmpty() && transitions == 0,
            "EX-M6 (" + summary + "): " + String.join("; ", mismatches.subList(0, Math.min(20, mismatches.size()))));
    }

    // ---------------------------------------------------------------- helpers

    @NotNull
    private DbAccessPolicyService service() {
        return new DbAccessPolicyService(
            leases.of(database::openConnection), DbAccessPolicyConfig.defaults(), PolicyTestSupport.systemClock());
    }

    @NotNull
    private AuthorizationDecision authorizeWithClock(@NotNull String user, @NotNull Clock clock) {
        return new DbAccessPolicyService(leases.of(database::openConnection), DbAccessPolicyConfig.defaults(), clock)
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
            leases.of(() -> new InternalProxyConnection(
                database.openConnection(), DbacTestSupport.config(database.getDatabaseConfig(), target))),
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

    // ---------------------------------------------------------------- expiry window helpers

    /**
     * Asserts that {@link #MARGIN_AFTER_SCHEMA} leaves exactly {@link #MARGIN_AFTER_REMAINING}
     */
    private void assertMarginFixture(@NotNull String userId) throws Exception {
        assertBoundaryFixture(MARGIN_AFTER_SCHEMA, userId,
            "g.EXPIRES_AT = DATEADD('MILLISECOND', " + MARGIN_AFTER_REMAINING.toMillis() + ", CURRENT_TIMESTAMP)",
            "FIXTURE: the margin view must leave exactly T_audit + delta + 1ms");
    }

    /**
     * One attempt, made the way the enforcement gate will make it: open the window, then authorize
     *
     * @param readsAtOpen how often opening the window read the monotonic clock
     * @param readsByAuthorize how often authorize read it
     */
    private record Attempt(
        @NotNull DbAccessPolicyService.ExpiryWindow window,
        @NotNull AuthorizationDecision decision,
        int readsAtOpen,
        int readsByAuthorize
    ) {
    }

    @NotNull
    private Attempt attempt(
        @NotNull String target,
        @NotNull String userId,
        @NotNull ManualNanoClock clock,
        @NotNull MetadataDelay delay,
        @NotNull Clock localClock
    ) {
        DbAccessPolicyService service = marginService(target, localClock, clock, delay);
        int before = clock.reads();
        DbAccessPolicyService.ExpiryWindow window = service.openExpiryWindow();
        int afterOpen = clock.reads();
        AuthorizationDecision decision = window.authorize(request(userId, container()));
        return new Attempt(window, decision, afterOpen - before, clock.reads() - afterOpen);
    }

    /**
     * A service over one of the boundary schemas, with a monotonic clock the test moves by hand
     * <p>
     * The metadata path moves that clock by the given delay, without reading it, at the point of the
     * read the delay names - which is how a slow pool, a slow statement or a slow close looks to a
     * window opened before authorize.
     */
    @NotNull
    private DbAccessPolicyService marginService(
        @NotNull String target,
        @NotNull Clock localClock,
        @NotNull ManualNanoClock monotonic,
        @NotNull MetadataDelay delay
    ) {
        MetadataConnectionSource plain = marginSource(target);
        MetadataConnectionSource source = () -> {
            monotonic.advance(delay.poolNanos());
            return delaying(plain.openConnection(), monotonic, delay);
        };
        return new DbAccessPolicyService(leases.of(source), DbAccessPolicyConfig.defaults(), localClock, monotonic);
    }

    /**
     * Metadata connections whose {@code {table_prefix}} resolves to one of the boundary schemas
     */
    @NotNull
    private static MetadataConnectionSource marginSource(@NotNull String target) {
        return () -> new InternalProxyConnection(
            database.openConnection(), DbacTestSupport.config(database.getDatabaseConfig(), target));
    }

    /** The three calls a window takes, in the only order it takes them */
    private enum Call {
        AUTHORIZE, CHECK_1, CHECK_2
    }

    /**
     * Makes one call on a window and describes what came back
     *
     * @return {@link #REFUSED} when the window refused the call, otherwise the decision's outcome.
     *     Any other exception - a failing clock - propagates.
     */
    @NotNull
    private static String call(
        @NotNull DbAccessPolicyService.ExpiryWindow window,
        @NotNull Call call,
        @Nullable WriteAuthorizationRequest request
    ) {
        try {
            AuthorizationDecision result = switch (call) {
                case AUTHORIZE -> window.authorize(request);
                case CHECK_1 -> window.requireMarginBeforeAudit();
                case CHECK_2 -> window.requireMarginBeforeExecute();
            };
            return outcome(result);
        } catch (IllegalStateException e) {
            return REFUSED;
        }
    }

    /**
     * A method as {@code name(SimpleParameterType, ...)}, for comparing an API against a list
     */
    @NotNull
    private static String signature(@NotNull Method method) {
        StringBuilder text = new StringBuilder(method.getName()).append('(');
        Class<?>[] parameters = method.getParameterTypes();
        for (int i = 0; i < parameters.length; i++) {
            text.append(i == 0 ? "" : ", ").append(parameters[i].getSimpleName());
        }
        return text.append(')').toString();
    }

    /**
     * Wraps a metadata connection so that its statement and its close move the monotonic clock
     */
    @NotNull
    private static Connection delaying(
        @NotNull Connection delegate,
        @NotNull ManualNanoClock clock,
        @NotNull MetadataDelay delay
    ) {
        return (Connection) Proxy.newProxyInstance(
            DbAccessPolicyTest.class.getClassLoader(), new Class<?>[]{Connection.class},
            (proxy, method, args) -> {
                Object result = invoke(delegate, method, args);
                if ("prepareStatement".equals(method.getName()) && result instanceof PreparedStatement statement) {
                    return Proxy.newProxyInstance(
                        DbAccessPolicyTest.class.getClassLoader(), new Class<?>[]{PreparedStatement.class},
                        (innerProxy, innerMethod, innerArgs) -> {
                            Object innerResult = invoke(statement, innerMethod, innerArgs);
                            if ("executeQuery".equals(innerMethod.getName())) {
                                clock.advance(delay.queryNanos());
                            }
                            return innerResult;
                        });
                }
                if ("close".equals(method.getName())) {
                    clock.advance(delay.closeNanos());
                }
                return result;
            });
    }

    @Nullable
    private static Object invoke(
        @NotNull Object target,
        @NotNull Method method,
        @Nullable Object[] args
    ) throws Throwable {
        try {
            return method.invoke(target, args);
        } catch (InvocationTargetException e) {
            throw e.getCause();
        }
    }

    /**
     * Checks one window result, collecting rather than failing
     * <p>
     * A kept allow must be the very object handed in. A refusal must be the expiry denial for that
     * allow: the same key, category, grant and expiry, {@code GRANT_EXPIRED}, no remaining lifetime,
     * and a payload recording exactly that.
     */
    private static void expectWindow(
        @NotNull List<String> violations,
        @NotNull String what,
        @NotNull AuthorizationDecision allow,
        @Nullable AuthorizationDecision result,
        boolean kept
    ) {
        if (kept) {
            if (result != allow) {
                violations.add(what + ": expected the same allow back, got " + outcome(result));
            }
            return;
        }
        if (result == null || result.isAllowed() || result.denialReason() != DenialReason.GRANT_EXPIRED) {
            violations.add(what + ": expected GRANT_EXPIRED, got " + outcome(result));
            return;
        }
        if (!Objects.equals(allow.key(), result.key())
            || allow.operationCategory() != result.operationCategory()
            || !Objects.equals(allow.appliedGrantId(), result.appliedGrantId())
            || !Objects.equals(allow.expiresAt(), result.expiresAt())
            || result.remainingLifetime() != null
            || result.auditPayload() == null
            || result.auditPayload().decision() != DbAccessDecision.DENY
            || result.auditPayload().denialReason() != DenialReason.GRANT_EXPIRED
        ) {
            violations.add(what + ": the expiry denial must describe the allow it replaced, got " + result);
        }
    }

    @NotNull
    private static String outcome(@Nullable AuthorizationDecision decision) {
        if (decision == null) {
            return "null";
        }
        return decision.isAllowed() ? "an allow" : "a denial for " + decision.denialReason();
    }

    /**
     * No request at all, for the one case that hands the window a null
     */
    @Nullable
    private static WriteAuthorizationRequest noRequest() {
        return null;
    }

    /**
     * The monotonic clock, moved by hand
     * <p>
     * Additions wrap exactly as {@code System.nanoTime()} does, which is what the wrap cases rely on.
     * Reads by the code under test are counted; the test's own look goes through {@link #peek()} and
     * is not.
     */
    private static final class ManualNanoClock implements LongSupplier {
        private long now;
        private int reads;

        ManualNanoClock(long start) {
            this.now = start;
        }

        @Override
        public long getAsLong() {
            reads++;
            return now;
        }

        void set(long value) {
            now = value;
        }

        void advance(long nanos) {
            now += nanos;
        }

        long peek() {
            return now;
        }

        int reads() {
            return reads;
        }
    }

    /**
     * A monotonic clock that works until a chosen read and throws there - from then on, or just that once
     */
    private static final class FailingNanoClock implements LongSupplier {
        private final long value;
        private final int failingRead;
        private final boolean recovers;
        private int reads;

        FailingNanoClock(long value, int failingRead) {
            this(value, failingRead, false);
        }

        private FailingNanoClock(long value, int failingRead, boolean recovers) {
            this.value = value;
            this.failingRead = failingRead;
            this.recovers = recovers;
        }

        /** Fails on that one read and works again afterwards */
        @NotNull
        static FailingNanoClock once(long value, int failingRead) {
            return new FailingNanoClock(value, failingRead, true);
        }

        @Override
        public long getAsLong() {
            reads++;
            if (recovers ? reads == failingRead : reads >= failingRead) {
                throw new ClockFailure();
            }
            return value;
        }
    }

    /**
     * What {@link FailingNanoClock} throws: its own type, so it cannot be mistaken for the window refusing a call
     */
    private static final class ClockFailure extends RuntimeException {
        ClockFailure() {
            super("the monotonic clock failed");
        }
    }

    /**
     * How far the metadata path moves the monotonic clock, and where
     * <p>
     * The pool delay comes before the statement runs, and so before the database reads its clock; the
     * statement delay as the statement returns, after it has; the close delay after the result has
     * been read.
     */
    private record MetadataDelay(long poolNanos, long queryNanos, long closeNanos) {
        static final MetadataDelay NONE = new MetadataDelay(0, 0, 0);

        @NotNull
        static MetadataDelay pool(long nanos) {
            return new MetadataDelay(nanos, 0, 0);
        }

        @NotNull
        static MetadataDelay query(long nanos) {
            return new MetadataDelay(0, nanos, 0);
        }

        long total() {
            return poolNanos + queryNanos + closeNanos;
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
