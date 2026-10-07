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

import io.cloudbeaver.service.dbac.policy.AuthorizationDecision;
import io.cloudbeaver.service.dbac.policy.DbAccessDecision;
import io.cloudbeaver.service.dbac.policy.DbAccessPolicyConfig;
import io.cloudbeaver.service.dbac.policy.DbAccessPolicyService;
import io.cloudbeaver.service.dbac.policy.DbOperationCategory;
import io.cloudbeaver.service.dbac.policy.DenialReason;
import io.cloudbeaver.service.dbac.policy.WriteAuthorizationRequest;
import io.cloudbeaver.service.dbac.tempwrite.MetadataConnectionSource;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.jkiss.dbeaver.model.DBPDataSourceContainer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Properties;
import java.util.function.LongSupplier;

/**
 * The same decision, on the engine that runs in production
 * <p>
 * H2 proves the logic; PostgreSQL proves the SQL. The authorization snapshot uses a derived table, a
 * left join and a {@code CASE} comparison against {@code CURRENT_TIMESTAMP}, and a query that is
 * portable in principle is not portable until it has run. These tests also cover the one thing H2
 * cannot show at all: that the answer does not change with the session's time zone, which is the
 * defect schema version 2 exists to remove.
 * <p>
 * Rather than depend on the CloudBeaver schema being installed here, these tests create the two
 * tables the query reads - {@code CB_USER} and {@code DBAC_TW_CURRENT} - in a throwaway schema with
 * the column types the real schema declares, and point the query at it through the same
 * {@code {table_prefix}} mechanism production uses. What is being verified is the statement, its
 * portability and its behaviour across session zones.
 * <p>
 * <b>What these tests do not establish.</b> Running against a real PostgreSQL is not the same as
 * establishing that a grant on a PostgreSQL connection is confined to one database. It is not: a
 * {@code PostgreDatabase} is a {@code JDBCRemoteInstance}, so the provider opens a separate JDBC
 * connection per database, and the {@code database} component of the endpoint fingerprint names the
 * initial one. What keeps a grant-eligible connection to a single database today is a
 * <em>coupling</em>, not a control designed for the purpose: listing other databases needs
 * {@code @dbeaver-show-non-default-db@}, that key is not on the property allowlist, and such a
 * connection is therefore refused before any grant applies. A mitigation that holds because of an
 * unrelated rule is worth writing down precisely because someone will later have a good reason to
 * relax that rule. See {@code docs/db-access-control-endpoint-identity.md} section 3.3.
 */
public class DbAccessPolicyPostgresTest {

    private static final String URL = System.getProperty(
        "dbac.test.postgres.url", "jdbc:postgresql://localhost:55432/dbactest");
    private static final String USER = System.getProperty("dbac.test.postgres.user", "postgres");
    private static final String PASSWORD = System.getProperty("dbac.test.postgres.password", "dbactest");

    /** When true, an unreachable PostgreSQL fails the run instead of skipping it. */
    private static final boolean REQUIRED =
        Boolean.parseBoolean(System.getProperty("dbac.test.postgres.required", "false"));

    private static final String PROJECT = "pg-policy-project";
    private static final String CONNECTION = "pg-policy-connection";
    private static final String HOST = "db.internal.example";
    private static final String DATABASE = "customer_prod";
    private static final String PROVIDER = "postgresql";
    private static final String DRIVER = "postgres-jdbc";
    private static final String CONFIGURATION_TYPE = "MANUAL";
    private static final String PORT = "5432";

    private static Driver driver;
    private static boolean available;
    private static String unusableBecause;
    private static String schema;

    /**
     * Schemas whose {@code DBAC_TW_CURRENT} is a view pinning {@code EXPIRES_AT} to the clock of
     * whatever statement reads it - see {@link #grantExpiringExactlyNowIsDeniedOnPostgres}
     */
    private static String atNowSchema;
    private static String afterNowSchema;

    /**
     * A schema whose {@code DBAC_TW_CURRENT} leaves exactly {@link #MARGIN_AFTER_REMAINING}, for the
     * expiry window cases - see {@link #ex1CheckOneIsStrictAtTheAuditMarginOnPostgres}
     */
    private static String marginSchema;

    /** check-1's margin, {@code T_audit + δ}, as the default configuration sets it */
    private static final Duration AUDIT_MARGIN =
        DbAccessPolicyConfig.defaults().auditTimeout().plus(DbAccessPolicyConfig.defaults().expiryGuardMargin());

    /** check-2's margin, {@code δ} */
    private static final Duration EXECUTE_MARGIN = DbAccessPolicyConfig.defaults().expiryGuardMargin();

    /** What {@link #marginSchema} leaves: one millisecond more than check-1's margin */
    private static final Duration MARGIN_AFTER_REMAINING = AUDIT_MARGIN.plusMillis(1);

    private static final long ONE_MS = 1_000_000L;

    /** Where the hand-moved monotonic clock starts */
    private static final long BASE = 7_000_000_000_000L;

    private final List<String> touchedUsers = new ArrayList<>();

    /** Owns every bounded metadata source this class makes, and shuts each down after the test */
    private final MetadataLeaseFixture leases = new MetadataLeaseFixture();

    @AfterEach
    public void closeLeases() {
        leases.close();
    }

    @BeforeAll
    public static void prepareSchema() throws Exception {
        available = probe();
        if (!available) {
            if (REQUIRED) {
                Assertions.fail("POSTGRESQL NOT VERIFIED: " + URL
                    + " could not be used and the run required it - " + unusableBecause);
            }
            return;
        }
        schema = "dbac_policy_" + Long.toHexString(System.nanoTime());
        try (Connection connection = open()) {
            exec(connection, "CREATE SCHEMA " + schema);
            exec(connection, "CREATE TABLE " + schema + ".CB_USER ("
                + "USER_ID VARCHAR(128) NOT NULL PRIMARY KEY,"
                + " IS_ACTIVE CHAR(1) NOT NULL)");
            exec(connection, "CREATE TABLE " + schema + ".DBAC_TW_CURRENT ("
                + "USER_ID VARCHAR(128) NOT NULL,"
                + " PROJECT_ID VARCHAR(255) NOT NULL,"
                + " CONNECTION_ID VARCHAR(255) NOT NULL,"
                + " GRANT_ID VARCHAR(128) NOT NULL,"
                + " REVISION BIGINT NOT NULL,"
                + " GRANTED_BY VARCHAR(128) NOT NULL,"
                + " GRANTED_AT TIMESTAMP WITH TIME ZONE NOT NULL,"
                + " EXPIRES_AT TIMESTAMP WITH TIME ZONE NOT NULL,"
                + " REASON VARCHAR(1000) NOT NULL,"
                + " REVOKED_AT TIMESTAMP WITH TIME ZONE,"
                + " REVOKED_BY VARCHAR(128),"
                + " REVOKE_REASON VARCHAR(1000),"
                + " PROVIDER_ID VARCHAR(128),"
                + " DRIVER_ID VARCHAR(128) NOT NULL,"
                + " CONFIGURATION_TYPE VARCHAR(32),"
                + " HOST_SNAPSHOT VARCHAR(255),"
                + " PORT_SNAPSHOT VARCHAR(16),"
                + " DATABASE_SNAPSHOT VARCHAR(255),"
                + " PRIMARY KEY (USER_ID, PROJECT_ID, CONNECTION_ID))");
            atNowSchema = schema + "_at";
            afterNowSchema = schema + "_after";
            createBoundaryViews(connection, atNowSchema, "CURRENT_TIMESTAMP");
            createBoundaryViews(
                connection, afterNowSchema, "CURRENT_TIMESTAMP + INTERVAL '1 microsecond'");
            marginSchema = schema + "_margin";
            createBoundaryViews(connection, marginSchema, marginExpression());
        }
    }

    /**
     * The expiry {@link #marginSchema} reports, as SQL evaluated against the reading statement's clock
     */
    @NotNull
    private static String marginExpression() {
        return "CURRENT_TIMESTAMP + INTERVAL '" + MARGIN_AFTER_REMAINING.toMillis() + " milliseconds'";
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
     */
    private static void createBoundaryViews(
        @NotNull Connection connection,
        @NotNull String target,
        @NotNull String expiresAtExpression
    ) throws SQLException {
        exec(connection, "CREATE SCHEMA " + target);
        exec(connection, "CREATE VIEW " + target + ".CB_USER AS"
            + " SELECT USER_ID, IS_ACTIVE FROM " + schema + ".CB_USER");
        exec(connection, "CREATE VIEW " + target + ".DBAC_TW_CURRENT AS"
            + " SELECT USER_ID, PROJECT_ID, CONNECTION_ID, GRANT_ID,"
            + " " + expiresAtExpression + " AS EXPIRES_AT,"
            + " REVOKED_AT, PROVIDER_ID, DRIVER_ID, CONFIGURATION_TYPE,"
            + " HOST_SNAPSHOT, PORT_SNAPSHOT, DATABASE_SNAPSHOT"
            + " FROM " + schema + ".DBAC_TW_CURRENT");
    }

    /**
     * Drops the throwaway schema, so a container reused across runs does not accumulate them
     */
    @AfterAll
    public static void dropTestSchema() throws Exception {
        if (!available || schema == null) {
            return;
        }
        try (Connection connection = open()) {
            for (String target : new String[]{marginSchema, afterNowSchema, atNowSchema, schema}) {
                if (target != null) {
                    exec(connection, "DROP SCHEMA IF EXISTS " + target + " CASCADE");
                }
            }
        }
    }

    @AfterEach
    public void cleanUp() throws Exception {
        if (!available) {
            return;
        }
        try (Connection connection = open()) {
            for (String user : touchedUsers) {
                exec(connection, "DELETE FROM " + schema + ".DBAC_TW_CURRENT WHERE USER_ID = '" + user + "'");
                exec(connection, "DELETE FROM " + schema + ".CB_USER WHERE USER_ID = '" + user + "'");
            }
        }
        touchedUsers.clear();
    }

    // ---------------------------------------------------------------- the query runs at all

    /**
     * The snapshot statement is accepted by PostgreSQL and yields the single allow
     */
    @Test
    public void activeGrantIsAllowedOnPostgres() throws Exception {
        skipIfUnavailable();
        String user = activeUser("pg-allow");
        putGrant(user, Duration.ofMinutes(30), false);

        AuthorizationDecision decision = service("UTC").authorize(request(user, container()));
        Assertions.assertTrue(decision.isAllowed(), decision.denialReason() + " was not expected");
        Assertions.assertNotNull(decision.appliedGrantId());
    }

    /**
     * Absence, expiry and revocation are three distinguishable answers, not one empty result
     */
    @Test
    public void absenceExpiryAndRevocationAreDistinguished() throws Exception {
        skipIfUnavailable();
        String noGrant = activeUser("pg-nogrant");
        assertDenied(service("UTC").authorize(request(noGrant, container())), DenialReason.NO_GRANT);

        String expired = activeUser("pg-expired");
        putGrant(expired, Duration.ofMinutes(-5), false);
        assertDenied(service("UTC").authorize(request(expired, container())), DenialReason.GRANT_EXPIRED);

        String revoked = activeUser("pg-revoked");
        putGrant(revoked, Duration.ofMinutes(30), true);
        assertDenied(service("UTC").authorize(request(revoked, container())), DenialReason.GRANT_REVOKED);
    }

    /**
     * The boundary is exclusive: expiring at the reading statement's own clock is expired
     * <p>
     * Run against {@link #atNowSchema}, so {@code EXPIRES_AT} and the statement's
     * {@code CURRENT_TIMESTAMP} are one value rather than two a few microseconds apart. The
     * precondition is asserted first, because a fixture that missed the boundary would make this
     * test pass for the wrong reason - and would keep passing if the comparison were widened to
     * {@code >=}.
     */
    @Test
    public void grantExpiringExactlyNowIsDeniedOnPostgres() throws Exception {
        skipIfUnavailable();
        String user = activeUser("pg-boundary-at");
        putGrant(user, Duration.ofMinutes(30), false);
        assertBoundaryFixture(atNowSchema, user, "g.EXPIRES_AT = CURRENT_TIMESTAMP",
            "the fixture must put EXPIRES_AT exactly on the reading statement's own clock");

        assertDenied(
            service("UTC", atNowSchema).authorize(request(user, container())),
            DenialReason.GRANT_EXPIRED);
    }

    /**
     * One tick past the boundary is still inside the grant
     * <p>
     * The other half of the pair: it fails if the comparison is ever tightened by a fudge factor,
     * which would deny a grant that has not expired.
     */
    @Test
    public void grantExpiringOneTickAfterNowIsAllowedOnPostgres() throws Exception {
        skipIfUnavailable();
        String user = activeUser("pg-boundary-after");
        putGrant(user, Duration.ofMinutes(30), false);
        assertBoundaryFixture(afterNowSchema, user, "g.EXPIRES_AT > CURRENT_TIMESTAMP",
            "the fixture must put EXPIRES_AT after the reading statement's own clock");

        Assertions.assertTrue(
            service("UTC", afterNowSchema).authorize(request(user, container())).isAllowed(),
            "a grant expiring one microsecond from now has not expired");
    }

    /**
     * EX-1 on PostgreSQL: check-1 is strict at {@code T_audit + δ}, from the database's own lifetime
     * <p>
     * The H2 case, on the engine that runs in production: the view leaves exactly
     * {@code T_audit + δ + 1ms}, so one millisecond minus a nanosecond of elapsed time is kept and
     * exactly one millisecond is refused. The session runs in a zone nine hours from UTC and this
     * node's clock is four seconds ahead of the database's - neither may change the remaining
     * lifetime, which must be exactly what the view put there. The monotonic clock is read once when
     * the window opens and never by authorize.
     */
    @Test
    public void ex1CheckOneIsStrictAtTheAuditMarginOnPostgres() throws Exception {
        skipIfUnavailable();
        String user = activeUser("pg-ex1");
        putGrant(user, Duration.ofMinutes(30), false);
        assertBoundaryFixture(marginSchema, user, "g.EXPIRES_AT = " + marginExpression(),
            "FIXTURE EX-1: the margin view must leave exactly T_audit + delta + 1ms");
        Clock ahead;
        try (Connection connection = open()) {
            ahead = PolicyTestSupport.clockOffsetFrom(readNow(connection).toInstant(), Duration.ofSeconds(4));
        }

        List<String> violations = new ArrayList<>();
        for (long elapsed : new long[]{0, ONE_MS - 1, ONE_MS, 2 * ONE_MS}) {
            String what = "check-1 at " + elapsed + "ns";
            ManualNanoClock clock = new ManualNanoClock(BASE);
            DbAccessPolicyService service = marginService("Asia/Seoul", ahead, clock);
            final DbAccessPolicyService.ExpiryWindow window = service.openExpiryWindow();
            int readsAtOpen = clock.reads();
            AuthorizationDecision allow = window.authorize(request(user, container()));
            if (readsAtOpen != 1 || clock.reads() != 1) {
                violations.add(what + ": the monotonic clock must be read once when the window opens and never"
                    + " by authorize, read " + readsAtOpen + " and " + (clock.reads() - readsAtOpen));
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
            expectWindow(violations, what, allow, window.requireMarginBeforeAudit(), elapsed < ONE_MS);
        }
        Assertions.assertTrue(violations.isEmpty(), "EX-1 (PostgreSQL): " + String.join("; ", violations));
    }

    /**
     * EX-2 on PostgreSQL: check-2 is strict at {@code δ}, counted from before authorize
     * <p>
     * check-1 passes with nothing elapsed; then {@code remaining - δ} minus a nanosecond is kept,
     * exactly {@code remaining - δ} is refused, and a millisecond more is refused.
     */
    @Test
    public void ex2CheckTwoIsStrictAtTheExecuteMarginOnPostgres() throws Exception {
        skipIfUnavailable();
        String user = activeUser("pg-ex2");
        putGrant(user, Duration.ofMinutes(30), false);
        assertBoundaryFixture(marginSchema, user, "g.EXPIRES_AT = " + marginExpression(),
            "FIXTURE EX-2: the margin view must leave exactly T_audit + delta + 1ms");
        long boundary = MARGIN_AFTER_REMAINING.minus(EXECUTE_MARGIN).toNanos();

        List<String> violations = new ArrayList<>();
        for (long elapsed : new long[]{boundary - 1, boundary, boundary + ONE_MS}) {
            String what = "check-2 at " + elapsed + "ns";
            ManualNanoClock clock = new ManualNanoClock(BASE);
            DbAccessPolicyService service = marginService("UTC", PolicyTestSupport.systemClock(), clock);
            DbAccessPolicyService.ExpiryWindow window = service.openExpiryWindow();
            AuthorizationDecision allow = window.authorize(request(user, container()));
            if (!allow.isAllowed()) {
                violations.add(what + ": authorize must allow, got " + allow.denialReason());
                continue;
            }
            AuthorizationDecision afterAudit = window.requireMarginBeforeAudit();
            expectWindow(violations, what + ", check-1 with nothing elapsed", allow, afterAudit, true);
            clock.set(BASE + elapsed);
            expectWindow(violations, what, allow, window.requireMarginBeforeExecute(), elapsed < boundary);
        }
        Assertions.assertTrue(violations.isEmpty(), "EX-2 (PostgreSQL): " + String.join("; ", violations));
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
        try (Connection connection = open();
             PreparedStatement dbStat = connection.prepareStatement(
                 "SELECT CASE WHEN " + predicate + " THEN 1 ELSE 0 END"
                     + " FROM " + target + ".DBAC_TW_CURRENT g WHERE g.USER_ID = ?")
        ) {
            dbStat.setString(1, userId);
            try (ResultSet dbResult = dbStat.executeQuery()) {
                Assertions.assertTrue(dbResult.next(), "the boundary view must expose the grant row");
                Assertions.assertEquals(1, dbResult.getInt(1), message);
            }
        }
    }

    /**
     * A port move is stale on PostgreSQL too
     * <p>
     * The comparison is engine-independent Java, so this is not about PostgreSQL semantics - it is
     * about the {@code PORT_SNAPSHOT} column being read back correctly from a real PostgreSQL row
     * rather than only from H2.
     */
    @Test
    public void portChangeIsDeniedOnPostgres() throws Exception {
        skipIfUnavailable();
        String user = activeUser("pg-port-move");
        putGrant(user, Duration.ofMinutes(30), false);

        assertDenied(
            service("UTC").authorize(request(user,
                PolicyTestSupport.builder(PROJECT, CONNECTION).port("5433").build())),
            DenialReason.GRANT_STALE);
    }

    // ---------------------------------------------------------------- user state

    @Test
    public void inactiveAndMissingUsersAreDeniedOnPostgres() throws Exception {
        skipIfUnavailable();
        String inactive = "pg-inactive";
        touchedUsers.add(inactive);
        try (Connection connection = open()) {
            exec(connection, "INSERT INTO " + schema + ".CB_USER (USER_ID, IS_ACTIVE) VALUES ('"
                + inactive + "', 'N')");
        }
        putGrant(inactive, Duration.ofMinutes(30), false);
        assertDenied(service("UTC").authorize(request(inactive, container())), DenialReason.USER_INACTIVE);

        String ghost = "pg-ghost";
        touchedUsers.add(ghost);
        putGrant(ghost, Duration.ofMinutes(30), false);
        assertDenied(service("UTC").authorize(request(ghost, container())), DenialReason.USER_INACTIVE);
    }

    // ---------------------------------------------------------------- session time zones

    /**
     * The same grant produces the same answer whatever zone the session is in
     * <p>
     * This is the property schema version 2 was introduced for. Reading through a session in Seoul,
     * UTC and New York must agree, because the stored value is an instant rather than a wall clock.
     */
    @Test
    public void theDecisionIsTheSameInEverySessionZone() throws Exception {
        skipIfUnavailable();
        String user = activeUser("pg-zones");
        putGrant(user, Duration.ofMinutes(30), false);

        for (String zone : new String[]{"UTC", "Asia/Seoul", "America/New_York"}) {
            Assertions.assertTrue(
                service(zone).authorize(request(user, container())).isAllowed(),
                "an unexpired grant must be allowed when the session zone is " + zone);
        }
    }

    /**
     * And an expired one is denied in every zone
     * <p>
     * The dangerous failure would be a grant that looks unexpired to a session nine hours ahead.
     */
    @Test
    public void anExpiredGrantIsDeniedInEverySessionZone() throws Exception {
        skipIfUnavailable();
        String user = activeUser("pg-zones-expired");
        putGrant(user, Duration.ofMinutes(-1), false);

        for (String zone : new String[]{"UTC", "Asia/Seoul", "America/New_York"}) {
            assertDenied(
                service(zone).authorize(request(user, container())),
                DenialReason.GRANT_EXPIRED);
        }
    }

    // ---------------------------------------------------------------- isolation and snapshot

    @Test
    public void userProjectAndConnectionAreIsolatedOnPostgres() throws Exception {
        skipIfUnavailable();
        String owner = activeUser("pg-owner");
        String other = activeUser("pg-other");
        putGrant(owner, Duration.ofMinutes(30), false);

        Assertions.assertTrue(service("UTC").authorize(request(owner, container())).isAllowed());
        assertDenied(service("UTC").authorize(request(other, container())), DenialReason.NO_GRANT);
        assertDenied(
            service("UTC").authorize(request(owner,
                PolicyTestSupport.container("pg-other-project", CONNECTION, HOST, DATABASE))),
            DenialReason.NO_GRANT);
        assertDenied(
            service("UTC").authorize(request(owner,
                PolicyTestSupport.container(PROJECT, CONNECTION + "-replica", HOST, DATABASE))),
            DenialReason.NO_GRANT);
    }

    @Test
    public void staleSnapshotIsDeniedOnPostgres() throws Exception {
        skipIfUnavailable();
        String user = activeUser("pg-stale");
        putGrant(user, Duration.ofMinutes(30), false);

        assertDenied(
            service("UTC").authorize(request(user,
                PolicyTestSupport.container(PROJECT, CONNECTION, "another-host", DATABASE))),
            DenialReason.GRANT_STALE);
    }

    // ---------------------------------------------------------------- failures

    @Test
    public void storeFailureIsDeniedOnPostgres() throws Exception {
        skipIfUnavailable();
        String user = activeUser("pg-storefail");
        putGrant(user, Duration.ofMinutes(30), false);

        DbAccessPolicyService service = new DbAccessPolicyService(
            leases.of(() -> {
                throw new SQLException("Injected metadata outage", "08006");
            }),
            DbAccessPolicyConfig.defaults(), PolicyTestSupport.systemClock());
        assertDenied(
            service.authorize(request(user, container())), DenialReason.PERMISSION_STORE_UNAVAILABLE);
    }

    /**
     * A connection already inside a transaction is refused rather than trusted
     * <p>
     * PostgreSQL pins {@code CURRENT_TIMESTAMP} to the start of the enclosing transaction, so a
     * snapshot taken there would report a clock from whenever that transaction began - and an expired
     * grant could keep passing. The repository refuses the connection, and the service turns that
     * into the same denial an outage produces.
     * <p>
     * <b>The grant here is live and the schema prefix resolves</b>, which is what makes the denial
     * mean something. Both matter: with a live grant, removing the guard produces an allow rather
     * than a different denial, so the assertion below is the thing standing between the guard and a
     * silent regression. That was not true until the connection was wrapped - see the comment on the
     * source below.
     */
    @Test
    public void connectionNotInAutoCommitIsRefused() throws Exception {
        skipIfUnavailable();
        String user = activeUser("pg-autocommit");
        putGrant(user, Duration.ofMinutes(30), false);

        MetadataConnectionSource inTransaction = () -> {
            // Wrapped exactly as service(zone, target) wraps, and that is the whole point of this
            // line. Without the wrapper the statement reaches PostgreSQL with a literal
            // {table_prefix} in it and fails with a syntax error - which the service also turns
            // into PERMISSION_STORE_UNAVAILABLE. The assertion below therefore passed whether or
            // not the auto-commit guard existed, so this test could not protect the guard it is
            // named after. Removing the guard from an isolated copy was how that was found: the
            // test stayed green and the denial came from the syntax error instead.
            Connection raw = open();
            raw.setAutoCommit(false);
            return PrefixingConnection.wrap(raw, schema + ".");
        };
        DbAccessPolicyService service = new DbAccessPolicyService(
            leases.of(inTransaction), DbAccessPolicyConfig.defaults(), PolicyTestSupport.systemClock());
        assertDenied(
            service.authorize(request(user, container())), DenialReason.PERMISSION_STORE_UNAVAILABLE);
    }

    /**
     * PostgreSQL really does pin the clock inside a transaction
     * <p>
     * Measured rather than assumed, because the whole autocommit rule rests on it.
     */
    @Test
    public void currentTimestampIsPinnedInsideATransaction() throws Exception {
        skipIfUnavailable();
        try (Connection connection = open()) {
            connection.setAutoCommit(false);
            OffsetDateTime first = readNow(connection);
            Thread.sleep(30);
            OffsetDateTime second = readNow(connection);
            connection.rollback();
            Assertions.assertEquals(
                first, second,
                "CURRENT_TIMESTAMP must be transaction-scoped; if this ever changes, the autocommit"
                    + " requirement on the snapshot query can be revisited");
        }
        try (Connection a = open(); Connection b = open()) {
            OffsetDateTime first = readNow(a);
            Thread.sleep(30);
            OffsetDateTime second = readNow(b);
            Assertions.assertTrue(second.isAfter(first), "separate statements must see the clock move");
        }
    }

    // ---------------------------------------------------------------- helpers

    private static void skipIfUnavailable() {
        org.junit.jupiter.api.Assumptions.assumeTrue(available, "PostgreSQL is not available");
    }

    /**
     * Whether the disposable PostgreSQL can be used, recording why not when it cannot
     * <p>
     * The driver is loaded from {@code deploy/drivers} through its own class loader rather than
     * looked up through {@code DriverManager}. In the OSGi test runtime {@code DriverManager} does
     * not see the PostgreSQL driver at all, so a {@code DriverManager} lookup reports "unreachable"
     * for a database that is running and reachable - which in required mode fails the build for the
     * wrong reason and in ordinary mode silently skips every test here. The two existing PostgreSQL
     * test classes load the driver this way for the same reason.
     */
    private static boolean probe() {
        try {
            driver = loadDriver();
        } catch (Exception e) {
            driver = null;
            unusableBecause = "the PostgreSQL JDBC driver could not be loaded (" + e + ")";
            return false;
        }
        try (Connection connection = open()) {
            if (connection == null) {
                unusableBecause = "the driver did not accept " + URL;
                return false;
            }
            return true;
        } catch (Exception e) {
            unusableBecause = "connecting failed (" + e + ")";
            return false;
        }
    }

    @NotNull
    private static Connection open() throws SQLException {
        Connection connection = driver.connect(URL, credentials());
        if (connection == null) {
            throw new SQLException("The PostgreSQL driver did not accept " + URL);
        }
        return connection;
    }

    @NotNull
    private static Properties credentials() {
        Properties properties = new Properties();
        properties.setProperty("user", USER);
        properties.setProperty("password", PASSWORD);
        return properties;
    }

    @NotNull
    private static Driver loadDriver() throws Exception {
        File jar = findDriverJar();
        if (jar == null) {
            throw new IllegalStateException("PostgreSQL JDBC driver jar not found under deploy/drivers");
        }
        URLClassLoader loader = new URLClassLoader(
            new URL[]{jar.toURI().toURL()}, Driver.class.getClassLoader());
        return (Driver) Class.forName("org.postgresql.Driver", true, loader)
            .getDeclaredConstructor().newInstance();
    }

    @Nullable
    private static File findDriverJar() {
        File dir = new File(System.getProperty("user.dir"));
        for (int i = 0; i < 6 && dir != null; i++, dir = dir.getParentFile()) {
            File candidate = new File(dir, "deploy/drivers/postgresql");
            File[] jars = candidate.listFiles((d, name) ->
                name.startsWith("postgresql-") && name.endsWith(".jar"));
            if (jars != null && jars.length > 0) {
                return jars[0];
            }
        }
        return null;
    }

    /**
     * A service whose connections run in the given session time zone and resolve
     * {@code {table_prefix}} to the throwaway schema
     */
    @NotNull
    private DbAccessPolicyService service(@NotNull String zone) {
        return service(zone, schema);
    }

    /**
     * The same, but resolving {@code {table_prefix}} to a chosen schema
     */
    @NotNull
    private DbAccessPolicyService service(@NotNull String zone, @NotNull String target) {
        MetadataConnectionSource source = () -> {
            Connection raw = open();
            try (java.sql.Statement dbStat = raw.createStatement()) {
                dbStat.execute("SET TIME ZONE '" + zone + "'");
            }
            return PrefixingConnection.wrap(raw, target + ".");
        };
        return new DbAccessPolicyService(
            leases.of(source), DbAccessPolicyConfig.defaults(), PolicyTestSupport.systemClock());
    }

    /**
     * A service over {@link #marginSchema}, in the given session zone, with the given clocks
     */
    @NotNull
    private DbAccessPolicyService marginService(
        @NotNull String zone,
        @NotNull Clock localClock,
        @NotNull LongSupplier monotonic
    ) {
        MetadataConnectionSource source = () -> {
            Connection raw = open();
            try (java.sql.Statement dbStat = raw.createStatement()) {
                dbStat.execute("SET TIME ZONE '" + zone + "'");
            }
            return PrefixingConnection.wrap(raw, marginSchema + ".");
        };
        return new DbAccessPolicyService(leases.of(source), DbAccessPolicyConfig.defaults(), localClock, monotonic);
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
     * The monotonic clock, moved by hand, counting how often the code under test reads it
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

        int reads() {
            return reads;
        }
    }

    @NotNull
    private static DBPDataSourceContainer container() {
        return PolicyTestSupport.container(PROJECT, CONNECTION, HOST, DATABASE);
    }

    @NotNull
    private static WriteAuthorizationRequest request(
        @NotNull String userId,
        @NotNull DBPDataSourceContainer container
    ) {
        return WriteAuthorizationRequest.of(userId, container, DbOperationCategory.SQL_TEXT);
    }

    private static void assertDenied(
        @NotNull AuthorizationDecision decision,
        @NotNull DenialReason expected
    ) {
        Assertions.assertFalse(decision.isAllowed(), "expected a denial, got an allow");
        Assertions.assertEquals(expected, decision.denialReason());
    }

    @NotNull
    private String activeUser(@NotNull String userId) throws Exception {
        touchedUsers.add(userId);
        try (Connection connection = open()) {
            exec(connection, "INSERT INTO " + schema + ".CB_USER (USER_ID, IS_ACTIVE) VALUES ('"
                + userId + "', 'Y')");
        }
        return userId;
    }

    private void putGrant(@NotNull String userId, @NotNull Duration fromNow, boolean revoked)
            throws Exception {
        try (Connection connection = open();
             PreparedStatement dbStat = connection.prepareStatement(
                 "INSERT INTO " + schema + ".DBAC_TW_CURRENT"
                     + " (USER_ID, PROJECT_ID, CONNECTION_ID, GRANT_ID, REVISION, GRANTED_BY,"
                     + "  GRANTED_AT, EXPIRES_AT, REASON, REVOKED_AT,"
                     + "  PROVIDER_ID, DRIVER_ID, CONFIGURATION_TYPE, HOST_SNAPSHOT, PORT_SNAPSHOT,"
                     + "  DATABASE_SNAPSHOT)"
                     + " VALUES (?,?,?,?,1,'admin', CURRENT_TIMESTAMP,"
                     + "  CURRENT_TIMESTAMP + (? * INTERVAL '1 second'), 'policy test',"
                     + (revoked ? " CURRENT_TIMESTAMP," : " NULL,")
                     + " ?,?,?,?,?,?)")
        ) {
            int i = 1;
            dbStat.setString(i++, userId);
            dbStat.setString(i++, PROJECT);
            dbStat.setString(i++, CONNECTION);
            dbStat.setString(i++, "grant-" + userId);
            dbStat.setLong(i++, fromNow.toSeconds());
            dbStat.setString(i++, PROVIDER);
            dbStat.setString(i++, DRIVER);
            dbStat.setString(i++, CONFIGURATION_TYPE);
            dbStat.setString(i++, HOST);
            dbStat.setString(i++, PORT);
            dbStat.setString(i, DATABASE);
            Assertions.assertEquals(1, dbStat.executeUpdate());
        }
    }

    @NotNull
    private static OffsetDateTime readNow(@NotNull Connection connection) throws SQLException {
        try (PreparedStatement dbStat = connection.prepareStatement("SELECT CURRENT_TIMESTAMP");
             ResultSet dbResult = dbStat.executeQuery()
        ) {
            Assertions.assertTrue(dbResult.next());
            return dbResult.getObject(1, OffsetDateTime.class);
        }
    }

    private static void exec(@NotNull Connection connection, @NotNull String sql) throws SQLException {
        try (java.sql.Statement dbStat = connection.createStatement()) {
            dbStat.execute(sql);
        }
    }

    /**
     * Substitutes {@code {table_prefix}} the way the production proxy connection does
     * <p>
     * The real substitution lives in the platform's {@code InternalProxyConnection}, which is not
     * reachable from a plain JDBC connection. This does the same job for the one statement under
     * test so the query text being verified is character-for-character the production one.
     */
    private static final class PrefixingConnection implements java.lang.reflect.InvocationHandler {
        private final Connection delegate;
        private final String prefix;

        private PrefixingConnection(@NotNull Connection delegate, @NotNull String prefix) {
            this.delegate = delegate;
            this.prefix = prefix;
        }

        @NotNull
        static Connection wrap(@NotNull Connection delegate, @NotNull String prefix) {
            return (Connection) java.lang.reflect.Proxy.newProxyInstance(
                DbAccessPolicyPostgresTest.class.getClassLoader(),
                new Class<?>[]{Connection.class},
                new PrefixingConnection(delegate, prefix));
        }

        @Override
        @Nullable
        public Object invoke(
            @NotNull Object proxy,
            @NotNull java.lang.reflect.Method method,
            @Nullable Object[] args
        ) throws Throwable {
            if ("prepareStatement".equals(method.getName()) && args != null && args.length > 0
                && args[0] instanceof String sql
            ) {
                args = args.clone();
                args[0] = sql.replace("{table_prefix}", prefix);
            }
            try {
                return method.invoke(delegate, args);
            } catch (java.lang.reflect.InvocationTargetException e) {
                throw e.getCause();
            }
        }
    }
}
