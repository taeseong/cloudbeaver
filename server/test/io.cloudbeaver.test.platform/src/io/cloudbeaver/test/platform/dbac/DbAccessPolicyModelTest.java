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

import io.cloudbeaver.service.dbac.policy.AuthorizationAuditPayload;
import io.cloudbeaver.service.dbac.policy.AuthorizationDecision;
import io.cloudbeaver.service.dbac.policy.ConnectionPropertyAllowlist;
import io.cloudbeaver.service.dbac.policy.DbAccessDecision;
import io.cloudbeaver.service.dbac.policy.DbAccessKey;
import io.cloudbeaver.service.dbac.policy.DbAccessPolicyConfig;
import io.cloudbeaver.service.dbac.policy.DbAccessPolicyService;
import io.cloudbeaver.service.dbac.policy.DbOperationCategory;
import io.cloudbeaver.service.dbac.policy.DenialReason;
import io.cloudbeaver.service.dbac.policy.SupportedTargetDatabase;
import io.cloudbeaver.service.dbac.policy.WriteAuthorizationRequest;
import io.cloudbeaver.service.dbac.tempwrite.EndpointSnapshot;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteGrantRequest;
import io.cloudbeaver.service.dbac.tempwrite.TempWritePermissionKey;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteRequestLimits;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteRevokeRequest;
import org.jkiss.code.NotNull;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * The decision model's rules, none of which need a database
 * <p>
 * These pin the parts of the policy core that are pure judgement: which target databases are on the
 * allowlist and why, how loosely a connection snapshot may be compared, what a broken configuration
 * falls back to, and which shapes of decision are refused outright. Getting any of them wrong is a
 * quiet failure - the code still runs, it just authorises something it should not - so each is
 * asserted rather than left to review.
 */
public class DbAccessPolicyModelTest {

    private static final OffsetDateTime SOME_TIME =
        OffsetDateTime.of(2026, 9, 8, 12, 0, 0, 0, ZoneOffset.UTC);

    // ---------------------------------------------------------------- supported target databases

    /**
     * The two drivers that actually are PostgreSQL and MySQL
     */
    @Test
    public void realPostgresAndMysqlDriversAreSupported() {
        Assertions.assertTrue(SupportedTargetDatabase.isSupported("postgresql", "postgres-jdbc"));
        Assertions.assertTrue(SupportedTargetDatabase.isSupported("postgresql", "postgresql"));
        Assertions.assertTrue(SupportedTargetDatabase.isSupported("mysql", "mysql8"));
        Assertions.assertTrue(SupportedTargetDatabase.isSupported("mysql", "mysql5"));
        Assertions.assertEquals(
            4, SupportedTargetDatabase.allowedCount(),
            "The allowlist is pinned; adding a database is a decision with its own evidence");
    }

    /**
     * Everything the PostgreSQL provider also ships is refused
     * <p>
     * This is the case a substring test on the driver id would get wrong. All of these live under
     * {@code datasource id="postgresql"} and most of them declare {@code org.postgresql.Driver}, so
     * neither the provider nor the JDBC class distinguishes them - only the pair does.
     */
    @Test
    public void otherDatabasesUnderThePostgresProviderAreRefused() {
        for (String driverId : new String[]{
            "postgres-redshift-jdbc", "postgres-cockroach-jdbc", "postgres-yugabytedb-jdbc",
            "postgres-materialize-jdbc", "postgres-cratedb-jdbc", "postgres-risingwave-jdbc",
            "postgres-timescale-jdbc", "postgres-greenplum-jdbc", "postgres-edb-jdbc",
            "postgres-gcloud-jdbc", "yellowbrick-jdbc", "postgres-yellowbrick-jdbc"}
        ) {
            Assertions.assertFalse(
                SupportedTargetDatabase.isSupported("postgresql", driverId),
                driverId + " is not PostgreSQL and must not be authorised");
        }
    }

    /**
     * And everything the MySQL provider also ships
     */
    @Test
    public void otherDatabasesUnderTheMysqlProviderAreRefused() {
        for (String driverId : new String[]{"mariaDB", "starRocks", "mysql_ndb", "mysql3"}) {
            Assertions.assertFalse(
                SupportedTargetDatabase.isSupported("mysql", driverId),
                driverId + " is not MySQL and must not be authorised");
        }
    }

    /**
     * A driver id is not unique across providers, so the provider half of the pair is load-bearing
     * <p>
     * The generic provider ships drivers with the ids {@code postgresql} and {@code mysql3}. A
     * generic JDBC connection can point at any server at all, so allowing one because its id matches
     * would authorise writes to an arbitrary database.
     */
    @Test
    public void theGenericProviderIsRefusedEvenWithAMatchingDriverId() {
        Assertions.assertFalse(SupportedTargetDatabase.isSupported("generic", "postgresql"));
        Assertions.assertFalse(SupportedTargetDatabase.isSupported("generic", "mysql3"));
        Assertions.assertFalse(SupportedTargetDatabase.isSupported("generic", "postgresql_generic"));
    }

    /**
     * Missing or empty identifiers are refused rather than treated as a wildcard
     */
    @Test
    public void missingIdentifiersAreRefused() {
        Assertions.assertFalse(SupportedTargetDatabase.isSupported(null, "postgres-jdbc"));
        Assertions.assertFalse(SupportedTargetDatabase.isSupported("postgresql", null));
        Assertions.assertFalse(SupportedTargetDatabase.isSupported("", "postgres-jdbc"));
        Assertions.assertFalse(SupportedTargetDatabase.isSupported("postgresql", "  "));
        Assertions.assertFalse(SupportedTargetDatabase.isSupported((org.jkiss.dbeaver.model.connection.DBPDriver) null));
    }

    // ---------------------------------------------------------------- endpoint snapshot

    /**
     * A fully specified endpoint, for a test to vary one field of
     */
    @NotNull
    private static EndpointSnapshot endpoint() {
        return new EndpointSnapshot(
            "postgresql", "postgres-jdbc", "MANUAL", "db.internal.example", "5432", "customer_prod");
    }

    /**
     * Every one of the six fields is compared, and a difference in any of them denies
     * <p>
     * Written as a table over the fields rather than as six tests, so a field added to the record
     * without being added here shows up as an unvaried field rather than as silence. The port row is
     * the one this whole record exists for: it was absent from the first version of the identity and
     * a grant survived a move to another server instance on the same host.
     */
    @Test
    public void everyEndpointFieldIsCompared() {
        EndpointSnapshot stored = endpoint();
        EndpointSnapshot[] differing = {
            new EndpointSnapshot("mysql", "postgres-jdbc", "MANUAL", "db.internal.example", "5432", "customer_prod"),
            new EndpointSnapshot("postgresql", "postgresql", "MANUAL", "db.internal.example", "5432", "customer_prod"),
            new EndpointSnapshot("postgresql", "postgres-jdbc", "URL", "db.internal.example", "5432", "customer_prod"),
            new EndpointSnapshot("postgresql", "postgres-jdbc", "MANUAL", "other.example", "5432", "customer_prod"),
            new EndpointSnapshot("postgresql", "postgres-jdbc", "MANUAL", "db.internal.example", "5433", "customer_prod"),
            new EndpointSnapshot("postgresql", "postgres-jdbc", "MANUAL", "db.internal.example", "5432", "other_db"),
        };
        Assertions.assertEquals(
            stored.getClass().getRecordComponents().length, differing.length,
            "one row per record component, so a new field cannot be added without being varied here");
        for (EndpointSnapshot other : differing) {
            Assertions.assertFalse(other.matches(stored), other.describe() + " must not match " + stored.describe());
        }
        Assertions.assertTrue(endpoint().matches(stored), "an identical endpoint must match");
    }

    /**
     * Host names are case-insensitive; database names are not
     */
    @Test
    public void endpointComparisonFollowsTheStatedCaseRules() {
        EndpointSnapshot stored = new EndpointSnapshot(
            "postgresql", "postgres-jdbc", "MANUAL", "DB.Internal.Example", "5432", "customer_prod");
        Assertions.assertTrue(endpoint().matches(stored), "DNS names are case-insensitive by definition");
        Assertions.assertFalse(
            new EndpointSnapshot(
                "postgresql", "postgres-jdbc", "MANUAL", "db.internal.example", "5432", "CUSTOMER_PROD")
                .matches(stored),
            "database name case can distinguish two real databases, so it is compared exactly");
    }

    /**
     * Nothing about the host is canonicalised beyond case
     * <p>
     * A port suffix, a trailing dot and a bracketed IPv6 form are all left alone. Each compares
     * unequal and therefore denies - the safe direction. A normaliser clever enough to call them
     * equal would be a normaliser whose bugs approve the wrong server.
     */
    @Test
    public void hostFormsThatLookEquivalentStillDeny() {
        EndpointSnapshot stored = endpoint();
        for (String other : new String[]{
            "db.internal.example:5432", "db.internal.example.", "10.0.0.5", "[::1]", "::1"}
        ) {
            Assertions.assertFalse(
                new EndpointSnapshot("postgresql", "postgres-jdbc", "MANUAL", other, "5432", "customer_prod")
                    .matches(stored),
                other + " must not be accepted as the stored host");
        }
    }

    /**
     * The port is compared as text, with no arithmetic and no default substitution
     * <p>
     * {@code "5432"} and {@code "05432"} reach the same server through a vendor driver that parses
     * them as integers, and are still called different here. That is deliberate: the platform copies
     * the string into the URL literally, so what a leading zero connects to is decided inside the
     * driver, and denying is the direction that cannot authorise the wrong instance.
     */
    @Test
    public void portIsComparedAsTextWithoutNormalisation() {
        EndpointSnapshot stored = endpoint();
        for (String other : new String[]{"05432", "5432 ", " 5432", "5433"}) {
            Assertions.assertFalse(
                new EndpointSnapshot(
                    "postgresql", "postgres-jdbc", "MANUAL", "db.internal.example", other, "customer_prod")
                    .matches(stored),
                "port " + other + " must not match the stored 5432");
        }
    }

    /**
     * Identifiers are compared exactly - they are identifiers, not prose
     */
    @Test
    public void identifiersAreComparedExactly() {
        EndpointSnapshot stored = endpoint();
        Assertions.assertFalse(
            new EndpointSnapshot(
                "postgresql", "Postgres-JDBC", "MANUAL", "db.internal.example", "5432", "customer_prod")
                .matches(stored));
        Assertions.assertFalse(
            new EndpointSnapshot(
                "postgresql", "postgres-redshift-jdbc", "MANUAL", "db.internal.example", "5432", "customer_prod")
                .matches(stored));
        Assertions.assertFalse(
            new EndpointSnapshot(
                "postgresql", "postgres-jdbc", "manual", "db.internal.example", "5432", "customer_prod")
                .matches(stored),
            "the configuration type is an enum name, not free text");
    }

    /**
     * No field of an endpoint may be absent
     * <p>
     * There is no partially populated endpoint to reason about: a configuration that cannot supply
     * all six is refused before a snapshot is built. Checked field by field so that a component
     * whose check is forgotten fails here.
     */
    @Test
    public void endpointRejectsEveryBlankField() {
        String[] full = {"postgresql", "postgres-jdbc", "MANUAL", "db.internal.example", "5432", "customer_prod"};
        for (int i = 0; i < full.length; i++) {
            for (String blank : new String[]{"", "   "}) {
                String[] parts = full.clone();
                parts[i] = blank;
                int field = i;
                Assertions.assertThrows(
                    IllegalArgumentException.class,
                    () -> new EndpointSnapshot(parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]),
                    "field " + field + " must not be accepted blank");
            }
        }
    }

    /**
     * A stored row that cannot supply the whole endpoint yields nothing at all
     * <p>
     * This is what a grant written under schema version 2 looks like: it has a driver, a host and a
     * database but no provider, configuration type or port, because those columns did not exist. It
     * must not be rebuilt as a partial endpoint that happens to compare equal on the three fields it
     * does have - that is the succession the new columns exist to catch - so the reader returns null
     * and the write gate denies.
     */
    @Test
    public void storedRowMissingAnyFieldYieldsNoEndpoint() {
        Assertions.assertNull(
            EndpointSnapshot.ofStored(
                null, "postgres-jdbc", null, "db.internal.example", null, "customer_prod"),
            "a schema version 2 row cannot produce an endpoint");
        String[] full = {"postgresql", "postgres-jdbc", "MANUAL", "db.internal.example", "5432", "customer_prod"};
        for (int i = 0; i < full.length; i++) {
            for (String missing : new String[]{null, "", "  "}) {
                String[] parts = full.clone();
                parts[i] = missing;
                Assertions.assertNull(
                    EndpointSnapshot.ofStored(parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]),
                    "a row missing field " + i + " must not produce an endpoint");
            }
        }
        Assertions.assertNotNull(
            EndpointSnapshot.ofStored(full[0], full[1], full[2], full[3], full[4], full[5]),
            "a complete row must produce one");
    }

    // ---------------------------------------------------------------- config, the public constructor

    /**
     * The canonical constructor refuses what the sanitizer would have replaced
     * <p>
     * The sanitizer is for external configuration; this constructor is a public entry point that an
     * enforcement bundle can call directly. A ceiling enforced only in the sanitizer would be a
     * suggestion, and a year-long skew threshold would leave the clock guard looking configured
     * while accepting any clock at all.
     */
    @Test
    public void configConstructorRefusesValuesBeyondTheCeilings() {
        Assertions.assertThrows(IllegalArgumentException.class,
            () -> new DbAccessPolicyConfig(Duration.ofDays(365), DbAccessPolicyConfig.DEFAULT_MAX_GRANT_DURATION),
            "a year of permitted clock drift is indistinguishable from no skew check");
        Assertions.assertThrows(IllegalArgumentException.class,
            () -> new DbAccessPolicyConfig(DbAccessPolicyConfig.DEFAULT_CLOCK_SKEW_THRESHOLD, Duration.ofDays(365)),
            "a year-long grant is not a temporary grant");
        for (Duration bad : new Duration[]{Duration.ZERO, Duration.ofSeconds(-1), Duration.ofDays(-365)}) {
            Assertions.assertThrows(IllegalArgumentException.class,
                () -> new DbAccessPolicyConfig(bad, DbAccessPolicyConfig.DEFAULT_MAX_GRANT_DURATION));
            Assertions.assertThrows(IllegalArgumentException.class,
                () -> new DbAccessPolicyConfig(DbAccessPolicyConfig.DEFAULT_CLOCK_SKEW_THRESHOLD, bad));
        }
    }

    /**
     * The ceilings are inclusive, and one nanosecond past them is not
     * <p>
     * Pinned from both sides so the boundary cannot drift in either direction. The exact ceiling
     * values are read back from a sanitized absurd request rather than hard-coded here, so this test
     * cannot disagree with the class it is testing.
     */
    @Test
    public void configCeilingsAreInclusive() {
        // Found by search rather than restated, so the boundary this test pins is the one the class
        // actually enforces. An earlier version asserted that a hard-coded 5 minutes equalled a
        // hard-coded 5 minutes, which proved nothing.
        Duration maxSkew = largestAccepted(
            candidate -> new DbAccessPolicyConfig(candidate, DbAccessPolicyConfig.DEFAULT_MAX_GRANT_DURATION));
        Duration maxGrant = largestAccepted(
            candidate -> new DbAccessPolicyConfig(DbAccessPolicyConfig.DEFAULT_CLOCK_SKEW_THRESHOLD, candidate));

        Assertions.assertEquals(Duration.ofMinutes(5), maxSkew, "the documented skew ceiling");
        Assertions.assertEquals(Duration.ofHours(24), maxGrant, "the documented grant ceiling");
        Assertions.assertThrows(IllegalArgumentException.class,
            () -> new DbAccessPolicyConfig(
                maxSkew.plusNanos(1), DbAccessPolicyConfig.DEFAULT_MAX_GRANT_DURATION));
        Assertions.assertThrows(IllegalArgumentException.class,
            () -> new DbAccessPolicyConfig(
                DbAccessPolicyConfig.DEFAULT_CLOCK_SKEW_THRESHOLD, maxGrant.plusNanos(1)));
    }

    /**
     * Finds the largest duration the builder accepts, by binary search
     * <p>
     * The point is that the answer comes out of the class under test. A helper that took the expected
     * ceiling as a parameter and handed it straight back would let the assertion compare a literal
     * with itself, which is what this replaced.
     */
    @NotNull
    private static Duration largestAccepted(
        @NotNull java.util.function.Function<Duration, DbAccessPolicyConfig> build
    ) {
        Duration accepted = Duration.ofNanos(1);
        Duration refused = Duration.ofDays(400);
        Assertions.assertTrue(accepts(build, accepted), "a nanosecond must be accepted");
        Assertions.assertFalse(accepts(build, refused), "400 days must be refused");
        while (refused.minus(accepted).compareTo(Duration.ofNanos(1)) > 0) {
            Duration middle = accepted.plus(refused.minus(accepted).dividedBy(2));
            if (middle.equals(accepted) || middle.equals(refused)) {
                break;
            }
            if (accepts(build, middle)) {
                accepted = middle;
            } else {
                refused = middle;
            }
        }
        return accepted;
    }

    private static boolean accepts(
        @NotNull java.util.function.Function<Duration, DbAccessPolicyConfig> build,
        @NotNull Duration candidate
    ) {
        try {
            build.apply(candidate);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * An oversized configuration cannot be smuggled past the sanitizer into the service
     * <p>
     * {@code sanitized} turns an absurd external value into the documented default; the point here
     * is that the direct route is closed too, so there is no way to hand the service a config the
     * sanitizer would have rejected.
     */
    @Test
    public void anOversizedConfigCannotReachTheService() {
        Assertions.assertEquals(
            DbAccessPolicyConfig.DEFAULT_CLOCK_SKEW_THRESHOLD,
            DbAccessPolicyConfig.sanitized(60 * 60 * 24 * 365, null).clockSkewThreshold(),
            "an absurd external value becomes the default rather than being honoured");
        Assertions.assertThrows(IllegalArgumentException.class,
            () -> new DbAccessPolicyService(
                () -> {
                    throw new UnsupportedOperationException("no connection should be needed");
                },
                new DbAccessPolicyConfig(Duration.ofDays(365), Duration.ofDays(365))),
            "and the direct route is closed, so the service cannot be given one either");
    }

    // ---------------------------------------------------------------- decision shapes

    /**
     * Every malformed decision shape is refused by the canonical constructor
     * <p>
     * The constructor of a public record is a public entry point: an enforcement bundle can call it
     * directly, and a partly populated allow built that way would be indistinguishable from one the
     * factories produced. Enumerated rather than sampled, so a shape that becomes legal by accident
     * shows up here.
     */
    @Test
    public void malformedDecisionsAreRefused() {
        DbAccessKey key = new DbAccessKey("u", "p", "c");
        OffsetDateTime expiry = OffsetDateTime.parse("2026-01-01T00:00:00Z");
        AuthorizationAuditPayload payload = new AuthorizationAuditPayload(
            DbAccessDecision.ALLOW, null, key.userId(), key.projectId(), key.connectionId(),
            "g", DbOperationCategory.SQL_TEXT, expiry);

        record Case(String name, Runnable construction) {
        }

        Case[] cases = {
            new Case("allow with a denial reason", () -> new AuthorizationDecision(
                DbAccessDecision.ALLOW, DenialReason.NO_GRANT, key,
                DbOperationCategory.SQL_TEXT, "g", expiry, payload)),
            new Case("allow with no key", () -> new AuthorizationDecision(
                DbAccessDecision.ALLOW, null, null,
                DbOperationCategory.SQL_TEXT, "g", expiry, payload)),
            new Case("allow with no grant", () -> new AuthorizationDecision(
                DbAccessDecision.ALLOW, null, key,
                DbOperationCategory.SQL_TEXT, null, expiry, payload)),
            new Case("allow with a blank grant", () -> new AuthorizationDecision(
                DbAccessDecision.ALLOW, null, key,
                DbOperationCategory.SQL_TEXT, "   ", expiry, payload)),
            new Case("allow with no expiry", () -> new AuthorizationDecision(
                DbAccessDecision.ALLOW, null, key,
                DbOperationCategory.SQL_TEXT, "g", null, payload)),
            new Case("allow with no payload", () -> new AuthorizationDecision(
                DbAccessDecision.ALLOW, null, key,
                DbOperationCategory.SQL_TEXT, "g", expiry, null)),
            new Case("allow whose payload names another grant", () -> new AuthorizationDecision(
                DbAccessDecision.ALLOW, null, key,
                DbOperationCategory.SQL_TEXT, "other", expiry, payload)),
            new Case("allow whose payload names another category", () -> new AuthorizationDecision(
                DbAccessDecision.ALLOW, null, key,
                DbOperationCategory.DATA_EDIT, "g", expiry, payload)),
            new Case("allow whose payload names another key", () -> new AuthorizationDecision(
                DbAccessDecision.ALLOW, null, new DbAccessKey("other", "p", "c"),
                DbOperationCategory.SQL_TEXT, "g", expiry, payload)),
            new Case("allow whose payload names another expiry", () -> new AuthorizationDecision(
                DbAccessDecision.ALLOW, null, key,
                DbOperationCategory.SQL_TEXT, "g", expiry.plusMinutes(1), payload)),
            new Case("recovery sentinel on a write category", () -> new AuthorizationDecision(
                DbAccessDecision.ALLOW, null, null,
                DbOperationCategory.SQL_TEXT, AuthorizationDecision.RECOVERY_GRANT_ID, null, null)),
            new Case("recovery allow carrying a key", () -> new AuthorizationDecision(
                DbAccessDecision.ALLOW, null, key,
                DbOperationCategory.TRANSACTION_ROLLBACK,
                AuthorizationDecision.RECOVERY_GRANT_ID, null, null)),
            new Case("recovery allow carrying an expiry", () -> new AuthorizationDecision(
                DbAccessDecision.ALLOW, null, null,
                DbOperationCategory.TRANSACTION_ROLLBACK,
                AuthorizationDecision.RECOVERY_GRANT_ID, expiry, null)),
            new Case("recovery allow carrying a payload", () -> new AuthorizationDecision(
                DbAccessDecision.ALLOW, null, null,
                DbOperationCategory.TRANSACTION_ROLLBACK,
                AuthorizationDecision.RECOVERY_GRANT_ID, null, payload)),
            // The recovery shape is where "an allow cannot carry a denial reason" is the only rule
            // that applies: the recovery check looks at the category, the key, the expiry and the
            // payload, and none of those is wrong here. Independent review found that deleting that
            // rule left every test green, because every other case that tried it was refused first
            // by the payload rule or by the agreement rule.
            new Case("recovery allow carrying a denial reason", () -> new AuthorizationDecision(
                DbAccessDecision.ALLOW, DenialReason.NO_GRANT, null,
                DbOperationCategory.TRANSACTION_ROLLBACK,
                AuthorizationDecision.RECOVERY_GRANT_ID, null, null)),
            new Case("denial with no reason", () -> new AuthorizationDecision(
                DbAccessDecision.DENY, null, key,
                DbOperationCategory.SQL_TEXT, null, null, null)),
            // Keyless, so that the "a denial must say why" rule is the only one that can refuse it.
            // The keyed case above is refused first by the rule that a known key needs a payload,
            // which meant the reason rule itself had nothing holding it.
            new Case("keyless denial with no reason", () -> new AuthorizationDecision(
                DbAccessDecision.DENY, null, null,
                DbOperationCategory.SQL_TEXT, null, null, null)),
            // Keyed and with a payload that agrees on every field, including the sentinel grant id.
            // That leaves "a denial cannot claim the recovery grant" as the only rule standing: the
            // keyless variant above it is refused first by the rule against naming a grant.
            new Case("keyed denial claiming the recovery grant", () -> new AuthorizationDecision(
                DbAccessDecision.DENY, DenialReason.NO_GRANT, key,
                DbOperationCategory.SQL_TEXT, AuthorizationDecision.RECOVERY_GRANT_ID, null,
                new AuthorizationAuditPayload(
                    DbAccessDecision.DENY, DenialReason.NO_GRANT, "u", "p", "c",
                    AuthorizationDecision.RECOVERY_GRANT_ID, DbOperationCategory.SQL_TEXT, null))),
            new Case("denial claiming the recovery grant", () -> new AuthorizationDecision(
                DbAccessDecision.DENY, DenialReason.NO_GRANT, null,
                DbOperationCategory.TRANSACTION_ROLLBACK,
                AuthorizationDecision.RECOVERY_GRANT_ID, null, null)),
            new Case("denial with a key but no payload", () -> new AuthorizationDecision(
                DbAccessDecision.DENY, DenialReason.NO_GRANT, key,
                DbOperationCategory.SQL_TEXT, null, null, null)),
            new Case("denial with no key but a payload", () -> new AuthorizationDecision(
                DbAccessDecision.DENY, DenialReason.NO_GRANT, null,
                DbOperationCategory.SQL_TEXT, null, null, payload)),
            new Case("denial carrying an allow payload", () -> new AuthorizationDecision(
                DbAccessDecision.DENY, DenialReason.NO_GRANT, key,
                DbOperationCategory.SQL_TEXT, "g", expiry, payload)),
        };
        for (Case one : cases) {
            Assertions.assertThrows(
                IllegalArgumentException.class, () -> one.construction().run(),
                one.name() + " must be refused");
        }
    }

    /**
     * The three legal shapes are accepted
     * <p>
     * Without this the test above would pass on a constructor that refuses everything.
     */
    @Test
    public void theThreeLegalDecisionShapesAreAccepted() {
        DbAccessKey key = new DbAccessKey("u", "p", "c");
        OffsetDateTime expiry = OffsetDateTime.parse("2026-01-01T00:00:00Z");

        Assertions.assertTrue(
            new AuthorizationDecision(
                DbAccessDecision.ALLOW, null, key, DbOperationCategory.SQL_TEXT, "g", expiry,
                new AuthorizationAuditPayload(
                    DbAccessDecision.ALLOW, null, key.userId(), key.projectId(), key.connectionId(),
                    "g", DbOperationCategory.SQL_TEXT, expiry))
                .isAllowed());
        Assertions.assertTrue(
            new AuthorizationDecision(
                DbAccessDecision.ALLOW, null, null, DbOperationCategory.TRANSACTION_ROLLBACK,
                AuthorizationDecision.RECOVERY_GRANT_ID, null, null)
                .isAllowed());
        Assertions.assertFalse(
            new AuthorizationDecision(
                DbAccessDecision.DENY, DenialReason.IDENTITY_MISSING, null,
                DbOperationCategory.SQL_TEXT, null, null, null)
                .isAllowed());
    }

    // ------------------------------------------- decision shape, the remaining combinations

    /**
     * A decision cannot omit what was decided or what it was about
     */
    @Test
    public void decisionRefusesNullDecisionOrCategory() {
        DbAccessKey key = new DbAccessKey("u", "p", "c");
        Assertions.assertThrows(IllegalArgumentException.class, () -> new AuthorizationDecision(
            null, DenialReason.NO_GRANT, null, DbOperationCategory.SQL_TEXT, null, null, null),
            "a decision with no verdict is not a decision");
        // Keyless, deliberately. A keyed denial with no payload is refused by the payload rule
        // first, so this assertion used to pass whether or not the category was checked at all -
        // removing the category check left every test green. With no key the denial is otherwise
        // legal, so the category check is the only thing that can refuse it.
        Assertions.assertThrows(IllegalArgumentException.class, () -> new AuthorizationDecision(
            DbAccessDecision.DENY, DenialReason.NO_GRANT, null, null, null, null, null),
            "every shape rule is expressed in terms of the category, so it cannot be absent");
        Assertions.assertNotNull(
            new AuthorizationDecision(
                DbAccessDecision.DENY, DenialReason.NO_GRANT, null,
                DbOperationCategory.SQL_TEXT, null, null, null),
            "the same denial with a category is legal, so the category is what the case turns on");
        Assertions.assertNotNull(key, "the key fixture stays in use below");
    }

    /**
     * A grant-backed allow on a category the write gate does not govern cannot be assembled at all
     * <p>
     * <b>What this actually exercises.</b> The refusal comes from
     * {@link AuthorizationAuditPayload}, not from {@link AuthorizationDecision}: building the
     * payload for such an allow throws before the decision constructor is reached, because an allow
     * payload must name a write-gated category. Independent review found that this test therefore
     * passed with the decision-level check deleted, so the name is now honest about which invariant
     * holds the line - and the decision-level check has its own test below.
     * <p>
     * The pair matters because the two rules protect different callers. Nobody can build the payload,
     * so nobody can build the decision through the factories; but the decision constructor is public
     * and its own check is what refuses a hand-assembled one.
     */
    @Test
    public void grantBackedAllowIsRefusedOnNonWriteGatedCategories() {
        DbAccessKey key = new DbAccessKey("u", "p", "c");
        OffsetDateTime expiry = SOME_TIME;
        DbOperationCategory[] notGated = java.util.Arrays.stream(DbOperationCategory.values())
            .filter(one -> !one.requiresWriteAuthorization())
            .toArray(DbOperationCategory[]::new);

        Assertions.assertEquals(
            2, notGated.length,
            "CONTAINER_READ and TRANSACTION_ROLLBACK are the categories a grant never backs."
                + " GROUPING was here until independent review showed the claim behind it was false");
        for (DbOperationCategory category : notGated) {
            Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> new AuthorizationDecision(
                    DbAccessDecision.ALLOW, null, key, category, "g", expiry,
                    new AuthorizationAuditPayload(
                        DbAccessDecision.ALLOW, null, "u", "p", "c", "g", category, expiry)),
                category + " must not accept a grant-backed allow");
        }
    }

    /**
     * The decision constructor refuses a non-write-gated allow on its own account
     * <p>
     * Distinguished by message, which is the only way to tell this rule from the one after it. Give
     * the decision a category the write gate does not govern and a payload that is itself valid, and
     * two different rules could refuse it: the category rule, or the agreement rule that compares the
     * payload's category against the decision's. Asserting the message says which one fired, so
     * deleting the category rule turns this test red instead of leaving it green on the other one.
     * <p>
     * With the payload invariant in place this rule is defence in depth rather than the only barrier.
     * It is kept, and pinned, because it is what refuses a decision assembled by hand rather than
     * through the factories - and because a later change to the payload rule would otherwise make it
     * load-bearing while still untested.
     */
    @Test
    public void theDecisionConstructorRefusesANonWriteGatedAllowItself() {
        DbAccessKey key = new DbAccessKey("u", "p", "c");
        OffsetDateTime expiry = SOME_TIME;
        AuthorizationAuditPayload validPayload = new AuthorizationAuditPayload(
            DbAccessDecision.ALLOW, null, "u", "p", "c", "g", DbOperationCategory.SQL_TEXT, expiry);

        IllegalArgumentException refused = Assertions.assertThrows(
            IllegalArgumentException.class,
            () -> new AuthorizationDecision(
                DbAccessDecision.ALLOW, null, key, DbOperationCategory.CONTAINER_READ, "g", expiry,
                validPayload));
        Assertions.assertTrue(
            refused.getMessage().contains("write-gated"),
            "the category rule must be what refuses this, not the payload agreement rule; got: "
                + refused.getMessage());
    }

    /**
     * The remaining allow-shape rules are pinned by their message
     * <p>
     * "An allow must name the grant it applied" and "An allow must say when it stops being valid"
     * cannot be reached with a payload that is itself valid: an allow payload has to name a grant and
     * an expiry, and the agreement rule then forces the decision to match. So each of these rules is
     * defence in depth against a decision assembled by hand, and each is reachable only as a
     * <em>different message</em> than the agreement rule would give.
     * <p>
     * Asserting the message is what makes the difference visible. A sweep that deleted every check in
     * this class one at a time found both of these rules unpinned - the cases meant to cover them were
     * being refused by the agreement rule instead, so deleting them left the suite green.
     */
    @Test
    public void theRemainingAllowShapeRulesArePinnedByMessage() {
        DbAccessKey key = new DbAccessKey("u", "p", "c");
        OffsetDateTime expiry = SOME_TIME;
        AuthorizationAuditPayload validPayload = new AuthorizationAuditPayload(
            DbAccessDecision.ALLOW, null, "u", "p", "c", "g", DbOperationCategory.SQL_TEXT, expiry);

        IllegalArgumentException noGrant = Assertions.assertThrows(
            IllegalArgumentException.class,
            () -> new AuthorizationDecision(
                DbAccessDecision.ALLOW, null, key, DbOperationCategory.SQL_TEXT, null, expiry,
                validPayload));
        Assertions.assertTrue(
            noGrant.getMessage().contains("must name the grant"),
            "the grant rule must be what refuses this, not the agreement rule; got: "
                + noGrant.getMessage());

        IllegalArgumentException noExpiry = Assertions.assertThrows(
            IllegalArgumentException.class,
            () -> new AuthorizationDecision(
                DbAccessDecision.ALLOW, null, key, DbOperationCategory.SQL_TEXT, "g", null,
                validPayload));
        Assertions.assertTrue(
            noExpiry.getMessage().contains("stops being valid"),
            "the expiry rule must be what refuses this, not the agreement rule; got: "
                + noExpiry.getMessage());
    }

    /**
     * The recovery sentinel belongs to rollback alone, in both directions
     */
    @Test
    public void theRecoverySentinelIsBoundToRollback() {
        for (DbOperationCategory category : DbOperationCategory.values()) {
            if (category == DbOperationCategory.TRANSACTION_ROLLBACK) {
                Assertions.assertTrue(
                    new AuthorizationDecision(
                        DbAccessDecision.ALLOW, null, null, category,
                        AuthorizationDecision.RECOVERY_GRANT_ID, null, null).isAllowed(),
                    "rollback is the one category the sentinel is for");
                continue;
            }
            Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> new AuthorizationDecision(
                    DbAccessDecision.ALLOW, null, null, category,
                    AuthorizationDecision.RECOVERY_GRANT_ID, null, null),
                category + " must not claim the recovery grant");
        }
    }

    /**
     * A denial taken before the key exists cannot name a grant or an expiry
     * <p>
     * Nothing was looked up at that point, so either value would describe a permission whose subject
     * the decision never established.
     */
    @Test
    public void keylessDenialCannotNameAGrantOrExpiry() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> new AuthorizationDecision(
            DbAccessDecision.DENY, DenialReason.IDENTITY_MISSING, null,
            DbOperationCategory.SQL_TEXT, "g", null, null));
        Assertions.assertThrows(IllegalArgumentException.class, () -> new AuthorizationDecision(
            DbAccessDecision.DENY, DenialReason.IDENTITY_MISSING, null,
            DbOperationCategory.SQL_TEXT, null, SOME_TIME, null));
        Assertions.assertFalse(
            new AuthorizationDecision(
                DbAccessDecision.DENY, DenialReason.IDENTITY_MISSING, null,
                DbOperationCategory.SQL_TEXT, null, null, null).isAllowed(),
            "the legal keyless denial still has to be accepted");
    }

    /**
     * Each field of the payload has to agree with the decision, one field at a time
     * <p>
     * Varied field by field rather than as one wrong payload, so a comparison dropped from the
     * agreement check shows up as the field it stopped covering - with one exception, named here
     * rather than left for a reader to discover. The {@code decision} row does <em>not</em> pin
     * {@code payload.decision() != decision}: a payload cannot disagree about the decision without
     * also disagreeing about the denial reason, because both classes lock those two fields to each
     * other, so the reason comparison on the next line refuses that row first. Neutralising the
     * decision comparison leaves this test green - measured, not assumed. The production javadoc
     * carries the same proof, and section 7 of {@code docs/db-access-control-build-verification.md}
     * lists it under the clauses that survive a sweep on purpose.
     * <p>
     * Each row builds the whole decision rather than only the payload, because one of the eight
     * compared fields cannot be varied any other way: {@code denialReason} is null on every allow,
     * so a disagreement about it only exists on a denial. While the table held payloads alone that
     * row was impossible to write, the count assertion said seven, and the
     * {@code payload.denialReason() != reason} comparison had nothing holding it - deleting it left
     * the suite green while letting an audit row record a different reason than the decision took.
     */
    @Test
    public void everyPayloadFieldMustAgreeWithTheDecision() {
        DbAccessKey key = new DbAccessKey("u", "p", "c");
        OffsetDateTime expiry = SOME_TIME;

        record Case(String field, Runnable construction) {
        }

        Case[] cases = {
            new Case("denialReason", () -> new AuthorizationDecision(
                // A denial that agrees on the other seven fields and names another reason. Legal in
                // every other respect: the payload is a valid denial payload and the decision is a
                // valid keyed denial, so the reason comparison is the only thing that can refuse it.
                DbAccessDecision.DENY, DenialReason.NO_GRANT, key,
                DbOperationCategory.SQL_TEXT, null, null,
                new AuthorizationAuditPayload(
                    DbAccessDecision.DENY, DenialReason.GRANT_EXPIRED, "u", "p", "c", null,
                    DbOperationCategory.SQL_TEXT, null))),
            new Case("decision", allowWith(key, expiry, new AuthorizationAuditPayload(
                DbAccessDecision.DENY, DenialReason.NO_GRANT, "u", "p", "c", "g",
                DbOperationCategory.SQL_TEXT, expiry))),
            new Case("userId", allowWith(key, expiry, new AuthorizationAuditPayload(
                DbAccessDecision.ALLOW, null, "other", "p", "c", "g",
                DbOperationCategory.SQL_TEXT, expiry))),
            new Case("projectId", allowWith(key, expiry, new AuthorizationAuditPayload(
                DbAccessDecision.ALLOW, null, "u", "other", "c", "g",
                DbOperationCategory.SQL_TEXT, expiry))),
            new Case("connectionId", allowWith(key, expiry, new AuthorizationAuditPayload(
                DbAccessDecision.ALLOW, null, "u", "p", "other", "g",
                DbOperationCategory.SQL_TEXT, expiry))),
            new Case("grantId", allowWith(key, expiry, new AuthorizationAuditPayload(
                DbAccessDecision.ALLOW, null, "u", "p", "c", "other",
                DbOperationCategory.SQL_TEXT, expiry))),
            new Case("operationCategory", allowWith(key, expiry, new AuthorizationAuditPayload(
                DbAccessDecision.ALLOW, null, "u", "p", "c", "g",
                DbOperationCategory.DATA_EDIT, expiry))),
            new Case("expiresAt", allowWith(key, expiry, new AuthorizationAuditPayload(
                DbAccessDecision.ALLOW, null, "u", "p", "c", "g",
                DbOperationCategory.SQL_TEXT, expiry.plusMinutes(1)))),
        };
        Assertions.assertEquals(
            8, cases.length, "one row per field the agreement check compares");
        for (Case one : cases) {
            Assertions.assertThrows(
                IllegalArgumentException.class, () -> one.construction().run(),
                "a payload disagreeing on " + one.field() + " must be refused");
        }
    }

    /**
     * The otherwise-legal grant-backed allow the agreement rows vary one payload field of
     */
    @NotNull
    private static Runnable allowWith(
        @NotNull DbAccessKey key,
        @NotNull OffsetDateTime expiry,
        @NotNull AuthorizationAuditPayload payload
    ) {
        return () -> new AuthorizationDecision(
            DbAccessDecision.ALLOW, null, key, DbOperationCategory.SQL_TEXT, "g", expiry, payload);
    }

    // ------------------------------------------- payload shape, on its own

    /**
     * A malformed audit payload is refused by its own constructor, with no decision involved
     * <p>
     * The payload is public and an enforcement bundle can build one directly. It is also the only
     * part of a decision that outlives the request, so a payload that contradicts itself is worse
     * than a missing one - it is evidence of something that never happened.
     */
    @Test
    public void malformedAuditPayloadsAreRefused() {
        record Case(String name, Runnable construction) {
        }

        Case[] cases = {
            new Case("no decision", () -> new AuthorizationAuditPayload(
                null, null, "u", "p", "c", "g", DbOperationCategory.SQL_TEXT, SOME_TIME)),
            new Case("no category", () -> new AuthorizationAuditPayload(
                DbAccessDecision.ALLOW, null, "u", "p", "c", "g", null, SOME_TIME)),
            new Case("null user", () -> new AuthorizationAuditPayload(
                DbAccessDecision.ALLOW, null, null, "p", "c", "g",
                DbOperationCategory.SQL_TEXT, SOME_TIME)),
            new Case("null project", () -> new AuthorizationAuditPayload(
                DbAccessDecision.ALLOW, null, "u", null, "c", "g",
                DbOperationCategory.SQL_TEXT, SOME_TIME)),
            new Case("null connection", () -> new AuthorizationAuditPayload(
                DbAccessDecision.ALLOW, null, "u", "p", null, "g",
                DbOperationCategory.SQL_TEXT, SOME_TIME)),
            new Case("blank user", () -> new AuthorizationAuditPayload(
                DbAccessDecision.ALLOW, null, "  ", "p", "c", "g",
                DbOperationCategory.SQL_TEXT, SOME_TIME)),
            new Case("blank project", () -> new AuthorizationAuditPayload(
                DbAccessDecision.ALLOW, null, "u", "  ", "c", "g",
                DbOperationCategory.SQL_TEXT, SOME_TIME)),
            new Case("blank connection", () -> new AuthorizationAuditPayload(
                DbAccessDecision.ALLOW, null, "u", "p", "  ", "g",
                DbOperationCategory.SQL_TEXT, SOME_TIME)),
            new Case("allow with a reason", () -> new AuthorizationAuditPayload(
                DbAccessDecision.ALLOW, DenialReason.NO_GRANT, "u", "p", "c", "g",
                DbOperationCategory.SQL_TEXT, SOME_TIME)),
            new Case("denial with no reason", () -> new AuthorizationAuditPayload(
                DbAccessDecision.DENY, null, "u", "p", "c", null,
                DbOperationCategory.SQL_TEXT, null)),
            new Case("allow on a read category", () -> new AuthorizationAuditPayload(
                DbAccessDecision.ALLOW, null, "u", "p", "c", "g",
                DbOperationCategory.CONTAINER_READ, SOME_TIME)),
            new Case("allow on a rollback", () -> new AuthorizationAuditPayload(
                DbAccessDecision.ALLOW, null, "u", "p", "c", "g",
                DbOperationCategory.TRANSACTION_ROLLBACK, SOME_TIME)),
            new Case("allow with no grant", () -> new AuthorizationAuditPayload(
                DbAccessDecision.ALLOW, null, "u", "p", "c", null,
                DbOperationCategory.SQL_TEXT, SOME_TIME)),
            new Case("allow with a blank grant", () -> new AuthorizationAuditPayload(
                DbAccessDecision.ALLOW, null, "u", "p", "c", "  ",
                DbOperationCategory.SQL_TEXT, SOME_TIME)),
            new Case("allow with no expiry", () -> new AuthorizationAuditPayload(
                DbAccessDecision.ALLOW, null, "u", "p", "c", "g",
                DbOperationCategory.SQL_TEXT, null)),
        };
        for (Case one : cases) {
            Assertions.assertThrows(
                IllegalArgumentException.class, () -> one.construction().run(),
                one.name() + " must be refused");
        }
    }

    /**
     * The two payload shapes that are legal are accepted
     */
    @Test
    public void theTwoLegalPayloadShapesAreAccepted() {
        Assertions.assertNotNull(new AuthorizationAuditPayload(
            DbAccessDecision.ALLOW, null, "u", "p", "c", "g", DbOperationCategory.SQL_TEXT, SOME_TIME));
        Assertions.assertNotNull(new AuthorizationAuditPayload(
            DbAccessDecision.DENY, DenialReason.NO_GRANT, "u", "p", "c", null,
            DbOperationCategory.CONTAINER_READ, null),
            "a denial can be about any category, including one no grant would back");
    }

    // ------------------------------------------- model input nulls

    /**
     * Security-relevant record components are refused when absent, not merely annotated
     * <p>
     * {@code org.jkiss.code.NotNull} has no runtime effect in this build - no processor, no weaver -
     * so an annotation on a component that a decision depends on is a comment unless the canonical
     * constructor checks it.
     */
    @Test
    public void annotatedComponentsAreCheckedAtRuntime() {
        Assertions.assertThrows(IllegalArgumentException.class,
            () -> new EndpointSnapshot(null, "d", "MANUAL", "h", "5432", "db"));
        Assertions.assertThrows(IllegalArgumentException.class,
            () -> new EndpointSnapshot("p", null, "MANUAL", "h", "5432", "db"));
        Assertions.assertThrows(IllegalArgumentException.class,
            () -> new EndpointSnapshot("p", "d", null, "h", "5432", "db"));
        Assertions.assertThrows(IllegalArgumentException.class,
            () -> new EndpointSnapshot("p", "d", "MANUAL", null, "5432", "db"));
        Assertions.assertThrows(IllegalArgumentException.class,
            () -> new EndpointSnapshot("p", "d", "MANUAL", "h", null, "db"));
        Assertions.assertThrows(IllegalArgumentException.class,
            () -> new EndpointSnapshot("p", "d", "MANUAL", "h", "5432", null));

        TempWritePermissionKey key = new TempWritePermissionKey("u", "p", "c");
        Assertions.assertThrows(IllegalArgumentException.class,
            () -> new TempWriteGrantRequest(
                key, "g", "admin", Duration.ofMinutes(30), "reason", null, 0L),
            "a grant request with no endpoint would be stored as a grant that can never match");
        Assertions.assertThrows(IllegalArgumentException.class,
            () -> new TempWriteGrantRequest(
                null, "g", "admin", Duration.ofMinutes(30), "reason", TempWriteTestSupport.ENDPOINT, 0L));
        Assertions.assertThrows(IllegalArgumentException.class,
            () -> new TempWriteGrantRequest(
                key, null, "admin", Duration.ofMinutes(30), "reason", TempWriteTestSupport.ENDPOINT, 0L));
        Assertions.assertThrows(IllegalArgumentException.class,
            () -> new TempWriteGrantRequest(
                key, "g", null, Duration.ofMinutes(30), "reason", TempWriteTestSupport.ENDPOINT, 0L));
        Assertions.assertThrows(IllegalArgumentException.class,
            () -> new WriteAuthorizationRequest("u", null, null, null, true),
            "a request with no category would produce a malformed decision");
    }

    // ------------------------------------------- the property allowlist itself

    /**
     * The allowlist is empty for driver properties on every supported driver
     * <p>
     * Asserted rather than assumed, because the class's whole safety argument is that it makes no
     * claim about which driver properties are harmless. A key added here without a recorded
     * justification fails this test, which is where the justification gets asked for.
     */
    @Test
    public void theDriverPropertyAllowlistIsEmptyEverywhere() {
        String[][] drivers = {
            {"postgresql", "postgres-jdbc"}, {"postgresql", "postgresql"},
            {"mysql", "mysql8"}, {"mysql", "mysql5"},
        };
        Assertions.assertEquals(
            SupportedTargetDatabase.allowedCount(), drivers.length,
            "every supported driver must be described by the property tables");
        for (String[] driver : drivers) {
            Assertions.assertTrue(
                ConnectionPropertyAllowlist.driverProperties(driver[0], driver[1]).isEmpty(),
                driver[0] + ":" + driver[1] + " must allow no driver property yet");
        }
        // Per provider, not per driver, and asymmetric on purpose. @dbeaver-show-all-dbs@ is
        // declared by the MySQL extension alone, with a default value the frontend does not strip,
        // so a MySQL connection stores it and would otherwise be refused. PostgreSQL declares no
        // provider property with a default, so it needs nothing allowed - and its counterpart key
        // @dbeaver-show-non-default-db@ is deliberately not allowed, because PostgreSQL opens a
        // separate connection per database.
        for (String driverId : new String[]{"postgres-jdbc", "postgresql"}) {
            Assertions.assertEquals(
                Set.of(), ConnectionPropertyAllowlist.providerProperties("postgresql", driverId),
                "postgresql:" + driverId + " needs no provider property allowed");
        }
        for (String driverId : new String[]{"mysql8", "mysql5"}) {
            Assertions.assertEquals(
                Set.of("@dbeaver-show-all-dbs@"),
                ConnectionPropertyAllowlist.providerProperties("mysql", driverId),
                "mysql:" + driverId + " allows exactly the one provider property it stores");
        }
        Assertions.assertEquals(
            SupportedTargetDatabase.allowedCount(), ConnectionPropertyAllowlist.describedDriverCount(),
            "a driver added to the target allowlist must be described here as well");
    }

    /**
     * A driver the tables do not describe allows nothing
     * <p>
     * Unreachable through the service, which checks the driver first, but the direction matters: an
     * unknown driver carrying unknown properties must not fall through to "allowed".
     */
    @Test
    public void anUndescribedDriverAllowsNoProperty() {
        Assertions.assertTrue(
            ConnectionPropertyAllowlist.allKeysAllowed(
                "oracle", "oracle_thin", Map.of(), Map.of()),
            "an empty map is allowed even for a driver nobody described - there is nothing to judge");
        Assertions.assertFalse(
            ConnectionPropertyAllowlist.allKeysAllowed(
                "oracle", "oracle_thin", Map.of("anything", "x"), Map.of()));
        Assertions.assertFalse(
            ConnectionPropertyAllowlist.allKeysAllowed(
                "oracle", "oracle_thin", Map.of(), Map.of("@dbeaver-show-all-dbs@", "false")),
            "even the otherwise allowed key is not allowed under an undescribed driver");
    }

    /**
     * Comparison is exact: no trimming, no case folding, no prefix matching
     * <p>
     * This mirrors how the drivers read the map. pgjdbc looks up the exact string, and Connector/J
     * marks each key case-sensitive or not individually - so a permissive comparison here would
     * accept a spelling the driver treats as a different property, or as the real one.
     */
    @Test
    public void allowlistComparisonIsExact() {
        // MySQL, because it is the only provider with a non-empty allowlist to compare against.
        String allowed = "@dbeaver-show-all-dbs@";
        Assertions.assertTrue(ConnectionPropertyAllowlist.allKeysAllowed(
            "mysql", "mysql8", Map.of(), Map.of(allowed, "false")));
        Assertions.assertFalse(
            ConnectionPropertyAllowlist.allKeysAllowed(
                "postgresql", "postgres-jdbc", Map.of(), Map.of(allowed, "false")),
            "the same key is not allowed under PostgreSQL, which never stores it");
        for (String variant : new String[]{
            allowed.toUpperCase(java.util.Locale.ROOT),
            allowed.toLowerCase(java.util.Locale.ROOT).replace("dbeaver", "DBeaver"),
            " " + allowed, allowed + " ", allowed + "x", "x" + allowed,
        }) {
            if (variant.equals(allowed)) {
                continue;
            }
            Assertions.assertFalse(
                ConnectionPropertyAllowlist.allKeysAllowed(
                    "mysql", "mysql8", Map.of(), Map.of(variant, "false")),
                "[" + variant + "] must not be accepted as [" + allowed + "]");
        }
    }

    // ---------------------------------------------------------------- reason text

    /**
     * A reason that could break the line it is written on is refused, not silently repaired
     * <p>
     * A reason reaches a log line and an audit row, both read line by line, so a newline inside one
     * value lets the rest be read as a separate record - which is how a forged audit entry gets
     * written by someone who can only supply a reason. Refused rather than stripped, because
     * stripping stores text nobody wrote.
     */
    @Test
    public void reasonRejectsControlCharactersAndLineSeparators() {
        String[] bad = {
            "two\rlines", "two\nlines", "two\r\nlines", "nul\u0000inside",
            "tab\tinside", "bell\u0007inside", "c1\u0085inside",
            "line\u2028separator", "paragraph\u2029separator",
        };
        for (String reason : bad) {
            Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> TempWriteRequestLimits.checkReason(reason),
                "must refuse " + reason.replaceAll("\\p{C}", "?"));
        }
        Assertions.assertEquals(
            "ordinary reason", TempWriteRequestLimits.checkReason("  ordinary reason  "),
            "an ordinary reason is still trimmed and accepted");
        Assertions.assertEquals(
            "with an accent " + (char) 0x00E9 + " and hangul " + (char) 0xC11C,
            TempWriteRequestLimits.checkReason("with an accent " + (char) 0x00E9 + " and hangul " + (char) 0xC11C),
            "non-ASCII text is not a control character");
    }

    /**
     * Grant and revoke reasons are checked identically
     * <p>
     * They go through the same method, and this pins that they keep doing so - a revoke reason
     * reaches the same audit row as a grant reason.
     */
    @Test
    public void grantAndRevokeReasonsAreCheckedTheSameWay() {
        TempWritePermissionKey key = new TempWritePermissionKey("u", "p", "c");
        for (String reason : new String[]{"break\rhere", "break\nhere", "nul\u0000here"}) {
            Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> new TempWriteGrantRequest(
                    key, "g", "admin", Duration.ofMinutes(30), reason, TempWriteTestSupport.ENDPOINT, 0L),
                "a grant reason must be refused");
            Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> new TempWriteRevokeRequest(key, "admin", reason, 1L),
                "a revoke reason must be refused");
        }
    }

    // ---------------------------------------------------------------- configuration

    /**
     * A missing, zero, negative or absurd setting falls back to the documented default
     * <p>
     * The direction is the whole point: a typo must not be a way to switch a guard off.
     */
    @Test
    public void brokenConfigurationFallsBackRatherThanDisablingTheCheck() {
        for (Integer skew : new Integer[]{null, 0, -1, -3600, 999_999}) {
            Assertions.assertEquals(
                DbAccessPolicyConfig.DEFAULT_CLOCK_SKEW_THRESHOLD,
                DbAccessPolicyConfig.sanitized(skew, 60).clockSkewThreshold(),
                "skew " + skew + " must fall back to the default");
        }
        for (Integer max : new Integer[]{null, 0, -1, -240, 99_999}) {
            Assertions.assertEquals(
                DbAccessPolicyConfig.DEFAULT_MAX_GRANT_DURATION,
                DbAccessPolicyConfig.sanitized(5, max).maxGrantDuration(),
                "max duration " + max + " must fall back to the default");
        }
    }

    @Test
    public void sensibleConfigurationIsKept() {
        DbAccessPolicyConfig config = DbAccessPolicyConfig.sanitized(12, 30);
        Assertions.assertEquals(Duration.ofSeconds(12), config.clockSkewThreshold());
        Assertions.assertEquals(Duration.ofMinutes(30), config.maxGrantDuration());
    }

    @Test
    public void defaultsAreTheDocumentedNumbers() {
        Assertions.assertEquals(Duration.ofSeconds(5), DbAccessPolicyConfig.defaults().clockSkewThreshold());
        Assertions.assertEquals(Duration.ofMinutes(240), DbAccessPolicyConfig.defaults().maxGrantDuration());
        Assertions.assertEquals(
            DbAccessPolicyConfig.DEFAULT_MAX_GRANT_DURATION, TempWriteRequestLimits.DEFAULT_MAX_DURATION,
            "the policy config and the request validator must agree on the ceiling");
    }

    /**
     * The record itself refuses a non-positive value, so nothing can construct one past the sanitiser
     */
    @Test
    public void configRecordRefusesNonPositiveValues() {
        Assertions.assertThrows(IllegalArgumentException.class,
            () -> new DbAccessPolicyConfig(Duration.ZERO, Duration.ofMinutes(1)));
        Assertions.assertThrows(IllegalArgumentException.class,
            () -> new DbAccessPolicyConfig(Duration.ofSeconds(1), Duration.ofMinutes(-1)));
    }

    // ---------------------------------------------------------------- duration and reason limits

    /**
     * Zero, negative and over the ceiling are all refused, and nothing is clamped
     */
    @Test
    public void durationLimitsRefuseRatherThanClamp() {
        Assertions.assertThrows(IllegalArgumentException.class,
            () -> TempWriteRequestLimits.checkDuration(Duration.ZERO, null));
        Assertions.assertThrows(IllegalArgumentException.class,
            () -> TempWriteRequestLimits.checkDuration(Duration.ofMinutes(-1), null));
        Assertions.assertThrows(IllegalArgumentException.class,
            () -> TempWriteRequestLimits.checkDuration(Duration.ofMinutes(241), null));
        Assertions.assertThrows(IllegalArgumentException.class,
            () -> TempWriteRequestLimits.checkDuration(null, null));
        // The boundary itself is allowed.
        TempWriteRequestLimits.checkDuration(Duration.ofMinutes(240), null);
        // A configured ceiling replaces the default, and is not itself a way to remove the limit.
        TempWriteRequestLimits.checkDuration(Duration.ofMinutes(30), Duration.ofMinutes(30));
        Assertions.assertThrows(IllegalArgumentException.class,
            () -> TempWriteRequestLimits.checkDuration(Duration.ofMinutes(31), Duration.ofMinutes(30)));
    }

    /**
     * A reason must be present and fit the column, and is stored trimmed
     */
    @Test
    public void reasonLimitsRefuseEmptyAndOverlongValues() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> TempWriteRequestLimits.checkReason(null));
        Assertions.assertThrows(IllegalArgumentException.class, () -> TempWriteRequestLimits.checkReason(""));
        Assertions.assertThrows(IllegalArgumentException.class, () -> TempWriteRequestLimits.checkReason("   "));
        Assertions.assertThrows(IllegalArgumentException.class,
            () -> TempWriteRequestLimits.checkReason("x".repeat(1001)));
        Assertions.assertEquals("x".repeat(1000), TempWriteRequestLimits.checkReason("x".repeat(1000)));
        Assertions.assertEquals("ticket 42", TempWriteRequestLimits.checkReason("  ticket 42  "));
        // Padding must not push a legitimate reason over the edge.
        Assertions.assertEquals(
            1000, TempWriteRequestLimits.checkReason("  " + "y".repeat(1000) + "  ").length());
    }

    // ---------------------------------------------------------------- decision shape

    /**
     * A denial must say why and an allow must not pretend to
     */
    @Test
    public void decisionRefusesContradictoryShapes() {
        DbAccessKey key = new DbAccessKey("u", "p", "c");
        Assertions.assertThrows(IllegalArgumentException.class, () -> new AuthorizationDecision(
            DbAccessDecision.DENY, null, key, DbOperationCategory.SQL_TEXT, null, null, null));
        Assertions.assertThrows(IllegalArgumentException.class, () -> new AuthorizationDecision(
            DbAccessDecision.ALLOW, DenialReason.NO_GRANT, key, DbOperationCategory.SQL_TEXT,
            "g", SOME_TIME, null));
        Assertions.assertThrows(IllegalArgumentException.class, () -> new AuthorizationDecision(
            DbAccessDecision.ALLOW, null, key, DbOperationCategory.SQL_TEXT, null, SOME_TIME, null));
    }

    @Test
    public void auditPayloadRefusesContradictoryShapes() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> new AuthorizationAuditPayload(
            DbAccessDecision.DENY, null, "u", "p", "c", null, DbOperationCategory.SQL_TEXT, null));
        Assertions.assertThrows(IllegalArgumentException.class, () -> new AuthorizationAuditPayload(
            DbAccessDecision.ALLOW, DenialReason.NO_GRANT, "u", "p", "c", "g",
            DbOperationCategory.SQL_TEXT, SOME_TIME));
        Assertions.assertThrows(IllegalArgumentException.class, () -> new AuthorizationAuditPayload(
            DbAccessDecision.ALLOW, null, " ", "p", "c", "g", DbOperationCategory.SQL_TEXT, SOME_TIME));
    }

    /**
     * No audit payload component is <em>named</em> after a statement, a credential or a host
     * <p>
     * A name check, and no more than that - it cannot tell what a value holds, only what the field is
     * called. It is still worth having: the payload is built from a fixed set of components, and a
     * field added later with an obvious name has to come past this test. What keeps values clean is
     * that the payload is assembled from the key, the grant id, the category and the expiry and from
     * nothing else, which the decision-shape tests pin.
     */
    @Test
    public void auditPayloadCarriesNothingSensitive() {
        var components = AuthorizationAuditPayload.class.getRecordComponents();
        Assertions.assertEquals(8, components.length, "a new audit field needs its own justification");
        for (var component : components) {
            String name = component.getName().toLowerCase(Locale.ROOT);
            for (String forbidden : new String[]{
                "sql", "statement", "query", "password", "credential", "secret", "token",
                "host", "url", "detail", "parameter"}
            ) {
                Assertions.assertFalse(
                    name.contains(forbidden),
                    "audit payload must not carry " + forbidden + ", found component " + component.getName());
            }
        }
    }

    /**
     * A key needs all three parts
     */
    @Test
    public void keyRefusesBlankParts() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> new DbAccessKey(" ", "p", "c"));
        Assertions.assertThrows(IllegalArgumentException.class, () -> new DbAccessKey("u", "", "c"));
        Assertions.assertThrows(IllegalArgumentException.class, () -> new DbAccessKey("u", "p", "  "));
        Assertions.assertEquals("u/p/c", new DbAccessKey("u", "p", "c").describe());
    }

    // ---------------------------------------------------------------- reasons and categories

    /**
     * Every denial reason has a safe, non-empty message that names nothing internal
     */
    @Test
    public void denialMessagesAreSafeAndPresent() {
        for (DenialReason reason : DenialReason.values()) {
            Assertions.assertFalse(reason.messageCode().isBlank(), reason + " needs a message code");
            Assertions.assertFalse(reason.userMessage().isBlank(), reason + " needs a user message");
            String message = reason.userMessage().toLowerCase(Locale.ROOT);
            for (String forbidden : new String[]{
                "select ", "insert ", "jdbc:", "exception", "stack", "password", "org.jkiss", "table_prefix"}
            ) {
                Assertions.assertFalse(
                    message.contains(forbidden),
                    reason + " user message must not mention " + forbidden);
            }
        }
    }

    /**
     * The reasons this slice reserves stay reserved
     * <p>
     * Moving one across this line is a later slice's job, and this assertion is what makes that
     * deliberate rather than incidental.
     */
    @Test
    public void everyDenialReasonIsAccountedFor() {
        Assertions.assertEquals(
            17, DenialReason.values().length,
            "a reason added without a decision about whether this slice produces it must fail here");
        long produced = java.util.Arrays.stream(DenialReason.values())
            .filter(DenialReason::producedByPolicyCore)
            .count();
        Assertions.assertEquals(
            12, produced,
            "eleven reasons the policy core produced before the endpoint gate, plus"
                + " ENDPOINT_UNSUPPORTED");
        Assertions.assertTrue(
            DenialReason.ENDPOINT_UNSUPPORTED.producedByPolicyCore(),
            "the endpoint gate is part of this slice, so its reason is produced here");
    }

    @Test
    public void reservedReasonsAreMarkedAsNotProducedYet() {
        for (DenialReason reason : new DenialReason[]{
            DenialReason.TRANSACTION_TAINTED, DenialReason.CONNECTION_BLOCKED,
            DenialReason.GRANT_SUPERSEDED, DenialReason.AUDIT_WRITE_FAILED,
            DenialReason.STATEMENT_NOT_ALLOWLISTED}
        ) {
            Assertions.assertFalse(reason.producedByPolicyCore(), reason + " is not implemented in this slice");
        }
        for (DenialReason reason : new DenialReason[]{
            DenialReason.NO_GRANT, DenialReason.GRANT_EXPIRED, DenialReason.GRANT_REVOKED,
            DenialReason.GRANT_STALE, DenialReason.USER_INACTIVE, DenialReason.CONNECTION_UNKNOWN,
            DenialReason.IDENTITY_MISSING, DenialReason.PERMISSION_STORE_UNAVAILABLE,
            DenialReason.CLOCK_SKEW_EXCEEDED, DenialReason.OPERATION_UNSUPPORTED,
            DenialReason.DBMS_UNSUPPORTED}
        ) {
            Assertions.assertTrue(reason.producedByPolicyCore(), reason + " is part of this slice");
        }
    }

    /**
     * The category vocabulary and how the write gate treats each one
     * <p>
     * The assertion about which categories are <em>not</em> write-gated is the one worth keeping
     * honest. A category classified as a read on the strength of a plausible-sounding javadoc, with a
     * test that only restated it, is how {@code GROUPING} spent three rounds looking verified; the
     * claim is now checked against the code path in the constant's javadoc, and this test is what
     * fails if someone moves it back.
     */
    @Test
    public void categoriesAreClassifiedAsStated() {
        Assertions.assertEquals(10, DbOperationCategory.values().length);
        for (DbOperationCategory category : new DbOperationCategory[]{
            DbOperationCategory.SQL_TEXT, DbOperationCategory.DATA_EDIT, DbOperationCategory.METADATA_DDL,
            DbOperationCategory.IMPORT_DATA, DbOperationCategory.EXPLAIN,
            DbOperationCategory.TRANSACTION_COMMIT, DbOperationCategory.TRANSACTION_AUTOCOMMIT_ON,
            // GROUPING joined this list after independent review. It had been classified as a read on
            // the strength of a javadoc claim that the query is assembled by the UI; the GraphQL field
            // is free text that the generator concatenates verbatim, and this project's own survey had
            // already recorded that as HIGH. See the constant's javadoc.
            DbOperationCategory.GROUPING}
        ) {
            Assertions.assertTrue(category.requiresWriteAuthorization(), category + " must be write-gated");
        }
        Assertions.assertFalse(DbOperationCategory.CONTAINER_READ.requiresWriteAuthorization());
        Assertions.assertEquals(
            DbOperationCategory.Gate.RECOVERY, DbOperationCategory.TRANSACTION_ROLLBACK.gate(),
            "rollback is the way out of trouble and is never judged");
    }

    /**
     * {@code EXPLAIN} is write-gated because {@code EXPLAIN ANALYZE} executes what it explains
     */
    @Test
    public void explainIsTreatedAsAWrite() {
        Assertions.assertTrue(DbOperationCategory.EXPLAIN.requiresWriteAuthorization());
    }
}
