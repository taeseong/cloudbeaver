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
import io.cloudbeaver.service.dbac.DbacEmbeddedSecurityController;
import io.cloudbeaver.service.dbac.db.DbacSchemaConstants;
import io.cloudbeaver.service.dbac.policy.AuthorizationDecision;
import io.cloudbeaver.service.dbac.policy.DbAccessPolicyConfig;
import io.cloudbeaver.service.dbac.policy.DbAccessPolicyService;
import io.cloudbeaver.service.dbac.policy.DbOperationCategory;
import io.cloudbeaver.service.dbac.policy.DenialReason;
import io.cloudbeaver.service.dbac.policy.WriteAuthorizationRequest;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteMutationCoordinator;
import io.cloudbeaver.test.platform.CEServerTestSuite;
import io.cloudbeaver.test.platform.dbac.FenceTestSupport.Db;
import io.cloudbeaver.test.platform.dbac.FenceTestSupport.Engine;
import io.cloudbeaver.test.platform.dbac.FenceTestSupport.GrantRow;
import io.cloudbeaver.test.platform.dbac.FenceTestSupport.HistoryRow;
import io.cloudbeaver.test.platform.dbac.FenceTestSupport.Intercepted;
import io.cloudbeaver.test.platform.dbac.KeyLockTestSupport.Pause;
import io.cloudbeaver.test.platform.dbac.KeyLockTestSupport.Worker;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.jkiss.dbeaver.DBException;
import org.jkiss.dbeaver.ext.h2.model.H2SQLDialect;
import org.jkiss.dbeaver.ext.postgresql.model.PostgreDialect;
import org.jkiss.dbeaver.model.impl.sql.BasicSQLDialect;
import org.jkiss.dbeaver.model.sql.SQLDialect;
import org.jkiss.dbeaver.model.sql.translate.SQLQueryTranslator;
import org.jkiss.utils.CommonUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.platform.suite.api.SelectClasses;

import java.io.Reader;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.time.Duration;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;

/**
 * P5-F: schema version 4 revokes every legacy grant in the transaction that records it, and nothing else does
 * <p>
 * A "version 3 database" here is one the real migration runner installed with a version manager shipping
 * version 3 - what the P4 build did. The upgrade is the real runner with this build's version manager. Rows
 * are written and read back with plain SQL, never through the code under test.
 * <p>
 * Each case runs on the test server's H2 metadata database, in a schema of its own, and those that the user
 * approval names for PostgreSQL run on the disposable PostgreSQL too. Failure injection happens on the
 * connection the runner is given, inside the very transaction under test, so whatever the injection wrote
 * is rolled back with everything else.
 */
@Timeout(value = 300, unit = TimeUnit.SECONDS, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
public class DbacFenceMigrationTest {

    private static final String HOST = "db.internal.example";
    private static final String DATABASE = "customer_prod";

    /** The current-table update the quarantine runs, as it is prepared */
    private static final String QUARANTINE_UPDATE = "UPDATE {table_prefix}" + DbacSchemaConstants.TABLE_TW_CURRENT;
    /** The history insert the quarantine runs, as it is prepared */
    private static final String QUARANTINE_HISTORY = "INSERT INTO {table_prefix}" + DbacSchemaConstants.TABLE_TW_HISTORY;
    /** The check after the quarantine, as it is prepared */
    private static final String QUARANTINE_CHECK =
        "SELECT COUNT(*) FROM {table_prefix}" + DbacSchemaConstants.TABLE_TW_CURRENT + " WHERE REVOKED_AT IS NULL";
    /** The two ways the version row is written, as they are prepared */
    private static final String VERSION_UPDATE = "UPDATE {table_prefix}" + DbacSchemaConstants.VERSION_TABLE_NAME;
    private static final String VERSION_INSERT = "INSERT INTO {table_prefix}" + DbacSchemaConstants.VERSION_TABLE_NAME;
    /** How the version row is read, as it is prepared */
    private static final String VERSION_READ = "SELECT VERSION FROM {table_prefix}" + DbacSchemaConstants.VERSION_TABLE_NAME;

    /** The fixed message a failed quarantine is refused with - the contract, written out */
    private static final String QUARANTINE_REFUSAL =
        "DBAC could not quarantine the legacy TEMP_WRITE grants; the version 4 migration is rolled back";
    /** The fixed message version 4 is refused with when it cannot be recorded */
    private static final String VERSION_REFUSAL = "DBAC could not record schema version 4 in this transaction; no grant was changed";
    /** The fixed message version 4 is refused with outside the migration transaction */
    private static final String TRANSACTION_REFUSAL =
        "DBAC records schema version 4 only inside the migration transaction; nothing was changed";
    /** The fixed message version 4 is refused with when the fence cannot have its own savepoint */
    private static final String SAVEPOINT_REFUSAL =
        "DBAC records schema version 4 only under a savepoint of the migration transaction; nothing was changed";

    /** The fence's events */
    private static final String QUARANTINE_FAILED = "DBAC_SCHEMA_FENCE_QUARANTINE_FAILED";
    private static final String VERSION_REFUSED = "DBAC_SCHEMA_FENCE_VERSION_REFUSED";
    private static final String UNDO_FAILED = "DBAC_SCHEMA_FENCE_UNDO_FAILED";

    private static Engine h2;
    private static Engine postgres;

    private final List<Map.Entry<Engine, String>> schemas = new ArrayList<>();
    private final MetadataLeaseFixture leases = new MetadataLeaseFixture();

    @BeforeAll
    public static void prepare() throws Exception {
        CEAppStarter.startServerIfNotStarted();
        EnforcementTestSupport.requirePostgres(KeyLockTestSupport.MONITOR);
        h2 = FenceTestSupport.h2(EnforcementTestSupport.metadata());
        postgres = FenceTestSupport.postgres();
    }

    @AfterEach
    public void cleanUp() throws Exception {
        try {
            leases.close();
        } finally {
            for (Map.Entry<Engine, String> schema : schemas) {
                FenceTestSupport.dropSchema(schema.getKey(), schema.getValue());
                Assertions.assertEquals(0, FenceTestSupport.countSchemas(schema.getKey(), schema.getValue()),
                    "FIXTURE: schema " + schema.getValue() + " was left behind");
            }
            schemas.clear();
        }
    }

    @NotNull
    private List<Engine> engines() {
        return List.of(h2, postgres);
    }

    @NotNull
    private String schema(@NotNull Engine engine, @NotNull String tag) {
        String schema = engine.schemaName(tag);
        schemas.add(new AbstractMap.SimpleEntry<>(engine, schema));
        return schema;
    }

    // ---------------------------------------------------------------- UR-0: what the fences cannot repair

    /**
     * UR-0: a grant left behind by a user that no longer exists gives nothing to a user created later under the same id
     */
    @Test
    public void ur0AnOrphanGrantGivesNothingToAUserCreatedLater() throws Exception {
        List<String> violations = new ArrayList<>();
        for (Engine engine : engines()) {
            String label = "UR-0 [" + engine.name() + "]";
            String schema = schema(engine, "ur0");
            FenceTestSupport.installVersionThree(engine, schema);
            try (Db db = engine.open(schema)) {
                FenceTestSupport.insertGrant(db.proxied(), "ur0-user", FenceTestSupport.CONNECTION, 1, Duration.ofMinutes(30), null);
                Assertions.assertEquals(0, FenceTestSupport.count(db.proxied(), "CB_USER", "USER_ID", "ur0-user"),
                    "FIXTURE " + label + ": the grant's user must not exist");
            }
            if (!upgraded(violations, label, engine, schema)) {
                continue;
            }
            try (Db db = engine.open(schema)) {
                PolicyTestSupport.putUser(db.proxied(), "ur0-user", true);
            }
            AuthorizationDecision decision = service(engine, schema).authorize(request("ur0-user"));
            expect(violations, label + ": the user created after the upgrade is not allowed", false, decision.isAllowed());
            expect(violations, label + ": the orphan grant is revoked", DenialReason.GRANT_REVOKED, decision.denialReason());
        }
        Assertions.assertEquals(List.of(), violations, "UR-0");
    }

    /**
     * UR-0b: a grant from an earlier incarnation gives nothing to the incarnation that exists at the upgrade
     */
    @Test
    public void ur0bAGrantOfAnEarlierIncarnationGivesNothingToTheCurrentOne() throws Exception {
        List<String> violations = new ArrayList<>();
        for (Engine engine : engines()) {
            String label = "UR-0b [" + engine.name() + "]";
            String schema = schema(engine, "ur0b");
            FenceTestSupport.installVersionThree(engine, schema);
            try (Db db = engine.open(schema)) {
                FenceTestSupport.insertGrant(db.proxied(), "ur0b-user", FenceTestSupport.CONNECTION, 1, Duration.ofMinutes(30), null);
                PolicyTestSupport.putUser(db.proxied(), "ur0b-user", true);
            }
            if (!upgraded(violations, label, engine, schema)) {
                continue;
            }
            AuthorizationDecision decision = service(engine, schema).authorize(request("ur0b-user"));
            expect(violations, label + ": the incarnation existing at the upgrade is not allowed", false, decision.isAllowed());
            expect(violations, label + ": the grant is revoked", DenialReason.GRANT_REVOKED, decision.denialReason());
        }
        Assertions.assertEquals(List.of(), violations, "UR-0b");
    }

    // ---------------------------------------------------------------- MG: the quarantine

    /**
     * MG-1: every grant that is not revoked is revoked - expired or not - at the next revision, with one REVOKED event each
     */
    @Test
    public void mg1EveryUnrevokedGrantIsRevokedWithOneEventEach() throws Exception {
        List<String> violations = new ArrayList<>();
        for (Engine engine : engines()) {
            String label = "MG-1 [" + engine.name() + "]";
            String schema = schema(engine, "mg1");
            FenceTestSupport.installVersionThree(engine, schema);
            List<GrantRow> before;
            List<HistoryRow> historyBefore;
            try (Db db = engine.open(schema)) {
                FenceTestSupport.insertGrant(db.proxied(), "mg1-active", FenceTestSupport.CONNECTION, 1, Duration.ofMinutes(30), null);
                FenceTestSupport.insertGrant(db.proxied(), "mg1-active", "fence-connection-2", 2, Duration.ofMinutes(30), null);
                FenceTestSupport.insertGrant(db.proxied(), "mg1-expired", FenceTestSupport.CONNECTION, 3, Duration.ofMinutes(-30), null);
                FenceTestSupport.insertGrant(
                    db.proxied(), "mg1-revoked", FenceTestSupport.CONNECTION, 5, Duration.ofMinutes(30), "admin-2");
                FenceTestSupport.insertHistory(db.proxied(), "mg1-old-1", "mg1-active", FenceTestSupport.CONNECTION, "GRANTED", 1);
                FenceTestSupport.insertHistory(db.proxied(), "mg1-old-2", "mg1-revoked", FenceTestSupport.CONNECTION, "REVOKED", 5);
                before = FenceTestSupport.grants(db.proxied());
                historyBefore = FenceTestSupport.history(db.proxied());
            }
            if (!upgraded(violations, label, engine, schema)) {
                continue;
            }
            try (Db db = engine.open(schema)) {
                expect(violations, label + ": version", 4, DbacTestSupport.readVersion(db.proxied()));
                expect(violations, label + ": version rows", 1, DbacTestSupport.countVersionRows(db.proxied()));
                expect(violations, label + ": nothing is left unrevoked", 0, FenceTestSupport.unrevoked(db.proxied()));
                checkQuarantined(violations, label, before, historyBefore,
                    FenceTestSupport.grants(db.proxied()), FenceTestSupport.history(db.proxied()));
            }
        }
        Assertions.assertEquals(List.of(), violations, "MG-1");
    }

    /**
     * Compares a quarantine's result with what was there before it
     * <p>
     * A grant that was revoked is untouched. Every other grant keeps everything it was issued with, is one
     * revision further, and is revoked by the fence. History keeps every old event and gains exactly one
     * REVOKED event per quarantined grant, carrying the new revision, the grant's expiry and, as its time,
     * the very instant the row was revoked; every event id is a new UUID.
     */
    private static void checkQuarantined(
        @NotNull List<String> violations,
        @NotNull String label,
        @NotNull List<GrantRow> before,
        @NotNull List<HistoryRow> historyBefore,
        @NotNull List<GrantRow> after,
        @NotNull List<HistoryRow> historyAfter
    ) {
        expect(violations, label + ": grant rows", before.size(), after.size());
        Map<String, GrantRow> byKey = after.stream().collect(Collectors.toMap(GrantRow::key, Function.identity()));
        Set<String> oldEvents = historyBefore.stream().map(HistoryRow::eventId).collect(Collectors.toSet());
        List<HistoryRow> added = historyAfter.stream().filter(event -> !oldEvents.contains(event.eventId())).toList();
        expect(violations, label + ": old events are kept as they were",
            historyBefore.stream().map(HistoryRow::whole).toList(),
            historyAfter.stream().filter(event -> oldEvents.contains(event.eventId())).map(HistoryRow::whole).toList());
        int quarantined = 0;
        for (GrantRow old : before) {
            GrantRow now = byKey.get(old.key());
            if (now == null) {
                violations.add(label + ": grant " + old.key() + " disappeared");
                continue;
            }
            List<HistoryRow> events = added.stream().filter(event -> event.key().equals(old.key())).toList();
            if (old.revokedAt() != null) {
                expect(violations, label + ": the already revoked " + old.key() + " is untouched", old.whole(), now.whole());
                expect(violations, label + ": the already revoked " + old.key() + " gains no event", 0, events.size());
                continue;
            }
            quarantined++;
            expect(violations, label + ": " + old.key() + " keeps what it was issued with", old.issued(), now.issued());
            expect(violations, label + ": " + old.key() + " is one revision further", old.revision() + 1, now.revision());
            expect(violations, label + ": " + old.key() + " is revoked", true, now.revokedAt() != null);
            expect(violations, label + ": " + old.key() + " revoked by", FenceTestSupport.FENCE_ACTOR, now.revokedBy());
            expect(violations, label + ": " + old.key() + " revoke reason", FenceTestSupport.FENCE_REASON, now.revokeReason());
            expect(violations, label + ": " + old.key() + " gains exactly one event", 1, events.size());
            if (events.size() != 1 || now.revokedAt() == null) {
                continue;
            }
            HistoryRow event = events.get(0);
            expect(violations, label + ": " + old.key() + " event type", "REVOKED", event.changeType());
            expect(violations, label + ": " + old.key() + " event grant", old.grantId(), event.grantId());
            expect(violations, label + ": " + old.key() + " event actor", FenceTestSupport.FENCE_ACTOR, event.actorId());
            expect(violations, label + ": " + old.key() + " event reason", FenceTestSupport.FENCE_REASON, event.reason());
            expect(violations, label + ": " + old.key() + " event revision", now.revision(), event.revision());
            expect(violations, label + ": " + old.key() + " event expiry", old.expiresAt().toInstant(),
                event.expiresAt() == null ? null : event.expiresAt().toInstant());
            expect(violations, label + ": " + old.key() + " event time is the revocation", now.revokedAt().toInstant(),
                event.changeTime().toInstant());
            expect(violations, label + ": " + old.key() + " event id is a UUID", true, FenceTestSupport.isUuid(event.eventId()));
        }
        expect(violations, label + ": one new event per quarantined grant", quarantined, added.size());
        expect(violations, label + ": every new event id is distinct", added.size(),
            (int) added.stream().map(HistoryRow::eventId).distinct().count());
    }

    /**
     * MG-2: a new installation is version 4 with nothing to revoke, and the version 4 script changes nothing
     */
    @Test
    public void mg2ANewInstallationIsVersionFourWithNothingToRevoke() throws Exception {
        List<String> violations = new ArrayList<>();
        for (Engine engine : engines()) {
            String label = "MG-2 [" + engine.name() + "]";
            String schema = schema(engine, "mg2");
            FenceTestSupport.freshSchema(engine, schema);
            if (!upgraded(violations, label, engine, schema)) {
                continue;
            }
            try (Db db = engine.open(schema)) {
                expect(violations, label + ": version", DbacSchemaConstants.CURRENT_SCHEMA_VERSION,
                    DbacTestSupport.readVersion(db.proxied()));
                expect(violations, label + ": version rows", 1, DbacTestSupport.countVersionRows(db.proxied()));
                expect(violations, label + ": grants", 0, FenceTestSupport.grants(db.proxied()).size());
                expect(violations, label + ": history", 0, FenceTestSupport.history(db.proxied()).size());
            }
        }
        for (SQLDialect dialect : new SQLDialect[]{new H2SQLDialect(), new PostgreDialect()}) {
            Reader reader = DbacTestSupport.realScriptSource()
                .openSchemaUpdateScript(KeyLockTestSupport.MONITOR, 4, dialect.getDialectId());
            Assertions.assertNotNull(reader, "MG-2: dbac_schema_update_4.sql must resolve for " + dialect.getDialectId());
            String text;
            try (Reader r = reader) {
                text = CommonUtils.normalizeTableNames(new String(readAll(r)), "dbac_fence_probe");
            }
            List<String> statements = DbacScriptStatements.split(SQLQueryTranslator.translateScript(
                new BasicSQLDialect() {
                }, dialect, SQLQueryTranslator.getDefaultPreferenceStore(), text));
            expect(violations, "MG-2: the version 4 script is one stateless statement on " + dialect.getDialectId(),
                List.of("SELECT 1"), statements);
        }
        Assertions.assertEquals(List.of(), violations, "MG-2");
    }

    @NotNull
    private static char[] readAll(@NotNull Reader reader) throws Exception {
        StringBuilder sb = new StringBuilder();
        char[] buffer = new char[4096];
        int read;
        while ((read = reader.read(buffer)) > 0) {
            sb.append(buffer, 0, read);
        }
        return sb.toString().toCharArray();
    }

    /** How MG-3 expects a start to end */
    private enum Outcome {
        /** the fence refuses with a fixed message and no cause */
        REFUSED,
        /** the fence passes on the very {@code Error} it was given */
        SAME_ERROR
    }

    /**
     * One way MG-3 makes the version 4 migration fail, and how the clean-up around it fails as well
     * <p>
     * A clean-up failure is armed by the injection itself, when its statement first runs: the runner rolls back once on its own
     * right after the version check, and that rollback must still work. Creating a savepoint fails from the start - nothing else
     * asks for one.
     */
    private static final class Breakage {
        final String tag;
        final String name;
        /** The statement the injection is attached to; null when the migration fails before any statement */
        String statement;
        /** A new injection for each run, given where to put what it throws, so no state carries over from one engine to the next */
        Function<AtomicReference<Throwable>, FenceTestSupport.Action> action = raised -> (target, sql, parameters) -> { };
        Outcome outcome = Outcome.REFUSED;
        /** The fixed message the fence refuses with */
        String refusal = QUARANTINE_REFUSAL;
        /** The events the fence must log, each as an event code and a detail */
        final List<String[]> logged = new ArrayList<>();
        /** What a plain rollback throws once armed */
        Supplier<Throwable> plainRollback;
        /** What a rollback to a savepoint throws once armed */
        Supplier<Throwable> savepointRollback;
        /** What creating a savepoint throws */
        Supplier<Throwable> setSavepoint;
        /** Once armed, the SQL whose results read as SQL NULL */
        String readsNullFrom;
        /** Whether creating a savepoint gives none */
        boolean setSavepointGivesNull;
        /** What the close throws once armed, after closing */
        Supplier<Throwable> closeFailure;
        /** What {@code getAutoCommit} throws from its second call on - the first is the runner's, as it opens its transaction */
        Supplier<Throwable> getAutoCommitFailure;
        /** Whether the fence must end by closing the connection */
        boolean closes;

        Breakage(@NotNull String tag, @NotNull String name) {
            this.tag = tag;
            this.name = name;
        }

        @NotNull
        Breakage at(@NotNull String statement, @NotNull Function<AtomicReference<Throwable>, FenceTestSupport.Action> action) {
            this.statement = statement;
            this.action = action;
            return this;
        }

        @NotNull
        Breakage passesTheError() {
            this.outcome = Outcome.SAME_ERROR;
            this.refusal = null;
            return this;
        }

        @NotNull
        Breakage refusing(@NotNull String refusal) {
            this.refusal = refusal;
            return this;
        }

        @NotNull
        Breakage logs(@NotNull String event, @NotNull String detail) {
            logged.add(new String[]{event, detail});
            return this;
        }

        @NotNull
        Breakage plainRollbackFails(@NotNull Supplier<Throwable> failure) {
            this.plainRollback = failure;
            return this;
        }

        @NotNull
        Breakage savepointRollbackFails(@NotNull Supplier<Throwable> failure) {
            this.savepointRollback = failure;
            return this;
        }

        @NotNull
        Breakage setSavepointFails(@NotNull Supplier<Throwable> failure) {
            this.setSavepoint = failure;
            return this;
        }

        @NotNull
        Breakage closes() {
            this.closes = true;
            return this;
        }

        @NotNull
        Breakage readsNullFrom(@NotNull String sql) {
            this.readsNullFrom = sql;
            return this;
        }

        @NotNull
        Breakage setSavepointGivesNull() {
            this.setSavepointGivesNull = true;
            return this;
        }

        @NotNull
        Breakage closeFails(@NotNull Supplier<Throwable> failure) {
            this.closeFailure = failure;
            return this;
        }

        @NotNull
        Breakage getAutoCommitFails(@NotNull Supplier<Throwable> failure) {
            this.getAutoCommitFailure = failure;
            return this;
        }

        /** Whether the fence must refuse before it even asks for its savepoint */
        boolean refusedBeforeSavepoint() {
            return getAutoCommitFailure != null;
        }

        /** Whether the fence cannot have its savepoint, so it must write nothing */
        boolean withoutSavepoint() {
            return setSavepoint != null || setSavepointGivesNull;
        }

        void arm(@NotNull Intercepted intercepted) {
            if (plainRollback != null && intercepted.rollbackFailure == null) {
                intercepted.rollbackFailure = plainRollback.get();
            }
            if (savepointRollback != null && intercepted.savepointRollbackFailure == null) {
                intercepted.savepointRollbackFailure = savepointRollback.get();
            }
            if (readsNullFrom != null) {
                intercepted.readsNullFrom = readsNullFrom;
            }
            if (closeFailure != null && intercepted.closeFailure == null) {
                intercepted.closeFailure = closeFailure.get();
            }
        }
    }

    /** An injection that throws what {@code failure} makes at the {@code nth} run of its statement, remembering it */
    @NotNull
    private static Function<AtomicReference<Throwable>, FenceTestSupport.Action> raise(int nth, @NotNull Supplier<Throwable> failure) {
        return raised -> {
            AtomicInteger seen = new AtomicInteger();
            return (target, sql, parameters) -> {
                if (seen.incrementAndGet() == nth) {
                    Throwable thrown = failure.get();
                    raised.set(thrown);
                    FenceTestSupport.<SQLException>sneakyThrow(thrown);
                }
            };
        };
    }

    /** What every injected failure says: the secret marker and a credential, which no log may carry */
    @NotNull
    private static String injected(@NotNull String where) {
        return "injected " + where + " failure " + LifecycleTestSupport.SECRET_MARKER + " " + LifecycleTestSupport.CREDENTIAL_FRAGMENT;
    }

    @NotNull
    private static SQLException injectedSql(@NotNull String where) {
        return new SQLException(injected(where), "42000");
    }

    @NotNull
    private static LifecycleTestSupport.InjectedError injectedError(@NotNull String where) {
        return new LifecycleTestSupport.InjectedError(where);
    }

    /**
     * MG-3: a failure anywhere in the quarantine rolls the whole upgrade back - version, grants and history - and fails the start
     * <p>
     * On both engines: PostgreSQL rolls DDL back as well and aborts a transaction at its first failed statement,
     * H2 does neither. Each failure is also logged by event code alone - no message, statement, schema or user.
     * <p>
     * The fence undoes its own work, whatever else fails: it writes nothing before it has a savepoint of its own, goes back to it
     * first, rolls the whole transaction back when that fails and closes the connection when that fails too. So nothing it wrote is
     * left for the runner, whose rollback may fail and whose transaction then turns auto-commit back on - which commits what is left.
     * What the fence itself threw is checked as the runner received it: a fixed message with no cause, or the very {@code Error}.
     */
    @Test
    public void mg3AFailingQuarantineRollsEverythingBack() throws Exception {
        List<Breakage> breakages = List.of(
            new Breakage("mg3_sql", "a statement fails")
                .at(QUARANTINE_UPDATE, raise(1, () -> injectedSql("quarantine")))
                .logs(QUARANTINE_FAILED, "STATEMENT_FAILED"),
            new Breakage("mg3_rows", "an update hits no row")
                .at(QUARANTINE_UPDATE, raised -> new FenceTestSupport.Action() {
                    private final AtomicBoolean done = new AtomicBoolean();

                    @Override
                    public void run(@NotNull Connection target, @NotNull String sql, @NotNull List<Object> parameters) throws SQLException {
                        if (done.compareAndSet(false, true)) {
                            // Someone else revokes every live grant at the revision the quarantine is about to
                            // write: its update finds no row, though the history and the final check would pass.
                            FenceTestSupport.execute(target, "UPDATE {table_prefix}DBAC_TW_CURRENT SET REVISION = REVISION + 1,"
                                + " REVOKED_AT = CURRENT_TIMESTAMP, REVOKED_BY = 'mg3-concurrent' WHERE REVOKED_AT IS NULL");
                        }
                    }
                })
                .logs(QUARANTINE_FAILED, "REVOKE_MISSED"),
            new Breakage("mg3_error", "an Error")
                .at(QUARANTINE_HISTORY, raise(1, () -> injectedError("quarantine history")))
                .passesTheError()
                .logs(QUARANTINE_FAILED, "ERROR"),
            new Breakage("mg3_error_rb", "an Error, and the rollback fails too")
                .at(QUARANTINE_HISTORY, raise(1, () -> injectedError("quarantine history")))
                .passesTheError()
                .logs(QUARANTINE_FAILED, "ERROR")
                .plainRollbackFails(() -> injectedError("rollback")),
            // The runner's own rollback fails, so its transaction commits whatever is left in it.
            new Breakage("mg3_a1", "a SQLException, and the runner's rollback fails")
                .at(QUARANTINE_UPDATE, raise(2, () -> injectedSql("quarantine")))
                .logs(QUARANTINE_FAILED, "STATEMENT_FAILED")
                .plainRollbackFails(() -> injectedSql("runner rollback")),
            // A DBException the fence's own code raises - a version row read back as NULL, which names the schema - after
            // somebody moved the row inside the same transaction. An injection cannot throw one: a reflection proxy turns a
            // checked exception its interface does not declare into an UndeclaredThrowableException.
            new Breakage("mg3_a2", "a DBException, and the runner's rollback fails")
                .at(VERSION_UPDATE, raised -> (target, sql, parameters) ->
                    FenceTestSupport.execute(target, "UPDATE {table_prefix}" + DbacSchemaConstants.VERSION_TABLE_NAME + " SET VERSION = 7"))
                .readsNullFrom(VERSION_READ)
                .refusing(VERSION_REFUSAL)
                .logs(VERSION_REFUSED, "VERSION_STATEMENT_FAILED")
                .plainRollbackFails(() -> injectedSql("runner rollback")),
            new Breakage("mg3_a3", "a RuntimeException, and the runner's rollback fails")
                .at(QUARANTINE_UPDATE, raise(2, () -> new LifecycleTestSupport.InjectedRuntimeException("quarantine update")))
                .logs(QUARANTINE_FAILED, "STATEMENT_FAILED")
                .plainRollbackFails(() -> injectedSql("runner rollback")),
            new Breakage("mg3_a4", "an Error, and a plain rollback fails")
                .at(QUARANTINE_HISTORY, raise(2, () -> injectedError("quarantine history")))
                .passesTheError()
                .logs(QUARANTINE_FAILED, "ERROR")
                .plainRollbackFails(() -> injectedError("rollback")),
            // Going back to the fence savepoint fails.
            new Breakage("mg3_b1", "a SQLException, the savepoint rollback fails, the full rollback works")
                .at(QUARANTINE_UPDATE, raise(2, () -> injectedSql("quarantine")))
                .logs(QUARANTINE_FAILED, "STATEMENT_FAILED")
                .logs(UNDO_FAILED, "SAVEPOINT_ROLLBACK_FAILED")
                .savepointRollbackFails(() -> injectedSql("savepoint rollback")),
            new Breakage("mg3_b2", "an Error, the savepoint rollback fails with one too, the full rollback works")
                .at(QUARANTINE_HISTORY, raise(2, () -> injectedError("quarantine history")))
                .passesTheError()
                .logs(QUARANTINE_FAILED, "ERROR")
                .logs(UNDO_FAILED, "SAVEPOINT_ROLLBACK_FAILED")
                .savepointRollbackFails(() -> injectedError("savepoint rollback")),
            new Breakage("mg3_c1", "a SQLException, the savepoint and the full rollback fail, the close works")
                .at(QUARANTINE_UPDATE, raise(2, () -> injectedSql("quarantine")))
                .logs(QUARANTINE_FAILED, "STATEMENT_FAILED")
                .logs(UNDO_FAILED, "SAVEPOINT_ROLLBACK_FAILED")
                .logs(UNDO_FAILED, "ROLLBACK_FAILED")
                .savepointRollbackFails(() -> injectedSql("savepoint rollback"))
                .plainRollbackFails(() -> injectedSql("rollback"))
                .closes(),
            new Breakage("mg3_c2", "an Error, the savepoint and the full rollback fail with Errors, the close works")
                .at(QUARANTINE_HISTORY, raise(2, () -> injectedError("quarantine history")))
                .passesTheError()
                .logs(QUARANTINE_FAILED, "ERROR")
                .logs(UNDO_FAILED, "SAVEPOINT_ROLLBACK_FAILED")
                .logs(UNDO_FAILED, "ROLLBACK_FAILED")
                .savepointRollbackFails(() -> injectedError("savepoint rollback"))
                .plainRollbackFails(() -> injectedError("rollback"))
                .closes(),
            new Breakage("mg3_c3", "a SQLException, both rollbacks fail, and the close reports a failure after closing")
                .at(QUARANTINE_UPDATE, raise(2, () -> injectedSql("quarantine")))
                .logs(QUARANTINE_FAILED, "STATEMENT_FAILED")
                .logs(UNDO_FAILED, "SAVEPOINT_ROLLBACK_FAILED")
                .logs(UNDO_FAILED, "ROLLBACK_FAILED")
                .logs(UNDO_FAILED, "CLOSE_FAILED")
                .savepointRollbackFails(() -> injectedSql("savepoint rollback"))
                .plainRollbackFails(() -> injectedSql("rollback"))
                .closeFails(() -> injectedSql("close"))
                .closes(),
            // The fence cannot have its savepoint at all.
            new Breakage("mg3_d1", "the fence savepoint cannot be created")
                .refusing(SAVEPOINT_REFUSAL)
                .logs(VERSION_REFUSED, "SAVEPOINT_FAILED")
                .setSavepointFails(() -> injectedSql("savepoint")),
            new Breakage("mg3_d2", "savepoints are not supported")
                .refusing(SAVEPOINT_REFUSAL)
                .logs(VERSION_REFUSED, "SAVEPOINT_UNSUPPORTED")
                .setSavepointFails(() -> new SQLFeatureNotSupportedException(injected("savepoint"))),
            new Breakage("mg3_d3", "the fence savepoint comes back as nothing")
                .refusing(SAVEPOINT_REFUSAL)
                .logs(VERSION_REFUSED, "SAVEPOINT_FAILED")
                .setSavepointGivesNull(),
            new Breakage("mg3_d4", "an Error while the fence savepoint is created")
                .passesTheError()
                .logs(VERSION_REFUSED, "SAVEPOINT_FAILED")
                .setSavepointFails(() -> injectedError("savepoint")),
            // The fence cannot even tell whether it runs inside a transaction.
            new Breakage("mg3_e1", "whether the connection is in a transaction cannot be told")
                .refusing(TRANSACTION_REFUSAL)
                .logs(VERSION_REFUSED, "TRANSACTION_UNKNOWN")
                .getAutoCommitFails(() -> injectedSql("auto-commit")));
        List<String> violations = new ArrayList<>();
        for (Engine engine : engines()) {
            for (Breakage breakage : breakages) {
                String label = "MG-3 [" + engine.name() + " " + breakage.name + "]";
                String schema = schema(engine, breakage.tag);
                final Snapshot before = legacyState(engine, schema);
                AtomicReference<Throwable> raised = new AtomicReference<>();
                AtomicReference<Throwable> thrown = new AtomicReference<>();
                FenceTestSupport.Recording recording = new FenceTestSupport.Recording();
                Intercepted intercepted;
                LifecycleTestSupport.Captured captured;
                try (Db db = engine.open(schema)) {
                    AtomicReference<Intercepted> self = new AtomicReference<>();
                    FenceTestSupport.Action action = breakage.action.apply(raised);
                    FenceTestSupport.Action armed = (target, sql, parameters) -> {
                        breakage.arm(self.get());
                        action.run(target, sql, parameters);
                    };
                    intercepted = new Intercepted(db.proxied(),
                        breakage.statement == null ? sql -> false : FenceTestSupport.startsWith(breakage.statement), armed);
                    self.set(intercepted);
                    if (breakage.setSavepoint != null) {
                        intercepted.setSavepointFailure = breakage.setSavepoint.get();
                        raised.set(intercepted.setSavepointFailure);
                    }
                    intercepted.setSavepointGivesNull = breakage.setSavepointGivesNull;
                    if (breakage.getAutoCommitFailure != null) {
                        intercepted.getAutoCommitFailure = breakage.getAutoCommitFailure.get();
                        intercepted.getAutoCommitFailsFrom = 2;
                    }
                    captured = captureLogs(() -> thrown.set(call(() -> FenceTestSupport.migrate(intercepted.connection, schema,
                        engine.dialect(), DbacTestSupport.realScriptSource(), recording))));
                }
                expect(violations, "FIXTURE " + label + ": the fence version was asked for", true, recording.fenceAsked);
                if (breakage.getAutoCommitFailure != null) {
                    // The runner asks first, as it opens its transaction; only what is asked after that fails.
                    expect(violations, "FIXTURE " + label + ": the runner asked about auto-commit as it opened its transaction", true,
                        intercepted.getAutoCommitCalls.get() >= 1);
                    expect(violations, label + ": the fence asks whether it runs inside a transaction", true,
                        intercepted.getAutoCommitCalls.get() >= 2);
                }
                if (breakage.statement != null) {
                    expect(violations, "FIXTURE " + label + ": the injection fired", true,
                        !intercepted.fired.isEmpty() || thrown.get() == null);
                }
                expect(violations, label + ": the start fails", true, thrown.get() != null);
                if (breakage.outcome == Outcome.SAME_ERROR) {
                    expect(violations, "FIXTURE " + label + ": an Error was injected", true,
                        raised.get() instanceof Error || thrown.get() == null);
                    expect(violations, label + ": the fence passes on the very Error it was given", true,
                        raised.get() != null && recording.fenceThrew == raised.get());
                    expect(violations, label + ": the start ends with that very Error", true,
                        raised.get() != null && thrown.get() == raised.get());
                } else {
                    checkFixedRefusal(violations, label + " as the fence threw it", recording.fenceThrew, schema);
                    expect(violations, label + ": the fence refuses with its fixed message", breakage.refusal,
                        recording.fenceThrew == null ? null : recording.fenceThrew.getMessage());
                    if (breakage.plainRollback == null) {
                        // The runner's rollback works, so what the fence threw is what the start ends with.
                        checkFixedRefusal(violations, label, thrown.get(), schema);
                    }
                }
                checkUnchanged(violations, label, engine, schema, before);
                try (Db db = engine.open(schema)) {
                    expect(violations, label + ": one version row", 1, DbacTestSupport.countVersionRows(db.proxied()));
                }
                checkFenceSavepoint(violations, label, breakage, intercepted);
                checkFenceLog(violations, label, captured, schema);
                for (String[] event : breakage.logged) {
                    expect(violations, label + ": logs " + event[0] + " " + event[1], true, captured.dbacMessages().stream()
                        .anyMatch(message -> message.contains("event=" + event[0] + " ")
                            && (message.contains("detail=" + event[1] + " ") || message.contains("detail=" + event[1] + "]"))));
                }
            }
        }
        Assertions.assertEquals(List.of(), violations, "MG-3");
    }

    /**
     * The fence asked for a savepoint of its own before it wrote the version, and a failure went back to that savepoint first
     * <p>
     * When the savepoint cannot be had, the fence still asked for it, and wrote nothing.
     */
    private static void checkFenceSavepoint(
        @NotNull List<String> violations,
        @NotNull String label,
        @NotNull Breakage breakage,
        @NotNull Intercepted intercepted
    ) {
        int asked = intercepted.indexOf(0, FenceTestSupport.CALL_SET_SAVEPOINT::equals);
        int written = intercepted.indexOf(0, call -> call.startsWith(FenceTestSupport.CALL_PREPARE + VERSION_UPDATE)
            || call.startsWith(FenceTestSupport.CALL_PREPARE + VERSION_INSERT));
        if (breakage.refusedBeforeSavepoint()) {
            expect(violations, label + ": refused before the fence asks for a savepoint", -1, asked);
            expect(violations, label + ": refused before the fence writes the version", -1, written);
            expect(violations, label + ": refused before the fence touches a grant or history table", 0L, intercepted.grantStatements());
            return;
        }
        expect(violations, label + ": the fence asks for a savepoint of its own", true, asked >= 0);
        if (breakage.withoutSavepoint()) {
            expect(violations, label + ": without its savepoint the fence writes no version", -1, written);
            expect(violations, label + ": without its savepoint the fence touches no grant or history table", 0L,
                intercepted.grantStatements());
            return;
        }
        expect(violations, label + ": the savepoint comes before the version is written", true, asked >= 0 && written > asked);
        int undone = asked < 0 ? -1 : intercepted.indexOf(asked, call -> FenceTestSupport.CALL_ROLLBACK.equals(call)
            || FenceTestSupport.CALL_ROLLBACK_TO_SAVEPOINT.equals(call));
        expect(violations, label + ": the failure is first taken back to a savepoint", FenceTestSupport.CALL_ROLLBACK_TO_SAVEPOINT,
            undone < 0 ? null : intercepted.calls.get(undone));
        expect(violations, label + ": that savepoint is the fence's own", true, !intercepted.savepoints.isEmpty()
            && !intercepted.rolledBackTo.isEmpty() && intercepted.rolledBackTo.get(0) == intercepted.savepoints.get(0));
        if (undone < 0) {
            return;
        }
        String next = undone + 1 < intercepted.calls.size() ? intercepted.calls.get(undone + 1) : null;
        String afterNext = undone + 2 < intercepted.calls.size() ? intercepted.calls.get(undone + 2) : null;
        if (breakage.savepointRollback != null) {
            expect(violations, label + ": when the savepoint cannot be gone back to, the whole transaction is rolled back next",
                FenceTestSupport.CALL_ROLLBACK, next);
        } else if (breakage.outcome == Outcome.SAME_ERROR) {
            expect(violations, label + ": once back at the savepoint, nothing else is rolled back - the runner does not roll back an Error",
                -1, intercepted.indexOf(undone + 1, FenceTestSupport.CALL_ROLLBACK::equals));
        }
        if (breakage.closes) {
            expect(violations, label + ": a transaction that cannot be rolled back is ended by closing the connection, right after",
                FenceTestSupport.CALL_CLOSE, afterNext);
        } else {
            expect(violations, label + ": a connection whose transaction could be rolled back is not closed", false,
                intercepted.calls.contains(FenceTestSupport.CALL_CLOSE));
        }
    }

    /**
     * MG-4: a version 3 build refuses to start on a version 4 database - there is no downgrade
     */
    @Test
    public void mg4AVersionThreeBuildRefusesAVersionFourDatabase() throws Exception {
        String schema = schema(h2, "mg4");
        FenceTestSupport.freshSchema(h2, schema);
        FenceTestSupport.upgrade(h2, schema);
        try (Db db = h2.open(schema)) {
            Assertions.assertEquals(4, DbacTestSupport.readVersion(db.proxied()), "FIXTURE MG-4: the database must be at version 4");
            DBException refused = Assertions.assertThrows(DBException.class,
                () -> FenceTestSupport.versionManager(3).getCurrentSchemaVersion(KeyLockTestSupport.MONITOR, db.proxied(), schema),
                "MG-4: a version 3 build must refuse a version 4 database");
            Assertions.assertTrue(refused.getMessage().contains("Unsupported DBAC schema version 4"),
                "MG-4: refused for the version, got: " + refused.getMessage());
            Assertions.assertThrows(DBException.class,
                () -> FenceTestSupport.migrate(db.proxied(), schema, h2.dialect(), 3, DbacTestSupport.realScriptSource()),
                "MG-4: a version 3 build's start must fail");
            Assertions.assertEquals(4, DbacTestSupport.readVersion(db.proxied()), "MG-4: the version stays 4");
        }
    }

    /**
     * MG-5: a lost version row is recovered through the quarantine as well - PostgreSQL by recording the version only, H2 by replay
     */
    @Test
    public void mg5RecoveryOfALostVersionRowQuarantinesToo() throws Exception {
        List<String> violations = new ArrayList<>();
        for (Engine engine : engines()) {
            String label = "MG-5 [" + engine.name() + "]";
            String schema = schema(engine, "mg5");
            Snapshot before = legacyState(engine, schema);
            boolean postgresEngine = engine == postgres;
            try (Db db = engine.open(schema)) {
                DbacTestSupport.deleteVersionRow(db.proxied());
                int reported = FenceTestSupport.versionManager(DbacSchemaConstants.CURRENT_SCHEMA_VERSION)
                    .getCurrentSchemaVersion(KeyLockTestSupport.MONITOR, db.proxied(), schema);
                Assertions.assertEquals(
                    postgresEngine ? DbacSchemaConstants.RECOVERY_PENDING_VERSION : DbacSchemaConstants.SCHEMA_NOT_PRESENT, reported,
                    "FIXTURE " + label + ": the lost version row must route into recovery");
                Throwable failed = call(() -> FenceTestSupport.migrate(db.proxied(), schema, engine.dialect(),
                    DbacSchemaConstants.CURRENT_SCHEMA_VERSION,
                    postgresEngine ? DbacTestSupport.createScriptIsForbidden() : DbacTestSupport.realScriptSource()));
                expect(violations, label + ": the recovery succeeds", null, describe(failed));
                expect(violations, label + ": version", 4, DbacTestSupport.readVersion(db.proxied()));
                expect(violations, label + ": version rows", 1, DbacTestSupport.countVersionRows(db.proxied()));
                expect(violations, label + ": nothing is left unrevoked", 0, FenceTestSupport.unrevoked(db.proxied()));
                checkQuarantined(violations, label, before.grants(), before.history(),
                    FenceTestSupport.grants(db.proxied()), FenceTestSupport.history(db.proxied()));
            }
        }
        Assertions.assertEquals(List.of(), violations, "MG-5");
    }

    /**
     * MG-6: a start on a version 4 database runs no quarantine - a grant of the fence era and its history are left exactly as they are
     */
    @Test
    public void mg6AStartAtVersionFourRunsNoQuarantine() throws Exception {
        List<String> violations = new ArrayList<>();
        for (Engine engine : engines()) {
            String label = "MG-6 [" + engine.name() + "]";
            String schema = schema(engine, "mg6");
            legacyState(engine, schema);
            if (!upgraded(violations, label, engine, schema)) {
                continue;
            }
            List<String> grants;
            List<String> history;
            int live;
            try (Db db = engine.open(schema)) {
                FenceTestSupport.insertGrant(db.proxied(), "mg6-fence-era", FenceTestSupport.CONNECTION, 1, Duration.ofMinutes(30), null);
                FenceTestSupport.insertHistory(
                    db.proxied(), "mg6-fence-era-event", "mg6-fence-era", FenceTestSupport.CONNECTION, "GRANTED", 1);
                grants = FenceTestSupport.wholeGrants(db.proxied());
                history = FenceTestSupport.wholeHistory(db.proxied());
                live = FenceTestSupport.unrevoked(db.proxied());
            }
            Intercepted recorded;
            try (Db db = engine.open(schema)) {
                recorded = new Intercepted(db.proxied(), sql -> false, (target, sql, parameters) -> { });
                Intercepted restart = recorded;
                expect(violations, label + ": the restart succeeds", null, describe(call(() -> FenceTestSupport.migrate(
                    restart.connection, schema, engine.dialect(), DbacSchemaConstants.CURRENT_SCHEMA_VERSION,
                    DbacTestSupport.realScriptSource()))));
            }
            try (Db db = engine.open(schema)) {
                expect(violations, label + ": the start touches no grant or history table", 0L, recorded.grantStatements());
                expect(violations, label + ": grants unchanged", grants, FenceTestSupport.wholeGrants(db.proxied()));
                expect(violations, label + ": history unchanged", history, FenceTestSupport.wholeHistory(db.proxied()));
                expect(violations, label + ": every grant live before the start is live after it", live,
                    FenceTestSupport.unrevoked(db.proxied()));
            }
        }
        Assertions.assertEquals(List.of(), violations, "MG-6");
    }

    /**
     * MG-7: a revision that cannot be advanced fails the quarantine whole - no other grant is revoked either
     */
    @Test
    public void mg7ARevisionAtItsLimitRollsEverythingBack() throws Exception {
        String schema = schema(h2, "mg7");
        FenceTestSupport.installVersionThree(h2, schema);
        try (Db db = h2.open(schema)) {
            FenceTestSupport.insertGrant(db.proxied(), "mg7-a-first", FenceTestSupport.CONNECTION, 1, Duration.ofMinutes(30), null);
            FenceTestSupport.insertGrant(
                db.proxied(), "mg7-z-last", FenceTestSupport.CONNECTION, Long.MAX_VALUE, Duration.ofMinutes(30), null);
        }
        Snapshot before = snapshot(h2, schema);
        Throwable thrown = call(() -> FenceTestSupport.upgrade(h2, schema));
        List<String> violations = new ArrayList<>();
        checkFixedRefusal(violations, "MG-7", thrown, schema);
        checkUnchanged(violations, "MG-7", h2, schema, before);
        Assertions.assertEquals(List.of(), violations, "MG-7");
    }

    /**
     * MG-8: an event id that collides with an existing one fails the quarantine whole
     */
    @Test
    public void mg8ACollidingEventIdRollsEverythingBack() throws Exception {
        List<String> violations = new ArrayList<>();
        for (Engine engine : engines()) {
            String label = "MG-8 [" + engine.name() + "]";
            String schema = schema(engine, "mg8");
            Snapshot before = legacyState(engine, schema);
            Throwable thrown;
            try (Db db = engine.open(schema)) {
                Intercepted intercepted = new Intercepted(db.proxied(), FenceTestSupport.startsWith(QUARANTINE_HISTORY),
                    (target, sql, parameters) -> {
                        if (!parameters.isEmpty() && parameters.get(0) instanceof String eventId) {
                            FenceTestSupport.insertHistory(target, eventId, "mg8-collider", FenceTestSupport.CONNECTION, "GRANTED", 1);
                        }
                    });
                thrown = call(() -> FenceTestSupport.migrate(intercepted.connection, schema, engine.dialect(),
                    DbacSchemaConstants.CURRENT_SCHEMA_VERSION, DbacTestSupport.realScriptSource()));
            }
            checkFixedRefusal(violations, label, thrown, schema);
            checkUnchanged(violations, label, engine, schema, before);
        }
        Assertions.assertEquals(List.of(), violations, "MG-8");
    }

    /**
     * MG-9: two starts upgrading one PostgreSQL database at once commit at most one quarantine
     * <p>
     * The other fails, and recognises version 4 when it starts again.
     * <p>
     * Ordered by the test, not by luck: the first start is held at its commit, after recording the version, and
     * the second is started only then and seen waiting on that row's lock in PostgreSQL's own lock table
     * before the first is let go.
     */
    @Test
    public void mg9ConcurrentUpgradesCommitAtMostOneQuarantine() throws Exception {
        String schema = schema(postgres, "mg9");
        Snapshot before = legacyState(postgres, schema);
        Pause atCommit = new Pause();
        KeyLockTestSupport.Hooks firstHooks = new KeyLockTestSupport.Hooks();
        firstHooks.beforeCommit = atCommit::hit;
        Db first = postgres.open(schema);
        Db second = postgres.open(schema);
        Worker<Object> firstStart;
        Worker<Object> secondStart = null;
        boolean secondWaited = false;
        try {
            firstStart = Worker.start("dbac-mg9-first", () -> {
                FenceTestSupport.migrate(KeyLockTestSupport.hooked(first.proxied(), firstHooks), schema, postgres.dialect(),
                    DbacSchemaConstants.CURRENT_SCHEMA_VERSION, DbacTestSupport.realScriptSource());
                return null;
            });
            atCommit.awaitReached("MG-9 the first start's commit");
            secondStart = Worker.start("dbac-mg9-second", () -> {
                FenceTestSupport.migrate(second.proxied(), schema, postgres.dialect(),
                    DbacSchemaConstants.CURRENT_SCHEMA_VERSION, DbacTestSupport.realScriptSource());
                return null;
            });
            secondWaited = waitingOnVersionRow(schema);
        } finally {
            atCommit.release();
        }
        try {
            Assertions.assertTrue(firstStart.awaitDone(), "MG-9: the first start did not finish");
            Assertions.assertNotNull(secondStart, "FIXTURE MG-9: the second start was never begun");
            Assertions.assertTrue(secondStart.awaitDone(), "MG-9: the second start did not finish");
        } finally {
            first.close();
            second.close();
        }
        List<String> violations = new ArrayList<>();
        expect(violations, "MG-9: the second start waited on the version row the first held", true, secondWaited);
        expect(violations, "MG-9: the first start commits", null, describe(firstStart.error));
        expect(violations, "MG-9: the second start fails", DBException.class,
            secondStart.error == null ? null : secondStart.error.getClass());
        if (secondStart.error != null) {
            expect(violations, "MG-9: the second start's refusal carries no cause", null, describe(secondStart.error.getCause()));
        }
        try (Db db = postgres.open(schema)) {
            expect(violations, "MG-9: version", 4, DbacTestSupport.readVersion(db.proxied()));
            expect(violations, "MG-9: version rows", 1, DbacTestSupport.countVersionRows(db.proxied()));
            checkQuarantined(violations, "MG-9", before.grants(), before.history(),
                FenceTestSupport.grants(db.proxied()), FenceTestSupport.history(db.proxied()));
            List<String> grants = FenceTestSupport.wholeGrants(db.proxied());
            List<String> history = FenceTestSupport.wholeHistory(db.proxied());
            Throwable restart = call(() -> FenceTestSupport.upgrade(postgres, schema));
            expect(violations, "MG-9: the failed start, restarted, recognises version 4", null, describe(restart));
            expect(violations, "MG-9: the restart changes no grant", grants, FenceTestSupport.wholeGrants(db.proxied()));
            expect(violations, "MG-9: the restart changes no history", history, FenceTestSupport.wholeHistory(db.proxied()));
        }
        Assertions.assertEquals(List.of(), violations, "MG-9");
    }

    /** Whether some PostgreSQL session waits on a lock while updating {@code schema}'s version row, within the test timeout */
    private static boolean waitingOnVersionRow(@NotNull String schema) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(KeyLockTestSupport.TIMEOUT_SECONDS);
        try (Connection raw = postgres.raw();
             PreparedStatement dbStat = raw.prepareStatement(
                 "SELECT COUNT(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND query ILIKE ?")) {
            dbStat.setString(1, "UPDATE " + schema + "." + DbacSchemaConstants.VERSION_TABLE_NAME + "%");
            while (System.nanoTime() < deadline) {
                try (ResultSet dbResult = dbStat.executeQuery()) {
                    dbResult.next();
                    if (dbResult.getInt(1) > 0) {
                        return true;
                    }
                }
                Thread.sleep(20);
            }
        }
        return false;
    }

    /**
     * MG-10: a check that still finds a grant unrevoked after the quarantine fails the upgrade whole
     * <p>
     * The grant appears just before the check, inside the upgrade's own transaction, as a writer that slipped
     * past the quarantine would make it appear. It is rolled back with everything else.
     */
    @Test
    public void mg10AGrantLeftUnrevokedFailsTheUpgrade() throws Exception {
        String schema = schema(h2, "mg10");
        Snapshot before = legacyState(h2, schema);
        Intercepted intercepted;
        Throwable thrown;
        try (Db db = h2.open(schema)) {
            intercepted = new Intercepted(db.proxied(), FenceTestSupport.startsWith(QUARANTINE_CHECK), (target, sql, parameters) ->
                FenceTestSupport.insertGrant(target, "mg10-slipped-in", FenceTestSupport.CONNECTION, 1, Duration.ofMinutes(30), null));
            thrown = call(() -> FenceTestSupport.migrate(intercepted.connection, schema, h2.dialect(),
                DbacSchemaConstants.CURRENT_SCHEMA_VERSION, DbacTestSupport.realScriptSource()));
        }
        List<String> violations = new ArrayList<>();
        checkFixedRefusal(violations, "MG-10", thrown, schema);
        checkUnchanged(violations, "MG-10", h2, schema, before);
        expect(violations, "FIXTURE MG-10: the injection fired", true, !intercepted.fired.isEmpty() || thrown == null);
        Assertions.assertEquals(List.of(), violations, "MG-10");
    }

    /**
     * MG-10b: version 4 is recorded only from version 3 or from no row at all, by this transaction alone and inside one
     * <p>
     * Otherwise no grant is touched.
     */
    @Test
    public void mg10bVersionFourThatCannotBeRecordedTouchesNoGrant() throws Exception {
        List<String> violations = new ArrayList<>();
        String schema = schema(h2, "mg10b");
        Snapshot before = legacyState(h2, schema);
        try (Db db = h2.open(schema)) {
            DbacTestSupport.setVersion(db.raw(), schema, 2);
            Intercepted recorded = new Intercepted(db.proxied(), sql -> false, (target, sql, parameters) -> { });
            db.raw().setAutoCommit(false);
            try {
                Throwable thrown = call(() -> FenceTestSupport.versionManager(DbacSchemaConstants.CURRENT_SCHEMA_VERSION)
                    .updateCurrentSchemaVersion(KeyLockTestSupport.MONITOR, recorded.connection, schema, 4));
                expect(violations, "MG-10b [row at 2]: refused", DBException.class, thrown == null ? null : thrown.getClass());
                expect(violations, "MG-10b [row at 2]: no grant or history statement", 0L, recorded.grantStatements());
            } finally {
                db.raw().rollback();
                db.raw().setAutoCommit(true);
            }
            DbacTestSupport.setVersion(db.raw(), schema, 3);
        }
        checkUnchanged(violations, "MG-10b [row at 2]", h2, schema, before);

        try (Db db = h2.open(schema); Connection other = h2.raw()) {
            DbacTestSupport.deleteVersionRow(db.proxied());
            Intercepted recorded = new Intercepted(
                DbacTestSupport.insertVersionRowConcurrently(db.proxied(), other, schema, 4), sql -> false,
                (target, sql, parameters) -> { });
            db.raw().setAutoCommit(false);
            try {
                Throwable thrown = call(() -> FenceTestSupport.versionManager(DbacSchemaConstants.CURRENT_SCHEMA_VERSION)
                    .updateCurrentSchemaVersion(KeyLockTestSupport.MONITOR, recorded.connection, schema, 4));
                expect(violations, "MG-10b [row inserted concurrently]: refused, not absorbed", DBException.class,
                    thrown == null ? null : thrown.getClass());
                expect(violations, "MG-10b [row inserted concurrently]: no grant or history statement", 0L, recorded.grantStatements());
                expect(violations, "MG-10b [row inserted concurrently]: the transaction is still usable", true,
                    DbacTestSupport.isUsable(db.raw(), schema));
            } finally {
                db.raw().rollback();
                db.raw().setAutoCommit(true);
            }
            expect(violations, "MG-10b [row inserted concurrently]: the other node's row stands", 4,
                DbacTestSupport.readVersion(db.proxied()));
            expect(violations, "MG-10b [row inserted concurrently]: grants unchanged", before.grantsWhole(),
                FenceTestSupport.wholeGrants(db.proxied()));
            expect(violations, "MG-10b [row inserted concurrently]: history unchanged", before.historyWhole(),
                FenceTestSupport.wholeHistory(db.proxied()));
        }

        String autoCommit = schema(h2, "mg10b_auto");
        Snapshot autoBefore = legacyState(h2, autoCommit);
        try (Db db = h2.open(autoCommit)) {
            Intercepted recorded = new Intercepted(db.proxied(), sql -> false, (target, sql, parameters) -> { });
            Throwable thrown = call(() -> FenceTestSupport.versionManager(DbacSchemaConstants.CURRENT_SCHEMA_VERSION)
                .updateCurrentSchemaVersion(KeyLockTestSupport.MONITOR, recorded.connection, autoCommit, 4));
            expect(violations, "MG-10b [auto-commit]: refused - every statement would commit on its own", DBException.class,
                thrown == null ? null : thrown.getClass());
            expect(violations, "MG-10b [auto-commit]: no grant or history statement", 0L, recorded.grantStatements());
        }
        checkUnchanged(violations, "MG-10b [auto-commit]", h2, autoCommit, autoBefore);
        Assertions.assertEquals(List.of(), violations, "MG-10b");
    }

    /**
     * MG-11: the version 1 to 2 and 2 to 3 steps of this build revoke nothing - only recording version 4 does
     */
    @Test
    public void mg11EarlierStepsRevokeNothing() throws Exception {
        List<String> violations = new ArrayList<>();
        String schema = schema(h2, "mg11");
        Snapshot before = legacyState(h2, schema);
        try (Db db = h2.open(schema)) {
            DbacTestSupport.setVersion(db.raw(), schema, 1);
            Intercepted recorded = new Intercepted(db.proxied(), sql -> false, (target, sql, parameters) -> { });
            db.raw().setAutoCommit(false);
            try {
                for (int step = 2; step <= 3; step++) {
                    int target = step;
                    expect(violations, "MG-11: the step to " + step + " succeeds", null, describe(call(() ->
                        FenceTestSupport.versionManager(DbacSchemaConstants.CURRENT_SCHEMA_VERSION)
                            .updateCurrentSchemaVersion(KeyLockTestSupport.MONITOR, recorded.connection, schema, target))));
                }
                db.raw().commit();
            } finally {
                db.raw().setAutoCommit(true);
            }
            expect(violations, "MG-11: the steps to 2 and 3 run no grant or history statement", 0L, recorded.grantStatements());
            expect(violations, "MG-11: version after the steps", 3, DbacTestSupport.readVersion(db.proxied()));
            expect(violations, "MG-11: grants unchanged by the steps", before.grantsWhole(), FenceTestSupport.wholeGrants(db.proxied()));
            expect(violations, "MG-11: history unchanged by the steps", before.historyWhole(), FenceTestSupport.wholeHistory(db.proxied()));
        }
        if (upgraded(violations, "MG-11", h2, schema)) {
            try (Db db = h2.open(schema)) {
                expect(violations, "MG-11: recording version 4 is what revokes", 0, FenceTestSupport.unrevoked(db.proxied()));
            }
        }
        Assertions.assertEquals(List.of(), violations, "MG-11");
    }

    // ---------------------------------------------------------------- FN-1: the migration never ships without the fences

    /**
     * FN-1: a build that records the fence version carries both fences, and the suite runs the tests that prove them
     */
    @Test
    public void fn1TheFenceVersionShipsWithBothFences() throws Exception {
        List<String> violations = new ArrayList<>();
        int fence = DbacSchemaConstants.USER_FENCE_SINCE_VERSION;
        expect(violations, "FN-1: the fence era starts at version 4", 4, fence);
        expect(violations, "FN-1: this build records the fence version", true, DbacSchemaConstants.CURRENT_SCHEMA_VERSION >= fence);
        // A tripwire, not a rule: a new installation and an H2 replay record the latest version directly, and the
        // quarantine runs only when that is the fence version. Raising the version past it has to decide how those
        // two still quarantine a database that was never at version 4 - this fails until somebody has.
        expect(violations, "FN-1: a version past the fence version must first decide how new installations and H2 replays quarantine",
            fence, DbacSchemaConstants.CURRENT_SCHEMA_VERSION);
        expect(violations, "FN-1: the deletion fence belongs to the same era", fence,
            DbacEmbeddedSecurityController.DELETION_FENCE_SINCE_VERSION);
        expect(violations, "FN-1: the grant fence belongs to the same era", fence, TempWriteMutationCoordinator.GRANT_FENCE_SINCE_VERSION);
        for (String source : List.of(
            "db/DbacSchemaVersionManager.java", "DbacEmbeddedSecurityController.java", "tempwrite/TempWriteMutationCoordinator.java")) {
            String text = Files.readString(MetadataShutdownTest.dbacSourceRoot().resolve("io/cloudbeaver/service/dbac/" + source),
                StandardCharsets.UTF_8);
            expect(violations, "FN-1: " + source + " refers to the fence version", true,
                text.contains("DbacSchemaConstants.USER_FENCE_SINCE_VERSION"));
        }
        try (Reader script = DbacTestSupport.realScriptSource().openSchemaUpdateScript(KeyLockTestSupport.MONITOR, fence, null)) {
            expect(violations, "FN-1: the fence version's script is in the same tree", true, script != null);
        }
        Set<Class<?>> suite = new HashSet<>(Arrays.asList(CEServerTestSuite.class.getAnnotation(SelectClasses.class).value()));
        for (Class<?> proof : List.of(UserRecreationTest.class, DbacFenceMigrationTest.class)) {
            expect(violations, "FN-1: the suite runs " + proof.getSimpleName(), true, suite.contains(proof));
        }
        Set<String> fenceTests = Arrays.stream(UserRecreationTest.class.getDeclaredMethods())
            .filter(method -> method.isAnnotationPresent(Test.class))
            .map(Method::getName)
            .collect(Collectors.toSet());
        for (String prefix : List.of("ur1", "ur3")) {
            expect(violations, "FN-1: the fence behaviour test " + prefix + " exists", true,
                fenceTests.stream().anyMatch(name -> name.startsWith(prefix)));
        }
        Assertions.assertEquals(List.of(), violations, "FN-1");
    }

    // ---------------------------------------------------------------- helpers

    /** What a schema held at one moment: version, grants and history */
    private record Snapshot(@Nullable Integer version, @NotNull List<GrantRow> grants, @NotNull List<HistoryRow> history) {
        @NotNull
        List<String> grantsWhole() {
            return grants.stream().map(GrantRow::whole).toList();
        }

        @NotNull
        List<String> historyWhole() {
            return history.stream().map(HistoryRow::whole).toList();
        }
    }

    @NotNull
    private static LifecycleTestSupport.Captured captureLogs(@NotNull LifecycleTestSupport.Body body) throws Exception {
        try {
            return LifecycleTestSupport.captureLogs(body);
        } catch (Exception | Error e) {
            throw e;
        } catch (Throwable e) {
            throw new IllegalStateException("FIXTURE: the log capture failed", e);
        }
    }

    /**
     * The quarantine's failure is logged by its own event, and only by event code, correlation id, a fixed detail and a class
     * <p>
     * The migration runner logs what it is thrown on its own account; that is upstream's line, checked here only
     * for not carrying what the failure was made of.
     */
    private static void checkFenceLog(
        @NotNull List<String> violations,
        @NotNull String label,
        @NotNull LifecycleTestSupport.Captured captured,
        @NotNull String schema
    ) {
        int fenceLines = 0;
        for (int i = 0; i < captured.dbacMessages().size(); i++) {
            String message = captured.dbacMessages().get(i);
            if (!message.contains("event=DBAC_SCHEMA_FENCE_")) {
                continue;
            }
            fenceLines++;
            expect(violations, label + ": the fence log line hands the logger no exception", null,
                describe(captured.dbacThrowables().get(i)));
            expect(violations, label + ": the fence log line carries a correlation id", true,
                message.matches("(?s).*EVENT_ID=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}.*"));
            expect(violations, label + ": the fence log line is one line", false, message.contains("\n") || message.contains("\r"));
            for (String leak : List.of(schema, "legacy-", "SELECT", "UPDATE", "INSERT", "42000")) {
                expect(violations, label + ": the fence log line does not mention " + leak, false,
                    message.toLowerCase(java.util.Locale.ROOT).contains(leak.toLowerCase(java.util.Locale.ROOT)));
            }
        }
        expect(violations, label + ": the failure is logged by its event", true, fenceLines > 0);
        for (String leak : List.of(LifecycleTestSupport.SECRET_MARKER, LifecycleTestSupport.CREDENTIAL_FRAGMENT, "secret-host",
            "injected quarantine failure", "injected ")) {
            expect(violations, label + ": nothing logged carries " + leak, false, captured.text().contains(leak));
        }
    }

    /** Upgrades {@code schema} with this build, recording a failure as a violation; whether it succeeded */
    private static boolean upgraded(
        @NotNull List<String> violations,
        @NotNull String label,
        @NotNull Engine engine,
        @NotNull String schema
    ) {
        Throwable failed = call(() -> FenceTestSupport.upgrade(engine, schema));
        expect(violations, label + ": the upgrade succeeds", null, describe(failed));
        return failed == null;
    }

    @NotNull
    private static Snapshot snapshot(@NotNull Engine engine, @NotNull String schema) throws Exception {
        try (Db db = engine.open(schema)) {
            return new Snapshot(DbacTestSupport.readVersion(db.proxied()), FenceTestSupport.grants(db.proxied()),
                FenceTestSupport.history(db.proxied()));
        }
    }

    /**
     * A version 3 database with the usual legacy mix: two live grants of one user, an expired one, a revoked one and some history
     */
    @NotNull
    private static Snapshot legacyState(@NotNull Engine engine, @NotNull String schema) throws Exception {
        FenceTestSupport.installVersionThree(engine, schema);
        try (Db db = engine.open(schema)) {
            FenceTestSupport.insertGrant(db.proxied(), "legacy-active", FenceTestSupport.CONNECTION, 1, Duration.ofMinutes(30), null);
            FenceTestSupport.insertGrant(db.proxied(), "legacy-active", "fence-connection-2", 4, Duration.ofMinutes(30), null);
            FenceTestSupport.insertGrant(db.proxied(), "legacy-expired", FenceTestSupport.CONNECTION, 2, Duration.ofMinutes(-30), null);
            FenceTestSupport.insertGrant(db.proxied(), "legacy-revoked", FenceTestSupport.CONNECTION, 3, Duration.ofMinutes(30), "admin-2");
            FenceTestSupport.insertHistory(db.proxied(), "legacy-event-1", "legacy-active", FenceTestSupport.CONNECTION, "GRANTED", 1);
        }
        return snapshot(engine, schema);
    }

    /** The upgrade failed with the fixed refusal: a {@code DBException} with no cause, naming nothing it read */
    private static void checkFixedRefusal(
        @NotNull List<String> violations,
        @NotNull String label,
        @Nullable Throwable thrown,
        @NotNull String schema
    ) {
        expect(violations, label + ": the upgrade fails with a DBException", DBException.class, thrown == null ? null : thrown.getClass());
        if (thrown == null) {
            return;
        }
        expect(violations, label + ": the refusal carries no cause", null, describe(thrown.getCause()));
        String message = String.valueOf(thrown.getMessage());
        for (String leak : List.of("injected", "42000", "23505", schema, "SELECT", "UPDATE", "INSERT", "legacy-")) {
            expect(violations, label + ": the refusal does not mention " + leak, false,
                message.toLowerCase(java.util.Locale.ROOT).contains(leak.toLowerCase(java.util.Locale.ROOT)));
        }
    }

    /** Version 3, the very same grants and the very same history as {@code before} */
    private static void checkUnchanged(
        @NotNull List<String> violations,
        @NotNull String label,
        @NotNull Engine engine,
        @NotNull String schema,
        @NotNull Snapshot before
    ) throws Exception {
        Snapshot after = snapshot(engine, schema);
        expect(violations, label + ": the version stays " + before.version(), before.version(), after.version());
        expect(violations, label + ": grants unchanged", before.grantsWhole(), after.grantsWhole());
        expect(violations, label + ": history unchanged", before.historyWhole(), after.historyWhole());
    }

    @NotNull
    private DbAccessPolicyService service(@NotNull Engine engine, @NotNull String schema) {
        return new DbAccessPolicyService(
            leases.of(FenceTestSupport.source(engine, schema)), DbAccessPolicyConfig.defaults(), PolicyTestSupport.systemClock());
    }

    @NotNull
    private static WriteAuthorizationRequest request(@NotNull String userId) {
        return WriteAuthorizationRequest.of(userId,
            PolicyTestSupport.container(FenceTestSupport.PROJECT, FenceTestSupport.CONNECTION, HOST, DATABASE),
            DbOperationCategory.SQL_TEXT);
    }

    /** Something whose failure is the result */
    @FunctionalInterface
    private interface Call {
        void run() throws Throwable;
    }

    @Nullable
    private static Throwable call(@NotNull Call call) {
        try {
            call.run();
            return null;
        } catch (Throwable e) {
            return e;
        }
    }

    @Nullable
    private static String describe(@Nullable Throwable error) {
        return error == null ? null : error.getClass().getName();
    }

    private static void expect(@NotNull List<String> violations, @NotNull String what, @Nullable Object expected, @Nullable Object actual) {
        if (!Objects.equals(expected, actual)) {
            violations.add(what + ": expected " + expected + ", got " + actual);
        }
    }
}
