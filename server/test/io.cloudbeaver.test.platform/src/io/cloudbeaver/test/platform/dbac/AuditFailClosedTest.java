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
import io.cloudbeaver.service.dbac.policy.AuthorizationAuditPayload;
import io.cloudbeaver.service.dbac.policy.AuthorizationDecision;
import io.cloudbeaver.service.dbac.policy.DbAccessDecision;
import io.cloudbeaver.service.dbac.policy.DbAccessKey;
import io.cloudbeaver.service.dbac.policy.DbAccessPolicyConfig;
import io.cloudbeaver.service.dbac.policy.DbOperationCategory;
import io.cloudbeaver.service.dbac.policy.DenialReason;
import io.cloudbeaver.service.dbac.policy.MetadataBudget;
import io.cloudbeaver.service.dbac.policy.MetadataLeaseSource;
import io.cloudbeaver.service.dbac.policy.enforcement.AccessAuditWriter;
import io.cloudbeaver.service.dbac.policy.enforcement.AuditEventId;
import io.cloudbeaver.service.dbac.policy.enforcement.AuditOutcome;
import io.cloudbeaver.service.dbac.policy.enforcement.EnforcementKeyLocks;
import io.cloudbeaver.service.dbac.tempwrite.MetadataConnectionSource;
import io.cloudbeaver.service.security.EmbeddedSecurityControllerFactory;
import io.cloudbeaver.service.security.db.CBDatabase;
import io.cloudbeaver.test.platform.dbac.MetadataTestSupport.FakeConnection;
import io.cloudbeaver.test.platform.dbac.MetadataTestSupport.FakeSource;
import io.cloudbeaver.test.platform.dbac.MetadataTestSupport.InjectedLeaseError;
import io.cloudbeaver.test.platform.dbac.MetadataTestSupport.InjectedSqlException;
import io.cloudbeaver.test.platform.dbac.MetadataTestSupport.ManualClock;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.LongSupplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * P5-3: the pre-execution audit writer - a row counts only once it is committed, everything else is FAILED, nothing is thrown
 * <p>
 * The rows are written into two real metadata databases: the test server's own H2 and a PostgreSQL schema
 * the real migration installs at version 4. Failures the databases cannot be made to produce on demand -
 * a refused borrow, a driver that throws, a count of zero - come from scripted connections. Time is moved
 * by hand wherever a budget is the subject, so no boundary depends on where a sleep landed.
 * <p>
 * What the writer is not asked here is anything the enforcement gate decides: whether to write a
 * correcting {@code WRITE_DENIED}, when the platform is called, what a {@code FAILED} turns into. P5-3
 * provides the primitive; the gate is P5-4's.
 */
@Timeout(value = 300, unit = TimeUnit.SECONDS, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
public class AuditFailClosedTest {

    private static final String PG_SCHEMA = "dbac_pg_audit";
    private static final DbAccessPolicyConfig CONFIG = DbAccessPolicyConfig.defaults();
    private static final Duration T_AUDIT = CONFIG.auditTimeout();

    /** Every user these tests record starts with this, so the rows can be found and removed */
    private static final String USER_PREFIX = "dbac-au-";
    private static final String PROJECT = "au-project";
    private static final String CONNECTION = "au-connection";
    /** An expiry in a zone other than UTC, at microsecond precision both engines keep */
    private static final OffsetDateTime EXPIRES_AT = OffsetDateTime.of(2031, 2, 3, 4, 5, 6, 789_000, ZoneOffset.ofHours(9));

    private static final String WRITE_ALLOWED = "WRITE_ALLOWED";
    private static final String WRITE_DENIED = "WRITE_DENIED";
    private static final String FAILURE_EVENT = "event=DBAC_AUDIT_WRITE_FAILED";

    /** The statement the writer must prepare, to the character */
    private static final String INSERT = "INSERT INTO {table_prefix}DBAC_AUDIT_EVENT"
        + " (EVENT_ID, EVENT_TYPE, EVENT_TIME, USER_ID, ACTOR_ID, PROJECT_ID, CONNECTION_ID, GRANT_ID,"
        + " OPERATION_CATEGORY, STATEMENT_TYPE, DECISION, DENIAL_REASON, EXPIRES_AT)"
        + " VALUES (?, ?, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)";
    private static final List<String> COLUMNS = List.of(
        "EVENT_ID", "EVENT_TYPE", "EVENT_TIME", "USER_ID", "ACTOR_ID", "PROJECT_ID", "CONNECTION_ID", "GRANT_ID",
        "OPERATION_CATEGORY", "STATEMENT_TYPE", "DECISION", "DENIAL_REASON", "EXPIRES_AT");

    /** What a row or a log may hold only if something from outside the payload leaked into it */
    private static final String CANARY_HOST = "au-canary-host.internal.example";
    private static final String CANARY_URL = "jdbc:postgresql://" + CANARY_HOST + ":5432/au_canary_db";
    private static final String CANARY_DB_USER = "au_canary_dbuser";
    private static final String CANARY_PASSWORD = "au-canary-pw-3f9a";
    private static final String CANARY_TOKEN = "au-canary-token-77d1";
    private static final String CANARY_SQL = "UPDATE au_canary_table SET secret_col = 1";
    private static final String CANARY_MESSAGE = "failed running " + CANARY_SQL + " on " + CANARY_URL
        + "?user=" + CANARY_DB_USER + "&password=" + CANARY_PASSWORD + " token=" + CANARY_TOKEN;
    private static final List<String> CANARIES = List.of(
        CANARY_HOST, "au_canary_db", CANARY_DB_USER, CANARY_PASSWORD, CANARY_TOKEN, "au_canary_table", "secret_col");

    /** The log's own correlation id, and the row's */
    private static final Pattern LOG_EVENT_ID = Pattern.compile("[ \\[]EVENT_ID=([0-9a-f-]{36})");
    private static final Pattern LOG_AUDIT_EVENT_ID = Pattern.compile("AUDIT_EVENT_ID=([0-9a-f-]{36})");

    private static final long BASE = 5_000_000_000_000L;
    private static final Duration WAIT = Duration.ofSeconds(20);
    private static final AtomicLong SEQUENCE = new AtomicLong();

    private static boolean installed;

    private final MetadataLeaseFixture leases = new MetadataLeaseFixture();

    /** A metadata database the rows are written to */
    private record Engine(@NotNull String name, @NotNull MetadataConnectionSource source) {
    }

    @BeforeAll
    public static void prepare() throws Exception {
        CEAppStarter.startServerIfNotStarted();
        Assertions.assertNotNull(EmbeddedSecurityControllerFactory.getDbInstance(), "FIXTURE: the server metadata database must exist");
        EnforcementTestSupport.requirePostgres(KeyLockTestSupport.MONITOR);
        KeyLockTestSupport.installDbacSchema(PG_SCHEMA);
        installed = true;
    }

    @AfterAll
    public static void dropSchema() throws Exception {
        if (!installed) {
            return;
        }
        KeyLockTestSupport.dropSchema(PG_SCHEMA);
        Assertions.assertEquals(0, KeyLockTestSupport.countSchemas(PG_SCHEMA), "FIXTURE: the PostgreSQL schema was left behind");
    }

    @AfterEach
    public void cleanUp() throws Exception {
        try {
            leases.close();
        } finally {
            for (Engine engine : engines()) {
                try (Connection connection = engine.source().openConnection();
                     PreparedStatement dbStat = connection.prepareStatement(
                         "DELETE FROM {table_prefix}DBAC_AUDIT_EVENT WHERE USER_ID LIKE ?")) {
                    dbStat.setString(1, USER_PREFIX + "%");
                    dbStat.executeUpdate();
                }
            }
        }
    }

    @NotNull
    private static List<Engine> engines() {
        CBDatabase h2 = EmbeddedSecurityControllerFactory.getDbInstance();
        return List.of(
            new Engine("H2", h2::openConnection),
            new Engine("PostgreSQL", () -> KeyLockTestSupport.openPostgres(PG_SCHEMA)));
    }

    // ---------------------------------------------------------------- AU-1: committed before it returns

    /**
     * AU-1: {@code RECORDED} means the row was committed by its own statement and another connection already sees it
     * <p>
     * On both engines, right after the insert's {@code executeUpdate} returns - before the lease is closed,
     * before the writer returns - a different connection must find the row: the statement committed it
     * itself, in auto-commit. The row holds exactly the payload, {@code EVENT_TIME} lies between two
     * readings of the database's own clock around the call, and the writer logs nothing. A connection
     * not in auto-commit is refused before anything is prepared: {@code FAILED}, and no row anywhere.
     */
    @Test
    public void au1AnAllowedRowIsCommittedAndVisibleBeforeTheWriterReturns() throws Throwable {
        List<String> violations = new ArrayList<>();
        for (Engine engine : engines()) {
            String user = newUser("au1");
            AuthorizationAuditPayload payload = allowed(user);
            AuditEventId id = AuditEventId.next();
            Watched watched = new Watched(engine.source());
            AtomicReference<Boolean> visibleAtStatementEnd = new AtomicReference<>();
            watched.afterUpdate = () -> visibleAtStatementEnd.set(readRow(engine, id) != null);
            AccessAuditWriter writer = writer(watched);
            AtomicReference<AuditOutcome> outcome = new AtomicReference<>();
            final OffsetDateTime before = dbNow(engine);
            final LifecycleTestSupport.Captured captured = LifecycleTestSupport.captureLogs(
                () -> outcome.set(writer.recordAllowedBeforeExecution(id, payload, budget())));
            final OffsetDateTime after = dbNow(engine);
            String what = engine.name();
            expect(violations, what + ": the outcome", AuditOutcome.RECORDED, outcome.get());
            expect(violations, what + ": visible to another connection as the statement returned", Boolean.TRUE,
                visibleAtStatementEnd.get());
            Map<String, Object> row = readRow(engine, id);
            expectRow(violations, what, row, id, WRITE_ALLOWED, payload);
            if (row != null && row.get("EVENT_TIME") instanceof OffsetDateTime time
                && (time.isBefore(before) || time.isAfter(after))) {
                violations.add(what + ": EVENT_TIME " + time + " is not the database's clock, which read " + before + " and " + after);
            }
            expect(violations, what + ": log lines for a recorded row", List.of(), captured.dbacMessages());

            String manualUser = newUser("au1-manual");
            AuditEventId manualId = AuditEventId.next();
            Watched manual = new Watched(engine.source());
            manual.manualCommit = true;
            AuditOutcome refused = writer(manual).recordAllowedBeforeExecution(manualId, allowed(manualUser), budget());
            expect(violations, what + " outside auto-commit: the outcome", AuditOutcome.FAILED, refused);
            expect(violations, what + " outside auto-commit: statements prepared", List.of(), manual.prepared);
            expect(violations, what + " outside auto-commit: a row anywhere", null, readRow(engine, manualId));
        }
        Assertions.assertEquals(List.of(), violations, "AU-1");
    }

    // ---------------------------------------------------------------- AU-2: anything else is FAILED

    /**
     * AU-2: an allowed row that is not committed exactly once, within the budget, is {@code FAILED} - and nothing is thrown
     * <p>
     * Scripted: no connection, a statement that cannot be prepared, the server cancelling the statement
     * (57014), no row and two rows, a connection not in auto-commit, a timeout that cannot be put back,
     * a {@code RuntimeException} and an {@code Error} from the driver, less than one second left, a
     * budget that is not {@code T_audit}, a denial's payload, a missing argument, a budget clock that
     * fails, and a lease source that throws. Each logs exactly one line naming the fixed failure.
     * <p>
     * Real, on both engines: the insert waits behind another transaction's uncommitted row with the same
     * {@code EVENT_ID}. The timeout the budget sets must end the wait - on PostgreSQL within the budget -
     * and the writer must return {@code FAILED}, with no row once the other transaction rolls back.
     */
    @Test
    public void au2AnAllowedRowThatIsNotCommittedIsFailed() throws Throwable {
        List<String> violations = new ArrayList<>();
        record Case(String name, MetadataTestSupport.Script script, @Nullable Throwable borrowFails, String failure, int executes) {
        }

        List<Case> cases = List.of(
            new Case("no connection", connection -> { }, new InjectedSqlException("borrow"), "failure=NO_LEASE detail=BORROW_FAILED", 0),
            new Case("cannot prepare", connection -> connection.prepareFails = new InjectedSqlException("prepare"), null,
                "failure=NOT_DONE detail=STATEMENT_FAILED", 0),
            new Case("cancelled by the server", connection -> connection.executeFails = new SQLException(
                "canceling statement due to statement timeout " + CANARY_MESSAGE, "57014"), null,
                "failure=NOT_DONE detail=EXECUTION_FAILED", 1),
            new Case("no row", connection -> connection.updateCount = 0, null, "failure=NOT_DONE detail=CARDINALITY", 1),
            new Case("two rows", connection -> connection.updateCount = 2, null, "failure=NOT_DONE detail=CARDINALITY", 1),
            new Case("not in auto-commit", connection -> connection.autoCommit = false, null,
                "failure=NOT_DONE detail=STATEMENT_FAILED", 0),
            new Case("the timeout is not put back", connection -> connection.restoreSetFails = new InjectedSqlException("restore"), null,
                "failure=NOT_DONE detail=RESTORE_FAILED", 1),
            new Case("a RuntimeException from the driver",
                connection -> connection.executeFails = new LifecycleTestSupport.InjectedRuntimeException("execute"), null,
                "failure=NOT_DONE detail=EXECUTION_FAILED", 1),
            new Case("an Error from the driver", connection -> connection.executeFails = new InjectedLeaseError("execute"), null,
                "failure=THREW exception=" + InjectedLeaseError.class.getName(), 1));
        for (Case one : cases) {
            FakeSource raw = new FakeSource(one.script());
            raw.fails = one.borrowFails();
            AccessAuditWriter writer = writer(raw);
            Run run = run(() -> writer.recordAllowedBeforeExecution(AuditEventId.next(), allowed(newUser("au2")), budget()));
            expectFailed(violations, one.name(), run, one.failure());
            int executes = raw.made.stream().mapToInt(connection -> connection.executes.get()).sum();
            expect(violations, one.name() + ": statements executed", one.executes(), executes);
        }

        ManualClock clock = new ManualClock(BASE);
        MetadataBudget halfSecondLeft = budget(clock);
        clock.advance(T_AUDIT.minusMillis(500));
        FakeSource late = new FakeSource();
        Run lateRun = run(() -> writer(late).recordAllowedBeforeExecution(AuditEventId.next(), allowed(newUser("au2")), halfSecondLeft));
        expectFailed(violations, "less than one second left", lateRun, "failure=NOT_DONE detail=BUDGET_EXHAUSTED");
        expect(violations, "less than one second left: statements prepared", 0, late.made.stream().mapToInt(c -> c.prepares.get()).sum());

        Map<String, MetadataBudget> otherBudgets = Map.of(
            "a budget of T_audit + 1s", MetadataBudget.startingNow(System::nanoTime, T_AUDIT.plusSeconds(1)),
            "a budget of 30s", MetadataBudget.startingNow(System::nanoTime, Duration.ofSeconds(30)),
            "a budget of 1s", MetadataBudget.startingNow(System::nanoTime, Duration.ofSeconds(1)));
        for (Map.Entry<String, MetadataBudget> other : otherBudgets.entrySet()) {
            FakeSource raw = new FakeSource();
            Run run = run(() -> writer(raw).recordAllowedBeforeExecution(AuditEventId.next(), allowed(newUser("au2")), other.getValue()));
            expectFailed(violations, other.getKey(), run, "failure=NOT_THE_AUDIT_BUDGET");
            expect(violations, other.getKey() + ": borrows", 0, raw.calls.get());
        }

        FakeSource deny = new FakeSource();
        Run denyRun = run(() -> writer(deny).recordAllowedBeforeExecution(
            AuditEventId.next(), denied(newUser("au2"), DenialReason.NO_GRANT, null, null), budget()));
        expectFailed(violations, "a denial's payload", denyRun, "failure=WRONG_DECISION");
        expect(violations, "a denial's payload: borrows", 0, deny.calls.get());

        FakeSource missing = new FakeSource();
        AccessAuditWriter missingWriter = writer(missing);
        AuthorizationAuditPayload payload = allowed(newUser("au2"));
        expectFailed(violations, "no id", run(() -> missingWriter.recordAllowedBeforeExecution(null, payload, budget())),
            "failure=MISSING_ARGUMENT");
        expectFailed(violations, "no payload", run(() -> missingWriter.recordAllowedBeforeExecution(AuditEventId.next(), null, budget())),
            "failure=MISSING_ARGUMENT");
        expectFailed(violations, "no budget", run(() -> missingWriter.recordAllowedBeforeExecution(AuditEventId.next(), payload, null)),
            "failure=MISSING_ARGUMENT");
        expect(violations, "missing arguments: borrows", 0, missing.calls.get());

        FakeSource clockless = new FakeSource();
        MetadataBudget failingClock = MetadataBudget.startedAt(() -> {
            throw new LifecycleTestSupport.InjectedRuntimeException("budget clock");
        }, BASE, T_AUDIT);
        expectFailed(violations, "a budget clock that fails",
            run(() -> writer(clockless).recordAllowedBeforeExecution(AuditEventId.next(), allowed(newUser("au2")), failingClock)),
            "failure=NO_LEASE detail=BUDGET_EXHAUSTED");

        List<Throwable> sourceFailures = List.of(
            new LifecycleTestSupport.InjectedRuntimeException("open"), new LifecycleTestSupport.InjectedError("open"));
        for (Throwable thrown : sourceFailures) {
            MetadataLeaseSource throwing = (budget, purpose) -> {
                throw Unchecked.of(thrown);
            };
            AccessAuditWriter writer = new AccessAuditWriter(throwing, CONFIG);
            expectFailed(violations, "a lease source that throws " + thrown.getClass().getSimpleName(),
                run(() -> writer.recordAllowedBeforeExecution(AuditEventId.next(), allowed(newUser("au2")), budget())),
                "failure=THREW exception=" + thrown.getClass().getName());
        }

        for (Engine engine : engines()) {
            String what = engine.name() + ", waiting behind an uncommitted row with the same id";
            String user = newUser("au2-wait");
            AuditEventId id = AuditEventId.next();
            AccessAuditWriter writer = writer(engine.source());
            MetadataTestSupport.Outcome<AuditOutcome> outcome;
            try (Connection blocker = engine.source().openConnection()) {
                blocker.setAutoCommit(false);
                insertDirectly(blocker, id, user);
                MetadataBudget budget = budget();
                outcome = MetadataTestSupport.within(WAIT, () -> writer.recordAllowedBeforeExecution(id, allowed(user), budget));
                blocker.rollback();
                blocker.setAutoCommit(true);
            }
            if (!outcome.finished() || outcome.thrown() != null) {
                violations.add(what + ": the writer must return, got finished=" + outcome.finished() + " thrown="
                    + (outcome.thrown() == null ? null : outcome.thrown().getClass().getName()));
                continue;
            }
            expect(violations, what + ": the outcome", AuditOutcome.FAILED, outcome.value());
            if (engine.name().equals("PostgreSQL") && outcome.elapsedNanos() > T_AUDIT.plusSeconds(1).toNanos()) {
                violations.add(what + ": the budget's timeout must end the wait, it took "
                    + TimeUnit.NANOSECONDS.toMillis(outcome.elapsedNanos()) + "ms");
            }
            expect(violations, what + ": a row once the other transaction rolled back", null, readRow(engine, id));
        }
        Assertions.assertEquals(List.of(), violations, "AU-2");
    }

    // ---------------------------------------------------------------- AU-3: a failed denial stays a denial

    /**
     * AU-3: a denied row that cannot be written is reported as {@code FAILED} and nothing more - the caller keeps its denial
     * <p>
     * {@link AuditOutcome} is two constants with no fields and no methods of its own, and no writer method
     * takes or returns a decision or a reason: an audit result has nothing in it a caller could mistake
     * for a different answer. Every failure the allowed row can meet, met by a denied row, returns
     * {@code FAILED} without a throw; an allow's payload is refused. On both engines a denial is recorded
     * with exactly its payload - with and without a grant.
     */
    @Test
    public void au3AFailedDeniedRowLeavesTheDenialAsItWas() throws Throwable {
        List<String> violations = new ArrayList<>();
        expect(violations, "the outcomes", List.of("RECORDED", "FAILED"),
            Arrays.stream(AuditOutcome.values()).map(Enum::name).toList());
        for (Field field : AuditOutcome.class.getDeclaredFields()) {
            if (!field.isEnumConstant() && !field.isSynthetic()) {
                violations.add("AuditOutcome carries a field " + field.getName());
            }
        }
        for (Method method : AuditOutcome.class.getDeclaredMethods()) {
            if (!method.isSynthetic() && !Set.of("values", "valueOf").contains(method.getName())) {
                violations.add("AuditOutcome declares a method " + method.getName());
            }
        }
        for (Method method : AccessAuditWriter.class.getDeclaredMethods()) {
            if (!Modifier.isPublic(method.getModifiers())) {
                continue;
            }
            if (method.getReturnType() != AuditOutcome.class) {
                violations.add("AccessAuditWriter." + method.getName() + " returns " + method.getReturnType().getSimpleName());
            }
            for (Class<?> parameter : method.getParameterTypes()) {
                if (parameter == AuthorizationDecision.class || parameter == DenialReason.class || parameter == DbAccessDecision.class) {
                    violations.add("AccessAuditWriter." + method.getName() + " takes a " + parameter.getSimpleName());
                }
            }
        }

        record Case(String name, MetadataTestSupport.Script script, @Nullable Throwable borrowFails, String failure) {
        }

        List<Case> cases = List.of(
            new Case("no connection", connection -> { }, new InjectedSqlException("borrow"), "failure=NO_LEASE detail=BORROW_FAILED"),
            new Case("no row", connection -> connection.updateCount = 0, null, "failure=NOT_DONE detail=CARDINALITY"),
            new Case("not in auto-commit", connection -> connection.autoCommit = false, null, "failure=NOT_DONE detail=STATEMENT_FAILED"),
            new Case("a RuntimeException from the driver",
                connection -> connection.executeFails = new LifecycleTestSupport.InjectedRuntimeException("execute"), null,
                "failure=NOT_DONE detail=EXECUTION_FAILED"),
            new Case("an Error from the driver", connection -> connection.executeFails = new InjectedLeaseError("execute"), null,
                "failure=THREW exception=" + InjectedLeaseError.class.getName()));
        for (Case one : cases) {
            FakeSource raw = new FakeSource(one.script());
            raw.fails = one.borrowFails();
            AuthorizationAuditPayload denial = denied(newUser("au3"), DenialReason.GRANT_REVOKED, "grant-au3", EXPIRES_AT);
            AuthorizationAuditPayload copy = new AuthorizationAuditPayload(denial.decision(), denial.denialReason(), denial.userId(),
                denial.projectId(), denial.connectionId(), denial.grantId(), denial.operationCategory(), denial.expiresAt());
            AccessAuditWriter writer = writer(raw);
            expectFailed(violations, "denied, " + one.name(), run(() -> writer.recordDenied(AuditEventId.next(), denial)), one.failure());
            expect(violations, "denied, " + one.name() + ": the denial", copy, denial);
        }
        FakeSource allowSource = new FakeSource();
        expectFailed(violations, "denied, an allow's payload",
            run(() -> writer(allowSource).recordDenied(AuditEventId.next(), allowed(newUser("au3")))), "failure=WRONG_DECISION");
        expect(violations, "denied, an allow's payload: borrows", 0, allowSource.calls.get());
        FakeSource nothing = new FakeSource();
        expectFailed(violations, "denied, no id",
            run(() -> writer(nothing).recordDenied(null, denied(newUser("au3"), DenialReason.NO_GRANT, null, null))),
            "failure=MISSING_ARGUMENT");
        expectFailed(violations, "denied, no payload", run(() -> writer(nothing).recordDenied(AuditEventId.next(), null)),
            "failure=MISSING_ARGUMENT");

        for (Engine engine : engines()) {
            for (AuthorizationAuditPayload denial : List.of(
                denied(newUser("au3-revoked"), DenialReason.GRANT_REVOKED, "grant-au3", EXPIRES_AT),
                denied(newUser("au3-nogrant"), DenialReason.NO_GRANT, null, null))
            ) {
                AuditEventId id = AuditEventId.next();
                String what = engine.name() + ", " + denial.denialReason();
                expect(violations, what + ": the outcome", AuditOutcome.RECORDED, writer(engine.source()).recordDenied(id, denial));
                expectRow(violations, what, readRow(engine, id), id, WRITE_DENIED, denial);
            }
        }
        Assertions.assertEquals(List.of(), violations, "AU-3");
    }

    // ---------------------------------------------------------------- AU-4: nothing else reaches a row or a log

    /**
     * AU-4: no host, URL, database user, password, token or statement reaches an audit column or a log
     * <p>
     * The thread is named after a host and a token, and every failure the writer meets carries a message
     * with a URL, a user, a password, a token and a statement - from the driver, from the lease source as a
     * {@code RuntimeException} and as an {@code Error}, and from the borrow. On both engines the rows hold
     * exactly the payload and nothing else; on a scripted connection the statement is exactly the audit
     * insert, with {@code EVENT_TIME} from the database's {@code CURRENT_TIMESTAMP}, and its ten bindings
     * are exactly the id and the payload's fields. Every log line keeps the P1 contract: a fixed event code,
     * an {@code EVENT_ID}, one line, no exception object, no stack trace and none of the canaries.
     */
    @Test
    public void au4NoSecretReachesAnAuditColumnOrALog() throws Throwable {
        List<String> violations = new ArrayList<>();
        Thread thread = Thread.currentThread();
        String name = thread.getName();
        thread.setName(CANARY_HOST + "-" + CANARY_TOKEN);
        try {
            for (Engine engine : engines()) {
                String user = newUser("au4");
                AuthorizationAuditPayload allow = allowed(user);
                AuthorizationAuditPayload deny = denied(user, DenialReason.GRANT_EXPIRED, allow.grantId(), EXPIRES_AT);
                AuditEventId allowId = AuditEventId.next();
                AuditEventId denyId = AuditEventId.next();
                AccessAuditWriter writer = writer(engine.source());
                expect(violations, engine.name() + ": allowed", AuditOutcome.RECORDED,
                    writer.recordAllowedBeforeExecution(allowId, allow, budget()));
                expect(violations, engine.name() + ": denied", AuditOutcome.RECORDED, writer.recordDenied(denyId, deny));
                for (AuditEventId id : List.of(allowId, denyId)) {
                    Map<String, Object> row = readRow(engine, id);
                    expectRow(violations, engine.name(), row, id, id == allowId ? WRITE_ALLOWED : WRITE_DENIED,
                        id == allowId ? allow : deny);
                    for (String canary : CANARIES) {
                        if (row != null && String.valueOf(row).contains(canary)) {
                            violations.add(engine.name() + ": the row holds '" + canary + "': " + row);
                        }
                    }
                }
            }

            FakeSource scripted = new FakeSource();
            Watched watched = new Watched(scripted);
            String user = newUser("au4-bind");
            AuthorizationAuditPayload allow = allowed(user);
            AuditEventId id = AuditEventId.next();
            expect(violations, "scripted: the outcome", AuditOutcome.RECORDED,
                writer(watched).recordAllowedBeforeExecution(id, allow, budget()));
            thread.setName(name);
            expect(violations, "scripted: the statement", List.of(INSERT), watched.prepared);
            expect(violations, "scripted: connections borrowed", 1, scripted.made.size());
            List<String> bindings = scripted.made.isEmpty() ? List.of() : scripted.made.get(0).calls().stream()
                .filter(call -> call.startsWith("set") && !call.startsWith("setQuery")).toList();
            expect(violations, "scripted: the bindings", List.of(
                "setString(1,String:" + id.value() + ")",
                "setString(2,String:" + WRITE_ALLOWED + ")",
                "setString(3,String:" + user + ")",
                "setString(4,String:" + user + ")",
                "setString(5,String:" + PROJECT + ")",
                "setString(6,String:" + CONNECTION + ")",
                "setString(7,String:" + allow.grantId() + ")",
                "setString(8,String:" + DbOperationCategory.SQL_TEXT.name() + ")",
                "setString(9,String:" + DbAccessDecision.ALLOW.name() + ")",
                "setNull(10,Integer:" + java.sql.Types.VARCHAR + ")",
                "setObject(11,OffsetDateTime:" + EXPIRES_AT.withOffsetSameInstant(ZoneOffset.UTC) + ")"), bindings);

            List<MetadataLeaseSource> failingSources = new ArrayList<>();
            failingSources.add(leases.of(new FakeSource(connection -> connection.executeFails = new CanarySqlException())));
            FakeSource refusing = new FakeSource();
            refusing.fails = new CanarySqlException();
            failingSources.add(leases.of(refusing));
            failingSources.add((budget, purpose) -> {
                throw new CanaryRuntimeException();
            });
            failingSources.add((budget, purpose) -> {
                throw new CanaryError();
            });
            List<AuthorizationAuditPayload> failingPayloads = new ArrayList<>();
            LifecycleTestSupport.Captured captured = LifecycleTestSupport.captureLogs(() -> {
                for (MetadataLeaseSource source : failingSources) {
                    AccessAuditWriter writer = new AccessAuditWriter(source, CONFIG);
                    AuthorizationAuditPayload allowFailing = allowed(newUser("au4-fail"));
                    AuthorizationAuditPayload denyFailing = denied(allowFailing.userId(), DenialReason.GRANT_REVOKED,
                        allowFailing.grantId(), EXPIRES_AT);
                    failingPayloads.add(allowFailing);
                    noThrow(violations, "failing allowed", () -> writer.recordAllowedBeforeExecution(
                        AuditEventId.next(), allowFailing, budget()));
                    noThrow(violations, "failing denied", () -> writer.recordDenied(AuditEventId.next(), denyFailing));
                }
            });
            expect(violations, "failure log lines", 2 * failingSources.size(), writerLines(captured.dbacMessages()).size());
            List<String> forbidden = new ArrayList<>(CANARIES);
            forbidden.addAll(MetadataTestSupport.SECRET_FRAGMENTS);
            forbidden.add(LifecycleTestSupport.SECRET_MARKER);
            forbidden.add(LifecycleTestSupport.CREDENTIAL_FRAGMENT);
            violations.addAll(LifecycleTestSupport.logContractViolations(captured, forbidden));
            for (String line : writerLines(captured.dbacMessages())) {
                List<String> payloadFields = new ArrayList<>(List.of(PROJECT, CONNECTION, "INSERT", "DBAC_AUDIT_EVENT", "{table_prefix}"));
                for (AuthorizationAuditPayload failing : failingPayloads) {
                    payloadFields.add(failing.userId());
                    payloadFields.add(failing.grantId());
                }
                for (String field : payloadFields) {
                    if (line.contains(field)) {
                        violations.add("a failure line names '" + field + "': " + line);
                    }
                }
            }
        } finally {
            thread.setName(name);
        }
        Assertions.assertEquals(List.of(), violations, "AU-4");
    }

    // ---------------------------------------------------------------- AU-5, AU-6: one id, one row

    /**
     * AU-5: three attempts are three rows, each under its own id - an id is not an idempotency key
     * <p>
     * A thousand ids from {@link AuditEventId#next()} are all different. On both engines three attempts
     * at the same write, each with a new id, are three {@code WRITE_ALLOWED} rows with those three ids.
     * An id used a second time is refused by the table, so the attempt that reused it is {@code FAILED}
     * and still three rows remain - nothing is merged into an earlier row.
     */
    @Test
    public void au5ARetriedAttemptIsANewRow() throws Throwable {
        List<String> violations = new ArrayList<>();
        Set<String> ids = new HashSet<>();
        for (int i = 0; i < 1000; i++) {
            ids.add(AuditEventId.next().value());
        }
        expect(violations, "distinct ids out of 1000", 1000, ids.size());
        for (Engine engine : engines()) {
            String user = newUser("au5");
            AccessAuditWriter writer = writer(engine.source());
            List<String> recorded = new ArrayList<>();
            AuditEventId first = null;
            for (int attempt = 0; attempt < 3; attempt++) {
                AuditEventId id = AuditEventId.next();
                first = first == null ? id : first;
                expect(violations, engine.name() + ": attempt " + attempt, AuditOutcome.RECORDED,
                    writer.recordAllowedBeforeExecution(id, allowed(user), budget()));
                recorded.add(id.value());
            }
            expect(violations, engine.name() + ": an id used again", AuditOutcome.FAILED,
                writer.recordAllowedBeforeExecution(first, allowed(user), budget()));
            List<Map<String, Object>> rows = rowsOf(engine, user);
            expect(violations, engine.name() + ": the rows' ids", new TreeSet<>(recorded),
                new TreeSet<>(rows.stream().map(row -> (String) row.get("EVENT_ID")).toList()));
            expect(violations, engine.name() + ": rows", 3, rows.size());
        }
        Assertions.assertEquals(List.of(), violations, "AU-5");
    }

    /**
     * AU-6: an allowed row and the denial that corrects it are two rows under two ids
     * <p>
     * On both engines: {@code WRITE_ALLOWED} under one id, then a correcting {@code WRITE_DENIED} for the
     * same key, grant and category ({@code GRANT_EXPIRED}, as a failed check-2 would give) under a new
     * one. And when the allowed row's result came back past its budget - so it is {@code FAILED} although
     * the row was committed - the correction is still written beside it under an id of its own.
     */
    @Test
    public void au6AnAllowedRowAndItsCorrectionAreTwoEvents() throws Throwable {
        List<String> violations = new ArrayList<>();
        for (Engine engine : engines()) {
            for (boolean lateAllow : new boolean[]{false, true}) {
                String what = engine.name() + (lateAllow ? ", the allowed row past its budget" : "");
                String user = newUser("au6");
                AuthorizationAuditPayload allow = allowed(user);
                final AuthorizationAuditPayload correction = denied(user, DenialReason.GRANT_EXPIRED, allow.grantId(), allow.expiresAt());
                ManualClock clock = new ManualClock(BASE);
                Watched watched = new Watched(engine.source());
                if (lateAllow) {
                    watched.afterUpdate = () -> clock.advance(T_AUDIT.plusMillis(1));
                }
                AccessAuditWriter writer = writer(watched);
                AuditEventId allowId = AuditEventId.next();
                expect(violations, what + ": allowed", lateAllow ? AuditOutcome.FAILED : AuditOutcome.RECORDED,
                    writer.recordAllowedBeforeExecution(allowId, allow, budget(clock)));
                watched.afterUpdate = () -> { };
                AuditEventId correctionId = AuditEventId.next();
                if (correctionId.equals(allowId)) {
                    violations.add(what + ": the correction needs an id of its own");
                }
                expect(violations, what + ": the correction", AuditOutcome.RECORDED, writer.recordDenied(correctionId, correction));
                expectRow(violations, what + ", allowed", readRow(engine, allowId), allowId, WRITE_ALLOWED, allow);
                expectRow(violations, what + ", correction", readRow(engine, correctionId), correctionId, WRITE_DENIED, correction);
                expect(violations, what + ": rows", 2, rowsOf(engine, user).size());
            }
        }
        Assertions.assertEquals(List.of(), violations, "AU-6");
    }

    // ---------------------------------------------------------------- AU-7: authorization, not execution

    /**
     * AU-7: {@code WRITE_ALLOWED} records authorization and the audit before execution - it says nothing about the operation
     * <p>
     * On both engines the same allowed row is written before an operation that then succeeds, throws a
     * {@code RuntimeException}, or throws an {@code Error}: every time exactly one {@code WRITE_ALLOWED}
     * row with no statement type and nothing for a {@code WRITE_DENIED}, and the three rows are the same
     * but for their ids and times. The writer has no way to be told how the operation went: its public
     * methods are exactly the two record calls, neither takes a result, a {@code Throwable}, a flag or
     * anything to run, and it is built from a lease source, a configuration and a clock only.
     */
    @Test
    public void au7AllowedRecordsAuthorizationNotExecution() throws Throwable {
        List<String> violations = new ArrayList<>();
        for (Engine engine : engines()) {
            for (LifecycleTestSupport.Fault operation : LifecycleTestSupport.Fault.values()) {
                String what = engine.name() + ", operation " + operation;
                String user = newUser("au7");
                AuthorizationAuditPayload payload = allowed(user);
                AuditEventId id = AuditEventId.next();
                AuditOutcome outcome = writer(engine.source()).recordAllowedBeforeExecution(id, payload, budget());
                expect(violations, what + ": the outcome", AuditOutcome.RECORDED, outcome);
                Throwable failed = null;
                try {
                    platformEquivalent(operation);
                } catch (RuntimeException | Error e) {
                    failed = e;
                }
                expect(violations, what + ": the operation failed", operation != LifecycleTestSupport.Fault.NONE, failed != null);
                List<Map<String, Object>> rows = rowsOf(engine, user);
                expect(violations, what + ": rows", 1, rows.size());
                expectRow(violations, what, rows.isEmpty() ? null : rows.get(0), id, WRITE_ALLOWED, payload);
            }
        }

        Set<String> api = new TreeSet<>();
        for (Method method : AccessAuditWriter.class.getDeclaredMethods()) {
            if (Modifier.isPublic(method.getModifiers()) || Modifier.isProtected(method.getModifiers())) {
                api.add(signature(method.getName(), method.getParameterTypes()));
            }
        }
        expect(violations, "the writer's methods", new TreeSet<>(List.of(
            "recordAllowedBeforeExecution(AuditEventId, AuthorizationAuditPayload, MetadataBudget)",
            "recordDenied(AuditEventId, AuthorizationAuditPayload)")), api);
        Set<Class<?>> allowedParameters = Set.of(MetadataLeaseSource.class, DbAccessPolicyConfig.class, LongSupplier.class);
        for (Constructor<?> constructor : AccessAuditWriter.class.getConstructors()) {
            for (Class<?> parameter : constructor.getParameterTypes()) {
                if (!allowedParameters.contains(parameter)) {
                    violations.add("a writer can be built with a " + parameter.getName());
                }
            }
        }
        Assertions.assertEquals(List.of(), violations, "AU-7");
    }

    // ---------------------------------------------------------------- AU-8: the log names the row

    /**
     * AU-8: a failure is logged under a new {@code EVENT_ID} and names the id of the row it was for
     * <p>
     * An allowed row and its correction both fail - the first with no row inserted, the second with no
     * connection: two lines, each with its own new {@code EVENT_ID}, different from each other and from
     * both rows' ids, and each naming its row's id, which row it was and why. A recorded row logs
     * nothing. On H2, an allowed row whose result arrived past its budget exists under exactly the id
     * the failure line names.
     */
    @Test
    public void au8AFailureLogNamesTheRowItWasFor() throws Throwable {
        List<String> violations = new ArrayList<>();
        String user = newUser("au8");
        AuthorizationAuditPayload allow = allowed(user);
        AuditEventId allowId = AuditEventId.next();
        AuditEventId correctionId = AuditEventId.next();
        AccessAuditWriter noRow = writer(new FakeSource(connection -> connection.updateCount = 0));
        FakeSource refusing = new FakeSource();
        refusing.fails = new InjectedSqlException("borrow");
        AccessAuditWriter noConnection = writer(refusing);
        LifecycleTestSupport.Captured captured = LifecycleTestSupport.captureLogs(() -> {
            noThrow(violations, "the allowed row", () -> noRow.recordAllowedBeforeExecution(allowId, allow, budget()));
            noThrow(violations, "the correction", () -> noConnection.recordDenied(
                correctionId, denied(user, DenialReason.GRANT_EXPIRED, allow.grantId(), allow.expiresAt())));
        });
        List<String> lines = writerLines(captured.dbacMessages());
        if (lines.size() != 2) {
            violations.add("expected two failure lines, got " + lines);
        } else {
            String allowLine = lines.get(0);
            String correctionLine = lines.get(1);
            expect(violations, "the allowed row's line names it", allowId.value(), group(LOG_AUDIT_EVENT_ID, allowLine));
            expect(violations, "the correction's line names it", correctionId.value(), group(LOG_AUDIT_EVENT_ID, correctionLine));
            if (!allowLine.contains("record=" + WRITE_ALLOWED) || !allowLine.contains("failure=NOT_DONE detail=CARDINALITY")) {
                violations.add("the allowed row's line must say which row and why: " + allowLine);
            }
            if (!correctionLine.contains("record=" + WRITE_DENIED) || !correctionLine.contains("failure=NO_LEASE detail=BORROW_FAILED")) {
                violations.add("the correction's line must say which row and why: " + correctionLine);
            }
            String first = group(LOG_EVENT_ID, allowLine);
            String second = group(LOG_EVENT_ID, correctionLine);
            Set<String> distinct = new HashSet<>(Arrays.asList(first, second, allowId.value(), correctionId.value()));
            if (first == null || second == null || distinct.size() != 4) {
                violations.add("each line needs an EVENT_ID of its own, apart from the rows' ids: " + lines);
            }
        }
        violations.addAll(LifecycleTestSupport.logContractViolations(captured, MetadataTestSupport.SECRET_FRAGMENTS));

        Engine h2 = engines().get(0);
        String recordedUser = newUser("au8-ok");
        AuditEventId recordedId = AuditEventId.next();
        LifecycleTestSupport.Captured quiet = LifecycleTestSupport.captureLogs(
            () -> writer(h2.source()).recordAllowedBeforeExecution(recordedId, allowed(recordedUser), budget()));
        expect(violations, "a recorded row's log lines", List.of(), quiet.dbacMessages());
        expect(violations, "a recorded row's id", recordedId.value(),
            readRow(h2, recordedId) == null ? null : readRow(h2, recordedId).get("EVENT_ID"));

        String lateUser = newUser("au8-late");
        AuditEventId lateId = AuditEventId.next();
        ManualClock clock = new ManualClock(BASE);
        Watched late = new Watched(h2.source());
        late.afterUpdate = () -> clock.advance(T_AUDIT.plusMillis(1));
        AtomicReference<AuditOutcome> lateOutcome = new AtomicReference<>();
        LifecycleTestSupport.Captured lateLog = LifecycleTestSupport.captureLogs(
            () -> lateOutcome.set(writer(late).recordAllowedBeforeExecution(lateId, allowed(lateUser), budget(clock))));
        expect(violations, "past the budget: the outcome", AuditOutcome.FAILED, lateOutcome.get());
        Map<String, Object> lateRow = readRow(h2, lateId);
        expect(violations, "past the budget: the row the line names", lateId.value(), lateRow == null ? null : lateRow.get("EVENT_ID"));
        List<String> lateLines = writerLines(lateLog.dbacMessages());
        expect(violations, "past the budget: the line", lateId.value(),
            lateLines.size() == 1 ? group(LOG_AUDIT_EVENT_ID, lateLines.get(0)) : lateLines);
        Assertions.assertEquals(List.of(), violations, "AU-8");
    }

    // ---------------------------------------------------------------- AU-9: the budget is the timeout

    /**
     * AU-9: the insert's query timeout is what is left of the audit budget, in whole seconds, and is put back
     * <p>
     * Scripted, with the budget's clock moved by hand: nothing spent sets {@code T_audit} itself, half a
     * second spent sets one second less, exactly one second left sets one, and less than that runs
     * nothing. Each timeout set is put back to what it was. On the H2 metadata pool the session carries the
     * timeout while the insert runs, and the same physical session reads zero once the writer has returned;
     * on PostgreSQL the insert's statement carries it, and the connection carries nothing afterwards.
     */
    @Test
    public void au9TheAuditTimeoutIsTheBudgetAndIsPutBack() throws Throwable {
        List<String> violations = new ArrayList<>();
        long seconds = T_AUDIT.getSeconds();
        record Case(Duration spent, @Nullable Integer timeout) {
        }

        for (Case one : List.of(
            new Case(Duration.ZERO, (int) seconds),
            new Case(Duration.ofMillis(500), (int) seconds - 1),
            new Case(T_AUDIT.minusSeconds(1), 1),
            new Case(T_AUDIT.minusSeconds(1).plusNanos(1), null))
        ) {
            String what = "scripted, " + one.spent() + " spent";
            ManualClock clock = new ManualClock(BASE);
            MetadataBudget budget = budget(clock);
            clock.advance(one.spent());
            FakeSource raw = new FakeSource();
            AuditOutcome outcome = writer(raw).recordAllowedBeforeExecution(AuditEventId.next(), allowed(newUser("au9")), budget);
            expect(violations, what + ": the outcome", one.timeout() == null ? AuditOutcome.FAILED : AuditOutcome.RECORDED, outcome);
            expect(violations, what + ": connections borrowed", 1, raw.made.size());
            List<String> calls = raw.made.isEmpty() ? List.of() : raw.made.get(0).calls();
            List<String> timeouts = calls.stream()
                .filter(call -> call.startsWith("setQueryTimeout(") || call.startsWith("restore(")).toList();
            expect(violations, what + ": timeouts set and put back",
                one.timeout() == null ? List.of() : List.of("setQueryTimeout(" + one.timeout() + ")", "restore(0)"), timeouts);
        }

        Engine h2 = engines().get(0);
        Watched session = new Watched(h2.source());
        session.observeTimeouts = true;
        session.recordSession = true;
        ManualClock h2Clock = new ManualClock(BASE);
        expect(violations, "H2: the outcome", AuditOutcome.RECORDED,
            writer(session).recordAllowedBeforeExecution(AuditEventId.next(), allowed(newUser("au9-h2")), budget(h2Clock)));
        expect(violations, "H2: the insert's own timeout, and the session's while it ran", List.of((int) seconds, (int) seconds),
            session.timeoutsDuringUpdate);
        if (session.sessions.size() != 1) {
            violations.add("H2: the insert must run on one session, it ran on " + session.sessions);
        } else {
            CBDatabase database = EmbeddedSecurityControllerFactory.getDbInstance();
            List<Connection> borrowed = new ArrayList<>();
            try {
                Integer after = null;
                for (int i = 0; i < 20 && after == null; i++) {
                    Connection next = database.openConnection();
                    borrowed.add(next);
                    if (MetadataLeaseTest.sessionId(next) == session.sessions.get(0)) {
                        try (Statement statement = next.createStatement()) {
                            after = statement.getQueryTimeout();
                        }
                    }
                }
                expect(violations, "H2: the same physical session after the writer returned", 0, after);
            } finally {
                for (Connection connection : borrowed) {
                    connection.close();
                }
            }
        }

        Engine postgres = engines().get(1);
        Watched kept = new Watched(postgres.source());
        kept.observeTimeouts = true;
        kept.keepOpen = true;
        ManualClock pgClock = new ManualClock(BASE);
        expect(violations, "PostgreSQL: the outcome", AuditOutcome.RECORDED,
            writer(kept).recordAllowedBeforeExecution(AuditEventId.next(), allowed(newUser("au9-pg")), budget(pgClock)));
        expect(violations, "PostgreSQL: the insert's own timeout; another statement's", List.of((int) seconds, 0),
            kept.timeoutsDuringUpdate);
        for (Connection connection : kept.kept) {
            try (Statement statement = connection.createStatement()) {
                expect(violations, "PostgreSQL: the connection after the writer returned", 0, statement.getQueryTimeout());
            } finally {
                connection.close();
            }
        }
        expect(violations, "PostgreSQL: the insert must run on one connection, kept", 1, kept.kept.size());
        Assertions.assertEquals(List.of(), violations, "AU-9");
    }

    // ---------------------------------------------------------------- AU-10: no lock, no controller, no platform

    /**
     * AU-10: the writer reaches no lock, coordinator, controller or platform type - neither in its source nor in its bytecode
     * <p>
     * Every class the writer's compiled classes refer to - class entries and the types in every
     * descriptor of their constant pools - must be one of a short list: the Java language, time, UUID,
     * the annotations, the platform log, and the policy types the writer is about. The key and user locks,
     * the taint registry, the deployment guard, the policy holder, the controller, the coordinator, the
     * metadata transaction, the raw connection source, JDBC, the lock package and every platform model
     * type are outside it. The sources may import nothing else either, used or not. And while the insert
     * runs, another thread takes the payload's grant and user write locks at once: the writer holds
     * neither.
     */
    @Test
    public void au10TheWriterReachesNoLockControllerOrPlatformType() throws Throwable {
        List<String> violations = new ArrayList<>();
        List<Class<?>> classes = new ArrayList<>(List.of(AccessAuditWriter.class, AuditOutcome.class, AuditEventId.class));
        classes.addAll(Arrays.asList(AccessAuditWriter.class.getDeclaredClasses()));
        for (Class<?> type : classes) {
            for (String referenced : referencedClasses(classBytes(type))) {
                if (!allowedReference(referenced)) {
                    violations.add(type.getSimpleName() + " refers to " + referenced);
                }
            }
        }
        Path sources = MetadataShutdownTest.dbacSourceRoot().resolve("io/cloudbeaver/service/dbac/policy/enforcement");
        for (String file : List.of("AccessAuditWriter.java", "AuditOutcome.java", "AuditEventId.java")) {
            for (String line : Files.readAllLines(sources.resolve(file), StandardCharsets.UTF_8)) {
                String trimmed = line.trim();
                if (!trimmed.startsWith("import ")) {
                    continue;
                }
                String imported = trimmed.substring("import ".length()).replace(";", "").trim();
                if (imported.startsWith("static ") || !allowedReference(imported.replace('.', '/'))) {
                    violations.add(file + " imports " + imported);
                }
            }
        }

        Engine h2 = engines().get(0);
        String user = newUser("au10");
        DbAccessKey key = new DbAccessKey(user, PROJECT, CONNECTION);
        AtomicReference<MetadataTestSupport.Outcome<Boolean>> locked = new AtomicReference<>();
        Watched watched = new Watched(h2.source());
        watched.beforeUpdate = () -> locked.set(MetadataTestSupport.within(Duration.ofSeconds(2), () -> {
            try (EnforcementKeyLocks.Held grant = EnforcementKeyLocks.global().lockGrantForWrite(key);
                 EnforcementKeyLocks.Held held = EnforcementKeyLocks.global().lockUserForWrite(user)) {
                return grant != null && held != null;
            }
        }));
        expect(violations, "the outcome", AuditOutcome.RECORDED,
            writer(watched).recordAllowedBeforeExecution(AuditEventId.next(), allowed(user), budget()));
        MetadataTestSupport.Outcome<Boolean> during = locked.get();
        if (during == null || !during.finished() || during.thrown() != null || !Boolean.TRUE.equals(during.value())) {
            violations.add("another thread must take the grant and user write locks while the insert runs, got "
                + (during == null ? "no attempt" : "finished=" + during.finished() + " value=" + during.value()));
        }
        Assertions.assertEquals(List.of(), violations, "AU-10");
    }

    // ---------------------------------------------------------------- AU-11: past the budget is not used

    /**
     * AU-11: a result that arrives after the audit budget is spent is {@code FAILED}, whatever it says
     * <p>
     * Scripted: the insert returns its one row exactly at the end of the budget, which counts, and a
     * nanosecond after it, which does not; a borrow that uses the whole budget gives no lease and runs
     * nothing; a denial's own budget is held to the same rule. On both engines a committed row whose
     * statement returned past the budget is in the table and is still {@code FAILED}: a late answer is
     * not acted on.
     */
    @Test
    public void au11AResultPastTheAuditBudgetIsNotUsed() throws Throwable {
        List<String> violations = new ArrayList<>();
        for (Duration statement : List.of(T_AUDIT, T_AUDIT.plusNanos(1))) {
            ManualClock clock = new ManualClock(BASE);
            FakeSource raw = new FakeSource(connection -> connection.onExecute = () -> clock.advance(statement));
            boolean within = statement.equals(T_AUDIT);
            Run run = run(() -> writer(raw).recordAllowedBeforeExecution(AuditEventId.next(), allowed(newUser("au11")), budget(clock)));
            if (within) {
                expect(violations, "returned at the end of the budget", AuditOutcome.RECORDED, run.outcome());
            } else {
                expectFailed(violations, "returned a nanosecond past the budget", run, "failure=NOT_DONE detail=OVER_BUDGET");
            }
        }

        ManualClock borrowClock = new ManualClock(BASE);
        FakeSource slowBorrow = new FakeSource();
        slowBorrow.onBorrow = () -> borrowClock.advance(T_AUDIT.plusMillis(1));
        Run borrowRun = run(() -> writer(slowBorrow).recordAllowedBeforeExecution(
            AuditEventId.next(), allowed(newUser("au11")), budget(borrowClock)));
        List<String> borrowLines = writerLines(borrowRun.lines());
        if (borrowRun.outcome() != AuditOutcome.FAILED || borrowRun.thrown() != null
            || borrowLines.size() != 1 || !borrowLines.get(0).contains("failure=NO_LEASE")) {
            violations.add("a borrow that spent the budget must give FAILED with no lease, got " + borrowRun);
        }
        expect(violations, "a borrow that spent the budget: statements executed", 0,
            slowBorrow.made.stream().mapToInt(connection -> connection.executes.get()).sum());

        ManualClock deniedClock = new ManualClock(BASE);
        FakeSource slowDenial = new FakeSource(connection -> connection.onExecute = () -> deniedClock.advance(T_AUDIT.plusNanos(1)));
        Run deniedRun = run(() -> writer(slowDenial, deniedClock).recordDenied(
            AuditEventId.next(), denied(newUser("au11"), DenialReason.NO_GRANT, null, null)));
        expectFailed(violations, "a denial a nanosecond past its own budget", deniedRun, "failure=NOT_DONE detail=OVER_BUDGET");

        for (Engine engine : engines()) {
            String user = newUser("au11-late");
            AuditEventId id = AuditEventId.next();
            ManualClock clock = new ManualClock(BASE);
            Watched watched = new Watched(engine.source());
            watched.afterUpdate = () -> clock.advance(T_AUDIT.plusMillis(1));
            AuditOutcome outcome = writer(watched).recordAllowedBeforeExecution(id, allowed(user), budget(clock));
            expect(violations, engine.name() + ": a committed row past the budget", AuditOutcome.FAILED, outcome);
            expectRow(violations, engine.name() + ", the late row", readRow(engine, id), id, WRITE_ALLOWED, allowed(user));
        }
        Assertions.assertEquals(List.of(), violations, "AU-11");
    }

    // ---------------------------------------------------------------- AU-12: a failing log changes nothing

    /**
     * AU-12: a log that throws - a {@code RuntimeException} or an {@code Error} - changes no outcome and escapes nowhere
     * <p>
     * A failed allowed row and a failed denied row stay {@code FAILED}, a recorded row stays
     * {@code RECORDED}, and nothing is thrown at the caller, while every DBAC log write on the thread fails.
     */
    @Test
    public void au12AFailingLogChangesNoOutcome() throws Throwable {
        List<String> violations = new ArrayList<>();
        List<String> fixture = new ArrayList<>();
        for (LifecycleTestSupport.Fault fault : List.of(LifecycleTestSupport.Fault.RUNTIME, LifecycleTestSupport.Fault.ERROR)) {
            AccessAuditWriter failing = writer(new FakeSource(connection -> connection.updateCount = 0));
            FakeSource refusing = new FakeSource();
            refusing.fails = new InjectedSqlException("borrow");
            AccessAuditWriter refused = writer(refusing);
            AccessAuditWriter working = writer(new FakeSource());
            List<String> outcomes = new ArrayList<>();
            int raised = LifecycleTestSupport.withFailingLog(fault, () -> {
                for (int i = 0; i < 3; i++) {
                    try {
                        AuditOutcome outcome = switch (i) {
                            case 0 -> failing.recordAllowedBeforeExecution(AuditEventId.next(), allowed(newUser("au12")), budget());
                            case 1 -> refused.recordDenied(AuditEventId.next(), denied(newUser("au12"), DenialReason.NO_GRANT, null, null));
                            default -> working.recordAllowedBeforeExecution(AuditEventId.next(), allowed(newUser("au12")), budget());
                        };
                        outcomes.add(String.valueOf(outcome));
                    } catch (Throwable t) {
                        outcomes.add("threw " + t.getClass().getSimpleName());
                    }
                }
            });
            expect(violations, fault + ": the outcomes", List.of("FAILED", "FAILED", "RECORDED"), outcomes);
            if (raised < 2) {
                fixture.add(fault + ": the log must have failed for both failures, it failed " + raised + " time(s)");
            }
        }
        Assertions.assertEquals(List.of(), violations, "AU-12");
        Assertions.assertEquals(List.of(), fixture, "FIXTURE AU-12");
    }

    // ---------------------------------------------------------------- helpers

    @NotNull
    private static String newUser(@NotNull String tag) {
        return USER_PREFIX + tag + "-" + Long.toHexString(System.nanoTime()) + "-" + SEQUENCE.incrementAndGet();
    }

    @NotNull
    private static AuthorizationAuditPayload allowed(@NotNull String user) {
        return new AuthorizationAuditPayload(DbAccessDecision.ALLOW, null, user, PROJECT, CONNECTION,
            "grant-" + user.substring(USER_PREFIX.length()), DbOperationCategory.SQL_TEXT, EXPIRES_AT);
    }

    @NotNull
    private static AuthorizationAuditPayload denied(
        @NotNull String user,
        @NotNull DenialReason reason,
        @Nullable String grantId,
        @Nullable OffsetDateTime expiresAt
    ) {
        return new AuthorizationAuditPayload(DbAccessDecision.DENY, reason, user, PROJECT, CONNECTION, grantId,
            DbOperationCategory.DATA_EDIT, expiresAt);
    }

    /** {@code T_audit} from now, on the system clock, as a window hands it out when nothing has passed since check-1 */
    @NotNull
    private static MetadataBudget budget() {
        return MetadataBudget.startingNow(System::nanoTime, T_AUDIT);
    }

    /** {@code T_audit} from the clock's current reading */
    @NotNull
    private static MetadataBudget budget(@NotNull ManualClock clock) {
        return MetadataBudget.startedAt(clock, clock.getAsLong(), T_AUDIT);
    }

    @NotNull
    private AccessAuditWriter writer(@NotNull MetadataConnectionSource raw) {
        return new AccessAuditWriter(leases.of(raw), CONFIG);
    }

    @NotNull
    private AccessAuditWriter writer(@NotNull MetadataConnectionSource raw, @NotNull LongSupplier deniedClock) {
        return new AccessAuditWriter(leases.of(raw), CONFIG, deniedClock);
    }

    /** Stands in for the platform call an enforcement gate makes after the audit */
    private static void platformEquivalent(@NotNull LifecycleTestSupport.Fault fault) {
        switch (fault) {
            case RUNTIME -> throw new LifecycleTestSupport.InjectedRuntimeException("operation");
            case ERROR -> throw new LifecycleTestSupport.InjectedError("operation");
            default -> {
            }
        }
    }

    /** What one writer call returned or threw, and what it logged on this thread */
    private record Run(@Nullable AuditOutcome outcome, @Nullable Throwable thrown, @NotNull List<String> lines) {
        @NotNull
        @Override
        public String toString() {
            return "outcome=" + outcome + " thrown=" + (thrown == null ? null : thrown.getClass().getName()) + " lines=" + lines;
        }
    }

    /** A writer call */
    @FunctionalInterface
    private interface WriterCall {
        @Nullable
        AuditOutcome call();
    }

    @NotNull
    private static Run run(@NotNull WriterCall call) throws Throwable {
        AtomicReference<AuditOutcome> outcome = new AtomicReference<>();
        AtomicReference<Throwable> thrown = new AtomicReference<>();
        LifecycleTestSupport.Captured captured = LifecycleTestSupport.captureLogs(() -> {
            try {
                outcome.set(call.call());
            } catch (Throwable t) {
                thrown.set(t);
            }
        });
        return new Run(outcome.get(), thrown.get(), captured.dbacMessages());
    }

    /** Calls the writer; anything it throws is a violation of its contract, not a crash of the test */
    private static void noThrow(@NotNull List<String> violations, @NotNull String what, @NotNull WriterCall call) {
        try {
            call.call();
        } catch (Throwable t) {
            violations.add(what + ": the writer threw " + t.getClass().getName());
        }
    }

    /** {@code FAILED}, nothing thrown, and exactly one line naming {@code failure} */
    private static void expectFailed(@NotNull List<String> violations, @NotNull String what, @NotNull Run run, @NotNull String failure) {
        if (run.thrown() != null) {
            violations.add(what + ": the writer threw " + run.thrown().getClass().getName());
            return;
        }
        if (run.outcome() != AuditOutcome.FAILED) {
            violations.add(what + ": expected FAILED, got " + run.outcome());
        }
        List<String> lines = writerLines(run.lines());
        if (lines.size() != 1 || !lines.get(0).contains(failure)) {
            violations.add(what + ": expected one line with " + failure + ", got " + run.lines());
        }
    }

    /** The writer's own lines among the DBAC ones; a lease logs its own events beside them */
    @NotNull
    private static List<String> writerLines(@NotNull List<String> messages) {
        return messages.stream().filter(message -> message.contains(FAILURE_EVENT)).toList();
    }

    private static void expect(@NotNull List<String> violations, @NotNull String what, @Nullable Object expected, @Nullable Object actual) {
        if (expected == null ? actual != null : !expected.equals(actual)) {
            violations.add(what + ": expected " + expected + ", got " + actual);
        }
    }

    /** The row holds exactly the payload: every column but {@code EVENT_TIME}, which must be present */
    private static void expectRow(
        @NotNull List<String> violations,
        @NotNull String what,
        @Nullable Map<String, Object> row,
        @NotNull AuditEventId id,
        @NotNull String eventType,
        @NotNull AuthorizationAuditPayload payload
    ) {
        if (row == null) {
            violations.add(what + ": no row under " + id);
            return;
        }
        Map<String, Object> expected = new LinkedHashMap<>();
        expected.put("EVENT_ID", id.value());
        expected.put("EVENT_TYPE", eventType);
        expected.put("USER_ID", payload.userId());
        expected.put("ACTOR_ID", payload.userId());
        expected.put("PROJECT_ID", payload.projectId());
        expected.put("CONNECTION_ID", payload.connectionId());
        expected.put("GRANT_ID", payload.grantId());
        expected.put("OPERATION_CATEGORY", payload.operationCategory().name());
        expected.put("STATEMENT_TYPE", null);
        expected.put("DECISION", payload.decision().name());
        expected.put("DENIAL_REASON", payload.denialReason() == null ? null : payload.denialReason().name());
        expected.put("EXPIRES_AT", payload.expiresAt() == null ? null : payload.expiresAt().toInstant());
        Map<String, Object> actual = new LinkedHashMap<>(row);
        Object time = actual.remove("EVENT_TIME");
        if (!expected.equals(actual)) {
            violations.add(what + ": the row must hold exactly the payload, expected " + expected + ", got " + actual);
        }
        if (time == null) {
            violations.add(what + ": the row has no EVENT_TIME");
        }
    }

    /** The row under {@code id}, read by a connection of its own; null when there is none */
    @Nullable
    private static Map<String, Object> readRow(@NotNull Engine engine, @NotNull AuditEventId id) throws SQLException {
        List<Map<String, Object>> rows = select(engine, "EVENT_ID", id.value());
        Assertions.assertTrue(rows.size() <= 1, "FIXTURE: EVENT_ID is the primary key");
        return rows.isEmpty() ? null : rows.get(0);
    }

    @NotNull
    private static List<Map<String, Object>> rowsOf(@NotNull Engine engine, @NotNull String user) throws SQLException {
        return select(engine, "USER_ID", user);
    }

    @NotNull
    private static List<Map<String, Object>> select(
        @NotNull Engine engine,
        @NotNull String column,
        @NotNull String value
    ) throws SQLException {
        try (Connection connection = engine.source().openConnection();
             PreparedStatement dbStat = connection.prepareStatement("SELECT " + String.join(", ", COLUMNS)
                 + " FROM {table_prefix}DBAC_AUDIT_EVENT WHERE " + column + " = ? ORDER BY EVENT_ID")) {
            dbStat.setString(1, value);
            List<Map<String, Object>> rows = new ArrayList<>();
            try (ResultSet dbResult = dbStat.executeQuery()) {
                while (dbResult.next()) {
                    Map<String, Object> row = new LinkedHashMap<>();
                    for (String name : COLUMNS) {
                        if (name.equals("EVENT_TIME")) {
                            row.put(name, dbResult.getObject(name, OffsetDateTime.class));
                        } else if (name.equals("EXPIRES_AT")) {
                            OffsetDateTime expires = dbResult.getObject(name, OffsetDateTime.class);
                            row.put(name, expires == null ? null : expires.toInstant());
                        } else {
                            row.put(name, dbResult.getString(name));
                        }
                    }
                    rows.add(row);
                }
            }
            return rows;
        }
    }

    @NotNull
    private static OffsetDateTime dbNow(@NotNull Engine engine) throws SQLException {
        try (Connection connection = engine.source().openConnection();
             PreparedStatement dbStat = connection.prepareStatement("SELECT CURRENT_TIMESTAMP");
             ResultSet dbResult = dbStat.executeQuery()) {
            Assertions.assertTrue(dbResult.next(), "FIXTURE: the database must tell its time");
            return dbResult.getObject(1, OffsetDateTime.class);
        }
    }

    /** A row under {@code id}, written on {@code connection} - for a test to hold uncommitted */
    private static void insertDirectly(@NotNull Connection connection, @NotNull AuditEventId id, @NotNull String user) throws SQLException {
        try (PreparedStatement dbStat = connection.prepareStatement("INSERT INTO {table_prefix}DBAC_AUDIT_EVENT"
            + " (EVENT_ID, EVENT_TYPE, EVENT_TIME, USER_ID) VALUES (?, ?, CURRENT_TIMESTAMP, ?)")) {
            dbStat.setString(1, id.value());
            dbStat.setString(2, WRITE_ALLOWED);
            dbStat.setString(3, user);
            Assertions.assertEquals(1, dbStat.executeUpdate(), "FIXTURE: the blocking row");
        }
    }

    @Nullable
    private static String group(@NotNull Pattern pattern, @NotNull String text) {
        Matcher matcher = pattern.matcher(text);
        return matcher.find() ? matcher.group(1) : null;
    }

    @NotNull
    private static String signature(@NotNull String name, @NotNull Class<?>[] parameters) {
        StringBuilder text = new StringBuilder(name).append('(');
        for (int i = 0; i < parameters.length; i++) {
            text.append(i == 0 ? "" : ", ").append(parameters[i].getSimpleName());
        }
        return text.append(')').toString();
    }

    // ---------------------------------------------------------------- bytecode

    /** Everything the writer's classes may refer to: a package ends in '/', a class matches itself and its nested classes */
    private static final List<String> ALLOWED_REFERENCES = List.of(
        "java/lang/",
        "java/time/Duration",
        "java/time/OffsetDateTime",
        "java/util/UUID",
        "java/util/Objects",
        "java/util/function/LongSupplier",
        "org/jkiss/code/",
        "org/jkiss/dbeaver/Log",
        "io/cloudbeaver/service/dbac/policy/AuthorizationAuditPayload",
        "io/cloudbeaver/service/dbac/policy/DbAccessDecision",
        "io/cloudbeaver/service/dbac/policy/DbAccessPolicyConfig",
        "io/cloudbeaver/service/dbac/policy/DbOperationCategory",
        "io/cloudbeaver/service/dbac/policy/DenialReason",
        "io/cloudbeaver/service/dbac/policy/MetadataBudget",
        "io/cloudbeaver/service/dbac/policy/MetadataLease",
        "io/cloudbeaver/service/dbac/policy/MetadataLeaseSource",
        "io/cloudbeaver/service/dbac/policy/MetadataOutcome",
        "io/cloudbeaver/service/dbac/policy/MetadataPurpose",
        "io/cloudbeaver/service/dbac/policy/MetadataUnavailableException",
        "io/cloudbeaver/service/dbac/policy/MetadataUpdate",
        "io/cloudbeaver/service/dbac/policy/UnusableCause",
        "io/cloudbeaver/service/dbac/policy/enforcement/AccessAuditWriter",
        "io/cloudbeaver/service/dbac/policy/enforcement/AuditOutcome",
        "io/cloudbeaver/service/dbac/policy/enforcement/AuditEventId");

    private static boolean allowedReference(@NotNull String name) {
        for (String allowed : ALLOWED_REFERENCES) {
            if (allowed.endsWith("/") ? name.startsWith(allowed) && !name.substring(allowed.length()).contains("/")
                || allowed.equals("java/lang/") && name.startsWith("java/lang/invoke/")
                : name.equals(allowed) || name.startsWith(allowed + "$")
            ) {
                return true;
            }
        }
        return false;
    }

    /** The compiled class, from the bundle's class loader or, failing that, the build output */
    @NotNull
    private static byte[] classBytes(@NotNull Class<?> type) throws IOException {
        String resource = type.getName().replace('.', '/') + ".class";
        ClassLoader loader = type.getClassLoader();
        try (InputStream in = loader == null ? null : loader.getResourceAsStream(resource)) {
            if (in != null) {
                return in.readAllBytes();
            }
        }
        Path built = MetadataLeaseTest.repositoryRoot()
            .resolve("server/bundles/io.cloudbeaver.service.dbac/target/classes").resolve(resource);
        Assertions.assertTrue(Files.isRegularFile(built), "FIXTURE: the class file of " + type.getName() + " was not found");
        return Files.readAllBytes(built);
    }

    /** Every class a class file refers to: its class entries, and every type named in a descriptor or signature */
    @NotNull
    private static Set<String> referencedClasses(@NotNull byte[] bytes) throws IOException {
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes));
        Assertions.assertEquals(0xCAFEBABE, in.readInt(), "FIXTURE: not a class file");
        in.readUnsignedShort();
        in.readUnsignedShort();
        int count = in.readUnsignedShort();
        String[] utf8 = new String[count];
        List<Integer> classes = new ArrayList<>();
        Set<Integer> literals = new HashSet<>();
        for (int i = 1; i < count; i++) {
            int tag = in.readUnsignedByte();
            switch (tag) {
                case 1 -> utf8[i] = in.readUTF();
                case 3, 4 -> in.readInt();
                case 5, 6 -> {
                    in.readLong();
                    i++;
                }
                case 7 -> classes.add(in.readUnsignedShort());
                case 8 -> literals.add(in.readUnsignedShort());
                case 9, 10, 11, 12, 17, 18 -> in.readInt();
                case 15 -> {
                    in.readUnsignedByte();
                    in.readUnsignedShort();
                }
                case 16, 19, 20 -> in.readUnsignedShort();
                default -> throw new IOException("constant pool tag " + tag);
            }
        }
        Set<String> found = new TreeSet<>();
        Pattern descriptor = Pattern.compile("L([\\w/$]+)[;<]");
        for (int index : classes) {
            String name = utf8[index];
            if (name.startsWith("[")) {
                Matcher matcher = descriptor.matcher(name);
                while (matcher.find()) {
                    found.add(matcher.group(1));
                }
            } else {
                found.add(name);
            }
        }
        for (int i = 1; i < count; i++) {
            if (utf8[i] == null || literals.contains(i)) {
                continue;
            }
            Matcher matcher = descriptor.matcher(utf8[i]);
            while (matcher.find()) {
                found.add(matcher.group(1));
            }
        }
        return found;
    }

    // ---------------------------------------------------------------- watched connections

    /** Runs inside a watched connection's call; may throw anything */
    @FunctionalInterface
    private interface Hook {
        void run() throws Exception;
    }

    /**
     * A raw source whose connections the test watches
     * <p>
     * It records each statement prepared, runs hooks just before and just after the update executes,
     * and can record the timeouts in force while it runs, hand out a connection that is not in
     * auto-commit (rolled back and restored when the lease closes it), or keep the physical connection
     * open past the lease's close so the test can look at it.
     */
    private static final class Watched implements MetadataConnectionSource {
        final List<String> prepared = Collections.synchronizedList(new ArrayList<>());
        final List<Integer> timeoutsDuringUpdate = Collections.synchronizedList(new ArrayList<>());
        final List<Long> sessions = Collections.synchronizedList(new ArrayList<>());
        final List<Connection> kept = Collections.synchronizedList(new ArrayList<>());
        final AtomicInteger updates = new AtomicInteger();
        private final MetadataConnectionSource delegate;
        volatile Hook beforeUpdate = () -> { };
        volatile Hook afterUpdate = () -> { };
        volatile boolean manualCommit;
        volatile boolean observeTimeouts;
        volatile boolean recordSession;
        volatile boolean keepOpen;

        Watched(@NotNull MetadataConnectionSource delegate) {
            this.delegate = delegate;
        }

        @NotNull
        @Override
        public Connection openConnection() throws SQLException {
            Connection connection = delegate.openConnection();
            boolean manual = manualCommit;
            boolean keep = keepOpen;
            if (manual) {
                connection.setAutoCommit(false);
            }
            if (recordSession) {
                sessions.add(MetadataLeaseTest.sessionId(connection));
            }
            return MetadataTestSupport.proxy(Connection.class, (self, method, args) -> {
                switch (method.getName()) {
                    case "prepareStatement" -> {
                        prepared.add((String) args[0]);
                        PreparedStatement statement = (PreparedStatement) invoke(connection, method, args);
                        return MetadataTestSupport.proxy(PreparedStatement.class, (inner, innerMethod, innerArgs) -> {
                            if (!innerMethod.getName().equals("executeUpdate")) {
                                return invoke(statement, innerMethod, innerArgs);
                            }
                            updates.incrementAndGet();
                            if (observeTimeouts) {
                                timeoutsDuringUpdate.add(statement.getQueryTimeout());
                                try (Statement other = connection.createStatement()) {
                                    timeoutsDuringUpdate.add(other.getQueryTimeout());
                                }
                            }
                            beforeUpdate.run();
                            Object result = invoke(statement, innerMethod, innerArgs);
                            afterUpdate.run();
                            return result;
                        });
                    }
                    case "close" -> {
                        if (manual) {
                            connection.rollback();
                            connection.setAutoCommit(true);
                        }
                        if (keep) {
                            kept.add(connection);
                            return null;
                        }
                        return invoke(connection, method, args);
                    }
                    case "hashCode" -> {
                        return System.identityHashCode(self);
                    }
                    case "equals" -> {
                        return self == args[0];
                    }
                    default -> {
                        return invoke(connection, method, args);
                    }
                }
            });
        }
    }

    @Nullable
    private static Object invoke(@NotNull Object target, @NotNull Method method, @Nullable Object[] args) throws Throwable {
        try {
            return method.invoke(target, args);
        } catch (InvocationTargetException e) {
            throw e.getCause();
        }
    }

    // ---------------------------------------------------------------- canaries

    /** A driver failure whose message carries a URL, a database user, a password, a token and a statement */
    private static final class CanarySqlException extends SQLException {
        CanarySqlException() {
            super(CANARY_MESSAGE, "08006");
        }
    }

    /** The same, as a {@code RuntimeException} */
    private static final class CanaryRuntimeException extends RuntimeException {
        CanaryRuntimeException() {
            super(CANARY_MESSAGE);
        }
    }

    /** The same, as an {@code Error} */
    private static final class CanaryError extends Error {
        CanaryError() {
            super(CANARY_MESSAGE);
        }
    }

    /** Lets a lambda that may not declare a checked exception throw the {@code RuntimeException} or {@code Error} it is given */
    private static final class Unchecked {
        private Unchecked() {
        }

        @NotNull
        static RuntimeException of(@NotNull Throwable thrown) {
            if (thrown instanceof Error error) {
                throw error;
            }
            return (RuntimeException) thrown;
        }
    }
}
