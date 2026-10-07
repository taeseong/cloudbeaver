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
import io.cloudbeaver.service.dbac.policy.BoundedMetadataConnections;
import io.cloudbeaver.service.dbac.policy.LeaseState;
import io.cloudbeaver.service.dbac.policy.MetadataBudget;
import io.cloudbeaver.service.dbac.policy.MetadataLease;
import io.cloudbeaver.service.dbac.policy.MetadataLeaseSource;
import io.cloudbeaver.service.dbac.policy.MetadataOutcome;
import io.cloudbeaver.service.dbac.policy.MetadataPurpose;
import io.cloudbeaver.service.dbac.policy.MetadataQuery;
import io.cloudbeaver.service.dbac.policy.MetadataRow;
import io.cloudbeaver.service.dbac.policy.MetadataRows;
import io.cloudbeaver.service.dbac.policy.MetadataUnavailableException;
import io.cloudbeaver.service.dbac.policy.MetadataUpdate;
import io.cloudbeaver.service.dbac.policy.UnusableCause;
import io.cloudbeaver.service.dbac.tempwrite.MetadataConnectionSource;
import io.cloudbeaver.service.security.EmbeddedSecurityControllerFactory;
import io.cloudbeaver.service.security.db.CBDatabase;
import io.cloudbeaver.test.platform.dbac.MetadataTestSupport.FakeConnection;
import io.cloudbeaver.test.platform.dbac.MetadataTestSupport.FakeSource;
import io.cloudbeaver.test.platform.dbac.MetadataTestSupport.InjectedLeaseError;
import io.cloudbeaver.test.platform.dbac.MetadataTestSupport.InjectedSqlException;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.GenericArrayType;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.RecordComponent;
import java.lang.reflect.Type;
import java.lang.reflect.TypeVariable;
import java.lang.reflect.WildcardType;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

/**
 * P5-1a: the metadata lease - one statement, nothing JDBC leaves it, the timeout always put back
 * <p>
 * Most cases run on a scripted connection whose query timeout behaves like H2's - it belongs to the
 * session - so a restore that is skipped, or done in the wrong place, shows up as a value. ST-7 runs on
 * the test server's real metadata pool (H2 behind DBCP); ST-8 is in {@link MetadataLeasePostgresTest}.
 */
public class MetadataLeaseTest {

    private static final Duration CALL_LIMIT = Duration.ofSeconds(10);

    private final MetadataLeaseFixture leases = new MetadataLeaseFixture();

    @AfterEach
    public void closeLeases() {
        leases.close();
    }

    @BeforeAll
    public static void startServer() throws Exception {
        CEAppStarter.startServerIfNotStarted();
    }

    // ---------------------------------------------------------------- ST: one statement, one template

    /**
     * ST-1, ML-1: one query, in template order; Done; the timeout restored; closed normally once; the slot back
     */
    @Test
    public void st1OneQueryRunsTheTemplateAndReturnsTheConnection() {
        FakeSource raw = new FakeSource();
        BoundedMetadataConnections source = source(raw);
        MetadataLease lease = lease(source);

        MetadataOutcome<MetadataRows> outcome = lease.query(MetadataTestSupport.valueQuery());

        FakeConnection connection = raw.only();
        Assertions.assertEquals("value", done(outcome).row(0).string("V"), "ST-1: the value must come back");
        Assertions.assertEquals(LeaseState.USED, lease.state(), "ST-1: a lease that ran its statement is USED");
        Assertions.assertEquals(1, connection.executes.get(), "ST-1: one execution");
        Assertions.assertEquals(0, connection.sessionTimeout.get(), "ST-1: the session's query timeout must be put back");
        List<String> calls = connection.calls();
        int set = indexOf(calls, "setQueryTimeout(");
        Assertions.assertTrue(set >= 0, "ST-1: a query timeout must be set, got " + calls);
        int seconds = Integer.parseInt(calls.get(set).replaceAll("\\D", ""));
        Assertions.assertTrue(seconds >= 1 && seconds <= MetadataTestSupport.LONG.getSeconds(),
            "ST-1: the timeout must be the remaining budget in whole seconds, got " + seconds);
        assertOrder(calls, "getAutoCommit", "prepareStatement", "getQueryTimeout", "setQueryTimeout(", "executeQuery",
            "result.close", "statement.close", "createStatement", "restore(0)", "restore.close");

        lease.close();
        Assertions.assertEquals(LeaseState.RETURNED, lease.state(), "ML-1: an ordinary close returns the connection");
        Assertions.assertEquals(List.of("close"), tail(connection.calls(), calls.size()), "ML-1: one ordinary close, no abort");
        Assertions.assertEquals(BoundedMetadataConnections.CAPACITY, source.availableSlots(), "ML-1: the slot must be free again");
    }

    /**
     * ST-2: a second statement on the same lease, of either kind, runs nothing
     */
    @Test
    public void st2ASecondStatementIsRefusedWithoutRunning() {
        FakeSource raw = new FakeSource();
        BoundedMetadataConnections source = source(raw);
        List<String> violations = new ArrayList<>();

        MetadataLease queried = lease(source);
        done(queried.query(MetadataTestSupport.valueQuery()));
        expectUnusable(violations, "query then query", queried.query(MetadataTestSupport.valueQuery()), UnusableCause.SECOND_STATEMENT);
        expectUnusable(violations, "query then update", queried.update(oneRowUpdate()), UnusableCause.SECOND_STATEMENT);
        queried.close();
        expectUnusable(violations, "query after close", queried.query(MetadataTestSupport.valueQuery()), UnusableCause.SECOND_STATEMENT);

        MetadataLease updated = lease(source);
        Assertions.assertEquals(1L, done(updated.update(oneRowUpdate())), "FIXTURE ST-2: the first update must run");
        expectUnusable(violations, "update then query", updated.query(MetadataTestSupport.valueQuery()), UnusableCause.SECOND_STATEMENT);
        updated.close();

        for (FakeConnection connection : raw.made) {
            if (connection.prepares.get() != 1 || connection.executes.get() != 1) {
                violations.add("connection " + connection.id + " prepared " + connection.prepares.get() + " and executed "
                    + connection.executes.get() + " times, expected once each");
            }
        }
        Assertions.assertEquals(List.of(), violations, "ST-2");
    }

    /**
     * ST-3: a statement that cannot be prepared sets no timeout and leaves the session untouched
     */
    @Test
    public void st3PrepareFailureTouchesNothing() {
        FakeSource raw = new FakeSource(connection -> connection.prepareFails = new InjectedSqlException("prepare"));
        MetadataLease lease = lease(source(raw));

        assertUnusable(lease.query(MetadataTestSupport.valueQuery()), UnusableCause.STATEMENT_FAILED, "ST-3");
        FakeConnection connection = raw.only();
        Assertions.assertEquals(-1, indexOf(connection.calls(), "setQueryTimeout("), "ST-3: no timeout may be set");
        Assertions.assertEquals(0, connection.count("createStatement"), "ST-3: nothing to restore");
        Assertions.assertEquals(LeaseState.USED, lease.state(), "ST-3: the session is as it was");
        lease.close();
        Assertions.assertEquals(LeaseState.RETURNED, lease.state(), "ST-3: and is returned normally");
        Assertions.assertEquals(0, connection.aborts.get(), "ST-3: no abort");
    }

    /**
     * ST-4: a timeout that cannot be set is restored anyway; returned when the restore works, aborted when it does not
     */
    @Test
    public void st4TimeoutSetupFailureStillRestores() {
        leases.allowResidue();
        List<String> violations = new ArrayList<>();

        FakeSource restored = new FakeSource(connection -> connection.setTimeoutFails = new InjectedSqlException("set"));
        MetadataLease first = lease(source(restored));
        expectUnusable(violations, "restore works", first.query(MetadataTestSupport.valueQuery()), UnusableCause.TIMEOUT_SETUP_FAILED);
        expect(violations, "restore works: restore attempted", 1, restored.only().count("restore(0)"));
        expect(violations, "restore works: state", LeaseState.USED, first.state());
        first.close();
        expect(violations, "restore works: end", LeaseState.RETURNED, first.state());

        FakeSource broken = new FakeSource(connection -> {
            connection.setTimeoutFails = new InjectedSqlException("set");
            connection.restoreSetFails = new InjectedSqlException("restore");
        });
        MetadataLease second = lease(source(broken));
        MetadataOutcome<MetadataRows> outcome = second.query(MetadataTestSupport.valueQuery());
        if (!(outcome instanceof MetadataOutcome.Unusable)) {
            violations.add("restore fails: expected an unusable result, got " + outcome);
        }
        expect(violations, "restore fails: state", LeaseState.CONTAMINATED, second.state());
        second.close();
        expect(violations, "restore fails: end", LeaseState.INVALIDATED, second.state());
        expect(violations, "restore fails: aborted before any close", "abort", firstOf(broken.only().calls(), "abort", "close"));

        FakeSource stuck = new FakeSource(connection -> {
            connection.setTimeoutFails = new InjectedSqlException("set");
            connection.restoreSetFails = new InjectedSqlException("restore");
            connection.abortFails = new InjectedSqlException("abort");
        });
        BoundedMetadataConnections stuckSource = source(stuck);
        MetadataLease third = lease(stuckSource);
        third.query(MetadataTestSupport.valueQuery());
        third.close();
        expect(violations, "abort fails: end", LeaseState.QUARANTINED, third.state());
        expect(violations, "abort fails: quarantined", 1, stuckSource.quarantined());
        expect(violations, "abort fails: never closed normally", 0, stuck.only().count("close"));
        Assertions.assertEquals(List.of(), violations, "ST-4");
    }

    /**
     * ST-5: a result that cannot be read as declared, or has the wrong number of rows, gives no value; the timeout is still restored
     */
    @Test
    public void st5MaterializationAndCardinalityFailuresGiveNoValue() {
        List<String> violations = new ArrayList<>();
        record Case(String name, List<Map<String, Object>> rows, MetadataQuery query, UnusableCause expected) {
        }

        Map<String, Object> wrongType = new HashMap<>();
        wrongType.put("V", 42);
        Map<String, Object> missing = new HashMap<>();
        List<Case> cases = List.of(
            new Case("a string column holding a number", List.of(wrongType), MetadataTestSupport.valueQuery(),
                UnusableCause.MATERIALIZATION_FAILED),
            new Case("SQL NULL in a column declared not null", List.of(missing),
                MetadataQuery.sql("SELECT V").columnString("V", false).expectRows(0, 10).build(), UnusableCause.MATERIALIZATION_FAILED),
            new Case("SQL NULL in an integer column", List.of(missing),
                MetadataQuery.sql("SELECT V").columnInt("V").expectRows(0, 10).build(), UnusableCause.MATERIALIZATION_FAILED),
            new Case("no row where one is expected", List.of(),
                MetadataQuery.sql("SELECT V").columnString("V", true).expectRows(1, 1).build(), UnusableCause.CARDINALITY),
            new Case("two rows where one is expected", List.of(Map.of("V", "a"), Map.of("V", "b")),
                MetadataQuery.sql("SELECT V").columnString("V", true).expectRows(1, 1).build(), UnusableCause.CARDINALITY));
        for (Case one : cases) {
            FakeSource raw = new FakeSource(connection -> connection.rows = one.rows());
            MetadataLease lease = lease(source(raw));
            expectUnusable(violations, one.name(), lease.query(one.query()), one.expected());
            expect(violations, one.name() + ": restored once", 1, raw.only().count("restore(0)"));
            expect(violations, one.name() + ": the session is clean", LeaseState.USED, lease.state());
            lease.close();
            expect(violations, one.name() + ": returned", LeaseState.RETURNED, lease.state());
        }
        FakeSource unreadable = new FakeSource(connection -> connection.readFails = new InjectedSqlException("read"));
        MetadataLease lease = lease(source(unreadable));
        expectUnusable(violations, "a row the driver cannot fetch", lease.query(MetadataTestSupport.valueQuery()),
            UnusableCause.MATERIALIZATION_FAILED);
        expect(violations, "a row the driver cannot fetch: restored once", 1, unreadable.only().count("restore(0)"));
        lease.close();
        expect(violations, "a row the driver cannot fetch: returned", LeaseState.RETURNED, lease.state());
        Assertions.assertEquals(List.of(), violations, "ST-5");
    }

    /**
     * ST-6: a result or statement that cannot be closed contaminates the lease, which is then aborted, never closed first
     */
    @Test
    public void st6CloseFailureContaminatesAndAborts() {
        List<String> violations = new ArrayList<>();
        for (String part : List.of("result", "statement")) {
            FakeSource raw = new FakeSource(connection -> {
                if (part.equals("result")) {
                    connection.resultCloseFails = new InjectedSqlException("result close");
                } else {
                    connection.statementCloseFails = new InjectedSqlException("statement close");
                }
            });
            MetadataLease lease = lease(source(raw));
            expectUnusable(violations, part, lease.query(MetadataTestSupport.valueQuery()), UnusableCause.CLOSE_FAILED);
            expect(violations, part + ": state", LeaseState.CONTAMINATED, lease.state());
            lease.close();
            expect(violations, part + ": end", LeaseState.INVALIDATED, lease.state());
            expect(violations, part + ": the first thing done to the connection", "abort", firstOf(raw.only().calls(), "abort", "close"));
        }
        Assertions.assertEquals(List.of(), violations, "ST-6");
    }

    /**
     * ST-7: on the real metadata pool (H2 behind DBCP) the timeout is the session's, and is gone after the lease
     * <p>
     * A second statement on the same session reads the lease's timeout while the lease's statement runs -
     * which is why the restore exists - and after the lease the same physical connection, handed out
     * again by the pool, reads zero.
     */
    @Test
    public void st7H2SessionTimeoutIsRestoredOnTheSamePhysicalConnection() throws Exception {
        CBDatabase database = EmbeddedSecurityControllerFactory.getDbInstance();
        Assertions.assertNotNull(database, "FIXTURE ST-7: the server metadata database must exist");
        long[] session = {-1};
        int[] seenWhileRunning = {-1};
        MetadataConnectionSource raw = () -> {
            Connection connection = database.openConnection();
            session[0] = sessionId(connection);
            return observing(connection, seenWhileRunning);
        };
        MetadataLease lease = lease(leases.bounded(raw, BoundedMetadataConnections.Tuning.PRODUCTION));
        MetadataOutcome<MetadataRows> outcome = lease.query(
            MetadataQuery.sql("SELECT 1 AS V").columnInt("V").expectRows(1, 1).build());
        Assertions.assertEquals(1, done(outcome).row(0).integer("V"), "FIXTURE ST-7: the statement must run");
        Assertions.assertTrue(seenWhileRunning[0] >= 1,
            "ST-7: on H2 the lease's timeout must be the session's while its statement runs, another statement saw " + seenWhileRunning[0]);
        lease.close();
        Assertions.assertEquals(LeaseState.RETURNED, lease.state(), "ST-7: a restored session is returned to the pool");

        List<Connection> borrowed = new ArrayList<>();
        try {
            Connection same = null;
            for (int i = 0; i < 20 && same == null; i++) {
                Connection next = database.openConnection();
                borrowed.add(next);
                if (sessionId(next) == session[0]) {
                    same = next;
                }
            }
            Assertions.assertNotNull(same, "FIXTURE ST-7: the pool must hand the returned physical connection out again");
            try (Statement statement = same.createStatement()) {
                Assertions.assertEquals(0, statement.getQueryTimeout(),
                    "ST-7: the physical connection the lease returned must not keep its query timeout");
            }
        } finally {
            for (Connection connection : borrowed) {
                connection.close();
            }
        }
    }

    /**
     * ST-9: a restore that fails leaves no value and a contaminated lease, which is aborted and never closed normally
     */
    @Test
    public void st9RestoreFailureIsNeverReturnedToThePool() {
        FakeSource raw = new FakeSource(connection -> connection.restoreSetFails = new InjectedSqlException("restore"));
        BoundedMetadataConnections source = source(raw);
        MetadataLease lease = lease(source);

        assertUnusable(lease.query(MetadataTestSupport.valueQuery()), UnusableCause.RESTORE_FAILED, "ST-9");
        Assertions.assertEquals(LeaseState.CONTAMINATED, lease.state(), "ST-9: the lease must be contaminated");
        lease.close();
        FakeConnection connection = raw.only();
        Assertions.assertEquals(0, connection.count("close"), "ST-9: a contaminated connection must not be closed before an abort");
        Assertions.assertEquals(List.of("abort", "close-after-abort"), afterLast(connection.calls(), "restore.close"),
            "ST-9: abort, then close");
        Assertions.assertEquals(LeaseState.INVALIDATED, lease.state(), "ST-9: aborted and closed is invalidated");
        Assertions.assertEquals(BoundedMetadataConnections.CAPACITY, source.availableSlots(), "ST-9: the slot is free again");
    }

    /**
     * ST-10: an Error while the statement runs is rethrown as it is, after the cleanup, and contaminates the lease
     */
    @Test
    public void st10AnErrorContaminatesAndIsRethrown() {
        InjectedLeaseError injected = new InjectedLeaseError("execute");
        FakeSource raw = new FakeSource(connection -> connection.executeFails = injected);
        MetadataLease lease = lease(source(raw));

        Error thrown = Assertions.assertThrows(Error.class, () -> lease.query(MetadataTestSupport.valueQuery()),
            "ST-10: the Error must propagate");
        Assertions.assertSame(injected, thrown, "ST-10: the very Error must propagate");
        Assertions.assertEquals(LeaseState.CONTAMINATED, lease.state(), "ST-10: an Error leaves the session unknown");
        FakeConnection connection = raw.only();
        Assertions.assertEquals(1, connection.count("restore(0)"), "ST-10: the timeout is still put back");
        lease.close();
        Assertions.assertEquals(LeaseState.INVALIDATED, lease.state(), "ST-10: and the connection is aborted");
        Assertions.assertEquals("abort", firstOf(connection.calls(), "abort", "close"), "ST-10: abort first");
    }

    /**
     * ST-11: a connection not in auto-commit is refused before anything is prepared
     */
    @Test
    public void st11AConnectionOutsideAutoCommitIsRefused() {
        List<String> violations = new ArrayList<>();
        List<MetadataTestSupport.Script> scripts = List.of(
            connection -> connection.autoCommit = false,
            connection -> connection.autoCommitFails = new InjectedSqlException("getAutoCommit"));
        for (int i = 0; i < scripts.size(); i++) {
            String what = i == 0 ? "not in auto-commit" : "auto-commit unreadable";
            FakeSource raw = new FakeSource(scripts.get(i));
            MetadataLease lease = lease(source(raw));
            expectUnusable(violations, what, lease.query(MetadataTestSupport.valueQuery()), UnusableCause.STATEMENT_FAILED);
            expect(violations, what + ": nothing prepared", 0, raw.only().prepares.get());
            lease.close();
            expect(violations, what + ": returned untouched", LeaseState.RETURNED, lease.state());
        }
        Assertions.assertEquals(List.of(), violations, "ST-11");
    }

    /**
     * ST-14: the restore is three calls - a new statement, the timeout, its close - and any one failing is a failed restore
     */
    @Test
    public void st14EveryRestoreStepMustSucceed() {
        List<String> violations = new ArrayList<>();
        List<MetadataTestSupport.Script> scripts = List.of(
            connection -> connection.restoreCreateFails = new InjectedSqlException("restore statement"),
            connection -> connection.restoreSetFails = new InjectedSqlException("restore timeout"),
            connection -> connection.restoreCloseFails = new InjectedSqlException("restore close"));
        List<String> names = List.of("createStatement fails", "setQueryTimeout fails", "close fails");
        for (int i = 0; i < scripts.size(); i++) {
            String what = names.get(i);
            FakeSource raw = new FakeSource(scripts.get(i));
            MetadataLease lease = lease(source(raw));
            expectUnusable(violations, what, lease.query(MetadataTestSupport.valueQuery()), UnusableCause.RESTORE_FAILED);
            expect(violations, what + ": state", LeaseState.CONTAMINATED, lease.state());
            lease.close();
            expect(violations, what + ": end", LeaseState.INVALIDATED, lease.state());
            expect(violations, what + ": aborted before any close", "abort", firstOf(raw.only().calls(), "abort", "close"));
        }
        Assertions.assertEquals(List.of(), violations, "ST-14");
    }

    /**
     * ST-15: a timeout that cannot even be read sets nothing, runs nothing and restores nothing
     */
    @Test
    public void st15AnUnreadableTimeoutRunsNothing() {
        FakeSource raw = new FakeSource(connection -> connection.getTimeoutFails = new InjectedSqlException("getQueryTimeout"));
        MetadataLease lease = lease(source(raw));
        assertUnusable(lease.query(MetadataTestSupport.valueQuery()), UnusableCause.TIMEOUT_SETUP_FAILED, "ST-15");
        FakeConnection connection = raw.only();
        Assertions.assertEquals(List.of(0, 0, -1), List.of(connection.executes.get(), connection.count("createStatement"),
            indexOf(connection.calls(), "setQueryTimeout(")), "ST-15: no execution, no restore, no timeout set");
        Assertions.assertEquals(LeaseState.USED, lease.state(), "ST-15: the session was not touched");
        lease.close();
        Assertions.assertEquals(LeaseState.RETURNED, lease.state(), "ST-15: returned");
    }

    /**
     * ST-12: an update returns its count only when it is the declared one; bindings reach the driver as declared
     */
    @Test
    public void st12UpdateCountAndBindingsAreExact() {
        List<String> violations = new ArrayList<>();
        OffsetDateTime seoul = OffsetDateTime.of(2026, 10, 7, 9, 30, 0, 0, ZoneOffset.ofHours(9));
        MetadataUpdate update = MetadataUpdate.sql("UPDATE {table_prefix}T SET A=?, B=?, C=?, D=?")
            .bindString("text").bindString(null).bindTimestamp(seoul).bindTimestamp(null).expectUpdateCount(1).build();

        FakeSource exact = new FakeSource();
        MetadataLease one = lease(source(exact));
        expect(violations, "exact count", 1L, done(one.update(update)));
        one.close();
        List<String> binds = exact.only().calls().stream().filter(call -> call.startsWith("set") && !call.startsWith("setQuery")).toList();
        expect(violations, "bindings", List.of(
            "setString(1,String:text)",
            "setNull(2,Integer:" + java.sql.Types.VARCHAR + ")",
            "setObject(3,OffsetDateTime:" + seoul.withOffsetSameInstant(ZoneOffset.UTC) + ")",
            "setNull(4,Integer:" + java.sql.Types.TIMESTAMP_WITH_TIMEZONE + ")"), binds);

        FakeSource wrong = new FakeSource(connection -> connection.updateCount = 2);
        MetadataLease two = lease(source(wrong));
        expectUnusable(violations, "two rows updated where one is declared", two.update(update), UnusableCause.CARDINALITY);
        two.close();
        expect(violations, "a wrong count still restores", 1, wrong.only().count("restore(0)"));
        Assertions.assertEquals(List.of(), violations, "ST-12");
    }

    /**
     * ST-13: the builders refuse what a DBAC statement never means, and a row answers only what was declared
     */
    @Test
    public void st13BuildersAndRowsRefuseWhatWasNotDeclared() {
        List<String> violations = new ArrayList<>();
        refuses(violations, "a blank query", () -> MetadataQuery.sql(" "));
        refuses(violations, "a duplicated column", () -> MetadataQuery.sql("S").columnString("A", true).columnInt("A"));
        refuses(violations, "min above max", () -> MetadataQuery.sql("S").expectRows(2, 1));
        refuses(violations, "a negative min", () -> MetadataQuery.sql("S").expectRows(-1, 1));
        refuses(violations, "max above the ceiling", () -> MetadataQuery.sql("S").expectRows(0, MetadataQuery.MAX_ROWS + 1));
        refuses(violations, "no columns", () -> MetadataQuery.sql("S").expectRows(0, 1).build());
        refuses(violations, "no row count", () -> MetadataQuery.sql("S").columnInt("A").build());
        refuses(violations, "a blank update", () -> MetadataUpdate.sql(""));
        refuses(violations, "a negative update count", () -> MetadataUpdate.sql("U").expectUpdateCount(-1));
        refuses(violations, "no update count", () -> MetadataUpdate.sql("U").build());

        FakeSource raw = new FakeSource();
        MetadataLease lease = lease(source(raw));
        MetadataRow row = done(lease.query(MetadataTestSupport.valueQuery())).row(0);
        lease.close();
        refuses(violations, "an undeclared column", () -> row.string("W"));
        refuses(violations, "a declared column as another kind", () -> row.integer("V"));
        Assertions.assertEquals(List.of(), violations, "ST-13");
    }

    /**
     * ST-16: a budget clock that fails inside the template is a spent budget - before the statement nothing runs,
     * after it the value is discarded
     */
    @Test
    public void st16AFailingBudgetClockInsideTheTemplateIsASpentBudget() {
        List<String> violations = new ArrayList<>();
        java.util.concurrent.atomic.AtomicBoolean broken = new java.util.concurrent.atomic.AtomicBoolean();
        java.util.function.LongSupplier clock = () -> {
            if (broken.get()) {
                throw new IllegalStateException("budget clock failed");
            }
            return System.nanoTime();
        };

        FakeSource before = new FakeSource();
        MetadataLease early = MetadataTestSupport.open(source(before), MetadataBudget.startingNow(clock, MetadataTestSupport.LONG),
            CALL_LIMIT).get();
        broken.set(true);
        expectUnusable(violations, "clock fails before the statement", early.query(MetadataTestSupport.valueQuery()),
            UnusableCause.BUDGET_EXHAUSTED);
        expect(violations, "clock fails before the statement: nothing prepared", 0, before.only().prepares.get());
        early.close();

        broken.set(false);
        FakeSource during = new FakeSource(connection -> connection.onExecute = () -> broken.set(true));
        MetadataLease late = MetadataTestSupport.open(source(during), MetadataBudget.startingNow(clock, MetadataTestSupport.LONG),
            CALL_LIMIT).get();
        expectUnusable(violations, "clock fails during the statement", late.query(MetadataTestSupport.valueQuery()),
            UnusableCause.OVER_BUDGET);
        expect(violations, "clock fails during the statement: restored", 1, during.only().count("restore(0)"));
        late.close();
        expect(violations, "clock fails during the statement: returned", LeaseState.RETURNED, late.state());
        Assertions.assertEquals(List.of(), violations, "ST-16");
    }

    // ---------------------------------------------------------------- ML: the lease's shape and lifetime

    /**
     * ML-2: a second close does nothing: one disposal, one slot release
     */
    @Test
    public void ml2DoubleCloseIsANoOp() {
        FakeSource raw = new FakeSource();
        BoundedMetadataConnections source = source(raw);
        MetadataLease lease = lease(source);
        done(lease.query(MetadataTestSupport.valueQuery()));
        lease.close();
        lease.close();
        Assertions.assertEquals(1, raw.only().closes.get(), "ML-2: one close of the connection");
        Assertions.assertEquals(1, source.disposedAs(LeaseState.RETURNED), "ML-2: one disposal");
        Assertions.assertEquals(BoundedMetadataConnections.CAPACITY, source.availableSlots(), "ML-2: the slot released once");
        Assertions.assertEquals(LeaseState.RETURNED, lease.state(), "ML-2: the state does not change");
    }

    /**
     * ML-5: no JDBC type anywhere on the public or protected surface of the lease API, generics and nested types included
     */
    @Test
    public void ml5NoJdbcTypeIsReachableFromTheLeaseApi() {
        Set<Class<?>> forbidden = Set.of(
            java.sql.Wrapper.class, Connection.class, Statement.class, PreparedStatement.class, java.sql.CallableStatement.class,
            ResultSet.class, java.sql.DatabaseMetaData.class, java.sql.ResultSetMetaData.class, java.sql.ParameterMetaData.class,
            java.sql.Savepoint.class, java.sql.Blob.class, java.sql.Clob.class, java.sql.NClob.class, java.sql.Array.class,
            java.sql.Ref.class, java.sql.SQLXML.class, java.sql.RowId.class, java.sql.Struct.class, javax.sql.DataSource.class);
        Set<Class<?>> types = new LinkedHashSet<>();
        for (Class<?> root : List.<Class<?>>of(
            MetadataLease.class, MetadataLeaseSource.class, MetadataQuery.class, MetadataUpdate.class, MetadataRows.class,
            MetadataRow.class, MetadataOutcome.class, BoundedMetadataConnections.class, MetadataBudget.class,
            MetadataUnavailableException.class, LeaseState.class, UnusableCause.class, MetadataPurpose.class)) {
            collectPublicTypes(root, types);
        }
        List<String> violations = new ArrayList<>();
        for (Class<?> type : types) {
            for (Method method : type.getDeclaredMethods()) {
                if (visible(method.getModifiers()) && !method.isSynthetic()) {
                    String where = type.getName() + "." + method.getName();
                    check(violations, where + " returns", method.getGenericReturnType(), forbidden);
                    for (Type parameter : method.getGenericParameterTypes()) {
                        check(violations, where + " takes", parameter, forbidden);
                    }
                    for (Type thrown : method.getGenericExceptionTypes()) {
                        check(violations, where + " throws", thrown, forbidden);
                    }
                    for (TypeVariable<Method> variable : method.getTypeParameters()) {
                        for (Type bound : variable.getBounds()) {
                            check(violations, where + " bounds", bound, forbidden);
                        }
                    }
                }
            }
            for (Constructor<?> constructor : type.getDeclaredConstructors()) {
                if (visible(constructor.getModifiers())) {
                    for (Type parameter : constructor.getGenericParameterTypes()) {
                        check(violations, type.getName() + ".<init> takes", parameter, forbidden);
                    }
                }
            }
            for (Field field : type.getDeclaredFields()) {
                if (visible(field.getModifiers())) {
                    check(violations, type.getName() + "." + field.getName(), field.getGenericType(), forbidden);
                }
            }
            if (type.isRecord()) {
                for (RecordComponent component : type.getRecordComponents()) {
                    check(violations, type.getName() + " component " + component.getName(), component.getGenericType(), forbidden);
                }
            }
            for (Type parent : Stream.concat(Stream.of(type.getGenericSuperclass()), Stream.of(type.getGenericInterfaces())).toList()) {
                if (parent != null) {
                    check(violations, type.getName() + " extends", parent, forbidden);
                }
            }
        }
        System.out.println("[DBAC P5-1a] ML-5 checked " + types.size() + " public types: "
            + types.stream().map(Class::getSimpleName).toList());
        Assertions.assertTrue(types.size() >= 20, "FIXTURE ML-5: the scan must reach the nested public types, got " + types.size());
        Assertions.assertEquals(List.of(), violations, "ML-5: a JDBC type is reachable from the lease API");
    }

    /**
     * ML-6: a hundred ordinary leases leave every slot free and nothing held
     */
    @Test
    public void ml6AHundredLeasesLeaveNothingBehind() {
        FakeSource raw = new FakeSource();
        BoundedMetadataConnections source = source(raw);
        for (int i = 0; i < 100; i++) {
            try (MetadataLease lease = lease(source)) {
                done(lease.query(MetadataTestSupport.valueQuery()));
            }
        }
        Assertions.assertEquals(BoundedMetadataConnections.CAPACITY, source.availableSlots(), "ML-6: every slot free");
        Assertions.assertEquals(0, source.quarantined(), "ML-6: nothing quarantined");
        Assertions.assertEquals(0, source.residualHeld(), "ML-6: nothing kept");
        Assertions.assertEquals(100, source.disposedAs(LeaseState.RETURNED), "ML-6: a hundred returned");
        Assertions.assertEquals(100, raw.made.stream().filter(connection -> connection.closes.get() == 1).count(),
            "ML-6: every connection closed exactly once");
    }

    /**
     * ML-7: the only places DBAC production code sets a query timeout are the lease's two, setting and restoring
     */
    @Test
    public void ml7OnlyTheLeaseSetsAQueryTimeout() throws IOException {
        Path sources = MetadataShutdownTest.dbacSourceRoot();
        Map<String, Integer> found = new HashMap<>();
        try (Stream<Path> files = Files.walk(sources)) {
            for (Path file : files.filter(path -> path.toString().endsWith(".java")).toList()) {
                String text = Files.readString(file, StandardCharsets.UTF_8);
                int count = occurrences(text, "setQueryTimeout(");
                if (count > 0) {
                    found.put(file.getFileName().toString(), count);
                }
            }
        }
        Assertions.assertEquals(Map.of("MetadataLease.java", 2), found,
            "ML-7: setQueryTimeout may appear only in the lease template, once to set and once to restore");
    }

    // ---------------------------------------------------------------- LS: the state table

    /**
     * LS-1: every call in every state a caller can see
     */
    @Test
    public void ls1EveryCallInEveryStateDoesWhatTheTableSays() {
        leases.allowResidue();
        List<String> violations = new ArrayList<>();
        BoundedMetadataConnections source;

        FakeSource clean = new FakeSource();
        source = source(clean);
        MetadataLease used = lease(source);
        done(used.query(MetadataTestSupport.valueQuery()));
        expectUnusable(violations, "USED query", used.query(MetadataTestSupport.valueQuery()), UnusableCause.SECOND_STATEMENT);
        expectUnusable(violations, "USED update", used.update(oneRowUpdate()), UnusableCause.SECOND_STATEMENT);
        used.close();
        expect(violations, "USED close", LeaseState.RETURNED, used.state());
        noOpAfterTerminal(violations, used, clean.only());

        FakeSource restoreFails = new FakeSource(connection -> connection.restoreSetFails = new InjectedSqlException("restore"));
        MetadataLease contaminated = lease(source(restoreFails));
        contaminated.query(MetadataTestSupport.valueQuery());
        expect(violations, "CONTAMINATED", LeaseState.CONTAMINATED, contaminated.state());
        expectUnusable(violations, "CONTAMINATED query", contaminated.query(MetadataTestSupport.valueQuery()),
            UnusableCause.SECOND_STATEMENT);
        expect(violations, "CONTAMINATED query ran nothing", 1, restoreFails.only().executes.get());
        contaminated.close();
        expect(violations, "CONTAMINATED close", LeaseState.INVALIDATED, contaminated.state());
        noOpAfterTerminal(violations, contaminated, restoreFails.only());

        FakeSource abortFails = new FakeSource(connection -> {
            connection.restoreSetFails = new InjectedSqlException("restore");
            connection.abortFails = new InjectedSqlException("abort");
        });
        MetadataLease quarantined = lease(source(abortFails));
        quarantined.query(MetadataTestSupport.valueQuery());
        quarantined.close();
        expect(violations, "QUARANTINED", LeaseState.QUARANTINED, quarantined.state());
        noOpAfterTerminal(violations, quarantined, abortFails.only());

        FakeSource unused = new FakeSource();
        MetadataLease open = lease(source(unused));
        expect(violations, "OPEN", LeaseState.OPEN, open.state());
        open.close();
        expect(violations, "OPEN close", LeaseState.RETURNED, open.state());
        expect(violations, "OPEN close ran nothing", 0, unused.only().prepares.get());
        Assertions.assertEquals(List.of(), violations, "LS-1");
    }

    /**
     * LS-2: an Error from close and from abort - as an out-of-memory would throw - still leaves the connection held
     */
    @Test
    public void ls2ErrorsDuringDisposalNeverDropTheConnection() {
        leases.allowResidue();
        FakeSource raw = new FakeSource(connection -> {
            connection.closeFails = new OutOfMemoryError("injected close " + MetadataTestSupport.SECRET_MESSAGE);
            connection.abortFails = new OutOfMemoryError("injected abort " + MetadataTestSupport.SECRET_MESSAGE);
        });
        BoundedMetadataConnections source = source(raw);
        MetadataLease lease = lease(source);
        done(lease.query(MetadataTestSupport.valueQuery()));
        Assertions.assertDoesNotThrow(lease::close, "LS-2: close never throws");
        Assertions.assertEquals(LeaseState.QUARANTINED, lease.state(), "LS-2: the lease ends terminal, holding the connection");
        Assertions.assertEquals(1, source.quarantined(), "LS-2: one connection held in its slot");
        Assertions.assertEquals(BoundedMetadataConnections.CAPACITY - 1, source.availableSlots(), "LS-2: its slot is consumed");
    }

    // ---------------------------------------------------------------- helpers

    @NotNull
    private BoundedMetadataConnections source(@NotNull FakeSource raw) {
        return leases.bounded(raw, BoundedMetadataConnections.Tuning.PRODUCTION);
    }

    @NotNull
    private static MetadataLease lease(@NotNull MetadataLeaseSource source) {
        return MetadataTestSupport.open(source, MetadataTestSupport.budget(MetadataTestSupport.LONG), CALL_LIMIT).get();
    }

    @NotNull
    private static MetadataUpdate oneRowUpdate() {
        return MetadataUpdate.sql("UPDATE {table_prefix}T SET V=?").bindString("v").expectUpdateCount(1).build();
    }

    @NotNull
    private static <T> T done(@NotNull MetadataOutcome<T> outcome) {
        if (outcome instanceof MetadataOutcome.Done<T> done) {
            return done.value();
        }
        Assertions.fail("expected a value, got " + outcome);
        throw new IllegalStateException();
    }

    private static void assertUnusable(@NotNull MetadataOutcome<?> outcome, @NotNull UnusableCause expected, @NotNull String id) {
        Assertions.assertEquals(new MetadataOutcome.Unusable<>(expected), outcome, id + ": expected no value because of " + expected);
    }

    private static void expectUnusable(
        @NotNull List<String> violations,
        @NotNull String what,
        @NotNull MetadataOutcome<?> outcome,
        @NotNull UnusableCause expected
    ) {
        if (!new MetadataOutcome.Unusable<>(expected).equals(outcome)) {
            violations.add(what + ": expected Unusable(" + expected + "), got " + outcome);
        }
    }

    private static void expect(@NotNull List<String> violations, @NotNull String what, @Nullable Object expected, @Nullable Object actual) {
        if (!java.util.Objects.equals(expected, actual)) {
            violations.add(what + ": expected " + expected + ", got " + actual);
        }
    }

    /** Close and both statements do nothing once a lease has ended */
    private static void noOpAfterTerminal(
        @NotNull List<String> violations,
        @NotNull MetadataLease lease,
        @NotNull FakeConnection connection
    ) {
        final LeaseState before = lease.state();
        final int calls = connection.calls().size();
        lease.close();
        expectUnusable(violations, before + " query", lease.query(MetadataTestSupport.valueQuery()), UnusableCause.SECOND_STATEMENT);
        expectUnusable(violations, before + " update", lease.update(oneRowUpdate()), UnusableCause.SECOND_STATEMENT);
        expect(violations, before + " stays", before, lease.state());
        expect(violations, before + " touches nothing", calls, connection.calls().size());
    }

    private static void refuses(@NotNull List<String> violations, @NotNull String what, @NotNull Runnable call) {
        try {
            call.run();
            violations.add(what + " was accepted");
        } catch (IllegalArgumentException | IllegalStateException expected) {
            // refused
        }
    }

    private static int indexOf(@NotNull List<String> calls, @NotNull String prefix) {
        for (int i = 0; i < calls.size(); i++) {
            if (calls.get(i).startsWith(prefix)) {
                return i;
            }
        }
        return -1;
    }

    private static void assertOrder(@NotNull List<String> calls, @NotNull String... prefixes) {
        int last = -1;
        for (String prefix : prefixes) {
            int at = -1;
            for (int i = last + 1; i < calls.size(); i++) {
                if (calls.get(i).startsWith(prefix)) {
                    at = i;
                    break;
                }
            }
            Assertions.assertTrue(at > last, "ST-1: expected " + prefix + " after position " + last + " in " + calls);
            last = at;
        }
    }

    @NotNull
    private static List<String> tail(@NotNull List<String> calls, int from) {
        return calls.subList(from, calls.size());
    }

    @NotNull
    private static List<String> afterLast(@NotNull List<String> calls, @NotNull String marker) {
        return calls.subList(calls.lastIndexOf(marker) + 1, calls.size());
    }

    /** Which of the two calls came first; null when neither happened */
    @Nullable
    private static String firstOf(@NotNull List<String> calls, @NotNull String one, @NotNull String other) {
        for (String call : calls) {
            if (call.equals(one) || call.equals(other)) {
                return call;
            }
        }
        return null;
    }

    private static int occurrences(@NotNull String text, @NotNull String token) {
        int count = 0;
        for (int at = text.indexOf(token); at >= 0; at = text.indexOf(token, at + token.length())) {
            count++;
        }
        return count;
    }

    private static boolean visible(int modifiers) {
        return Modifier.isPublic(modifiers) || Modifier.isProtected(modifiers);
    }

    private static void collectPublicTypes(@NotNull Class<?> type, @NotNull Set<Class<?>> into) {
        if (!into.add(type)) {
            return;
        }
        for (Class<?> nested : type.getDeclaredClasses()) {
            if (visible(nested.getModifiers())) {
                collectPublicTypes(nested, into);
            }
        }
        if (type.isSealed()) {
            for (Class<?> permitted : type.getPermittedSubclasses()) {
                if (visible(permitted.getModifiers())) {
                    collectPublicTypes(permitted, into);
                }
            }
        }
    }

    private static void check(
        @NotNull List<String> violations,
        @NotNull String where,
        @NotNull Type type,
        @NotNull Set<Class<?>> forbidden
    ) {
        checkType(violations, where, type, forbidden, new java.util.HashSet<>());
    }

    private static void checkType(
        @NotNull List<String> violations,
        @NotNull String where,
        @NotNull Type type,
        @NotNull Set<Class<?>> forbidden,
        @NotNull Set<Type> seen
    ) {
        if (!seen.add(type)) {
            return;
        }
        if (type instanceof Class<?> raw) {
            Class<?> component = raw;
            while (component.isArray()) {
                component = component.getComponentType();
            }
            for (Class<?> jdbc : forbidden) {
                if (jdbc.isAssignableFrom(component)) {
                    violations.add(where + " " + component.getName());
                }
            }
        } else if (type instanceof ParameterizedType parameterized) {
            checkType(violations, where, parameterized.getRawType(), forbidden, seen);
            for (Type argument : parameterized.getActualTypeArguments()) {
                checkType(violations, where + " (argument)", argument, forbidden, seen);
            }
        } else if (type instanceof WildcardType wildcard) {
            for (Type bound : wildcard.getUpperBounds()) {
                checkType(violations, where + " (bound)", bound, forbidden, seen);
            }
            for (Type bound : wildcard.getLowerBounds()) {
                checkType(violations, where + " (bound)", bound, forbidden, seen);
            }
        } else if (type instanceof TypeVariable<?> variable) {
            for (Type bound : variable.getBounds()) {
                checkType(violations, where + " (bound)", bound, forbidden, seen);
            }
        } else if (type instanceof GenericArrayType array) {
            checkType(violations, where + " (array)", array.getGenericComponentType(), forbidden, seen);
        }
    }

    /** H2's id for the session behind a connection */
    static long sessionId(@NotNull Connection connection) throws java.sql.SQLException {
        try (Statement statement = connection.createStatement(); ResultSet result = statement.executeQuery("SELECT SESSION_ID()")) {
            Assertions.assertTrue(result.next(), "FIXTURE: SESSION_ID() must return a row");
            return result.getLong(1);
        }
    }

    /**
     * A real connection whose prepared statements, as they execute, read the timeout another statement of the same session sees
     */
    @NotNull
    private static Connection observing(@NotNull Connection delegate, @NotNull int[] seenWhileRunning) {
        return MetadataTestSupport.proxy(Connection.class, (self, method, args) -> {
            Object result = invoke(delegate, method, args);
            if (method.getName().equals("prepareStatement") && result instanceof PreparedStatement statement) {
                return MetadataTestSupport.proxy(PreparedStatement.class, (inner, innerMethod, innerArgs) -> {
                    if (innerMethod.getName().equals("executeQuery")) {
                        try (Statement other = delegate.createStatement()) {
                            seenWhileRunning[0] = other.getQueryTimeout();
                        }
                    }
                    return invoke(statement, innerMethod, innerArgs);
                });
            }
            return result;
        });
    }

    @Nullable
    private static Object invoke(@NotNull Object target, @NotNull Method method, @Nullable Object[] args) throws Throwable {
        try {
            return method.invoke(target, args);
        } catch (InvocationTargetException e) {
            throw e.getCause();
        }
    }

    /** Where the repository's sources are, found by walking up from the working directory */
    @NotNull
    static Path repositoryRoot() {
        File dir = new File(System.getProperty("user.dir")).getAbsoluteFile();
        for (int i = 0; i < 8 && dir != null; i++, dir = dir.getParentFile()) {
            if (new File(dir, "server/bundles/io.cloudbeaver.service.dbac/src").isDirectory()) {
                return dir.toPath();
            }
        }
        Assertions.fail("FIXTURE: the repository sources were not found above " + System.getProperty("user.dir"));
        throw new IllegalStateException();
    }
}
