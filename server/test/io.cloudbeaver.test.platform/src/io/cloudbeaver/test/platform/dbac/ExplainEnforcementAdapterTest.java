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
import io.cloudbeaver.service.dbac.PolicyServiceHolder;
import io.cloudbeaver.service.dbac.policy.BoundedMetadataConnections;
import io.cloudbeaver.service.dbac.policy.DbAccessKey;
import io.cloudbeaver.service.dbac.policy.DbAccessPolicyConfig;
import io.cloudbeaver.service.dbac.policy.DbOperationCategory;
import io.cloudbeaver.service.dbac.policy.DenialReason;
import io.cloudbeaver.service.dbac.policy.enforcement.EnforcementKeyLocks;
import io.cloudbeaver.service.dbac.policy.enforcement.TransactionTaintRegistry;
import io.cloudbeaver.service.dbac.tempwrite.MetadataConnectionSource;
import io.cloudbeaver.service.sql.DbacEnforcedExecution;
import io.cloudbeaver.service.sql.WebSQLExecutionPlan;
import io.cloudbeaver.test.platform.dbac.KeyLockTestSupport.Worker;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.jkiss.dbeaver.model.DBPExclusiveResource;
import org.jkiss.dbeaver.model.exec.DBCExecutionContext;
import org.jkiss.dbeaver.model.exec.DBCSession;
import org.jkiss.dbeaver.model.exec.DBCTransactionManager;
import org.jkiss.dbeaver.model.impl.jdbc.JDBCExecutionContext;
import org.jkiss.dbeaver.model.impl.jdbc.JDBCRemoteInstance;
import org.jkiss.dbeaver.model.runtime.DBRProgressMonitor;
import org.jkiss.dbeaver.model.runtime.LoggingProgressMonitor;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.lang.management.LockInfo;
import java.lang.management.ManagementFactory;
import java.lang.management.MonitorInfo;
import java.lang.management.ThreadInfo;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Predicate;
import java.util.stream.Stream;

/**
 * P6-B: what the Explain entry point does on the inside - its locks, its recovery, its audit, its context and connection
 * <p>
 * Every case drives {@code WebSQLProcessor.explainExecutionPlan()}, the production Explain entry point, except where a case
 * needs a context the server cannot make (one that is not JDBC): that one calls the adapter's package-private Explain
 * entry by reflection, as the processor calls it. What happens inside is seen without a test seam in production: the
 * instance's exclusive lock and the context's monitor from the platform's own state and the JVM's thread information, the
 * key locks from the registry's private state, the planner's statements through a proxy in the place of the context's JDBC
 * connection, the server backend from {@code pg_stat_activity}, the audit row through the metadata leases' raw connection
 * source - swapped through its private field and put back - and the order of calls from the bytecode. A statement that
 * draws from the fixture sequence counts every time it really runs, since no rollback gives a sequence value back.
 * Nothing is decided by how long something took.
 */
@Timeout(value = 600, unit = TimeUnit.SECONDS, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
public class ExplainEnforcementAdapterTest {

    private static final String ADAPTER = "io.cloudbeaver.service.sql.DbacEnforcedExecution";
    private static final String ADAPTER_CLASS = "io/cloudbeaver/service/sql/DbacEnforcedExecution";
    private static final String GATE = "io.cloudbeaver.service.dbac.policy.enforcement.EnforcementGate";
    private static final String PROCESSOR_CLASS = "io/cloudbeaver/service/sql/WebSQLProcessor";
    private static final long WAIT_SECONDS = 30;
    private static final Map<String, Object> ANALYZE = Map.of("ANALYZE", true);

    private static EnforcementTestSupport.Fixtures fixtures;
    private static final DBRProgressMonitor MONITOR = new LoggingProgressMonitor();

    private final List<AutoCloseable> closeAfter = new ArrayList<>();
    private final List<EnforcementTestSupport.Target> targets = new ArrayList<>();

    @BeforeAll
    public static void startServer() throws Exception {
        CEAppStarter.startServerIfNotStarted();
        fixtures = EnforcementTestSupport.fixtures("xea", MONITOR);
    }

    @AfterEach
    public void cleanUp() throws Exception {
        Collections.reverse(closeAfter);
        for (AutoCloseable one : closeAfter) {
            try {
                one.close();
            } catch (Exception e) {
                System.out.println("[DBAC P6-B] cleanup failed: " + e.getClass().getName());
            }
        }
        closeAfter.clear();
        letGoOfLeftLocks();
        targets.clear();
        fixtures.afterEach();
    }

    @AfterAll
    public static void deleteUsers() throws Exception {
        fixtures.afterAll();
    }

    // ---------------------------------------------------------------- XA-1: locks and the metadata database while waiting

    /**
     * XA-1: X, then M, then the grant key K, then the user U - with no metadata connection while waiting - and all four while planning
     * <p>
     * The case holds each in turn and catches the Explain waiting for it: waiting for X it holds nothing; waiting for M it
     * holds X; waiting for K it holds X and M; waiting for U it holds X, M and K. No metadata lease has been borrowed and
     * none is out while it waits. A slow plan - {@code EXPLAIN ANALYZE} of a statement that sleeps - is then caught inside
     * the planner with all four held. Afterwards all four are free.
     */
    @Test
    public void xa1LocksAreTakenXThenMThenKThenUWithNoMetadataWhileWaiting() throws Exception {
        List<String> violations = new ArrayList<>();
        for (String stage : List.of("X", "M", "K", "U")) {
            EnforcementTestSupport.Target target = readOnlyTarget(fixtures.user);
            final DbAccessKey key = accessKey(target);
            final String user = target.subject.userId();
            final JDBCExecutionContext context = target.context();
            try (Hold held = hold(stage, target, key, user)) {
                final long borrows = metadataBorrows();
                Worker<Object> explain = explainAsync(target, plainSelect(target), Map.of());
                Thread job = awaitAdapterThread(stage, thread -> switch (stage) {
                    case "X" -> stackHas(thread, "SimpleExclusiveLock", "acquireTaskLock");
                    case "M" -> blockedOn(thread, context);
                    default -> stackHas(thread, "ReentrantReadWriteLock$ReadLock", "tryLock");
                });
                if (job == null) {
                    violations.add("waiting for " + stage + ": the Explain must wait for it");
                } else {
                    expect(violations, "waiting for " + stage + ": X held by the Explain", !stage.equals("X"),
                        exclusiveOwner(target.instance()) == job);
                    expect(violations, "waiting for " + stage + ": M held by the Explain", stage.equals("K") || stage.equals("U"),
                        holdsMonitor(job, context));
                    expect(violations, "waiting for " + stage + ": K held by the Explain", stage.equals("U"),
                        readLocks(true, key.userId(), key) > 0);
                    expect(violations, "waiting for " + stage + ": U held by the Explain", false, readLocks(false, user, null) > 0);
                    expect(violations, "waiting for " + stage + ": metadata borrows since the call", borrows, metadataBorrows());
                    expect(violations, "waiting for " + stage + ": metadata leases out", BoundedMetadataConnections.CAPACITY,
                        leases().availableSlots());
                }
                held.close();
                explain.awaitDone();
            }
            expectAllFree(violations, "after waiting for " + stage, target, key, user);
        }

        EnforcementTestSupport.Target target = writableTarget(fixtures.user);
        final DbAccessKey key = accessKey(target);
        final String user = target.subject.userId();
        int backend = EnforcementTestSupport.backendPid(target.jdbc());
        Worker<Object> explain = explainAsync(target, "SELECT pg_sleep(" + EnforcementTestSupport.SLOW_COMMIT_SECONDS + ")", ANALYZE);
        Thread job = awaitAdapterThread("the planner", thread -> sleepingIn(backend));
        if (job == null) {
            violations.add("the slow plan must be seen inside the planner");
        } else {
            expect(violations, "inside the planner: X", true, exclusiveOwner(target.instance()) == job);
            expect(violations, "inside the planner: M", true, holdsMonitor(job, target.context()));
            expect(violations, "inside the planner: K", true, readLocks(true, key.userId(), key) > 0);
            expect(violations, "inside the planner: U", true, readLocks(false, user, null) > 0);
        }
        EnforcementTestSupport.Outcome outcome = outcomeOf(explain);
        expect(violations, "the slow plan succeeds", true, outcome.succeeded());
        expectAllFree(violations, "after the slow plan", target, key, user);
        Assertions.assertEquals(List.of(), violations, "XA-1");
    }

    // ---------------------------------------------------------------- XA-2 - XA-4: recovery

    /**
     * XA-2: a lost connection is recovered with nothing held, and the retry is authorized and audited afresh, on the new connection
     * <p>
     * The planner's first statement fails as a lost connection. The platform's recovery closes the connection and opens a
     * new one; at that close the grant key and the user are free and no frame of the adapter or the gate is on the job's
     * stack - the attempt has returned and given back X and M too. The retry plans on the new connection: two
     * {@code WRITE_ALLOWED} rows, one per attempt with an id of its own, and the statement ran exactly once.
     */
    @Test
    public void xa2ALostConnectionIsRecoveredWithNothingHeldAndTheRetryJudgedAfresh() throws Exception {
        List<String> violations = new ArrayList<>();
        EnforcementTestSupport.Target target = writableTarget(fixtures.user);
        JDBCExecutionContext context = target.context();
        ExplainSpy spy = ExplainSpy.install(context, accessKey(target), target.subject.userId());
        spy.loseConnectionOnce = true;
        final long sequence = EnforcementTestSupport.sequenceValue(target);
        final Set<String> allowed = auditIds(target, EnforcementTestSupport.EVENT_WRITE_ALLOWED);
        final int denied = audits(target, EnforcementTestSupport.EVENT_WRITE_DENIED);

        EnforcementTestSupport.Outcome outcome = EnforcementTestSupport.explain(target, analyzeUpdate(target), ANALYZE);

        expect(violations, "the Explain after recovery", true, outcome.succeeded());
        expect(violations, "statements the planner made on the lost connection", 1, spy.created.get());
        expect(violations, "the lost connection closed by the recovery", true, spy.closed.get() > 0);
        expect(violations, "at that close: grant key reads", 0, spy.atClose.get("grant"));
        expect(violations, "at that close: user reads", 0, spy.atClose.get("user"));
        expect(violations, "at that close: adapter or gate frames on the job's stack", 0, spy.atClose.get("frames"));
        expect(violations, "the context's connection after the recovery is a new one", true,
            context.getConnectionOrNull() != null && context.getConnectionOrNull() != spy.proxy);
        Set<String> now = auditIds(target, EnforcementTestSupport.EVENT_WRITE_ALLOWED);
        now.removeAll(allowed);
        expect(violations, "new WRITE_ALLOWED rows, each with its own id: one per attempt", 2, now.size());
        expect(violations, "WRITE_DENIED rows", denied, audits(target, EnforcementTestSupport.EVENT_WRITE_DENIED));
        expect(violations, "the statement's executions", sequence + 1, EnforcementTestSupport.sequenceValue(target));
        expect(violations, "committed", 0, target.committedValue());
        Assertions.assertEquals(List.of(), violations, "XA-2");
    }

    /**
     * XA-3: a revoke that comes between a lost connection and its retry is seen by the retry: refused, nothing planned
     * <p>
     * When the first attempt's planner fails as a lost connection, a revoke is already waiting for the grant key the
     * attempt holds. The key's fair lock lets the revoke in before the retry reads it; the retry is refused
     * {@code GRANT_REVOKED} and the statement never runs.
     */
    @Test
    public void xa3ARevokeBeforeTheRetryRefusesIt() throws Exception {
        List<String> violations = new ArrayList<>();
        EnforcementTestSupport.Target target = writableTarget(fixtures.user);
        ExplainSpy spy = ExplainSpy.install(target.context(), accessKey(target), target.subject.userId());
        final long sequence = EnforcementTestSupport.sequenceValue(target);
        final Set<String> allowed = auditIds(target, EnforcementTestSupport.EVENT_WRITE_ALLOWED);
        final int revokedRows = EnforcementTestSupport.countAudit(target.key(), EnforcementTestSupport.EVENT_WRITE_DENIED,
            DbOperationCategory.EXPLAIN, DenialReason.GRANT_REVOKED);
        AtomicReference<Worker<Object>> revoke = new AtomicReference<>();
        AtomicBoolean revokeWaited = new AtomicBoolean();
        spy.onLose = () -> {
            revoke.set(Worker.<Object>start("dbac-xea-revoke", () -> {
                EnforcementTestSupport.revoke(target.key());
                return null;
            }));
            revokeWaited.set(KeyLockTestSupport.awaitParked(revoke.get().thread));
        };
        spy.loseConnectionOnce = true;

        EnforcementTestSupport.Outcome outcome = EnforcementTestSupport.explain(target, analyzeUpdate(target), ANALYZE);

        expect(violations, "the revoke waited for the attempt's grant key", true, revokeWaited.get());
        expectRefused(violations, "the retry after the revoke", outcome, DenialReason.GRANT_REVOKED);
        expect(violations, "statements the planner made", 1, spy.created.get());
        expect(violations, "the statement's executions", sequence, EnforcementTestSupport.sequenceValue(target));
        Set<String> now = auditIds(target, EnforcementTestSupport.EVENT_WRITE_ALLOWED);
        now.removeAll(allowed);
        expect(violations, "new WRITE_ALLOWED rows: the first attempt only", 1, now.size());
        expect(violations, "WRITE_DENIED rows for the revoke", revokedRows + 1, EnforcementTestSupport.countAudit(target.key(),
            EnforcementTestSupport.EVENT_WRITE_DENIED, DbOperationCategory.EXPLAIN, DenialReason.GRANT_REVOKED));
        Worker<Object> revoker = revoke.get();
        Assertions.assertTrue(revoker != null && revoker.awaitDone() && revoker.error == null,
            "FIXTURE: the revoke must have run and finished");
        Assertions.assertEquals(List.of(), violations, "XA-3");
    }

    /**
     * XA-4: a refusal is neither recovered nor retried: one attempt, one denial row, the connection left as it was
     */
    @Test
    public void xa4ARefusalIsNotRecoveredOrRetried() throws Exception {
        List<String> violations = new ArrayList<>();
        EnforcementTestSupport.Target target = readOnlyTarget(fixtures.user);
        JDBCExecutionContext context = target.context();
        ExplainSpy spy = ExplainSpy.install(context, accessKey(target), target.subject.userId());
        final int denied = audits(target, EnforcementTestSupport.EVENT_WRITE_DENIED);

        EnforcementTestSupport.Outcome outcome = EnforcementTestSupport.explain(target, plainSelect(target), Map.of());

        expectRefused(violations, "the READ_ONLY Explain", outcome, DenialReason.NO_GRANT);
        expect(violations, "WRITE_DENIED rows: one attempt", denied + 1, audits(target, EnforcementTestSupport.EVENT_WRITE_DENIED));
        expect(violations, "connections closed by a recovery", 0, spy.closed.get());
        expect(violations, "the context keeps its connection", true, context.getConnectionOrNull() == spy.proxy);
        expect(violations, "statements the planner made", 0, spy.created.get());
        Assertions.assertEquals(List.of(), violations, "XA-4");
    }

    // ---------------------------------------------------------------- XA-5, XA-6: contexts and generations

    /**
     * XA-5: a generation that changes before the planner is called is refused, with a correction row, and nothing is planned
     */
    @Test
    public void xa5AGenerationChangedBeforeThePlannerRefuses() throws Exception {
        List<String> violations = new ArrayList<>();
        EnforcementTestSupport.Target target = writableTarget(fixtures.user);
        DbAccessKey key = accessKey(target);
        JDBCExecutionContext context = target.context();
        Connection other = EnforcementTestSupport.openRawPostgres(MONITOR);
        closeAfter.add(other);
        final long sequence = EnforcementTestSupport.sequenceValue(target);
        final int allowed = audits(target, EnforcementTestSupport.EVENT_WRITE_ALLOWED);
        final int stale = EnforcementTestSupport.countAudit(target.key(), EnforcementTestSupport.EVENT_WRITE_DENIED,
            DbOperationCategory.EXPLAIN, DenialReason.GRANT_STALE);
        Worker<Object> explain;
        try (Hold held = Hold.grantWrite(key)) {
            explain = explainAsync(target, analyzeUpdate(target), ANALYZE);
            if (awaitAdapterThread("K", thread -> stackHas(thread, "ReentrantReadWriteLock$ReadLock", "tryLock")) == null) {
                violations.add("the Explain must wait for the grant key");
            }
            swapConnection(context, other);
        }
        expectRefused(violations, "the Explain whose generation changed", outcomeOf(explain), DenialReason.GRANT_STALE);
        expect(violations, "the statement's executions", sequence, EnforcementTestSupport.sequenceValue(target));
        expect(violations, "WRITE_ALLOWED rows", allowed + 1, audits(target, EnforcementTestSupport.EVENT_WRITE_ALLOWED));
        expect(violations, "WRITE_DENIED rows: the correction", stale + 1, EnforcementTestSupport.countAudit(target.key(),
            EnforcementTestSupport.EVENT_WRITE_DENIED, DbOperationCategory.EXPLAIN, DenialReason.GRANT_STALE));
        Assertions.assertEquals(List.of(), violations, "XA-5");
    }

    /**
     * XA-6: a context that is not JDBC, no context at all and a context without a connection are refused, and nothing is planned
     */
    @Test
    public void xa6NoJdbcContextNoContextAndNoGenerationAreRefused() throws Exception {
        List<String> violations = new ArrayList<>();
        AtomicInteger planned = new AtomicInteger();
        FakeContext fake = new FakeContext();
        expectRefusal(violations, "an Explain on a context that is not JDBC",
            () -> explainDirectly(source(fake.context, "dbac-xea-nobody"), planned), DenialReason.ENDPOINT_UNSUPPORTED);
        expectRefusal(violations, "an Explain with no context", () -> explainDirectly(source(null, "dbac-xea-nobody"), planned),
            DenialReason.CONNECTION_UNKNOWN);
        expect(violations, "plans made for them", 0, planned.get());
        expect(violations, "calls on the context that is not JDBC", List.of(), fake.calls);

        EnforcementTestSupport.Target target = writableTarget(fixtures.user);
        JDBCExecutionContext context = target.context();
        final long sequence = EnforcementTestSupport.sequenceValue(target);
        Connection real = context.getConnectionOrNull();
        setConnection(context, null);
        try {
            expectRefused(violations, "an Explain on a context without a connection",
                EnforcementTestSupport.explain(target, analyzeUpdate(target), ANALYZE), DenialReason.CONNECTION_UNKNOWN);
            expect(violations, "a connection opened by the refusal", true, context.getConnectionOrNull() == null);
        } finally {
            setConnection(context, real);
        }
        expect(violations, "the statement's executions", sequence, EnforcementTestSupport.sequenceValue(target));
        Assertions.assertEquals(List.of(), violations, "XA-6");
    }

    // ---------------------------------------------------------------- XA-7 - XA-9: the policy

    /**
     * XA-7: every Explain by a READ_ONLY user is refused before the planner - plain, with no configuration, with ANALYZE on or off
     */
    @Test
    public void xa7EveryReadOnlyExplainIsRefusedBeforeThePlanner() throws Exception {
        final List<String> violations = new ArrayList<>();
        EnforcementTestSupport.Target target = readOnlyTarget(fixtures.user);
        final ExplainSpy spy = ExplainSpy.install(target.context(), accessKey(target), target.subject.userId());
        final long sequence = EnforcementTestSupport.sequenceValue(target);
        final int denied = audits(target, EnforcementTestSupport.EVENT_WRITE_DENIED);
        Map<String, Map<String, Object>> cases = new LinkedHashMap<>();
        cases.put("plain, no configuration", Map.of());
        cases.put("ANALYZE on", ANALYZE);
        cases.put("ANALYZE off", Map.of("ANALYZE", false));
        cases.put("VERBOSE", Map.of("VERBOSE", true));
        for (Map.Entry<String, Map<String, Object>> one : cases.entrySet()) {
            String sql = Boolean.TRUE.equals(one.getValue().get("ANALYZE")) ? analyzeUpdate(target) : plainSelect(target);
            expectRefused(violations, one.getKey(), EnforcementTestSupport.explain(target, sql, one.getValue()), DenialReason.NO_GRANT);
        }
        expect(violations, "statements the planner made", 0, spy.created.get());
        expect(violations, "the statement's executions", sequence, EnforcementTestSupport.sequenceValue(target));
        expect(violations, "WRITE_DENIED rows: one per Explain", denied + cases.size(),
            audits(target, EnforcementTestSupport.EVENT_WRITE_DENIED));
        Assertions.assertEquals(List.of(), violations, "XA-7");
    }

    /**
     * XA-8: an Explain under a live grant plans exactly once, with one allowed row and no denial
     */
    @Test
    public void xa8AnExplainUnderALiveGrantPlansExactlyOnce() throws Exception {
        List<String> violations = new ArrayList<>();
        EnforcementTestSupport.Target target = writableTarget(fixtures.user);
        final ExplainSpy spy = ExplainSpy.install(target.context(), accessKey(target), target.subject.userId());
        final long sequence = EnforcementTestSupport.sequenceValue(target);
        final int allowed = audits(target, EnforcementTestSupport.EVENT_WRITE_ALLOWED);
        final int denied = audits(target, EnforcementTestSupport.EVENT_WRITE_DENIED);

        EnforcementTestSupport.Outcome outcome = EnforcementTestSupport.explain(target, analyzeUpdate(target), ANALYZE);

        expect(violations, "the Explain", true, outcome.succeeded());
        expect(violations, "its plan", true, outcome.result() instanceof WebSQLExecutionPlan);
        expect(violations, "statements the planner made", 1, spy.created.get());
        expect(violations, "the statement's executions", sequence + 1, EnforcementTestSupport.sequenceValue(target));
        expect(violations, "WRITE_ALLOWED rows", allowed + 1, audits(target, EnforcementTestSupport.EVENT_WRITE_ALLOWED));
        expect(violations, "WRITE_DENIED rows", denied, audits(target, EnforcementTestSupport.EVENT_WRITE_DENIED));
        Assertions.assertEquals(List.of(), violations, "XA-8");
    }

    /**
     * XA-9: an expired grant, a revoked grant and an inactive user are refused before the planner
     */
    @Test
    public void xa9ExpiredRevokedAndInactiveAreRefusedBeforeThePlanner() throws Exception {
        List<String> violations = new ArrayList<>();
        EnforcementTestSupport.Target expired = writableTarget(fixtures.user);
        EnforcementTestSupport.setExpiresAt(expired.key(), EnforcementTestSupport.metadataNow().minusMinutes(1));
        expectRefusedUnplanned(violations, "an expired grant", expired, DenialReason.GRANT_EXPIRED);

        EnforcementTestSupport.Target revoked = writableTarget(fixtures.user);
        EnforcementTestSupport.revoke(revoked.key());
        expectRefusedUnplanned(violations, "a revoked grant", revoked, DenialReason.GRANT_REVOKED);

        EnforcementTestSupport.Subject user = fixtures.newUser();
        EnforcementTestSupport.Target inactive = writableTarget(user);
        fixtures.admin.client().sendQuery(EnforcementTestSupport.GQL_ENABLE_USER, Map.of("userId", user.userId(), "enabled", false));
        expectRefusedUnplanned(violations, "an inactive user", inactive, DenialReason.USER_INACTIVE);
        Assertions.assertEquals(List.of(), violations, "XA-9");
    }

    // ---------------------------------------------------------------- XA-10 - XA-12: the audit and the final checks

    /**
     * XA-10: an allowed row that cannot be written refuses the Explain before the planner, and the correction is written
     */
    @Test
    public void xa10AnAuditThatFailsRefusesBeforeThePlanner() throws Exception {
        final List<String> violations = new ArrayList<>();
        EnforcementTestSupport.Target target = writableTarget(fixtures.user);
        final ExplainSpy spy = ExplainSpy.install(target.context(), accessKey(target), target.subject.userId());
        MetadataTap tap = MetadataTap.install();
        closeAfter.add(tap);
        final long sequence = EnforcementTestSupport.sequenceValue(target);
        final int allowed = audits(target, EnforcementTestSupport.EVENT_WRITE_ALLOWED);
        final int failed = EnforcementTestSupport.countAudit(target.key(), EnforcementTestSupport.EVENT_WRITE_DENIED,
            DbOperationCategory.EXPLAIN, DenialReason.AUDIT_WRITE_FAILED);
        tap.failNextAuditInsert = true;

        EnforcementTestSupport.Outcome outcome = EnforcementTestSupport.explain(target, analyzeUpdate(target), ANALYZE);

        expect(violations, "the allowed row's insert was attempted and failed", false, tap.failNextAuditInsert);
        expectRefused(violations, "the Explain whose allowed row failed", outcome, DenialReason.AUDIT_WRITE_FAILED);
        expect(violations, "statements the planner made", 0, spy.created.get());
        expect(violations, "the statement's executions", sequence, EnforcementTestSupport.sequenceValue(target));
        expect(violations, "WRITE_ALLOWED rows", allowed, audits(target, EnforcementTestSupport.EVENT_WRITE_ALLOWED));
        expect(violations, "WRITE_DENIED rows: the correction", failed + 1, EnforcementTestSupport.countAudit(target.key(),
            EnforcementTestSupport.EVENT_WRITE_DENIED, DbOperationCategory.EXPLAIN, DenialReason.AUDIT_WRITE_FAILED));
        Assertions.assertEquals(List.of(), violations, "XA-10");
    }

    /**
     * XA-11: check-2 refuses an Explain whose grant ran into the margin after its allowed row, before the planner, with a correction
     * <p>
     * The grant has a few seconds more than check-1 needs. Once the allowed row is in, its lease's connection is held at its
     * close - after the row, before check-2 - until the database clock is within the margin of the expiry. Check-2 then
     * refuses {@code GRANT_EXPIRED}.
     */
    @Test
    public void xa11CheckTwoRefusesBeforeThePlanner() throws Exception {
        final List<String> violations = new ArrayList<>();
        EnforcementTestSupport.Target target = writableTarget(fixtures.user);
        final ExplainSpy spy = ExplainSpy.install(target.context(), accessKey(target), target.subject.userId());
        MetadataTap tap = MetadataTap.install();
        closeAfter.add(tap);
        final long sequence = EnforcementTestSupport.sequenceValue(target);
        final int allowed = audits(target, EnforcementTestSupport.EVENT_WRITE_ALLOWED);
        final int expired = EnforcementTestSupport.countAudit(target.key(), EnforcementTestSupport.EVENT_WRITE_DENIED,
            DbOperationCategory.EXPLAIN, DenialReason.GRANT_EXPIRED);
        Duration margin = policyConfig().expiryGuardMargin();
        OffsetDateTime expiresAt = EnforcementTestSupport.metadataNow().plusSeconds(6);
        EnforcementTestSupport.setExpiresAt(target.key(), expiresAt);
        AtomicBoolean held = new AtomicBoolean();
        tap.onAuditClose = () -> {
            held.set(true);
            awaitDatabaseTime(expiresAt.minus(margin).plusNanos(TimeUnit.MILLISECONDS.toNanos(300)));
        };

        EnforcementTestSupport.Outcome outcome = EnforcementTestSupport.explain(target, analyzeUpdate(target), ANALYZE);

        expect(violations, "the allowed row's lease held at its close", true, held.get());
        expectRefused(violations, "the Explain refused by check-2", outcome, DenialReason.GRANT_EXPIRED);
        expect(violations, "statements the planner made", 0, spy.created.get());
        expect(violations, "the statement's executions", sequence, EnforcementTestSupport.sequenceValue(target));
        expect(violations, "WRITE_ALLOWED rows", allowed + 1, audits(target, EnforcementTestSupport.EVENT_WRITE_ALLOWED));
        expect(violations, "WRITE_DENIED rows: the correction", expired + 1, EnforcementTestSupport.countAudit(target.key(),
            EnforcementTestSupport.EVENT_WRITE_DENIED, DbOperationCategory.EXPLAIN, DenialReason.GRANT_EXPIRED));
        Assertions.assertEquals(List.of(), violations, "XA-11");
    }

    /**
     * XA-12: a policy service that is not ready - before the call, or turned so after the allowed row - refuses before the planner
     * <p>
     * Not ready before the call: the attempt knows no key, so nothing is audited, but the transaction the context has open
     * is still rolled back. Turned not ready after the allowed row: the final confirmation refuses, with a correction row.
     */
    @Test
    public void xa12APolicyServiceThatIsNotReadyRefusesBeforeThePlanner() throws Exception {
        List<String> violations = new ArrayList<>();
        EnforcementTestSupport.Target before = writableTarget(fixtures.user);
        EnforcementTestSupport.openTransaction(before, 86);
        final ExplainSpy spy = ExplainSpy.install(before.context(), accessKey(before), before.subject.userId());
        final int allowedBefore = audits(before, EnforcementTestSupport.EVENT_WRITE_ALLOWED);
        final int deniedBefore = audits(before, EnforcementTestSupport.EVENT_WRITE_DENIED);
        EnforcementTestSupport.Outcome outcome;
        try (HolderDown ignored = HolderDown.to("Failed")) {
            outcome = EnforcementTestSupport.explain(before, plainSelect(before), Map.of());
        }
        expectRefused(violations, "not ready before the call", outcome, DenialReason.PERMISSION_STORE_UNAVAILABLE);
        expect(violations, "not ready before the call: audit rows", allowedBefore + deniedBefore,
            audits(before, EnforcementTestSupport.EVENT_WRITE_ALLOWED) + audits(before, EnforcementTestSupport.EVENT_WRITE_DENIED));
        expect(violations, "not ready before the call: the open transaction rolled back", 1, spy.rollbacks.get());
        expect(violations, "not ready before the call: the registry's state", TransactionTaintRegistry.State.CLEAN,
            stateOf(before.context()));
        expect(violations, "not ready before the call: statements the planner made", 0, spy.created.get());
        expect(violations, "not ready before the call: committed", 0, before.committedValue());

        EnforcementTestSupport.Target after = writableTarget(fixtures.user);
        final ExplainSpy afterSpy = ExplainSpy.install(after.context(), accessKey(after), after.subject.userId());
        MetadataTap tap = MetadataTap.install();
        closeAfter.add(tap);
        final long sequence = EnforcementTestSupport.sequenceValue(after);
        final int allowed = audits(after, EnforcementTestSupport.EVENT_WRITE_ALLOWED);
        final int unavailable = EnforcementTestSupport.countAudit(after.key(), EnforcementTestSupport.EVENT_WRITE_DENIED,
            DbOperationCategory.EXPLAIN, DenialReason.PERMISSION_STORE_UNAVAILABLE);
        AtomicReference<HolderDown> down = new AtomicReference<>();
        tap.onAuditClose = () -> down.set(HolderDown.to("Failed"));
        try {
            outcome = EnforcementTestSupport.explain(after, analyzeUpdate(after), ANALYZE);
        } finally {
            if (down.get() != null) {
                down.get().close();
            }
        }
        expect(violations, "turned not ready after the allowed row", true, down.get() != null);
        expectRefused(violations, "not ready after the allowed row", outcome, DenialReason.PERMISSION_STORE_UNAVAILABLE);
        expect(violations, "not ready after the allowed row: statements the planner made", 0, afterSpy.created.get());
        expect(violations, "not ready after the allowed row: the statement's executions", sequence,
            EnforcementTestSupport.sequenceValue(after));
        expect(violations, "not ready after the allowed row: WRITE_ALLOWED rows", allowed + 1,
            audits(after, EnforcementTestSupport.EVENT_WRITE_ALLOWED));
        expect(violations, "not ready after the allowed row: the correction", unavailable + 1, EnforcementTestSupport.countAudit(
            after.key(), EnforcementTestSupport.EVENT_WRITE_DENIED, DbOperationCategory.EXPLAIN,
            DenialReason.PERMISSION_STORE_UNAVAILABLE));
        Assertions.assertEquals(List.of(), violations, "XA-12");
    }

    // ---------------------------------------------------------------- XA-13, XA-14: the transaction and the generation afterwards

    /**
     * XA-13: a refused Explain rolls the open transaction back before its denial row, and the registry knows the real context
     * <p>
     * A rollback that works leaves the context clean, and the denial row is written only after it. A rollback that fails
     * severs and blocks the context - known by the platform's context id and the context object itself.
     */
    @Test
    public void xa13ARefusalRollsBackFirstAndTheRegistryKnowsTheRealContext() throws Exception {
        final List<String> violations = new ArrayList<>();
        EnforcementTestSupport.Target target = readOnlyTarget(fixtures.user);
        EnforcementTestSupport.openTransaction(target, 87);
        ExplainSpy spy = ExplainSpy.install(target.context(), accessKey(target), target.subject.userId());
        MetadataTap tap = MetadataTap.install();
        closeAfter.add(tap);
        AtomicInteger rollbacksAtDenial = new AtomicInteger(-1);
        tap.onAuditInsert = () -> rollbacksAtDenial.compareAndSet(-1, spy.rollbacks.get());
        expectRefused(violations, "the READ_ONLY Explain", EnforcementTestSupport.explain(target, plainSelect(target), Map.of()),
            DenialReason.NO_GRANT);
        expect(violations, "rollbacks done when the denial row was written", 1, rollbacksAtDenial.get());
        expect(violations, "the registry's state after a rollback that worked", TransactionTaintRegistry.State.CLEAN,
            stateOf(target.context()));
        expect(violations, "committed", 0, target.committedValue());

        EnforcementTestSupport.Target failing = readOnlyTarget(fixtures.user);
        EnforcementTestSupport.openTransaction(failing, 88);
        JDBCExecutionContext context = failing.context();
        ExplainSpy failingSpy = ExplainSpy.install(context, accessKey(failing), failing.subject.userId());
        failingSpy.rollbackFails = true;
        expectRefused(violations, "the READ_ONLY Explain whose rollback fails",
            EnforcementTestSupport.explain(failing, plainSelect(failing), Map.of()), DenialReason.NO_GRANT);
        expect(violations, "the registry's state for the context", TransactionTaintRegistry.State.BLOCKED, stateOf(context));
        try {
            TransactionTaintRegistry.global().state(context.getContextId(), new Object());
            violations.add("another object under the context's id must be refused by the registry");
        } catch (IllegalStateException expected) {
            // the identity is the context object itself
        }
        expect(violations, "the connection aborted", 1, failingSpy.aborts.get());
        expect(violations, "the context severed", true, context.getConnectionOrNull() == null);
        expectSeveredAndNothingCommitted(violations, failing.schema, failingSpy.backend);
        Assertions.assertEquals(List.of(), violations, "XA-13");
    }

    /**
     * XA-14: a generation that changes while the planner runs is not reported a success - the context is blocked, no correction written
     */
    @Test
    public void xa14AGenerationChangedByThePlanIsNotASuccess() throws Exception {
        List<String> violations = new ArrayList<>();
        EnforcementTestSupport.Target target = writableTarget(fixtures.user);
        JDBCExecutionContext context = target.context();
        int backend = EnforcementTestSupport.backendPid(target.jdbc());
        Connection other = EnforcementTestSupport.openRawPostgres(MONITOR);
        closeAfter.add(other);
        final int allowed = audits(target, EnforcementTestSupport.EVENT_WRITE_ALLOWED);
        final int denied = audits(target, EnforcementTestSupport.EVENT_WRITE_DENIED);
        Worker<Object> explain = explainAsync(target, "SELECT pg_sleep(" + EnforcementTestSupport.SLOW_COMMIT_SECONDS + ")", ANALYZE);
        if (awaitAdapterThread("the planner", thread -> sleepingIn(backend)) == null) {
            violations.add("the slow plan must be seen inside the planner");
        }
        swapConnection(context, other);
        EnforcementTestSupport.Outcome outcome = outcomeOf(explain);
        expectRefused(violations, "the Explain whose generation changed under it", outcome, DenialReason.CONNECTION_BLOCKED);
        expect(violations, "its result", null, outcome.result());
        expect(violations, "the registry's state", TransactionTaintRegistry.State.BLOCKED, stateOf(context));
        expect(violations, "WRITE_ALLOWED rows", allowed + 1, audits(target, EnforcementTestSupport.EVENT_WRITE_ALLOWED));
        expect(violations, "WRITE_DENIED rows: none after the planner", denied, audits(target, EnforcementTestSupport.EVENT_WRITE_DENIED));
        Assertions.assertEquals(List.of(), violations, "XA-14");
    }

    // ---------------------------------------------------------------- XA-15: no strict real-time guarantee (EX-3)

    /**
     * XA-15 (EX-3): what check-2 allowed is planned even when the grant expires before the planner runs - a known limit
     * <p>
     * Pinned on purpose, not a defect. The grant has a few seconds more than check-1 needs; once check-2 has allowed, the
     * planner's first statement is held - inside the platform call - until the database clock is past the expiry, and
     * then let go. The plan is made: the margin is a conservative margin, not a real-time bound, and nothing checks the
     * clock again after check-2.
     */
    @Test
    public void xa15WhatCheckTwoAllowedIsPlannedEvenPastTheExpiry() throws Exception {
        final List<String> violations = new ArrayList<>();
        EnforcementTestSupport.Target target = writableTarget(fixtures.user);
        ExplainSpy spy = ExplainSpy.install(target.context(), accessKey(target), target.subject.userId());
        final long sequence = EnforcementTestSupport.sequenceValue(target);
        final int allowed = audits(target, EnforcementTestSupport.EVENT_WRITE_ALLOWED);
        final int denied = audits(target, EnforcementTestSupport.EVENT_WRITE_DENIED);
        OffsetDateTime expiresAt = EnforcementTestSupport.metadataNow().plusSeconds(6);
        EnforcementTestSupport.setExpiresAt(target.key(), expiresAt);
        CountDownLatch release = new CountDownLatch(1);
        spy.pause = release;
        final Worker<Object> explain = explainAsync(target, analyzeUpdate(target), ANALYZE);
        boolean reached = spy.reached.await(WAIT_SECONDS, TimeUnit.SECONDS);
        expect(violations, "the planner reached once check-2 allowed", true, reached);
        awaitDatabaseTime(expiresAt.plusNanos(TimeUnit.MILLISECONDS.toNanos(200)));
        OffsetDateTime releasedAt = EnforcementTestSupport.metadataNow();
        release.countDown();
        EnforcementTestSupport.Outcome outcome = outcomeOf(explain);
        expect(violations, "the planner let go after the expiry", true, releasedAt.isAfter(expiresAt));
        expect(violations, "the plan, made past the expiry", true, outcome.succeeded());
        expect(violations, "the statement's executions", sequence + 1, EnforcementTestSupport.sequenceValue(target));
        expect(violations, "WRITE_ALLOWED rows", allowed + 1, audits(target, EnforcementTestSupport.EVENT_WRITE_ALLOWED));
        expect(violations, "WRITE_DENIED rows", denied, audits(target, EnforcementTestSupport.EVENT_WRITE_DENIED));
        Assertions.assertEquals(List.of(), violations, "XA-15");
    }

    // ---------------------------------------------------------------- XA-16: the log

    /**
     * XA-16: what DBAC logs for a refusal, a failed rollback and a failed postcondition carries no SQL, configuration, URL,
     * credential, driver message or stack trace - only a fixed event code and a new event id
     */
    @Test
    public void xa16TheLogCarriesNothingOfTheStatementOrTheConnection() throws Throwable {
        final List<String> violations = new ArrayList<>();
        String sqlMarker = "dbac_xea_sql_marker_5f1d";
        String configMarker = "DBAC_XEA_CFG_MARKER_9c3a";
        // Anywhere in the log: what the request or the connection carried. In DBAC's own lines: a driver's message too
        final List<String> forbidden = List.of(sqlMarker, configMarker, EnforcementTestSupport.PG_PASSWORD,
            EnforcementTestSupport.PG_URL);
        List<String> forbiddenInDbacLines = new ArrayList<>(forbidden);
        forbiddenInDbacLines.add("injected:");

        EnforcementTestSupport.Target target = readOnlyTarget(fixtures.user);
        EnforcementTestSupport.openTransaction(target, 89);
        ExplainSpy spy = ExplainSpy.install(target.context(), accessKey(target), target.subject.userId());
        spy.rollbackFails = true;
        AtomicReference<EnforcementTestSupport.Outcome> refused = new AtomicReference<>();
        LifecycleTestSupport.Captured captured = LifecycleTestSupport.captureLogs(() -> refused.set(EnforcementTestSupport.explain(
            target, "SELECT id /* " + sqlMarker + " */ FROM " + target.table(), Map.of(configMarker, true))));
        expectRefused(violations, "the READ_ONLY Explain whose rollback fails", refused.get(), DenialReason.NO_GRANT);
        expectLogged(violations, "the failed rollback", captured, "event=DBAC_ROLLBACK_FAILED");
        violations.addAll(dbacLogViolations(captured, forbiddenInDbacLines));
        for (String fragment : forbidden) {
            if (captured.text().contains(fragment)) {
                violations.add("the log contains '" + fragment + "'");
            }
        }

        EnforcementTestSupport.Target changed = writableTarget(fixtures.user);
        JDBCExecutionContext context = changed.context();
        int backend = EnforcementTestSupport.backendPid(changed.jdbc());
        Connection other = EnforcementTestSupport.openRawPostgres(MONITOR);
        closeAfter.add(other);
        Worker<Object> swapper = Worker.<Object>start("dbac-xea-swapper", () -> {
            if (awaitAdapterThread("the planner", thread -> sleepingIn(backend)) != null) {
                swapConnection(context, other);
            }
            return null;
        });
        AtomicReference<EnforcementTestSupport.Outcome> blocked = new AtomicReference<>();
        LifecycleTestSupport.Captured postcondition = LifecycleTestSupport.captureLogs(() -> blocked.set(EnforcementTestSupport.explain(
            changed, "SELECT pg_sleep(" + EnforcementTestSupport.SLOW_COMMIT_SECONDS + ") /* " + sqlMarker + " */", ANALYZE)));
        Assertions.assertTrue(swapper.awaitDone() && swapper.error == null, "FIXTURE: the connection must have been swapped");
        expectRefused(violations, "the Explain whose generation changed", blocked.get(), DenialReason.CONNECTION_BLOCKED);
        expectLogged(violations, "the failed postcondition", postcondition,
            "event=DBAC_POSTCONDITION_FAILED", "detail=EXPLAIN_GENERATION_CHANGED");
        violations.addAll(dbacLogViolations(postcondition, forbiddenInDbacLines));
        Assertions.assertEquals(List.of(), violations, "XA-16");
    }

    // ---------------------------------------------------------------- XA-17: the code

    /**
     * XA-17: in the bytecode - the adapter's Explain enters the gate before X, M inside X, the gate inside M, M left before X; the
     * gate gives back U before K; the processor looks nothing up outside its recovery loop and reaches DBAC only through the adapter
     */
    @Test
    public void xa17TheExplainEntryPointInTheBytecode() throws Exception {
        List<String> violations = new ArrayList<>();
        Map<String, ClassMethods> adapter = classes(ADAPTER_CLASS);
        List<String> explain = adapter.getOrDefault(ADAPTER_CLASS, ClassMethods.EMPTY).events("explain");
        int enter = indexOf(explain, "call io/cloudbeaver/service/dbac/policy/enforcement/EnforcementGate#enter", 0);
        int lookup = indexOf(explain, "call " + ADAPTER_CLASS + "$Source#executionContext", 0);
        int x = indexOf(explain, "call org/jkiss/dbeaver/model/DBPExclusiveResource#acquireExclusiveLock", 0);
        int m = indexOf(explain, "monitorenter", 0);
        int decide = indexOf(explain, "call " + ADAPTER_CLASS + "#decide", 0);
        int leaveM = indexOf(explain, "monitorexit", Math.max(decide, 0));
        int leaveX = indexOf(explain, "call org/jkiss/dbeaver/model/DBPExclusiveResource#releaseExclusiveLock", Math.max(decide, 0));
        if (!(enter >= 0 && enter < lookup && lookup < x && x < m && m < decide && decide < leaveM && leaveM < leaveX)) {
            violations.add("explain: expected enter < context lookup < X < M < gate < leave M < leave X, got enter=" + enter
                + " lookup=" + lookup + " X=" + x + " M=" + m + " gate=" + decide + " leaveM=" + leaveM + " leaveX=" + leaveX);
        }
        int planCall = -1;
        List<String> execute = adapter.getOrDefault(ADAPTER_CLASS + "$Explain", ClassMethods.EMPTY).events("execute");
        int session = indexOf(execute, "call org/jkiss/dbeaver/model/impl/jdbc/JDBCExecutionContext#openSession", 0);
        planCall = indexOf(execute, "call " + ADAPTER_CLASS + "$ExplainCall#plan", Math.max(session, 0));
        int after = indexOf(execute, "call org/jkiss/dbeaver/model/impl/jdbc/JDBCExecutionContext#getConnectionOrNull",
            Math.max(planCall, 0));
        if (!(session >= 0 && session < planCall && planCall < after)) {
            violations.add("Explain.execute(): expected a session, then the planner call, then the generation, got session=" + session
                + " plan=" + planCall + " generation=" + after);
        }
        List<String> gateRun = classes("io/cloudbeaver/service/dbac/policy/enforcement/EnforcementGate")
            .getOrDefault("io/cloudbeaver/service/dbac/policy/enforcement/EnforcementGate$Attempt", ClassMethods.EMPTY).events("run");
        int releaseUser = indexOf(gateRun, "field io/cloudbeaver/service/dbac/policy/enforcement/EnforcementGate$Step#RELEASE_USER", 0);
        int releaseGrant = indexOf(gateRun, "field io/cloudbeaver/service/dbac/policy/enforcement/EnforcementGate$Step#RELEASE_GRANT", 0);
        if (!(releaseUser >= 0 && releaseUser < releaseGrant)) {
            violations.add("the gate must give back U before K, got user=" + releaseUser + " grant=" + releaseGrant);
        }

        Map<String, ClassMethods> processor = classes(PROCESSOR_CLASS);
        ClassMethods outer = processor.getOrDefault(PROCESSOR_CLASS, ClassMethods.EMPTY);
        List<String> entry = outer.events("explainExecutionPlan");
        if (indexOf(entry, "call org/jkiss/dbeaver/model/exec/DBExecUtils#tryExecuteRecover", 0) < 0) {
            violations.add("explainExecutionPlan must plan inside the platform's recovery loop");
        }
        for (String event : entry) {
            for (String outside : List.of("WebSQLProcessor#getExecutionContext(", "GeneralUtils#adapt(",
                "DBCQueryPlanner#planQueryExecution(", "#openSession(", "DbacEnforcedExecution#explain(")) {
                if (event.contains(outside)) {
                    violations.add("explainExecutionPlan must not call " + outside + " outside its recovery loop: " + event);
                }
            }
        }
        boolean explainInLoop = false;
        boolean planInCallback = false;
        boolean freshContext = false;
        for (Map.Entry<String, List<String>> method : outer.methods().entrySet()) {
            if (method.getKey().startsWith("lambda$explainExecutionPlan$")) {
                explainInLoop |= method.getValue().stream().anyMatch(event -> event.startsWith("call " + ADAPTER_CLASS + "#explain("));
                planInCallback |= method.getValue().stream().anyMatch(event -> event.contains("DBCQueryPlanner#planQueryExecution("))
                    && method.getValue().stream().anyMatch(event -> event.contains("GeneralUtils#adapt("));
            }
        }
        for (Map.Entry<String, ClassMethods> one : processor.entrySet()) {
            freshContext |= one.getValue().classRefs().contains(ADAPTER_CLASS + "$Source") && one.getValue().events("executionContext")
                .stream().anyMatch(event -> event.contains("WebSQLProcessor#getExecutionContext("));
            for (String referenced : one.getValue().classRefs()) {
                if (referenced.startsWith("io/cloudbeaver/service/dbac/")) {
                    violations.add(one.getKey() + " refers to " + referenced + " - the processor reaches DBAC only through the adapter");
                }
            }
        }
        expect(violations, "the adapter's Explain called inside the recovery loop", true, explainInLoop);
        expect(violations, "the planner looked up and called inside the adapter's callback", true, planInCallback);
        expect(violations, "the processor's source looks the context up afresh", true, freshContext);
        Method entryMethod = null;
        for (Method method : DbacEnforcedExecution.class.getDeclaredMethods()) {
            if (method.getName().equals("explain")) {
                entryMethod = method;
            }
        }
        expect(violations, "the adapter's Explain entry: static and package-private", true, entryMethod != null
            && Modifier.isStatic(entryMethod.getModifiers()) && !Modifier.isPublic(entryMethod.getModifiers())
            && !Modifier.isPrivate(entryMethod.getModifiers()) && !Modifier.isProtected(entryMethod.getModifiers()));
        Assertions.assertEquals(List.of(), violations, "XA-17");
    }

    // ---------------------------------------------------------------- explaining

    @NotNull
    private static String plainSelect(@NotNull EnforcementTestSupport.Target target) {
        return "SELECT id FROM " + target.table();
    }

    /** A statement that draws from the fixture sequence, which no rollback undoes: each run of it is counted */
    @NotNull
    private static String analyzeUpdate(@NotNull EnforcementTestSupport.Target target) {
        return "UPDATE " + target.table() + " SET v = nextval('" + target.schema + ".seq')::int WHERE id = 1";
    }

    @NotNull
    private static Worker<Object> explainAsync(@NotNull EnforcementTestSupport.Target target, @NotNull String sql,
                                               @NotNull Map<String, Object> configuration) {
        return Worker.<Object>start("dbac-xea-explain", () -> target.processor.explainExecutionPlan(target.monitor, sql, configuration));
    }

    @NotNull
    private static EnforcementTestSupport.Outcome outcomeOf(@NotNull Worker<Object> worker) throws InterruptedException {
        boolean done = worker.awaitDone();
        return new EnforcementTestSupport.Outcome(done, worker.result, worker.error, System.nanoTime());
    }

    /** The adapter's package-private Explain entry, called as the processor calls it, with a planner that only counts */
    @Nullable
    private static Object explainDirectly(@NotNull DbacEnforcedExecution.Source source, @NotNull AtomicInteger planned) throws Exception {
        Class<?> callType = Class.forName(ADAPTER + "$ExplainCall", true, DbacEnforcedExecution.class.getClassLoader());
        Object call = Proxy.newProxyInstance(callType.getClassLoader(), new Class<?>[]{callType}, (self, method, args) -> {
            if (method.getName().equals("plan")) {
                planned.incrementAndGet();
                return "a plan";
            }
            return switch (method.getName()) {
                case "hashCode" -> System.identityHashCode(self);
                case "equals" -> self == args[0];
                default -> null;
            };
        });
        Method entry = DbacEnforcedExecution.class.getDeclaredMethod("explain", DBRProgressMonitor.class,
            DbacEnforcedExecution.Source.class, callType);
        entry.setAccessible(true);
        try {
            return entry.invoke(null, MONITOR, source, call);
        } catch (InvocationTargetException e) {
            if (e.getTargetException() instanceof Exception thrown) {
                throw thrown;
            }
            throw e;
        }
    }

    private static void expectRefusedUnplanned(
        @NotNull List<String> violations,
        @NotNull String what,
        @NotNull EnforcementTestSupport.Target target,
        @NotNull DenialReason reason
    ) throws Exception {
        ExplainSpy spy = ExplainSpy.install(target.context(), accessKey(target), target.subject.userId());
        final long sequence = EnforcementTestSupport.sequenceValue(target);
        expectRefused(violations, what, EnforcementTestSupport.explain(target, analyzeUpdate(target), ANALYZE), reason);
        expect(violations, what + ": statements the planner made", 0, spy.created.get());
        expect(violations, what + ": the statement's executions", sequence, EnforcementTestSupport.sequenceValue(target));
    }

    /** Waits until the metadata database's clock is past {@code moment} - a state of the database, not a sleep of a fixed length */
    private static void awaitDatabaseTime(@NotNull OffsetDateTime moment) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(WAIT_SECONDS);
        while (!EnforcementTestSupport.metadataNow().isAfter(moment)) {
            Assertions.assertTrue(System.nanoTime() < deadline, "FIXTURE: the database clock did not reach " + moment);
            Thread.sleep(20);
        }
    }

    @NotNull
    private static DbAccessPolicyConfig policyConfig() {
        PolicyServiceHolder.Ready ready = Assertions.assertInstanceOf(PolicyServiceHolder.Ready.class,
            PolicyServiceHolder.global().current(), "FIXTURE: the policy service must be ready");
        return ready.service().config();
    }

    @NotNull
    private static BoundedMetadataConnections leases() {
        return Assertions.assertInstanceOf(BoundedMetadataConnections.class, EnforcementTestSupport.metadataLeases(),
            "FIXTURE: the server's metadata leases must be the bounded source");
    }

    /** The ids of the Explain audit rows of one type for the target's key */
    @NotNull
    private static Set<String> auditIds(@NotNull EnforcementTestSupport.Target target, @NotNull String type) throws SQLException {
        Set<String> ids = new TreeSet<>();
        try (Connection connection = EnforcementTestSupport.metadata().openConnection();
             PreparedStatement statement = connection.prepareStatement(
                 "SELECT EVENT_ID FROM {table_prefix}DBAC_AUDIT_EVENT WHERE EVENT_TYPE=? AND USER_ID=? AND PROJECT_ID=?"
                     + " AND CONNECTION_ID=? AND OPERATION_CATEGORY=?")) {
            statement.setString(1, type);
            statement.setString(2, target.key().userId());
            statement.setString(3, target.key().projectId());
            statement.setString(4, target.key().connectionId());
            statement.setString(5, DbOperationCategory.EXPLAIN.name());
            try (ResultSet result = statement.executeQuery()) {
                while (result.next()) {
                    ids.add(result.getString(1));
                }
            }
        }
        return ids;
    }

    private static void expectLogged(
        @NotNull List<String> violations,
        @NotNull String what,
        @NotNull LifecycleTestSupport.Captured captured,
        @NotNull String... fragments
    ) {
        boolean found = captured.dbacMessages().stream()
            .anyMatch(message -> Stream.of(fragments).allMatch(message::contains) && message.contains("EVENT_ID="));
        if (!found) {
            violations.add(what + ": a DBAC log line with " + List.of(fragments) + " and an EVENT_ID, got " + captured.dbacMessages());
        }
    }

    /** What the P1 log contract forbids in the DBAC lines themselves */
    @NotNull
    private static List<String> dbacLogViolations(@NotNull LifecycleTestSupport.Captured captured, @NotNull List<String> forbidden) {
        List<String> violations = new ArrayList<>();
        for (int i = 0; i < captured.dbacMessages().size(); i++) {
            String message = captured.dbacMessages().get(i);
            if (captured.dbacThrowables().get(i) != null) {
                violations.add("an exception object is handed to the logger: " + message);
            }
            if (message.contains("\tat ")) {
                violations.add("a stack trace in a DBAC line: " + message);
            }
            for (String fragment : forbidden) {
                if (message.contains(fragment)) {
                    violations.add("a DBAC line contains '" + fragment + "'");
                }
            }
        }
        return violations;
    }

    // ---------------------------------------------------------------- the target's connection, wrapped

    /**
     * A proxy put in the place of the context's JDBC connection: everything goes to the real one, while the planner's
     * statements, rollbacks, aborts and closes are counted; the case can make the first statement fail as a lost connection,
     * hold it until let go, or make rollbacks fail. At the first close it notes what the attempt still holds.
     */
    private static final class ExplainSpy {
        final Connection real;
        final Connection proxy;
        final int backend;
        final AtomicInteger created = new AtomicInteger();
        final AtomicInteger rollbacks = new AtomicInteger();
        final AtomicInteger aborts = new AtomicInteger();
        final AtomicInteger closed = new AtomicInteger();
        final CountDownLatch reached = new CountDownLatch(1);
        final Map<String, Integer> atClose = new ConcurrentHashMap<>();
        volatile boolean loseConnectionOnce;
        volatile boolean rollbackFails;
        volatile CountDownLatch pause;
        volatile Fault onLose = () -> {
        };
        private volatile Thread job;
        private final DbAccessKey key;
        private final String user;

        private ExplainSpy(@NotNull Connection real, @NotNull DbAccessKey key, @NotNull String user) throws SQLException {
            this.real = real;
            this.key = key;
            this.user = user;
            this.backend = EnforcementTestSupport.backendPid(real);
            this.proxy = (Connection) Proxy.newProxyInstance(ExplainEnforcementAdapterTest.class.getClassLoader(),
                new Class<?>[]{Connection.class}, (self, method, args) -> {
                    switch (method.getName()) {
                        case "createStatement" -> {
                            created.incrementAndGet();
                            job = Thread.currentThread();
                            CountDownLatch hold = pause;
                            if (hold != null) {
                                reached.countDown();
                                hold.await(WAIT_SECONDS * 2, TimeUnit.SECONDS);
                            }
                            if (loseConnectionOnce) {
                                loseConnectionOnce = false;
                                onLose.run();
                                throw new SQLException("injected: the connection is lost", "08006");
                            }
                        }
                        case "rollback" -> {
                            if (aborts.get() == 0) {
                                rollbacks.incrementAndGet();
                            }
                            if (rollbackFails) {
                                throw new SQLException("injected: the rollback fails", "08006");
                            }
                        }
                        case "abort" -> aborts.incrementAndGet();
                        case "close" -> {
                            if (closed.incrementAndGet() == 1) {
                                noteAtClose();
                            }
                        }
                        case "hashCode" -> {
                            return System.identityHashCode(self);
                        }
                        case "equals" -> {
                            return self == args[0];
                        }
                        default -> {
                        }
                    }
                    try {
                        return method.invoke(real, args);
                    } catch (InvocationTargetException e) {
                        throw e.getTargetException();
                    }
                });
        }

        private void noteAtClose() {
            try {
                atClose.put("grant", readLocks(true, key.userId(), key));
                atClose.put("user", readLocks(false, user, null));
                Thread attempt = job;
                long frames = attempt == null ? -1 : Stream.of(attempt.getStackTrace())
                    .filter(frame -> frame.getClassName().startsWith(ADAPTER) || frame.getClassName().startsWith(GATE)).count();
                atClose.put("frames", (int) frames);
            } catch (Exception e) {
                atClose.put("failed", 1);
            }
        }

        @NotNull
        static ExplainSpy install(@NotNull JDBCExecutionContext context, @NotNull DbAccessKey key, @NotNull String user) throws Exception {
            ExplainSpy spy = new ExplainSpy(context.getConnection(MONITOR), key, user);
            setConnection(context, spy.proxy);
            return spy;
        }
    }

    /** Something a hook runs that may throw */
    @FunctionalInterface
    private interface Fault {
        void run() throws Exception;
    }

    // ---------------------------------------------------------------- the metadata database, tapped

    /**
     * The server's metadata leases, given connections that let the case act at the audit row: the bounded source's raw
     * connection source is swapped - through its private field, put back on close - for one whose connections fail the
     * next audit insert when asked, run a hook when an audit insert is prepared, and run a hook once when the connection
     * that wrote an audit row is closed: after the row's verdict, before the gate's next step
     */
    private static final class MetadataTap implements AutoCloseable {
        private final BoundedMetadataConnections leases;
        private final Field rawField;
        private final MetadataConnectionSource original;
        volatile boolean failNextAuditInsert;
        volatile Runnable onAuditInsert = () -> {
        };
        volatile Fault onAuditClose;

        private MetadataTap(
            @NotNull BoundedMetadataConnections leases,
            @NotNull Field rawField,
            @NotNull MetadataConnectionSource original
        ) {
            this.leases = leases;
            this.rawField = rawField;
            this.original = original;
        }

        @NotNull
        static MetadataTap install() throws Exception {
            BoundedMetadataConnections leases = leases();
            Field raw = BoundedMetadataConnections.class.getDeclaredField("raw");
            raw.setAccessible(true);
            MetadataConnectionSource original = (MetadataConnectionSource) raw.get(leases);
            MetadataTap tap = new MetadataTap(leases, raw, original);
            raw.set(leases, (MetadataConnectionSource) () -> tap.wrap(original.openConnection()));
            return tap;
        }

        @NotNull
        private Connection wrap(@NotNull Connection target) {
            AtomicBoolean wroteAudit = new AtomicBoolean();
            return (Connection) Proxy.newProxyInstance(ExplainEnforcementAdapterTest.class.getClassLoader(),
                new Class<?>[]{Connection.class}, (self, method, args) -> {
                    if (method.getName().equals("prepareStatement") && args != null && args.length > 0 && args[0] instanceof String sql
                        && KeyLockTestSupport.normalized(sql).startsWith("INSERT INTO DBAC_AUDIT_EVENT")) {
                        wroteAudit.set(true);
                        onAuditInsert.run();
                        if (failNextAuditInsert) {
                            failNextAuditInsert = false;
                            throw new SQLException("injected: the audit insert fails");
                        }
                    }
                    if (method.getName().equals("close") && wroteAudit.get()) {
                        Fault hook = onAuditClose;
                        onAuditClose = null;
                        if (hook != null) {
                            hook.run();
                        }
                    }
                    try {
                        return method.invoke(target, args);
                    } catch (InvocationTargetException e) {
                        throw e.getTargetException();
                    }
                });
        }

        @Override
        public void close() throws Exception {
            rawField.set(leases, original);
        }
    }

    // ---------------------------------------------------------------- targets

    /**
     * A target with no grant, whose connection waits for a row lock at most 20 seconds - a transaction a defect left open
     * on a connection the context no longer has would otherwise hold the row for good
     */
    @NotNull
    private EnforcementTestSupport.Target readOnlyTarget(@NotNull EnforcementTestSupport.Subject subject) throws Exception {
        EnforcementTestSupport.Target target = fixtures.readOnlyTarget(subject);
        EnforcementTestSupport.execute(target.jdbc(), "SET lock_timeout = '20s'");
        targets.add(target);
        return target;
    }

    /** A target with a live grant, bounded as {@link #readOnlyTarget} is */
    @NotNull
    private EnforcementTestSupport.Target writableTarget(@NotNull EnforcementTestSupport.Subject subject) throws Exception {
        EnforcementTestSupport.Target target = readOnlyTarget(subject);
        EnforcementTestSupport.grant(target.key());
        return target;
    }

    /**
     * Puts {@code replacement} in the place of the context's connection; the one taken out is closed after the case, so a
     * transaction a defect left open on it cannot hold its row through the cleanup
     */
    private void swapConnection(@NotNull JDBCExecutionContext context, @NotNull Connection replacement) throws Exception {
        Connection original = context.getConnectionOrNull();
        if (original != null) {
            closeAfter.add(original);
        }
        setConnection(context, replacement);
    }

    /**
     * After a case: an instance lock or a key lock a defect left held would stop every later case and the cleanup itself,
     * so it is let go here - the case that left it has already failed on it
     */
    private void letGoOfLeftLocks() throws Exception {
        for (EnforcementTestSupport.Target target : targets) {
            Object lock = target.instance().getExclusiveLock();
            Field locksField = lock.getClass().getDeclaredField("locks");
            locksField.setAccessible(true);
            synchronized (lock) {
                Object global = ((Map<?, ?>) locksField.get(lock)).get("#global");
                if (global != null) {
                    Field thread = global.getClass().getDeclaredField("lockThread");
                    thread.setAccessible(true);
                    if (thread.get(global) != null) {
                        System.out.println("[DBAC P6-B] an instance lock was left held; let go");
                        thread.set(global, null);
                        Field count = global.getClass().getDeclaredField("lockCount");
                        count.setAccessible(true);
                        count.set(global, 0);
                    }
                }
            }
        }
        for (Field field : EnforcementKeyLocks.class.getDeclaredFields()) {
            if (Modifier.isStatic(field.getModifiers())) {
                continue;
            }
            field.setAccessible(true);
            Object family = field.get(EnforcementKeyLocks.global());
            for (Field inner : family.getClass().getDeclaredFields()) {
                if (ConcurrentHashMap.class.isAssignableFrom(inner.getType())) {
                    inner.setAccessible(true);
                    Map<?, ?> entries = (Map<?, ?>) inner.get(family);
                    for (Map.Entry<?, ?> entry : List.copyOf(entries.entrySet())) {
                        for (Field lock : entry.getValue().getClass().getDeclaredFields()) {
                            if (lock.getType() == ReentrantReadWriteLock.class) {
                                lock.setAccessible(true);
                                ReentrantReadWriteLock held = (ReentrantReadWriteLock) lock.get(entry.getValue());
                                if (held.getReadLockCount() > 0 || held.isWriteLocked()) {
                                    System.out.println("[DBAC P6-B] a key lock was left held; dropped");
                                    entries.remove(entry.getKey());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /** The server's policy service holder, put into {@code Failed} or {@code Disposed} through its private state and back on close */
    private static final class HolderDown implements AutoCloseable {
        private final AtomicReference<Object> state;
        private final Object was;
        private final Object down;

        private HolderDown(@NotNull AtomicReference<Object> state, @NotNull Object was, @NotNull Object down) {
            this.state = state;
            this.was = was;
            this.down = down;
        }

        @NotNull
        @SuppressWarnings("unchecked")
        static HolderDown to(@NotNull String kind) throws Exception {
            PolicyServiceHolder holder = PolicyServiceHolder.global();
            Field field = PolicyServiceHolder.class.getDeclaredField("state");
            field.setAccessible(true);
            AtomicReference<Object> state = (AtomicReference<Object>) field.get(holder);
            Object was = state.get();
            PolicyServiceHolder.Ready ready = Assertions.assertInstanceOf(PolicyServiceHolder.Ready.class, was,
                "FIXTURE: the policy service must be ready before the case puts it down");
            Object down;
            if (kind.equals("Failed")) {
                java.lang.reflect.Constructor<?> make = PolicyServiceHolder.Failed.class.getDeclaredConstructors()[0];
                make.setAccessible(true);
                down = make.newInstance(privateField(ready, "token"), ready.database(),
                    PolicyServiceHolder.FailureCode.DATABASE_INIT_FAILED, privateField(ready, "plan"));
            } else {
                down = privateField(null, PolicyServiceHolder.Disposed.class, "INSTANCE");
            }
            Assertions.assertTrue(state.compareAndSet(was, down), "FIXTURE: the holder changed under the case");
            Assertions.assertEquals(kind, holder.current().getClass().getSimpleName(), "FIXTURE: the holder must now be " + kind);
            return new HolderDown(state, was, down);
        }

        @Override
        public void close() {
            Assertions.assertTrue(state.compareAndSet(down, was), "FIXTURE: the holder could not be put back");
        }
    }

    @Nullable
    private static Object privateField(@NotNull Object owner, @NotNull String name) throws Exception {
        return privateField(owner, owner.getClass(), name);
    }

    @Nullable
    private static Object privateField(@Nullable Object owner, @NotNull Class<?> type, @NotNull String name) throws Exception {
        Field field = type.getDeclaredField(name);
        field.setAccessible(true);
        return field.get(owner);
    }

    // ---------------------------------------------------------------- holds

    /** What an XA-1 stage holds: X, M, the grant key K or the user U */
    @NotNull
    private static Hold hold(
        @NotNull String stage,
        @NotNull EnforcementTestSupport.Target target,
        @NotNull DbAccessKey key,
        @NotNull String user
    ) throws InterruptedException {
        return switch (stage) {
            case "X" -> Hold.exclusive(target.instance());
            case "M" -> Hold.monitor(target.context());
            case "K" -> Hold.grantWrite(key);
            default -> Hold.userWrite(user);
        };
    }

    /** Something a thread of the case's own holds until closed */
    private static final class Hold implements AutoCloseable {
        private final CountDownLatch held = new CountDownLatch(1);
        private final CountDownLatch release = new CountDownLatch(1);
        private final Worker<Object> worker;

        private Hold(@NotNull String name, @NotNull HoldBody body) throws InterruptedException {
            this.worker = Worker.start("dbac-xea-hold-" + name, () -> {
                body.hold(held, release);
                return null;
            });
            Assertions.assertTrue(held.await(WAIT_SECONDS, TimeUnit.SECONDS), "FIXTURE: " + name + " was not taken");
        }

        @FunctionalInterface
        private interface HoldBody {
            void hold(@NotNull CountDownLatch held, @NotNull CountDownLatch release) throws Exception;
        }

        @NotNull
        static Hold exclusive(@NotNull JDBCRemoteInstance instance) throws InterruptedException {
            return new Hold("X", (held, release) -> {
                DBPExclusiveResource lock = instance.getExclusiveLock();
                Object token = lock.acquireExclusiveLock();
                try {
                    held.countDown();
                    release.await(WAIT_SECONDS * 2, TimeUnit.SECONDS);
                } finally {
                    lock.releaseExclusiveLock(token);
                }
            });
        }

        @NotNull
        static Hold monitor(@NotNull Object monitor) throws InterruptedException {
            return new Hold("M", (held, release) -> {
                synchronized (monitor) {
                    held.countDown();
                    release.await(WAIT_SECONDS * 2, TimeUnit.SECONDS);
                }
            });
        }

        @NotNull
        static Hold grantWrite(@NotNull DbAccessKey key) throws InterruptedException {
            return new Hold("K", (held, release) -> {
                try (EnforcementKeyLocks.Held ignored = EnforcementKeyLocks.global().lockGrantForWrite(key)) {
                    held.countDown();
                    release.await(WAIT_SECONDS * 2, TimeUnit.SECONDS);
                }
            });
        }

        @NotNull
        static Hold userWrite(@NotNull String userId) throws InterruptedException {
            return new Hold("U", (held, release) -> {
                try (EnforcementKeyLocks.Held ignored = EnforcementKeyLocks.global().lockUserForWrite(userId)) {
                    held.countDown();
                    release.await(WAIT_SECONDS * 2, TimeUnit.SECONDS);
                }
            });
        }

        @Override
        public void close() throws InterruptedException {
            release.countDown();
            Assertions.assertTrue(worker.awaitDone(), "FIXTURE: a hold was not released");
        }
    }

    // ---------------------------------------------------------------- the platform's connection

    private static void setConnection(@NotNull JDBCExecutionContext context, @Nullable Connection connection) throws Exception {
        Field field = JDBCExecutionContext.class.getDeclaredField("connection");
        field.setAccessible(true);
        field.set(context, connection);
    }

    // ---------------------------------------------------------------- a context that is not JDBC

    /** A context of no JDBC kind that is its own transaction manager - as a JDBC context is - and records what is called on it */
    private static final class FakeContext {
        final List<String> calls = new CopyOnWriteArrayList<>();
        final DBCSession session = (DBCSession) Proxy.newProxyInstance(
            TransactionEnforcementAdapterTest.class.getClassLoader(), new Class<?>[]{DBCSession.class},
            (self, method, args) -> defaultOf(method.getReturnType()));
        final DBCExecutionContext context = (DBCExecutionContext) Proxy.newProxyInstance(
            TransactionEnforcementAdapterTest.class.getClassLoader(),
            new Class<?>[]{DBCExecutionContext.class, DBCTransactionManager.class},
            (self, method, args) -> {
                return switch (method.getName()) {
                    case "commit", "rollback", "setAutoCommit" -> {
                        calls.add(method.getName());
                        yield null;
                    }
                    case "isConnected" -> true;
                    case "getContextId" -> 9_400_001L;
                    case "openSession" -> session;
                    case "hashCode" -> System.identityHashCode(self);
                    case "equals" -> self == args[0];
                    default -> defaultOf(method.getReturnType());
                };
            });
    }

    @Nullable
    private static Object defaultOf(@NotNull Class<?> type) {
        if (type == boolean.class) {
            return false;
        }
        if (type == int.class) {
            return 0;
        }
        if (type == long.class) {
            return 0L;
        }
        return null;
    }

    @NotNull
    private static DbacEnforcedExecution.Source source(@Nullable DBCExecutionContext context, @NotNull String userId) {
        return new DbacEnforcedExecution.Source() {
            @Nullable
            @Override
            public DBCExecutionContext executionContext() {
                return context;
            }

            @NotNull
            @Override
            public String userId() {
                return userId;
            }
        };
    }

    // ---------------------------------------------------------------- what the platform and the registry hold

    @NotNull
    private static DbAccessKey accessKey(@NotNull EnforcementTestSupport.Target target) {
        return new DbAccessKey(target.subject.userId(), target.container.getProject().getId(), target.container.getId());
    }

    /** The thread holding the instance's exclusive lock, from the platform's own state */
    @Nullable
    private static Thread exclusiveOwner(@NotNull JDBCRemoteInstance instance) throws Exception {
        Object lock = instance.getExclusiveLock();
        Field locksField = lock.getClass().getDeclaredField("locks");
        locksField.setAccessible(true);
        Map<?, ?> locks = (Map<?, ?>) locksField.get(lock);
        Object global;
        synchronized (lock) {
            global = locks.get("#global");
        }
        if (global == null) {
            return null;
        }
        Field thread = global.getClass().getDeclaredField("lockThread");
        thread.setAccessible(true);
        return (Thread) thread.get(global);
    }

    private static boolean holdsMonitor(@NotNull Thread thread, @NotNull Object monitor) {
        ThreadInfo[] infos = ManagementFactory.getThreadMXBean().getThreadInfo(new long[]{thread.threadId()}, true, false);
        if (infos.length == 0 || infos[0] == null) {
            return false;
        }
        for (MonitorInfo held : infos[0].getLockedMonitors()) {
            if (held.getIdentityHashCode() == System.identityHashCode(monitor)
                && held.getClassName().equals(monitor.getClass().getName())) {
                return true;
            }
        }
        return false;
    }

    private static boolean blockedOn(@NotNull Thread thread, @NotNull Object monitor) {
        ThreadInfo info = ManagementFactory.getThreadMXBean().getThreadInfo(thread.threadId());
        LockInfo lock = info == null ? null : info.getLockInfo();
        return thread.getState() == Thread.State.BLOCKED && lock != null && lock.getIdentityHashCode() == System.identityHashCode(monitor);
    }

    private static boolean stackHas(@NotNull Thread thread, @NotNull String classSuffix, @NotNull String method) {
        for (StackTraceElement frame : thread.getStackTrace()) {
            if (frame.getClassName().endsWith(classSuffix) && frame.getMethodName().equals(method)) {
                return true;
            }
        }
        return false;
    }

    private static boolean sleepingIn(int backend) {
        try (Connection observer = EnforcementTestSupport.openRawPostgres(MONITOR);
             PreparedStatement statement = observer.prepareStatement("SELECT wait_event FROM pg_stat_activity WHERE pid = ?")) {
            statement.setInt(1, backend);
            try (ResultSet result = statement.executeQuery()) {
                return result.next() && "PgSleep".equals(result.getString(1));
            }
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * The adapter's thread once it is where {@code there} says, or null when no thread of the adapter got there in time
     */
    @Nullable
    private static Thread awaitAdapterThread(@NotNull String what, @NotNull Predicate<Thread> there) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(WAIT_SECONDS);
        while (System.nanoTime() < deadline) {
            for (Map.Entry<Thread, StackTraceElement[]> one : Thread.getAllStackTraces().entrySet()) {
                boolean adapter = Stream.of(one.getValue()).anyMatch(frame -> frame.getClassName().startsWith(ADAPTER));
                if (adapter && there.test(one.getKey())) {
                    return one.getKey();
                }
            }
            Thread.sleep(20);
        }
        System.out.println("[DBAC P6-B] no adapter thread was seen at " + what);
        return null;
    }

    /** How many read holds the registry's lock for a grant key or user has now, 0 when it has no lock for it */
    private static int readLocks(boolean grant, @NotNull String userId, @Nullable DbAccessKey key) throws Exception {
        for (Field field : EnforcementKeyLocks.class.getDeclaredFields()) {
            if (Modifier.isStatic(field.getModifiers()) || !field.getName().startsWith(grant ? "grant" : "user")) {
                continue;
            }
            field.setAccessible(true);
            Object family = field.get(EnforcementKeyLocks.global());
            for (Field inner : family.getClass().getDeclaredFields()) {
                if (ConcurrentHashMap.class.isAssignableFrom(inner.getType())) {
                    inner.setAccessible(true);
                    Object entry = ((Map<?, ?>) inner.get(family)).get(grant ? key : userId);
                    if (entry == null) {
                        return 0;
                    }
                    for (Field lock : entry.getClass().getDeclaredFields()) {
                        if (lock.getType() == ReentrantReadWriteLock.class) {
                            lock.setAccessible(true);
                            return ((ReentrantReadWriteLock) lock.get(entry)).getReadLockCount();
                        }
                    }
                }
            }
        }
        throw new IllegalStateException("FIXTURE: the key lock registry could not be read");
    }

    private static void expectAllFree(
        @NotNull List<String> violations,
        @NotNull String what,
        @NotNull EnforcementTestSupport.Target target,
        @NotNull DbAccessKey key,
        @NotNull String user
    ) throws Exception {
        expect(violations, what + ": X", null, exclusiveOwner(target.instance()));
        expect(violations, what + ": K", 0, readLocks(true, key.userId(), key));
        expect(violations, what + ": U", 0, readLocks(false, user, null));
    }

    /** The registry's state for the context, or null when the registry holds its id for another object */
    @Nullable
    private static TransactionTaintRegistry.State stateOf(@NotNull JDBCExecutionContext context) {
        try {
            return TransactionTaintRegistry.global().state(context.getContextId(), context);
        } catch (IllegalStateException e) {
            return null;
        }
    }

    private static long metadataBorrows() {
        return Assertions.assertInstanceOf(BoundedMetadataConnections.class, EnforcementTestSupport.metadataLeases(),
            "FIXTURE: the server's metadata leases must be the bounded source").submittedTasks();
    }

    private static int audits(@NotNull EnforcementTestSupport.Target target, @NotNull String type) throws Exception {
        return EnforcementTestSupport.countAudit(target.key(), type, DbOperationCategory.EXPLAIN);
    }

    /**
     * The severed connection's server backend ends - the platform closes connections in a background task, so this
     * waits up to 15 seconds - and a separate client then sees nothing committed
     */
    private static void expectSeveredAndNothingCommitted(@NotNull List<String> violations, @NotNull String schema, int backend)
            throws Exception {
        try (Connection observer = EnforcementTestSupport.openRawPostgres(MONITOR)) {
            boolean gone = false;
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15);
            while (!gone && System.nanoTime() < deadline) {
                try (PreparedStatement statement = observer.prepareStatement("SELECT COUNT(*) FROM pg_stat_activity WHERE pid = ?")) {
                    statement.setInt(1, backend);
                    try (ResultSet result = statement.executeQuery()) {
                        gone = result.next() && result.getInt(1) == 0;
                    }
                }
                if (!gone) {
                    Thread.sleep(50);
                }
            }
            expect(violations, "the severed connection's server backend ended", true, gone);
            expect(violations, "committed, as a separate client sees it", 0, EnforcementTestSupport.readValue(observer, schema));
        }
    }

    @NotNull
    private static List<Throwable> causes(@NotNull Throwable error) {
        List<Throwable> chain = new ArrayList<>();
        for (Throwable one = error; one != null && chain.size() < 20; one = one.getCause()) {
            chain.add(one);
        }
        return chain;
    }

    private static void expectRefused(
        @NotNull List<String> violations,
        @NotNull String what,
        @NotNull EnforcementTestSupport.Outcome outcome,
        @NotNull DenialReason reason
    ) {
        if (!outcome.completed()) {
            violations.add(what + ": did not finish");
        } else if (outcome.error() == null) {
            violations.add(what + ": expected a refusal for " + reason + ", but it succeeded with " + outcome.result());
        } else if (!EnforcementTestSupport.mentions(outcome.error(), reason)) {
            violations.add(what + ": expected a refusal for " + reason + ", got " + EnforcementTestSupport.describe(outcome.error()));
        }
    }

    @FunctionalInterface
    private interface Call {
        @Nullable
        Object run() throws Exception;
    }

    @Nullable
    private static Object call(@NotNull Call call) {
        try {
            return call.run();
        } catch (Throwable t) {
            return t;
        }
    }

    private static void expectRefusal(
        @NotNull List<String> violations,
        @NotNull String what,
        @NotNull Call call,
        @NotNull DenialReason reason
    ) {
        Object outcome = call(call);
        if (!(outcome instanceof DbacEnforcedExecution.Refusal refusal) || refusal.reason() != reason) {
            violations.add(what + ": expected a refusal for " + reason + ", got " + (outcome instanceof Throwable t
                ? t.getClass().getName() : outcome));
        }
    }

    private static void expect(@NotNull List<String> violations, @NotNull String what, @Nullable Object expected, @Nullable Object actual) {
        if (!java.util.Objects.equals(expected, actual)) {
            violations.add(what + ": expected " + expected + ", got " + actual);
        }
    }

    // ---------------------------------------------------------------- bytecode, method by method

    /** A class's methods, each as the ordered calls, field reads and monitor instructions it contains, and the classes it refers to */
    private record ClassMethods(@NotNull Map<String, List<String>> methods, @NotNull Set<String> classRefs) {
        static final ClassMethods EMPTY = new ClassMethods(Map.of(), Set.of());

        @NotNull
        List<String> events(@NotNull String method) {
            List<String> all = new ArrayList<>();
            for (Map.Entry<String, List<String>> one : methods.entrySet()) {
                if (one.getKey().startsWith(method + "(")) {
                    all.addAll(one.getValue());
                }
            }
            return all;
        }

        @NotNull
        List<String> allEvents() {
            List<String> all = new ArrayList<>();
            methods.values().forEach(all::addAll);
            return all;
        }
    }

    /** The class and its nested classes, from the clone's compiled bundles */
    @NotNull
    private static Map<String, ClassMethods> classes(@NotNull String className) throws IOException {
        Map<String, ClassMethods> found = new HashMap<>();
        Path bundles = MetadataLeaseTest.repositoryRoot().resolve("server/bundles");
        try (Stream<Path> files = Files.walk(bundles)) {
            for (Path file : files.filter(f -> f.toString().replace('\\', '/').contains("/target/classes/")
                && f.getFileName().toString().endsWith(".class")).toList()) {
                String path = file.toString().replace('\\', '/');
                int start = path.indexOf("/target/classes/") + "/target/classes/".length();
                String name = path.substring(start, path.length() - ".class".length());
                if (name.equals(className) || name.startsWith(className + "$")) {
                    found.put(name, parse(Files.readAllBytes(file)));
                }
            }
        }
        return found;
    }

    /** Every adapter method reachable from {@code start} through calls to adapter methods */
    @NotNull
    private static Set<String> reachable(@NotNull Map<String, ClassMethods> classes, @NotNull String start) {
        Set<String> seen = new TreeSet<>();
        List<String> todo = new ArrayList<>(List.of(start));
        while (!todo.isEmpty()) {
            String method = todo.remove(todo.size() - 1);
            if (!seen.add(method)) {
                continue;
            }
            String owner = method.substring(0, method.indexOf('#'));
            String name = method.substring(method.indexOf('#') + 1);
            for (String event : classes.getOrDefault(owner, ClassMethods.EMPTY).events(name)) {
                if (event.startsWith("call " + ADAPTER_CLASS)) {
                    todo.add(event.substring(5, event.indexOf('(')));
                }
            }
        }
        return classes.isEmpty() ? Set.of() : seen;
    }

    private static int indexOf(@NotNull List<String> events, @NotNull String wanted, int from) {
        for (int i = Math.max(0, from); i < events.size(); i++) {
            if (events.get(i).equals(wanted) || events.get(i).startsWith(wanted + "(")) {
                return i;
            }
        }
        return -1;
    }

    @NotNull
    private static ClassMethods parse(@NotNull byte[] bytes) throws IOException {
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes));
        in.readInt();
        in.readUnsignedShort();
        in.readUnsignedShort();
        int count = in.readUnsignedShort();
        Object[] pool = new Object[count];
        int[] tags = new int[count];
        for (int i = 1; i < count; i++) {
            int tag = in.readUnsignedByte();
            tags[i] = tag;
            switch (tag) {
                case 1 -> pool[i] = in.readUTF();
                case 3, 4 -> in.readInt();
                case 5, 6 -> {
                    in.readLong();
                    i++;
                }
                case 7, 8, 16, 19, 20 -> pool[i] = in.readUnsignedShort();
                case 9, 10, 11, 12, 17, 18 -> pool[i] = new int[]{in.readUnsignedShort(), in.readUnsignedShort()};
                case 15 -> {
                    in.readUnsignedByte();
                    in.readUnsignedShort();
                }
                default -> throw new IOException("FIXTURE: unknown constant pool tag " + tag);
            }
        }
        Set<String> classRefs = new HashSet<>();
        for (int i = 1; i < count; i++) {
            if (tags[i] == 7) {
                classRefs.add((String) pool[(Integer) pool[i]]);
            }
        }
        in.readUnsignedShort();
        in.readUnsignedShort();
        in.readUnsignedShort();
        int interfaces = in.readUnsignedShort();
        for (int i = 0; i < interfaces; i++) {
            in.readUnsignedShort();
        }
        int fields = in.readUnsignedShort();
        for (int i = 0; i < fields; i++) {
            in.readUnsignedShort();
            in.readUnsignedShort();
            in.readUnsignedShort();
            skipAttributes(in);
        }
        Map<String, List<String>> methods = new HashMap<>();
        int methodCount = in.readUnsignedShort();
        for (int i = 0; i < methodCount; i++) {
            in.readUnsignedShort();
            String name = (String) pool[in.readUnsignedShort()];
            String descriptor = (String) pool[in.readUnsignedShort()];
            List<String> events = new ArrayList<>();
            int attributes = in.readUnsignedShort();
            for (int a = 0; a < attributes; a++) {
                String attribute = (String) pool[in.readUnsignedShort()];
                int length = in.readInt();
                byte[] body = new byte[length];
                in.readFully(body);
                if (attribute.equals("Code")) {
                    events = code(body, pool, tags);
                }
            }
            methods.put(name + descriptor, events);
        }
        return new ClassMethods(methods, classRefs);
    }

    private static void skipAttributes(@NotNull DataInputStream in) throws IOException {
        int attributes = in.readUnsignedShort();
        for (int a = 0; a < attributes; a++) {
            in.readUnsignedShort();
            in.skipBytes(in.readInt());
        }
    }

    /** The calls, field reads and monitor instructions of one method's code, in order */
    @NotNull
    private static List<String> code(@NotNull byte[] body, @NotNull Object[] pool, @NotNull int[] tags) throws IOException {
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(body));
        in.readUnsignedShort();
        in.readUnsignedShort();
        int length = in.readInt();
        byte[] code = new byte[length];
        in.readFully(code);
        List<String> events = new ArrayList<>();
        int pc = 0;
        while (pc < length) {
            int op = code[pc] & 0xff;
            if (op >= 0xb6 && op <= 0xb9) {
                int index = ((code[pc + 1] & 0xff) << 8) | (code[pc + 2] & 0xff);
                int[] ref = (int[]) pool[index];
                String owner = (String) pool[(Integer) pool[ref[0]]];
                int[] nameAndType = (int[]) pool[ref[1]];
                events.add("call " + owner + "#" + pool[nameAndType[0]] + pool[nameAndType[1]]);
            } else if (op == 0xb2 || op == 0xb4) {
                int index = ((code[pc + 1] & 0xff) << 8) | (code[pc + 2] & 0xff);
                int[] ref = (int[]) pool[index];
                String owner = (String) pool[(Integer) pool[ref[0]]];
                int[] nameAndType = (int[]) pool[ref[1]];
                events.add("field " + owner + "#" + pool[nameAndType[0]]);
            } else if (op == 0xc2) {
                events.add("monitorenter");
            } else if (op == 0xc3) {
                events.add("monitorexit");
            }
            pc += instructionLength(code, pc);
        }
        return events;
    }

    private static int instructionLength(@NotNull byte[] code, int pc) {
        int op = code[pc] & 0xff;
        switch (op) {
            case 0x10, 0x12, 0x15, 0x16, 0x17, 0x18, 0x19, 0x36, 0x37, 0x38, 0x39, 0x3a, 0xa9, 0xbc:
                return 2;
            case 0x11, 0x13, 0x14, 0x84, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xbb, 0xbd, 0xc0, 0xc1, 0xc6, 0xc7:
                return 3;
            case 0xc5:
                return 4;
            case 0xb9, 0xba, 0xc8, 0xc9:
                return 5;
            case 0xc4:
                return (code[pc + 1] & 0xff) == 0x84 ? 6 : 4;
            case 0xaa: {
                int at = (pc + 4) & ~3;
                int low = readInt(code, at + 4);
                int high = readInt(code, at + 8);
                return at - pc + 12 + (high - low + 1) * 4;
            }
            case 0xab: {
                int at = (pc + 4) & ~3;
                int pairs = readInt(code, at + 4);
                return at - pc + 8 + pairs * 8;
            }
            default:
                if (op >= 0x99 && op <= 0xa8) {
                    return 3;
                }
                return 1;
        }
    }

    private static int readInt(@NotNull byte[] code, int at) {
        return ((code[at] & 0xff) << 24) | ((code[at + 1] & 0xff) << 16) | ((code[at + 2] & 0xff) << 8) | (code[at + 3] & 0xff);
    }
}
