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

import io.cloudbeaver.WebSessionProjectImpl;
import io.cloudbeaver.app.CEAppStarter;
import io.cloudbeaver.model.WebAsyncTaskInfo;
import io.cloudbeaver.model.WebConnectionInfo;
import io.cloudbeaver.model.WebServerError;
import io.cloudbeaver.service.dbac.PolicyServiceHolder;
import io.cloudbeaver.service.dbac.policy.BoundedMetadataConnections;
import io.cloudbeaver.service.dbac.policy.DbAccessKey;
import io.cloudbeaver.service.dbac.policy.DbOperationCategory;
import io.cloudbeaver.service.dbac.policy.DenialReason;
import io.cloudbeaver.service.dbac.policy.enforcement.EnforcementKeyLocks;
import io.cloudbeaver.service.dbac.policy.enforcement.TransactionTaintRegistry;
import io.cloudbeaver.service.sql.DbacEnforcedExecution;
import io.cloudbeaver.service.sql.WebSQLContextInfo;
import io.cloudbeaver.service.sql.WebSQLProcessor;
import io.cloudbeaver.service.sql.WebServiceBindingSQL;
import io.cloudbeaver.test.platform.dbac.KeyLockTestSupport.Worker;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.jkiss.dbeaver.model.DBPErrorAssistant;
import org.jkiss.dbeaver.model.DBPExclusiveResource;
import org.jkiss.dbeaver.model.connection.DBPConnectionConfiguration;
import org.jkiss.dbeaver.model.connection.DBPDriver;
import org.jkiss.dbeaver.model.connection.DBPDriverConfigurationType;
import org.jkiss.dbeaver.model.exec.DBCExecutionContext;
import org.jkiss.dbeaver.model.exec.DBCInvalidatePhase;
import org.jkiss.dbeaver.model.exec.DBCSession;
import org.jkiss.dbeaver.model.exec.DBCTransactionManager;
import org.jkiss.dbeaver.model.exec.DBExecUtils;
import org.jkiss.dbeaver.model.impl.jdbc.JDBCExecutionContext;
import org.jkiss.dbeaver.model.impl.jdbc.JDBCRemoteInstance;
import org.jkiss.dbeaver.model.runtime.DBRProgressMonitor;
import org.jkiss.dbeaver.model.runtime.LoggingProgressMonitor;
import org.jkiss.dbeaver.registry.DataSourceDescriptor;
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
import java.io.OutputStream;
import java.lang.management.LockInfo;
import java.lang.management.ManagementFactory;
import java.lang.management.MonitorInfo;
import java.lang.management.ThreadInfo;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Proxy;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
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
 * P6-A: what the transaction entry points' adapter does on the inside - its locks, its context, its connection
 * <p>
 * Every case drives a production entry point of {@code WebSQLContextInfo}, or the adapter's own public calls where a
 * case needs a context the server cannot make (one that is not JDBC). What happens inside is seen without a test seam
 * in production: the instance's exclusive lock and the context's monitor are read from the platform's own state and
 * the JVM's thread information, the key locks from the registry's private state, the server backend from
 * {@code pg_stat_activity}, and the order of calls from the adapter's bytecode. A case that needs the platform's
 * connection to change under it changes the context's private field, or wraps the JDBC connection in a proxy that
 * fails where the case says. Nothing is decided by how long something took, except where a bound is the point.
 */
@Timeout(value = 600, unit = TimeUnit.SECONDS, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
public class TransactionEnforcementAdapterTest {

    private static final String ADAPTER = "io.cloudbeaver.service.sql.DbacEnforcedExecution";
    private static final String ADAPTER_CLASS = "io/cloudbeaver/service/sql/DbacEnforcedExecution";
    private static final long WAIT_SECONDS = 30;

    private static EnforcementTestSupport.Fixtures fixtures;
    private static final DBRProgressMonitor MONITOR = new LoggingProgressMonitor();

    private final List<AutoCloseable> closeAfter = new ArrayList<>();

    @BeforeAll
    public static void startServer() throws Exception {
        CEAppStarter.startServerIfNotStarted();
        fixtures = EnforcementTestSupport.fixtures("tea", MONITOR);
    }

    @AfterEach
    public void cleanUp() throws Exception {
        Collections.reverse(closeAfter);
        for (AutoCloseable one : closeAfter) {
            try {
                one.close();
            } catch (Exception e) {
                System.out.println("[DBAC P6-A] cleanup failed: " + e.getClass().getName());
            }
        }
        closeAfter.clear();
        fixtures.afterEach();
    }

    @AfterAll
    public static void deleteUsers() throws Exception {
        fixtures.afterAll();
    }

    // ---------------------------------------------------------------- TA-1, TA-2: lock order

    /**
     * TA-1: the instance lock X, then the context monitor M, then the grant key K, then the user U - all four held while the
     * platform commits
     * <p>
     * The case holds each in turn and catches the commit waiting for it: waiting for X it holds nothing; waiting for M
     * it holds X; waiting for K it holds X and M; waiting for U it holds X, M and K. A slow commit - a deferred trigger
     * that sleeps - is then caught inside the platform's commit, with all four held. Afterwards all four are free.
     */
    @Test
    public void ta1LocksAreTakenXThenMThenKThenU() throws Exception {
        List<String> violations = new ArrayList<>();
        for (String stage : List.of("X", "M", "K", "U")) {
            EnforcementTestSupport.Target target = readOnlyTarget();
            EnforcementTestSupport.openTransaction(target, 71);
            DbAccessKey key = accessKey(target);
            String user = target.subject.userId();
            JDBCExecutionContext context = target.context();
            try (Hold held = hold(stage, target, key, user)) {
                WebAsyncTaskInfo task = target.sqlContext.commitTransaction();
                Thread job = awaitAdapterThread(stage, thread -> switch (stage) {
                    case "X" -> stackHas(thread, "SimpleExclusiveLock", "acquireTaskLock");
                    case "M" -> blockedOn(thread, context);
                    default -> stackHas(thread, "ReentrantReadWriteLock$ReadLock", "tryLock");
                });
                if (job == null) {
                    violations.add("waiting for " + stage + ": the commit must wait for it");
                } else {
                    expect(violations, "waiting for " + stage + ": X held by the commit", !stage.equals("X"),
                        exclusiveOwner(target.instance()) == job);
                    expect(violations, "waiting for " + stage + ": M held by the commit", stage.equals("K") || stage.equals("U"),
                        holdsMonitor(job, context));
                    expect(violations, "waiting for " + stage + ": K held by the commit", stage.equals("U"),
                        readLocks(true, key.userId(), key) > 0);
                    expect(violations, "waiting for " + stage + ": U held by the commit", false, readLocks(false, user, null) > 0);
                }
                held.close();
                EnforcementTestSupport.await(task);
            }
            expectAllFree(violations, "after waiting for " + stage, target, key, user);
        }

        EnforcementTestSupport.Target target = writableTarget();
        EnforcementTestSupport.openTransaction(target, EnforcementTestSupport.SLOW_VALUE);
        DbAccessKey key = accessKey(target);
        String user = target.subject.userId();
        int backend = EnforcementTestSupport.backendPid(target.jdbc());
        WebAsyncTaskInfo task = target.sqlContext.commitTransaction();
        Thread job = awaitAdapterThread("the platform commit", thread -> sleepingIn(backend));
        if (job == null) {
            violations.add("the slow commit must be seen inside the platform");
        } else {
            expect(violations, "inside the platform commit: X", true, exclusiveOwner(target.instance()) == job);
            expect(violations, "inside the platform commit: M", true, holdsMonitor(job, target.context()));
            expect(violations, "inside the platform commit: K", true, readLocks(true, key.userId(), key) > 0);
            expect(violations, "inside the platform commit: U", true, readLocks(false, user, null) > 0);
        }
        EnforcementTestSupport.Outcome outcome = EnforcementTestSupport.await(task);
        expect(violations, "the slow commit succeeds", true, outcome.succeeded());
        expectAllFree(violations, "after the slow commit", target, key, user);
        Assertions.assertEquals(List.of(), violations, "TA-1");
    }

    /**
     * TA-2: in the adapter's bytecode, the gate is entered before X is taken, M inside X, the gate run inside M, M left before X
     * <p>
     * And the entry points look the context up inside the task: the methods that create the tasks call neither the
     * processor's context lookup nor the transaction manager lookup - only the tasks' {@code run()} does, through the
     * adapter. The adapter's request carries the very id its context reference gives the gate.
     */
    @Test
    public void ta2TheGateIsEnteredFirstAndTheContextLookedUpInsideTheTask() throws Exception {
        List<String> violations = new ArrayList<>();
        Map<String, ClassMethods> adapter = classes(ADAPTER_CLASS);
        if (adapter.isEmpty()) {
            violations.add("the adapter's classes must be found");
        }
        for (String entryPoint : List.of("commit", "autoCommitOn")) {
            List<String> events = adapter.getOrDefault(ADAPTER_CLASS, ClassMethods.EMPTY).events(entryPoint);
            int enter = indexOf(events, "call io/cloudbeaver/service/dbac/policy/enforcement/EnforcementGate#enter", 0);
            int lookup = indexOf(events, "call io/cloudbeaver/service/sql/DbacEnforcedExecution$Source#executionContext", 0);
            int x = indexOf(events, "call org/jkiss/dbeaver/model/DBPExclusiveResource#acquireExclusiveLock", 0);
            int m = indexOf(events, "monitorenter", 0);
            int decide = indexOf(events, "call " + ADAPTER_CLASS + "#decide", 0);
            int leaveM = indexOf(events, "monitorexit", Math.max(decide, 0));
            int leaveX = indexOf(events, "call org/jkiss/dbeaver/model/DBPExclusiveResource#releaseExclusiveLock", Math.max(decide, 0));
            if (!(enter >= 0 && enter < lookup && lookup < x && x < m && m < decide && decide < leaveM && leaveM < leaveX)) {
                violations.add(entryPoint + ": expected enter < context lookup < X < M < gate < leave M < leave X, got enter=" + enter
                    + " lookup=" + lookup + " X=" + x + " M=" + m + " gate=" + decide + " leaveM=" + leaveM + " leaveX=" + leaveX);
            }
        }
        List<String> decide = adapter.getOrDefault(ADAPTER_CLASS, ClassMethods.EMPTY).events("decide");
        if (indexOf(decide, "call io/cloudbeaver/service/dbac/policy/enforcement/EnforcementGate$Entry#run", 0) < 0) {
            violations.add("the gate must be run from decide()");
        }
        List<String> request = adapter.getOrDefault(ADAPTER_CLASS, ClassMethods.EMPTY).events("request");
        if (indexOf(request, "call " + ADAPTER_CLASS + "$Ref#contextId", 0) < 0
            || indexOf(request, "call java/lang/String#valueOf", 0) < 0) {
            violations.add("the request's context id must be the context reference's id, as text, got " + request);
        }
        List<String> refId = adapter.getOrDefault(ADAPTER_CLASS + "$Ref", ClassMethods.EMPTY).events("contextId");
        if (refId.stream().noneMatch(event -> event.contains("#getContextId("))) {
            violations.add("the context reference's id must be the platform's context id, got " + refId);
        }

        Map<String, ClassMethods> entryPoints = classes("io/cloudbeaver/service/sql/WebSQLContextInfo");
        ClassMethods outer = entryPoints.getOrDefault("io/cloudbeaver/service/sql/WebSQLContextInfo", ClassMethods.EMPTY);
        for (String method : List.of("commitTransaction", "setAutoCommit", "rollbackTransaction")) {
            for (String event : outer.events(method)) {
                if (event.contains("WebSQLProcessor#getExecutionContext(") || event.contains("DBUtils#getTransactionManager(")) {
                    violations.add(method + " must not look the context up outside its task: " + event);
                }
            }
        }
        Set<String> adapterCalls = new TreeSet<>();
        for (Map.Entry<String, ClassMethods> one : entryPoints.entrySet()) {
            for (String event : one.getValue().allEvents()) {
                if (event.startsWith("call " + ADAPTER_CLASS + "#")) {
                    adapterCalls.add(event.substring(event.indexOf('#') + 1, event.indexOf('(')));
                }
                if (event.contains("io/cloudbeaver/service/dbac/")) {
                    violations.add(one.getKey() + " must reach DBAC only through the adapter: " + event);
                }
            }
        }
        expect(violations, "the entry points' calls into the adapter", new TreeSet<>(List.of("autoCommitOn", "commit", "rollback")),
            adapterCalls);
        Assertions.assertEquals(List.of(), violations, "TA-2");
    }

    // ---------------------------------------------------------------- TA-3 - TA-7: contexts and generations

    /**
     * TA-3: the registry knows the context by the platform's id and the context object itself
     * <p>
     * A READ_ONLY commit is refused, and its rollback fails, so the context is blocked: the registry answers BLOCKED for
     * the context's id and object, and refuses to answer for another object under that id.
     */
    @Test
    public void ta3TheRegistryKnowsTheRealContextByItsId() throws Exception {
        List<String> violations = new ArrayList<>();
        EnforcementTestSupport.Target target = readOnlyTarget();
        EnforcementTestSupport.openTransaction(target, 72);
        JDBCExecutionContext context = target.context();
        Spy spy = Spy.install(context);
        spy.rollbackFails = true;
        EnforcementTestSupport.Outcome outcome = EnforcementTestSupport.commit(target);
        expectRefused(violations, "the READ_ONLY commit", outcome, DenialReason.NO_GRANT);
        expect(violations, "rollbacks tried", 1, spy.rollbacks.get());
        expect(violations, "the registry's state for the context", TransactionTaintRegistry.State.BLOCKED, stateOf(context));
        try {
            TransactionTaintRegistry.global().state(context.getContextId(), new Object());
            violations.add("another object under the context's id must be refused by the registry");
        } catch (IllegalStateException expected) {
            // the identity is the context object itself
        }
        expect(violations, "the context severed", true, context.getConnectionOrNull() == null);
        expect(violations, "the connection aborted", 1, spy.aborts.get());
        expectSeveredAndNothingCommitted(violations, target.schema, spy.backend);
        Assertions.assertEquals(List.of(), violations, "TA-3");
    }

    /**
     * TA-4: a context that is not JDBC is refused before anything is locked, and its transaction is not touched; no context at
     * all is refused too
     * <p>
     * The explicit rollback of such a context stays as the platform always did it.
     */
    @Test
    public void ta4AContextThatIsNotJdbcIsRefused() throws Exception {
        List<String> violations = new ArrayList<>();
        FakeContext fake = new FakeContext();
        DbacEnforcedExecution.Source source = source(fake.context, "dbac-tea-nobody");
        expectRefusal(violations, "commit on a context that is not JDBC", () -> DbacEnforcedExecution.commit(MONITOR, source),
            DenialReason.ENDPOINT_UNSUPPORTED);
        expectRefusal(violations, "auto-commit on a context that is not JDBC", () -> DbacEnforcedExecution.autoCommitOn(MONITOR, source),
            DenialReason.ENDPOINT_UNSUPPORTED);
        expect(violations, "platform commits", List.of(), fake.calls.stream().filter(call -> !call.equals("rollback")).toList());
        Object rolledBack = call(() -> DbacEnforcedExecution.rollback(MONITOR, source));
        expect(violations, "the explicit rollback of a context that is not JDBC", List.of("rollback"), fake.calls);
        if (rolledBack instanceof Throwable failure) {
            violations.add("the explicit rollback must work as before, failed with " + failure.getClass().getName());
        }
        DbacEnforcedExecution.Source none = source(null, "dbac-tea-nobody");
        expectRefusal(violations, "commit with no context", () -> DbacEnforcedExecution.commit(MONITOR, none),
            DenialReason.CONNECTION_UNKNOWN);
        expectRefusal(violations, "auto-commit on with no context", () -> DbacEnforcedExecution.autoCommitOn(MONITOR, none),
            DenialReason.CONNECTION_UNKNOWN);
        Assertions.assertEquals(List.of(), violations, "TA-4");
    }

    /**
     * TA-5: a context without a connection - no generation - is refused, and nothing reconnects it to commit
     */
    @Test
    public void ta5NoGenerationIsRefused() throws Exception {
        List<String> violations = new ArrayList<>();
        EnforcementTestSupport.Target target = writableTarget();
        EnforcementTestSupport.openTransaction(target, 73);
        JDBCExecutionContext context = target.context();
        Connection real = context.getConnectionOrNull();
        setConnection(context, null);
        try {
            expectRefused(violations, "commit", EnforcementTestSupport.commit(target), DenialReason.CONNECTION_UNKNOWN);
            expectRefused(violations, "auto-commit on", EnforcementTestSupport.setAutoCommit(target, true),
                DenialReason.CONNECTION_UNKNOWN);
            expect(violations, "a connection opened by the refusals", true, context.getConnectionOrNull() == null);
        } finally {
            setConnection(context, real);
        }
        expect(violations, "committed", 0, target.committedValue());
        Assertions.assertEquals(List.of(), violations, "TA-5");
    }

    /**
     * TA-6: a generation that changes before the operation is refused and the platform is never called
     * <p>
     * The case holds the grant key, so the commit waits for it inside the gate with X and M held and the generation
     * read; it then puts another connection in the context's place and lets the key go. The gate's final confirmation
     * sees the change: refused {@code GRANT_STALE}, with a correcting audit row; the rollback refuses to touch a
     * connection that is no longer the context's, so the context is severed and blocked. Nothing was committed.
     */
    @Test
    public void ta6AGenerationChangedBeforeTheOperationRefuses() throws Exception {
        List<String> violations = new ArrayList<>();
        EnforcementTestSupport.Target target = writableTarget();
        EnforcementTestSupport.openTransaction(target, 74);
        DbAccessKey key = accessKey(target);
        JDBCExecutionContext context = target.context();
        Connection other = EnforcementTestSupport.openRawPostgres(MONITOR);
        closeAfter.add(other);
        int allowed = audits(target, EnforcementTestSupport.EVENT_WRITE_ALLOWED);
        final int denied = audits(target, EnforcementTestSupport.EVENT_WRITE_DENIED);
        WebAsyncTaskInfo task;
        try (Hold held = Hold.grantWrite(key)) {
            task = target.sqlContext.commitTransaction();
            if (awaitAdapterThread("K", thread -> stackHas(thread, "ReentrantReadWriteLock$ReadLock", "tryLock")) == null) {
                violations.add("the commit must wait for the grant key");
            }
            swapConnection(context, other);
        }
        EnforcementTestSupport.Outcome outcome = EnforcementTestSupport.await(task);
        expectRefused(violations, "the commit whose generation changed", outcome, DenialReason.GRANT_STALE);
        expect(violations, "WRITE_ALLOWED rows", allowed + 1, audits(target, EnforcementTestSupport.EVENT_WRITE_ALLOWED));
        expect(violations, "WRITE_DENIED rows: the correction", denied + 1, audits(target, EnforcementTestSupport.EVENT_WRITE_DENIED));
        expect(violations, "the registry's state", TransactionTaintRegistry.State.BLOCKED, stateOf(context));
        expect(violations, "committed", 0, target.committedValue());
        Assertions.assertEquals(List.of(), violations, "TA-6");
    }

    /**
     * TA-7: a generation that changes while the platform commits is not reported a success - the context is blocked, no correction written
     * <p>
     * A slow commit is caught sleeping in the server; the case puts another connection in the context's place. The
     * commit returns into a changed context: refused {@code CONNECTION_BLOCKED}, BLOCKED, one {@code WRITE_ALLOWED} row
     * and no {@code WRITE_DENIED} row, because the platform was called.
     */
    @Test
    public void ta7AGenerationChangedByTheCommitIsNotASuccess() throws Exception {
        List<String> violations = new ArrayList<>();
        EnforcementTestSupport.Target target = writableTarget();
        EnforcementTestSupport.openTransaction(target, EnforcementTestSupport.SLOW_VALUE);
        JDBCExecutionContext context = target.context();
        int backend = EnforcementTestSupport.backendPid(target.jdbc());
        Connection other = EnforcementTestSupport.openRawPostgres(MONITOR);
        closeAfter.add(other);
        final int allowed = audits(target, EnforcementTestSupport.EVENT_WRITE_ALLOWED);
        final int denied = audits(target, EnforcementTestSupport.EVENT_WRITE_DENIED);
        WebAsyncTaskInfo task = target.sqlContext.commitTransaction();
        if (awaitAdapterThread("the platform commit", thread -> sleepingIn(backend)) == null) {
            violations.add("the slow commit must be seen inside the platform");
        }
        swapConnection(context, other);
        EnforcementTestSupport.Outcome outcome = EnforcementTestSupport.await(task);
        expectRefused(violations, "the commit whose generation changed under it", outcome, DenialReason.CONNECTION_BLOCKED);
        expect(violations, "the commit's result", null, outcome.result());
        expect(violations, "the registry's state", TransactionTaintRegistry.State.BLOCKED, stateOf(context));
        expect(violations, "WRITE_ALLOWED rows", allowed + 1, audits(target, EnforcementTestSupport.EVENT_WRITE_ALLOWED));
        expect(violations, "WRITE_DENIED rows: none after the platform call", denied,
            audits(target, EnforcementTestSupport.EVENT_WRITE_DENIED));
        Assertions.assertEquals(List.of(), violations, "TA-7");
    }

    // ---------------------------------------------------------------- TA-8 - TA-11: the explicit rollback

    /**
     * TA-8: an explicit rollback on a live connection releases a blocked context
     * <p>
     * The context is blocked by an auto-commit on whose postcondition failed; the platform reconnects it; the explicit
     * rollback works and leaves it clean, and a commit on it is no longer refused for the block.
     */
    @Test
    public void ta8AnExplicitRollbackReleasesABlockedContext() throws Exception {
        List<String> violations = new ArrayList<>();
        EnforcementTestSupport.Target target = writableTarget();
        final JDBCExecutionContext context = target.context();
        target.jdbc().setAutoCommit(false);
        target.updateInTransaction(75);
        expectRefused(violations, "auto-commit on with JDBC off and the cache on", EnforcementTestSupport.setAutoCommit(target, true),
            DenialReason.CONNECTION_BLOCKED);
        expect(violations, "the registry's state after the failed postcondition", TransactionTaintRegistry.State.BLOCKED, stateOf(context));
        // Without the block the old connection may still hold the row, and the steps below would wait for it for good
        Assertions.assertEquals(List.of(), violations, "TA-8: the block");
        context.invalidateContext(MONITOR, DBCInvalidatePhase.INVALIDATE);
        expect(violations, "a live connection after the platform reconnected", true, context.getConnectionOrNull() != null);
        EnforcementTestSupport.execute(target.jdbc(), "SET lock_timeout = '10s'");
        EnforcementTestSupport.Outcome rollback = EnforcementTestSupport.rollback(target);
        expect(violations, "the explicit rollback", true, rollback.succeeded());
        expect(violations, "the registry's state after the explicit rollback", TransactionTaintRegistry.State.CLEAN, stateOf(context));
        EnforcementTestSupport.openTransaction(target, 76);
        EnforcementTestSupport.Outcome commit = EnforcementTestSupport.commit(target);
        expect(violations, "a commit after the release", true, commit.succeeded());
        expect(violations, "committed", 76, target.committedValue());
        Assertions.assertEquals(List.of(), violations, "TA-8");
    }

    /**
     * TA-9: an explicit rollback that fails severs the context and blocks it, and the failure reaches the caller as a failure,
     * not a refusal
     */
    @Test
    public void ta9AFailedExplicitRollbackSeversAndBlocks() throws Exception {
        List<String> violations = new ArrayList<>();
        EnforcementTestSupport.Target target = readOnlyTarget();
        EnforcementTestSupport.openTransaction(target, 77);
        JDBCExecutionContext context = target.context();
        Spy spy = Spy.install(context);
        spy.rollbackFails = true;
        EnforcementTestSupport.Outcome outcome = EnforcementTestSupport.rollback(target);
        expect(violations, "the explicit rollback's outcome", false, outcome.succeeded());
        if (outcome.error() != null && causes(outcome.error()).stream().anyMatch(DbacEnforcedExecution.Refusal.class::isInstance)) {
            violations.add("a failed rollback is a failure, not a refusal");
        }
        expect(violations, "rollbacks tried", 1, spy.rollbacks.get());
        expect(violations, "the connection aborted", 1, spy.aborts.get());
        expect(violations, "the context severed", true, context.getConnectionOrNull() == null);
        expect(violations, "the registry's state", TransactionTaintRegistry.State.BLOCKED, stateOf(context));
        expectSeveredAndNothingCommitted(violations, target.schema, spy.backend);
        Assertions.assertEquals(List.of(), violations, "TA-9");
    }

    /**
     * TA-10: the explicit rollback takes no grant key or user lock, borrows no metadata connection and writes no audit row
     * <p>
     * The case holds the grant key's and the user's write locks itself - as a revoke and a deactivation would - and
     * also lets a real revoke queue for the grant key behind a reader. The rollback finishes while they wait.
     */
    @Test
    public void ta10TheExplicitRollbackNeedsNothingOfThePolicy() throws Exception {
        List<String> violations = new ArrayList<>();
        EnforcementTestSupport.Target target = writableTarget();
        EnforcementTestSupport.openTransaction(target, 78);
        DbAccessKey key = accessKey(target);
        long borrows = metadataBorrows();
        final int allowed = audits(target, EnforcementTestSupport.EVENT_WRITE_ALLOWED);
        final int denied = audits(target, EnforcementTestSupport.EVENT_WRITE_DENIED);
        try (Hold grant = Hold.grantWrite(key); Hold user = Hold.userWrite(target.subject.userId())) {
            EnforcementTestSupport.Outcome outcome = EnforcementTestSupport.rollback(target);
            expect(violations, "the rollback while both writers hold their locks", true, outcome.succeeded());
        }
        Worker<Object> revoke;
        try (KeyLockTestSupport.Reader reader = KeyLockTestSupport.Reader.ofGrant(key)) {
            revoke = Worker.start("dbac-tea-revoke", () -> {
                EnforcementTestSupport.revoke(target.key());
                return null;
            });
            Assertions.assertTrue(KeyLockTestSupport.awaitParked(revoke.thread), "FIXTURE: the revoke must wait for the grant key");
            EnforcementTestSupport.openTransaction(target, 79);
            EnforcementTestSupport.Outcome outcome = EnforcementTestSupport.rollback(target);
            expect(violations, "the rollback while a revoke waits", true, outcome.succeeded());
            reader.release();
        }
        final boolean revoked = revoke.awaitDone() && revoke.error == null;
        expect(violations, "metadata borrows", borrows, metadataBorrows());
        expect(violations, "WRITE_ALLOWED rows", allowed, audits(target, EnforcementTestSupport.EVENT_WRITE_ALLOWED));
        expect(violations, "WRITE_DENIED rows", denied, audits(target, EnforcementTestSupport.EVENT_WRITE_DENIED));
        expect(violations, "committed", 0, target.committedValue());
        Assertions.assertEquals(List.of(), violations, "TA-10");
        Assertions.assertTrue(revoked, "FIXTURE: the revoke must finish once the key is free");
    }

    /**
     * TA-11: from the adapter's {@code rollback()}, nothing reaches the policy - so a failed or stopping policy service cannot stop it
     * <p>
     * Read from the adapter's bytecode: every method {@code rollback()} can reach inside the adapter calls nothing of
     * the gate, the policy service holder or service, the key locks, the metadata leases or the audit writer; it does
     * reach the registry's release after an explicit rollback, and its block.
     */
    @Test
    public void ta11TheExplicitRollbackReachesNothingOfThePolicy() throws Exception {
        List<String> violations = new ArrayList<>();
        Map<String, ClassMethods> adapter = classes(ADAPTER_CLASS);
        Set<String> reached = reachable(adapter, ADAPTER_CLASS + "#rollback");
        if (reached.isEmpty()) {
            violations.add("the adapter's rollback must be found");
        }
        Set<String> outside = new TreeSet<>();
        for (String method : reached) {
            String owner = method.substring(0, method.indexOf('#'));
            String name = method.substring(method.indexOf('#') + 1);
            for (String event : adapter.getOrDefault(owner, ClassMethods.EMPTY).events(name)) {
                if (event.startsWith("call ") && !event.startsWith("call " + ADAPTER_CLASS)) {
                    outside.add(event.substring(5));
                }
            }
        }
        for (String forbidden : List.of("EnforcementGate", "PolicyServiceHolder", "DbAccessPolicyService", "EnforcementKeyLocks",
            "MetadataLease", "BoundedMetadataConnections", "AccessAuditWriter", "DeploymentGuard")) {
            for (String target : outside) {
                if (target.contains("/" + forbidden)) {
                    violations.add("the explicit rollback reaches " + target);
                }
            }
        }
        for (String needed : List.of("TransactionTaintRegistry#releaseAfterExplicitRollback", "TransactionTaintRegistry#markBlocked")) {
            if (outside.stream().noneMatch(target -> target.contains(needed + "("))) {
                violations.add("the explicit rollback must reach " + needed);
            }
        }
        Assertions.assertEquals(List.of(), violations, "TA-11");
    }

    // ---------------------------------------------------------------- TA-12 - TA-15: auto-commit and the transaction flag

    /**
     * TA-12: auto-commit off is not gated: no key lock, no audit row, no metadata borrow - also while both writers hold their locks
     */
    @Test
    public void ta12AutoCommitOffStaysUngated() throws Exception {
        List<String> violations = new ArrayList<>();
        EnforcementTestSupport.Target target = readOnlyTarget();
        long borrows = metadataBorrows();
        final int denied = audits(target, EnforcementTestSupport.EVENT_WRITE_DENIED);
        try (Hold grant = Hold.grantWrite(accessKey(target)); Hold user = Hold.userWrite(target.subject.userId())) {
            EnforcementTestSupport.Outcome outcome = EnforcementTestSupport.setAutoCommit(target, false);
            expect(violations, "auto-commit off", true, outcome.succeeded());
        }
        expect(violations, "JDBC auto-commit afterwards", "false", EnforcementTestSupport.jdbcAutoCommitState(target));
        expect(violations, "metadata borrows", borrows, metadataBorrows());
        expect(violations, "WRITE_DENIED rows", denied, audits(target, EnforcementTestSupport.EVENT_WRITE_DENIED));
        Assertions.assertEquals(List.of(), violations, "TA-12");
    }

    /**
     * TA-13: auto-commit on while JDBC already is - though the platform's cache says otherwise - succeeds at once and calls nothing
     * <p>
     * No platform call (its cache stays false), no key lock (both writers hold theirs), no metadata borrow, no audit row.
     */
    @Test
    public void ta13AutoCommitOnWhenJdbcAlreadyIsCallsNothing() throws Exception {
        List<String> violations = new ArrayList<>();
        EnforcementTestSupport.Target target = readOnlyTarget();
        JDBCExecutionContext context = target.context();
        Assertions.assertEquals("true", EnforcementTestSupport.jdbcAutoCommitState(target), "FIXTURE: JDBC auto-commit");
        setCachedAutoCommit(context, Boolean.FALSE);
        long borrows = metadataBorrows();
        final int denied = audits(target, EnforcementTestSupport.EVENT_WRITE_DENIED);
        try (Hold grant = Hold.grantWrite(accessKey(target)); Hold user = Hold.userWrite(target.subject.userId())) {
            EnforcementTestSupport.Outcome outcome = EnforcementTestSupport.setAutoCommit(target, true);
            expect(violations, "auto-commit on", true, outcome.succeeded());
            expect(violations, "its result", Boolean.TRUE, outcome.result());
        }
        expect(violations, "the platform's cache: never called", Boolean.FALSE, cachedAutoCommit(context));
        expect(violations, "metadata borrows", borrows, metadataBorrows());
        expect(violations, "WRITE_DENIED rows", denied, audits(target, EnforcementTestSupport.EVENT_WRITE_DENIED));
        Assertions.assertEquals(List.of(), violations, "TA-13");
    }

    /**
     * TA-14: auto-commit on while JDBC is off but the cache on is never a success: blocked, no correction written
     */
    @Test
    public void ta14AutoCommitOnThatChangesNothingIsNeverASuccess() throws Exception {
        final List<String> violations = new ArrayList<>();
        EnforcementTestSupport.Target target = writableTarget();
        JDBCExecutionContext context = target.context();
        target.jdbc().setAutoCommit(false);
        Assertions.assertEquals(Boolean.TRUE, cachedAutoCommit(context), "FIXTURE: the platform's auto-commit cache");
        target.updateInTransaction(80);
        final int allowed = audits(target, EnforcementTestSupport.EVENT_WRITE_ALLOWED);
        final int denied = audits(target, EnforcementTestSupport.EVENT_WRITE_DENIED);
        EnforcementTestSupport.Outcome outcome = EnforcementTestSupport.setAutoCommit(target, true);
        expectRefused(violations, "auto-commit on", outcome, DenialReason.CONNECTION_BLOCKED);
        expect(violations, "the registry's state", TransactionTaintRegistry.State.BLOCKED, stateOf(context));
        expect(violations, "the context severed", true, context.getConnectionOrNull() == null);
        expect(violations, "WRITE_ALLOWED rows", allowed + 1, audits(target, EnforcementTestSupport.EVENT_WRITE_ALLOWED));
        expect(violations, "WRITE_DENIED rows: none after the platform call", denied,
            audits(target, EnforcementTestSupport.EVENT_WRITE_DENIED));
        expect(violations, "committed", 0, target.committedValue());
        Assertions.assertEquals(List.of(), violations, "TA-14");
    }

    /**
     * TA-15: a transaction flag that cannot be read counts as an open transaction, which the refusal rolls back
     */
    @Test
    public void ta15AnUnreadableTransactionFlagCountsAsOpen() throws Exception {
        final List<String> violations = new ArrayList<>();
        EnforcementTestSupport.Target target = readOnlyTarget();
        EnforcementTestSupport.openTransaction(target, 81);
        JDBCExecutionContext context = target.context();
        Spy spy = Spy.install(context);
        spy.autoCommitFails = true;
        EnforcementTestSupport.Outcome outcome = EnforcementTestSupport.commit(target);
        spy.autoCommitFails = false;
        expectRefused(violations, "the READ_ONLY commit", outcome, DenialReason.NO_GRANT);
        expect(violations, "rollbacks: the unreadable flag counted as open", 1, spy.rollbacks.get());
        expect(violations, "the registry's state after a rollback that worked", TransactionTaintRegistry.State.CLEAN, stateOf(context));
        expect(violations, "committed", 0, target.committedValue());
        Spy.uninstall(context, spy);
        Assertions.assertEquals(List.of(), violations, "TA-15");
    }

    // ---------------------------------------------------------------- TA-16, TA-17: refusals and bounds

    /**
     * TA-16: a refusal is not an error the platform recovers from - it would retry the call - one call is one attempt, and the
     * user is shown the reason with no internal frames
     */
    @Test
    public void ta16ARefusalIsNotRecovered() throws Exception {
        List<String> violations = new ArrayList<>();
        EnforcementTestSupport.Target target = readOnlyTarget();
        EnforcementTestSupport.openTransaction(target, 82);
        int denied = audits(target, EnforcementTestSupport.EVENT_WRITE_DENIED);
        EnforcementTestSupport.Outcome outcome = EnforcementTestSupport.commit(target);
        expectRefused(violations, "the READ_ONLY commit", outcome, DenialReason.NO_GRANT);
        if (outcome.error() != null) {
            for (Throwable one : causes(outcome.error())) {
                DBPErrorAssistant.ErrorType type = DBExecUtils.discoverErrorType(target.container.getDataSource(), one);
                if (type == DBPErrorAssistant.ErrorType.CONNECTION_LOST || type == DBPErrorAssistant.ErrorType.TRANSACTION_ABORTED) {
                    violations.add("the refusal reads as " + type + " in " + one.getClass().getName());
                }
            }
            if (causes(outcome.error()).stream().noneMatch(DbacEnforcedExecution.Refusal.class::isInstance)) {
                violations.add("the failure must carry the adapter's refusal");
            }
            // What the GraphQL client is given of the task's error: the reason and its code, no internal frames
            WebServerError shown = new WebServerError(outcome.error());
            expect(violations, "the message the user is shown", DenialReason.NO_GRANT.userMessage() + " ["
                + DenialReason.NO_GRANT.messageCode() + "]", shown.getMessage());
            expect(violations, "internal frames in the stack trace the user is shown", false, shown.getStackTrace().contains("\tat "));
        }
        expect(violations, "WRITE_DENIED rows: one attempt", denied + 1, audits(target, EnforcementTestSupport.EVENT_WRITE_DENIED));
        Assertions.assertEquals(List.of(), violations, "TA-16");
    }

    /**
     * TA-17: a rollback the network never answers is cut off by the connection's network timeout: aborted, severed, blocked
     * <p>
     * The target is reached through a forwarder the case can freeze. The READ_ONLY commit is refused; its rollback,
     * under the key locks, waits on a frozen network, and must return within the adapter's network timeout plus a
     * margin: the connection aborted rather than handed back, the context severed and blocked, the key locks free.
     * The server, once its client is gone, ends the transaction.
     */
    @Test
    public void ta17ARollbackTheNetworkNeverAnswersIsBounded() throws Exception {
        final List<String> violations = new ArrayList<>();
        Forwarder forwarder = new Forwarder();
        closeAfter.add(forwarder);
        ForwardedTarget target = ForwardedTarget.open(fixtures.user, forwarder);
        closeAfter.add(target);
        JDBCExecutionContext context = target.context();
        context.setAutoCommit(MONITOR, false);
        Connection jdbc = context.getConnection(MONITOR);
        final int backend = EnforcementTestSupport.backendPid(jdbc);
        EnforcementTestSupport.execute(jdbc, "UPDATE " + target.schema + ".t SET v = 83 WHERE id = 1");
        final DbAccessKey key = new DbAccessKey(target.userId, target.container.getProject().getId(), target.container.getId());
        forwarder.frozen.set(true);
        long start = System.nanoTime();
        EnforcementTestSupport.Outcome outcome = EnforcementTestSupport.await(target.sqlContext.commitTransaction());
        long millis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
        forwarder.frozen.set(false);
        long bound = 10_000 + 15_000;
        if (!outcome.completed() || millis > bound) {
            violations.add("the refused commit must return within the network timeout plus a margin, took " + millis + "ms, completed="
                + outcome.completed());
        }
        expectRefused(violations, "the READ_ONLY commit", outcome, DenialReason.NO_GRANT);
        expect(violations, "the registry's state", TransactionTaintRegistry.State.BLOCKED, stateOf(context));
        expect(violations, "the context severed", true, context.getConnectionOrNull() == null);
        expect(violations, "the grant key free", 0, readLocks(true, key.userId(), key));
        expect(violations, "the user free", 0, readLocks(false, target.userId, null));
        expectSeveredAndNothingCommitted(violations, target.schema, backend);
        Assertions.assertEquals(List.of(), violations, "TA-17");
    }

    // ---------------------------------------------------------------- TA-18: the adapter's surface

    /**
     * TA-18: the adapter offers its three calls, its source and its refusal - no decision, window, budget, writer or test seam
     */
    @Test
    public void ta18TheAdapterOffersNothingElse() throws Exception {
        List<String> violations = new ArrayList<>();
        Class<?> adapter = DbacEnforcedExecution.class;
        expect(violations, "final", true, Modifier.isFinal(adapter.getModifiers()));
        Set<String> methods = new TreeSet<>();
        for (Method method : adapter.getDeclaredMethods()) {
            if (Modifier.isPublic(method.getModifiers())) {
                methods.add(method.getName());
            }
        }
        expect(violations, "public methods", new TreeSet<>(List.of("autoCommitOn", "commit", "rollback")), methods);
        Set<String> fields = new TreeSet<>();
        for (Field field : adapter.getDeclaredFields()) {
            if (!Modifier.isPrivate(field.getModifiers())) {
                fields.add(field.getName());
            }
        }
        for (String field : fields) {
            Field one = adapter.getDeclaredField(field);
            if (!Modifier.isStatic(one.getModifiers()) || !Modifier.isFinal(one.getModifiers())) {
                violations.add("a field that is not a constant: " + field);
            }
        }
        Set<String> types = new TreeSet<>();
        for (Class<?> type : adapter.getDeclaredClasses()) {
            if (Modifier.isPublic(type.getModifiers())) {
                types.add(type.getSimpleName());
            }
        }
        expect(violations, "public nested types", new TreeSet<>(List.of("Refusal", "Source")), types);
        for (java.lang.reflect.Constructor<?> constructor : adapter.getDeclaredConstructors()) {
            if (!Modifier.isPrivate(constructor.getModifiers())) {
                violations.add("a constructor that is not private: " + constructor);
            }
        }
        for (java.lang.reflect.Constructor<?> constructor : DbacEnforcedExecution.Refusal.class.getDeclaredConstructors()) {
            if (Modifier.isPublic(constructor.getModifiers())) {
                violations.add("a refusal anyone can make: " + constructor);
            }
        }
        for (Map.Entry<String, ClassMethods> one : classes(ADAPTER_CLASS).entrySet()) {
            for (String referenced : one.getValue().classRefs) {
                for (String forbidden : List.of("AuthorizationDecision", "DbAccessPolicyService", "MetadataBudget", "AccessAuditWriter",
                    "PolicyServiceHolder", "EnforcementKeyLocks", "DeploymentGuard", "MetadataLease")) {
                    if (referenced.contains("/" + forbidden)) {
                        violations.add(one.getKey() + " refers to " + referenced);
                    }
                }
            }
            for (String event : one.getValue().allEvents()) {
                if (event.startsWith("call io/cloudbeaver/service/dbac/policy/enforcement/EnforcementGate#of(")) {
                    violations.add(one.getKey() + " makes a gate of its own");
                }
            }
        }
        Assertions.assertEquals(List.of(), violations, "TA-18");
    }

    // ---------------------------------------------------------------- TA-19: a policy service that is down

    /**
     * TA-19: while the policy service is failed or disposed, the explicit rollback still works and releases a blocked context
     * <p>
     * The case blocks the context through an auto-commit on whose postcondition failed, lets the platform reconnect it,
     * opens a transaction on the new connection, and puts the server's policy service holder into {@code Failed} - and
     * in a second round {@code Disposed} - through the holder's private state, put back afterwards. The explicit
     * rollback works meanwhile and leaves the context clean, and nothing is committed.
     */
    @Test
    public void ta19TheExplicitRollbackWorksWhileThePolicyServiceIsDown() throws Exception {
        List<String> violations = new ArrayList<>();
        EnforcementTestSupport.Target target = writableTarget();
        JDBCExecutionContext context = target.context();
        int value = 84;
        for (String down : List.of("Failed", "Disposed")) {
            target.jdbc().setAutoCommit(false);
            target.updateInTransaction(value++);
            expectRefused(violations, down + ": auto-commit on with JDBC off and the cache on",
                EnforcementTestSupport.setAutoCommit(target, true), DenialReason.CONNECTION_BLOCKED);
            expect(violations, down + ": the registry's state after the failed postcondition", TransactionTaintRegistry.State.BLOCKED,
                stateOf(context));
            // Without the block the old connection may still hold the row, and the steps below would wait for it
            Assertions.assertEquals(List.of(), violations, "TA-19: the block");
            context.invalidateContext(MONITOR, DBCInvalidatePhase.INVALIDATE);
            Connection jdbc = target.jdbc();
            EnforcementTestSupport.execute(jdbc, "SET lock_timeout = '20s'");
            jdbc.setAutoCommit(false);
            target.updateInTransaction(value++);
            try (HolderDown ignored = HolderDown.to(down)) {
                EnforcementTestSupport.Outcome rollback = EnforcementTestSupport.rollback(target);
                expect(violations, down + ": the explicit rollback", true, rollback.succeeded());
                expect(violations, down + ": the registry's state after it", TransactionTaintRegistry.State.CLEAN, stateOf(context));
            }
            expect(violations, down + ": committed", 0, target.committedValue());
        }
        Assertions.assertEquals(List.of(), violations, "TA-19");
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

    // ---------------------------------------------------------------- targets

    /**
     * A target with no grant, whose connection waits for a row lock at most 20 seconds - a transaction a defect left
     * open on a connection the context no longer has would otherwise hold the row for good
     */
    @NotNull
    private static EnforcementTestSupport.Target readOnlyTarget() throws Exception {
        EnforcementTestSupport.Target target = fixtures.readOnlyTarget(fixtures.user);
        EnforcementTestSupport.execute(target.jdbc(), "SET lock_timeout = '20s'");
        return target;
    }

    /** A target with a live grant, bounded as {@link #readOnlyTarget()} is */
    @NotNull
    private static EnforcementTestSupport.Target writableTarget() throws Exception {
        EnforcementTestSupport.Target target = readOnlyTarget();
        EnforcementTestSupport.grant(target.key());
        return target;
    }

    // ---------------------------------------------------------------- holds

    /** What a TA-1 stage holds: X, M, the grant key K or the user U */
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
            this.worker = Worker.start("dbac-tea-hold-" + name, () -> {
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

    // ---------------------------------------------------------------- the connection, wrapped

    /**
     * A proxy put in the place of the context's JDBC connection: everything goes to the real one, except where the case
     * makes the auto-commit flag unreadable or the rollback fail; rollbacks and aborts are counted
     */
    private static final class Spy {
        final Connection real;
        final Connection proxy;
        final int backend;
        final AtomicInteger rollbacks = new AtomicInteger();
        final AtomicInteger aborts = new AtomicInteger();
        volatile boolean rollbackFails;
        volatile boolean autoCommitFails;

        private Spy(@NotNull Connection real) throws SQLException {
            this.real = real;
            this.backend = EnforcementTestSupport.backendPid(real);
            this.proxy = (Connection) Proxy.newProxyInstance(TransactionEnforcementAdapterTest.class.getClassLoader(),
                new Class<?>[]{Connection.class}, (self, method, args) -> {
                    switch (method.getName()) {
                        case "rollback" -> {
                            if (aborts.get() == 0) {
                                // After the abort the platform's close rolls back too, on a thread of its own
                                rollbacks.incrementAndGet();
                            }
                            if (rollbackFails) {
                                throw new SQLException("injected: the rollback fails", "08006");
                            }
                        }
                        case "getAutoCommit" -> {
                            if (autoCommitFails && calledFromAdapter()) {
                                throw new SQLException("injected: the flag cannot be read");
                            }
                        }
                        case "abort" -> aborts.incrementAndGet();
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

        @NotNull
        static Spy install(@NotNull JDBCExecutionContext context) throws Exception {
            Spy spy = new Spy(context.getConnection(MONITOR));
            setConnection(context, spy.proxy);
            return spy;
        }

        static void uninstall(@NotNull JDBCExecutionContext context, @NotNull Spy spy) throws Exception {
            if (context.getConnectionOrNull() == spy.proxy) {
                setConnection(context, spy.real);
            }
        }
    }

    /** Whether the proxied call was made by the adapter itself, rather than by the platform */
    private static boolean calledFromAdapter() {
        StackTraceElement[] stack = new Throwable().getStackTrace();
        for (int i = 0; i < stack.length - 1; i++) {
            if (stack[i].getClassName().contains("$Proxy")) {
                return stack[i + 1].getClassName().startsWith(ADAPTER);
            }
        }
        return false;
    }

    /**
     * Puts {@code replacement} in the place of the context's connection; the one taken out is closed after the case, so
     * a transaction a defect left open on it cannot hold its row through the cleanup
     */
    private void swapConnection(@NotNull JDBCExecutionContext context, @NotNull Connection replacement) throws Exception {
        Connection original = context.getConnectionOrNull();
        if (original != null) {
            closeAfter.add(original);
        }
        setConnection(context, replacement);
    }

    private static void setConnection(@NotNull JDBCExecutionContext context, @Nullable Connection connection) throws Exception {
        Field field = JDBCExecutionContext.class.getDeclaredField("connection");
        field.setAccessible(true);
        field.set(context, connection);
    }

    private static void setCachedAutoCommit(@NotNull JDBCExecutionContext context, @Nullable Boolean value) throws Exception {
        Field field = JDBCExecutionContext.class.getDeclaredField("autoCommit");
        field.setAccessible(true);
        field.set(context, value);
    }

    @Nullable
    private static Boolean cachedAutoCommit(@NotNull JDBCExecutionContext context) throws Exception {
        Field field = JDBCExecutionContext.class.getDeclaredField("autoCommit");
        field.setAccessible(true);
        return (Boolean) field.get(context);
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

    // ---------------------------------------------------------------- a target behind a forwarder

    /**
     * A TCP forwarder in front of the PostgreSQL target that the case can freeze: while frozen, it passes no byte either way
     */
    private static final class Forwarder implements AutoCloseable {
        final AtomicBoolean frozen = new AtomicBoolean();
        final ServerSocket server;
        private final List<Socket> sockets = new CopyOnWriteArrayList<>();
        private final String[] target = EnforcementTestSupport.urlParts();
        private volatile boolean closed;

        Forwarder() throws IOException {
            this.server = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
            Thread acceptor = new Thread(this::accept, "dbac-tea-forwarder");
            acceptor.setDaemon(true);
            acceptor.start();
        }

        int port() {
            return server.getLocalPort();
        }

        private void accept() {
            while (!closed) {
                try {
                    Socket client = server.accept();
                    Socket upstream = new Socket(target[0], Integer.parseInt(target[1]));
                    sockets.add(client);
                    sockets.add(upstream);
                    pump(client, upstream);
                    pump(upstream, client);
                } catch (IOException e) {
                    return;
                }
            }
        }

        private void pump(@NotNull Socket from, @NotNull Socket to) {
            Thread thread = new Thread(() -> {
                byte[] buffer = new byte[8192];
                try (InputStream in = from.getInputStream(); OutputStream out = to.getOutputStream()) {
                    while (true) {
                        int read = in.read(buffer);
                        if (read < 0) {
                            break;
                        }
                        while (frozen.get() && !closed) {
                            Thread.sleep(20);
                        }
                        out.write(buffer, 0, read);
                        out.flush();
                    }
                } catch (IOException | InterruptedException ignored) {
                    // one side closed; the other is closed below
                } finally {
                    close(from);
                    close(to);
                }
            }, "dbac-tea-forwarder-pump");
            thread.setDaemon(true);
            thread.start();
        }

        private static void close(@NotNull Socket socket) {
            try {
                socket.close();
            } catch (IOException ignored) {
                // already closed
            }
        }

        @Override
        public void close() throws IOException {
            closed = true;
            frozen.set(false);
            server.close();
            for (Socket socket : sockets) {
                close(socket);
            }
        }
    }

    /** A connection to the PostgreSQL target through a forwarder, registered in the user's session, with a fixture schema */
    private static final class ForwardedTarget implements AutoCloseable {
        final String userId;
        final String schema;
        final WebSessionProjectImpl project;
        final DataSourceDescriptor container;
        final WebSQLContextInfo sqlContext;
        final WebSQLProcessor processor;

        private ForwardedTarget(@NotNull String userId, @NotNull String schema, @NotNull WebSessionProjectImpl project,
                                @NotNull DataSourceDescriptor container, @NotNull WebSQLProcessor processor,
                                @NotNull WebSQLContextInfo sqlContext) {
            this.userId = userId;
            this.schema = schema;
            this.project = project;
            this.container = container;
            this.processor = processor;
            this.sqlContext = sqlContext;
        }

        @NotNull
        static ForwardedTarget open(@NotNull EnforcementTestSupport.Subject subject, @NotNull Forwarder forwarder) throws Exception {
            EnforcementTestSupport.requirePostgres(MONITOR);
            String schema = "dbac_tea_" + Long.toHexString(System.nanoTime());
            try (Connection raw = EnforcementTestSupport.openRawPostgres(MONITOR)) {
                EnforcementTestSupport.execute(raw, "CREATE SCHEMA " + schema);
                EnforcementTestSupport.execute(raw, "CREATE TABLE " + schema + ".t (id INT PRIMARY KEY, v INT NOT NULL)");
                EnforcementTestSupport.execute(raw, "INSERT INTO " + schema + ".t (id, v) VALUES (1, 0)");
            }
            WebSessionProjectImpl project = subject.session().getGlobalProject() != null
                ? subject.session().getGlobalProject()
                : subject.session().getSingletonProject();
            String[] parts = EnforcementTestSupport.urlParts();
            DBPConnectionConfiguration configuration = new DBPConnectionConfiguration();
            configuration.setConfigurationType(DBPDriverConfigurationType.MANUAL);
            configuration.setHostName("127.0.0.1");
            configuration.setHostPort(String.valueOf(forwarder.port()));
            configuration.setDatabaseName(parts[2]);
            configuration.setUserName(EnforcementTestSupport.PG_USER);
            configuration.setUserPassword(EnforcementTestSupport.PG_PASSWORD);
            DBPDriver driver = EnforcementTestSupport.postgresDriverDescriptor();
            DataSourceDescriptor container = project.getDataSourceRegistry().createDataSource(
                DataSourceDescriptor.generateNewId(driver), driver, configuration);
            container.setName("DBAC P6-A " + schema);
            container.setSavePassword(true);
            container.setTemporary(true);
            container.connect(MONITOR, true, true);
            project.getDataSourceRegistry().addDataSource(container);
            WebConnectionInfo connectionInfo = project.addConnection(container);
            WebSQLProcessor processor = WebServiceBindingSQL.getSQLProcessor(connectionInfo);
            WebSQLContextInfo sqlContext = processor.createContext(null, null, project.getId());
            return new ForwardedTarget(subject.userId(), schema, project, container, processor, sqlContext);
        }

        @NotNull
        JDBCExecutionContext context() {
            return (JDBCExecutionContext) processor.getExecutionContext();
        }

        @Override
        public void close() throws Exception {
            try {
                container.disconnect(MONITOR);
                container.getRegistry().removeDataSource(container);
                project.removeConnection(container);
            } finally {
                try (Connection raw = EnforcementTestSupport.openRawPostgres(MONITOR)) {
                    EnforcementTestSupport.execute(raw, "DROP SCHEMA IF EXISTS " + schema + " CASCADE");
                }
            }
        }
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
        System.out.println("[DBAC P6-A] no adapter thread was seen at " + what);
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
        int total = 0;
        List<DbOperationCategory> gated = List.of(DbOperationCategory.TRANSACTION_COMMIT, DbOperationCategory.TRANSACTION_AUTOCOMMIT_ON);
        for (DbOperationCategory category : gated) {
            total += EnforcementTestSupport.countAudit(target.key(), type, category);
        }
        return total;
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

    /** A class's methods, each as the ordered calls and monitor instructions it contains, and the classes it refers to */
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

    /** The calls and monitor instructions of one method's code, in order */
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
