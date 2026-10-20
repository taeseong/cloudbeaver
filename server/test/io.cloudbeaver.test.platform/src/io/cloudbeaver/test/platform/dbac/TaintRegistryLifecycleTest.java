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
import io.cloudbeaver.service.dbac.DbacSecurityControllerFactory;
import io.cloudbeaver.service.dbac.PolicyServiceHolder;
import io.cloudbeaver.service.dbac.PolicyServiceHolder.Disposed;
import io.cloudbeaver.service.dbac.PolicyServiceHolder.Ready;
import io.cloudbeaver.service.dbac.PolicyServiceHolder.Stopping;
import io.cloudbeaver.service.dbac.policy.enforcement.TaintContextCloseHandler;
import io.cloudbeaver.service.dbac.policy.enforcement.TransactionTaintRegistry;
import io.cloudbeaver.service.dbac.policy.enforcement.TransactionTaintRegistry.Operation;
import io.cloudbeaver.service.dbac.policy.enforcement.TransactionTaintRegistry.Probe;
import io.cloudbeaver.service.dbac.policy.enforcement.TransactionTaintRegistry.State;
import io.cloudbeaver.service.security.db.CBDatabase;
import io.cloudbeaver.test.platform.dbac.KeyLockTestSupport.Worker;
import io.cloudbeaver.test.platform.dbac.LifecycleTestSupport.Captured;
import io.cloudbeaver.test.platform.dbac.LifecycleTestSupport.Fault;
import io.cloudbeaver.test.platform.dbac.LifecycleTestSupport.Fixture;
import io.cloudbeaver.test.platform.dbac.LifecycleTestSupport.TestFactory;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.jkiss.dbeaver.model.exec.DBCExecutionContext;
import org.jkiss.dbeaver.model.impl.jdbc.JDBCExecutionContext;
import org.jkiss.dbeaver.model.qm.QMUtils;
import org.jkiss.dbeaver.model.runtime.DBRProgressMonitor;
import org.jkiss.dbeaver.model.runtime.LoggingProgressMonitor;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.lang.ref.Reference;
import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Member;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BiConsumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * P5-2: the transaction taint registry - what it remembers about a context, whose context it is, and when it stops
 * <p>
 * Isolated registries are used everywhere but in TR-2 and TR-12, which look at the server's production wiring: the
 * global registry is never closed by a test. A pause inside the registry's lifecycle lock is made by its test probe,
 * so every interleaving here is forced, not hoped for.
 */
@Timeout(value = 300, unit = TimeUnit.SECONDS, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
public class TaintRegistryLifecycleTest {

    /** How long a test waits for a thread to reach a pause or to finish */
    private static final long WAIT_SECONDS = 10;
    /** How many polls in a row a waiting thread must be seen parked */
    private static final int PARKED_POLLS = 20;
    /** What no log line may carry */
    private static final List<String> FORBIDDEN_LOG_FRAGMENTS = List.of(LifecycleTestSupport.SECRET_MARKER,
        LifecycleTestSupport.CREDENTIAL_FRAGMENT, "secret-host", "injected at");
    /** Types the registry's public surface may not mention */
    private static final List<String> FORBIDDEN_TYPE_PREFIXES = List.of("org.jkiss.dbeaver.model.exec", "org.jkiss.dbeaver.model.impl",
        "org.jkiss.dbeaver.model.qm", "org.jkiss.dbeaver.model.sql", "org.jkiss.dbeaver.model.connection", "java.sql", "javax.sql",
        "java.lang.ref");

    private static EnforcementTestSupport.Fixtures fixtures;

    private final DBRProgressMonitor monitor = new LoggingProgressMonitor();

    @BeforeAll
    public static void startServer() throws Exception {
        CEAppStarter.startServerIfNotStarted();
        fixtures = EnforcementTestSupport.fixtures("tr", new LoggingProgressMonitor());
    }

    @AfterAll
    public static void afterAll() throws Exception {
        fixtures.afterAll();
    }

    // ---------------------------------------------------------------- TR-2: the production wiring hears a real close

    /**
     * TR-2: a real execution context closed through the platform leaves no entry in the server's registry, at once
     * <p>
     * The close notification is synchronous on the closing thread (CH-7), so the entry is gone when {@code close()} returns.
     */
    @Test
    public void tr2ARealCloseRemovesTheEntryAtOnce() throws Exception {
        TransactionTaintRegistry registry = TransactionTaintRegistry.global();
        try (EnforcementTestSupport.Target target = openTarget()) {
            JDBCExecutionContext context = isolated(target);
            long id = context.getContextId();
            try {
                int before = registry.trackedContexts();
                Assertions.assertTrue(registry.markTainted(id, context), "TR-2: the server's registry is open");
                Assertions.assertEquals(State.TAINTED, registry.state(id, context), "TR-2: the context is tainted before it closes");
                Assertions.assertEquals(before + 1, registry.trackedContexts(), "TR-2: one entry for the context");
                context.close();
                Assertions.assertEquals(State.CLEAN, registry.state(id, context), "TR-2: right after the close returns, the entry is gone");
                Assertions.assertEquals(before, registry.trackedContexts(), "TR-2: and the registry holds nothing for it");
            } finally {
                registry.contextClosed(id);
            }
        }
        Assertions.assertEquals(0, registry.trackedContexts(), "TR-2: nothing is left in the server's registry");
    }

    // ---------------------------------------------------------------- TR-6: the weak backstop

    /**
     * TR-6: an entry whose context was collected without a close is removed by the next operation on any context
     * <p>
     * The reference queue is drained at the start of every public operation, a bounded number at a time; a context
     * nobody looks up again does not stay behind.
     */
    @Test
    public void tr6ACollectedContextLeavesNoEntry() throws Exception {
        TransactionTaintRegistry registry = TransactionTaintRegistry.isolated();
        Object doomed = new Object();
        registry.markBlocked(9, doomed);
        WeakReference<Object> gone = new WeakReference<>(doomed);
        Assertions.assertEquals(1, registry.trackedContexts(), "TR-6: the blocked context is tracked while it lives");
        doomed = null;
        collect(gone, "TR-6");
        Object other = new Object();
        Assertions.assertTrue(eventually(() -> {
            registry.state(10, other);
            return registry.trackedContexts() == 0;
        }), "TR-6: an operation on another context must remove the collected one's entry");
        Assertions.assertNull(pendingReference(registry), "TR-6: and its reference must have left the queue");

        // Bounded: one operation never drains more than EXPUNGE_LIMIT references, and they all go in the end
        int stale = 3 * TransactionTaintRegistry.EXPUNGE_LIMIT + 5;
        List<Object> held = new ArrayList<>();
        List<WeakReference<Object>> many = new ArrayList<>();
        for (int i = 0; i < stale; i++) {
            Object context = new Object();
            held.add(context);
            if (i % 2 == 0) {
                registry.markBlocked(1000 + i, context);
            } else {
                registry.markTainted(1000 + i, context);
            }
            many.add(new WeakReference<>(context));
        }
        Assertions.assertEquals(stale, registry.trackedContexts(), "TR-6: every stale context was tracked while it lived");
        held.clear();
        for (WeakReference<Object> reference : many) {
            collect(reference, "TR-6");
        }
        int previous = stale;
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(WAIT_SECONDS);
        while (previous > 0 && System.nanoTime() < deadline) {
            int now = registry.trackedContexts();
            Assertions.assertTrue(previous - now <= TransactionTaintRegistry.EXPUNGE_LIMIT,
                "TR-6: one operation drained " + (previous - now) + " references, more than " + TransactionTaintRegistry.EXPUNGE_LIMIT);
            previous = now;
            if (now > 0) {
                Thread.sleep(5);
            }
        }
        Assertions.assertEquals(0, previous, "TR-6: every collected context must be removed in the end");
        Assertions.assertNull(pendingReference(registry), "TR-6: and the queue must be empty");
    }

    // ---------------------------------------------------------------- TR-7: clear against an operation

    /**
     * TR-7: clear and an operation already under way are ordered by the lifecycle lock - no entry survives a clear
     */
    @Test
    public void tr7ClearIsOrderedAfterAnOperationAlreadyUnderWay() throws Exception {
        // 1. a mark paused inside the lock holds the clear back; it completes, then the clear removes what it made
        Pause pause = new Pause(Operation.MARK_TAINTED, 70);
        TransactionTaintRegistry registry = TransactionTaintRegistry.isolated(pause);
        Object context = new Object();
        Worker<Boolean> mark = Worker.start("dbac-tr7-mark", () -> registry.markTainted(70, context));
        Worker<Object> clear = null;
        try {
            Assertions.assertTrue(pause.reached(), "TR-7: the mark must pause inside the lifecycle lock");
            clear = Worker.start("dbac-tr7-clear", () -> {
                registry.clear();
                return null;
            });
            Assertions.assertTrue(awaitParked(clear.thread), "TR-7: the clear must wait for the mark under way");
        } finally {
            pause.release();
        }
        Assertions.assertEquals(Boolean.TRUE, mark.get("TR-7 mark"), "TR-7: the mark began while the registry was open");
        Assertions.assertNotNull(clear, "FIXTURE TR-7: the clear was never started");
        clear.get("TR-7 clear");
        Assertions.assertFalse(registry.isOpen(), "TR-7: the clear closes the registry");
        Assertions.assertEquals(0, registry.trackedContexts(), "TR-7: the clear removes what the mark made before it");

        // 2. a clear that comes first turns the mark into nothing
        TransactionTaintRegistry closed = TransactionTaintRegistry.isolated();
        closed.clear();
        Assertions.assertFalse(closed.markTainted(71, context), "TR-7: a mark after the clear reports that nothing was recorded");
        Assertions.assertFalse(closed.markBlocked(71, context), "TR-7: so does a block");
        Assertions.assertEquals(0, closed.trackedContexts(), "TR-7: and nothing is recorded");

        // 3. a close and a mark race: each takes effect when it reaches the entry
        Assertions.assertEquals(State.TAINTED, interleave(State.CLEAN, Operation.MARK_TAINTED, Operation.CONTEXT_CLOSED),
            "TR-7: a mark that reaches the entry after the close leaves it tainted");
        Assertions.assertEquals(State.CLEAN, interleave(State.CLEAN, Operation.CONTEXT_CLOSED, Operation.MARK_TAINTED),
            "TR-7: a close that reaches the entry after the mark removes it");
    }

    // ---------------------------------------------------------------- TR-8: whose context it is

    /**
     * TR-8: an id belongs to one live object; another live object with that id is refused, a collected one is forgotten
     */
    @Test
    public void tr8AnIdBelongsToOneLiveObject() throws Exception {
        TransactionTaintRegistry registry = TransactionTaintRegistry.isolated();
        Twin owner = new Twin();
        Twin impostor = new Twin();
        Assertions.assertEquals(owner, impostor, "FIXTURE TR-8: the two objects are equal and still not the same object");
        Assertions.assertTrue(registry.markBlocked(80, owner), "TR-8: the owner is blocked");
        List<String> accepted = new ArrayList<>();
        for (Operation operation : Operation.values()) {
            if (operation == Operation.CONTEXT_CLOSED) {
                continue;
            }
            try {
                apply(registry, operation, 80, impostor);
                accepted.add(operation.name());
            } catch (IllegalStateException expected) {
                // refused: the id belongs to a live object that is not this one
            }
        }
        Assertions.assertEquals(List.of(), accepted, "TR-8: an equal but different live object must be refused by every operation");
        Assertions.assertEquals(State.BLOCKED, registry.state(80, owner), "TR-8: a refused operation leaves the owner's entry as it was");

        // As between a collection and its enqueue: the reference is not in the queue, the lookup itself must see it is stale
        collectBlocked(registry, 81);
        Object successor = new Object();
        Assertions.assertEquals(State.CLEAN, registry.state(81, successor),
            "TR-8: a collected owner's entry is stale - the next object with its id starts clean, never blocked");
        Assertions.assertTrue(registry.markTainted(81, successor), "TR-8: the successor can be marked");
        Assertions.assertEquals(State.TAINTED, registry.state(81, successor),
            "TR-8: tainted, not the collected owner's block");

        // The same for a change with no lookup before it: the mark itself must see the entry is stale
        collectBlocked(registry, 82);
        Object markedFirst = new Object();
        Assertions.assertTrue(registry.markTainted(82, markedFirst), "TR-8: a mark on a stale entry is recorded");
        Assertions.assertEquals(State.TAINTED, registry.state(82, markedFirst),
            "TR-8: a mark on a stale entry starts from clean, never from the collected owner's block");

        // A context the caller does not name is refused before anything is looked at, and the registry stays usable
        List<String> acceptedNull = new ArrayList<>();
        for (Operation operation : Operation.values()) {
            if (operation == Operation.CONTEXT_CLOSED) {
                continue;
            }
            try {
                apply(registry, operation, 84, null);
                acceptedNull.add(operation.name());
            } catch (NullPointerException expected) {
                // refused: no identity
            }
        }
        Assertions.assertEquals(List.of(), acceptedNull, "TR-8: every operation that takes an identity must refuse none");
        Object usable = new Object();
        Assertions.assertTrue(registry.markTainted(84, usable), "TR-8: the registry stays usable after a refused null");
        Assertions.assertEquals(State.TAINTED, registry.state(84, usable), "TR-8: and records as before");

        Reference.reachabilityFence(owner);
        for (long id : new long[]{80, 81, 82, 84}) {
            registry.contextClosed(id);
        }
        Assertions.assertEquals(0, registry.trackedContexts(), "TR-8: nothing left");
    }

    /**
     * Blocks a context that is then collected, and takes the registry's reference to it out of the queue - so that only
     * the stale entry itself says the context is gone
     */
    private static void collectBlocked(@NotNull TransactionTaintRegistry registry, long id) throws Exception {
        Object doomed = new Object();
        registry.markBlocked(id, doomed);
        WeakReference<Object> gone = new WeakReference<>(doomed);
        Assertions.assertEquals(State.BLOCKED, registry.state(id, doomed), "TR-8: blocked while it lives");
        doomed = null;
        collect(gone, "TR-8");
        Reference<?> drained = drainOwnReference(registry, gone);
        Assertions.assertNotNull(drained, "TR-8: the registry tracks a collected context through its own reference queue");
        Assertions.assertEquals(id, read(drained, "contextId"), "FIXTURE TR-8: the reference taken out is the collected context's");
    }

    // ---------------------------------------------------------------- TR-9: the real lifecycle

    /**
     * TR-9: a policy service shutting down while operations are under way leaves its registry empty and closed
     * <p>
     * The holder's cleanup plan clears the very registry the close handler reports to; a mark that began while the
     * service was Ready completes first, and anything after the clear changes nothing.
     */
    @Test
    public void tr9AShutdownLeavesTheRegistryEmptyWhateverIsUnderWay() throws Exception {
        Fixture fixture = new Fixture();
        Pause pause = new Pause(Operation.MARK_TAINTED, 900);
        TransactionTaintRegistry registry = TransactionTaintRegistry.isolated(pause);
        TestFactory factory = factory(fixture, registry);
        CBDatabase database = factory.init();
        Assertions.assertInstanceOf(Ready.class, factory.state(), "FIXTURE TR-9: the holder is Ready");
        Object ready = new Object();
        Assertions.assertTrue(registry.markTainted(901, ready), "TR-9: a mark while Ready is recorded");
        Assertions.assertEquals(State.TAINTED, registry.state(901, ready), "TR-9: and remembered");

        Object underWay = new Object();
        Worker<Boolean> mark = Worker.start("dbac-tr9-mark", () -> registry.markTainted(900, underWay));
        Worker<Throwable> stopper = null;
        try {
            Assertions.assertTrue(pause.reached(), "TR-9: the mark must pause inside the lifecycle lock");
            stopper = Worker.start("dbac-tr9-shutdown", () -> LifecycleTestSupport.shutdownCatching(database));
            Worker<Throwable> stopping = stopper;
            Assertions.assertTrue(eventually(() -> fixture.registrar.unregistered.size() == 1),
                "TR-9: the shutdown must unregister the handler first");
            Assertions.assertTrue(awaitParked(stopping.thread), "TR-9: the shutdown's clear must wait for the mark under way");
            Assertions.assertInstanceOf(Stopping.class, factory.state(), "TR-9: still Stopping while the clear waits");
        } finally {
            pause.release();
        }
        Assertions.assertEquals(Boolean.TRUE, mark.get("TR-9 mark"), "TR-9: the mark began while the registry was open");
        Assertions.assertNotNull(stopper, "FIXTURE TR-9: the shutdown was never started");
        Assertions.assertNull(stopper.get("TR-9 shutdown"), "TR-9: the shutdown must not fail");
        Assertions.assertInstanceOf(Disposed.class, factory.state(), "TR-9: the holder ends Disposed");
        Assertions.assertFalse(registry.isOpen(), "TR-9: the shutdown closed the registry");
        Assertions.assertEquals(0, registry.trackedContexts(), "TR-9: no entry survives the shutdown");

        Assertions.assertFalse(registry.markTainted(902, ready), "TR-9: a late mark records nothing");
        Assertions.assertFalse(registry.markBlocked(902, ready), "TR-9: a late block records nothing");
        Assertions.assertDoesNotThrow(() -> registry.contextClosed(901), "TR-9: a late close is harmless");
        TaintContextCloseHandler handler = (TaintContextCloseHandler) fixture.registrar.registered.get(0);
        Assertions.assertDoesNotThrow(() -> handler.handleContextClose(LifecycleTestSupport.context(901)),
            "TR-9: a handler call that was already under way when it was unregistered is harmless");
        Assertions.assertEquals(0, registry.trackedContexts(), "TR-9: still nothing");

        // Four threads that keep marking through the whole shutdown
        Fixture busy = new Fixture();
        TransactionTaintRegistry busyRegistry = TransactionTaintRegistry.isolated();
        TestFactory busyFactory = factory(busy, busyRegistry);
        final CBDatabase busyDatabase = busyFactory.init();
        Assertions.assertInstanceOf(Ready.class, busyFactory.state(), "FIXTURE TR-9: the second holder is Ready");
        AtomicBoolean stop = new AtomicBoolean();
        AtomicBoolean disposed = new AtomicBoolean();
        AtomicInteger recorded = new AtomicInteger();
        AtomicInteger recordedAfterDisposed = new AtomicInteger();
        List<Worker<Object>> gates = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            long id = 950 + i;
            Object gateContext = new Object();
            boolean block = i % 2 == 0;
            gates.add(Worker.start("dbac-tr9-gate-" + i, () -> {
                while (!stop.get()) {
                    boolean late = disposed.get();
                    if (block ? busyRegistry.markBlocked(id, gateContext) : busyRegistry.markTainted(id, gateContext)) {
                        recorded.incrementAndGet();
                        if (late) {
                            recordedAfterDisposed.incrementAndGet();
                        }
                    }
                }
                return null;
            }));
        }
        Assertions.assertTrue(eventually(() -> recorded.get() > 100), "TR-9: the gates mark while the service is Ready");
        Assertions.assertNull(LifecycleTestSupport.shutdownCatching(busyDatabase), "TR-9: the busy shutdown must not fail");
        Assertions.assertInstanceOf(Disposed.class, busyFactory.state(), "TR-9: the busy holder ends Disposed");
        disposed.set(true);
        Assertions.assertEquals(0, busyRegistry.trackedContexts(), "TR-9: no entry survives a shutdown under load");
        Thread.sleep(50);
        stop.set(true);
        for (Worker<Object> gate : gates) {
            gate.get("TR-9 gate");
        }
        Assertions.assertEquals(0, recordedAfterDisposed.get(), "TR-9: no mark that began after the shutdown is recorded");
        Assertions.assertEquals(0, busyRegistry.trackedContexts(), "TR-9: and nothing is left");
    }

    // ---------------------------------------------------------------- TR-10: failures stay in the handler

    /**
     * TR-10: a registry failure on a close never reaches the query manager's dispatcher, and is logged by class only
     */
    @Test
    public void tr10ARegistryFailureStaysInTheCloseHandler() throws Throwable {
        for (Fault fault : List.of(Fault.RUNTIME, Fault.ERROR)) {
            Failing failing = new Failing(fault);
            TransactionTaintRegistry registry = TransactionTaintRegistry.isolated(failing);
            TaintContextCloseHandler handler = new TaintContextCloseHandler(registry, () -> true);
            Captured captured = LifecycleTestSupport.captureLogs(() -> Assertions.assertDoesNotThrow(
                () -> handler.handleContextClose(LifecycleTestSupport.context(5)),
                "TR-10: a registry " + fault + " must not escape the close handler"));
            Assertions.assertEquals(List.of(5L), failing.closed(), "TR-10: the close must reach the registry, which fails with " + fault);
            checkHandlerLog("direct " + fault, fault, captured);
            Worker<Object> clear = Worker.start("dbac-tr10-clear", () -> {
                registry.clear();
                return null;
            });
            clear.get("TR-10 clear after a failed close: the failure must have left the lifecycle lock free");
            Assertions.assertFalse(registry.isOpen(), "TR-10: the clear went through after the failed close");
        }

        // Through the real query manager: the dispatcher never sees the failure, and nothing of it is logged
        Failing failing = new Failing(Fault.ERROR);
        TransactionTaintRegistry registry = TransactionTaintRegistry.isolated(failing);
        TaintContextCloseHandler handler = new TaintContextCloseHandler(registry, () -> true);
        Captured captured;
        long closed;
        try (EnforcementTestSupport.Target target = openTarget()) {
            JDBCExecutionContext context = isolated(target);
            closed = context.getContextId();
            QMUtils.registerHandler(handler);
            try {
                captured = LifecycleTestSupport.captureLogs(context::close);
            } finally {
                QMUtils.unregisterHandler(handler);
            }
        }
        Assertions.assertEquals(1, Collections.frequency(failing.closed(), closed),
            "TR-10: the real close must reach the registry once, which fails, got " + failing.closed());
        Assertions.assertEquals(1, captured.dbacMessages().stream()
                .filter(m -> m.contains("event=DBAC_TAINT_SINK_CLOSE_FAILED ")).count(),
            "TR-10: the handler logs the failure once, got " + captured.dbacMessages());
        for (String fragment : FORBIDDEN_LOG_FRAGMENTS) {
            Assertions.assertFalse(captured.text().contains(fragment), "TR-10: nothing logged carries '" + fragment + "'");
        }
        Assertions.assertFalse(captured.text().contains("Error notifying QM handler '" + handler.getHandlerName() + "'"),
            "TR-10: the dispatcher must not have been handed the failure");
    }

    /** One handler failure: one P1-safe line with the fixed code and the exception class */
    private static void checkHandlerLog(@NotNull String label, @NotNull Fault fault, @NotNull Captured captured) {
        Assertions.assertEquals(List.of(), LifecycleTestSupport.logContractViolations(captured, FORBIDDEN_LOG_FRAGMENTS),
            "TR-10: a " + label + " must be logged by the P1 contract");
        Assertions.assertEquals(1, captured.dbacMessages().size(),
            "TR-10: a " + label + " must be logged once, got " + captured.dbacMessages());
        String exception = fault == Fault.ERROR
            ? LifecycleTestSupport.InjectedError.class.getName()
            : LifecycleTestSupport.InjectedRuntimeException.class.getName();
        String message = captured.dbacMessages().get(0);
        Assertions.assertTrue(message.contains("event=DBAC_TAINT_SINK_CLOSE_FAILED ") && message.endsWith(" exception=" + exception + "]"),
            "TR-10: a " + label + " must be logged with the fixed code and the class only, got " + message);
        Assertions.assertNull(captured.dbacThrowables().get(0), "TR-10: the logger must not be handed the " + label);
    }

    // ---------------------------------------------------------------- TR-11, TR-14: the state machine

    /**
     * TR-11: a blocked context is released by an explicit rollback only; a close forgets it, nothing else does
     */
    @Test
    public void tr11OnlyAnExplicitRollbackReleasesABlock() {
        TransactionTaintRegistry registry = TransactionTaintRegistry.isolated();
        Object context = new Object();
        Assertions.assertTrue(registry.markBlocked(110, context), "TR-11: blocked");
        Assertions.assertTrue(registry.rollbackSucceeded(110, context), "TR-11: the registry is open");
        Assertions.assertEquals(State.BLOCKED, registry.state(110, context), "TR-11: a gate's own rollback does not release a block");
        registry.markTainted(110, context);
        Assertions.assertEquals(State.BLOCKED, registry.state(110, context), "TR-11: a taint does not soften a block");
        registry.markBlocked(110, context);
        Assertions.assertEquals(State.BLOCKED, registry.state(110, context), "TR-11: blocking again keeps it blocked");
        Assertions.assertTrue(registry.releaseAfterExplicitRollback(110, context), "TR-11: the registry is open");
        Assertions.assertEquals(State.CLEAN, registry.state(110, context), "TR-11: an explicit rollback releases the block");

        Object closing = new Object();
        registry.markBlocked(111, closing);
        Assertions.assertEquals(State.BLOCKED, registry.state(111, closing), "TR-11: blocked");
        registry.contextClosed(111);
        Assertions.assertEquals(State.CLEAN, registry.state(111, closing), "TR-11: a close forgets the context, leaving no tombstone");
        Assertions.assertEquals(0, registry.trackedContexts(), "TR-11: nothing left");
    }

    /**
     * TR-14: every state against every operation, as the design's table says
     */
    @Test
    public void tr14EveryTransitionFollowsTheTable() {
        List<String> violations = new ArrayList<>();
        for (State from : State.values()) {
            for (Operation operation : Operation.values()) {
                if (operation == Operation.STATE) {
                    continue;
                }
                TransactionTaintRegistry registry = TransactionTaintRegistry.isolated();
                Object context = new Object();
                prepare(registry, 140, context, from);
                State before = registry.state(140, context);
                if (before != from) {
                    violations.add(from + ": could not be reached, got " + before);
                    continue;
                }
                apply(registry, operation, 140, context);
                State after = registry.state(140, context);
                State expected = expected(from, operation);
                if (after != expected) {
                    violations.add(from + " + " + operation + ": expected " + expected + ", got " + after);
                }
                int tracked = registry.trackedContexts();
                if (tracked != (expected == State.CLEAN ? 0 : 1)) {
                    violations.add(from + " + " + operation + ": " + tracked + " entries for a " + expected + " context");
                }
            }
        }
        Assertions.assertEquals(List.of(), violations, "TR-14");
    }

    /** The design's transition table */
    @NotNull
    private static State expected(@NotNull State from, @NotNull Operation operation) {
        return switch (operation) {
            case MARK_TAINTED -> from == State.BLOCKED ? State.BLOCKED : State.TAINTED;
            case MARK_BLOCKED -> State.BLOCKED;
            case ROLLBACK_SUCCEEDED -> from == State.BLOCKED ? State.BLOCKED : State.CLEAN;
            case RELEASE_AFTER_EXPLICIT_ROLLBACK, CONTEXT_CLOSED -> State.CLEAN;
            case STATE -> from;
        };
    }

    // ---------------------------------------------------------------- TR-12: the production seam

    /**
     * TR-12: the server's policy service reports closes to, and clears, the one global registry - not NONE
     * <p>
     * Both the registered handler and the cleanup plan of the server's Ready holder hold it, and no production code
     * makes another registry.
     */
    @Test
    public void tr12TheProductionSinkIsTheGlobalRegistry() throws Exception {
        Ready ready = Assertions.assertInstanceOf(Ready.class, PolicyServiceHolder.global().current(),
            "FIXTURE TR-12: the server's policy service is Ready");
        Object plan = read(ready, "plan");
        Object planSink = read(plan, "sink");
        Object handler = read(plan, "handler");
        Assertions.assertNotSame(TaintContextCloseHandler.TaintSink.NONE, planSink, "TR-12: the production sink is not NONE");
        Assertions.assertSame(TransactionTaintRegistry.global(), planSink, "TR-12: the shutdown clears the global registry");
        TaintContextCloseHandler registered = Assertions.assertInstanceOf(TaintContextCloseHandler.class, handler,
            "TR-12: the plan unregisters the taint close handler");
        Assertions.assertSame(TransactionTaintRegistry.global(), read(registered, "sink"),
            "TR-12: the registered handler reports to the same registry the plan clears");

        Path root = MetadataShutdownTest.dbacSourceRoot();
        List<String> otherRegistries = new ArrayList<>();
        try (Stream<Path> sources = Files.walk(root)) {
            for (Path source : sources.filter(p -> p.toString().endsWith(".java")).toList()) {
                if (source.getFileName().toString().equals("TransactionTaintRegistry.java")) {
                    continue;
                }
                String text = Files.readString(source, StandardCharsets.UTF_8);
                if (text.contains("TransactionTaintRegistry.isolated(") || text.contains("new TransactionTaintRegistry(")) {
                    otherRegistries.add(root.relativize(source).toString());
                }
            }
        }
        Assertions.assertEquals(List.of(), otherRegistries, "TR-12: no production code may make a registry other than the global one");
        String factory = Files.readString(root.resolve("io/cloudbeaver/service/dbac/DbacSecurityControllerFactory.java"),
            StandardCharsets.UTF_8);
        Assertions.assertTrue(factory.contains("TransactionTaintRegistry.global()"),
            "TR-12: the factory's production seams use the global registry");
        Assertions.assertFalse(factory.contains("TaintSink.NONE"), "TR-12: the factory no longer hands out NONE");
    }

    // ---------------------------------------------------------------- TR-13, TR-16: closed

    /**
     * TR-13: a closed registry answers no question - a state lookup fails - and records nothing
     */
    @Test
    public void tr13AClosedRegistryRefusesToSayAContextIsClean() {
        TransactionTaintRegistry registry = TransactionTaintRegistry.isolated();
        Object context = new Object();
        registry.markBlocked(130, context);
        Assertions.assertEquals(State.BLOCKED, registry.state(130, context), "TR-13: blocked while open");
        registry.clear();
        Assertions.assertFalse(registry.isOpen(), "TR-13: the clear closes the registry");
        Assertions.assertThrows(IllegalStateException.class, () -> registry.state(130, context),
            "TR-13: a closed registry must not say a context is clean - a blocked one would pass");
        Assertions.assertFalse(registry.markTainted(130, context), "TR-13: no taint is recorded");
        Assertions.assertFalse(registry.markBlocked(130, context), "TR-13: no block is recorded");
        Assertions.assertFalse(registry.rollbackSucceeded(130, context), "TR-13: no rollback is recorded");
        Assertions.assertFalse(registry.releaseAfterExplicitRollback(130, context), "TR-13: no release is recorded");
        Assertions.assertDoesNotThrow(() -> registry.contextClosed(130), "TR-13: a close is harmless");
        Assertions.assertEquals(0, registry.trackedContexts(), "TR-13: nothing is held");
    }

    /**
     * TR-16: clearing is terminal and idempotent, also when several threads clear at once
     */
    @Test
    public void tr16ClearIsIdempotent() throws Exception {
        TransactionTaintRegistry registry = TransactionTaintRegistry.isolated();
        Object context = new Object();
        registry.markTainted(160, context);
        registry.clear();
        Assertions.assertDoesNotThrow(registry::clear, "TR-16: a second clear must not fail");
        Assertions.assertFalse(registry.isOpen(), "TR-16: still closed");
        Assertions.assertEquals(0, registry.trackedContexts(), "TR-16: still empty");

        TransactionTaintRegistry shared = TransactionTaintRegistry.isolated();
        for (int i = 0; i < 32; i++) {
            shared.markBlocked(1600 + i, new Object[]{i});
        }
        CountDownLatch start = new CountDownLatch(1);
        List<Worker<Object>> clears = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            clears.add(Worker.start("dbac-tr16-clear-" + i, () -> {
                start.await(WAIT_SECONDS, TimeUnit.SECONDS);
                shared.clear();
                return null;
            }));
        }
        start.countDown();
        for (Worker<Object> clear : clears) {
            clear.get("TR-16 clear");
        }
        Assertions.assertFalse(shared.isOpen(), "TR-16: closed after concurrent clears");
        Assertions.assertEquals(0, shared.trackedContexts(), "TR-16: empty after concurrent clears");
    }

    // ---------------------------------------------------------------- TR-15: interleavings

    /**
     * TR-15: two operations on one context take effect in the order they reach its entry, whatever order they began in
     */
    @Test
    public void tr15OperationsTakeEffectInTheOrderTheyReachTheEntry() throws Exception {
        List<String> violations = new ArrayList<>();
        checkInterleaving(violations, State.CLEAN, Operation.MARK_TAINTED, Operation.MARK_BLOCKED, State.BLOCKED);
        checkInterleaving(violations, State.TAINTED, Operation.ROLLBACK_SUCCEEDED, Operation.MARK_BLOCKED, State.BLOCKED);
        checkInterleaving(violations, State.TAINTED, Operation.MARK_BLOCKED, Operation.ROLLBACK_SUCCEEDED, State.BLOCKED);
        checkInterleaving(violations, State.BLOCKED, Operation.RELEASE_AFTER_EXPLICIT_ROLLBACK, Operation.MARK_TAINTED, State.CLEAN);
        checkInterleaving(violations, State.BLOCKED, Operation.MARK_TAINTED, Operation.RELEASE_AFTER_EXPLICIT_ROLLBACK, State.TAINTED);
        checkInterleaving(violations, State.TAINTED, Operation.CONTEXT_CLOSED, Operation.MARK_BLOCKED, State.CLEAN);
        checkInterleaving(violations, State.BLOCKED, Operation.ROLLBACK_SUCCEEDED, Operation.CONTEXT_CLOSED, State.CLEAN);
        Assertions.assertEquals(List.of(), violations, "TR-15");

        // Many threads, few contexts: every result is one the table allows, and nothing throws
        TransactionTaintRegistry registry = TransactionTaintRegistry.isolated();
        Object[] contexts = {new Object(), new Object(), new Object(), new Object()};
        List<Worker<Object>> workers = new ArrayList<>();
        for (int t = 0; t < 8; t++) {
            long seed = 1500 + t;
            workers.add(Worker.start("dbac-tr15-" + t, () -> {
                Random random = new Random(seed);
                for (int i = 0; i < 2000; i++) {
                    int c = random.nextInt(contexts.length);
                    Operation operation = Operation.values()[random.nextInt(Operation.values().length)];
                    apply(registry, operation, 1500 + c, contexts[c]);
                }
                return null;
            }));
        }
        for (Worker<Object> worker : workers) {
            worker.get("TR-15 stress");
        }
        for (int c = 0; c < contexts.length; c++) {
            registry.contextClosed(1500 + c);
        }
        Assertions.assertEquals(0, registry.trackedContexts(), "TR-15: closing every context leaves nothing");
    }

    /** Starts at {@code from}, pauses {@code first} inside the lock, runs {@code second} to the end, then lets {@code first} go */
    private static void checkInterleaving(
        @NotNull List<String> violations,
        @NotNull State from,
        @NotNull Operation first,
        @NotNull Operation second,
        @NotNull State expected
    ) throws Exception {
        String label = from + ": " + first + " paused, " + second + " in between";
        try {
            State after = interleave(from, first, second);
            if (after != expected) {
                violations.add(label + ": expected " + expected + ", got " + after);
            }
        } catch (AssertionError e) {
            violations.add(label + ": " + e.getMessage());
        }
    }

    /**
     * Runs {@code first} on one thread, paused inside the lifecycle lock, and {@code second} to the end on another;
     * returns the state once both are done
     */
    @NotNull
    private static State interleave(@NotNull State from, @NotNull Operation first, @NotNull Operation second) throws Exception {
        long id = 7000 + first.ordinal() * 10L + second.ordinal();
        Pause pause = new Pause(first, id);
        TransactionTaintRegistry registry = TransactionTaintRegistry.isolated(pause);
        Object context = new Object();
        prepare(registry, id, context, from);
        Assertions.assertEquals(from, registry.state(id, context), "the starting state must be reached");
        Worker<Object> paused = Worker.start("dbac-tr-first", () -> {
            apply(registry, first, id, context);
            return null;
        });
        try {
            Assertions.assertTrue(pause.reached(), first + " must pause inside the lifecycle lock");
            Worker<Object> between = Worker.start("dbac-tr-second", () -> {
                apply(registry, second, id, context);
                return null;
            });
            between.get(second + " while " + first + " is paused");
        } finally {
            pause.release();
        }
        paused.get(first + " after the pause");
        return registry.state(id, context);
    }

    // ---------------------------------------------------------------- TR-17, TR-18: nothing left, nothing exposed

    /**
     * TR-17: entries, queued references and threads do not outlive what made them
     */
    @Test
    public void tr17NothingLeaks() throws Exception {
        TransactionTaintRegistry registry = TransactionTaintRegistry.isolated();
        List<Object> contexts = new ArrayList<>();
        for (int i = 0; i < 200; i++) {
            Object context = new Object();
            contexts.add(context);
            switch (i % 4) {
                case 0 -> registry.markTainted(1700 + i, context);
                case 1 -> registry.markBlocked(1700 + i, context);
                case 2 -> {
                    registry.markTainted(1700 + i, context);
                    registry.rollbackSucceeded(1700 + i, context);
                }
                default -> {
                    registry.markBlocked(1700 + i, context);
                    registry.releaseAfterExplicitRollback(1700 + i, context);
                }
            }
        }
        Assertions.assertEquals(100, registry.trackedContexts(), "TR-17: one entry per tainted or blocked context, none for a clean one");
        for (int i = 0; i < contexts.size(); i++) {
            registry.contextClosed(1700 + i);
        }
        Assertions.assertEquals(0, registry.trackedContexts(), "TR-17: closing every context leaves no entry");
        contexts.clear();
        System.gc();
        Thread.sleep(50);
        for (int i = 0; i < 10; i++) {
            registry.trackedContexts();
        }
        Assertions.assertNull(pendingReference(registry), "TR-17: no reference waits in the queue after the operations");

        Assertions.assertTrue(eventually(() -> testThreads().isEmpty()), "TR-17: no test thread is left, got " + testThreads());
        Assertions.assertEquals(0, TransactionTaintRegistry.global().trackedContexts(), "TR-17: the server's registry holds nothing");
    }

    /**
     * TR-18: the registry's public surface names no platform, JDBC or reference type, and exposes no internal entry
     */
    @Test
    public void tr18ThePublicSurfaceIsPlatformFree() throws Exception {
        List<String> violations = new ArrayList<>();
        List<Class<?>> types = new ArrayList<>();
        types.add(TransactionTaintRegistry.class);
        types.addAll(Arrays.asList(TransactionTaintRegistry.class.getDeclaredClasses()));
        for (Class<?> type : types) {
            if (type != TransactionTaintRegistry.class && exposed(type.getModifiers())
                && !Set.of(State.class, Operation.class, Probe.class).contains(type)) {
                violations.add("public nested type " + type.getSimpleName());
            }
            if (!exposed(type.getModifiers())) {
                continue;
            }
            for (Method method : type.getDeclaredMethods()) {
                if (exposed(method.getModifiers()) && !method.isSynthetic()) {
                    check(violations, method, method.getGenericReturnType().getTypeName());
                    for (var parameter : method.getGenericParameterTypes()) {
                        check(violations, method, parameter.getTypeName());
                    }
                }
            }
            for (Constructor<?> constructor : type.getDeclaredConstructors()) {
                if (type == TransactionTaintRegistry.class && exposed(constructor.getModifiers())) {
                    violations.add("public constructor - registries are made by global() and isolated() only");
                }
            }
            for (Field field : type.getDeclaredFields()) {
                if (exposed(field.getModifiers()) && !field.isSynthetic()) {
                    check(violations, field, field.getGenericType().getTypeName());
                }
            }
        }
        String source = Files.readString(MetadataShutdownTest.dbacSourceRoot()
            .resolve("io/cloudbeaver/service/dbac/policy/enforcement/TransactionTaintRegistry.java"), StandardCharsets.UTF_8);
        source.lines()
            .filter(line -> line.startsWith("import "))
            .filter(line -> line.startsWith("import org.jkiss.dbeaver.") || line.startsWith("import java.sql")
                || line.startsWith("import javax.sql"))
            .forEach(line -> violations.add("the registry imports " + line));
        Assertions.assertEquals(List.of(), violations, "TR-18");
    }

    /** The threads this class starts that are still alive */
    @NotNull
    private static Set<String> testThreads() {
        return Thread.getAllStackTraces().keySet().stream()
            .filter(Thread::isAlive)
            .map(Thread::getName)
            .filter(name -> name.startsWith("dbac-tr"))
            .collect(Collectors.toSet());
    }

    private static boolean exposed(int modifiers) {
        return Modifier.isPublic(modifiers) || Modifier.isProtected(modifiers);
    }

    private static void check(@NotNull List<String> violations, @NotNull Member member, @NotNull String typeName) {
        for (String prefix : FORBIDDEN_TYPE_PREFIXES) {
            if (typeName.contains(prefix)) {
                violations.add(member.getDeclaringClass().getSimpleName() + "." + member.getName() + " mentions " + typeName);
            }
        }
        if (typeName.contains("$Entry") || typeName.contains("$Identity")) {
            violations.add(member.getDeclaringClass().getSimpleName() + "." + member.getName() + " exposes " + typeName);
        }
    }

    // ---------------------------------------------------------------- helpers

    /** Pauses the first time an operation reaches the registry's lifecycle lock for one context */
    private static final class Pause implements Probe {
        private final Operation operation;
        private final long contextId;
        private final AtomicBoolean taken = new AtomicBoolean();
        private final CountDownLatch inside = new CountDownLatch(1);
        private final CountDownLatch release = new CountDownLatch(1);

        Pause(@NotNull Operation operation, long contextId) {
            this.operation = operation;
            this.contextId = contextId;
        }

        @Override
        public void insideLifecycleLock(@NotNull Operation operation, long contextId) {
            if (operation != this.operation || contextId != this.contextId || !taken.compareAndSet(false, true)) {
                return;
            }
            inside.countDown();
            try {
                if (!release.await(KeyLockTestSupport.TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                    throw new IllegalStateException("FIXTURE: the paused operation was never released");
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        /** Whether the operation reached its pause in time */
        boolean reached() throws InterruptedException {
            return inside.await(WAIT_SECONDS, TimeUnit.SECONDS);
        }

        void release() {
            release.countDown();
        }
    }

    /** Fails every close that reaches the registry's lifecycle lock, remembering whose it was */
    private static final class Failing implements Probe {
        private final Fault fault;
        private final List<Long> closed = new ArrayList<>();

        Failing(@NotNull Fault fault) {
            this.fault = fault;
        }

        @Override
        public void insideLifecycleLock(@NotNull Operation operation, long contextId) {
            if (operation != Operation.CONTEXT_CLOSED) {
                return;
            }
            synchronized (closed) {
                closed.add(contextId);
            }
            if (fault == Fault.ERROR) {
                throw new LifecycleTestSupport.InjectedError("registry close");
            }
            throw new LifecycleTestSupport.InjectedRuntimeException("registry close");
        }

        /** The ids of the closes it failed, in order */
        @NotNull
        List<Long> closed() {
            synchronized (closed) {
                return List.copyOf(closed);
            }
        }
    }

    /** Equal to every other twin, and the same as none of them */
    private static final class Twin {
        @Override
        public boolean equals(@Nullable Object other) {
            return other instanceof Twin;
        }

        @Override
        public int hashCode() {
            return 1;
        }
    }

    /** An isolated lifecycle whose close handler and cleanup plan use {@code registry} */
    @NotNull
    private static TestFactory factory(@NotNull Fixture fixture, @NotNull TransactionTaintRegistry registry) {
        return new TestFactory(fixture, new DbacSecurityControllerFactory.LifecycleSeams(
            fixture.admitter, fixture.registrar, registry, fixture.serviceFactory));
    }

    /** Brings a fresh context to {@code state} */
    private static void prepare(@NotNull TransactionTaintRegistry registry, long id, @NotNull Object context, @NotNull State state) {
        switch (state) {
            case TAINTED -> registry.markTainted(id, context);
            case BLOCKED -> registry.markBlocked(id, context);
            default -> {
                // clean: no entry
            }
        }
    }

    /** Runs one registry operation */
    private static void apply(@NotNull TransactionTaintRegistry registry, @NotNull Operation operation, long id, @Nullable Object context) {
        BiConsumer<Long, Object> call = switch (operation) {
            case STATE -> registry::state;
            case MARK_TAINTED -> registry::markTainted;
            case MARK_BLOCKED -> registry::markBlocked;
            case ROLLBACK_SUCCEEDED -> registry::rollbackSucceeded;
            case RELEASE_AFTER_EXPLICIT_ROLLBACK -> registry::releaseAfterExplicitRollback;
            case CONTEXT_CLOSED -> (contextId, ignored) -> registry.contextClosed(contextId);
        };
        call.accept(id, context);
    }

    /** Collects what {@code reference} points to; the test cannot go on if the collector does not */
    private static void collect(@NotNull WeakReference<Object> reference, @NotNull String label) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(WAIT_SECONDS);
        while (reference.get() != null && System.nanoTime() < deadline) {
            System.gc();
            Thread.sleep(10);
        }
        Assertions.assertNull(reference.get(), "FIXTURE " + label + ": the context was not collected");
    }

    /** The registry's reference queue; the registry is expected to keep exactly one */
    @NotNull
    private static ReferenceQueue<?> queueOf(@NotNull TransactionTaintRegistry registry) throws IllegalAccessException {
        List<Field> queues = Arrays.stream(TransactionTaintRegistry.class.getDeclaredFields())
            .filter(field -> ReferenceQueue.class.isAssignableFrom(field.getType()))
            .toList();
        Assertions.assertEquals(1, queues.size(), "the registry must track collected contexts through one reference queue");
        Field field = queues.get(0);
        field.setAccessible(true);
        return (ReferenceQueue<?>) field.get(registry);
    }

    /** What is waiting in the registry's queue, taken out of it; null when it is empty */
    @Nullable
    private static Reference<?> pendingReference(@NotNull TransactionTaintRegistry registry) throws IllegalAccessException {
        return queueOf(registry).poll();
    }

    /** Waits until the registry's reference for a collected context reaches its queue and takes it out; null if it never does */
    @Nullable
    private static Reference<?> drainOwnReference(@NotNull TransactionTaintRegistry registry, @NotNull WeakReference<Object> gone)
            throws Exception {
        ReferenceQueue<?> queue = queueOf(registry);
        Reference<?> drained = queue.remove(TimeUnit.SECONDS.toMillis(WAIT_SECONDS));
        Assertions.assertNull(gone.get(), "FIXTURE: the context is collected");
        return drained;
    }

    /** Reads a field, wherever in the class hierarchy it is declared */
    @Nullable
    private static Object read(@NotNull Object owner, @NotNull String name) throws Exception {
        for (Class<?> type = owner.getClass(); type != null; type = type.getSuperclass()) {
            try {
                Field field = type.getDeclaredField(name);
                field.setAccessible(true);
                return field.get(owner);
            } catch (NoSuchFieldException ignored) {
                // look in the superclass
            }
        }
        Assertions.fail("FIXTURE: " + owner.getClass().getName() + " has no field " + name);
        return null;
    }

    /** A condition that becomes true, polled until it does or the wait is over */
    @FunctionalInterface
    private interface Condition {
        boolean holds() throws Exception;
    }

    private static boolean eventually(@NotNull Condition condition) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(WAIT_SECONDS);
        while (System.nanoTime() < deadline) {
            if (condition.holds()) {
                return true;
            }
            Thread.sleep(5);
        }
        return condition.holds();
    }

    /** Whether {@code thread} is seen waiting {@code PARKED_POLLS} times in a row, rather than running or finished */
    private static boolean awaitParked(@NotNull Thread thread) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(WAIT_SECONDS);
        int parked = 0;
        while (System.nanoTime() < deadline) {
            Thread.State state = thread.getState();
            if (state == Thread.State.TERMINATED) {
                return false;
            }
            parked = state == Thread.State.WAITING || state == Thread.State.TIMED_WAITING ? parked + 1 : 0;
            if (parked >= PARKED_POLLS) {
                return true;
            }
            Thread.sleep(5);
        }
        return false;
    }

    @NotNull
    private EnforcementTestSupport.Target openTarget() throws Exception {
        EnforcementTestSupport.requirePostgres(monitor);
        return EnforcementTestSupport.openTarget(fixtures.user, monitor);
    }

    @NotNull
    private JDBCExecutionContext isolated(@NotNull EnforcementTestSupport.Target target) throws Exception {
        DBCExecutionContext context = target.instance().openIsolatedContext(monitor, "DBAC taint registry probe", null);
        return (JDBCExecutionContext) context;
    }

}
