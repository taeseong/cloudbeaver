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
package io.cloudbeaver.service.dbac.policy.enforcement;

import org.jkiss.code.NotNull;

import java.lang.ref.Reference;
import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.UnaryOperator;

/**
 * What the policy service knows about the transaction of each execution context: clean, tainted or blocked
 * <p>
 * <b>States.</b> {@code CLEAN} is the absence of an entry. {@code TAINTED} marks a context whose transaction a gate
 * is about to roll back, so that a thread dying between the mark and the rollback leaves it refused rather than
 * clean; a successful rollback by the gate makes it clean again. {@code BLOCKED} marks a context whose transaction
 * could not be ended: only an explicit rollback on a live connection releases it - neither the gate's own rollback
 * nor a taint does - and a close forgets it, because the transaction ended with its physical connection.
 * <pre>
 *            markTainted          markBlocked
 *   CLEAN ---------------&gt; TAINTED -----------&gt; BLOCKED
 *     ^  &lt;-- rollbackSucceeded --'                 |
 *     |  &lt;------------- releaseAfterExplicitRollback ---'
 *     '---- contextClosed (from any state: the entry is removed, no tombstone)
 * </pre>
 * <b>Identity.</b> An entry is keyed by the context id, which the platform hands out once per JVM and never reuses,
 * and it remembers the context object weakly. The connection generation is not part of the key: a block survives a
 * reconnect. An operation for the same id and a different live object - compared by {@code ==}, never by
 * {@code equals} - throws {@link IllegalStateException} and changes nothing; an entry whose object was collected is
 * stale, and the next object with that id starts clean, so a block never passes to another object. Collected
 * objects are also removed through a reference queue, a bounded number at the start of every operation. That is a
 * bound on memory, not a reason for correctness.
 * <p>
 * <b>Lifecycle.</b> Every lookup and change runs under the read side of an internal lifecycle lock and first checks
 * that the registry is open. {@link #clear()} takes the write side, closes the registry for good and removes every
 * entry. An operation already under way therefore either completes before the clear, which then removes what it
 * did, or begins after it and records nothing; once cleared, the registry holds no entry again. A closed registry
 * refuses to answer {@link #state} - saying clean would let a blocked context through while the service stops - and
 * its other operations do nothing. There is no reopening, as the policy service holder has no way back from
 * Disposed either.
 * <p>
 * The production instance is {@link #global()}: the policy service's close handler reports closes to it, and the
 * service's cleanup plan clears it when the service stops. No gate marks or reads it yet. The registry and its public
 * surface use no platform or JDBC type; a caller passes the context's id and the context itself as an {@code Object}.
 */
public final class TransactionTaintRegistry implements TaintContextCloseHandler.TaintSink {

    /** What the registry knows about one execution context */
    public enum State {
        /** Nothing is recorded: the context's transaction is not known to be in doubt */
        CLEAN,
        /** A gate is ending the context's transaction; until it has, the context is refused */
        TAINTED,
        /** The context's transaction could not be ended; only an explicit rollback releases it */
        BLOCKED
    }

    /** The registry operation a {@link Probe} is told about */
    public enum Operation {
        STATE,
        MARK_TAINTED,
        MARK_BLOCKED,
        ROLLBACK_SUCCEEDED,
        RELEASE_AFTER_EXPLICIT_ROLLBACK,
        CONTEXT_CLOSED
    }

    /**
     * A test seam: told about every operation inside the lifecycle lock, after the registry was found open and before
     * the entry is looked at
     */
    @FunctionalInterface
    public interface Probe {
        /** Does nothing; the production registry's probe */
        Probe NONE = (operation, contextId) -> {
        };

        /** Called inside the lifecycle lock; a test may pause here */
        void insideLifecycleLock(@NotNull Operation operation, long contextId);
    }

    /** The most collected contexts one operation removes */
    public static final int EXPUNGE_LIMIT = 64;

    private static final String MSG_CLOSED = "DBAC transaction taint registry is closed";
    private static final String MSG_OTHER_OBJECT = "DBAC transaction taint registry: another live object holds this context id";

    private static final TransactionTaintRegistry GLOBAL = new TransactionTaintRegistry(Probe.NONE);

    /** One entry's weak hold on its context, which also names the entry it belongs to once it is collected */
    private static final class Identity extends WeakReference<Object> {
        private final long contextId;

        Identity(@NotNull Object context, @NotNull ReferenceQueue<Object> queue, long contextId) {
            super(context, queue);
            this.contextId = contextId;
        }
    }

    /** A tainted or blocked context */
    private record Entry(@NotNull Identity identity, @NotNull State state) {
    }

    private final Probe probe;
    private final ReentrantReadWriteLock lifecycle = new ReentrantReadWriteLock();
    private final ConcurrentHashMap<Long, Entry> entries = new ConcurrentHashMap<>();
    private final ReferenceQueue<Object> collected = new ReferenceQueue<>();
    /** Guarded by {@link #lifecycle}: read under either side, set false once under the write side */
    private boolean open = true;

    private TransactionTaintRegistry(@NotNull Probe probe) {
        this.probe = probe;
    }

    /**
     * The registry of the server's policy service; there is no other in production
     */
    @NotNull
    public static TransactionTaintRegistry global() {
        return GLOBAL;
    }

    /**
     * A registry of its own, for a test - so that closing it cannot close the server's
     */
    @NotNull
    public static TransactionTaintRegistry isolated() {
        return new TransactionTaintRegistry(Probe.NONE);
    }

    /**
     * A registry of its own, for a test, whose probe is told about every operation inside the lifecycle lock
     */
    @NotNull
    public static TransactionTaintRegistry isolated(@NotNull Probe probe) {
        return new TransactionTaintRegistry(probe);
    }

    /**
     * What is known about the context
     *
     * @throws IllegalStateException when the registry is closed, or when another live object holds the id
     */
    @NotNull
    public State state(long contextId, @NotNull Object identity) {
        Objects.requireNonNull(identity, "identity");
        Lock read = lifecycle.readLock();
        read.lock();
        try {
            if (!open) {
                throw new IllegalStateException(MSG_CLOSED);
            }
            expungeCollected();
            probe.insideLifecycleLock(Operation.STATE, contextId);
            Entry current = entries.computeIfPresent(contextId, (id, entry) -> {
                Object holder = entry.identity().get();
                if (holder == null) {
                    // stale: its context was collected, and nothing of it passes to the next object with this id
                    return null;
                }
                if (holder != identity) {
                    throw new IllegalStateException(MSG_OTHER_OBJECT);
                }
                return entry;
            });
            return current == null ? State.CLEAN : current.state();
        } finally {
            read.unlock();
        }
    }

    /**
     * A gate is about to roll the context's transaction back; a block stays a block
     *
     * @return false when the registry is closed and nothing was recorded
     * @throws IllegalStateException when another live object holds the id
     */
    public boolean markTainted(long contextId, @NotNull Object identity) {
        return transition(Operation.MARK_TAINTED, contextId, identity, from -> from == State.BLOCKED ? State.BLOCKED : State.TAINTED);
    }

    /**
     * The context's transaction could not be ended
     *
     * @return false when the registry is closed and nothing was recorded
     * @throws IllegalStateException when another live object holds the id
     */
    public boolean markBlocked(long contextId, @NotNull Object identity) {
        return transition(Operation.MARK_BLOCKED, contextId, identity, from -> State.BLOCKED);
    }

    /**
     * The gate's own rollback succeeded: a taint is lifted, a block is not
     *
     * @return false when the registry is closed and nothing was recorded
     * @throws IllegalStateException when another live object holds the id
     */
    public boolean rollbackSucceeded(long contextId, @NotNull Object identity) {
        return transition(Operation.ROLLBACK_SUCCEEDED, contextId, identity, from -> from == State.BLOCKED ? State.BLOCKED : State.CLEAN);
    }

    /**
     * An explicit rollback on a live connection succeeded: whatever transaction the context had is over
     *
     * @return false when the registry is closed and nothing was recorded
     * @throws IllegalStateException when another live object holds the id
     */
    public boolean releaseAfterExplicitRollback(long contextId, @NotNull Object identity) {
        return transition(Operation.RELEASE_AFTER_EXPLICIT_ROLLBACK, contextId, identity, from -> State.CLEAN);
    }

    /**
     * The context was closed: its entry, whatever it held, is removed. Idempotent, and nothing once the registry is closed
     */
    @Override
    public void contextClosed(long contextId) {
        Lock read = lifecycle.readLock();
        read.lock();
        try {
            if (!open) {
                return;
            }
            expungeCollected();
            probe.insideLifecycleLock(Operation.CONTEXT_CLOSED, contextId);
            entries.remove(contextId);
        } finally {
            read.unlock();
        }
    }

    /**
     * Closes the registry for good and removes every entry, once no operation is under way. Idempotent
     */
    @Override
    public void clear() {
        Lock write = lifecycle.writeLock();
        write.lock();
        try {
            open = false;
            entries.clear();
            while (collected.poll() != null) {
                // the entries these named are gone already
            }
        } finally {
            write.unlock();
        }
    }

    /**
     * Whether the registry still records anything
     */
    public boolean isOpen() {
        Lock read = lifecycle.readLock();
        read.lock();
        try {
            return open;
        } finally {
            read.unlock();
        }
    }

    /**
     * How many contexts are tainted or blocked, after the collected ones this call removed
     */
    public int trackedContexts() {
        Lock read = lifecycle.readLock();
        read.lock();
        try {
            if (open) {
                expungeCollected();
            }
            return entries.size();
        } finally {
            read.unlock();
        }
    }

    /**
     * One change of one context's state, made atomically on its entry
     */
    private boolean transition(
        @NotNull Operation operation,
        long contextId,
        @NotNull Object identity,
        @NotNull UnaryOperator<State> next
    ) {
        Objects.requireNonNull(identity, "identity");
        Lock read = lifecycle.readLock();
        read.lock();
        try {
            if (!open) {
                return false;
            }
            expungeCollected();
            probe.insideLifecycleLock(operation, contextId);
            entries.compute(contextId, (id, current) -> {
                Identity held = current == null ? null : current.identity();
                Object holder = held == null ? null : held.get();
                if (holder != null && holder != identity) {
                    throw new IllegalStateException(MSG_OTHER_OBJECT);
                }
                // no entry, or a stale one whose context was collected: the context starts clean
                State from = holder == null ? State.CLEAN : current.state();
                State to = next.apply(from);
                if (to == State.CLEAN) {
                    return null;
                }
                return new Entry(holder == null ? new Identity(identity, collected, id) : held, to);
            });
            return true;
        } finally {
            read.unlock();
        }
    }

    /**
     * Removes the entries of up to {@link #EXPUNGE_LIMIT} collected contexts; called under the read lock, while open
     */
    private void expungeCollected() {
        for (int i = 0; i < EXPUNGE_LIMIT; i++) {
            Reference<?> reference = collected.poll();
            if (reference == null) {
                return;
            }
            Identity gone = (Identity) reference;
            entries.computeIfPresent(gone.contextId, (id, entry) -> entry.identity() == gone ? null : entry);
        }
    }
}
