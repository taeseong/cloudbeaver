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

import io.cloudbeaver.service.dbac.policy.DbAccessKey;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;

import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * The grant-key and user locks that every change of a TEMP_WRITE grant or of a user's state, and every future
 * enforcement point, share
 * <p>
 * Two families of fair read-write locks:
 * <ul>
 *     <li><b>K</b> - one per grant key, {@link DbAccessKey}: user, project and connection, compared as
 *     the exact three strings. Grant, supersede and revoke take its write lock.</li>
 *     <li><b>U</b> - one per user id, compared as the exact string. Deactivation, deletion and team
 *     deletion take its write lock.</li>
 * </ul>
 * An enforcement point takes the read locks - K, then U - before it authorizes and keeps them until
 * the platform operation has returned, so a revoke or a deactivation cannot commit while a write it
 * would forbid is in flight, and nothing authorized after it can see the old state. The enforcement gate
 * does that; no production entry point calls the gate yet. A grant also reads U while it holds K.
 * <p>
 * <b>One registry.</b> {@link #global()} is the only instance and nothing else can make one, so a writer
 * and a reader cannot end up on different registries. It has no lifecycle: a lock holds no resource, so
 * nothing is replaced or re-acquired when the policy service moves between ready, failed, stopping and
 * disposed - and a revoke or a deactivation, which take a permission away, must work in all of those.
 * <p>
 * <b>Identity.</b> Nothing is folded, trimmed or normalised: the metadata database compares these ids as
 * exact strings, and a lock that treated two of them as one would only serialize more, but a lock that
 * treated one of them as two would let a writer and a reader of the same row miss each other.
 * <p>
 * <b>Kept only while used (S4).</b> Each key maps to an entry: its lock and the number of holds and waits
 * that took it. A reference is taken in the same map operation that finds or makes the entry, before
 * anything waits on its lock, and given back exactly once on every way out - when a hold is closed, after
 * its lock is unlocked, or at once when a timed read times out, is interrupted or fails. The last reference
 * given back removes the entry, and only if the key still maps to that very entry. Both steps run inside
 * the map's own lock for the key, so an entry that anything holds or waits for is never removed, and a
 * request that comes after a removal makes a new entry that nothing else can still be using: a writer and
 * a reader of one key always meet on one lock. The registry therefore holds as many entries as there are
 * keys in use, however many keys were ever used.
 * <p>
 * <b>Writers wait without a limit.</b> A writer that gave up would leave the grant or the user in place -
 * failing open - so {@link #lockGrantForWrite} and {@link #lockUserForWrite} use {@link Lock#lock()}. An
 * interrupt does not end the wait. One that was already set, or arrived while waiting, is cleared once
 * the lock is held and set again when the lock is released, on every way out: it is a request the caller
 * still gets, not a reason to leave a permission behind. An interrupt that arrives while the change itself
 * runs is not touched, and what the JDBC driver does with it is not something this class can promise.
 * <p>
 * <b>Readers wait a bounded time.</b> A timed read uses {@link Lock#tryLock(long, TimeUnit)}, which keeps
 * the lock fair - a reader does not overtake a queued writer - unlike the untimed {@code tryLock()}.
 */
public final class EnforcementKeyLocks {

    /** The longest a timed read may wait; the ceiling {@code DbAccessPolicyConfig} puts on {@code T_k} */
    public static final Duration MAX_READ_TIMEOUT = Duration.ofSeconds(60);

    private static final EnforcementKeyLocks GLOBAL = new EnforcementKeyLocks();

    private final Family<DbAccessKey> grants = new Family<>();
    private final Family<String> users = new Family<>();

    private EnforcementKeyLocks() {
    }

    /**
     * The registry every writer and reader shares
     */
    @NotNull
    public static EnforcementKeyLocks global() {
        return GLOBAL;
    }

    /**
     * Takes the grant key's write lock, waiting as long as it takes
     *
     * @throws IllegalArgumentException when there is no key; nothing is locked then
     */
    @NotNull
    public Held lockGrantForWrite(@NotNull DbAccessKey key) {
        return grants.lockForWrite(requireKey(key));
    }

    /**
     * Takes the user's write lock, waiting as long as it takes
     *
     * @throws IllegalArgumentException when there is no user id; nothing is locked then
     */
    @NotNull
    public Held lockUserForWrite(@NotNull String userId) {
        return users.lockForWrite(requireUser(userId));
    }

    /**
     * Takes the grant key's read lock if it can within {@code timeout}
     *
     * @return the hold, or null when the timeout passed
     * @throws IllegalArgumentException when there is no key, or the timeout is not positive or exceeds {@link #MAX_READ_TIMEOUT}
     * @throws InterruptedException     when interrupted while waiting; nothing is held then
     */
    @Nullable
    public Held tryLockGrantForRead(@NotNull DbAccessKey key, @NotNull Duration timeout) throws InterruptedException {
        long nanos = timeoutNanos(timeout);
        return grants.tryLockForRead(requireKey(key), nanos);
    }

    /**
     * Takes the user's read lock if it can within {@code timeout}
     *
     * @return the hold, or null when the timeout passed
     * @throws IllegalArgumentException when there is no user id, or the timeout is not positive or exceeds {@link #MAX_READ_TIMEOUT}
     * @throws InterruptedException     when interrupted while waiting; nothing is held then
     */
    @Nullable
    public Held tryLockUserForRead(@NotNull String userId, @NotNull Duration timeout) throws InterruptedException {
        long nanos = timeoutNanos(timeout);
        return users.tryLockForRead(requireUser(userId), nanos);
    }

    @NotNull
    private static DbAccessKey requireKey(@Nullable DbAccessKey key) {
        if (key == null) {
            throw new IllegalArgumentException("A grant key lock needs a key");
        }
        return key;
    }

    @NotNull
    private static String requireUser(@Nullable String userId) {
        if (userId == null) {
            throw new IllegalArgumentException("A user lock needs a user id");
        }
        return userId;
    }

    private static long timeoutNanos(@Nullable Duration timeout) {
        if (timeout == null || timeout.isZero() || timeout.isNegative() || timeout.compareTo(MAX_READ_TIMEOUT) > 0) {
            throw new IllegalArgumentException(
                "A timed read needs a positive timeout of at most " + MAX_READ_TIMEOUT.toSeconds() + " seconds");
        }
        return timeout.toNanos();
    }

    /**
     * A lock held until closed, on the thread that took it; closing it again does nothing
     */
    public interface Held extends AutoCloseable {
        @Override
        void close();
    }

    /**
     * One key's lock and how many holds and waits took it
     * <p>
     * {@link #references} is read and changed only inside its family's map operation for the key, which runs
     * under the map's lock for that key.
     */
    private static final class Entry {
        private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock(true);
        private int references;
    }

    /**
     * The entries of one family of keys
     */
    private static final class Family<K> {
        private final ConcurrentHashMap<K, Entry> entries = new ConcurrentHashMap<>();

        /** The key's entry, made when there is none, with a reference taken in the same step */
        @NotNull
        private Entry reference(@NotNull K key) {
            return entries.compute(key, (ignored, current) -> {
                Entry entry = current == null ? new Entry() : current;
                entry.references++;
                return entry;
            });
        }

        /** Gives one reference back; the last one removes the entry, if the key still maps to it */
        private void dereference(@NotNull K key, @NotNull Entry entry) {
            entries.compute(key, (ignored, current) -> {
                entry.references--;
                return current == entry && entry.references == 0 ? null : current;
            });
        }

        @NotNull
        private Held lockForWrite(@NotNull K key) {
            Entry entry = reference(key);
            Lock writeLock = entry.lock.writeLock();
            boolean locked = false;
            try {
                writeLock.lock();
                locked = true;
            } finally {
                if (!locked) {
                    dereference(key, entry);
                }
            }
            // Set before the call or while waiting: cleared now that the lock is held, given back on release.
            boolean interrupted = Thread.interrupted();
            return new Hold<>(this, key, entry, writeLock, interrupted);
        }

        @Nullable
        private Held tryLockForRead(@NotNull K key, long nanos) throws InterruptedException {
            Entry entry = reference(key);
            Lock readLock = entry.lock.readLock();
            boolean locked = false;
            try {
                locked = readLock.tryLock(nanos, TimeUnit.NANOSECONDS);
            } finally {
                if (!locked) {
                    dereference(key, entry);
                }
            }
            return locked ? new Hold<>(this, key, entry, readLock, false) : null;
        }
    }

    /**
     * One hold of a lock: unlocks it, then gives its reference back, once
     */
    private static final class Hold<K> implements Held {
        private final Family<K> family;
        private final K key;
        private final Entry entry;
        private final Lock lock;
        private final boolean interrupted;
        private boolean closed;

        private Hold(@NotNull Family<K> family, @NotNull K key, @NotNull Entry entry, @NotNull Lock lock, boolean interrupted) {
            this.family = family;
            this.key = key;
            this.entry = entry;
            this.lock = lock;
            this.interrupted = interrupted;
        }

        @Override
        public void close() {
            if (closed) {
                return;
            }
            closed = true;
            try {
                lock.unlock();
                // Not in a finally: a lock that could not be unlocked is still held, and its entry stays with it.
                family.dereference(key, entry);
            } finally {
                if (interrupted) {
                    Thread.currentThread().interrupt();
                }
            }
        }
    }
}
