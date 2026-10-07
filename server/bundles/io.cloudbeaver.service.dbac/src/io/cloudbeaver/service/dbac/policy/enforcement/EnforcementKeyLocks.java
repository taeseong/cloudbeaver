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
 * An enforcement point will take the read locks - K, then U - before it authorizes and keep them until
 * the platform operation has returned, so a revoke or a deactivation cannot commit while a write it
 * would forbid is in flight, and nothing authorized after it can see the old state. That reader is not
 * wired yet; {@link #tryLockGrantForRead} and {@link #tryLockUserForRead} have no production caller.
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
 * <b>Kept, not removed.</b> A lock, once made, stays for the life of the registry (C17 D2). Removing an
 * idle one is not safe without a reference count: a thread that has looked a lock up but not yet locked
 * it would be left holding a lock that is no longer the key's. P4 has only administrative writers, so the
 * number of keys is bounded by grants and user changes; the policy must be revisited before readers
 * make entries for every key that a write is attempted on (S4).
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

    private final ConcurrentHashMap<DbAccessKey, ReentrantReadWriteLock> grantLocks = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, ReentrantReadWriteLock> userLocks = new ConcurrentHashMap<>();

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
        return lockForWrite(grantLock(key).writeLock());
    }

    /**
     * Takes the user's write lock, waiting as long as it takes
     *
     * @throws IllegalArgumentException when there is no user id; nothing is locked then
     */
    @NotNull
    public Held lockUserForWrite(@NotNull String userId) {
        return lockForWrite(userLock(userId).writeLock());
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
        return tryLockForRead(grantLock(key).readLock(), nanos);
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
        return tryLockForRead(userLock(userId).readLock(), nanos);
    }

    @NotNull
    private ReentrantReadWriteLock grantLock(@Nullable DbAccessKey key) {
        if (key == null) {
            throw new IllegalArgumentException("A grant key lock needs a key");
        }
        return grantLocks.computeIfAbsent(key, ignored -> new ReentrantReadWriteLock(true));
    }

    @NotNull
    private ReentrantReadWriteLock userLock(@Nullable String userId) {
        if (userId == null) {
            throw new IllegalArgumentException("A user lock needs a user id");
        }
        return userLocks.computeIfAbsent(userId, ignored -> new ReentrantReadWriteLock(true));
    }

    private static long timeoutNanos(@Nullable Duration timeout) {
        if (timeout == null || timeout.isZero() || timeout.isNegative() || timeout.compareTo(MAX_READ_TIMEOUT) > 0) {
            throw new IllegalArgumentException(
                "A timed read needs a positive timeout of at most " + MAX_READ_TIMEOUT.toSeconds() + " seconds");
        }
        return timeout.toNanos();
    }

    @NotNull
    private static Held lockForWrite(@NotNull Lock writeLock) {
        writeLock.lock();
        // Set before the call or while waiting: cleared now that the lock is held, given back on release.
        boolean interrupted = Thread.interrupted();
        return new WriteHold(writeLock, interrupted);
    }

    @Nullable
    private static Held tryLockForRead(@NotNull Lock readLock, long nanos) throws InterruptedException {
        if (!readLock.tryLock(nanos, TimeUnit.NANOSECONDS)) {
            return null;
        }
        return new ReadHold(readLock);
    }

    /**
     * A lock held until closed, on the thread that took it; closing it again does nothing
     */
    public interface Held extends AutoCloseable {
        @Override
        void close();
    }

    private static final class WriteHold implements Held {
        private final Lock lock;
        private final boolean interrupted;
        private boolean closed;

        private WriteHold(@NotNull Lock lock, boolean interrupted) {
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
            } finally {
                if (interrupted) {
                    Thread.currentThread().interrupt();
                }
            }
        }
    }

    private static final class ReadHold implements Held {
        private final Lock lock;
        private boolean closed;

        private ReadHold(@NotNull Lock lock) {
            this.lock = lock;
        }

        @Override
        public void close() {
            if (closed) {
                return;
            }
            closed = true;
            lock.unlock();
        }
    }
}
