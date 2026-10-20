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

import io.cloudbeaver.service.dbac.policy.DbAccessKey;
import io.cloudbeaver.service.dbac.policy.enforcement.EnforcementKeyLocks;
import io.cloudbeaver.test.platform.dbac.KeyLockTestSupport.Worker;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.BooleanSupplier;

/**
 * P6-0 S4: the key lock registry keeps an entry only while something holds or waits for its lock
 * <p>
 * Every grant key and user id gets an entry - its fair lock and the number of holds and waits that took it - and
 * the entry leaves the registry when the last of them gives its reference back. The cases look at the registry's
 * private state by reflection: which entry a key maps to, how many references it counts, and what its lock is
 * doing. They add nothing to the registry's API.
 * <p>
 * The races around the removal are made deterministic with a barrier on the registry's own map: a thread of the
 * test holds the map's lock for one key, so a release that reaches the map for that key stops there, after the
 * lock was unlocked and before the reference is given back, while the test looks.
 * <p>
 * The registry is the global one the production code uses. Every key here is unique to its case, and every hold is
 * taken and released on a thread of the case's own.
 */
@Timeout(value = 300, unit = TimeUnit.SECONDS, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
public class KeyLockRegistryTest {

    private static final String PREFIX = "dbac-klr-";
    private static final String PROJECT = "klr-project";
    private static final String CONNECTION = "klr-connection";
    /** Long enough that a waiting read is still waiting when the case looks at it */
    private static final Duration LONG = Duration.ofSeconds(20);
    /** Short enough that a read behind a held write times out quickly */
    private static final Duration SHORT = Duration.ofMillis(100);
    private static final long WAIT_SECONDS = 30;
    private static final int CHURN = 100_000;
    private static final int RACES = 1_000;
    private static final AtomicLong SEQUENCE = new AtomicLong();

    /** The two kinds of lock the registry keeps */
    private enum Family {
        GRANT("grant") {
            @NotNull
            @Override
            Object key(@NotNull String id) {
                return new DbAccessKey(id, PROJECT, CONNECTION);
            }

            @NotNull
            @Override
            EnforcementKeyLocks.Held write(@NotNull Object key) {
                return EnforcementKeyLocks.global().lockGrantForWrite((DbAccessKey) key);
            }

            @Nullable
            @Override
            EnforcementKeyLocks.Held read(@NotNull Object key, @NotNull Duration timeout) throws InterruptedException {
                return EnforcementKeyLocks.global().tryLockGrantForRead((DbAccessKey) key, timeout);
            }
        },
        USER("user") {
            @NotNull
            @Override
            Object key(@NotNull String id) {
                return id;
            }

            @NotNull
            @Override
            EnforcementKeyLocks.Held write(@NotNull Object key) {
                return EnforcementKeyLocks.global().lockUserForWrite((String) key);
            }

            @Nullable
            @Override
            EnforcementKeyLocks.Held read(@NotNull Object key, @NotNull Duration timeout) throws InterruptedException {
                return EnforcementKeyLocks.global().tryLockUserForRead((String) key, timeout);
            }
        };

        /** How the registry's field for this family is named */
        final String field;

        Family(@NotNull String field) {
            this.field = field;
        }

        @NotNull
        abstract Object key(@NotNull String id);

        @NotNull
        abstract EnforcementKeyLocks.Held write(@NotNull Object key);

        @Nullable
        abstract EnforcementKeyLocks.Held read(@NotNull Object key, @NotNull Duration timeout) throws InterruptedException;

        /** A key no other case uses */
        @NotNull
        Object newKey(@NotNull String tag) {
            return key(PREFIX + tag + "-" + Long.toHexString(System.nanoTime()) + "-" + SEQUENCE.incrementAndGet());
        }
    }

    // ---------------------------------------------------------------- KLR-1 - KLR-7: one key, its holders and waiters

    /**
     * KLR-1: while a holder has the key, a new request for it uses the holder's entry and waits on the same lock
     * <p>
     * A writer holds; a reader asks and waits. The key still maps to the writer's entry, which now counts both, and
     * the reader is queued on that entry's lock. Once the writer leaves, the reader holds the same lock, and once
     * the reader leaves the key is gone from the registry.
     */
    @Test
    public void klr1AHolderAndANewRequestShareOneLock() throws Exception {
        List<String> violations = new ArrayList<>();
        for (Family family : Family.values()) {
            String what = family + ": ";
            Object key = family.newKey("klr1");
            Holder writer = Holder.writer(family, key);
            try {
                expectHeld(violations, what + "the writer", writer);
                Seen first = seen(family, key);
                expectReferences(violations, what + "with the writer", 1, first);
                Holder reader = Holder.reader(family, key, LONG);
                try {
                    if (!KeyLockTestSupport.awaitParked(reader.thread())) {
                        violations.add(what + "the reader must wait for the writer");
                    }
                    Seen waiting = seen(family, key);
                    expectSame(violations, what + "while the reader waits", first, waiting);
                    expectReferences(violations, what + "while the reader waits", 2, waiting);
                    if (first != null && !first.lock().hasQueuedThread(reader.thread())) {
                        violations.add(what + "the reader must wait on the writer's lock");
                    }
                    writer.release();
                    expectHeld(violations, what + "the reader, once the writer left", reader);
                    Seen reading = seen(family, key);
                    expectSame(violations, what + "while the reader holds", first, reading);
                    expectReferences(violations, what + "while the reader holds", 1, reading);
                    if (first != null && first.lock().getReadLockCount() != 1) {
                        violations.add(what + "the reader must hold the writer's lock, read locks " + first.lock().getReadLockCount());
                    }
                } finally {
                    reader.release();
                }
                expectAbsent(violations, what + "once both left", family, key);
            } finally {
                writer.release();
            }
        }
        Assertions.assertEquals(List.of(), violations, "KLR-1");
    }

    /**
     * KLR-2: a waiter keeps the entry when the holder leaves, and the holder unlocks before it gives its reference back
     * <p>
     * A writer holds and a reader waits. The test stops the writer's release where it reaches the registry: by
     * then the writer has unlocked, the reader holds the very same lock, and both references are still counted.
     * Let go, the writer's release leaves the entry to the reader.
     */
    @Test
    public void klr2AWaiterKeepsTheEntryWhenTheHolderLeaves() throws Exception {
        List<String> violations = new ArrayList<>();
        for (Family family : Family.values()) {
            String what = family + ": ";
            Object key = family.newKey("klr2");
            Holder writer = Holder.writer(family, key);
            Holder reader = null;
            try {
                expectHeld(violations, what + "the writer", writer);
                reader = Holder.reader(family, key, LONG);
                if (!KeyLockTestSupport.awaitParked(reader.thread())) {
                    violations.add(what + "the reader must wait for the writer");
                }
                Seen waiting = seen(family, key);
                expectReferences(violations, what + "while the reader waits", 2, waiting);
                try (Barrier barrier = new Barrier(family, key)) {
                    writer.releaseLater();
                    if (!awaitBlocked(writer.thread())) {
                        violations.add(what + "the writer's release must reach the registry for its key");
                    }
                    Seen inside = barrier.look();
                    expectSame(violations, what + "at the writer's release", waiting, inside);
                    expectReferences(violations, what + "at the writer's release", 2, inside);
                    if (inside != null && inside.lock().isWriteLocked()) {
                        violations.add(what + "the writer must unlock before it gives its reference back");
                    }
                    if (inside != null && !eventually(() -> inside.lock().getReadLockCount() == 1)) {
                        violations.add(what + "the reader must hold the same lock while the writer's release waits");
                    }
                }
                writer.awaitDone();
                Seen after = seen(family, key);
                expectSame(violations, what + "after the writer left", waiting, after);
                expectReferences(violations, what + "after the writer left", 1, after);
            } finally {
                writer.release();
                if (reader != null) {
                    reader.release();
                }
            }
            expectAbsent(violations, what + "once both left", family, key);
        }
        Assertions.assertEquals(List.of(), violations, "KLR-2");
    }

    /**
     * KLR-3: a timed read that times out gives its reference back - and only its own
     * <p>
     * A writer holds, one reader waits long, another gives up after a moment. The entry stays, counting the writer
     * and the waiting reader, and leaves once they have both gone.
     */
    @Test
    public void klr3ATimedOutReadGivesItsReferenceBack() throws Exception {
        List<String> violations = new ArrayList<>();
        for (Family family : Family.values()) {
            String what = family + ": ";
            Object key = family.newKey("klr3");
            Holder writer = Holder.writer(family, key);
            Holder waiter = null;
            try {
                expectHeld(violations, what + "the writer", writer);
                final Seen first = seen(family, key);
                waiter = Holder.reader(family, key, LONG);
                if (!KeyLockTestSupport.awaitParked(waiter.thread())) {
                    violations.add(what + "the long reader must wait for the writer");
                }
                Holder late = Holder.reader(family, key, SHORT);
                late.release();
                if (late.held || late.error() != null) {
                    violations.add(what + "the short reader must time out, held=" + late.held + " error=" + late.error());
                }
                Seen afterTimeout = seen(family, key);
                expectSame(violations, what + "after the timeout", first, afterTimeout);
                expectReferences(violations, what + "after the timeout", 2, afterTimeout);
                writer.release();
                expectHeld(violations, what + "the long reader", waiter);
                expectReferences(violations, what + "with the long reader", 1, seen(family, key));
            } finally {
                writer.release();
                if (waiter != null) {
                    waiter.release();
                }
            }
            expectAbsent(violations, what + "once all left", family, key);
        }
        Assertions.assertEquals(List.of(), violations, "KLR-3");
    }

    /**
     * KLR-4: a timed read interrupted while it waits gives its reference back
     */
    @Test
    public void klr4AnInterruptedReadGivesItsReferenceBack() throws Exception {
        List<String> violations = new ArrayList<>();
        for (Family family : Family.values()) {
            String what = family + ": ";
            Object key = family.newKey("klr4");
            Holder writer = Holder.writer(family, key);
            try {
                expectHeld(violations, what + "the writer", writer);
                Holder interrupted = Holder.reader(family, key, LONG);
                if (!KeyLockTestSupport.awaitParked(interrupted.thread())) {
                    violations.add(what + "the reader must wait for the writer");
                }
                interrupted.thread().interrupt();
                // The worker records what the read threw only once it has finished
                interrupted.release();
                if (!(interrupted.error() instanceof InterruptedException) || interrupted.held) {
                    violations.add(what + "the interrupted read must end in InterruptedException holding nothing, got "
                        + interrupted.error());
                }
                expectReferences(violations, what + "after the interrupt", 1, seen(family, key));
            } finally {
                writer.release();
            }
            expectAbsent(violations, what + "once the writer left", family, key);
        }
        Assertions.assertEquals(List.of(), violations, "KLR-4");
    }

    /**
     * KLR-5: closing a hold twice gives one reference back
     * <p>
     * A read closed twice next to another read, and a write closed twice in front of a waiting read: each time the
     * other one's reference still keeps the entry, and a writer from elsewhere still cannot get the key.
     */
    @Test
    public void klr5ClosingTwiceGivesOneReferenceBack() throws Exception {
        List<String> violations = new ArrayList<>();
        for (Family family : Family.values()) {
            String what = family + ", a read closed twice: ";
            Object key = family.newKey("klr5-read");
            Holder twice = Holder.reader(family, key, LONG, 2);
            Holder other = Holder.reader(family, key, LONG);
            try {
                expectHeld(violations, what + "the first read", twice);
                expectHeld(violations, what + "the second read", other);
                Seen both = seen(family, key);
                expectReferences(violations, what + "with both", 2, both);
                twice.release();
                Seen one = seen(family, key);
                expectSame(violations, what + "after the double close", both, one);
                expectReferences(violations, what + "after the double close", 1, one);
                expectNotWritable(violations, what, family, key, other);
            } finally {
                twice.release();
                other.release();
            }
            expectAbsent(violations, what + "once both left", family, key);

            what = family + ", a write closed twice: ";
            key = family.newKey("klr5-write");
            Holder writer = Holder.writer(family, key, 2);
            Holder reader = null;
            try {
                expectHeld(violations, what + "the writer", writer);
                reader = Holder.reader(family, key, LONG);
                if (!KeyLockTestSupport.awaitParked(reader.thread())) {
                    violations.add(what + "the reader must wait for the writer");
                }
                writer.release();
                expectHeld(violations, what + "the reader", reader);
                expectReferences(violations, what + "after the double close", 1, seen(family, key));
                expectNotWritable(violations, what, family, key, reader);
            } finally {
                writer.release();
                if (reader != null) {
                    reader.release();
                }
            }
            expectAbsent(violations, what + "once both left", family, key);
        }
        Assertions.assertEquals(List.of(), violations, "KLR-5");
    }

    /**
     * KLR-6: a writer waiting for a reader and a reader waiting for a writer each wait on the holder's entry
     */
    @Test
    public void klr6WritersAndReadersWaitForEachOtherOnOneEntry() throws Exception {
        List<String> violations = new ArrayList<>();
        for (Family family : Family.values()) {
            for (boolean readerFirst : new boolean[]{true, false}) {
                String what = family + (readerFirst ? ", a writer waits for a reader: " : ", a reader waits for a writer: ");
                Object key = family.newKey("klr6");
                Holder holder = readerFirst ? Holder.reader(family, key, LONG) : Holder.writer(family, key);
                Holder waiter = null;
                try {
                    expectHeld(violations, what + "the holder", holder);
                    Seen first = seen(family, key);
                    expectReferences(violations, what + "with the holder", 1, first);
                    waiter = readerFirst ? Holder.writer(family, key) : Holder.reader(family, key, LONG);
                    if (!KeyLockTestSupport.awaitParked(waiter.thread())) {
                        violations.add(what + "the second one must wait");
                    }
                    Seen waiting = seen(family, key);
                    expectSame(violations, what + "while it waits", first, waiting);
                    expectReferences(violations, what + "while it waits", 2, waiting);
                    if (first != null && !first.lock().hasQueuedThread(waiter.thread())) {
                        violations.add(what + "the waiter must be queued on the holder's lock");
                    }
                    holder.release();
                    expectHeld(violations, what + "the waiter, once the holder left", waiter);
                    Seen after = seen(family, key);
                    expectSame(violations, what + "after the holder left", first, after);
                    expectReferences(violations, what + "after the holder left", 1, after);
                    if (first != null && (readerFirst ? !first.lock().isWriteLocked() : first.lock().getReadLockCount() != 1)) {
                        violations.add(what + "the waiter must hold the holder's lock");
                    }
                } finally {
                    holder.release();
                    if (waiter != null) {
                        waiter.release();
                    }
                }
                expectAbsent(violations, what + "once both left", family, key);
            }
        }
        Assertions.assertEquals(List.of(), violations, "KLR-6");
    }

    /**
     * KLR-7: different keys have different entries; holding one neither blocks nor keeps the other
     */
    @Test
    public void klr7DifferentKeysAreIndependent() throws Exception {
        List<String> violations = new ArrayList<>();
        for (Family family : Family.values()) {
            String what = family + ": ";
            Object one = family.newKey("klr7-a");
            Object two = family.newKey("klr7-b");
            Holder first = Holder.writer(family, one);
            Holder second = null;
            try {
                expectHeld(violations, what + "the first key's writer", first);
                second = Holder.reader(family, two, SHORT);
                expectHeld(violations, what + "the second key while the first is written", second);
                Seen a = seen(family, one);
                Seen b = seen(family, two);
                if (a == null || b == null || a.entry() == b.entry() || a.lock() == b.lock()) {
                    violations.add(what + "two keys need two entries and two locks, got " + a + " and " + b);
                }
                expectReferences(violations, what + "the first key", 1, a);
                expectReferences(violations, what + "the second key", 1, b);
                first.release();
                expectAbsent(violations, what + "the first key once its writer left", family, one);
                expectReferences(violations, what + "the second key while it is still held", 1, seen(family, two));
            } finally {
                first.release();
                if (second != null) {
                    second.release();
                }
            }
            expectAbsent(violations, what + "the second key once its reader left", family, two);
        }
        DbAccessKey key = (DbAccessKey) Family.GRANT.newKey("klr7-c");
        DbAccessKey otherProject = new DbAccessKey(key.userId(), PROJECT + "-b", CONNECTION);
        Holder writer = Holder.writer(Family.GRANT, key);
        try {
            expectHeld(violations, "a grant key's writer", writer);
            Holder elsewhere = Holder.reader(Family.GRANT, otherProject, SHORT);
            expectHeld(violations, "the same user and connection in another project", elsewhere);
            elsewhere.release();
            Holder user = Holder.reader(Family.USER, key.userId(), SHORT);
            expectHeld(violations, "the grant key's user, which is another family", user);
            user.release();
        } finally {
            writer.release();
        }
        expectAbsent(violations, "the grant key", Family.GRANT, key);
        expectAbsent(violations, "the other project's key", Family.GRANT, otherProject);
        expectAbsent(violations, "the grant key's user", Family.USER, key.userId());
        Assertions.assertEquals(List.of(), violations, "KLR-7");
    }

    // ---------------------------------------------------------------- KLR-8: churn

    /**
     * KLR-8: a hundred thousand one-time grant keys and users leave the registry exactly as it was
     * <p>
     * Each key is read-locked K then U and released U then K, every sixteenth one write-locked instead, as the
     * enforcement gate and the administrative writers would. Nothing of them may be left.
     */
    @Test
    public void klr8ChurnLeavesTheRegistryAsItWas() throws Exception {
        List<String> violations = new ArrayList<>();
        ConcurrentHashMap<Object, Object> grants = map(Family.GRANT);
        ConcurrentHashMap<Object, Object> users = map(Family.USER);
        int grantsBefore = grants.size();
        int usersBefore = users.size();
        String run = PREFIX + "klr8-" + Long.toHexString(System.nanoTime()) + "-";
        int refused = 0;
        long start = System.nanoTime();
        for (int i = 0; i < CHURN; i++) {
            String id = run + i;
            DbAccessKey key = new DbAccessKey(id, PROJECT, CONNECTION);
            if (i % 16 == 0) {
                try (EnforcementKeyLocks.Held grant = EnforcementKeyLocks.global().lockGrantForWrite(key);
                     EnforcementKeyLocks.Held user = EnforcementKeyLocks.global().lockUserForWrite(id)) {
                    refused += grant == null || user == null ? 1 : 0;
                }
                continue;
            }
            try (EnforcementKeyLocks.Held grant = EnforcementKeyLocks.global().tryLockGrantForRead(key, LONG);
                 EnforcementKeyLocks.Held user = EnforcementKeyLocks.global().tryLockUserForRead(id, LONG)) {
                refused += grant == null || user == null ? 1 : 0;
            }
        }
        long millis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
        long grantsLeft = grants.keySet().stream().filter(k -> ((DbAccessKey) k).userId().startsWith(run)).count();
        long usersLeft = users.keySet().stream().filter(k -> ((String) k).startsWith(run)).count();
        System.out.println("DBAC_KEY_LOCK_CHURN keys=" + CHURN + " millis=" + millis + " grantsBefore=" + grantsBefore
            + " grantsAfter=" + grants.size() + " usersBefore=" + usersBefore + " usersAfter=" + users.size()
            + " grantsLeft=" + grantsLeft + " usersLeft=" + usersLeft);
        expect(violations, "locks refused during the churn", 0, refused);
        expect(violations, "grant keys of the churn left in the registry", 0L, grantsLeft);
        expect(violations, "users of the churn left in the registry", 0L, usersLeft);
        expect(violations, "grant entries after the churn", grantsBefore, grants.size());
        expect(violations, "user entries after the churn", usersBefore, users.size());
        Assertions.assertEquals(List.of(), violations, "KLR-8");
    }

    // ---------------------------------------------------------------- KLR-9 - KLR-11: the removal

    /**
     * KLR-9: a request just before the last release keeps the entry; one just after it gets a new entry, never the old one
     * <p>
     * Before: a second reader has its reference when the first one's release is stopped at the registry; let go,
     * the entry stays with the second reader. After: the only reader's release is stopped at the registry with its
     * lock already unlocked; let go, the entry is removed, and a writer that comes next gets a new entry while the
     * old one is unlocked and unreferenced. Then the two are raced from a barrier a thousand times, and every
     * outcome must be one of these two.
     */
    @Test
    public void klr9ARequestJustBeforeOrJustAfterTheRemoval() throws Exception {
        List<String> violations = new ArrayList<>();
        for (Family family : Family.values()) {
            String what = family + ", just before: ";
            Object key = family.newKey("klr9-before");
            Holder leaving = Holder.reader(family, key, LONG);
            Holder arriving = null;
            try {
                expectHeld(violations, what + "the leaving reader", leaving);
                Seen first = seen(family, key);
                arriving = Holder.reader(family, key, LONG);
                expectHeld(violations, what + "the arriving reader", arriving);
                try (Barrier barrier = new Barrier(family, key)) {
                    leaving.releaseLater();
                    if (!awaitBlocked(leaving.thread())) {
                        violations.add(what + "the leaving reader's release must reach the registry for its key");
                    }
                    Seen inside = barrier.look();
                    expectSame(violations, what + "at the release", first, inside);
                    expectReferences(violations, what + "at the release", 2, inside);
                    if (inside != null && inside.lock().getReadLockCount() != 1) {
                        violations.add(what + "the leaving reader must have unlocked, read locks " + inside.lock().getReadLockCount());
                    }
                }
                leaving.awaitDone();
                Seen after = seen(family, key);
                expectSame(violations, what + "after the release", first, after);
                expectReferences(violations, what + "after the release", 1, after);
            } finally {
                leaving.release();
                if (arriving != null) {
                    arriving.release();
                }
            }
            expectAbsent(violations, what + "once both left", family, key);

            what = family + ", just after: ";
            key = family.newKey("klr9-after");
            Holder only = Holder.reader(family, key, LONG);
            Holder next = null;
            try {
                expectHeld(violations, what + "the only reader", only);
                Seen old = seen(family, key);
                try (Barrier barrier = new Barrier(family, key)) {
                    only.releaseLater();
                    if (!awaitBlocked(only.thread())) {
                        violations.add(what + "the reader's release must reach the registry for its key");
                    }
                    Seen inside = barrier.look();
                    expectSame(violations, what + "at the release", old, inside);
                    expectReferences(violations, what + "at the release", 1, inside);
                    if (inside != null && inside.lock().getReadLockCount() != 0) {
                        violations.add(what + "the reader must unlock before it gives its reference back");
                    }
                }
                only.awaitDone();
                expectAbsent(violations, what + "after the last release", family, key);
                next = Holder.writer(family, key);
                expectHeld(violations, what + "the next writer", next);
                Seen fresh = seen(family, key);
                if (old != null && fresh != null && fresh.entry() == old.entry()) {
                    violations.add(what + "the next writer must get a new entry, not the removed one");
                }
                expectReferences(violations, what + "the new entry", 1, fresh);
                expectRetired(violations, what, old);
            } finally {
                only.release();
                if (next != null) {
                    next.release();
                }
            }
            expectAbsent(violations, what + "once the writer left", family, key);

            raceTheRemoval(violations, family);
        }
        Assertions.assertEquals(List.of(), violations, "KLR-9");
    }

    private static void raceTheRemoval(@NotNull List<String> violations, @NotNull Family family) throws Exception {
        int kept = 0;
        int replaced = 0;
        for (int i = 0; i < RACES && violations.size() < 20; i++) {
            String what = family + ", race " + i + ": ";
            Object key = family.newKey("klr9-race");
            CyclicBarrier start = new CyclicBarrier(2);
            Holder leaving = Holder.readerClosingAt(family, key, start);
            expectHeld(violations, what + "the leaving reader", leaving);
            Seen old = seen(family, key);
            Holder arriving = Holder.writerAfter(family, key, start);
            leaving.releaseLater();
            try {
                expectHeld(violations, what + "the arriving writer", arriving);
                leaving.awaitDone();
                Seen now = seen(family, key);
                expectReferences(violations, what + "the arriving writer's entry", 1, now);
                if (now != null && !now.lock().isWriteLocked()) {
                    violations.add(what + "the key's entry must be the one the writer holds");
                }
                if (old != null && now != null && now.entry() == old.entry()) {
                    kept++;
                } else {
                    replaced++;
                    expectRetired(violations, what, old);
                }
            } finally {
                leaving.release();
                arriving.release();
            }
            expectAbsent(violations, what + "once both left", family, key);
        }
        System.out.println("DBAC_KEY_LOCK_RACE family=" + family + " races=" + RACES + " entryKept=" + kept + " entryReplaced=" + replaced);
    }

    /**
     * KLR-10: no grant key or user ever has two entries in use at once
     * <p>
     * Eight threads hammer one key with writes and reads, some of the reads with a timeout too short to wait. Inside
     * every hold the thread checks that the entry the key maps to is the one whose lock it holds, and that writers
     * and readers exclude each other.
     */
    @Test
    public void klr10NoTwoEntriesOfOneKeyAreInUseAtOnce() throws Exception {
        List<String> violations = Collections.synchronizedList(new ArrayList<>());
        for (Family family : Family.values()) {
            Object key = family.newKey("klr10");
            AtomicInteger writers = new AtomicInteger();
            AtomicInteger readers = new AtomicInteger();
            AtomicInteger holds = new AtomicInteger();
            List<Worker<Object>> threads = new ArrayList<>();
            CyclicBarrier start = new CyclicBarrier(8);
            for (int t = 0; t < 8; t++) {
                threads.add(Worker.start("dbac-klr10-" + t, () -> {
                    start.await(WAIT_SECONDS, TimeUnit.SECONDS);
                    ThreadLocalRandom random = ThreadLocalRandom.current();
                    for (int i = 0; i < 2_000 && violations.size() < 20; i++) {
                        int roll = random.nextInt(8);
                        if (roll < 2) {
                            try (EnforcementKeyLocks.Held ignored = family.write(key)) {
                                insideWrite(violations, family, key, writers, readers);
                                holds.incrementAndGet();
                            }
                        } else {
                            Duration timeout = roll < 4 ? Duration.ofMillis(1) : LONG;
                            try (EnforcementKeyLocks.Held held = family.read(key, timeout)) {
                                if (held != null) {
                                    insideRead(violations, family, key, writers, readers);
                                    holds.incrementAndGet();
                                }
                            }
                        }
                    }
                    return null;
                }));
            }
            for (Worker<Object> thread : threads) {
                if (!thread.awaitDone() || thread.error != null) {
                    violations.add(family + ": a thread did not finish cleanly: " + thread.error);
                }
            }
            if (holds.get() == 0) {
                violations.add(family + ": nothing was ever held");
            }
            expectAbsent(violations, family + ": once all left", family, key);
        }
        Assertions.assertEquals(List.of(), violations, "KLR-10");
    }

    private static void insideWrite(
        @NotNull List<String> violations,
        @NotNull Family family,
        @NotNull Object key,
        @NotNull AtomicInteger writers,
        @NotNull AtomicInteger readers
    ) {
        if (writers.incrementAndGet() != 1 || readers.get() != 0) {
            violations.add(family + ": a writer got in next to writers=" + writers.get() + " readers=" + readers.get());
        }
        Seen seen = seen(family, key);
        if (seen == null || !seen.lock().isWriteLockedByCurrentThread()) {
            violations.add(family + ": a writer's key maps to an entry whose lock it does not hold");
        }
        writers.decrementAndGet();
    }

    private static void insideRead(
        @NotNull List<String> violations,
        @NotNull Family family,
        @NotNull Object key,
        @NotNull AtomicInteger writers,
        @NotNull AtomicInteger readers
    ) {
        readers.incrementAndGet();
        if (writers.get() != 0) {
            violations.add(family + ": a reader got in next to a writer");
        }
        Seen seen = seen(family, key);
        if (seen == null || seen.lock().getReadHoldCount() == 0) {
            violations.add(family + ": a reader's key maps to an entry whose lock it does not hold");
        }
        readers.decrementAndGet();
    }

    /**
     * KLR-11: a release removes the key's entry only when that entry is its own
     * <p>
     * Nothing in production can put another entry under a key while one is referenced; the case does it by
     * reflection, to see the check that the last release makes. The release must leave the other entry where it is.
     */
    @Test
    public void klr11AReleaseRemovesOnlyItsOwnEntry() throws Exception {
        List<String> violations = new ArrayList<>();
        for (Family family : Family.values()) {
            String what = family + ": ";
            Object key = family.newKey("klr11");
            Holder reader = Holder.reader(family, key, LONG);
            Object other = null;
            try {
                expectHeld(violations, what + "the reader", reader);
                Seen own = seen(family, key);
                expectReferences(violations, what + "with the reader", 1, own);
                if (own == null) {
                    continue;
                }
                other = anotherEntryLike(own.entry());
                if (!map(family).replace(key, own.entry(), other)) {
                    violations.add(what + "FIXTURE could not put another entry under the key");
                }
                reader.release();
                Seen left = seen(family, key);
                if (left == null || left.entry() != other) {
                    violations.add(what + "the last release must leave another entry under its key alone, found " + left);
                }
            } finally {
                reader.release();
                if (other != null) {
                    map(family).remove(key, other);
                }
            }
            expectAbsent(violations, what + "after the case", family, key);
        }
        Assertions.assertEquals(List.of(), violations, "KLR-11");
    }

    // ---------------------------------------------------------------- KLR-12: the API

    /**
     * KLR-12: the registry offers only what it did - no test-only mutator, no reset, no other way to make one
     */
    @Test
    public void klr12TheRegistryHasNoTestOrResetApi() {
        List<String> violations = new ArrayList<>();
        Set<String> methods = new TreeSet<>();
        for (Method method : EnforcementKeyLocks.class.getDeclaredMethods()) {
            if (Modifier.isPublic(method.getModifiers()) && !method.isSynthetic()) {
                methods.add(method.getName());
            }
        }
        expect(violations, "public methods", new TreeSet<>(List.of("global", "lockGrantForWrite", "lockUserForWrite",
            "tryLockGrantForRead", "tryLockUserForRead")), methods);
        Set<String> fields = new TreeSet<>();
        for (Field field : EnforcementKeyLocks.class.getDeclaredFields()) {
            if (Modifier.isPublic(field.getModifiers())) {
                fields.add(field.getName());
            }
        }
        expect(violations, "public fields", new TreeSet<>(List.of("MAX_READ_TIMEOUT")), fields);
        Set<String> types = new TreeSet<>();
        for (Class<?> type : EnforcementKeyLocks.class.getDeclaredClasses()) {
            if (Modifier.isPublic(type.getModifiers())) {
                types.add(type.getSimpleName());
            }
        }
        expect(violations, "public nested types", new TreeSet<>(List.of("Held")), types);
        expect(violations, "Held's methods", List.of("close"),
            Arrays.stream(EnforcementKeyLocks.Held.class.getDeclaredMethods()).map(Method::getName).toList());
        for (Constructor<?> constructor : EnforcementKeyLocks.class.getDeclaredConstructors()) {
            if (!Modifier.isPrivate(constructor.getModifiers())) {
                violations.add("every constructor must be private: " + constructor);
            }
        }
        Assertions.assertEquals(List.of(), violations, "KLR-12");
    }

    // ---------------------------------------------------------------- holders

    /** Takes a lock */
    @FunctionalInterface
    private interface Take {
        @Nullable
        EnforcementKeyLocks.Held take() throws InterruptedException;
    }

    /**
     * One lock request on a thread of its own: takes the lock, holds it until released, then closes it {@code closes} times
     */
    private static final class Holder {
        private final Worker<Object> worker;
        private final CountDownLatch settled = new CountDownLatch(1);
        private final CountDownLatch release = new CountDownLatch(1);
        volatile boolean held;

        /**
         * Starts the request
         *
         * @param meet where the holder meets the other party of a race, or null
         * @param meetFirst whether it meets it before it asks for the lock - otherwise before it closes
         */
        private Holder(@NotNull String name, @NotNull Take take, int closes, @Nullable CyclicBarrier meet, boolean meetFirst) {
            this.worker = Worker.start(name, () -> {
                EnforcementKeyLocks.Held hold = null;
                try {
                    if (meet != null && meetFirst) {
                        meet.await(WAIT_SECONDS, TimeUnit.SECONDS);
                    }
                    hold = take.take();
                    held = hold != null;
                } finally {
                    settled.countDown();
                }
                if (hold == null) {
                    return null;
                }
                release.await(WAIT_SECONDS * 2, TimeUnit.SECONDS);
                if (meet != null && !meetFirst) {
                    meet.await(WAIT_SECONDS, TimeUnit.SECONDS);
                }
                for (int i = 0; i < closes; i++) {
                    hold.close();
                }
                return null;
            });
        }

        @NotNull
        static Holder writer(@NotNull Family family, @NotNull Object key) {
            return writer(family, key, 1);
        }

        @NotNull
        static Holder writer(@NotNull Family family, @NotNull Object key, int closes) {
            return new Holder("dbac-klr-writer", () -> family.write(key), closes, null, false);
        }

        /** A writer that asks for the lock only once it meets the other party at {@code meet} */
        @NotNull
        static Holder writerAfter(@NotNull Family family, @NotNull Object key, @NotNull CyclicBarrier meet) {
            return new Holder("dbac-klr-writer", () -> family.write(key), 1, meet, true);
        }

        @NotNull
        static Holder reader(@NotNull Family family, @NotNull Object key, @NotNull Duration timeout) {
            return reader(family, key, timeout, 1);
        }

        @NotNull
        static Holder reader(@NotNull Family family, @NotNull Object key, @NotNull Duration timeout, int closes) {
            return new Holder("dbac-klr-reader", () -> family.read(key, timeout), closes, null, false);
        }

        /** A reader that, once released, closes only when it meets the other party at {@code meet} */
        @NotNull
        static Holder readerClosingAt(@NotNull Family family, @NotNull Object key, @NotNull CyclicBarrier meet) {
            return new Holder("dbac-klr-reader", () -> family.read(key, LONG), 1, meet, false);
        }

        @NotNull
        Thread thread() {
            return worker.thread;
        }

        @Nullable
        Throwable error() {
            return worker.error;
        }

        boolean awaitSettled() throws InterruptedException {
            return settled.await(WAIT_SECONDS, TimeUnit.SECONDS);
        }

        /** Lets the holder close, without waiting for it */
        void releaseLater() {
            release.countDown();
        }

        void awaitDone() throws InterruptedException {
            Assertions.assertTrue(worker.awaitDone(), "FIXTURE: " + worker.thread.getName() + " did not finish");
        }

        /** Lets the holder close and waits until it has */
        void release() throws InterruptedException {
            release.countDown();
            awaitDone();
        }
    }

    private static void expectHeld(
        @NotNull List<String> violations,
        @NotNull String what,
        @NotNull Holder holder
    ) throws InterruptedException {
        if (!holder.awaitSettled() || !holder.held) {
            violations.add(what + " must hold its lock, error=" + holder.error());
        }
    }

    /** A writer from elsewhere must not get the key while {@code holder} holds it */
    private static void expectNotWritable(
        @NotNull List<String> violations,
        @NotNull String what,
        @NotNull Family family,
        @NotNull Object key,
        @NotNull Holder holder
    ) throws InterruptedException {
        Holder probe = Holder.writer(family, key);
        try {
            if (probe.settled.await(500, TimeUnit.MILLISECONDS)) {
                violations.add(what + "a writer from elsewhere got the key while a reader still held it");
            }
        } finally {
            holder.release();
            probe.release();
        }
    }

    // ---------------------------------------------------------------- the registry's state, by reflection

    /**
     * What the registry keeps for a key: the entry, its lock, and the references it counts (null where there is no count)
     */
    private record Seen(@NotNull Object entry, @NotNull ReentrantReadWriteLock lock, @Nullable Integer references) {
    }

    /** The registry's map for one family */
    @NotNull
    @SuppressWarnings("unchecked")
    private static ConcurrentHashMap<Object, Object> map(@NotNull Family family) {
        try {
            for (Field field : EnforcementKeyLocks.class.getDeclaredFields()) {
                if (Modifier.isStatic(field.getModifiers()) || !field.getName().startsWith(family.field)) {
                    continue;
                }
                field.setAccessible(true);
                Object value = field.get(EnforcementKeyLocks.global());
                if (value instanceof ConcurrentHashMap<?, ?> found) {
                    return (ConcurrentHashMap<Object, Object>) found;
                }
                for (Field inner : value.getClass().getDeclaredFields()) {
                    if (ConcurrentHashMap.class.isAssignableFrom(inner.getType())) {
                        inner.setAccessible(true);
                        return (ConcurrentHashMap<Object, Object>) inner.get(value);
                    }
                }
            }
        } catch (IllegalAccessException e) {
            throw new IllegalStateException("FIXTURE: the registry could not be read", e);
        }
        throw new IllegalStateException("FIXTURE: the registry has no map for " + family);
    }

    /**
     * What the key maps to now, read inside the map's own lock for the key, where the registry changes its counts
     */
    @Nullable
    private static Seen seen(@NotNull Family family, @NotNull Object key) {
        Seen[] found = new Seen[1];
        map(family).compute(key, (k, value) -> {
            found[0] = value == null ? null : describe(value);
            return value;
        });
        return found[0];
    }

    @NotNull
    private static Seen describe(@NotNull Object value) {
        if (value instanceof ReentrantReadWriteLock lock) {
            return new Seen(value, lock, null);
        }
        ReentrantReadWriteLock lock = null;
        Integer references = null;
        try {
            for (Field field : value.getClass().getDeclaredFields()) {
                if (Modifier.isStatic(field.getModifiers())) {
                    continue;
                }
                field.setAccessible(true);
                if (field.getType() == ReentrantReadWriteLock.class) {
                    lock = (ReentrantReadWriteLock) field.get(value);
                } else if (field.getType() == int.class) {
                    references = field.getInt(value);
                }
            }
        } catch (IllegalAccessException e) {
            throw new IllegalStateException("FIXTURE: an entry could not be read", e);
        }
        if (lock == null) {
            throw new IllegalStateException("FIXTURE: an entry without a lock: " + value.getClass());
        }
        return new Seen(value, lock, references);
    }

    /** A new, unreferenced entry of the same kind - the only way to see what a release does to an entry not its own */
    @NotNull
    private static Object anotherEntryLike(@NotNull Object entry) throws ReflectiveOperationException {
        if (entry instanceof ReentrantReadWriteLock) {
            return new ReentrantReadWriteLock(true);
        }
        Constructor<?> constructor = entry.getClass().getDeclaredConstructor();
        constructor.setAccessible(true);
        return constructor.newInstance();
    }

    private static void expectSame(@NotNull List<String> violations, @NotNull String what, @Nullable Seen expected, @Nullable Seen actual) {
        if (expected == null || actual == null || expected.entry() != actual.entry()) {
            violations.add(what + ": the key must still map to the same entry, expected " + expected + ", got " + actual);
        }
    }

    private static void expectReferences(@NotNull List<String> violations, @NotNull String what, int expected, @Nullable Seen seen) {
        if (seen == null) {
            violations.add(what + ": the key must have an entry");
        } else if (seen.references() == null || seen.references() != expected) {
            violations.add(what + ": references expected " + expected + ", got " + seen.references());
        }
    }

    private static void expectAbsent(@NotNull List<String> violations, @NotNull String what, @NotNull Family family, @NotNull Object key) {
        Seen left = seen(family, key);
        if (left != null) {
            violations.add(what + ": the key must have no entry, found references=" + left.references());
        }
    }

    /** A removed entry is unlocked, unqueued and unreferenced: nobody can be using it */
    private static void expectRetired(@NotNull List<String> violations, @NotNull String what, @Nullable Seen old) {
        if (old == null) {
            violations.add(what + "the old entry was never seen");
            return;
        }
        Seen now = describe(old.entry());
        if (now.lock().isWriteLocked() || now.lock().getReadLockCount() != 0 || now.lock().hasQueuedThreads()) {
            violations.add(what + "the removed entry's lock must be free and unqueued");
        }
        if (now.references() == null || now.references() != 0) {
            violations.add(what + "the removed entry must count no reference, got " + now.references());
        }
    }

    private static void expect(@NotNull List<String> violations, @NotNull String what, @Nullable Object expected, @Nullable Object actual) {
        if (!java.util.Objects.equals(expected, actual)) {
            violations.add(what + ": expected " + expected + ", got " + actual);
        }
    }

    // ---------------------------------------------------------------- the barrier

    /**
     * Holds the registry map's lock for one key on a thread of its own
     * <p>
     * While it is held, anything that takes or gives back a reference for that key stops at the map, and the test
     * can look at the entry from inside the lock where the counts change.
     */
    private static final class Barrier implements AutoCloseable {
        private final CountDownLatch inside = new CountDownLatch(1);
        private final CountDownLatch look = new CountDownLatch(1);
        private final CountDownLatch looked = new CountDownLatch(1);
        private final CountDownLatch open = new CountDownLatch(1);
        private final Worker<Object> worker;
        @Nullable
        private volatile Seen seen;

        Barrier(@NotNull Family family, @NotNull Object key) throws InterruptedException {
            this.worker = Worker.start("dbac-klr-barrier", () -> {
                map(family).compute(key, (k, value) -> {
                    inside.countDown();
                    try {
                        if (look.await(WAIT_SECONDS * 2, TimeUnit.SECONDS)) {
                            seen = value == null ? null : describe(value);
                        }
                        looked.countDown();
                        open.await(WAIT_SECONDS * 2, TimeUnit.SECONDS);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                    return value;
                });
                return null;
            });
            Assertions.assertTrue(inside.await(WAIT_SECONDS, TimeUnit.SECONDS), "FIXTURE: the barrier did not take the key");
        }

        /** The entry as it is now, seen from inside the barrier */
        @Nullable
        Seen look() throws InterruptedException {
            look.countDown();
            Assertions.assertTrue(looked.await(WAIT_SECONDS, TimeUnit.SECONDS), "FIXTURE: the barrier did not look");
            return seen;
        }

        @Override
        public void close() throws InterruptedException {
            look.countDown();
            open.countDown();
            Assertions.assertTrue(worker.awaitDone(), "FIXTURE: the barrier did not finish");
        }
    }

    /** Whether {@code thread} is blocked on a monitor - seen so several times in a row - rather than running or done */
    private static boolean awaitBlocked(@NotNull Thread thread) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        int blocked = 0;
        while (System.nanoTime() < deadline) {
            Thread.State state = thread.getState();
            if (state == Thread.State.TERMINATED) {
                return false;
            }
            blocked = state == Thread.State.BLOCKED ? blocked + 1 : 0;
            if (blocked >= 5) {
                return true;
            }
            Thread.sleep(20);
        }
        return false;
    }

    private static boolean eventually(@NotNull BooleanSupplier condition) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (System.nanoTime() < deadline) {
            if (condition.getAsBoolean()) {
                return true;
            }
            Thread.sleep(10);
        }
        return condition.getAsBoolean();
    }
}
