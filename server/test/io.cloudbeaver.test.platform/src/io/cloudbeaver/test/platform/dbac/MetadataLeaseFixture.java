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

import io.cloudbeaver.service.dbac.policy.BoundedMetadataConnections;
import io.cloudbeaver.service.dbac.policy.MetadataLeaseSource;
import io.cloudbeaver.service.dbac.tempwrite.MetadataConnectionSource;
import org.jkiss.code.NotNull;
import org.junit.jupiter.api.Assertions;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * The only place a test makes a bounded metadata source, and the owner of every one it makes
 * <p>
 * A test that needs leases over a raw connection source asks this fixture, which keeps the whole of
 * what the bounded source's {@code create} returns - the leases and the shutdown - and, when the
 * test ends, shuts each source down in both phases: {@code beginClose} for all, then
 * {@code finishClose} for all. The raw connections belong to the test, so there is no pool close
 * between them. A source left with a stuck worker, a quarantined or kept connection, or a slot still
 * held fails the test, unless the test said that is what it is about.
 * <p>
 * Not thread-safe: a test makes its sources on its own thread.
 */
final class MetadataLeaseFixture implements AutoCloseable {

    /** How long to wait for a closed source's worker threads to be gone */
    private static final long THREADS_GONE_MILLIS = TimeUnit.SECONDS.toMillis(10);

    private final List<BoundedMetadataConnections.Owned> owned = new ArrayList<>();
    private boolean residueAllowed;

    /**
     * Leases over {@code raw}, with the production timings
     */
    @NotNull
    MetadataLeaseSource of(@NotNull MetadataConnectionSource raw) {
        return owned(raw, BoundedMetadataConnections.Tuning.PRODUCTION).leases();
    }

    /**
     * The same, as the bounded source itself, so a test can read its counters
     */
    @NotNull
    BoundedMetadataConnections bounded(@NotNull MetadataConnectionSource raw, @NotNull BoundedMetadataConnections.Tuning tuning) {
        return owned(raw, tuning).leases();
    }

    /**
     * Both halves; the fixture still owns them and still shuts the source down, which is harmless if the test did first
     */
    @NotNull
    BoundedMetadataConnections.Owned owned(@NotNull MetadataConnectionSource raw, @NotNull BoundedMetadataConnections.Tuning tuning) {
        BoundedMetadataConnections.Owned made = BoundedMetadataConnections.create(raw, tuning);
        owned.add(made);
        return made;
    }

    /**
     * Shuts {@code which} down now, both phases, and stops owning it - so nothing in the test keeps it reachable
     */
    void closeAndForget(@NotNull BoundedMetadataConnections.Owned which) {
        which.shutdown().beginClose();
        which.shutdown().finishClose();
        owned.remove(which);
    }

    /**
     * Lets the test end with a stuck worker, a quarantine or a residual, because that is what it is about
     */
    void allowResidue() {
        residueAllowed = true;
    }

    /**
     * Every source made so far
     */
    @NotNull
    List<BoundedMetadataConnections.Owned> made() {
        return List.copyOf(owned);
    }

    /**
     * Both phases for every source, then the leak check
     */
    @Override
    public void close() {
        List<BoundedMetadataConnections.Owned> all = List.copyOf(owned);
        owned.clear();
        for (BoundedMetadataConnections.Owned one : all) {
            one.shutdown().beginClose();
        }
        for (BoundedMetadataConnections.Owned one : all) {
            one.shutdown().finishClose();
        }
        if (residueAllowed) {
            return;
        }
        List<String> leaks = new ArrayList<>();
        for (BoundedMetadataConnections.Owned one : all) {
            BoundedMetadataConnections source = one.leases();
            BoundedMetadataConnections.ShutdownReport report = source.lastShutdownReport();
            if (report == null || !report.clean() || report.quarantineReleased() != 0) {
                leaks.add("source " + source.serial() + " shut down with " + report);
            }
            if (source.residualHeld() != 0 || source.quarantined() != 0 || source.runningWorkers() != 0) {
                leaks.add("source " + source.serial() + " still holds residual=" + source.residualHeld()
                    + " quarantined=" + source.quarantined() + " running=" + source.runningWorkers());
            }
            if (source.availableSlots() != BoundedMetadataConnections.CAPACITY) {
                leaks.add("source " + source.serial() + " has " + source.availableSlots() + " free slots after shutdown");
            }
        }
        for (BoundedMetadataConnections.Owned one : all) {
            int alive = awaitThreadsGone(one.leases().serial());
            if (alive != 0) {
                leaks.add("source " + one.leases().serial() + " still has " + alive + " worker threads");
            }
        }
        Assertions.assertEquals(List.of(), leaks, "LEAK: a bounded metadata source did not shut down clean");
    }

    /**
     * Live worker threads of the source with this serial, after waiting a bounded time for them to end
     */
    static int awaitThreadsGone(long serial) {
        long deadline = System.currentTimeMillis() + THREADS_GONE_MILLIS;
        int alive = workerThreads(serial);
        while (alive != 0 && System.currentTimeMillis() < deadline) {
            try {
                Thread.sleep(20);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
            alive = workerThreads(serial);
        }
        return alive;
    }

    /**
     * Live worker threads of the source with this serial
     */
    static int workerThreads(long serial) {
        String prefix = BoundedMetadataConnections.THREAD_PREFIX + serial + "-";
        Set<Thread> threads = Thread.getAllStackTraces().keySet();
        int alive = 0;
        for (Thread thread : threads) {
            if (thread.isAlive() && thread.getName().startsWith(prefix)) {
                alive++;
            }
        }
        return alive;
    }
}
