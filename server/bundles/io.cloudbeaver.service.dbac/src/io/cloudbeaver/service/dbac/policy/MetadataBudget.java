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
package io.cloudbeaver.service.dbac.policy;

import org.jkiss.code.NotNull;

import java.time.Duration;
import java.util.function.LongSupplier;

/**
 * How much time one metadata read may take in total, from waiting for a connection to the last row
 * <p>
 * One budget covers the borrow and the statement together: a connection that took most of the
 * budget to arrive leaves only the rest for the statement, and a result that arrives after the budget
 * is spent is thrown away rather than acted on.
 * <p>
 * <b>Elapsed time only grows.</b> It is measured as {@code now - start} on a monotonic nanosecond
 * clock, never compared as an absolute value, so the clock may start anywhere and wrap. It is floored
 * at zero and at the largest value already measured, so a clock that steps backwards cannot hand time
 * back.
 * <p>
 * <b>Whole seconds only reach JDBC.</b> {@link #wholeSeconds()} rounds the remaining time down, so a
 * query timeout built from it never exceeds what is left. A statement is never started with less than
 * one whole second: JDBC reads a timeout of zero as "no limit".
 * <p>
 * Thread-safe; in practice one thread uses it.
 */
public final class MetadataBudget {

    private final LongSupplier clock;
    private final long startNanos;
    private final Duration total;
    /** The largest elapsed time measured so far; no later measurement is smaller */
    private long elapsedFloorNanos;

    private MetadataBudget(@NotNull LongSupplier clock, long startNanos, @NotNull Duration total) {
        if (total.isNegative() || total.isZero()) {
            throw new IllegalArgumentException("A metadata budget must be positive, got " + total);
        }
        this.clock = clock;
        this.startNanos = startNanos;
        this.total = total;
    }

    /**
     * A budget of {@code total} that starts now, by {@code clock}
     *
     * @param clock a monotonic nanosecond counter, {@code System::nanoTime} in production
     */
    @NotNull
    public static MetadataBudget startingNow(@NotNull LongSupplier clock, @NotNull Duration total) {
        return new MetadataBudget(clock, clock.getAsLong(), total);
    }

    /**
     * A budget of {@code total} that started at {@code startNanos} on {@code clock}
     * <p>
     * For a budget that has to be counted from a point already measured, rather than from now.
     */
    @NotNull
    public static MetadataBudget startedAt(@NotNull LongSupplier clock, long startNanos, @NotNull Duration total) {
        return new MetadataBudget(clock, startNanos, total);
    }

    /**
     * The whole budget
     */
    @NotNull
    public Duration total() {
        return total;
    }

    /**
     * Time spent since the start: {@code max(largest so far, max(0, now - start))}
     */
    public synchronized long elapsedNanos() {
        long sinceStart = clock.getAsLong() - startNanos;
        elapsedFloorNanos = Math.max(elapsedFloorNanos, Math.max(0L, sinceStart));
        return elapsedFloorNanos;
    }

    /**
     * What is left; negative once the budget is overspent
     */
    @NotNull
    public Duration remaining() {
        return total.minus(Duration.ofNanos(elapsedNanos()));
    }

    /**
     * What is left in nanoseconds, never more than {@link Long#MAX_VALUE}; zero or negative once spent
     */
    public long remainingNanos() {
        Duration left = remaining();
        if (left.isNegative() || left.isZero()) {
            return left.isZero() ? 0L : -1L;
        }
        return left.compareTo(Duration.ofNanos(Long.MAX_VALUE)) >= 0 ? Long.MAX_VALUE : left.toNanos();
    }

    /**
     * What is left in whole seconds, rounded down; zero once less than one second is left
     */
    public int wholeSeconds() {
        Duration left = remaining();
        if (left.isNegative()) {
            return 0;
        }
        long seconds = left.getSeconds();
        return seconds > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int) seconds;
    }

    /**
     * Whether more than the whole budget has been spent
     */
    public boolean isOverspent() {
        return remaining().isNegative();
    }
}
