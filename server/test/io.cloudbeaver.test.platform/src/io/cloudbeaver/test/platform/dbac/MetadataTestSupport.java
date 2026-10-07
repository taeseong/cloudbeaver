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
import io.cloudbeaver.service.dbac.policy.MetadataBudget;
import io.cloudbeaver.service.dbac.policy.MetadataLease;
import io.cloudbeaver.service.dbac.policy.MetadataLeaseSource;
import io.cloudbeaver.service.dbac.policy.MetadataPurpose;
import io.cloudbeaver.service.dbac.policy.MetadataQuery;
import io.cloudbeaver.service.dbac.policy.MetadataUnavailableException;
import io.cloudbeaver.service.dbac.tempwrite.MetadataConnectionSource;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.junit.jupiter.api.Assertions;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.LongSupplier;

/**
 * Scripted JDBC objects, clocks and bounded waits for the P5-1a metadata lease tests
 * <p>
 * A {@link FakeConnection} answers exactly the calls a metadata lease makes and refuses everything
 * else, records each call in order, and can be told to fail any one of them. Its abort closes it, as
 * pgjdbc's does, unless told to behave like H2's, which does nothing. Its query timeout
 * behaves like H2's: it belongs to the session, so a value set on one statement is what the next
 * statement reads - which is what makes a missing restore visible.
 * <p>
 * Every wait in these tests is bounded and turns into an assertion failure, never a hung run: a
 * blocked call that does not come back in time fails the test and is then released.
 */
final class MetadataTestSupport {

    /** A secret that must never reach a log: a URL, a host and a password, as a driver message would carry them */
    static final String SECRET_MESSAGE = "jdbc:h2:tcp://secret-metadata.internal.example/cb;USER=cb;PASSWORD=dbac-lease-pw-7c2e";
    /** The parts of {@link #SECRET_MESSAGE} a log must not contain */
    static final List<String> SECRET_FRAGMENTS = List.of("secret-metadata.internal.example", "dbac-lease-pw-7c2e", "jdbc:h2:tcp://");

    /** A whole budget long enough that nothing in a test runs out of it by accident */
    static final Duration LONG = Duration.ofSeconds(20);

    private static final AtomicInteger CONNECTIONS = new AtomicInteger();

    private MetadataTestSupport() {
    }

    /** A failure the code under test cannot have made itself */
    static final class InjectedSqlException extends SQLException {
        InjectedSqlException(@NotNull String where) {
            super("injected " + where + " " + SECRET_MESSAGE, "08006");
        }
    }

    /** An injected {@link Error} */
    static final class InjectedLeaseError extends Error {
        InjectedLeaseError(@NotNull String where) {
            super("injected " + where + " " + SECRET_MESSAGE);
        }
    }

    // ---------------------------------------------------------------- scripted connection

    /**
     * One scripted metadata connection
     * <p>
     * Every knob is a failure to throw at one call; {@code null} means the call works.
     */
    static final class FakeConnection implements InvocationHandler {
        final int id = CONNECTIONS.incrementAndGet();
        final List<String> journal = Collections.synchronizedList(new ArrayList<>());
        final Connection proxy;
        final AtomicInteger sessionTimeout = new AtomicInteger();
        final AtomicInteger closes = new AtomicInteger();
        final AtomicInteger aborts = new AtomicInteger();
        final AtomicInteger prepares = new AtomicInteger();
        final AtomicInteger executes = new AtomicInteger();
        final AtomicReference<Thread> closedBy = new AtomicReference<>();
        volatile boolean autoCommit = true;
        /** An abort that returns but leaves the connection open, as H2 2.4's does */
        volatile boolean abortIneffective;
        volatile boolean aborted;
        volatile boolean closed;
        @Nullable volatile Throwable autoCommitFails;
        @Nullable volatile Throwable prepareFails;
        @Nullable volatile Throwable getTimeoutFails;
        @Nullable volatile Throwable setTimeoutFails;
        @Nullable volatile Throwable executeFails;
        /** Thrown by {@code ResultSet.next}: the driver cannot fetch a row */
        @Nullable volatile Throwable readFails;
        @Nullable volatile Throwable resultCloseFails;
        @Nullable volatile Throwable statementCloseFails;
        @Nullable volatile Throwable restoreCreateFails;
        @Nullable volatile Throwable restoreSetFails;
        @Nullable volatile Throwable restoreCloseFails;
        @Nullable volatile Throwable closeFails;
        @Nullable volatile Throwable abortFails;
        @Nullable volatile Throwable closeAfterAbortFails;
        /** Rows an executed query returns; the value of a missing column is SQL NULL */
        volatile List<Map<String, Object>> rows = List.of(Map.of("V", "value"));
        volatile int updateCount = 1;
        /** Runs inside executeQuery/executeUpdate, before it returns */
        volatile Runnable onExecute = () -> {
        };

        FakeConnection() {
            this.proxy = proxy(Connection.class, this);
        }

        @Nullable
        @Override
        public Object invoke(@NotNull Object self, @NotNull Method method, @Nullable Object[] args) throws Throwable {
            String name = method.getName();
            switch (name) {
                case "getAutoCommit" -> {
                    journal.add("getAutoCommit");
                    fail(autoCommitFails);
                    return autoCommit;
                }
                case "prepareStatement" -> {
                    journal.add("prepareStatement");
                    prepares.incrementAndGet();
                    fail(prepareFails);
                    return statement();
                }
                case "createStatement" -> {
                    journal.add("createStatement");
                    fail(restoreCreateFails);
                    return restoreStatement();
                }
                case "abort" -> {
                    journal.add("abort");
                    aborts.incrementAndGet();
                    fail(abortFails);
                    aborted = true;
                    if (!abortIneffective) {
                        closed = true;
                    }
                    return null;
                }
                case "close" -> {
                    journal.add(aborted ? "close-after-abort" : "close");
                    closes.incrementAndGet();
                    fail(aborted ? closeAfterAbortFails : closeFails);
                    closed = true;
                    closedBy.set(Thread.currentThread());
                    return null;
                }
                case "isClosed" -> {
                    return closed;
                }
                case "hashCode" -> {
                    return System.identityHashCode(self);
                }
                case "equals" -> {
                    return self == args[0];
                }
                case "toString" -> {
                    return "fake-connection#" + id;
                }
                default -> throw new UnsupportedOperationException("Connection." + name);
            }
        }

        @NotNull
        private PreparedStatement statement() {
            return proxy(PreparedStatement.class, (self, method, args) -> {
                String name = method.getName();
                switch (name) {
                    case "getQueryTimeout" -> {
                        journal.add("getQueryTimeout");
                        fail(getTimeoutFails);
                        return sessionTimeout.get();
                    }
                    case "setQueryTimeout" -> {
                        journal.add("setQueryTimeout(" + args[0] + ")");
                        fail(setTimeoutFails);
                        sessionTimeout.set((Integer) args[0]);
                        return null;
                    }
                    case "setString", "setObject", "setNull" -> {
                        journal.add(name + "(" + args[0] + "," + describe(args[1]) + ")");
                        return null;
                    }
                    case "executeQuery" -> {
                        journal.add("executeQuery");
                        executes.incrementAndGet();
                        onExecute.run();
                        fail(executeFails);
                        return resultSet(rows);
                    }
                    case "executeUpdate" -> {
                        journal.add("executeUpdate");
                        executes.incrementAndGet();
                        onExecute.run();
                        fail(executeFails);
                        return updateCount;
                    }
                    case "close" -> {
                        journal.add("statement.close");
                        fail(statementCloseFails);
                        return null;
                    }
                    case "hashCode" -> {
                        return System.identityHashCode(self);
                    }
                    case "equals" -> {
                        return self == args[0];
                    }
                    default -> throw new UnsupportedOperationException("PreparedStatement." + name);
                }
            });
        }

        @NotNull
        private Statement restoreStatement() {
            return proxy(Statement.class, (self, method, args) -> {
                String name = method.getName();
                switch (name) {
                    case "setQueryTimeout" -> {
                        journal.add("restore(" + args[0] + ")");
                        fail(restoreSetFails);
                        sessionTimeout.set((Integer) args[0]);
                        return null;
                    }
                    case "getQueryTimeout" -> {
                        return sessionTimeout.get();
                    }
                    case "close" -> {
                        journal.add("restore.close");
                        fail(restoreCloseFails);
                        return null;
                    }
                    case "hashCode" -> {
                        return System.identityHashCode(self);
                    }
                    case "equals" -> {
                        return self == args[0];
                    }
                    default -> throw new UnsupportedOperationException("Statement." + name);
                }
            });
        }

        @NotNull
        private ResultSet resultSet(@NotNull List<Map<String, Object>> data) {
            int[] at = {-1};
            boolean[] lastNull = {false};
            return proxy(ResultSet.class, (self, method, args) -> {
                String name = method.getName();
                switch (name) {
                    case "next" -> {
                        fail(readFails);
                        at[0]++;
                        return at[0] < data.size();
                    }
                    case "getString", "getObject", "getInt", "getLong" -> {
                        Object value = data.get(at[0]).get((String) args[0]);
                        lastNull[0] = value == null;
                        if (value == null) {
                            return name.equals("getInt") ? (Object) 0 : name.equals("getLong") ? (Object) 0L : null;
                        }
                        if (name.equals("getObject") && args.length > 1 && !((Class<?>) args[1]).isInstance(value)) {
                            throw new SQLException("Cannot convert " + value.getClass().getSimpleName());
                        }
                        if (name.equals("getString") && !(value instanceof String)) {
                            throw new SQLException("Not a string");
                        }
                        return value;
                    }
                    case "wasNull" -> {
                        return lastNull[0];
                    }
                    case "close" -> {
                        journal.add("result.close");
                        fail(resultCloseFails);
                        return null;
                    }
                    case "hashCode" -> {
                        return System.identityHashCode(self);
                    }
                    case "equals" -> {
                        return self == args[0];
                    }
                    default -> throw new UnsupportedOperationException("ResultSet." + name);
                }
            });
        }

        /** The calls in order, as one list a test can compare */
        @NotNull
        List<String> calls() {
            synchronized (journal) {
                return new ArrayList<>(journal);
            }
        }

        /** How often one call was made */
        int count(@NotNull String call) {
            synchronized (journal) {
                return (int) journal.stream().filter(call::equals).count();
            }
        }

        /** Every knob back to working */
        void heal() {
            abortIneffective = false;
            autoCommitFails = null;
            prepareFails = null;
            getTimeoutFails = null;
            setTimeoutFails = null;
            executeFails = null;
            readFails = null;
            resultCloseFails = null;
            statementCloseFails = null;
            restoreCreateFails = null;
            restoreSetFails = null;
            restoreCloseFails = null;
            closeFails = null;
            abortFails = null;
            closeAfterAbortFails = null;
        }

        private static void fail(@Nullable Throwable failure) throws Throwable {
            if (failure != null) {
                throw failure;
            }
        }

        @NotNull
        private static String describe(@Nullable Object value) {
            return value == null ? "null" : value.getClass().getSimpleName() + ":" + value;
        }
    }

    // ---------------------------------------------------------------- scripted source

    /** Shapes a connection before a source hands it out */
    @FunctionalInterface
    interface Script {
        void apply(@NotNull FakeConnection connection);
    }

    /**
     * A raw connection source that hands out {@link FakeConnection}s, and can be made to wait or fail
     */
    static final class FakeSource implements MetadataConnectionSource {
        final List<FakeConnection> made = Collections.synchronizedList(new ArrayList<>());
        final AtomicInteger calls = new AtomicInteger();
        final AtomicInteger interruptedWorkers = new AtomicInteger();
        final List<Thread> borrowingThreads = Collections.synchronizedList(new ArrayList<>());
        private final Script script;
        /** When set, every borrow waits for it, uninterruptibly, before making a connection */
        @Nullable volatile CountDownLatch gate;
        /** Released each time a borrow reaches the gate */
        final AtomicInteger atGate = new AtomicInteger();
        /** When set, a borrow throws this instead of making a connection */
        @Nullable volatile Throwable fails;
        /** Runs on the worker before the connection is made, after the gate */
        volatile Runnable onBorrow = () -> {
        };

        FakeSource() {
            this(connection -> {
            });
        }

        FakeSource(@NotNull Script script) {
            this.script = script;
        }

        @NotNull
        @Override
        public Connection openConnection() throws SQLException {
            calls.incrementAndGet();
            borrowingThreads.add(Thread.currentThread());
            CountDownLatch wait = gate;
            if (wait != null) {
                atGate.incrementAndGet();
                awaitUninterruptibly(wait);
            }
            onBorrow.run();
            Throwable failure = fails;
            if (failure instanceof SQLException sql) {
                throw sql;
            }
            if (failure instanceof RuntimeException runtime) {
                throw runtime;
            }
            if (failure instanceof Error error) {
                throw error;
            }
            FakeConnection connection = new FakeConnection();
            script.apply(connection);
            made.add(connection);
            return connection.proxy;
        }

        /** Waits without ever giving up on an interrupt, and records that one came */
        private void awaitUninterruptibly(@NotNull CountDownLatch latch) {
            boolean interrupted = false;
            while (true) {
                try {
                    latch.await();
                    break;
                } catch (InterruptedException e) {
                    interrupted = true;
                }
            }
            if (interrupted || Thread.currentThread().isInterrupted()) {
                interruptedWorkers.incrementAndGet();
            }
        }

        /** The one connection made, when exactly one is expected */
        @NotNull
        FakeConnection only() {
            Assertions.assertEquals(1, made.size(), "FIXTURE: expected exactly one connection to be made");
            return made.get(0);
        }
    }

    // ---------------------------------------------------------------- clocks

    /** A monotonic nanosecond clock moved by hand, safe to read and move from any thread */
    static final class ManualClock implements LongSupplier {
        final AtomicLong now;

        ManualClock(long start) {
            this.now = new AtomicLong(start);
        }

        @Override
        public long getAsLong() {
            return now.get();
        }

        void advance(@NotNull Duration by) {
            now.addAndGet(by.toNanos());
        }

        void set(long value) {
            now.set(value);
        }
    }

    // ---------------------------------------------------------------- queries

    /** A query of one nullable string column, any number of rows up to ten */
    @NotNull
    static MetadataQuery valueQuery() {
        return MetadataQuery.sql("SELECT V FROM {table_prefix}T").columnString("V", true).expectRows(0, 10).build();
    }

    /** A budget of {@code total} from now, on the system clock */
    @NotNull
    static MetadataBudget budget(@NotNull Duration total) {
        return MetadataBudget.startingNow(System::nanoTime, total);
    }

    /** Production tuning, but a short wait in {@code finishClose} and a probe */
    @NotNull
    static BoundedMetadataConnections.Tuning tuning(@NotNull Duration finishWait, @NotNull BoundedMetadataConnections.Probe probe) {
        return new BoundedMetadataConnections.Tuning(finishWait, BoundedMetadataConnections.KEEP_ALIVE, probe);
    }

    // ---------------------------------------------------------------- bounded calls

    /** What a call on another thread came back with */
    record Outcome<T>(@Nullable T value, @Nullable Throwable thrown, long elapsedNanos, boolean finished) {
        @NotNull
        T get() {
            Assertions.assertTrue(finished, "the call did not finish");
            if (thrown != null) {
                Assertions.fail("the call threw " + thrown.getClass().getName());
            }
            return value;
        }
    }

    /** A call that may throw anything */
    @FunctionalInterface
    interface Call<T> {
        @Nullable
        T call() throws Throwable;
    }

    /** Runs {@code call} on its own thread and waits for it at most {@code limit} */
    @NotNull
    static <T> Outcome<T> within(@NotNull Duration limit, @NotNull Call<T> call) {
        AtomicReference<T> value = new AtomicReference<>();
        AtomicReference<Throwable> thrown = new AtomicReference<>();
        AtomicLong elapsed = new AtomicLong();
        CountDownLatch done = new CountDownLatch(1);
        Thread thread = new Thread(() -> {
            long start = System.nanoTime();
            try {
                value.set(call.call());
            } catch (Throwable t) {
                thrown.set(t);
            } finally {
                elapsed.set(System.nanoTime() - start);
                done.countDown();
            }
        }, "dbac-lease-test-call");
        thread.setDaemon(true);
        thread.start();
        boolean finished;
        try {
            finished = done.await(limit.toNanos(), TimeUnit.NANOSECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            finished = false;
        }
        return new Outcome<>(value.get(), thrown.get(), elapsed.get(), finished);
    }

    /** A call running on its own thread, to be awaited later */
    static final class Pending<T> {
        private final Thread thread;
        private final AtomicReference<T> value = new AtomicReference<>();
        private final AtomicReference<Throwable> thrown = new AtomicReference<>();
        private final AtomicLong elapsed = new AtomicLong();
        private final CountDownLatch done = new CountDownLatch(1);

        private Pending(@NotNull Call<T> call, @NotNull String name) {
            this.thread = new Thread(() -> {
                long start = System.nanoTime();
                try {
                    value.set(call.call());
                } catch (Throwable t) {
                    thrown.set(t);
                } finally {
                    elapsed.set(System.nanoTime() - start);
                    done.countDown();
                }
            }, name);
            this.thread.setDaemon(true);
        }

        /** The thread the call runs on */
        @NotNull
        Thread thread() {
            return thread;
        }

        /** Waits at most {@code limit} */
        @NotNull
        Outcome<T> await(@NotNull Duration limit) {
            boolean finished;
            try {
                finished = done.await(limit.toNanos(), TimeUnit.NANOSECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                finished = false;
            }
            return new Outcome<>(value.get(), thrown.get(), elapsed.get(), finished);
        }
    }

    /** Starts {@code call} on its own thread */
    @NotNull
    static <T> Pending<T> start(@NotNull String name, @NotNull Call<T> call) {
        Pending<T> pending = new Pending<>(call, name);
        pending.thread.start();
        return pending;
    }

    /** Opens a lease, or returns the refusal */
    @NotNull
    static Outcome<MetadataLease> open(@NotNull MetadataLeaseSource source, @NotNull MetadataBudget budget, @NotNull Duration limit) {
        return within(limit, () -> source.open(budget, MetadataPurpose.SNAPSHOT));
    }

    /** The refusal's reason, or a failure when the call did something else */
    @NotNull
    static MetadataUnavailableException.Reason refusal(@NotNull Outcome<?> outcome) {
        Assertions.assertTrue(outcome.finished(), "the borrow did not come back in time");
        Assertions.assertInstanceOf(MetadataUnavailableException.class, outcome.thrown(),
            "expected the borrow to be refused, got " + (outcome.thrown() == null ? "a lease" : outcome.thrown().getClass().getName()));
        return ((MetadataUnavailableException) outcome.thrown()).reason();
    }

    /** Waits up to ten seconds for a condition, then reports whether it held */
    static boolean eventually(@NotNull java.util.function.BooleanSupplier condition) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                return false;
            }
            try {
                Thread.sleep(5);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return condition.getAsBoolean();
            }
        }
        return true;
    }

    @SuppressWarnings("unchecked")
    @NotNull
    static <T> T proxy(@NotNull Class<T> type, @NotNull InvocationHandler handler) {
        return (T) Proxy.newProxyInstance(MetadataTestSupport.class.getClassLoader(), new Class<?>[]{type}, handler);
    }
}
