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
import io.cloudbeaver.service.dbac.policy.LeaseState;
import io.cloudbeaver.service.dbac.policy.MetadataLease;
import io.cloudbeaver.service.dbac.policy.MetadataOutcome;
import io.cloudbeaver.service.dbac.policy.MetadataQuery;
import io.cloudbeaver.service.dbac.policy.MetadataRows;
import io.cloudbeaver.service.dbac.policy.UnusableCause;
import io.cloudbeaver.service.dbac.tempwrite.MetadataConnectionSource;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

/**
 * P5-1a ST-8: the same lease template on a real PostgreSQL connection
 * <p>
 * On pgjdbc the query timeout belongs to the statement: another statement of the same connection reads
 * zero while the lease's runs, and nothing is left once it is closed. The template still runs its
 * restore - a harmless zero on a statement of its own - because it does not tell engines apart.
 * Nothing is created on the server: every statement here is a plain {@code SELECT}.
 */
public class MetadataLeasePostgresTest {

    private static final String URL = System.getProperty(
        "dbac.test.postgres.url", "jdbc:postgresql://localhost:55432/dbactest");
    private static final String USER = System.getProperty("dbac.test.postgres.user", "postgres");
    private static final String PASSWORD = System.getProperty("dbac.test.postgres.password", "dbactest");

    /** When true, an unreachable PostgreSQL fails the run instead of skipping it. */
    private static final boolean REQUIRED =
        Boolean.parseBoolean(System.getProperty("dbac.test.postgres.required", "false"));

    private static final Duration WAIT = Duration.ofSeconds(15);

    private static Driver driver;
    private static boolean available;
    private static String unusableBecause;

    private final MetadataLeaseFixture leases = new MetadataLeaseFixture();

    @AfterEach
    public void closeLeases() {
        leases.close();
    }

    @BeforeAll
    public static void probePostgres() {
        available = probe();
        if (!available && REQUIRED) {
            Assertions.fail("POSTGRESQL NOT VERIFIED: " + URL + " could not be used and the run required it - " + unusableBecause);
        }
    }

    /**
     * ST-8: on PostgreSQL the timeout is the statement's: another statement reads zero during, and the connection reads zero after
     */
    @Test
    public void st8PostgresTimeoutBelongsToTheStatement() throws Exception {
        skipIfUnavailable();
        try (Connection physical = open()) {
            KeptConnection kept = new KeptConnection(physical);
            MetadataLease lease = lease(() -> kept.proxy);
            MetadataOutcome<MetadataRows> outcome = lease.query(MetadataQuery.sql("SELECT 1 AS V").columnInt("V").expectRows(1, 1).build());
            Assertions.assertInstanceOf(MetadataOutcome.Done.class, outcome, "FIXTURE ST-8: the statement must run, got " + outcome);
            Assertions.assertTrue(kept.leaseTimeout >= 1, "ST-8: the lease must set a timeout, saw " + kept.leaseTimeout);
            Assertions.assertEquals(0, kept.otherDuring, "ST-8: another statement of the connection must read zero while the lease runs");
            Assertions.assertEquals(List.of("restore(0)"), kept.restores, "ST-8: the template restores on PostgreSQL as well");
            lease.close();
            Assertions.assertEquals(LeaseState.RETURNED, lease.state(), "ST-8: returned");
            Assertions.assertEquals(1, kept.closes, "FIXTURE ST-8: the lease closed the connection once");
            try (Statement statement = physical.createStatement()) {
                Assertions.assertEquals(0, statement.getQueryTimeout(), "ST-8: nothing left on the connection after the lease");
            }
        }
    }

    /**
     * ST-8 (timeout): a statement over its timeout is cancelled by the server (57014), gives no value, and the connection stays usable
     */
    @Test
    public void st8PostgresTimeoutCancelsTheStatement() throws Exception {
        skipIfUnavailable();
        try (Connection physical = open()) {
            KeptConnection kept = new KeptConnection(physical);
            BoundedMetadataConnections source = leases.bounded(() -> kept.proxy, BoundedMetadataConnections.Tuning.PRODUCTION);
            MetadataLease lease = MetadataTestSupport.open(source, MetadataTestSupport.budget(Duration.ofSeconds(2)), WAIT).get();
            long start = System.nanoTime();
            MetadataOutcome<MetadataRows> outcome = lease.query(
                MetadataQuery.sql("SELECT CAST(pg_sleep(5) AS TEXT) AS V").columnString("V", true).expectRows(0, 1).build());
            long millis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
            Assertions.assertEquals(new MetadataOutcome.Unusable<>(UnusableCause.EXECUTION_FAILED), outcome, "ST-8: cancelled, no value");
            Assertions.assertTrue(millis < 4000, "ST-8: cancelled at the timeout, took " + millis + "ms");
            Assertions.assertEquals(LeaseState.USED, lease.state(), "ST-8: the restore still worked, so the session is clean");
            lease.close();
            try (Statement statement = physical.createStatement(); ResultSet result = statement.executeQuery("SELECT 1")) {
                Assertions.assertTrue(result.next(), "ST-8: the connection is usable after the cancel");
                Assertions.assertEquals(0, statement.getQueryTimeout(), "ST-8: and carries no timeout");
            }
        }
    }

    /**
     * CC-8: on PostgreSQL the abort really closes the connection, so a contaminated lease is invalidated, not kept
     * <p>
     * The counterpart of CC-7 on H2, where abort does nothing and the same lease ends quarantined.
     */
    @Test
    public void cc8PostgresAbortInvalidatesAContaminatedLease() throws Exception {
        skipIfUnavailable();
        Connection physical = open();
        try {
            List<String> calls = Collections.synchronizedList(new ArrayList<>());
            Connection failingRestore = MetadataTestSupport.proxy(Connection.class, (self, method, args) -> switch (method.getName()) {
                case "createStatement" -> {
                    Statement statement = (Statement) invoke(physical, method, args);
                    yield MetadataTestSupport.proxy(Statement.class, (inner, innerMethod, innerArgs) -> {
                        if (innerMethod.getName().equals("setQueryTimeout")) {
                            throw new SQLException("injected restore failure");
                        }
                        return invoke(statement, innerMethod, innerArgs);
                    });
                }
                case "abort", "close" -> {
                    calls.add(method.getName());
                    yield invoke(physical, method, args);
                }
                default -> invoke(physical, method, args);
            });
            MetadataLease lease = lease(() -> failingRestore);
            MetadataOutcome<MetadataRows> outcome = lease.query(MetadataQuery.sql("SELECT 1 AS V").columnInt("V").expectRows(1, 1).build());
            Assertions.assertEquals(new MetadataOutcome.Unusable<>(UnusableCause.RESTORE_FAILED), outcome, "CC-8: no value");
            Assertions.assertEquals(LeaseState.CONTAMINATED, lease.state(), "CC-8: contaminated");
            lease.close();
            Assertions.assertEquals(LeaseState.INVALIDATED, lease.state(), "CC-8: pgjdbc's abort closes, so the lease is invalidated");
            Assertions.assertEquals(List.of("abort", "close"), calls, "CC-8: abort, then close");
            Assertions.assertTrue(physical.isClosed(), "CC-8: the physical connection is closed");
        } finally {
            physical.close();
        }
    }

    // ---------------------------------------------------------------- helpers

    @NotNull
    private MetadataLease lease(@NotNull MetadataConnectionSource raw) {
        BoundedMetadataConnections source = leases.bounded(raw, BoundedMetadataConnections.Tuning.PRODUCTION);
        return MetadataTestSupport.open(source, MetadataTestSupport.budget(Duration.ofSeconds(10)), WAIT).get();
    }

    /**
     * A real connection the lease can borrow and close without closing it, watched while the lease's statement runs
     */
    private static final class KeptConnection {
        final Connection proxy;
        final List<String> restores = Collections.synchronizedList(new ArrayList<>());
        volatile int otherDuring = -1;
        volatile int leaseTimeout = -1;
        volatile int closes;

        KeptConnection(@NotNull Connection physical) {
            this.proxy = MetadataTestSupport.proxy(Connection.class, (self, method, args) -> switch (method.getName()) {
                case "close" -> {
                    closes++;
                    yield null;
                }
                case "prepareStatement" -> watched((PreparedStatement) invoke(physical, method, args), physical);
                case "createStatement" -> restoring((Statement) invoke(physical, method, args));
                default -> invoke(physical, method, args);
            });
        }

        @NotNull
        private PreparedStatement watched(@NotNull PreparedStatement statement, @NotNull Connection physical) {
            return MetadataTestSupport.proxy(PreparedStatement.class, (self, method, args) -> {
                if (method.getName().equals("executeQuery")) {
                    leaseTimeout = statement.getQueryTimeout();
                    try (Statement other = physical.createStatement()) {
                        otherDuring = other.getQueryTimeout();
                    }
                }
                return invoke(statement, method, args);
            });
        }

        @NotNull
        private Statement restoring(@NotNull Statement statement) {
            return MetadataTestSupport.proxy(Statement.class, (self, method, args) -> {
                if (method.getName().equals("setQueryTimeout")) {
                    restores.add("restore(" + args[0] + ")");
                }
                return invoke(statement, method, args);
            });
        }
    }

    @Nullable
    private static Object invoke(@NotNull Object target, @NotNull Method method, @Nullable Object[] args) throws Throwable {
        try {
            return method.invoke(target, args);
        } catch (InvocationTargetException e) {
            throw e.getCause();
        }
    }

    private static void skipIfUnavailable() {
        org.junit.jupiter.api.Assumptions.assumeTrue(available, "PostgreSQL is not available");
    }

    private static boolean probe() {
        try {
            driver = loadDriver();
        } catch (Exception e) {
            driver = null;
            unusableBecause = "the PostgreSQL JDBC driver could not be loaded (" + e.getClass().getName() + ")";
            return false;
        }
        try (Connection connection = open()) {
            return connection != null;
        } catch (Exception e) {
            unusableBecause = "connecting failed (" + e.getClass().getName() + ")";
            return false;
        }
    }

    @NotNull
    private static Connection open() throws SQLException {
        Properties properties = new Properties();
        properties.setProperty("user", USER);
        properties.setProperty("password", PASSWORD);
        Connection connection = driver.connect(URL, properties);
        if (connection == null) {
            throw new SQLException("The PostgreSQL driver did not accept the URL");
        }
        return connection;
    }

    @NotNull
    private static Driver loadDriver() throws Exception {
        File jar = findDriverJar();
        if (jar == null) {
            throw new IllegalStateException("PostgreSQL JDBC driver jar not found under deploy/drivers");
        }
        URLClassLoader loader = new URLClassLoader(new URL[]{jar.toURI().toURL()}, Driver.class.getClassLoader());
        return (Driver) Class.forName("org.postgresql.Driver", true, loader).getDeclaredConstructor().newInstance();
    }

    @Nullable
    private static File findDriverJar() {
        File dir = new File(System.getProperty("user.dir"));
        for (int i = 0; i < 6 && dir != null; i++, dir = dir.getParentFile()) {
            File candidate = new File(dir, "deploy/drivers/postgresql");
            File[] jars = candidate.listFiles((d, name) -> name.startsWith("postgresql-") && name.endsWith(".jar"));
            if (jars != null && jars.length > 0) {
                return jars[0];
            }
        }
        return null;
    }
}
