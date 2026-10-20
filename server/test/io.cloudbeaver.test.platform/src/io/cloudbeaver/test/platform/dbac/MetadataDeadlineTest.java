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
import io.cloudbeaver.service.dbac.policy.AuthorizationDecision;
import io.cloudbeaver.service.dbac.policy.BoundedMetadataConnections;
import io.cloudbeaver.service.dbac.policy.DbAccessPolicyConfig;
import io.cloudbeaver.service.dbac.policy.DbAccessPolicyService;
import io.cloudbeaver.service.dbac.policy.DbOperationCategory;
import io.cloudbeaver.service.dbac.policy.DenialReason;
import io.cloudbeaver.service.dbac.policy.LeaseState;
import io.cloudbeaver.service.dbac.policy.MetadataBudget;
import io.cloudbeaver.service.dbac.policy.MetadataLease;
import io.cloudbeaver.service.dbac.policy.MetadataOutcome;
import io.cloudbeaver.service.dbac.policy.UnusableCause;
import io.cloudbeaver.service.dbac.policy.WriteAuthorizationRequest;
import io.cloudbeaver.service.dbac.tempwrite.EndpointSnapshot;
import io.cloudbeaver.test.platform.dbac.MetadataTestSupport.FakeConnection;
import io.cloudbeaver.test.platform.dbac.MetadataTestSupport.FakeSource;
import io.cloudbeaver.test.platform.dbac.MetadataTestSupport.InjectedSqlException;
import io.cloudbeaver.test.platform.dbac.MetadataTestSupport.ManualClock;
import org.jkiss.code.NotNull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * P5-1a: one total budget for the borrow and the statement, in whole seconds, monotonic
 * <p>
 * DL drives a lease with a clock the test moves - by the borrow, by the statement - so the budget's
 * arithmetic is exact. TS checks the snapshot timeout {@code T_s} at the service: where the timeout is
 * set, what a failure to set it means, and what the configuration accepts.
 */
public class MetadataDeadlineTest {

    private static final Duration WAIT = Duration.ofSeconds(10);
    private static final long BASE = 9_000_000_000_000L;
    private static final OffsetDateTime DB_NOW = OffsetDateTime.of(2026, 10, 7, 3, 0, 0, 0, ZoneOffset.UTC);
    private static final String ROW_USER = "deadline-user";

    private final MetadataLeaseFixture leases = new MetadataLeaseFixture();

    @AfterEach
    public void closeLeases() {
        leases.close();
    }

    @BeforeAll
    public static void startServer() throws Exception {
        CEAppStarter.startServerIfNotStarted();
    }

    // ---------------------------------------------------------------- DL

    /**
     * DL-1: borrow 0.8 s, statement 1.3 s, budget 2 s: the statement gets one second, and its late value is discarded
     */
    @Test
    public void dl1BorrowAndStatementShareOneBudget() {
        ManualClock clock = new ManualClock(BASE);
        FakeSource raw = new FakeSource(connection -> connection.onExecute = () -> clock.advance(Duration.ofMillis(1300)));
        raw.onBorrow = () -> clock.advance(Duration.ofMillis(800));
        MetadataLease lease = lease(raw, MetadataBudget.startingNow(clock, Duration.ofSeconds(2)));
        MetadataOutcome<?> outcome = lease.query(MetadataTestSupport.valueQuery());
        FakeConnection connection = raw.only();
        Assertions.assertEquals(1, connection.count("setQueryTimeout(1)"), "DL-1: the remaining 1.2 s becomes a 1 s timeout");
        Assertions.assertEquals(new MetadataOutcome.Unusable<>(UnusableCause.OVER_BUDGET), outcome, "DL-1: 2.1 s in total is over");
        Assertions.assertEquals(0, connection.sessionTimeout.get(), "DL-1: restored all the same");
        lease.close();
        Assertions.assertEquals(LeaseState.RETURNED, lease.state(), "DL-1: and returned, the session being clean");
    }

    /**
     * DL-2: a borrow that leaves less than one second runs no statement
     */
    @Test
    public void dl2LessThanASecondLeftRunsNothing() {
        ManualClock clock = new ManualClock(BASE);
        FakeSource raw = new FakeSource();
        raw.onBorrow = () -> clock.advance(Duration.ofMillis(1500));
        MetadataLease lease = lease(raw, MetadataBudget.startingNow(clock, Duration.ofSeconds(2)));
        Assertions.assertEquals(new MetadataOutcome.Unusable<>(UnusableCause.BUDGET_EXHAUSTED),
            lease.query(MetadataTestSupport.valueQuery()),
            "DL-2");
        Assertions.assertEquals(0, raw.only().prepares.get(), "DL-2: nothing prepared");
        lease.close();
    }

    /**
     * DL-3: a driver that ignores the timeout and answers late: the answer is discarded
     */
    @Test
    public void dl3ALateAnswerIsDiscarded() {
        ManualClock clock = new ManualClock(BASE);
        FakeSource raw = new FakeSource(connection -> connection.onExecute = () -> clock.advance(Duration.ofSeconds(5)));
        MetadataLease lease = lease(raw, MetadataBudget.startingNow(clock, Duration.ofSeconds(2)));
        Assertions.assertEquals(new MetadataOutcome.Unusable<>(UnusableCause.OVER_BUDGET), lease.query(MetadataTestSupport.valueQuery()),
            "DL-3");
        lease.close();
    }

    /**
     * DL-4: a clock that steps back never hands time back
     */
    @Test
    public void dl4AClockSteppingBackGivesNothingBack() {
        ManualClock clock = new ManualClock(BASE);
        MetadataBudget budget = MetadataBudget.startingNow(clock, Duration.ofSeconds(2));
        clock.advance(Duration.ofMillis(500));
        Duration before = budget.remaining();
        clock.advance(Duration.ofSeconds(-10));
        Assertions.assertEquals(before, budget.remaining(), "DL-4: remaining must not grow");
        Assertions.assertEquals(1, budget.wholeSeconds(), "DL-4: 1.5 s left is one whole second");

        FakeSource raw = new FakeSource();
        ManualClock backwards = new ManualClock(BASE);
        MetadataBudget leaseBudget = MetadataBudget.startingNow(backwards, Duration.ofSeconds(2));
        raw.onBorrow = () -> {
            // The borrow takes 0.8 s, which is measured, and then the clock steps back half a minute.
            backwards.advance(Duration.ofMillis(800));
            leaseBudget.elapsedNanos();
            backwards.advance(Duration.ofSeconds(-30));
        };
        MetadataLease lease = lease(raw, leaseBudget);
        lease.query(MetadataTestSupport.valueQuery());
        Assertions.assertEquals(1, raw.only().count("setQueryTimeout(1)"),
            "DL-4: the 0.8 s already measured stays spent, so the timeout is one second, got " + raw.only().calls());
        Assertions.assertEquals(Duration.ofMillis(1200), leaseBudget.remaining(), "DL-4: remaining did not grow back");
        lease.close();
    }

    /**
     * DL-5: a budget that starts just before the clock wraps measures across the wrap
     */
    @Test
    public void dl5ElapsedTimeIsCorrectAcrossTheWrap() {
        ManualClock clock = new ManualClock(Long.MAX_VALUE - 500_000_000L);
        MetadataBudget budget = MetadataBudget.startingNow(clock, Duration.ofSeconds(3));
        clock.advance(Duration.ofSeconds(2));
        Assertions.assertTrue(clock.getAsLong() < 0, "FIXTURE DL-5: the clock wrapped");
        Assertions.assertEquals(Duration.ofSeconds(2).toNanos(), budget.elapsedNanos(), "DL-5: two seconds elapsed");
        Assertions.assertEquals(Duration.ofSeconds(1), budget.remaining(), "DL-5: one second left");
        Assertions.assertEquals(1, budget.wholeSeconds(), "DL-5");
        clock.advance(Duration.ofSeconds(2));
        Assertions.assertTrue(budget.isOverspent(), "DL-5: and then overspent");
        Assertions.assertEquals(0, budget.wholeSeconds(), "DL-5: no whole second left");
        Assertions.assertTrue(budget.remainingNanos() < 0, "DL-5: nothing left");
        Assertions.assertThrows(IllegalArgumentException.class, () -> MetadataBudget.startingNow(clock, Duration.ZERO),
            "DL-5: an empty budget is refused");
    }

    /**
     * DL-6: a snapshot whose borrow and statement together exceed T_s is not acted on - the same answer as an outage
     */
    @Test
    public void dl6ASnapshotOverTsIsNotActedOn() throws Throwable {
        FakeSource slow = new FakeSource(connection -> {
            connection.rows = List.of(snapshotRow());
            connection.onExecute = () -> sleep(DbAccessPolicyConfig.DEFAULT_SNAPSHOT_TIMEOUT.toMillis() + 200);
        });
        FakeSource quick = new FakeSource(connection -> connection.rows = List.of(snapshotRow()));
        Assertions.assertTrue(authorize(quick).isAllowed(), "FIXTURE DL-6: the same row, read in time, allows");
        AuthorizationDecision[] late = new AuthorizationDecision[1];
        LifecycleTestSupport.Captured captured = LifecycleTestSupport.captureLogs(() -> late[0] = authorize(slow));
        Assertions.assertEquals(DenialReason.PERMISSION_STORE_UNAVAILABLE, late[0].denialReason(),
            "DL-6: store unavailable, never an allow");
        Assertions.assertTrue(captured.dbacMessages().stream().anyMatch(message -> message.contains("detail=" + UnusableCause.OVER_BUDGET)),
            "DL-6: because the budget was spent, got " + captured.dbacMessages());
    }

    // ---------------------------------------------------------------- TS

    /**
     * TS-1: the snapshot sets its timeout before it executes, no larger than T_s, and puts it back after
     */
    @Test
    public void ts1TheSnapshotTimeoutIsSetBeforeTheStatement() {
        FakeSource raw = new FakeSource(connection -> connection.rows = List.of(snapshotRow()));
        Assertions.assertTrue(authorize(raw).isAllowed(), "FIXTURE TS-1: the row allows");
        List<String> calls = raw.only().calls();
        int set = -1;
        for (int i = 0; i < calls.size(); i++) {
            if (calls.get(i).startsWith("setQueryTimeout(")) {
                set = i;
                break;
            }
        }
        Assertions.assertTrue(set >= 0, "TS-1: a timeout must be set, got " + calls);
        int seconds = Integer.parseInt(calls.get(set).replaceAll("\\D", ""));
        Assertions.assertTrue(seconds >= 1 && seconds <= DbAccessPolicyConfig.DEFAULT_SNAPSHOT_TIMEOUT.getSeconds(),
            "TS-1: within T_s, got " + seconds);
        Assertions.assertTrue(set < calls.indexOf("executeQuery"), "TS-1: before the statement runs, got " + calls);
        Assertions.assertTrue(calls.indexOf("restore(0)") > calls.indexOf("executeQuery"), "TS-1: and put back after it");
    }

    /**
     * TS-4: a timeout that cannot be set is the same answer as an outage
     */
    @Test
    public void ts4ATimeoutThatCannotBeSetDenies() {
        FakeSource raw = new FakeSource(connection -> {
            connection.rows = List.of(snapshotRow());
            connection.setTimeoutFails = new InjectedSqlException("set timeout");
        });
        AuthorizationDecision decision = authorize(raw);
        Assertions.assertEquals(DenialReason.PERMISSION_STORE_UNAVAILABLE, decision.denialReason(), "TS-4: never an allow");
        Assertions.assertEquals(0, raw.only().executes.get(), "TS-4: the statement does not run");
    }

    /**
     * TS-5: T_s is a whole number of seconds from one to thirty; the five-part constructor and the defaults give two
     */
    @Test
    public void ts5TheSnapshotTimeoutIsBounded() {
        List<String> violations = new ArrayList<>();
        DbAccessPolicyConfig defaults = DbAccessPolicyConfig.defaults();
        for (Duration refused : List.of(Duration.ZERO, Duration.ofSeconds(-1), Duration.ofSeconds(30).plusNanos(1),
            Duration.ofMillis(1500), Duration.ofSeconds(31))) {
            try {
                config(refused);
                violations.add(refused + " was accepted");
            } catch (IllegalArgumentException expected) {
                // refused
            }
        }
        for (Duration accepted : List.of(Duration.ofSeconds(1), Duration.ofSeconds(30))) {
            try {
                if (!accepted.equals(config(accepted).snapshotTimeout())) {
                    violations.add(accepted + " was changed");
                }
            } catch (IllegalArgumentException e) {
                violations.add(accepted + " was refused");
            }
        }
        DbAccessPolicyConfig fivePart = new DbAccessPolicyConfig(defaults.clockSkewThreshold(), defaults.maxGrantDuration(),
            defaults.expiryGuardMargin(), defaults.auditTimeout(), defaults.keyLockTimeout());
        for (DbAccessPolicyConfig one : List.of(defaults, fivePart, DbAccessPolicyConfig.sanitized(null, null))) {
            if (!Duration.ofSeconds(2).equals(one.snapshotTimeout())) {
                violations.add("a default configuration has T_s " + one.snapshotTimeout());
            }
        }
        if (!Duration.ofSeconds(2).equals(DbAccessPolicyConfig.DEFAULT_SNAPSHOT_TIMEOUT)) {
            violations.add("the default T_s is " + DbAccessPolicyConfig.DEFAULT_SNAPSHOT_TIMEOUT);
        }
        Assertions.assertEquals(List.of(), violations, "TS-5");
    }

    /**
     * TS-8: the configured T_s is the one the snapshot runs within - five seconds lets a 2.5 s statement allow,
     * and one second, whose whole seconds are gone before the statement, runs nothing
     */
    @Test
    public void ts8TheConfiguredSnapshotTimeoutIsTheOneUsed() throws Throwable {
        FakeSource slow = new FakeSource(connection -> {
            connection.rows = List.of(snapshotRow());
            connection.onExecute = () -> sleep(2500);
        });
        Assertions.assertTrue(authorize(slow, config(Duration.ofSeconds(5))).isAllowed(),
            "TS-8: a 2.5 s statement fits a configured T_s of 5 s (the default 2 s would refuse it)");
        FakeSource quick = new FakeSource(connection -> connection.rows = List.of(snapshotRow()));
        AuthorizationDecision[] decision = new AuthorizationDecision[1];
        LifecycleTestSupport.Captured captured = LifecycleTestSupport.captureLogs(
            () -> decision[0] = authorize(quick, config(Duration.ofSeconds(1))));
        Assertions.assertEquals(DenialReason.PERMISSION_STORE_UNAVAILABLE, decision[0].denialReason(),
            "TS-8: with T_s 1 s less than a whole second is left once the borrow is done");
        Assertions.assertEquals(0, quick.only().prepares.get(), "TS-8: so nothing is run");
        Assertions.assertTrue(
            captured.dbacMessages().stream().anyMatch(message -> message.contains("detail=" + UnusableCause.BUDGET_EXHAUSTED)),
            "TS-8: and the log says why, got " + captured.dbacMessages());
    }

    // ---------------------------------------------------------------- helpers

    @NotNull
    private MetadataLease lease(@NotNull FakeSource raw, @NotNull MetadataBudget budget) {
        BoundedMetadataConnections source = leases.bounded(raw, BoundedMetadataConnections.Tuning.PRODUCTION);
        return MetadataTestSupport.open(source, budget, WAIT).get();
    }

    @NotNull
    private AuthorizationDecision authorize(@NotNull FakeSource raw) {
        return authorize(raw, DbAccessPolicyConfig.defaults());
    }

    @NotNull
    private AuthorizationDecision authorize(@NotNull FakeSource raw, @NotNull DbAccessPolicyConfig config) {
        DbAccessPolicyService service = new DbAccessPolicyService(
            leases.of(raw), config, Clock.fixed(DB_NOW.toInstant().plusSeconds(4), ZoneOffset.UTC));
        return service.authorize(WriteAuthorizationRequest.of(ROW_USER,
            PolicyTestSupport.container("deadline-project", "deadline-connection",
                TempWriteTestSupport.ENDPOINT.host(), TempWriteTestSupport.ENDPOINT.database()),
            DbOperationCategory.SQL_TEXT));
    }

    /** The authorization row of an active user with one live grant on the fixture endpoint */
    @NotNull
    private static Map<String, Object> snapshotRow() {
        EndpointSnapshot stored = TempWriteTestSupport.ENDPOINT;
        Map<String, Object> row = new HashMap<>();
        row.put("DB_NOW", DB_NOW);
        row.put("FOUND_USER", ROW_USER);
        row.put("IS_ACTIVE", "Y");
        row.put("GRANT_ID", "g");
        row.put("EXPIRES_AT", DB_NOW.plusMinutes(30));
        row.put("PROVIDER_ID", stored.providerId());
        row.put("DRIVER_ID", stored.driverId());
        row.put("CONFIGURATION_TYPE", stored.configurationType());
        row.put("HOST_SNAPSHOT", stored.host());
        row.put("PORT_SNAPSHOT", stored.port());
        row.put("DATABASE_SNAPSHOT", stored.database());
        row.put("NOT_EXPIRED", 1);
        return row;
    }

    @NotNull
    private static DbAccessPolicyConfig config(@NotNull Duration snapshotTimeout) {
        DbAccessPolicyConfig defaults = DbAccessPolicyConfig.defaults();
        return new DbAccessPolicyConfig(defaults.clockSkewThreshold(), defaults.maxGrantDuration(), defaults.expiryGuardMargin(),
            defaults.auditTimeout(), defaults.keyLockTimeout(), snapshotTimeout);
    }

    private static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
