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
import io.cloudbeaver.model.WebAsyncTaskInfo;
import io.cloudbeaver.service.dbac.policy.AuthorizationDecision;
import io.cloudbeaver.service.dbac.policy.DbOperationCategory;
import io.cloudbeaver.service.dbac.policy.DenialReason;
import org.jkiss.code.NotNull;
import org.jkiss.dbeaver.model.runtime.LoggingProgressMonitor;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.Map;

/**
 * P6-A: the transaction entry points - commit, auto-commit on - driven from outside, as a user reaches them
 * <p>
 * Twelve of the Slice 4a red tests, copied from {@code EnforcementEntryPointTest} without a changed assertion; the
 * Explain tests stay there for P6-B. Each one first proves its own premise through the policy core, so a failure is
 * about the entry point and never about a fixture that granted or revoked the wrong thing; a premise that does not
 * hold fails with {@code FIXTURE} instead. The behaviour that must survive enforcement lives in
 * {@link EnforcementRegressionGuardTest}.
 * <p>
 * Every judged subject is an ordinary {@code authRole=user} account; the test admin only creates,
 * deactivates and deletes users. Changes are put into the open transaction directly on the
 * context's connection, because SQL_TEXT is outside Slice 4a and the path a change took into the
 * transaction is not what is being judged. A denial is recognised by its {@link DenialReason}
 * message code or user message anywhere in the failure, which is the one thing these tests require
 * of the Slice 4a exception.
 */
public class TransactionEnforcementEntryPointTest {

    private static EnforcementTestSupport.Fixtures fixtures;

    @BeforeAll
    public static void startServer() throws Exception {
        CEAppStarter.startServerIfNotStarted();
        fixtures = EnforcementTestSupport.fixtures("tep", new LoggingProgressMonitor());
    }

    @AfterEach
    public void cleanUp() throws Exception {
        fixtures.afterEach();
    }

    @AfterAll
    public static void deleteUsers() throws Exception {
        fixtures.afterAll();
    }

    // ---------------------------------------------------------------- commit

    /** T1a: a READ_ONLY user's commit is denied and the open transaction is rolled back */
    @Test
    public void t1aReadOnlyCommitIsDeniedAndRolledBack() throws Exception {
        EnforcementTestSupport.Target target = fixtures.readOnlyTarget(fixtures.user);
        EnforcementTestSupport.premiseDenies("T1a", target, DbOperationCategory.TRANSACTION_COMMIT, DenialReason.NO_GRANT);
        EnforcementTestSupport.openTransaction(target, 31);

        EnforcementTestSupport.Outcome outcome = EnforcementTestSupport.commit(target);

        int value = target.committedValue();
        EnforcementTestSupport.assertDenied("T1a", outcome, DenialReason.NO_GRANT, "committed row afterwards=" + value);
        Assertions.assertEquals(0, value, "T1a: a denied commit must leave committed state unchanged");
    }

    /** T1b: a change made while the grant was valid cannot be committed after it expires */
    @Test
    public void t1bCommitAfterExpiryIsDeniedAndRolledBack() throws Exception {
        EnforcementTestSupport.Target target = fixtures.writableTarget(fixtures.user);
        EnforcementTestSupport.openTransaction(target, 32);
        EnforcementTestSupport.setExpiresAt(target.key(), EnforcementTestSupport.metadataNow().minusSeconds(1));
        EnforcementTestSupport.premiseDenies("T1b", target, DbOperationCategory.TRANSACTION_COMMIT, DenialReason.GRANT_EXPIRED);

        EnforcementTestSupport.Outcome outcome = EnforcementTestSupport.commit(target);

        int value = target.committedValue();
        EnforcementTestSupport.assertDenied("T1b", outcome, DenialReason.GRANT_EXPIRED, "committed row afterwards=" + value);
        Assertions.assertEquals(0, value, "T1b: an expired grant must not commit");
    }

    /** V2: a change made before a revoke cannot be committed after it */
    @Test
    public void v2CommitAfterRevokeIsDeniedAndRolledBack() throws Exception {
        EnforcementTestSupport.Target target = fixtures.writableTarget(fixtures.user);
        EnforcementTestSupport.openTransaction(target, 33);
        EnforcementTestSupport.revoke(target.key());
        EnforcementTestSupport.premiseDenies("V2", target, DbOperationCategory.TRANSACTION_COMMIT, DenialReason.GRANT_REVOKED);

        EnforcementTestSupport.Outcome outcome = EnforcementTestSupport.commit(target);

        int value = target.committedValue();
        EnforcementTestSupport.assertDenied("V2", outcome, DenialReason.GRANT_REVOKED, "committed row afterwards=" + value);
        Assertions.assertEquals(0, value, "V2: a revoked grant must not commit");
    }

    /** U3: a deactivated user cannot commit, even in a session opened before the deactivation */
    @Test
    public void u3CommitAfterDeactivationIsDenied() throws Exception {
        EnforcementTestSupport.Subject user = fixtures.newUser();
        EnforcementTestSupport.Target target = fixtures.writableTarget(user);
        EnforcementTestSupport.premiseAllows("U3", target, DbOperationCategory.TRANSACTION_COMMIT);
        EnforcementTestSupport.openTransaction(target, 34);

        fixtures.admin.client().sendQuery(EnforcementTestSupport.GQL_ENABLE_USER, Map.of("userId", user.userId(), "enabled", false));
        String k2 = sessionAfterAccountChange("deactivation", user);
        EnforcementTestSupport.premiseDenies("U3", target, DbOperationCategory.TRANSACTION_COMMIT, DenialReason.USER_INACTIVE);

        EnforcementTestSupport.Outcome outcome = EnforcementTestSupport.commit(target);

        int value = target.committedValue();
        EnforcementTestSupport.assertDenied("U3", outcome, DenialReason.USER_INACTIVE, k2 + "; committed row afterwards=" + value);
        Assertions.assertEquals(0, value, "U3: a deactivated user must not commit");
    }

    /** U4: a deleted user cannot commit, even in a session opened before the deletion */
    @Test
    public void u4CommitAfterDeletionIsDenied() throws Exception {
        EnforcementTestSupport.Subject user = fixtures.newUser();
        EnforcementTestSupport.Target target = fixtures.writableTarget(user);
        EnforcementTestSupport.premiseAllows("U4", target, DbOperationCategory.TRANSACTION_COMMIT);
        EnforcementTestSupport.openTransaction(target, 35);

        // P5-F's deletion fence refuses to delete a user who holds a live grant, so the grant is revoked first. The
        // policy judges the user before the grant, so the denial expected below is still the deletion's.
        EnforcementTestSupport.revoke(target.key());
        fixtures.admin.client().sendQuery(EnforcementTestSupport.GQL_DELETE_USER, Map.of("userId", user.userId()));
        String k2 = sessionAfterAccountChange("deletion", user);
        AuthorizationDecision premise = EnforcementTestSupport.decide(target, DbOperationCategory.TRANSACTION_COMMIT);
        Assertions.assertFalse(premise.isAllowed(), "FIXTURE U4: the policy core should deny a deleted user");
        DenialReason expected = premise.denialReason();
        Assertions.assertTrue(expected == DenialReason.USER_INACTIVE || expected == DenialReason.IDENTITY_MISSING,
            "FIXTURE U4: unexpected premise reason " + expected);

        EnforcementTestSupport.Outcome outcome = EnforcementTestSupport.commit(target);

        int value = target.committedValue();
        EnforcementTestSupport.assertDenied("U4", outcome, expected, k2 + "; committed row afterwards=" + value);
        Assertions.assertEquals(0, value, "U4: a deleted user must not commit");
    }

    /**
     * K2: what an account change does to a session that is already open
     * <p>
     * Recorded, not asserted. If the platform ended the session itself the gated call would fail
     * for that reason, and the U tests would be measuring the wrong thing.
     */
    @NotNull
    private static String sessionAfterAccountChange(@NotNull String change, @NotNull EnforcementTestSupport.Subject user) {
        String graphQl;
        try {
            Map<String, Object> active = user.client().sendQuery(EnforcementTestSupport.GQL_ACTIVE_USER, null);
            graphQl = active == null ? "no active user" : "active user " + active.get("userId");
        } catch (Exception e) {
            graphQl = "call failed (" + e.getClass().getSimpleName() + ")";
        }
        String k2 = "K2: after " + change + " the GraphQL session reports " + graphQl
            + ", the server-side session userId=" + user.session().getUserId();
        System.out.println("[DBAC S1] " + k2);
        return k2;
    }

    // ---------------------------------------------------------------- auto-commit on

    /** AC-BB1: a READ_ONLY user cannot commit by turning auto-commit on */
    @Test
    public void acBb1ReadOnlyAutoCommitOnIsDeniedAndRolledBack() throws Exception {
        EnforcementTestSupport.Target target = fixtures.readOnlyTarget(fixtures.user);
        EnforcementTestSupport.premiseDenies("AC-BB1", target, DbOperationCategory.TRANSACTION_AUTOCOMMIT_ON, DenialReason.NO_GRANT);
        EnforcementTestSupport.openTransaction(target, 36);

        EnforcementTestSupport.Outcome outcome = EnforcementTestSupport.setAutoCommit(target, true);

        int value = target.committedValue();
        String autoCommit = EnforcementTestSupport.jdbcAutoCommitState(target);
        EnforcementTestSupport.assertDenied("AC-BB1", outcome, DenialReason.NO_GRANT,
            "committed row afterwards=" + value + ", JDBC auto-commit afterwards=" + autoCommit);
        Assertions.assertEquals(0, value, "AC-BB1: a denied auto-commit on must not commit");
        Assertions.assertEquals("false", autoCommit, "AC-BB1: a denied auto-commit on must leave manual commit in place");
    }

    /**
     * AC-11: success is reported only when auto-commit is really on
     * <p>
     * JDBC is switched off behind the platform's back, so its cache still says true and
     * {@code setAutoCommit(true)} returns without doing anything. Today the entry point reports
     * success regardless. Slice 4a must read JDBC again after the call and refuse to call it a
     * success, blocking the connection instead.
     */
    @Test
    public void ac11SuccessIsNotReportedWhileJdbcAutoCommitStaysOff() throws Exception {
        EnforcementTestSupport.Target target = fixtures.writableTarget(fixtures.user);
        EnforcementTestSupport.premiseAllows("AC-11", target, DbOperationCategory.TRANSACTION_AUTOCOMMIT_ON);
        target.jdbc().setAutoCommit(false);
        Assertions.assertTrue(target.context().isAutoCommit(), "FIXTURE AC-11: the cache must still say auto-commit");
        target.updateInTransaction(37);

        EnforcementTestSupport.Outcome outcome = EnforcementTestSupport.setAutoCommit(target, true);

        int value = target.committedValue();
        String observed = "result=" + outcome.result() + ", JDBC auto-commit afterwards="
            + EnforcementTestSupport.jdbcAutoCommitState(target) + ", committed row afterwards=" + value;
        if (outcome.succeeded()) {
            Assertions.fail("AC-11: expected no success while JDBC auto-commit stayed false, but the call reported success; " + observed);
        }
        EnforcementTestSupport.assertDenied("AC-11", outcome, DenialReason.CONNECTION_BLOCKED, observed);
        Assertions.assertEquals(0, value, "AC-11: nothing may be committed");
    }

    // ---------------------------------------------------------------- audit

    /** AU-BB1: an allowed commit leaves exactly one WRITE_ALLOWED row */
    @Test
    public void auBb1AllowedCommitIsAudited() throws Exception {
        EnforcementTestSupport.Target target = fixtures.writableTarget(fixtures.user);
        EnforcementTestSupport.premiseAllows("AU-BB1", target, DbOperationCategory.TRANSACTION_COMMIT);
        int before = EnforcementTestSupport.countAudit(
            target.key(), EnforcementTestSupport.EVENT_WRITE_ALLOWED, DbOperationCategory.TRANSACTION_COMMIT);
        EnforcementTestSupport.openTransaction(target, 38);

        EnforcementTestSupport.Outcome outcome = EnforcementTestSupport.commit(target);

        int after = EnforcementTestSupport.countAudit(
            target.key(), EnforcementTestSupport.EVENT_WRITE_ALLOWED, DbOperationCategory.TRANSACTION_COMMIT);
        Assertions.assertTrue(outcome.succeeded(), "AU-BB1: an allowed commit must succeed: "
            + EnforcementTestSupport.describe(outcome.error()));
        Assertions.assertEquals(before + 1, after,
            "AU-BB1: an allowed commit must leave exactly one WRITE_ALLOWED row, found " + (after - before));
    }

    /**
     * AU-BB2: a denied commit is refused for the right reason, rolled back, and recorded as such
     * <p>
     * An audit row alone is not enough. Exactly one denial must be recorded in total - not one for
     * the right reason plus others for wrong ones - and that one must name the reason the policy
     * gave; the operation itself must have failed with that reason; and committed state must be
     * unchanged as seen from a separate connection.
     */
    @Test
    public void auBb2DeniedCommitIsRefusedRolledBackAndAudited() throws Exception {
        EnforcementTestSupport.Target target = fixtures.readOnlyTarget(fixtures.user);
        EnforcementTestSupport.premiseDenies("AU-BB2", target, DbOperationCategory.TRANSACTION_COMMIT, DenialReason.NO_GRANT);
        int totalBefore = EnforcementTestSupport.countAudit(
            target.key(), EnforcementTestSupport.EVENT_WRITE_DENIED, DbOperationCategory.TRANSACTION_COMMIT);
        int reasonBefore = EnforcementTestSupport.countAudit(target.key(), EnforcementTestSupport.EVENT_WRITE_DENIED,
            DbOperationCategory.TRANSACTION_COMMIT, DenialReason.NO_GRANT);
        EnforcementTestSupport.openTransaction(target, 39);

        final EnforcementTestSupport.Outcome outcome = EnforcementTestSupport.commit(target);

        int totalAfter = EnforcementTestSupport.countAudit(
            target.key(), EnforcementTestSupport.EVENT_WRITE_DENIED, DbOperationCategory.TRANSACTION_COMMIT);
        int reasonAfter = EnforcementTestSupport.countAudit(target.key(), EnforcementTestSupport.EVENT_WRITE_DENIED,
            DbOperationCategory.TRANSACTION_COMMIT, DenialReason.NO_GRANT);
        final int value = target.committedValue();
        String counts = "WRITE_DENIED total " + totalBefore + " -> " + totalAfter
            + ", DENIAL_REASON=NO_GRANT " + reasonBefore + " -> " + reasonAfter;
        System.out.println("[DBAC S1] AU-BB2 " + counts);
        EnforcementTestSupport.Expectations expect = new EnforcementTestSupport.Expectations("AU-BB2");
        expect.check(totalAfter - totalBefore == 1,
            "the WRITE_DENIED rows must grow by exactly 1 in total (grew by " + (totalAfter - totalBefore) + ")");
        expect.check(reasonAfter - reasonBefore == 1,
            "the WRITE_DENIED rows with DENIAL_REASON=NO_GRANT must grow by exactly 1 (grew by " + (reasonAfter - reasonBefore) + ")");
        expect.check(outcome.error() != null && EnforcementTestSupport.mentions(outcome.error(), DenialReason.NO_GRANT),
            "the commit must fail with DENY(NO_GRANT)");
        expect.check(value == 0, "the committed row seen from a separate connection must stay 0");
        expect.verify("commit " + (outcome.succeeded() ? "succeeded" : "failed with " + EnforcementTestSupport.describe(outcome.error()))
            + ", committed row " + value + ", " + counts);
    }

    // ---------------------------------------------------------------- races (time-based, auxiliary)

    /**
     * V1-BB: a revoke does not complete while a commit under that grant is still in flight
     * <p>
     * Time-based and auxiliary only: the commit is made slow by a deferred trigger, and the revoke
     * starts half a second into it. The deterministic version, which is the one that decides, is V1
     * with barriers in S2.
     */
    @Test
    public void v1BbRevokeWaitsForAnInFlightCommit() throws Exception {
        EnforcementTestSupport.Target target = fixtures.writableTarget(fixtures.user);
        EnforcementTestSupport.premiseAllows("V1-BB", target, DbOperationCategory.TRANSACTION_COMMIT);
        EnforcementTestSupport.openTransaction(target, EnforcementTestSupport.SLOW_VALUE);

        final long started = System.nanoTime();
        WebAsyncTaskInfo task = target.sqlContext.commitTransaction();
        Thread.sleep(500);
        Assertions.assertTrue(task.isRunning(), "FIXTURE V1-BB: the commit must still be running when the revoke starts");
        EnforcementTestSupport.revoke(target.key());
        long revoked = System.nanoTime();
        EnforcementTestSupport.Outcome outcome = EnforcementTestSupport.await(task);

        assertWaitedForSlowCommit("V1-BB", "revoke", started, revoked, outcome);
    }

    /** U1-BB: a deactivation does not complete while a commit by that user is still in flight */
    @Test
    public void u1BbDeactivationWaitsForAnInFlightCommit() throws Exception {
        EnforcementTestSupport.Subject user = fixtures.newUser();
        EnforcementTestSupport.Target target = fixtures.writableTarget(user);
        EnforcementTestSupport.premiseAllows("U1-BB", target, DbOperationCategory.TRANSACTION_COMMIT);
        EnforcementTestSupport.openTransaction(target, EnforcementTestSupport.SLOW_VALUE);

        final long started = System.nanoTime();
        WebAsyncTaskInfo task = target.sqlContext.commitTransaction();
        Thread.sleep(500);
        Assertions.assertTrue(task.isRunning(), "FIXTURE U1-BB: the commit must still be running when the deactivation starts");
        fixtures.admin.client().sendQuery(EnforcementTestSupport.GQL_ENABLE_USER, Map.of("userId", user.userId(), "enabled", false));
        long deactivated = System.nanoTime();
        EnforcementTestSupport.Outcome outcome = EnforcementTestSupport.await(task);

        assertWaitedForSlowCommit("U1-BB", "deactivation", started, deactivated, outcome);
    }

    /**
     * Judges the race against the commit's measured duration, not the trigger's nominal sleep
     * <p>
     * The sleep runs on the database server's clock, and on the Docker test host that clock was
     * measured running a few percent fast against the JVM's, so a nominal 3 s sleep is observed as
     * noticeably less. The competing change has to finish no earlier than the commit did, less the
     * polling slack of {@link EnforcementTestSupport#await}.
     */
    private static void assertWaitedForSlowCommit(
        @NotNull String id,
        @NotNull String what,
        long started,
        long finished,
        @NotNull EnforcementTestSupport.Outcome commit
    ) {
        long commitMillis = Duration.ofNanos(commit.observedAtNanos() - started).toMillis();
        long waitedMillis = Duration.ofNanos(finished - started).toMillis();
        Assertions.assertTrue(commit.succeeded(), "FIXTURE " + id + ": the slow commit itself must succeed: "
            + EnforcementTestSupport.describe(commit.error()));
        Assertions.assertTrue(commitMillis >= 1500,
            "FIXTURE " + id + ": the commit was not slow (" + commitMillis + " ms), so the race was not staged");
        Assertions.assertTrue(waitedMillis >= commitMillis - 200,
            id + " (time-based, auxiliary): the " + what + " returned after " + waitedMillis
                + " ms, while the in-flight commit ran for " + commitMillis + " ms");
    }

    // ---------------------------------------------------------------- expiry margin

    /**
     * EX-BB1: a grant with less life left than the audit timeout plus the guard margin is refused
     * <p>
     * The grant has about 900 ms left when the commit is attempted, under the design's default
     * margin. The premise proves it is still valid before the commit, and the metadata clock is
     * read again after the commit returns: if the grant had already expired by then, a denial would
     * be natural expiry rather than the margin, so that is a fixture failure, never a pass. This is
     * the conservative margin, not strict real-time expiry.
     */
    @Test
    public void exBb1CommitInsideTheExpiryMarginIsDenied() throws Exception {
        EnforcementTestSupport.Target target = fixtures.writableTarget(fixtures.user);
        EnforcementTestSupport.openTransaction(target, 40);
        EnforcementTestSupport.setExpiresAt(target.key(), EnforcementTestSupport.metadataNow().plus(Duration.ofMillis(900)));
        OffsetDateTime expiresAt = EnforcementTestSupport.readExpiresAt(target.key());
        EnforcementTestSupport.premiseAllows("EX-BB1", target, DbOperationCategory.TRANSACTION_COMMIT);

        EnforcementTestSupport.Outcome outcome = EnforcementTestSupport.commit(target);

        OffsetDateTime afterCommit = EnforcementTestSupport.metadataNow();
        Assertions.assertTrue(afterCommit.isBefore(expiresAt), "FIXTURE EX-BB1: the grant expired naturally before the commit"
            + " returned (DB_NOW=" + afterCommit + ", EXPIRES_AT=" + expiresAt + "), so this run cannot judge the margin");
        int value = target.committedValue();
        EnforcementTestSupport.assertDenied("EX-BB1", outcome, DenialReason.GRANT_EXPIRED,
            "the grant was still valid when the commit returned (DB_NOW=" + afterCommit + " < EXPIRES_AT=" + expiresAt
                + "); committed row afterwards=" + value);
        Assertions.assertEquals(0, value, "EX-BB1: a commit inside the expiry margin must not commit");
    }
}
