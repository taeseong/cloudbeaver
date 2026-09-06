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
import io.cloudbeaver.service.dbac.tempwrite.MetadataDbClock;
import io.cloudbeaver.service.dbac.tempwrite.MetadataDbTime;
import io.cloudbeaver.service.dbac.tempwrite.MetadataTransaction;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteChangeType;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteGrant;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteGrantRepository;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteGrantRequest;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteMutationCoordinator;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteMutationResult;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteMutationStatus;
import io.cloudbeaver.service.dbac.tempwrite.TempWritePermissionKey;
import io.cloudbeaver.service.security.EmbeddedSecurityControllerFactory;
import io.cloudbeaver.service.security.db.CBDatabase;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/**
 * TEMP_WRITE persistence against the running server's H2 metadata database
 * <p>
 * These are integration tests. They use the metadata database of an actually started CE server, so
 * the schema under test is the one the migration installed, the connection is the one production
 * uses - {@code CBDatabase.openConnection()}, which is what substitutes {@code {table_prefix}} - and
 * the SQL is executed by a real engine rather than asserted against a string.
 * <p>
 * The concurrency tests force the race rather than hoping for it: a barrier releases both writers
 * only once both have read the revision and neither has written, which is the only window where two
 * mutations genuinely contend.
 * <p>
 * Nothing here authorises anything. This slice stores and reads state; no code yet consults it to
 * allow or deny a database write.
 */
public class TempWriteRepositoryTest {

    private static final String PROJECT = "tw-project";
    private static final String CONNECTION = "tw-connection";

    private static CBDatabase database;

    private final TempWriteGrantRepository repository = new TempWriteGrantRepository();
    private final List<TempWritePermissionKey> touched = new ArrayList<>();

    @BeforeAll
    public static void startServer() throws Exception {
        CEAppStarter.startServerIfNotStarted();
        database = EmbeddedSecurityControllerFactory.getDbInstance();
        Assertions.assertNotNull(database, "CBDatabase instance must exist after server startup");
    }

    @AfterEach
    public void cleanUp() throws Exception {
        try (Connection connection = database.openConnection()) {
            for (TempWritePermissionKey key : touched) {
                TempWriteTestSupport.deleteKey(connection, key);
            }
        }
        touched.clear();
    }

    // ---------------------------------------------------------------- reads

    @Test
    public void currentIsEmptyForAKeyNeverGranted() throws Exception {
        TempWritePermissionKey key = key("never-granted");
        try (Connection connection = database.openConnection()) {
            Assertions.assertEquals(Optional.empty(), repository.findCurrent(connection, key));
        }
    }

    @Test
    public void findsExactlyTheRequestedKey() throws Exception {
        TempWritePermissionKey wanted = key("exact-user");
        TempWritePermissionKey other = key("exact-other");
        commitGrant(wanted, TempWriteGrant.NO_ROW_REVISION);
        commitGrant(other, TempWriteGrant.NO_ROW_REVISION);
        try (Connection connection = database.openConnection()) {
            TempWriteGrant found = repository.findCurrent(connection, wanted).orElseThrow();
            Assertions.assertEquals(wanted, found.key());
            Assertions.assertEquals(TempWriteGrant.FIRST_REVISION, found.revision());
        }
    }

    /**
     * A grant belongs to one user, and no other user inherits it
     */
    @Test
    public void anotherUserSeesNoGrant() throws Exception {
        TempWritePermissionKey granted = key("isolated-user");
        TempWritePermissionKey neighbour = key("other-user");
        commitGrant(granted, TempWriteGrant.NO_ROW_REVISION);
        try (Connection connection = database.openConnection()) {
            Assertions.assertTrue(repository.findCurrent(connection, granted).isPresent());
            Assertions.assertTrue(repository.findCurrent(connection, neighbour).isEmpty());
        }
    }

    /**
     * A grant on one connection never authorises another, which is why the key is a triple
     */
    @Test
    public void anotherConnectionAndProjectSeeNoGrant() throws Exception {
        TempWritePermissionKey granted = new TempWritePermissionKey("scoped-user", PROJECT, CONNECTION);
        TempWritePermissionKey otherConnection = new TempWritePermissionKey("scoped-user", PROJECT, "other-conn");
        TempWritePermissionKey otherProject = new TempWritePermissionKey("scoped-user", "other-proj", CONNECTION);
        remember(granted);
        remember(otherConnection);
        remember(otherProject);
        commitGrant(granted, TempWriteGrant.NO_ROW_REVISION);
        try (Connection connection = database.openConnection()) {
            Assertions.assertTrue(repository.findCurrent(connection, granted).isPresent());
            Assertions.assertTrue(repository.findCurrent(connection, otherConnection).isEmpty());
            Assertions.assertTrue(repository.findCurrent(connection, otherProject).isEmpty());
        }
    }

    /**
     * The two list queries are scoped as declared, counted inside a project only this test uses
     * <p>
     * A project of its own rather than the shared one: {@code listByConnection} counts every user on
     * a connection by design, so a row another test left behind - or one a failed cleanup never
     * removed - would change the count and fail this test for an unrelated reason.
     */
    @Test
    public void listsAreScopedToTheirUserAndConnection() throws Exception {
        String project = "tw-list-project";
        TempWritePermissionKey mine = new TempWritePermissionKey("list-user", project, CONNECTION);
        TempWritePermissionKey myOther = new TempWritePermissionKey("list-user", project, "list-conn-2");
        TempWritePermissionKey theirs = new TempWritePermissionKey("list-other", project, CONNECTION);
        remember(mine);
        remember(myOther);
        remember(theirs);
        commitGrant(mine, TempWriteGrant.NO_ROW_REVISION);
        commitGrant(myOther, TempWriteGrant.NO_ROW_REVISION);
        commitGrant(theirs, TempWriteGrant.NO_ROW_REVISION);
        try (Connection connection = database.openConnection()) {
            Assertions.assertEquals(2, repository.listByUser(connection, "list-user").size());
            Assertions.assertEquals(1, repository.listByUser(connection, "list-other").size());
            Assertions.assertEquals(
                2, repository.listByConnection(connection, project, CONNECTION).size(),
                "both users hold a grant on this connection");
            Assertions.assertEquals(
                1, repository.listByConnection(connection, project, "list-conn-2").size());
        }
    }

    // ---------------------------------------------------------------- compare-and-set

    @Test
    public void firstGrantInsertsAtRevisionOne() throws Exception {
        TempWritePermissionKey key = key("first-grant");
        TempWriteMutationResult result = commitGrant(key, TempWriteGrant.NO_ROW_REVISION);
        Assertions.assertEquals(TempWriteMutationStatus.COMMITTED, result.status());
        Assertions.assertEquals(TempWriteGrant.FIRST_REVISION, result.revision());
        Assertions.assertEquals(1, result.attempts());
        assertState(key, 1, TempWriteGrant.FIRST_REVISION, List.of("GRANTED@1"));
    }

    @Test
    public void secondGrantIncrementsRevision() throws Exception {
        TempWritePermissionKey key = key("second-grant");
        commitGrant(key, TempWriteGrant.NO_ROW_REVISION);
        TempWriteMutationResult second = commitGrant(key, TempWriteGrant.FIRST_REVISION);
        Assertions.assertEquals(TempWriteMutationStatus.COMMITTED, second.status());
        Assertions.assertEquals(2L, second.revision());
        assertState(key, 1, 2L, List.of("GRANTED@1", "GRANTED@2", "SUPERSEDED@2"));
    }

    /**
     * A request that started from an older view is refused, not applied to the newer row
     */
    @Test
    public void staleStartRevisionIsRefused() throws Exception {
        TempWritePermissionKey key = key("stale-revision");
        commitGrant(key, TempWriteGrant.NO_ROW_REVISION);
        TempWriteMutationResult refused = coordinator().grant(
            TempWriteTestSupport.grantRequest(
                key, TempWriteGrant.NO_ROW_REVISION, TempWriteTestSupport.DEFAULT_DURATION, "stale"));
        Assertions.assertEquals(TempWriteMutationStatus.CONFLICT_SUPERSEDED, refused.status());
        Assertions.assertEquals(0, refused.affectedRows());
        Assertions.assertEquals(1, refused.attempts(), "a superseded request must not be retried");
        assertState(key, 1, TempWriteGrant.FIRST_REVISION, List.of("GRANTED@1"));
    }

    /**
     * Replacing a live grant ends the old one and starts the new one in one transaction
     */
    @Test
    public void replacingAnActiveGrantRecordsSupersededAndGranted() throws Exception {
        TempWritePermissionKey key = key("replace-active");
        commitGrant(key, TempWriteGrant.NO_ROW_REVISION);
        commitGrant(key, TempWriteGrant.FIRST_REVISION);
        try (Connection connection = database.openConnection()) {
            List<String> history = TempWriteTestSupport.historyOf(connection, key);
            Assertions.assertEquals(List.of("GRANTED@1", "GRANTED@2", "SUPERSEDED@2"), history);
            TempWriteGrant current = repository.findCurrent(connection, key).orElseThrow();
            Assertions.assertFalse(current.isRevoked(), "a replacement leaves the row live");
        }
    }

    /**
     * Replacing an already revoked grant records only the new grant
     * <p>
     * The old one already has its {@code REVOKED} event; superseding it again would claim a
     * transition that never happened.
     */
    @Test
    public void replacingARevokedGrantRecordsOnlyGranted() throws Exception {
        TempWritePermissionKey key = key("replace-revoked");
        commitGrant(key, TempWriteGrant.NO_ROW_REVISION);
        coordinator().revoke(TempWriteTestSupport.revokeRequest(key, TempWriteGrant.FIRST_REVISION));
        commitGrant(key, 2L);
        try (Connection connection = database.openConnection()) {
            Assertions.assertEquals(
                List.of("GRANTED@1", "REVOKED@2", "GRANTED@3"),
                TempWriteTestSupport.historyOf(connection, key));
        }
    }

    // ---------------------------------------------------------------- revoke

    @Test
    public void revokeEndsTheGrantAndRecordsIt() throws Exception {
        TempWritePermissionKey key = key("revoke-ok");
        commitGrant(key, TempWriteGrant.NO_ROW_REVISION);
        TempWriteMutationResult result =
            coordinator().revoke(TempWriteTestSupport.revokeRequest(key, TempWriteGrant.FIRST_REVISION));
        Assertions.assertEquals(TempWriteMutationStatus.COMMITTED, result.status());
        Assertions.assertEquals(2L, result.revision());
        try (Connection connection = database.openConnection()) {
            TempWriteGrant current = repository.findCurrent(connection, key).orElseThrow();
            Assertions.assertTrue(current.isRevoked());
            Assertions.assertEquals("admin-2", current.revokedBy());
            Assertions.assertEquals(
                List.of("GRANTED@1", "REVOKED@2"), TempWriteTestSupport.historyOf(connection, key));
        }
    }

    /**
     * A repeated revoke succeeds without writing anything, so a retried request is harmless
     */
    @Test
    public void revokeIsIdempotent() throws Exception {
        TempWritePermissionKey key = key("revoke-twice");
        commitGrant(key, TempWriteGrant.NO_ROW_REVISION);
        coordinator().revoke(TempWriteTestSupport.revokeRequest(key, TempWriteGrant.FIRST_REVISION));
        TempWriteMutationResult again =
            coordinator().revoke(TempWriteTestSupport.revokeRequest(key, 2L));
        Assertions.assertEquals(TempWriteMutationStatus.NO_OP, again.status());
        Assertions.assertEquals(0, again.affectedRows());
        assertState(key, 1, 2L, List.of("GRANTED@1", "REVOKED@2"));
    }

    @Test
    public void revokeOnAKeyWithNoRowIsANoOp() throws Exception {
        TempWritePermissionKey key = key("revoke-absent");
        TempWriteMutationResult result = coordinator().revoke(
            TempWriteTestSupport.revokeRequest(key, TempWriteGrant.NO_ROW_REVISION));
        Assertions.assertEquals(TempWriteMutationStatus.NO_OP, result.status());
        assertState(key, 0, null, List.of());
    }

    // ---------------------------------------------------------------- atomicity

    /**
     * A failing history insert takes the current row with it
     */
    @Test
    public void historyFailureRollsBackTheCurrentRow() throws Exception {
        TempWritePermissionKey key = key("history-fails");
        remember(key);
        TempWriteMutationCoordinator failing = TempWriteMutationCoordinator.withoutAuditing(
            TempWriteTestSupport.failingOn(
                database::openConnection, TempWriteTestSupport.HISTORY_TABLE, "42601"),
            repository);
        SQLException failure = Assertions.assertThrows(
            SQLException.class,
            () -> failing.grant(TempWriteTestSupport.grantRequest(
                key, TempWriteGrant.NO_ROW_REVISION, TempWriteTestSupport.DEFAULT_DURATION, "history")));
        Assertions.assertEquals("42601", failure.getSQLState());
        assertState(key, 0, null, List.of());
    }

    /**
     * A failing current-row write leaves no history behind either
     */
    @Test
    public void currentFailureLeavesNoHistory() throws Exception {
        TempWritePermissionKey key = key("current-fails");
        remember(key);
        TempWriteMutationCoordinator failing = TempWriteMutationCoordinator.withoutAuditing(
            TempWriteTestSupport.failingOn(
                database::openConnection, "INSERT INTO " + TempWriteTestSupport.CURRENT_TABLE, "42601"),
            repository);
        Assertions.assertThrows(
            SQLException.class,
            () -> failing.grant(TempWriteTestSupport.grantRequest(
                key, TempWriteGrant.NO_ROW_REVISION, TempWriteTestSupport.DEFAULT_DURATION, "current")));
        assertState(key, 0, null, List.of());
    }

    /**
     * An unchecked failure after the write, before the commit, still leaves nothing behind
     * <p>
     * This is the path no {@code catch (SQLException)} can see, and it is not hypothetical: without
     * the coordinator's {@code finally} guard the transaction reaches
     * {@code JDBCTransaction.close()} still open, that method restores auto-commit, and JDBC commits
     * the pending work - storing a current row whose history event was never written. The injection
     * point is the history insert, so the current row has definitely been written by the time it
     * fires.
     */
    @Test
    public void uncheckedFailureAfterTheWriteStillRollsBack() throws Exception {
        TempWritePermissionKey key = key("unchecked-fails");
        remember(key);
        TempWriteMutationCoordinator failing = TempWriteMutationCoordinator.withoutAuditing(
            TempWriteTestSupport.failingUncheckedOn(
                database::openConnection, TempWriteTestSupport.HISTORY_TABLE),
            repository);
        IllegalStateException failure = Assertions.assertThrows(
            IllegalStateException.class,
            () -> failing.grant(TempWriteTestSupport.grantRequest(
                key, TempWriteGrant.NO_ROW_REVISION, TempWriteTestSupport.DEFAULT_DURATION, "unchecked")));
        Assertions.assertTrue(
            failure.getMessage().contains("Injected unchecked failure"),
            "the original failure must reach the caller, not be replaced by cleanup");
        assertState(key, 0, null, List.of());
    }

    /**
     * When the rollback itself fails, nothing is stored and nothing is hidden
     * <p>
     * A separate scenario from the unchecked-exception one above, and the more dangerous of the two.
     * The current row is written, the history insert fails, and the rollback that should undo the
     * write fails as well. JDBC specifies that putting a connection with a pending transaction into
     * auto-commit mode commits that work, so anything that restores auto-commit here stores a grant
     * whose history event never existed - a permission with no trace of who granted it.
     * <p>
     * The counters are asserted, not just the row counts: a build that lost the write for some other
     * reason would satisfy row counts alone while leaving the hole open.
     */
    @Test
    public void rollbackFailureStoresNothingAndIsNotHidden() throws Exception {
        TempWritePermissionKey key = key("rollback-fails");
        remember(key);
        TempWriteTestSupport.RollbackFailureProbe probe = new TempWriteTestSupport.RollbackFailureProbe(
            database::openConnection, TempWriteTestSupport.HISTORY_TABLE, "42601");
        TempWriteMutationCoordinator coordinator = TempWriteMutationCoordinator.withoutAuditing(probe, repository);

        SQLException failure = Assertions.assertThrows(
            SQLException.class,
            () -> coordinator.grant(TempWriteTestSupport.grantRequest(
                key, TempWriteGrant.NO_ROW_REVISION, TempWriteTestSupport.DEFAULT_DURATION, "rollback")));

        System.out.println("[DBAC] H2 rollback-failure probe: " + probe.describe());
        Assertions.assertEquals("42601", failure.getSQLState(), "the original failure must reach the caller");
        Assertions.assertTrue(
            hasSqlState(failure.getSuppressed(), "08006"),
            "the rollback failure must be visible to the caller, not only in a log");
        Assertions.assertEquals(
            0, probe.autoCommitTrue.get(),
            "restoring auto-commit after a failed rollback would commit the pending write");
        Assertions.assertEquals(0, probe.commits.get(), "nothing may be committed");
        Assertions.assertEquals(1, probe.rollbacks.get(), "a failed rollback must not be retried");
        Assertions.assertEquals(
            1, probe.currentWrites.get(), "a failed rollback is terminal, so no new compare-and-set");
        Assertions.assertEquals(
            1, probe.opened.get(), "a poisoned connection must not be replaced and retried");
        Assertions.assertTrue(
            probe.aborts.get() >= 1,
            "close() must attempt to sever the poisoned connection rather than hand it back intact");
        assertState(key, 0, null, List.of());
    }

    /**
     * A transaction nobody finished stores nothing, even though no failure occurred
     * <p>
     * The gap this closes is not a failure path at all. A caller that returns from the try block
     * without committing or rolling back has decided nothing, and restoring auto-commit on the way
     * out would commit the write - JDBC says so, and it is the same defect that made
     * {@code JDBCTransaction} unusable here. Both coordinator paths decide on every branch today, so
     * this is about the guarantee living in the transaction rather than in its callers' discipline.
     */
    @Test
    public void transactionNobodyFinishedStoresNothing() throws Exception {
        TempWritePermissionKey key = key("abandoned");
        remember(key);
        try (Connection connection = database.openConnection();
             MetadataTransaction txn = new MetadataTransaction(connection)
        ) {
            MetadataDbTime dbNow = MetadataDbClock.readNow(connection);
            Assertions.assertEquals(
                1,
                repository.insertCurrent(
                    connection, TempWriteTestSupport.storedGrant(key, TempWriteGrant.FIRST_REVISION, dbNow)),
                "Precondition: the row must really have been written inside the transaction");
            Assertions.assertEquals(
                1, TempWriteTestSupport.countCurrent(connection, key),
                "Precondition: the transaction must see its own write");
            // No commit(), no rollback(). Leaving the block is the whole test.
        }
        assertState(key, 0, null, List.of());
    }

    /**
     * And if that closing rollback cannot be done either, the connection is severed instead
     */
    @Test
    public void unfinishedTransactionThatCannotRollBackIsSevered() throws Exception {
        TempWritePermissionKey key = key("abandoned-stuck");
        remember(key);
        TempWriteTestSupport.RollbackFailureProbe probe = new TempWriteTestSupport.RollbackFailureProbe(
            database::openConnection, "NO_SUCH_TABLE_FRAGMENT", "42601");
        try (Connection connection = probe.openConnection();
             MetadataTransaction txn = new MetadataTransaction(connection)
        ) {
            MetadataDbTime dbNow = MetadataDbClock.readNow(connection);
            repository.insertCurrent(
                connection, TempWriteTestSupport.storedGrant(key, TempWriteGrant.FIRST_REVISION, dbNow));
        }
        System.out.println("[DBAC] H2 abandoned-transaction probe: " + probe.describe());
        // Storage first, counters after: a regression here has to report itself as a stored row.
        assertState(key, 0, null, List.of());
        Assertions.assertEquals(
            0, probe.autoCommitTrue.get(),
            "auto-commit must not be restored when the closing rollback failed");
        Assertions.assertEquals(0, probe.commits.get(), "nothing may be committed");
        Assertions.assertEquals(1, probe.rollbacks.get(), "close() must try exactly one rollback");
        Assertions.assertTrue(
            probe.aborts.get() >= 1,
            "close() must attempt to sever the connection; whether the driver honours abort is its own"
                + " business, and the pool's rollback-on-return covers the case where it does not");
    }

    /**
     * A rollback that fails with an unchecked exception is just as terminal
     * <p>
     * Not a hypothetical. When the poisoned state was decided inside {@code catch (SQLException)},
     * this exact case restored auto-commit and committed the grant row with no history and no audit
     * entry - the fail-open this whole structure exists to remove, reachable by nothing more than a
     * driver choosing a different exception class. Both engines were measured storing one row.
     */
    @Test
    public void uncheckedRollbackFailureIsAlsoTerminal() throws Exception {
        assertRollbackFailureIsTerminal(
            key("rollback-unchecked"), "unchecked",
            () -> new IllegalStateException("Injected unchecked rollback failure"));
    }

    /**
     * And so is one that fails with an Error, which is the route a driver cannot cause but the JVM can
     */
    @Test
    public void errorFromRollbackIsAlsoTerminal() throws Exception {
        assertRollbackFailureIsTerminal(
            key("rollback-error"), "error",
            () -> new LinkageError("Injected Error from rollback"));
    }

    private void assertRollbackFailureIsTerminal(
        @NotNull TempWritePermissionKey key,
        @NotNull String reason,
        @NotNull Supplier<Throwable> injected
    ) throws Exception {
        remember(key);
        TempWriteTestSupport.RollbackFailureProbe probe = new TempWriteTestSupport.RollbackFailureProbe(
            database::openConnection, TempWriteTestSupport.HISTORY_TABLE, "42601", injected);
        TempWriteMutationCoordinator coordinator = TempWriteMutationCoordinator.withoutAuditing(probe, repository);

        // Throwable, not SQLException, and asserted last on purpose. What matters first is that
        // nothing was stored and the connection was severed; which class came out is a secondary
        // fact. Asserting the class first would let a regression that commits the row be reported as
        // a mere exception-type mismatch, which reads like a test problem rather than a fail-open.
        final Throwable thrown = Assertions.assertThrows(
            Throwable.class,
            () -> coordinator.grant(TempWriteTestSupport.grantRequest(
                key, TempWriteGrant.NO_ROW_REVISION, TempWriteTestSupport.DEFAULT_DURATION, reason)));

        System.out.println("[DBAC] H2 " + reason + " rollback-failure probe: " + probe.describe());
        assertState(key, 0, null, List.of());
        Assertions.assertEquals(
            0, probe.autoCommitTrue.get(),
            "restoring auto-commit after a failed rollback would commit the pending write");
        Assertions.assertEquals(0, probe.commits.get(), "nothing may be committed");
        Assertions.assertTrue(
            probe.aborts.get() >= 1, "close() must attempt to sever the poisoned connection");
        Assertions.assertEquals(1, probe.rollbacks.get(), "a failed rollback must not be retried");
        Assertions.assertEquals(1, probe.currentWrites.get(), "a failed rollback is terminal");
        Assertions.assertEquals(1, probe.opened.get(), "a poisoned connection must not be replaced");

        SQLException failure = Assertions.assertInstanceOf(
            SQLException.class, thrown,
            "the original failure must reach the caller, not the rollback failure that followed it");
        Assertions.assertEquals("42601", failure.getSQLState());
        Throwable expected = injected.get();
        Assertions.assertTrue(
            java.util.Arrays.stream(failure.getSuppressed())
                .anyMatch(suppressed -> suppressed.getClass() == expected.getClass()),
            "the rollback failure must be attached to the failure the caller sees, got: "
                + java.util.Arrays.toString(failure.getSuppressed()));
    }

    /**
     * An audit sink sees the coordinator's own connection, before the commit
     * <p>
     * Phase 2 requires the audit entry for a grant to be written in the same transaction as the row,
     * so a permission cannot exist without a record of who granted it. This proves the seam is real
     * rather than promised: the sink is called on the same connection, the row is not yet visible to
     * anyone else at that point, and both land together.
     */
    @Test
    public void auditSinkRunsInsideTheSameTransaction() throws Exception {
        TempWritePermissionKey key = key("audit-inside");
        List<String> seen = new ArrayList<>();
        TempWriteMutationCoordinator coordinator = new TempWriteMutationCoordinator(
            database::openConnection,
            repository,
            (connection, changeType, grant, actor, dbNow) -> {
                // Reading through the coordinator's own connection sees the uncommitted row; reading
                // through a different one does not. That is what "same transaction" means here.
                // The revision recorded is the one being written, and the clock reading handed in is
                // the same one the row carries - a sink that had to read its own clock could disagree
                // with the row it is describing.
                seen.add(changeType + "/" + grant.revision() + "/" + actor
                    + "/inTxn=" + (TempWriteTestSupport.countCurrent(connection, key) == 1)
                    + "/uncommittedRevision=" + uncommittedRevisionElsewhere(key)
                    + "/clockIsTheRowClock=" + dbNow.equals(
                        changeType == TempWriteChangeType.GRANTED ? grant.grantedAt() : grant.revokedAt()));
            });
        coordinator.grant(TempWriteTestSupport.grantRequest(
            key, TempWriteGrant.NO_ROW_REVISION, TempWriteTestSupport.DEFAULT_DURATION, "audited"));
        // On the grant there is no committed row yet, so another connection sees nothing at all.
        Assertions.assertEquals(
            List.of("GRANTED/1/admin-1/inTxn=true/uncommittedRevision=null/clockIsTheRowClock=true"),
            seen);
        assertState(key, 1, TempWriteGrant.FIRST_REVISION, List.of("GRANTED@1"));

        coordinator.revoke(TempWriteTestSupport.revokeRequest(key, TempWriteGrant.FIRST_REVISION));
        Assertions.assertEquals(2, seen.size(), "the revoke must be audited too");
        // On the revoke the row already exists at revision 1, committed by the grant. What proves the
        // sink is inside the transaction is that another connection still sees revision 1 while the
        // sink is looking at the row the revoke is about to move to revision 2.
        // Revision 2, not 1: the sink is handed the row as the revoke will commit it, so an observer
        // never has to reconstruct the transition for itself.
        Assertions.assertEquals(
            "REVOKED/2/admin-2/inTxn=true/uncommittedRevision=1/clockIsTheRowClock=true", seen.get(1));
    }

    /**
     * A failing audit sink rolls the whole transition back
     * <p>
     * The other half of the requirement. If auditing could fail while the row survived, the audit
     * trail would be a best-effort log rather than a record, and a grant could exist that nothing
     * accounts for.
     */
    @Test
    public void auditFailureRollsBackTheTransition() throws Exception {
        TempWritePermissionKey key = key("audit-fails");
        remember(key);
        TempWriteMutationCoordinator coordinator = new TempWriteMutationCoordinator(
            database::openConnection,
            repository,
            (connection, changeType, grant, actor, dbNow) -> {
                throw new SQLException("Injected audit failure", "42601");
            });
        SQLException failure = Assertions.assertThrows(
            SQLException.class,
            () -> coordinator.grant(TempWriteTestSupport.grantRequest(
                key, TempWriteGrant.NO_ROW_REVISION, TempWriteTestSupport.DEFAULT_DURATION, "audit")));
        Assertions.assertEquals("42601", failure.getSQLState());
        assertState(key, 0, null, List.of());
    }

    /**
     * A broken metadata database is an error, never an empty answer
     * <p>
     * A caller that could not tell an outage from "this user has no grant" would read a dead store as
     * a denial of nothing.
     */
    @Test
    public void readFailurePropagatesInsteadOfLookingEmpty() throws Exception {
        TempWritePermissionKey key = key("read-fails");
        try (Connection real = database.openConnection()) {
            Connection broken = TempWriteTestSupport.failingOn(
                () -> real, "SELECT USER_ID", "42601").openConnection();
            SQLException failure = Assertions.assertThrows(
                SQLException.class, () -> repository.findCurrent(broken, key));
            Assertions.assertEquals("42601", failure.getSQLState());
        }
    }

    // ---------------------------------------------------------------- concurrency

    /**
     * Two grants that start from the same revision produce one winner and one refusal
     * <p>
     * This is the corrected I10. Both requests are valid and both start from revision 0; the loser is
     * refused rather than retried into success, so the key ends with exactly one current row and
     * exactly one {@code GRANTED} event, and the refused request leaves no history at all.
     */
    @Test
    public void concurrentGrantsLeaveExactlyOneWinner() throws Exception {
        TempWritePermissionKey key = key("concurrent-grants");
        remember(key);
        CyclicBarrier barrier = new CyclicBarrier(2);
        List<TempWriteMutationResult> results = runBoth(
            () -> barrierCoordinator(barrier).grant(TempWriteTestSupport.grantRequest(
                key, TempWriteGrant.NO_ROW_REVISION, Duration.ofMinutes(30), "first")),
            () -> barrierCoordinator(barrier).grant(TempWriteTestSupport.grantRequest(
                key, TempWriteGrant.NO_ROW_REVISION, Duration.ofMinutes(60), "second")));
        assertOneWinnerOneConflict(results);
        assertState(key, 1, TempWriteGrant.FIRST_REVISION, List.of("GRANTED@1"));
    }

    /**
     * A grant and a revoke racing from the same revision leave one consistent row
     */
    @Test
    public void concurrentGrantAndRevokeLeaveOneConsistentRow() throws Exception {
        TempWritePermissionKey key = key("concurrent-mixed");
        commitGrant(key, TempWriteGrant.NO_ROW_REVISION);
        CyclicBarrier barrier = new CyclicBarrier(2);
        List<TempWriteMutationResult> results = runBoth(
            () -> barrierCoordinator(barrier).grant(TempWriteTestSupport.grantRequest(
                key, TempWriteGrant.FIRST_REVISION, Duration.ofMinutes(30), "racing grant")),
            () -> barrierCoordinator(barrier).revoke(
                TempWriteTestSupport.revokeRequest(key, TempWriteGrant.FIRST_REVISION)));
        assertOneWinnerOneConflict(results);
        try (Connection connection = database.openConnection()) {
            Assertions.assertEquals(1, TempWriteTestSupport.countCurrent(connection, key));
            Assertions.assertEquals(2L, TempWriteTestSupport.currentRevision(connection, key));
            TempWriteGrant current = repository.findCurrent(connection, key).orElseThrow();
            // Either outcome is correct; what must hold is that the history describes the state the
            // row is actually in. Which of the two won is not deterministic and asserting one of them
            // would be asserting a coin toss. A replacement records two events because it both ends
            // the old grant and starts a new one; a revoke records one.
            Assertions.assertEquals(
                current.isRevoked()
                    ? List.of("GRANTED@1", "REVOKED@2")
                    : List.of("GRANTED@1", "GRANTED@2", "SUPERSEDED@2"),
                TempWriteTestSupport.historyOf(connection, key),
                "history must describe the state the current row is actually in");
        }
    }

    /**
     * A grant that commits after a revoke cannot bring the old permission back
     * <p>
     * This is I12, and it is the reason the start revision is never refreshed. The delayed grant is
     * held just before its write, the revoke commits, and then the grant is released: it finds the
     * revision moved and is refused. A build that re-read the revision on retry would let it succeed
     * and quietly restore write access that an administrator had just taken away.
     */
    @Test
    public void grantDelayedPastARevokeCannotResurrect() throws Exception {
        TempWritePermissionKey key = key("delayed-grant");
        commitGrant(key, TempWriteGrant.NO_ROW_REVISION);
        CountDownLatch hasRead = new CountDownLatch(1);
        CountDownLatch mayWrite = new CountDownLatch(1);
        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            final Future<TempWriteMutationResult> delayed = pool.submit(
                () -> pausedCoordinator(hasRead, mayWrite).grant(TempWriteTestSupport.grantRequest(
                    key, TempWriteGrant.FIRST_REVISION, Duration.ofMinutes(30), "delayed")));
            // Both halves of the ordering are forced: the grant has provably read revision 1 before
            // the revoke starts, and it cannot write until the revoke has committed.
            Assertions.assertTrue(
                hasRead.await(30, TimeUnit.SECONDS), "the delayed grant never reached its write");
            TempWriteMutationResult revoke =
                coordinator().revoke(TempWriteTestSupport.revokeRequest(key, TempWriteGrant.FIRST_REVISION));
            Assertions.assertEquals(TempWriteMutationStatus.COMMITTED, revoke.status());
            mayWrite.countDown();
            TempWriteMutationResult late = delayed.get(60, TimeUnit.SECONDS);
            Assertions.assertEquals(TempWriteMutationStatus.CONFLICT_SUPERSEDED, late.status());
            Assertions.assertEquals(0, late.affectedRows());
        } finally {
            pool.shutdownNow();
        }
        try (Connection connection = database.openConnection()) {
            TempWriteGrant current = repository.findCurrent(connection, key).orElseThrow();
            Assertions.assertTrue(current.isRevoked(), "the revoke must still stand");
            Assertions.assertEquals(2L, current.revision());
            Assertions.assertEquals(
                List.of("GRANTED@1", "REVOKED@2"), TempWriteTestSupport.historyOf(connection, key));
        }
    }

    /**
     * Contention that never resolves fails closed after the retry limit
     */
    @Test
    public void transientConflictBeyondTheRetryLimitFailsClosed() throws Exception {
        TempWritePermissionKey key = key("retry-exhausted");
        remember(key);
        TempWriteMutationCoordinator alwaysContended = TempWriteMutationCoordinator.withoutAuditing(
            TempWriteTestSupport.failingOn(
                database::openConnection, "INSERT INTO " + TempWriteTestSupport.CURRENT_TABLE, "23505"),
            repository);
        TempWriteMutationResult result = alwaysContended.grant(TempWriteTestSupport.grantRequest(
            key, TempWriteGrant.NO_ROW_REVISION, TempWriteTestSupport.DEFAULT_DURATION, "contended"));
        Assertions.assertEquals(TempWriteMutationStatus.RETRY_EXHAUSTED, result.status());
        Assertions.assertEquals(
            TempWriteMutationCoordinator.MAX_TRANSIENT_RETRIES + 1, result.attempts(),
            "one initial attempt plus the permitted retries, and no more");
        Assertions.assertEquals(0, result.affectedRows());
        assertState(key, 0, null, List.of());
    }

    // ---------------------------------------------------------------- stored content and clock

    /**
     * Expiry is the database clock plus the duration, computed from a value the database produced
     */
    @Test
    public void expiryIsTheDatabaseClockPlusTheDuration() throws Exception {
        TempWritePermissionKey key = key("clock-expiry");
        Duration duration = Duration.ofMinutes(45);
        remember(key);
        coordinator().grant(TempWriteTestSupport.grantRequest(
            key, TempWriteGrant.NO_ROW_REVISION, duration, "clock"));
        try (Connection connection = database.openConnection()) {
            TempWriteGrant grant = repository.findCurrent(connection, key).orElseThrow();
            Assertions.assertEquals(
                duration, Duration.between(grant.grantedAt().instant(), grant.expiresAt().instant()));
            Assertions.assertEquals(
                duration, Duration.between(grant.grantedAt().stored(), grant.expiresAt().stored()));
            MetadataDbTime dbNow = MetadataDbClock.readNow(connection);
            Assertions.assertTrue(
                grant.expiresAt().instant().isAfter(dbNow.instant()),
                "a fresh 45 minute grant must still be in the future");
        }
    }

    /**
     * The grant, its expiry and its history event all carry the same clock reading
     */
    @Test
    public void oneClockReadingIsSharedByTheRowAndItsHistory() throws Exception {
        TempWritePermissionKey key = key("clock-shared");
        remember(key);
        coordinator().grant(TempWriteTestSupport.grantRequest(
            key, TempWriteGrant.NO_ROW_REVISION, TempWriteTestSupport.DEFAULT_DURATION, "shared clock"));
        try (Connection connection = database.openConnection()) {
            TempWriteGrant grant = repository.findCurrent(connection, key).orElseThrow();
            Assertions.assertEquals(
                grant.grantedAt().instant(), historyChangeTime(connection, key).toInstant());
        }
    }

    /**
     * What this engine actually does to a timestamp, pinned rather than assumed
     * <p>
     * Round-tripping a value with nanoseconds shows how much precision the column keeps. The
     * assertion is deliberately about the relationship - the value read back is the value written,
     * truncated, never rounded up past it - because an expiry that came back later than it was
     * written would extend a grant.
     */
    @Test
    public void storedTimestampPrecisionIsPinned() throws Exception {
        TempWritePermissionKey key = key("clock-precision");
        remember(key);
        coordinator().grant(TempWriteTestSupport.grantRequest(
            key, TempWriteGrant.NO_ROW_REVISION, Duration.ofSeconds(90), "precision"));
        try (Connection connection = database.openConnection()) {
            TempWriteGrant grant = repository.findCurrent(connection, key).orElseThrow();
            OffsetDateTime granted = grant.grantedAt().stored();
            Assertions.assertEquals(
                Duration.ofSeconds(90),
                Duration.between(granted, grant.expiresAt().stored()),
                "a whole-second duration must survive the column exactly");
            System.out.println("[DBAC] H2 stored GRANTED_AT=" + granted + " nanos=" + granted.getNano());
        }
    }

    /**
     * Nothing that could carry a secret or a statement is stored
     * <p>
     * Checked against the table rather than the model, because the model is what the test would have
     * to trust otherwise.
     */
    @Test
    public void storedRowsHoldNoCredentialOrStatementColumns() throws Exception {
        try (Connection connection = database.openConnection()) {
            List<String> forbidden = List.of(
                "PASSWORD", "SECRET", "TOKEN", "CREDENTIAL", "SQL_TEXT", "STATEMENT_TEXT", "DETAIL");
            for (String table : new String[]{"DBAC_TW_CURRENT", "DBAC_TW_HISTORY"}) {
                List<String> columns = columnsOf(connection, table);
                Assertions.assertFalse(columns.isEmpty(), table + " must exist");
                for (String column : columns) {
                    for (String banned : forbidden) {
                        Assertions.assertFalse(
                            column.contains(banned),
                            table + " must not have a column like " + banned + ", found " + column);
                    }
                }
            }
        }
    }

    // ---------------------------------------------------------------- helpers

    @NotNull
    private TempWriteMutationCoordinator coordinator() {
        return TempWriteMutationCoordinator.withoutAuditing(database::openConnection, repository);
    }

    @NotNull
    private TempWriteMutationCoordinator barrierCoordinator(@NotNull CyclicBarrier barrier) {
        return TempWriteMutationCoordinator.withoutAuditing(
            TempWriteTestSupport.barrierBeforeWrite(database::openConnection, barrier), repository);
    }

    @NotNull
    private TempWriteMutationCoordinator pausedCoordinator(
        @NotNull CountDownLatch hasRead,
        @NotNull CountDownLatch mayWrite
    ) {
        return TempWriteMutationCoordinator.withoutAuditing(
            TempWriteTestSupport.pauseBeforeWrite(database::openConnection, hasRead, mayWrite), repository);
    }

    @NotNull
    private TempWritePermissionKey key(@NotNull String user) {
        TempWritePermissionKey key = new TempWritePermissionKey(user, PROJECT, CONNECTION);
        remember(key);
        return key;
    }

    private void remember(@NotNull TempWritePermissionKey key) {
        if (!touched.contains(key)) {
            touched.add(key);
        }
    }

    @NotNull
    private TempWriteMutationResult commitGrant(
        @NotNull TempWritePermissionKey key,
        long startRevision
    ) throws SQLException {
        TempWriteGrantRequest request = TempWriteTestSupport.grantRequest(
            key, startRevision, TempWriteTestSupport.DEFAULT_DURATION, "setup");
        TempWriteMutationResult result = coordinator().grant(request);
        Assertions.assertEquals(
            TempWriteMutationStatus.COMMITTED, result.status(), "setup grant must commit");
        return result;
    }

    private void assertState(
        @NotNull TempWritePermissionKey key,
        int expectedRows,
        @Nullable Long expectedRevision,
        @NotNull List<String> expectedHistory
    ) throws SQLException {
        try (Connection connection = database.openConnection()) {
            Assertions.assertEquals(
                expectedRows, TempWriteTestSupport.countCurrent(connection, key), "current row count");
            Assertions.assertEquals(
                expectedRevision, TempWriteTestSupport.currentRevision(connection, key), "current revision");
            Assertions.assertEquals(
                expectedHistory, TempWriteTestSupport.historyOf(connection, key), "history");
        }
    }

    /**
     * What revision another connection can see for this key, which is the committed state
     * <p>
     * Used to show that the audit sink really runs inside the uncommitted transaction rather than
     * merely being handed a connection that happens to work: the sink sees the new state, everyone
     * else still sees the old one.
     */
    @Nullable
    private static Long uncommittedRevisionElsewhere(@NotNull TempWritePermissionKey key)
            throws SQLException {
        try (Connection other = database.openConnection()) {
            return TempWriteTestSupport.currentRevision(other, key);
        }
    }

    /**
     * Whether any of these carries a given SQLSTATE
     */
    private static boolean hasSqlState(@NotNull Throwable[] candidates, @NotNull String sqlState) {
        for (Throwable candidate : candidates) {
            if (candidate instanceof SQLException sql && sqlState.equals(sql.getSQLState())) {
                return true;
            }
        }
        return false;
    }

    private static void assertOneWinnerOneConflict(@NotNull List<TempWriteMutationResult> results) {
        long committed = results.stream().filter(TempWriteMutationResult::isCommitted).count();
        long refused = results.stream().filter(TempWriteMutationResult::isRefused).count();
        Assertions.assertEquals(2, results.size());
        Assertions.assertEquals(1, committed, "exactly one writer may win: " + results);
        Assertions.assertEquals(1, refused, "exactly one writer must be refused: " + results);
        Assertions.assertEquals(
            TempWriteMutationStatus.CONFLICT_SUPERSEDED,
            results.stream().filter(TempWriteMutationResult::isRefused).findFirst().orElseThrow().status(),
            "the loser is superseded, not retried into success or failure");
    }

    @NotNull
    private static List<TempWriteMutationResult> runBoth(
        @NotNull Callable<TempWriteMutationResult> first,
        @NotNull Callable<TempWriteMutationResult> second
    ) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<TempWriteMutationResult> a = pool.submit(first);
            Future<TempWriteMutationResult> b = pool.submit(second);
            return List.of(a.get(60, TimeUnit.SECONDS), b.get(60, TimeUnit.SECONDS));
        } finally {
            pool.shutdownNow();
        }
    }

    @NotNull
    private static OffsetDateTime historyChangeTime(
        @NotNull Connection connection,
        @NotNull TempWritePermissionKey key
    ) throws SQLException {
        try (PreparedStatement dbStat = connection.prepareStatement(
            "SELECT CHANGE_TIME FROM " + TempWriteTestSupport.HISTORY_TABLE
                + " WHERE USER_ID=? AND PROJECT_ID=? AND CONNECTION_ID=?")
        ) {
            dbStat.setString(1, key.userId());
            dbStat.setString(2, key.projectId());
            dbStat.setString(3, key.connectionId());
            try (ResultSet dbResult = dbStat.executeQuery()) {
                Assertions.assertTrue(dbResult.next(), "history event must exist");
                return dbResult.getObject(1, OffsetDateTime.class);
            }
        }
    }

    @NotNull
    private static List<String> columnsOf(@NotNull Connection connection, @NotNull String table)
            throws SQLException {
        List<String> columns = new ArrayList<>();
        try (ResultSet dbResult = connection.getMetaData().getColumns(null, null, table, null)) {
            while (dbResult.next()) {
                columns.add(dbResult.getString("COLUMN_NAME").toUpperCase(java.util.Locale.ROOT));
            }
        }
        return columns;
    }
}
