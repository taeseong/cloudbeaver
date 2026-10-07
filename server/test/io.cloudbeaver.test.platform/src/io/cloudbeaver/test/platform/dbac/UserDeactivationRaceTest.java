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
import io.cloudbeaver.server.CBApplicationCE;
import io.cloudbeaver.service.dbac.DbacEmbeddedSecurityController;
import io.cloudbeaver.service.dbac.policy.DbAccessKey;
import io.cloudbeaver.service.dbac.policy.DbAccessPolicyConfig;
import io.cloudbeaver.service.security.CBEmbeddedSecurityController;
import io.cloudbeaver.service.security.db.CBDatabase;
import io.cloudbeaver.test.platform.dbac.KeyLockTestSupport.Pause;
import io.cloudbeaver.test.platform.dbac.KeyLockTestSupport.Reader;
import io.cloudbeaver.test.platform.dbac.KeyLockTestSupport.UserDb;
import io.cloudbeaver.test.platform.dbac.KeyLockTestSupport.Worker;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.jkiss.dbeaver.DBException;
import org.jkiss.dbeaver.model.exec.DBCException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * P4: the user (U) write lock that deactivation, deletion and team deletion take
 * <p>
 * The controller under test is the one the DBAC factory builds, over a real H2 metadata database of
 * its own whose connections the test can stop at a chosen statement or commit. The readers are
 * simulated with the registry's timed read API; the enforcement gate that will hold them is not
 * wired, so nothing here claims a deactivated user is already blocked from writing.
 * <p>
 * PostgreSQL is used only for the X and M of a real connection (UL-6). The controller itself is not
 * exercised on a PostgreSQL metadata database - that integration is NOT VERIFIED; the subject
 * identity it relies on is characterized on both engines in {@code LockIdentityCharacterizationTest}.
 */
@Timeout(value = 180, unit = TimeUnit.SECONDS, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
public class UserDeactivationRaceTest {

    private static EnforcementTestSupport.Fixtures fixtures;
    private static UserDb db;

    @BeforeAll
    public static void prepare() throws Exception {
        CEAppStarter.startServerIfNotStarted();
        EnforcementTestSupport.requirePostgres(KeyLockTestSupport.MONITOR);
        fixtures = EnforcementTestSupport.fixtures("p4ul", KeyLockTestSupport.MONITOR);
        db = UserDb.open();
    }

    @AfterAll
    public static void cleanUp() throws Exception {
        try {
            if (db != null) {
                db.close();
            }
        } finally {
            if (fixtures != null) {
                fixtures.afterAll();
            }
        }
    }

    @AfterEach
    public void disarm() throws Exception {
        db.database.armed = false;
        db.hooks().reset();
        fixtures.afterEach();
    }

    private static void disable(@NotNull String userId) throws DBException {
        db.controller.enableUser(userId, false, "dbac-p4-admin", "dbac-p4");
    }

    // ---------------------------------------------------------------- UL

    /**
     * UL-1: deactivations and deletions of one user wait for its readers and for each other, before touching the database
     */
    @Test
    public void ul1SameUserMutationsAreSerialized() throws Exception {
        String publicDisable = db.newUser("ul1-public", true);
        db.arm();
        Worker<Object> worker;
        boolean parked;
        int opened;
        String flagWhileWaiting;
        try (Reader reader = Reader.ofUser(publicDisable)) {
            worker = Worker.start("dbac-ul1-public", () -> {
                disable(publicDisable);
                return null;
            });
            parked = KeyLockTestSupport.awaitParked(worker.thread);
            opened = db.hooks().opened.get();
            flagWhileWaiting = db.activeFlag(publicDisable);
        }
        worker.get("UL-1 public disable");
        Assertions.assertTrue(parked, "UL-1: a deactivation must wait for a reader of the user");
        Assertions.assertEquals(0, opened, "UL-1: the waiting deactivation must not open a metadata connection");
        Assertions.assertEquals("Y", flagWhileWaiting, "UL-1: the user must stay active while the reader holds it");
        Assertions.assertEquals("N", db.activeFlag(publicDisable), "UL-1: the deactivation must then commit");

        String protectedDisable = db.newUser("ul1-protected", true);
        Connection autoCommit = db.database.plain();
        try {
            Worker<Object> viaConnection;
            boolean protectedParked;
            String protectedFlag;
            try (Reader reader = Reader.ofUser(protectedDisable)) {
                viaConnection = Worker.start("dbac-ul1-protected", () -> {
                    db.enableUserOn(autoCommit, protectedDisable, false);
                    return null;
                });
                protectedParked = KeyLockTestSupport.awaitParked(viaConnection.thread);
                protectedFlag = db.activeFlag(protectedDisable);
            }
            viaConnection.get("UL-1 protected disable");
            Assertions.assertTrue(protectedParked, "UL-1: the protected auto-commit deactivation must wait for a reader too");
            Assertions.assertEquals("Y", protectedFlag, "UL-1: the user must stay active while the reader holds it");
            Assertions.assertEquals("N", db.activeFlag(protectedDisable), "UL-1: the protected deactivation must then commit");
        } finally {
            autoCommit.close();
        }

        String deleted = db.newUser("ul1-delete", true);
        Worker<Object> deletion;
        boolean deletionParked;
        int subjectsWhileWaiting;
        try (Reader reader = Reader.ofUser(deleted)) {
            deletion = Worker.start("dbac-ul1-delete", () -> {
                db.controller.deleteUser(deleted);
                return null;
            });
            deletionParked = KeyLockTestSupport.awaitParked(deletion.thread);
            subjectsWhileWaiting = db.count("CB_AUTH_SUBJECT", "SUBJECT_ID", deleted);
        }
        deletion.get("UL-1 delete");
        Assertions.assertTrue(deletionParked, "UL-1: a deletion must wait for a reader of the user");
        Assertions.assertEquals(1, subjectsWhileWaiting, "UL-1: the user must exist while the reader holds it");
        Assertions.assertEquals(0, db.count("CB_USER", "USER_ID", deleted), "UL-1: the deletion must then commit");

        String both = db.newUser("ul1-both", true);
        db.hooks().reset();
        Pause pause = new Pause();
        db.hooks().after = sql -> {
            if (KeyLockTestSupport.normalized(sql).startsWith("UPDATE CB_USER SET IS_ACTIVE")) {
                pause.hit();
            }
        };
        Worker<Object> first = Worker.start("dbac-ul1-first", () -> {
            disable(both);
            return null;
        });
        Worker<Object> second = null;
        boolean secondParked;
        long tokenDeletesWhileWaiting;
        try {
            pause.awaitReached("UL-1 the first deactivation's update");
            second = Worker.start("dbac-ul1-second", () -> {
                db.controller.deleteUser(both);
                return null;
            });
            secondParked = KeyLockTestSupport.awaitParked(second.thread);
            tokenDeletesWhileWaiting = db.hooks().count("DELETE FROM CB_AUTH_TOKEN");
        } finally {
            pause.release();
        }
        first.get("UL-1 first");
        second.get("UL-1 second");
        Assertions.assertTrue(secondParked, "UL-1: a deletion must wait for a deactivation of the same user");
        Assertions.assertEquals(0, tokenDeletesWhileWaiting, "UL-1: the waiting deletion must not have started");
        Assertions.assertEquals(0, db.count("CB_USER", "USER_ID", both), "UL-1: the deletion must then run");
    }

    /**
     * UL-2: a reader of one user does not hold back the deactivation of another
     */
    @Test
    public void ul2DifferentUsersProceedIndependently() throws Exception {
        String held = db.newUser("ul2-held", true);
        String other = db.newUser("ul2-other", true);
        try (Reader reader = Reader.ofUser(held)) {
            Worker.start("dbac-ul2-other", () -> {
                disable(other);
                return null;
            }).get("UL-2 another user's deactivation while the first is held");
        }
        Assertions.assertEquals("N", db.activeFlag(other), "UL-2: another user's deactivation must complete");
        Assertions.assertEquals("Y", db.activeFlag(held), "UL-2: the held user is untouched");
    }

    /**
     * UL-3: activation takes no lock - public or protected, even with a reader and a queued deactivation
     */
    @Test
    public void ul3ActivationTakesNoLock() throws Exception {
        String user = db.newUser("ul3", false);
        Worker<Object> queued;
        boolean queuedParked;
        Worker<Object> publicEnable;
        String flagAfterPublic;
        Worker<Object> protectedEnable;
        try (Reader reader = Reader.ofUser(user)) {
            queued = Worker.start("dbac-ul3-queued-disable", () -> {
                disable(user);
                return null;
            });
            queuedParked = KeyLockTestSupport.awaitParked(queued.thread);
            publicEnable = Worker.start("dbac-ul3-public-enable", () -> {
                db.controller.enableUser(user, true, null, null);
                return null;
            });
            Assertions.assertTrue(publicEnable.awaitDone(), "UL-3: a public activation must not wait for the user lock");
            flagAfterPublic = db.activeFlag(user);
            try (Connection inTransaction = db.database.plain()) {
                inTransaction.setAutoCommit(false);
                protectedEnable = Worker.start("dbac-ul3-protected-enable", () -> {
                    db.enableUserOn(inTransaction, user, true);
                    return null;
                });
                Assertions.assertTrue(protectedEnable.awaitDone(), "UL-3: a protected activation must not wait for the user lock");
                inTransaction.commit();
                inTransaction.setAutoCommit(true);
            }
        }
        queued.get("UL-3 queued deactivation");
        Assertions.assertTrue(queuedParked, "UL-3: the deactivation must queue behind the reader");
        Assertions.assertNull(publicEnable.error, "UL-3: the public activation must not fail");
        Assertions.assertEquals("Y", flagAfterPublic, "UL-3: the public activation must commit while the reader holds the user");
        Assertions.assertNull(protectedEnable.error, "UL-3: a protected activation inside a transaction is allowed");
        Assertions.assertEquals("N", db.activeFlag(user), "UL-3: the queued deactivation runs once the reader is gone");
    }

    /**
     * UL-4: the user lock is still held when the change has become visible, until the call returns
     */
    @Test
    public void ul4TheUserLockIsHeldUntilTheChangeIsVisible() throws Exception {
        String disabled = db.newUser("ul4-disable", true);
        db.arm();
        Pause afterUpdate = new Pause();
        db.hooks().after = sql -> {
            if (KeyLockTestSupport.normalized(sql).startsWith("UPDATE CB_USER SET IS_ACTIVE")) {
                afterUpdate.hit();
            }
        };
        Worker<Object> disable = Worker.start("dbac-ul4-disable", () -> {
            disable(disabled);
            return null;
        });
        String flag;
        boolean readable;
        try {
            afterUpdate.awaitReached("UL-4 the deactivation's update");
            flag = db.activeFlag(disabled);
            readable = KeyLockTestSupport.userReadableElsewhere(disabled);
        } finally {
            afterUpdate.release();
        }
        disable.get("UL-4 deactivation");
        Assertions.assertEquals("N", flag, "FIXTURE UL-4: the auto-committed deactivation was not visible");
        Assertions.assertFalse(readable, "UL-4: a reader must not get the user while the committed deactivation has not returned");
        Assertions.assertTrue(KeyLockTestSupport.userReadableElsewhere(disabled), "UL-4: a reader gets the user after it returned");

        checkHeldAfterCommit("delete", db.newUser("ul4-delete", true), id -> db.controller.deleteUser(id),
            id -> db.count("CB_USER", "USER_ID", id) == 0);
        checkHeldAfterCommit("deleteTeam", db.newTeam("ul4"), id -> db.controller.deleteTeam(id, false),
            id -> db.count("CB_TEAM", "TEAM_ID", id) == 0);
    }

    /** A user-state call on one subject id */
    @FunctionalInterface
    private interface SubjectCall {
        void run(@NotNull String subjectId) throws Exception;
    }

    /** A check of whether a change is visible */
    @FunctionalInterface
    private interface Visible {
        boolean check(@NotNull String subjectId) throws Exception;
    }

    private static void checkHeldAfterCommit(
        @NotNull String label,
        @NotNull String subjectId,
        @NotNull SubjectCall call,
        @NotNull Visible visible
    ) throws Exception {
        db.hooks().reset();
        db.arm();
        Pause afterCommit = new Pause();
        db.hooks().afterCommit = afterCommit::hit;
        Worker<Object> worker = Worker.start("dbac-ul4-" + label, () -> {
            call.run(subjectId);
            return null;
        });
        boolean changed;
        boolean readable;
        try {
            afterCommit.awaitReached("UL-4 " + label + " commit");
            changed = visible.check(subjectId);
            readable = KeyLockTestSupport.userReadableElsewhere(subjectId);
        } finally {
            afterCommit.release();
        }
        worker.get("UL-4 " + label);
        Assertions.assertTrue(changed, "FIXTURE UL-4: the committed " + label + " was not visible");
        Assertions.assertFalse(readable, "UL-4: a reader must not get the subject while the committed " + label + " has not returned");
        Assertions.assertTrue(KeyLockTestSupport.userReadableElsewhere(subjectId), "UL-4: a reader gets the subject after " + label);
    }

    /** How UL-5 makes a statement fail */
    private enum Failure {
        SQL,
        RUNTIME,
        ERROR
    }

    /**
     * UL-5: every way out releases the user lock and restores the interrupt
     */
    @Test
    public void ul5EveryFailureReleasesTheUserLockAndRestoresTheInterrupt() throws Exception {
        for (Failure failure : Failure.values()) {
            final String label = "UL-5 [disable " + failure + "]";
            final String user = db.newUser("ul5-" + failure.ordinal(), true);
            db.hooks().reset();
            db.arm();
            db.hooks().before = failing("UPDATE CB_USER SET IS_ACTIVE", failure);
            Worker<Object> worker = Worker.start("dbac-ul5-disable", () -> {
                Thread.currentThread().interrupt();
                disable(user);
                return null;
            });
            Assertions.assertTrue(worker.awaitDone(), label + ": the deactivation did not finish");
            Class<? extends Throwable> expected = switch (failure) {
                case SQL -> DBCException.class;
                case RUNTIME -> IllegalStateException.class;
                case ERROR -> LifecycleTestSupport.InjectedError.class;
            };
            Assertions.assertInstanceOf(expected, worker.error, label + ": the failure must reach the caller");
            Assertions.assertEquals("Y", db.activeFlag(user), label + ": the failed deactivation must not be stored");
            assertReleasedAndRestored(label, user, worker);
        }

        final String label = "UL-5 [delete SQL]";
        final String user = db.newUser("ul5-delete", true);
        db.hooks().reset();
        db.arm();
        db.hooks().before = failing("DELETE FROM CB_USER", Failure.SQL);
        Worker<Object> worker = Worker.start("dbac-ul5-delete", () -> {
            Thread.currentThread().interrupt();
            db.controller.deleteUser(user);
            return null;
        });
        Assertions.assertTrue(worker.awaitDone(), label + ": the deletion did not finish");
        Assertions.assertInstanceOf(DBCException.class, worker.error, label + ": the failure must reach the caller");
        // upstream JDBCTransaction.close() restores auto-commit without a rollback; what it left is recorded, not judged
        System.out.println("[DBAC P4] " + label + " state after the failed upstream deletion: " + db.snapshot(user));
        assertReleasedAndRestored(label, user, worker);
    }

    @NotNull
    private static KeyLockTestSupport.Hook failing(@NotNull String prefix, @NotNull Failure failure) {
        return sql -> {
            if (KeyLockTestSupport.normalized(sql).startsWith(prefix)) {
                switch (failure) {
                    case SQL -> throw new SQLException("injected user-state failure", "42000");
                    case RUNTIME -> throw new IllegalStateException("injected user-state failure");
                    default -> throw new LifecycleTestSupport.InjectedError("user-state");
                }
            }
        };
    }

    private static void assertReleasedAndRestored(@NotNull String label, @NotNull String user, @NotNull Worker<?> worker)
            throws InterruptedException {
        Assertions.assertFalse(db.hooks().statements().isEmpty(), "FIXTURE " + label + ": no statement was run");
        Assertions.assertFalse(db.hooks().anyInterrupted(),
            label + ": the interrupt set before the call must be cleared while the change runs");
        Assertions.assertTrue(worker.interruptedOnReturn, label + ": the interrupt must be restored when the call returns");
        Assertions.assertTrue(KeyLockTestSupport.userReadableElsewhere(user), label + ": a reader must get the user afterwards");
        Assertions.assertTrue(KeyLockTestSupport.userWritableElsewhere(user), label + ": a writer must get the user afterwards");
    }

    /**
     * UL-6: deactivation and deletion take neither a grant key's lock nor a connection's X or M
     */
    @Test
    public void ul6UserWritersTakeNoKeyOrConnectionLock() throws Exception {
        String user = db.newUser("ul6", true);
        db.arm();
        Pause pause = new Pause();
        db.hooks().after = sql -> {
            if (KeyLockTestSupport.normalized(sql).startsWith("UPDATE CB_USER SET IS_ACTIVE")) {
                pause.hit();
            }
        };
        Worker<Object> disable = Worker.start("dbac-ul6-disable", () -> {
            disable(user);
            return null;
        });
        boolean keyWritable;
        try {
            pause.awaitReached("UL-6 the deactivation's update");
            keyWritable = KeyLockTestSupport.grantWritableElsewhere(new DbAccessKey(user, "ul6-project", "ul6-connection"));
        } finally {
            pause.release();
        }
        disable.get("UL-6 deactivation");
        Assertions.assertTrue(keyWritable, "UL-6: a deactivation in flight must not hold a grant key of that user");

        db.database.armed = false;
        db.hooks().reset();
        String disabledUnder = db.newUser("ul6-x-m-disable", true);
        String deletedUnder = db.newUser("ul6-x-m-delete", true);
        // closed by fixtures.afterEach()
        EnforcementTestSupport.Target target = fixtures.readOnlyTarget(fixtures.user);
        boolean finished = KeyLockTestSupport.finishesWhileXAndMHeld(target, () -> {
            disable(disabledUnder);
            db.controller.deleteUser(deletedUnder);
            return null;
        });
        Assertions.assertTrue(finished, "UL-6: a deactivation and a deletion must finish while a connection's X and M are held");
        Assertions.assertEquals("N", db.activeFlag(disabledUnder), "UL-6: the deactivation under X and M must commit");
        Assertions.assertEquals(0, db.count("CB_USER", "USER_ID", deletedUnder), "UL-6: the deletion under X and M must commit");
    }

    /**
     * UL-7: an interrupt set before the call, or arriving while it waits, neither skips the change nor is lost
     */
    @Test
    public void ul7AnInterruptDoesNotSkipTheChangeAndIsRestored() throws Exception {
        String before = db.newUser("ul7-before", true);
        db.arm();
        Worker<Object> interrupted = Worker.start("dbac-ul7-before", () -> {
            Thread.currentThread().interrupt();
            disable(before);
            return null;
        });
        interrupted.get("UL-7 pre-interrupted deactivation");
        Assertions.assertEquals("N", db.activeFlag(before), "UL-7: a deactivation called with the interrupt set must still commit");
        assertReleasedAndRestored("UL-7 pre-interrupted", before, interrupted);

        db.hooks().reset();
        String waiting = db.newUser("ul7-waiting", true);
        Worker<Object> disable;
        boolean parked;
        boolean parkedAfterInterrupt;
        try (Reader reader = Reader.ofUser(waiting)) {
            disable = Worker.start("dbac-ul7-waiting", () -> {
                disable(waiting);
                return null;
            });
            parked = KeyLockTestSupport.awaitParked(disable.thread);
            disable.thread.interrupt();
            parkedAfterInterrupt = KeyLockTestSupport.awaitParked(disable.thread);
            Assertions.assertEquals("Y", db.activeFlag(waiting), "UL-7: nothing may change while the reader holds the user");
        }
        disable.get("UL-7 interrupted while waiting");
        Assertions.assertTrue(parked, "UL-7: the deactivation must wait for the reader");
        Assertions.assertTrue(parkedAfterInterrupt, "UL-7: an interrupt must not end the wait");
        Assertions.assertEquals("N", db.activeFlag(waiting), "UL-7: the interrupted deactivation must commit");
        assertReleasedAndRestored("UL-7 interrupted while waiting", waiting, disable);
    }

    /**
     * UL-8: a deactivation behind a reader that holds the user longer than T_k does not fail - it waits and then commits
     */
    @Test
    public void ul8DeactivationOutwaitsTheReaderTimeout() throws Exception {
        Duration readerTimeout = DbAccessPolicyConfig.DEFAULT_KEY_LOCK_TIMEOUT;
        String user = db.newUser("ul8", true);
        Worker<Object> disable;
        boolean parked;
        boolean stillWaiting;
        try (Reader reader = Reader.ofUser(user)) {
            disable = Worker.start("dbac-ul8-disable", () -> {
                disable(user);
                return null;
            });
            parked = KeyLockTestSupport.awaitParked(disable.thread);
            Thread.sleep(readerTimeout.plusSeconds(1).toMillis());
            stillWaiting = !disable.finished() && disable.thread.isAlive();
        }
        disable.get("UL-8");
        Assertions.assertTrue(parked, "UL-8: the deactivation must wait for the reader");
        Assertions.assertTrue(stillWaiting, "UL-8: the deactivation must still be waiting, not failed, after T_k + 1 s");
        Assertions.assertEquals("N", db.activeFlag(user), "UL-8: the deactivation must then commit");
    }

    /**
     * UL-9: a null user or team id is refused before any connection or lock; a blank one is an ordinary value
     */
    @Test
    public void ul9NullIdentityFailsClosedAndBlankIsAnOrdinaryValue() throws Exception {
        db.arm();
        Assertions.assertThrows(DBException.class, () -> db.controller.enableUser(null, false, "dbac-p4-admin", "dbac-p4"),
            "UL-9: a deactivation of no user must be refused");
        Assertions.assertThrows(DBCException.class, () -> db.controller.deleteUser(null), "UL-9: a deletion of no user must be refused");
        Assertions.assertThrows(DBCException.class, () -> db.controller.deleteTeam(null, false),
            "UL-9: a deletion of no team must be refused");
        Assertions.assertThrows(DBCException.class, () -> db.controller.deleteTeam(null, true),
            "UL-9: a forced deletion of no team must be refused");
        try (Connection connection = KeyLockTestSupport.hooked(db.database.plain(), db.hooks())) {
            Assertions.assertThrows(SQLException.class, () -> db.enableUserOn(connection, null, false),
                "UL-9: a protected deactivation of no user must be refused");
        }
        Assertions.assertEquals(0, db.hooks().opened.get(), "UL-9: a null identity must not open a metadata connection");
        Assertions.assertEquals(List.of(), db.hooks().statements(), "UL-9: a null identity must not run a statement");

        db.database.armed = false;
        db.hooks().reset();
        String sentinel = db.newUser("ul9-sentinel", true);
        for (String blank : List.of("", " ")) {
            String label = "UL-9 [blank '" + blank + "']";
            disable(blank);
            db.controller.deleteUser(blank);
            Assertions.assertThrows(DBCException.class, () -> db.controller.deleteTeam(blank, false),
                label + ": the team API must refuse a subject it cannot prove to be a team");
            Assertions.assertEquals("Y", db.activeFlag(sentinel), label + ": a blank id must change no other user");
            Assertions.assertEquals(1, db.count("CB_AUTH_SUBJECT", "SUBJECT_ID", sentinel),
                label + ": a blank id must delete no other user");
            Assertions.assertTrue(KeyLockTestSupport.userReadableElsewhere(blank), label + ": the blank id's lock must be free afterwards");
        }
    }

    /**
     * UL-10: a protected deactivation on a connection inside a transaction is refused before its update
     */
    @Test
    public void ul10ProtectedDeactivationInsideATransactionFailsClosed() throws Exception {
        String user = db.newUser("ul10", true);
        Throwable thrown = null;
        long updates;
        try (Connection connection = KeyLockTestSupport.hooked(db.database.plain(), db.hooks())) {
            connection.setAutoCommit(false);
            try {
                db.enableUserOn(connection, user, false);
            } catch (Throwable e) {
                thrown = e;
            }
            updates = db.hooks().count("UPDATE CB_USER");
            connection.rollback();
            connection.setAutoCommit(true);
        }
        Assertions.assertInstanceOf(SQLException.class, thrown,
            "UL-10: a deactivation whose commit would happen outside the user lock must be refused");
        Assertions.assertEquals(0, updates, "UL-10: the refusal must come before the update");
        Assertions.assertEquals("Y", db.activeFlag(user), "UL-10: the user must be unchanged");
        Assertions.assertTrue(KeyLockTestSupport.userReadableElsewhere(user), "UL-10: the user lock must be free afterwards");
    }

    /**
     * UL-11: a real team is deleted exactly as upstream deletes it, under the subject's lock, taken before the type is read
     */
    @Test
    public void ul11RealTeamDeletionIsUnchanged() throws Exception {
        String empty = db.newTeam("ul11-empty");
        db.controller.deleteTeam(empty, false);
        Assertions.assertEquals(0, db.count("CB_AUTH_SUBJECT", "SUBJECT_ID", empty), "UL-11: an empty team must be deleted");
        Assertions.assertEquals(0, db.count("CB_TEAM", "TEAM_ID", empty), "UL-11: an empty team must be deleted");

        String member = db.newUser("ul11-member", true);
        String withMember = db.newTeam("ul11-member");
        db.assignTeam(member, withMember);
        Assertions.assertThrows(DBCException.class, () -> db.controller.deleteTeam(withMember, false),
            "UL-11: a team with members is refused without force, as upstream refuses it");
        Assertions.assertEquals(1, db.count("CB_TEAM", "TEAM_ID", withMember), "UL-11: the refused team must remain");
        db.controller.deleteTeam(withMember, true);
        Assertions.assertEquals(0, db.count("CB_TEAM", "TEAM_ID", withMember), "UL-11: a forced deletion must delete the team");
        Assertions.assertEquals(0, db.count("CB_USER_TEAM", "TEAM_ID", withMember), "UL-11: and its memberships");
        Assertions.assertEquals("Y", db.activeFlag(member), "UL-11: and leave its members as they were");

        String waited = db.newTeam("ul11-waited");
        db.hooks().reset();
        db.arm();
        Worker<Object> deletion;
        boolean parked;
        int teamsWhileWaiting;
        int openedWhileWaiting;
        long typeReadsWhileWaiting;
        try (Reader reader = Reader.ofUser(waited)) {
            deletion = Worker.start("dbac-ul11-waited", () -> {
                db.controller.deleteTeam(waited, false);
                return null;
            });
            parked = KeyLockTestSupport.awaitParked(deletion.thread);
            teamsWhileWaiting = db.count("CB_TEAM", "TEAM_ID", waited);
            openedWhileWaiting = db.hooks().opened.get();
            typeReadsWhileWaiting = db.hooks().count("SELECT SUBJECT_TYPE");
        }
        deletion.get("UL-11 waited");
        Assertions.assertTrue(parked, "UL-11: a team deletion must wait for a reader of the subject");
        Assertions.assertEquals(1, teamsWhileWaiting, "UL-11: the team must exist while the reader holds it");
        // The type is read under the lock: read before it, a team confirmed then could be deleted and its id
        // taken by a new user while the deletion waits, and the deletion would then cascade to that user.
        Assertions.assertEquals(0, openedWhileWaiting, "UL-11: the waiting team deletion must not open a metadata connection");
        Assertions.assertEquals(0, typeReadsWhileWaiting, "UL-11: the subject type must be read only once the lock is held");
        Assertions.assertEquals(1, db.hooks().count("SELECT SUBJECT_TYPE"),
            "FIXTURE UL-11: the hooks must have seen the deletion's subject type lookup");
        Assertions.assertEquals(0, db.count("CB_TEAM", "TEAM_ID", waited), "UL-11: the team deletion must then run");
    }

    /**
     * UL-12: the team API refuses a user subject, before any DELETE - the user, its session and token and the event queue are unchanged
     */
    @Test
    public void ul12TheTeamApiRefusesAUserSubject() throws Exception {
        db.arm();
        String plain = db.newUser("ul12-plain", true);
        String plainBefore = db.snapshot(plain);
        for (boolean force : new boolean[]{false, true}) {
            Throwable thrown = call(() -> db.controller.deleteTeam(plain, force));
            Assertions.assertInstanceOf(DBCException.class, thrown, "UL-12: deleteTeam(user, force=" + force + ") must be refused");
            Assertions.assertEquals(plainBefore, db.snapshot(plain), "UL-12: the user must be unchanged, force=" + force);
        }

        String withSession = db.newUser("ul12-session", true);
        db.insertSessionAndToken(withSession);
        String sessionBefore = db.snapshot(withSession);
        List<?> pool = KeyLockTestSupport.eventPool();
        for (boolean force : new boolean[]{false, true}) {
            Worker<Object> deletion;
            boolean finishedWhileQueueHeld;
            List<Object> queueBefore;
            List<Object> queueAfter;
            synchronized (pool) {
                queueBefore = new ArrayList<>(pool);
                deletion = Worker.start("dbac-ul12-session", () -> {
                    db.controller.deleteTeam(withSession, force);
                    return null;
                });
                finishedWhileQueueHeld = deletion.done.await(10, TimeUnit.SECONDS);
                queueAfter = new ArrayList<>(pool);
            }
            Assertions.assertTrue(deletion.awaitDone(), "UL-12: the refused deletion did not finish");
            Assertions.assertTrue(finishedWhileQueueHeld, "UL-12: the refusal must not try to queue an event, force=" + force);
            Assertions.assertInstanceOf(DBCException.class, deletion.error, "UL-12: deleteTeam(user with a session) must be refused");
            Assertions.assertEquals(queueBefore, queueAfter, "UL-12: no event may be queued, force=" + force);
            Assertions.assertEquals(sessionBefore, db.snapshot(withSession), "UL-12: user, session and token must be unchanged");
        }

        String missing = "dbac-p4-missing-" + Long.toHexString(System.nanoTime());
        Assertions.assertInstanceOf(DBCException.class, call(() -> db.controller.deleteTeam(missing, false)),
            "UL-12: a subject that does not exist is not proven to be a team and must be refused");
        String unknown = "dbac-p4-unknown-" + Long.toHexString(System.nanoTime());
        db.insertRawSubject(unknown, "X");
        Assertions.assertInstanceOf(DBCException.class, call(() -> db.controller.deleteTeam(unknown, true)),
            "UL-12: a subject of an unknown type must be refused");
        Assertions.assertEquals(1, db.count("CB_AUTH_SUBJECT", "SUBJECT_ID", unknown), "UL-12: the unknown subject must remain");
        String team = db.newTeam("ul12-lookup");
        db.hooks().before = sql -> {
            if (KeyLockTestSupport.normalized(sql).startsWith("SELECT SUBJECT_TYPE FROM CB_AUTH_SUBJECT")) {
                throw new SQLException("injected subject lookup failure", "08006");
            }
        };
        Assertions.assertInstanceOf(DBCException.class, call(() -> db.controller.deleteTeam(team, true)),
            "UL-12: a team whose type cannot be read must not be deleted");
        Assertions.assertEquals(1, db.count("CB_TEAM", "TEAM_ID", team), "UL-12: the team must remain when its type could not be read");
        Assertions.assertEquals(0, db.hooks().count("DELETE"),
            "UL-12: no refused team deletion may run a DELETE, got " + db.hooks().statements());
    }

    /** A call whose failure is the result */
    @FunctionalInterface
    private interface Action {
        void run() throws Throwable;
    }

    @Nullable
    private static Throwable call(@NotNull Action action) {
        try {
            action.run();
            return null;
        } catch (Throwable e) {
            return e;
        }
    }

    // ---------------------------------------------------------------- CF

    /**
     * CF-1: every controller production builds is the DBAC controller
     */
    @Test
    public void cf1EveryProductionControllerIsTheDbacController() throws Exception {
        CBApplicationCE application = (CBApplicationCE) CEAppStarter.getTestApp();
        Map<String, Object> controllers = new TreeMap<>();
        controllers.put("per-request", application.createSecurityController(fixtures.admin.session()));
        controllers.put("admin", application.getAdminSecurityController(fixtures.admin.session()));
        controllers.put("global", application.getSecurityController());
        controllers.put("database admin", adminControllerOf(EnforcementTestSupport.metadata()));
        controllers.put("isolated factory", db.controller);
        for (Map.Entry<String, Object> entry : controllers.entrySet()) {
            Assertions.assertInstanceOf(DbacEmbeddedSecurityController.class, entry.getValue(),
                "CF-1: the " + entry.getKey() + " controller must be the DBAC controller");
        }
    }

    @Nullable
    private static Object adminControllerOf(@NotNull CBDatabase database) throws Exception {
        Field field = CBDatabase.class.getDeclaredField("adminSecurityController");
        field.setAccessible(true);
        return field.get(database);
    }

    /** The public user-state and deletion methods of the embedded controller, and whether DBAC must wrap each */
    private static final Map<String, Boolean> USER_STATE_METHODS = Map.ofEntries(
        Map.entry("void enableUser(java.lang.String,boolean,java.lang.String,java.lang.String)", true),
        Map.entry("void deleteUser(java.lang.String)", true),
        Map.entry("void deleteTeam(java.lang.String,boolean)", true),
        // re-activates only; activation needs no lock
        Map.entry("java.util.List importUsers(org.jkiss.dbeaver.model.security.user.SMUserImportList)", false),
        // team membership, credentials, object permissions and objects - not whether a user exists or is active
        Map.entry("void deleteUserTeams(java.lang.String,java.lang.String[])", false),
        Map.entry("void deleteUserCredentials(java.lang.String,java.lang.String)", false),
        Map.entry("void deleteObject(java.lang.String,java.lang.String,org.jkiss.dbeaver.model.auth.SMObjectType)", false),
        Map.entry("void deleteObjectPermissions(java.util.Set,org.jkiss.dbeaver.model.auth.SMObjectType,java.util.Set,java.util.Set)",
            false),
        Map.entry("void deleteAllObjectPermissions(java.lang.String,org.jkiss.dbeaver.model.auth.SMObjectType)", false),
        Map.entry("void deleteAllSubjectObjectPermissions(java.lang.String,org.jkiss.dbeaver.model.auth.SMObjectType)", false),
        // a read
        Map.entry("java.util.List findActiveUserSessions(java.lang.String,java.time.LocalDateTime,boolean)", false));

    private static final Pattern USER_STATE_NAME = Pattern.compile("(?i).*(delete|enable|disable|import|active).*");

    /**
     * CF-2: the public methods that can change whether a subject exists or is active are known, and DBAC wraps the ones that do
     */
    @Test
    public void cf2UserStateAndSubjectDeletionMethodsAreKnown() throws Exception {
        Set<String> actual = Arrays.stream(CBEmbeddedSecurityController.class.getMethods())
            .filter(method -> USER_STATE_NAME.matcher(method.getName()).matches())
            .map(UserDeactivationRaceTest::signature)
            .collect(Collectors.toCollection(TreeSet::new));
        Assertions.assertEquals(new TreeSet<>(USER_STATE_METHODS.keySet()), actual,
            "CF-2: the embedded controller's user-state methods changed; review them against the DBAC user lock");

        Set<String> wrapped = Arrays.stream(DbacEmbeddedSecurityController.class.getDeclaredMethods())
            .filter(method -> !method.isSynthetic())
            .map(UserDeactivationRaceTest::signature)
            .collect(Collectors.toCollection(TreeSet::new));
        for (Map.Entry<String, Boolean> entry : USER_STATE_METHODS.entrySet()) {
            if (entry.getValue()) {
                Assertions.assertTrue(wrapped.contains(entry.getKey()), "CF-2: DBAC must override " + entry.getKey());
            }
        }
        Method protectedEnable = CBEmbeddedSecurityController.class.getDeclaredMethod(
            "enableUser", Connection.class, String.class, boolean.class, String.class, String.class);
        Assertions.assertTrue(wrapped.contains(signature(protectedEnable)), "CF-2: DBAC must override the protected enableUser");
    }

    @NotNull
    private static String signature(@NotNull Method method) {
        return method.getReturnType().getTypeName() + " " + method.getName() + "("
            + Arrays.stream(method.getParameterTypes()).map(Class::getTypeName).collect(Collectors.joining(",")) + ")";
    }
}
