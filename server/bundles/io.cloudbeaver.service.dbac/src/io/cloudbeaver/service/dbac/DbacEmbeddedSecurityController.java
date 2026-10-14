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
package io.cloudbeaver.service.dbac;

import io.cloudbeaver.model.app.ServletAuthApplication;
import io.cloudbeaver.model.config.SMControllerConfiguration;
import io.cloudbeaver.service.dbac.db.DbacCBDatabase;
import io.cloudbeaver.service.dbac.db.DbacSchemaConstants;
import io.cloudbeaver.service.dbac.policy.DbAccessPolicyConfig;
import io.cloudbeaver.service.dbac.policy.MetadataBudget;
import io.cloudbeaver.service.dbac.policy.MetadataLease;
import io.cloudbeaver.service.dbac.policy.MetadataOutcome;
import io.cloudbeaver.service.dbac.policy.MetadataPurpose;
import io.cloudbeaver.service.dbac.policy.MetadataQuery;
import io.cloudbeaver.service.dbac.policy.MetadataRows;
import io.cloudbeaver.service.dbac.policy.MetadataUnavailableException;
import io.cloudbeaver.service.dbac.policy.enforcement.EnforcementKeyLocks;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteGrantRepository;
import io.cloudbeaver.service.security.CBEmbeddedSecurityController;
import io.cloudbeaver.service.security.db.CBDatabase;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.jkiss.dbeaver.DBException;
import org.jkiss.dbeaver.Log;
import org.jkiss.dbeaver.model.auth.SMCredentialsProvider;
import org.jkiss.dbeaver.model.exec.DBCException;
import org.jkiss.dbeaver.model.security.SMSubjectType;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.UUID;

/**
 * The embedded security controller with the DBAC user lock around every change that takes a user away
 * <p>
 * Deactivation, deletion and team deletion take the user's write lock ({@code U}) from
 * {@link EnforcementKeyLocks} before the upstream method runs and keep it until it has returned, so the
 * change commits while no enforcement point holds that user's read lock, and none can authorize against
 * the old state afterwards. The whole upstream call is inside the lock because its commit is inside it:
 * the auto-committed {@code UPDATE} of {@code enableUser}, the transaction of {@code deleteUser} - there
 * is no hook between their statements and their commit. Activation takes no lock: it only makes a user
 * active, and a reader that saw the user inactive denied, which was right at the time (design §4.5).
 * <p>
 * <b>The team API cannot delete a user.</b> Upstream {@code deleteTeam} deletes the subject row without
 * looking at its type, and a user's row cascades from it - so a user id passed as a team id deleted the
 * user without its token cleanup or event. Under the subject's lock, this controller reads the subject's
 * type and lets the deletion through only when it is a team; a user, a subject that does not exist, one
 * of an unknown type and one whose type cannot be read are refused before anything is deleted. A
 * confirmed team cannot turn into a user while the lock is held: team deletion takes the same lock, and
 * a user cannot be created under an id that a subject still holds.
 * <p>
 * <b>A user holding a live grant is not deleted.</b> Under the user's write lock, before anything is
 * deleted, the deletion fence confirms on a metadata lease that the user holds no TEMP_WRITE grant that is
 * neither revoked nor expired, and refuses otherwise - also when it cannot find out. With the grant fence
 * in the TEMP_WRITE coordinator, which issues a grant only to an existing user under that user's read lock,
 * this keeps a grant from being inherited by a later user of the same id; schema version 4 revoked every
 * grant written before the two fences existed ({@link DbacSchemaConstants#USER_FENCE_SINCE_VERSION}).
 * <p>
 * <b>No id, no call.</b> A null user or team id is refused before any connection is opened or lock taken.
 * A blank one is an ordinary id, compared as the database compares it.
 * <p>
 * Every controller CloudBeaver builds is one of these: {@link DbacSecurityControllerFactory} creates them
 * in place of the upstream class, including the database's own admin controller.
 */
public final class DbacEmbeddedSecurityController<T extends ServletAuthApplication> extends CBEmbeddedSecurityController<T> {

    /**
     * What a subject id names
     */
    public enum SubjectKind {
        USER,
        TEAM,
        /** No subject has this id */
        MISSING,
        /** A subject whose type is neither the user nor the team code */
        UNKNOWN
    }

    /** The subject-type lookup, with the table prefix still to be substituted by the connection */
    public static final String SUBJECT_TYPE_QUERY = "SELECT SUBJECT_TYPE FROM {table_prefix}CB_AUTH_SUBJECT WHERE SUBJECT_ID=?";

    /**
     * The schema version whose fence era this deletion fence belongs to
     * <p>
     * The deletion fence is half of what {@link DbacSchemaConstants#USER_FENCE_SINCE_VERSION} promises,
     * the grant fence the other half and the version 4 quarantine the base. Referring to the one
     * constant keeps the three from being shipped apart.
     */
    public static final int DELETION_FENCE_SINCE_VERSION = DbacSchemaConstants.USER_FENCE_SINCE_VERSION;

    /** Logged when a subject's type could not be read for a team deletion */
    private static final String EVENT_SUBJECT_TYPE_UNREADABLE = "DBAC_SUBJECT_TYPE_UNREADABLE";
    /** Logged when the deletion fence refuses because the user holds a live grant */
    static final String EVENT_DELETION_FENCE_REFUSED = "DBAC_USER_DELETION_FENCE_REFUSED";
    /** Logged when the deletion fence refuses because it could not find out */
    static final String EVENT_DELETION_FENCE_UNCONFIRMED = "DBAC_USER_DELETION_FENCE_UNCONFIRMED";

    private static final Log log = Log.getLog(DbacEmbeddedSecurityController.class);

    public DbacEmbeddedSecurityController(
        @NotNull T application,
        @NotNull CBDatabase database,
        @NotNull SMCredentialsProvider credentialsProvider,
        @NotNull SMControllerConfiguration smConfig
    ) {
        super(application, database, credentialsProvider, smConfig);
    }

    /**
     * Deactivates under the user's lock; activates without one
     */
    @Override
    public void enableUser(
        @NotNull String userId,
        boolean enabled,
        @Nullable String disabledBy,
        @Nullable String disableReason
    ) throws DBException {
        if (enabled) {
            super.enableUser(userId, true, disabledBy, disableReason);
            return;
        }
        if (userId == null) {
            throw new DBCException("DBAC refuses to deactivate a user without a user id");
        }
        try (EnforcementKeyLocks.Held ignored = EnforcementKeyLocks.global().lockUserForWrite(userId)) {
            super.enableUser(userId, false, disabledBy, disableReason);
        }
    }

    /**
     * The overload that runs the {@code UPDATE}: a deactivation runs it under the user's lock, and only in auto-commit mode
     * <p>
     * In auto-commit mode the {@code UPDATE} commits as it runs, inside the lock. On a connection inside a
     * transaction the commit would come after this method returned and the lock was released, so a
     * deactivation there is refused before the {@code UPDATE}. The public {@code enableUser} reaches this
     * with the lock already held, which the lock allows. An activation is not restricted - upstream
     * {@code importUsers} activates inside its transaction.
     */
    @Override
    protected void enableUser(
        @NotNull Connection dbCon,
        @NotNull String userId,
        boolean enabled,
        @Nullable String disabledBy,
        @Nullable String disableReason
    ) throws SQLException {
        if (enabled) {
            super.enableUser(dbCon, userId, true, disabledBy, disableReason);
            return;
        }
        if (userId == null) {
            throw new SQLException("DBAC refuses to deactivate a user without a user id");
        }
        if (!dbCon.getAutoCommit()) {
            throw new SQLException("DBAC deactivates a user only in auto-commit mode, so that the change commits under the user lock");
        }
        try (EnforcementKeyLocks.Held ignored = EnforcementKeyLocks.global().lockUserForWrite(userId)) {
            super.enableUser(dbCon, userId, false, disabledBy, disableReason);
        }
    }

    /**
     * Deletes under the user's lock, and only a user who holds no live grant
     * <p>
     * <b>The deletion fence.</b> A grant left behind by a deleted user would be inherited by the next user
     * created under the same id. So, holding the user's write lock - which every grant issue needs to read -
     * the deletion first counts the user's grants that are neither revoked nor expired, by the metadata
     * database's own clock, and refuses unless it can confirm there are none. Expired and revoked grants do
     * not hold it: a new incarnation is denied those anyway. A refusal comes before the upstream method, so
     * the user, its sessions and tokens and the event queue are as they were.
     */
    @Override
    public void deleteUser(@Nullable String userId) throws DBCException {
        if (userId == null) {
            throw new DBCException("DBAC refuses to delete a user without a user id");
        }
        try (EnforcementKeyLocks.Held ignored = EnforcementKeyLocks.global().lockUserForWrite(userId)) {
            requireNoLiveGrant(userId);
            super.deleteUser(userId);
        }
    }

    /**
     * The deletion fence: returns only when the user is confirmed to hold no grant that is neither revoked nor expired
     * <p>
     * One statement on a metadata lease of this controller's database, within the whole snapshot budget
     * {@code T_s}, borrow included. Not confirmed - the lease refused, the statement failed or ran out of
     * time, the database is not the DBAC one - is a refusal too.
     */
    private void requireNoLiveGrant(@NotNull String userId) throws DBCException {
        if (!(database instanceof DbacCBDatabase dbac)) {
            throw unconfirmed("NOT_DBAC_DATABASE", null);
        }
        MetadataBudget budget = MetadataBudget.startingNow(System::nanoTime, DbAccessPolicyConfig.defaults().snapshotTimeout());
        long live;
        try (MetadataLease lease = dbac.metadataLeases().open(budget, MetadataPurpose.DELETION_FENCE)) {
            MetadataOutcome<MetadataRows> outcome = lease.query(MetadataQuery.sql(TempWriteGrantRepository.ACTIVE_GRANTS_OF_USER)
                .bindString(userId)
                .columnLong(TempWriteGrantRepository.ACTIVE_GRANTS_COLUMN)
                .expectRows(1, 1)
                .build());
            if (!(outcome instanceof MetadataOutcome.Done<MetadataRows> done)) {
                throw unconfirmed(((MetadataOutcome.Unusable<MetadataRows>) outcome).cause().name(), null);
            }
            live = done.value().row(0).longValue(TempWriteGrantRepository.ACTIVE_GRANTS_COLUMN);
        } catch (MetadataUnavailableException e) {
            throw unconfirmed(e.reason().name(), e.failureClass());
        } catch (RuntimeException e) {
            throw unconfirmed("UNEXPECTED", e.getClass().getName());
        }
        if (live != 0) {
            logDeletionFence(EVENT_DELETION_FENCE_REFUSED, "LIVE_GRANT", null);
            throw new DBCException("DBAC refuses to delete a user who still holds temporary write access; "
                + "revoke it first - the user was not deleted");
        }
    }

    @NotNull
    private static DBCException unconfirmed(@NotNull String detail, @Nullable String failureClass) {
        logDeletionFence(EVENT_DELETION_FENCE_UNCONFIRMED, detail, failureClass);
        return new DBCException("DBAC could not confirm that the user holds no temporary write access; "
            + "the user was not deleted");
    }

    /**
     * Records a deletion refusal by event code, a new correlation id, a fixed detail and at most a class name - never the user id
     */
    private static void logDeletionFence(@NotNull String eventCode, @NotNull String detail, @Nullable String failureClass) {
        try {
            log.error("DBAC user deletion fence refused a deletion [event=" + eventCode
                + " EVENT_ID=" + UUID.randomUUID()
                + " detail=" + detail
                + (failureClass == null ? "" : " exception=" + failureClass) + "]");
        } catch (RuntimeException | Error ignored) {
            // Deliberately nothing: the refusal must not depend on whether it could be logged.
        }
    }

    /**
     * Deletes a team under its subject's lock, and refuses anything it cannot prove to be a team before deleting anything
     */
    @Override
    public void deleteTeam(@Nullable String teamId, boolean force) throws DBCException {
        if (teamId == null) {
            throw new DBCException("DBAC refuses to delete a team without a team id");
        }
        try (EnforcementKeyLocks.Held ignored = EnforcementKeyLocks.global().lockUserForWrite(teamId)) {
            SubjectKind kind;
            try (Connection connection = database.openConnection()) {
                kind = readSubjectKind(connection, teamId);
            } catch (SQLException | RuntimeException e) {
                logUnreadable(e);
                throw new DBCException("DBAC could not confirm that the subject is a team; nothing was deleted");
            }
            if (kind == SubjectKind.USER) {
                throw new DBCException("DBAC refuses to delete a user through the team API; nothing was deleted");
            }
            if (kind != SubjectKind.TEAM) {
                throw new DBCException("DBAC refuses to delete a subject that is not a team; nothing was deleted");
            }
            super.deleteTeam(teamId, force);
        }
    }

    /**
     * What the subject with this id is, read in one statement
     * <p>
     * The id is compared by the database exactly as stored; nothing is folded or trimmed. A type that is
     * neither the user nor the team code is {@link SubjectKind#UNKNOWN}, never guessed.
     */
    @NotNull
    public static SubjectKind readSubjectKind(@NotNull Connection connection, @NotNull String subjectId) throws SQLException {
        try (PreparedStatement dbStat = connection.prepareStatement(SUBJECT_TYPE_QUERY)) {
            dbStat.setString(1, subjectId);
            try (ResultSet dbResult = dbStat.executeQuery()) {
                if (!dbResult.next()) {
                    return SubjectKind.MISSING;
                }
                String type = dbResult.getString(1);
                SubjectKind kind = SMSubjectType.user.getCode().equals(type) ? SubjectKind.USER
                    : SMSubjectType.team.getCode().equals(type) ? SubjectKind.TEAM
                    : SubjectKind.UNKNOWN;
                return dbResult.next() ? SubjectKind.UNKNOWN : kind;
            }
        }
    }

    /**
     * Records the failure by event code, a new correlation id and the exception class - never its message
     */
    private static void logUnreadable(@NotNull Throwable failure) {
        try {
            log.error("DBAC could not read a subject type for a team deletion [event=" + EVENT_SUBJECT_TYPE_UNREADABLE
                + " EVENT_ID=" + UUID.randomUUID() + " exception=" + failure.getClass().getName() + "]");
        } catch (RuntimeException | Error ignored) {
            // Deliberately nothing: the refusal must not depend on whether it could be logged.
        }
    }
}
