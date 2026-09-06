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
package io.cloudbeaver.service.dbac.tempwrite;

import org.jkiss.code.NotNull;
import org.jkiss.dbeaver.Log;

import java.sql.Connection;
import java.sql.SQLException;

/**
 * A metadata transaction that cannot commit a half-written state, even when the rollback fails
 * <p>
 * The platform's {@code JDBCTransaction} is deliberately not used here, and the reason is narrow but
 * decisive: its {@code close()} restores auto-commit unconditionally. JDBC specifies that switching a
 * connection with a pending transaction into auto-commit mode <b>commits</b> that work. So on the one
 * path that matters most - a write succeeded, the next statement failed, and the rollback failed too -
 * that class stores exactly the partial state the transaction existed to prevent. Nothing about the
 * platform is wrong; it simply has no notion of a transaction whose rollback did not work.
 * <p>
 * <b>Poisoned means poisoned.</b> Once a rollback has failed this object never touches the connection
 * again except to try to sever it. In particular it does not restore auto-commit, does not retry the
 * rollback, and does not let the caller treat the failure as ordinary contention. The failure is
 * terminal and is reported: {@link #rollbackRecording} attaches it to the exception the caller is
 * already throwing, so it cannot be lost in a log.
 * <p>
 * <b>Every exit rolls back or commits.</b> A caller that returns without doing either gets a
 * rollback from {@link #close()}, because restoring auto-commit on a transaction nobody decided about
 * would commit it. The two coordinator paths decide on every branch, so nothing reaches that today;
 * it is there so the guarantee belongs to this class rather than to its callers' discipline.
 * <p>
 * <b>Poisoned is set before the attempt, not after it.</b> Both rollback methods mark the transaction
 * poisoned first and clear the mark only once {@code rollback()} has returned normally. Deciding it in
 * a catch clause instead makes the guarantee depend on which exception class the driver happened to
 * throw - an unchecked driver failure or an {@code Error} would slip past a {@code catch (SQLException)}
 * and leave the transaction looking healthy, and {@code close()} would then restore auto-commit and
 * commit the partial state. This ordering is the reason the guarantee holds for every failure route.
 * <p>
 * <b>How the connection is discarded.</b> Measured against the pool this fork actually uses -
 * {@code CBDatabase} builds a DBCP2 {@code PoolingDataSource} over a {@code GenericObjectPool} of
 * {@code PoolableConnection} - a poisoned connection is destroyed rather than reused, by two
 * independent routes:
 * <ul>
 *   <li>{@code PoolableConnectionFactory.rollbackOnReturn} defaults to {@code true}, so returning a
 *       connection whose auto-commit is still {@code false} makes {@code passivateObject} attempt the
 *       rollback again. It fails again, and {@code GenericObjectPool.returnObject} responds to a
 *       failed passivation by calling {@code destroy}. Leaving auto-commit alone is therefore not
 *       only safe, it is what triggers the disposal. One condition to be honest about: that rollback
 *       is guarded by {@code !conn.isReadOnly()}, and {@code autoCommitOnReturn} also defaults to
 *       {@code true}, so on a connection somebody had marked read-only this route would skip the
 *       rollback and reach {@code setAutoCommit(true)} instead. {@code CBDatabase} never marks the
 *       metadata connection read-only - checked, not assumed - and the second route below does not
 *       depend on that.</li>
 *   <li>{@link #close()} additionally attempts {@link Connection#abort}, which severs the physical
 *       connection where the driver supports it. {@code PoolableConnection.close()} then sees a
 *       closed delegate and calls {@code invalidateObject} instead of returning it to the pool.</li>
 * </ul>
 * Neither route needs a change to the platform or to the pool configuration. {@code abort} is
 * best-effort on purpose: a driver that does not implement it changes nothing, because the first
 * route already covers the case.
 * <p>
 * <b>One place this class must not be used.</b> While {@code CBDatabase} is initialising, its
 * {@code openConnection()} hands out a shared connection whose {@code close()} is a no-op, so a
 * poisoned transaction there would sever the connection the startup itself is using rather than
 * discard a pooled one. No caller does this today - nothing in production calls the coordinator yet -
 * and any future one must take its connection from the pool, after initialisation.
 * <p>
 * Public only so the test bundle can drive the exits the coordinator never takes - a guarantee that
 * cannot be tested directly is a guarantee nobody will notice losing. The package is exported with
 * {@code x-friends:="io.cloudbeaver.test.platform"}, which is a build-time restriction rather than a
 * runtime one: {@code io.cloudbeaver.server.ce} does {@code Require-Bundle} this bundle, so at
 * runtime the class is reachable. What limits the damage is the surface, not the manifest - the only
 * public members are the constructor and {@link #close()}, so the worst an unintended caller can do
 * is open an empty transaction and close it again.
 * <p>
 * <b>What this class does not cover.</b> Once {@link #close()} has run the connection is either
 * severed or back in auto-commit mode, so anything written through it afterwards commits immediately.
 * Nothing here protects a connection past the one transaction it was given.
 */
public final class MetadataTransaction implements AutoCloseable {

    private static final Log log = Log.getLog(MetadataTransaction.class);

    private final Connection connection;
    private final boolean restoreAutoCommit;

    private boolean committed;
    private boolean rolledBack;
    private boolean poisoned;

    /**
     * Takes over an existing connection for the duration of one transaction
     * <p>
     * Public for the same narrow reason the class is: the test bundle has to be able to construct one
     * and then abandon it. {@link #commit()} and the rollback methods stay package-private, so a
     * caller outside this package can start a transaction and can only end it through
     * {@link #close()} - which is exactly the exit being tested.
     */
    public MetadataTransaction(@NotNull Connection connection) throws SQLException {
        this.connection = connection;
        this.restoreAutoCommit = connection.getAutoCommit();
        if (restoreAutoCommit) {
            connection.setAutoCommit(false);
        }
    }

    void commit() throws SQLException {
        connection.commit();
        committed = true;
    }

    /**
     * Rolls back, and turns a failure into a thrown exception rather than a log line
     * <p>
     * Used on the paths that decide to abandon a transaction while nothing has gone wrong yet - a
     * superseded revision, a lost compare-and-set. If the rollback fails there, the failure becomes
     * the exception the caller sees, which is correct: it is the more serious of the two facts.
     *
     * @throws SQLException if the rollback fails, after marking this transaction poisoned. An
     *     unchecked failure or an {@code Error} propagates instead, and leaves it poisoned just the
     *     same - the state is set before the attempt, not decided by which class was thrown.
     */
    void rollback() throws SQLException {
        if (committed || rolledBack || poisoned) {
            // Returns quietly rather than reporting, unlike rollbackRecording. The asymmetry is
            // deliberate: this method is called where nothing has gone wrong yet, so "already
            // finished" is not news. A caller that needs to know whether the transaction is poisoned
            // has to use rollbackRecording, which says so.
            return;
        }
        // Poisoned first, cleared only on success. Deciding this in a catch clause made the
        // invariant depend on which exception class the driver picked: an unchecked driver failure or
        // an Error left the transaction unpoisoned, and close() then restored auto-commit, which per
        // the JDBC spec commits the very work the rollback was trying to undo.
        poisoned = true;
        connection.rollback();
        poisoned = false;
        rolledBack = true;
    }

    /**
     * Rolls back while a failure is already being reported, keeping both facts visible
     * <p>
     * A rollback that fails is attached to {@code cause} with {@code addSuppressed}, so the caller
     * gets the original failure <i>and</i> the knowledge that the transaction could not be undone.
     * Returning {@code false} tells the caller the failure is terminal: it must not be retried as
     * contention, because a poisoned connection cannot be reasoned about any further.
     *
     * @param cause the failure already on its way to the caller
     * @return {@code true} when the transaction is cleanly rolled back or was already finished
     */
    boolean rollbackRecording(@NotNull Throwable cause) {
        if (committed || rolledBack) {
            return true;
        }
        if (poisoned) {
            return false;
        }
        // Poisoned first for the same reason as in rollback(): every way the rollback can fail has
        // to reach the same terminal state, not only SQLException. Error is caught rather than left
        // to propagate so that the caller still receives the original failure, with this one attached.
        poisoned = true;
        try {
            connection.rollback();
        } catch (SQLException | RuntimeException | Error rollbackFailure) {
            cause.addSuppressed(rollbackFailure);
            log.error("A TEMP_WRITE transaction could not be rolled back; the connection is discarded",
                rollbackFailure);
            return false;
        }
        poisoned = false;
        rolledBack = true;
        return true;
    }

    @Override
    public void close() {
        if (!committed && !rolledBack && !poisoned) {
            // A caller that leaves without committing or rolling back has decided nothing, and the
            // only safe reading of "nothing" is "do not keep it". Restoring auto-commit here would
            // commit it instead - the exact JDBCTransaction behaviour this class exists to avoid, so
            // the guarantee has to cover a caller that forgot as well as one that failed. Nothing in
            // this bundle reaches here today: both coordinator paths decide on every branch. It is
            // written for the callers that come later.
            rollbackUnfinished();
        }
        if (poisoned) {
            // Deliberately no setAutoCommit(true): that would commit the work the failed rollback
            // left pending. Severing the connection instead, and otherwise leaving auto-commit off so
            // the pool retries the rollback and destroys the connection when it fails again.
            abortQuietly();
            return;
        }
        if (restoreAutoCommit) {
            try {
                connection.setAutoCommit(true);
            } catch (SQLException e) {
                log.error("Could not restore auto-commit after a TEMP_WRITE transaction", e);
            }
        }
    }

    /**
     * Rolls back a transaction nobody finished, and poisons it if that cannot be done
     * <p>
     * {@code close()} cannot throw, so the failure is logged at error rather than propagated - but it
     * still reaches the terminal state, which is what decides whether the connection survives.
     */
    private void rollbackUnfinished() {
        poisoned = true;
        try {
            connection.rollback();
            poisoned = false;
            rolledBack = true;
        } catch (SQLException | RuntimeException | Error e) {
            log.error("An unfinished TEMP_WRITE transaction could not be rolled back on close; "
                + "the connection is discarded", e);
        }
    }

    private void abortQuietly() {
        try {
            connection.abort(Runnable::run);
        } catch (SQLException | RuntimeException e) {
            // Best effort. A driver without abort support leaves the pool's own rollback-on-return to
            // discard the connection, which is the route this class actually relies on.
            log.debug("Could not abort a poisoned TEMP_WRITE connection: " + e.getMessage());
        }
    }
}
