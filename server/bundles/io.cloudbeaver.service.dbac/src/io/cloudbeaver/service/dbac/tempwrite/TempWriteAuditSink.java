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

import java.sql.Connection;
import java.sql.SQLException;

/**
 * Where a committed TEMP_WRITE transition is audited, inside the transaction that made it
 * <p>
 * Phase 2 requires {@code TEMP_WRITE_GRANTED} and {@code TEMP_WRITE_REVOKED} to be recorded in the
 * same metadata transaction as the current-row change, so a state change can never exist without its
 * audit entry. That is not satisfiable from outside {@link TempWriteMutationCoordinator}: the
 * coordinator owns the connection and commits it, so by the time a caller regains control the
 * transaction is closed. This interface is the seam that makes it satisfiable from inside.
 * <p>
 * The audit implementation itself is not part of this slice. What is part of this slice is the
 * guarantee that adding one later needs no change to the transaction boundary: the sink is handed the
 * coordinator's own {@link Connection}, is called after the current row and its history are written
 * and before the commit, and a failure here rolls the whole transition back. Deferring the seam
 * instead would have meant reopening the boundary later, which is the change hardest to review.
 * <p>
 * A sink must not commit, roll back, or change the auto-commit mode of the connection it is given.
 * It writes and returns; the coordinator decides the outcome. It must also not read a clock: the
 * reading that decided the transition is handed to it, so an audit entry always carries the same
 * instant as the row it describes.
 */
@FunctionalInterface
public interface TempWriteAuditSink {

    /**
     * A sink that records nothing
     * <p>
     * The default while no audit layer exists. Not a silent failure: Phase 2's fail-closed audit
     * policy applies to the audit layer once it exists, and a caller that wants auditing supplies a
     * sink rather than relying on this one.
     */
    TempWriteAuditSink NONE = (connection, changeType, grant, actor, dbNow) -> { };

    /**
     * Records one committed transition
     *
     * @param connection the coordinator's connection, already inside the transaction being committed
     * @param changeType which transition is being recorded
     * @param grant the row <b>as it will be committed</b>, carrying the revision being written - for a
     *     revoke this is the revoked form, not the grant being replaced
     * @param actor who caused the transition
     * @param dbNow the single database clock reading this transaction was decided by; a sink must use
     *     it rather than reading a clock of its own, or the audit entry and the row it describes can
     *     disagree, and a JVM clock would reintroduce the session-timezone defect schema version 2
     *     exists to remove
     * @throws SQLException to abort the whole transition; the coordinator rolls back and propagates
     */
    void record(
        @NotNull Connection connection,
        @NotNull TempWriteChangeType changeType,
        @NotNull TempWriteGrant grant,
        @NotNull String actor,
        @NotNull MetadataDbTime dbNow
    ) throws SQLException;
}
