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
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;

/**
 * Reads the metadata database clock, the only clock allowed to decide when a grant ends
 * <p>
 * Phase 2 made the metadata database the single time authority, because application nodes disagree
 * with each other and with the database and a grant issued on one node may be checked on another.
 * Nothing here consults {@code Instant.now()}, and a failure never falls back to the local clock.
 * <p>
 * A reading is taken inside the caller's transaction and is meant to be taken once per mutation: the
 * current row, its expiry and its history event then all carry the same value, so a reader cannot
 * find a history event that appears to predate the grant it describes.
 * <p>
 * <b>Why the clock is read from the database at all.</b> Reading the server clock is what makes the
 * value independent of the node that asked. Schema version 2 completes the picture: the columns are
 * {@code TIMESTAMP WITH TIME ZONE}, so what is stored is an instant and no session setting can
 * reinterpret it. At version 1 the columns were naive and the session zone leaked into the stored
 * value, which is the defect the migration removes.
 */
public final class MetadataDbClock {

    /**
     * Reads the database clock as an instant, matching the zoned columns this schema declares.
     * <p>
     * {@code CURRENT_TIMESTAMP} is zoned on both H2 and PostgreSQL, which is exactly what the version 2
     * columns are, so the reading needs no conversion and carries no dependency on the session zone.
     * {@code LOCALTIMESTAMP} is deliberately not used: it renders a wall clock in the session zone, and
     * that was the version 1 defect.
     */
    private static final String CLOCK_QUERY = "SELECT CURRENT_TIMESTAMP";

    private MetadataDbClock() {
        // clock reading only
    }

    /**
     * Takes one reading of the database clock inside the caller's transaction
     * <p>
     * A failure propagates. It must never fall back to the JVM clock: a metadata database that
     * cannot be read is exactly the situation where the local clock is least trustworthy, and a
     * grant whose expiry came from the wrong clock is a grant that outlives its window.
     *
     * @param connection an open metadata connection, already inside the caller's transaction
     * @throws SQLException if the clock cannot be read, or the database returns no row or no value
     */
    @NotNull
    public static MetadataDbTime readNow(@NotNull Connection connection) throws SQLException {
        try (PreparedStatement dbStat = connection.prepareStatement(CLOCK_QUERY);
             ResultSet dbResult = dbStat.executeQuery()
        ) {
            if (!dbResult.next()) {
                throw new SQLException("The metadata database returned no row for its clock");
            }
            OffsetDateTime now = dbResult.getObject(1, OffsetDateTime.class);
            if (now == null) {
                throw new SQLException("The metadata database returned a null clock reading");
            }
            return MetadataDbTime.ofStored(now);
        }
    }
}
