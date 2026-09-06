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

import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;

/**
 * An instant from the metadata database clock
 * <p>
 * Schema version 2 declares every DBAC time column as {@code TIMESTAMP WITH TIME ZONE}, so a stored
 * value is an absolute instant rather than a wall-clock reading. This type is therefore an ordinary
 * {@link Instant} with no caveats: it can be compared against any other instant, including one from
 * another node or from {@code Instant.now()}, and it means the same thing whatever time zone the
 * reading or writing session used.
 * <p>
 * That was not true at version 1, which used naive {@code TIMESTAMP}. There the value depended on the
 * session's time zone - the PostgreSQL driver takes that from the client JVM - so two nodes in
 * different zones stored and compared different values for the same moment, and a grant expired
 * whenever the reading node thought it did. The migration exists to remove that, and this type no
 * longer carries the qualification it used to.
 * <p>
 * Bound to {@link ZoneOffset#UTC} when handed to JDBC, purely so the wire representation is stable
 * and readable in a log. The offset carries no meaning of its own: the column stores an instant, and
 * reading it back at any offset yields the same instant.
 */
public record MetadataDbTime(@NotNull Instant instant) {

    /**
     * Wraps an instant read from, or about to be written to, a zoned column
     */
    @NotNull
    public static MetadataDbTime of(@NotNull Instant instant) {
        return new MetadataDbTime(instant);
    }

    /**
     * Wraps a value as JDBC returned it from a {@code TIMESTAMP WITH TIME ZONE} column
     */
    @NotNull
    public static MetadataDbTime ofStored(@NotNull OffsetDateTime stored) {
        return new MetadataDbTime(stored.toInstant());
    }

    /**
     * This instant in the form JDBC binds to a zoned column
     */
    @NotNull
    public OffsetDateTime stored() {
        return instant.atOffset(ZoneOffset.UTC);
    }

    /**
     * Returns this reading advanced by a duration
     * <p>
     * Used to compute {@code EXPIRES_AT}. The arithmetic runs in Java on a value that came from the
     * database, so the application clock never becomes the authority for when a grant ends.
     *
     * @param duration how far ahead of this reading the result should be
     */
    @NotNull
    public MetadataDbTime plus(@NotNull Duration duration) {
        return new MetadataDbTime(instant.plus(duration));
    }
}
