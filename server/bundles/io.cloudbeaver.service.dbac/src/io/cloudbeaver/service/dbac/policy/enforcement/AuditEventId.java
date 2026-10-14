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
package io.cloudbeaver.service.dbac.policy.enforcement;

import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;

import java.util.UUID;

/**
 * The {@code EVENT_ID} of one audit row, and the correlation id its failure is logged under
 * <p>
 * Made only by {@link #next()}, a new random UUID each time. There is no way to make one from a
 * string, so nothing a request carries - a statement, a host name - can reach the row's key column.
 * <p>
 * One id per row. An attempt that is retried is a new attempt with a new id, and a correcting
 * {@code WRITE_DENIED} after a {@code WRITE_ALLOWED} has an id of its own: the two rows are two
 * events, not one event recorded twice.
 */
public final class AuditEventId {

    private final String value;

    private AuditEventId(@NotNull String value) {
        this.value = value;
    }

    /**
     * A new id, never handed out before
     */
    @NotNull
    public static AuditEventId next() {
        return new AuditEventId(UUID.randomUUID().toString());
    }

    /**
     * The id as it is stored in {@code EVENT_ID}
     */
    @NotNull
    public String value() {
        return value;
    }

    @Override
    public boolean equals(@Nullable Object other) {
        return other instanceof AuditEventId id && id.value.equals(value);
    }

    @Override
    public int hashCode() {
        return value.hashCode();
    }

    @NotNull
    @Override
    public String toString() {
        return value;
    }
}
