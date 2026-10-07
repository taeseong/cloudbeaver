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
package io.cloudbeaver.service.dbac.policy;

import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;

import java.time.OffsetDateTime;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * One result row, copied out of the driver
 * <p>
 * Holds exactly the columns the query declared, each as the kind it was declared with. Asking for a
 * column that was not declared, or as another kind, is a programming error and throws
 * {@code IllegalArgumentException} - it never falls back to a guess.
 */
public final class MetadataRow {

    private final Map<String, MetadataColumn.Kind> kinds;
    private final Map<String, Object> values;

    MetadataRow(@NotNull Map<String, MetadataColumn.Kind> kinds, @NotNull Map<String, Object> values) {
        this.kinds = kinds;
        this.values = Collections.unmodifiableMap(new HashMap<>(values));
    }

    /**
     * A column declared with {@code columnString}
     */
    @Nullable
    public String string(@NotNull String label) {
        return (String) value(label, MetadataColumn.Kind.STRING);
    }

    /**
     * A column declared with {@code columnTimestamp}
     */
    @Nullable
    public OffsetDateTime timestamp(@NotNull String label) {
        return (OffsetDateTime) value(label, MetadataColumn.Kind.TIMESTAMP);
    }

    /**
     * A column declared with {@code columnInt}
     */
    public int integer(@NotNull String label) {
        return (Integer) value(label, MetadataColumn.Kind.INT);
    }

    /**
     * A column declared with {@code columnLong}
     */
    public long longValue(@NotNull String label) {
        return (Long) value(label, MetadataColumn.Kind.LONG);
    }

    @Nullable
    private Object value(@NotNull String label, @NotNull MetadataColumn.Kind kind) {
        MetadataColumn.Kind declared = kinds.get(label);
        if (declared == null) {
            throw new IllegalArgumentException("The column " + label + " was not declared by the query");
        }
        if (declared != kind) {
            throw new IllegalArgumentException("The column " + label + " was declared as " + declared + ", not " + kind);
        }
        return values.get(label);
    }
}
