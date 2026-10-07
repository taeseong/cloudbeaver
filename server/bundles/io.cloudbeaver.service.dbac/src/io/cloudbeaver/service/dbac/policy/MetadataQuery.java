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
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * One metadata SELECT, as a value
 * <p>
 * The text, the values bound to it, the columns to read and how many rows are acceptable - all fixed
 * when it is built. A lease runs it and returns the declared columns, read in full and copied, so no
 * JDBC object is ever handed to the caller.
 * <p>
 * {@code {table_prefix}} in the text is substituted by the metadata connection, as on every other
 * metadata path.
 */
public final class MetadataQuery {

    /** More rows than this is never what a DBAC statement means */
    public static final int MAX_ROWS = 1000;

    private final String text;
    private final List<MetadataBinding> bindings;
    private final List<MetadataColumn> columns;
    private final int minRows;
    private final int maxRows;

    private MetadataQuery(@NotNull Builder builder) {
        this.text = builder.text;
        this.bindings = List.copyOf(builder.bindings);
        this.columns = List.copyOf(builder.columns);
        this.minRows = builder.minRows;
        this.maxRows = builder.maxRows;
    }

    /**
     * Starts a query with this text
     */
    @NotNull
    public static Builder sql(@NotNull String sqlWithTablePrefix) {
        return new Builder(sqlWithTablePrefix);
    }

    @NotNull
    String text() {
        return text;
    }

    @NotNull
    List<MetadataBinding> bindings() {
        return bindings;
    }

    @NotNull
    List<MetadataColumn> columns() {
        return columns;
    }

    int minRows() {
        return minRows;
    }

    int maxRows() {
        return maxRows;
    }

    /**
     * Builds a {@link MetadataQuery}; parameters are bound in the order they are added
     */
    public static final class Builder {
        private final String text;
        private final List<MetadataBinding> bindings = new ArrayList<>();
        private final List<MetadataColumn> columns = new ArrayList<>();
        private final Set<String> labels = new HashSet<>();
        private int minRows = -1;
        private int maxRows = -1;

        private Builder(@NotNull String text) {
            if (text == null || text.isBlank()) {
                throw new IllegalArgumentException("A metadata query needs a statement");
            }
            this.text = text;
        }

        /**
         * The next parameter, as a string; null binds SQL NULL
         */
        @NotNull
        public Builder bindString(@Nullable String value) {
            bindings.add(MetadataBinding.string(value));
            return this;
        }

        /**
         * The next parameter, as a timestamp with time zone, normalized to UTC; null binds SQL NULL
         */
        @NotNull
        public Builder bindTimestamp(@Nullable OffsetDateTime value) {
            bindings.add(MetadataBinding.timestamp(value));
            return this;
        }

        /**
         * A column read with {@code getString}
         */
        @NotNull
        public Builder columnString(@NotNull String label, boolean nullable) {
            return column(label, MetadataColumn.Kind.STRING, nullable);
        }

        /**
         * A column read as an {@code OffsetDateTime}
         */
        @NotNull
        public Builder columnTimestamp(@NotNull String label, boolean nullable) {
            return column(label, MetadataColumn.Kind.TIMESTAMP, nullable);
        }

        /**
         * A column read with {@code getInt}; SQL NULL is a failure to read
         */
        @NotNull
        public Builder columnInt(@NotNull String label) {
            return column(label, MetadataColumn.Kind.INT, false);
        }

        /**
         * A column read with {@code getLong}; SQL NULL is a failure to read
         */
        @NotNull
        public Builder columnLong(@NotNull String label) {
            return column(label, MetadataColumn.Kind.LONG, false);
        }

        /**
         * How many rows are acceptable, inclusive; anything else makes the result unusable
         */
        @NotNull
        public Builder expectRows(int min, int max) {
            if (min < 0 || min > max || max > MAX_ROWS) {
                throw new IllegalArgumentException(
                    "Expected rows must satisfy 0 <= min <= max <= " + MAX_ROWS + ", got " + min + ".." + max);
            }
            this.minRows = min;
            this.maxRows = max;
            return this;
        }

        /**
         * The query; it needs at least one column and an expected row count
         */
        @NotNull
        public MetadataQuery build() {
            if (columns.isEmpty()) {
                throw new IllegalStateException("A metadata query must declare the columns it reads");
            }
            if (minRows < 0) {
                throw new IllegalStateException("A metadata query must declare how many rows it expects");
            }
            return new MetadataQuery(this);
        }

        @NotNull
        private Builder column(@NotNull String label, @NotNull MetadataColumn.Kind kind, boolean nullable) {
            if (label == null || label.isBlank()) {
                throw new IllegalArgumentException("A metadata column needs a label");
            }
            if (!labels.add(label)) {
                throw new IllegalArgumentException("The column " + label + " is declared twice");
            }
            columns.add(new MetadataColumn(label, kind, nullable));
            return this;
        }
    }
}
