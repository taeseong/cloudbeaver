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
import java.util.List;

/**
 * One metadata INSERT, UPDATE or DELETE, as a value
 * <p>
 * The text, the values bound to it and the exact update count it must produce. A lease runs it and
 * returns the count; any other count makes the result unusable.
 */
public final class MetadataUpdate {

    private final String text;
    private final List<MetadataBinding> bindings;
    private final long expectedCount;

    private MetadataUpdate(@NotNull Builder builder) {
        this.text = builder.text;
        this.bindings = List.copyOf(builder.bindings);
        this.expectedCount = builder.expectedCount;
    }

    /**
     * Starts an update with this text
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

    long expectedCount() {
        return expectedCount;
    }

    /**
     * Builds a {@link MetadataUpdate}; parameters are bound in the order they are added
     */
    public static final class Builder {
        private final String text;
        private final List<MetadataBinding> bindings = new ArrayList<>();
        private long expectedCount = -1;

        private Builder(@NotNull String text) {
            if (text == null || text.isBlank()) {
                throw new IllegalArgumentException("A metadata update needs a statement");
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
         * The update count the statement must produce
         */
        @NotNull
        public Builder expectUpdateCount(long exactly) {
            if (exactly < 0) {
                throw new IllegalArgumentException("An expected update count cannot be negative, got " + exactly);
            }
            this.expectedCount = exactly;
            return this;
        }

        /**
         * The update; it needs an expected update count
         */
        @NotNull
        public MetadataUpdate build() {
            if (expectedCount < 0) {
                throw new IllegalStateException("A metadata update must declare the update count it expects");
            }
            return new MetadataUpdate(this);
        }
    }
}
