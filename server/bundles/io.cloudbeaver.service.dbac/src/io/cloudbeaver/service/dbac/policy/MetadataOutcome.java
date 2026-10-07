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

/**
 * What a lease's one statement produced: a value, or nothing usable
 * <p>
 * {@code Done} is returned only when the statement ran, its result was read as declared, the result
 * and statement were closed and the session's query timeout was put back - all within the budget.
 * Anything else is {@code Unusable}, and carries no value at all.
 *
 * @param <T> the value: the rows of a query, or the update count of an update
 */
public sealed interface MetadataOutcome<T> permits MetadataOutcome.Done, MetadataOutcome.Unusable {

    /**
     * The statement's value
     *
     * @param value never null
     * @param <T>   the value's type
     */
    record Done<T>(@NotNull T value) implements MetadataOutcome<T> {
        /**
         * Refuses a missing value
         */
        public Done {
            if (value == null) {
                throw new IllegalArgumentException("A finished metadata statement must carry its value");
            }
        }
    }

    /**
     * No value, and why
     *
     * @param cause never null
     * @param <T>   the value's type, had there been one
     */
    record Unusable<T>(@NotNull UnusableCause cause) implements MetadataOutcome<T> {
        /**
         * Refuses a missing cause
         */
        public Unusable {
            if (cause == null) {
                throw new IllegalArgumentException("An unusable metadata result must say why");
            }
        }
    }
}
