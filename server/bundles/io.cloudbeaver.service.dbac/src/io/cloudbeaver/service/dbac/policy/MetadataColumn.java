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
 * One result column a metadata query declares, and how it is read
 *
 * @param label    the column label, as the statement names it
 * @param kind     how it is read
 * @param nullable whether SQL NULL is an acceptable value; a null in a column that is not is a failure to read
 */
record MetadataColumn(@NotNull String label, @NotNull Kind kind, boolean nullable) {

    /** The readable kinds */
    enum Kind {
        /** Read with {@code getString} */
        STRING,
        /** Read with {@code getObject(label, OffsetDateTime.class)} */
        TIMESTAMP,
        /** Read with {@code getInt}, then {@code wasNull} */
        INT,
        /** Read with {@code getLong}, then {@code wasNull} */
        LONG
    }
}
