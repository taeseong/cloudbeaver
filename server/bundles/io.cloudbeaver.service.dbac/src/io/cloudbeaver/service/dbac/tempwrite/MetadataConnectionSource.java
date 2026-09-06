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
 * Where the coordinator gets a metadata connection from
 * <p>
 * In production this is {@code CBDatabase::openConnection} and nothing else. That path returns the
 * proxy connection which substitutes {@code {table_prefix}}, so taking a connection straight from the
 * pooled {@code DataSource} would send the literal placeholder to the server.
 * <p>
 * It is an interface so a test can hand back a wrapped connection that fails a chosen statement, and
 * drive the rollback and retry paths deterministically. Those paths decide whether a state change is
 * left half applied, which is not something to leave to whatever a real race happens to produce.
 */
@FunctionalInterface
public interface MetadataConnectionSource {

    /**
     * Opens a connection to the metadata database
     * <p>
     * The caller owns it and closes it. Each call must return a connection that can hold its own
     * transaction: the retry policy depends on a failed attempt being abandoned entirely and the
     * next one starting from a clean transaction.
     *
     * @throws SQLException if no connection can be opened
     */
    @NotNull
    Connection openConnection() throws SQLException;
}
