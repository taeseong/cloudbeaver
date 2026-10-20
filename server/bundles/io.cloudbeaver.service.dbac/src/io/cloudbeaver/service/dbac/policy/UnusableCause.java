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

/**
 * Why a lease's statement produced no value
 * <p>
 * Every cause is the same answer to the caller - the store could not be read - and is kept apart only
 * so that a log says which step failed.
 */
public enum UnusableCause {
    /** Less than one whole second of the budget was left; nothing was run */
    BUDGET_EXHAUSTED,
    /** The lease had already run its one statement; nothing was run */
    SECOND_STATEMENT,
    /** The statement could not be prepared, or the connection was not in auto-commit; nothing was run */
    STATEMENT_FAILED,
    /** The query timeout could not be read or set */
    TIMEOUT_SETUP_FAILED,
    /** Binding or executing failed, including a query timeout */
    EXECUTION_FAILED,
    /** A declared column could not be read as declared */
    MATERIALIZATION_FAILED,
    /** The number of rows or the update count was not the declared one */
    CARDINALITY,
    /** The result or the statement could not be closed */
    CLOSE_FAILED,
    /** The session's query timeout could not be put back */
    RESTORE_FAILED,
    /** The value arrived after the budget was spent and was thrown away */
    OVER_BUDGET
}
