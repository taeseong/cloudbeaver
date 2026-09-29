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
package io.cloudbeaver.test.platform.dbac;

import io.cloudbeaver.DBWConstants;
import io.cloudbeaver.app.CEAppStarter;
import io.cloudbeaver.service.dbac.policy.DbOperationCategory;
import io.cloudbeaver.service.dbac.policy.DenialReason;
import io.cloudbeaver.test.platform.util.GraphQLTestClientWrapper;
import org.jkiss.code.Nullable;
import org.jkiss.dbeaver.model.data.json.JSONUtils;
import org.jkiss.dbeaver.model.runtime.LoggingProgressMonitor;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

/**
 * What Slice 4a must leave exactly as it is
 * <p>
 * Every test here passes today and has to keep passing once enforcement is wired: rollback always
 * works, turning auto-commit off is not gated, a TEMP_WRITE user keeps Explain, commit and
 * auto-commit on, and a READ_ONLY user keeps reading. They are kept apart from the red security
 * tests so they can be committed on their own while those are still red.
 * <p>
 * The subject is an ordinary {@code authRole=user} account; the test admin only creates and deletes
 * it.
 */
public class EnforcementRegressionGuardTest {

    private static EnforcementTestSupport.Fixtures fixtures;

    @BeforeAll
    public static void startServer() throws Exception {
        CEAppStarter.startServerIfNotStarted();
        fixtures = EnforcementTestSupport.fixtures("rg", new LoggingProgressMonitor());
    }

    @AfterEach
    public void cleanUp() throws Exception {
        fixtures.afterEach();
    }

    @AfterAll
    public static void deleteUsers() throws Exception {
        fixtures.afterAll();
    }

    /** RG-1: auto-commit off is deliberately not gated - starting a transaction commits nothing */
    @Test
    public void rg1AutoCommitOffStaysUngatedForReadOnly() throws Exception {
        EnforcementTestSupport.Target target = fixtures.readOnlyTarget(fixtures.user);
        EnforcementTestSupport.premiseDenies("RG-1", target, DbOperationCategory.TRANSACTION_COMMIT, DenialReason.NO_GRANT);

        EnforcementTestSupport.Outcome off = EnforcementTestSupport.setAutoCommit(target, false);

        Assertions.assertTrue(off.succeeded(), "RG-1: auto-commit off must stay ungated: " + EnforcementTestSupport.describe(off.error()));
        Assertions.assertFalse(target.jdbc().getAutoCommit(), "RG-1: the connection must be in manual commit afterwards");
    }

    /** RG-2: rollback is recovery and is never judged, READ_ONLY or not */
    @Test
    public void rg2RollbackAlwaysWorksForReadOnly() throws Exception {
        EnforcementTestSupport.Target target = fixtures.readOnlyTarget(fixtures.user);
        EnforcementTestSupport.premiseDenies("RG-2", target, DbOperationCategory.TRANSACTION_COMMIT, DenialReason.NO_GRANT);
        EnforcementTestSupport.openTransaction(target, 21);

        EnforcementTestSupport.Outcome outcome = EnforcementTestSupport.rollback(target);

        Assertions.assertTrue(outcome.succeeded(), "RG-2: rollback must work for a READ_ONLY user: "
            + EnforcementTestSupport.describe(outcome.error()));
        Assertions.assertEquals(0, EnforcementTestSupport.readValue(target.jdbc(), target.schema),
            "RG-2: the transaction must be rolled back");
        Assertions.assertEquals(0, target.committedValue(), "RG-2: nothing may have been committed");
    }

    /** RG-3 (EXP-3): a TEMP_WRITE user keeps Explain */
    @Test
    public void rg3TempWriteExplainKeepsWorking() throws Exception {
        EnforcementTestSupport.Target target = fixtures.writableTarget(fixtures.user);
        EnforcementTestSupport.premiseAllows("RG-3", target, DbOperationCategory.EXPLAIN);

        EnforcementTestSupport.Outcome outcome = EnforcementTestSupport.explain(target, "SELECT id FROM " + target.table(), Map.of());

        Assertions.assertTrue(outcome.succeeded(), "RG-3: Explain must keep working under TEMP_WRITE: "
            + EnforcementTestSupport.describe(outcome.error()));
    }

    /** RG-4: a TEMP_WRITE user keeps commit */
    @Test
    public void rg4TempWriteCommitKeepsWorking() throws Exception {
        EnforcementTestSupport.Target target = fixtures.writableTarget(fixtures.user);
        EnforcementTestSupport.premiseAllows("RG-4", target, DbOperationCategory.TRANSACTION_COMMIT);
        EnforcementTestSupport.openTransaction(target, 24);

        EnforcementTestSupport.Outcome outcome = EnforcementTestSupport.commit(target);

        Assertions.assertTrue(outcome.succeeded(), "RG-4: commit must keep working under TEMP_WRITE: "
            + EnforcementTestSupport.describe(outcome.error()));
        Assertions.assertEquals(24, target.committedValue(), "RG-4: the change must be committed");
    }

    /** RG-5: a TEMP_WRITE user keeps auto-commit on, and it really is on afterwards */
    @Test
    public void rg5TempWriteAutoCommitOnKeepsWorking() throws Exception {
        EnforcementTestSupport.Target target = fixtures.writableTarget(fixtures.user);
        EnforcementTestSupport.premiseAllows("RG-5", target, DbOperationCategory.TRANSACTION_AUTOCOMMIT_ON);
        EnforcementTestSupport.openTransaction(target, 25);

        EnforcementTestSupport.Outcome outcome = EnforcementTestSupport.setAutoCommit(target, true);

        Assertions.assertTrue(outcome.succeeded(), "RG-5: auto-commit on must keep working under TEMP_WRITE: "
            + EnforcementTestSupport.describe(outcome.error()));
        Assertions.assertEquals(Boolean.TRUE, outcome.result(), "RG-5: the call must report success");
        Assertions.assertTrue(target.jdbc().getAutoCommit(), "RG-5: JDBC auto-commit must really be on");
        Assertions.assertEquals(25, target.committedValue(), "RG-5: turning auto-commit on must commit the open change");
    }

    /**
     * RG-6: reading through SQL_TEXT is outside Slice 4a and must be untouched by it
     * <p>
     * "The task stopped without an error" is not enough - a task can stop without delivering
     * anything. The task has to report FINISHED, and the result set read back through the same
     * GraphQL path the UI uses has to hold exactly the fixture row: one row whose first column,
     * {@code v}, is the number 0.
     */
    @Test
    public void rg6ReadOnlySelectIsUnaffected() throws Exception {
        EnforcementTestSupport.Target target = fixtures.readOnlyTarget(fixtures.user);
        Map<String, Object> task = fixtures.user.client().sendQuery(EnforcementTestSupport.GQL_ASYNC_SQL_EXECUTE, Map.of(
            "projectId", target.project.getId(),
            "connectionId", target.container.getId(),
            "contextId", target.sqlContext.getId(),
            "sql", "SELECT v FROM " + target.table() + " WHERE id = 1"));
        Assertions.assertNotNull(task, "FIXTURE: asyncSqlExecuteQuery returned no task");
        String taskId = String.valueOf(task.get("id"));

        EnforcementTestSupport.GraphQlTask finished = EnforcementTestSupport.awaitGraphQlTask(fixtures.user.client(), taskId);
        Assertions.assertNull(finished.error(), "RG-6: a READ_ONLY SELECT must not fail: " + finished.error());
        Assertions.assertTrue(DBWConstants.TASK_STATUS_FINISHED.equalsIgnoreCase(finished.status()),
            "RG-6: the task must report " + DBWConstants.TASK_STATUS_FINISHED + ", reported " + finished.status());

        Map<String, Object> resultSet = new GraphQLTestClientWrapper(fixtures.user.client()).readTaskResultSet(taskId);
        Assertions.assertNotNull(resultSet, "RG-6: the finished task must deliver a result set");
        List<Map<String, Object>> columns = JSONUtils.getObjectList(resultSet, "columns");
        List<Map<String, Object>> rows = JSONUtils.getObjectList(resultSet, "rowsWithMetaData");
        Object first = rows.size() == 1 && rows.get(0).get("data") instanceof List<?> data && !data.isEmpty() ? data.get(0) : null;
        System.out.println("[DBAC S1] RG-6 status=" + finished.status() + ", columns="
            + columns.stream().map(column -> column.get("name")).toList() + ", rows=" + rows.size()
            + ", first value=" + first + " (" + (first == null ? "null" : first.getClass().getSimpleName()) + ")");

        Assertions.assertFalse(columns.isEmpty(), "RG-6: the result set must describe its columns");
        Assertions.assertTrue("v".equalsIgnoreCase(String.valueOf(columns.get(0).get("name"))),
            "RG-6: the first column must be v, was " + columns.get(0).get("name"));
        Assertions.assertEquals(1, rows.size(), "RG-6: the SELECT must return exactly the one fixture row");
        Assertions.assertTrue(isNumericZero(first), "RG-6: the fixture value must read back as the number 0, was " + first);
    }

    /**
     * Whether a JSON-decoded cell is the number zero, whatever numeric form the decoder chose
     * <p>
     * A number may arrive as an integer, a double or a numeric string. Anything else - null, an
     * empty string, a boolean, a non-numeric string - is not zero.
     */
    private static boolean isNumericZero(@Nullable Object value) {
        String text;
        if (value instanceof Number number) {
            text = number.toString();
        } else if (value instanceof String string) {
            text = string.trim();
        } else {
            return false;
        }
        try {
            return new BigDecimal(text).compareTo(BigDecimal.ZERO) == 0;
        } catch (NumberFormatException e) {
            return false;
        }
    }
}
