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

import io.cloudbeaver.app.CEAppStarter;
import io.cloudbeaver.service.dbac.policy.DbOperationCategory;
import io.cloudbeaver.service.dbac.policy.DenialReason;
import org.jkiss.dbeaver.model.runtime.LoggingProgressMonitor;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Map;

/**
 * P6-B: the Explain entry point - {@code WebSQLProcessor.explainExecutionPlan()} - driven from outside, as a user reaches it
 * <p>
 * The two Explain tests of the Slice 4a red set, copied from {@code EnforcementEntryPointTest} without a changed
 * assertion. Each one first proves its own premise through the policy core, so a failure is about the entry point and
 * never about a fixture that granted or revoked the wrong thing; a premise that does not hold fails with
 * {@code FIXTURE} instead. In Slice 4a every Explain is write-gated: a READ_ONLY user is denied plain EXPLAIN as well
 * as EXPLAIN ANALYZE.
 */
public class ExplainEnforcementEntryPointTest {

    private static EnforcementTestSupport.Fixtures fixtures;

    @BeforeAll
    public static void startServer() throws Exception {
        CEAppStarter.startServerIfNotStarted();
        fixtures = EnforcementTestSupport.fixtures("xep", new LoggingProgressMonitor());
    }

    @AfterEach
    public void cleanUp() throws Exception {
        fixtures.afterEach();
    }

    @AfterAll
    public static void deleteUsers() throws Exception {
        fixtures.afterAll();
    }

    // ---------------------------------------------------------------- Explain

    /** EXP-1: a READ_ONLY user cannot Explain at all - the approved Slice 4a regression */
    @Test
    public void exp1ReadOnlyPlainExplainIsDenied() throws Exception {
        EnforcementTestSupport.Target target = fixtures.readOnlyTarget(fixtures.user);
        EnforcementTestSupport.premiseDenies("EXP-1", target, DbOperationCategory.EXPLAIN, DenialReason.NO_GRANT);

        EnforcementTestSupport.Outcome outcome = EnforcementTestSupport.explain(target, "SELECT id FROM " + target.table(), Map.of());

        EnforcementTestSupport.assertDenied("EXP-1", outcome, DenialReason.NO_GRANT, "plain EXPLAIN by a READ_ONLY user");
    }

    /**
     * EXP-2: a READ_ONLY user cannot run a statement through EXPLAIN ANALYZE, not even partly
     * <p>
     * The statement draws from a sequence, which no rollback undoes. The platform planner already
     * rolls back the row change ({@code PostgreExecutionPlan:186-191}), so an unchanged row proves
     * nothing; an unchanged sequence is what proves the statement never ran. A gate that let the
     * statement execute and denied afterwards must fail here.
     */
    @Test
    public void exp2ReadOnlyExplainAnalyzeNeverExecutesTheStatement() throws Exception {
        EnforcementTestSupport.Target target = fixtures.readOnlyTarget(fixtures.user);
        EnforcementTestSupport.premiseDenies("EXP-2", target, DbOperationCategory.EXPLAIN, DenialReason.NO_GRANT);
        long sequenceBefore = EnforcementTestSupport.sequenceValue(target);

        EnforcementTestSupport.Outcome outcome = EnforcementTestSupport.explain(target,
            "UPDATE " + target.table() + " SET v = nextval('" + target.schema + ".seq')::int WHERE id = 1",
            Map.of("ANALYZE", true));

        long sequenceAfter = EnforcementTestSupport.sequenceValue(target);
        int value = target.committedValue();
        EnforcementTestSupport.Expectations expect = new EnforcementTestSupport.Expectations("EXP-2");
        expect.check(outcome.error() != null && EnforcementTestSupport.mentions(outcome.error(), DenialReason.NO_GRANT),
            "expected DENY(NO_GRANT)");
        expect.check(sequenceAfter == sequenceBefore, "the sequence must not advance - the statement must never run");
        expect.check(value == 0, "the committed row must be unchanged");
        expect.verify("explain " + (outcome.succeeded() ? "returned a plan" : "failed with "
            + EnforcementTestSupport.describe(outcome.error())) + ", sequence " + sequenceBefore + " -> " + sequenceAfter
            + ", committed row " + value);
    }
}
