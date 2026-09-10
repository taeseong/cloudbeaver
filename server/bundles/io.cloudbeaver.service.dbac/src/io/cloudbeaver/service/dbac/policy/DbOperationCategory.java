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
 * What kind of database operation is being asked about
 * <p>
 * Phase 2 section 12.3 names the categories that must reach the write gate. This enum uses the
 * names given for Phase 3 slice 3, which differ from that section's spelling; the mapping is written
 * on each constant so a reader of either document can follow it. Nothing in this slice classifies a
 * SQL statement - the classifier is a later slice - so these values are the vocabulary a caller uses
 * to say what it is doing, not the output of any analysis.
 * <p>
 * <b>Three kinds, and the difference matters.</b> {@link Gate#WRITE_GATED} categories need a live
 * TEMP_WRITE grant. {@link Gate#NOT_WRITE_GATED} categories never needed one, so the write gate is
 * the wrong thing to ask about them - a caller that asks anyway has wired something incorrectly and
 * is refused rather than quietly told yes. {@link Gate#RECOVERY} is rollback, which must stay
 * available precisely when everything else is denied.
 */
public enum DbOperationCategory {

    /**
     * A SQL statement submitted as text. Phase 2 calls this {@code SQL_STATEMENT}.
     * <p>
     * Write-gated regardless of what the text turns out to be: this slice has no classifier, and a
     * gate that let unclassified text through would be a gate in name only.
     */
    SQL_TEXT(Gate.WRITE_GATED),

    /**
     * A typed change made through the data grid. Phase 2 calls this {@code DATA_EDITOR_MUTATION}.
     */
    DATA_EDIT(Gate.WRITE_GATED),

    /**
     * An object change - create, alter, drop, truncate, rename, comment. Phase 2 calls this
     * {@code DDL_OBJECT_CHANGE}.
     */
    METADATA_DDL(Gate.WRITE_GATED),

    /**
     * A data import. Phase 2 calls this {@code DATA_IMPORT} and requires the decision to be taken
     * again at execution time, not only when the import is configured.
     */
    IMPORT_DATA(Gate.WRITE_GATED),

    /**
     * A plan request. Phase 2 calls this {@code EXPLAIN_PLAN}.
     * <p>
     * Write-gated on purpose: {@code EXPLAIN ANALYZE} executes the statement it is explaining, so
     * treating the category as read-only would open a hole shaped exactly like the one this project
     * exists to close.
     */
    EXPLAIN(Gate.WRITE_GATED),

    /**
     * Committing an open transaction
     */
    TRANSACTION_COMMIT(Gate.WRITE_GATED),

    /**
     * Turning auto-commit on, which commits whatever the transaction was holding
     */
    TRANSACTION_AUTOCOMMIT_ON(Gate.WRITE_GATED),

    /**
     * Reading the object tree of a connection - metadata only
     * <p>
     * Not write-gated. Phase 2 section 10 keeps reads working when the permission store is down -
     * READ_ONLY is the resting state, so a read never needs a grant and must not be blocked by a
     * failure to look one up.
     * <p>
     * <b>Scope, narrowly.</b> This is the navigator's object tree. It is deliberately <em>not</em>
     * the category for a data read that carries a client-supplied filter expression, even though
     * CloudBeaver's operation for that is spelled {@code readDataFromContainer}: a
     * {@code SQLDataFilter} carries {@code where}, {@code orderBy} and {@code criteria} as free
     * text, and {@code WebSQLDataFilter.makeDataFilter} passes {@code where} into
     * {@code DBDDataFilter.setWhere} without inspecting it. Whether that path can be treated as a
     * read at all is an open enforcement-slice question - see {@code docs/db-mutation-surface.md}
     * section 13.12 - and no category here answers it yes. A caller that reaches for this constant
     * to cover a filtered data read is using the wrong one.
     */
    CONTAINER_READ(Gate.NOT_WRITE_GATED),

    /**
     * A grouping or aggregation query
     * <p>
     * <b>Write-gated, and an earlier version of this file had it wrong.</b> It said the query was
     * "built by the UI over an existing result set" and was therefore as safe as a read. The code
     * says otherwise: {@code service.sql.graphqls:456} declares {@code functions: [String!]}, and
     * {@code SQLGroupingQueryGenerator.java:123-124} appends each element into the generated SQL
     * verbatim ({@code sql.append(", ").append(func)}). The client sends completed SQL expressions
     * as free text and there is no allowlist anywhere on that path. This project's own survey
     * recorded it as HIGH with "allowlist = REQUIRED" - {@code docs/db-mutation-surface.md} section
     * 13.12 - which the old javadoc contradicted.
     * <p>
     * Write-gating it is the fail-closed reading of that: client-supplied SQL text of unknown effect
     * is exactly the UNKNOWN case, and CLAUDE.md section 2.1 sends UNKNOWN to DENY. It is not the
     * final answer. A grouping query built only from allowlisted aggregate functions is a read, and
     * the enforcement slice may reclassify it once such an allowlist exists; until then the gate is
     * consulted and, with no grant, the answer is no. Note also that the central SQL classifier
     * cannot substitute for that allowlist, because injected text arrives inside a {@code SELECT}.
     */
    GROUPING(Gate.WRITE_GATED),

    /**
     * Rolling a transaction back
     * <p>
     * Phase 2 section 12.3: rollback is not judged, it is always allowed. It is the one operation
     * that must work when a connection is in trouble, and denying it would strand uncommitted work
     * instead of discarding it. This slice models that; wiring it to the real service is later.
     */
    TRANSACTION_ROLLBACK(Gate.RECOVERY);

    /**
     * How the write gate treats a category
     */
    public enum Gate {
        /** Needs a live TEMP_WRITE grant. */
        WRITE_GATED,
        /** Never needed one; asking the write gate about it is a wiring mistake. */
        NOT_WRITE_GATED,
        /** Always permitted, because it is how a caller gets out of trouble. */
        RECOVERY,
    }

    private final Gate gate;

    DbOperationCategory(@NotNull Gate gate) {
        this.gate = gate;
    }

    @NotNull
    public Gate gate() {
        return gate;
    }

    /**
     * Whether a caller must obtain a decision from the write gate before performing this operation
     * <p>
     * A read path should ask this and skip the gate entirely rather than call it and interpret the
     * answer, which is why {@link DbAccessPolicyService} refuses categories that answer {@code false}.
     */
    public boolean requiresWriteAuthorization() {
        return gate == Gate.WRITE_GATED;
    }
}
