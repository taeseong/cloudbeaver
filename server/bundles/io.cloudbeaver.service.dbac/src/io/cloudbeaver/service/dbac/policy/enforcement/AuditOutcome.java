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
package io.cloudbeaver.service.dbac.policy.enforcement;

/**
 * What became of one audit row
 * <p>
 * Two values and nothing else. In particular no denial reason and no decision: the caller already
 * holds its decision, and an audit result has no business replacing it. A failed audit of a denial
 * leaves that denial exactly as it was.
 */
public enum AuditOutcome {
    /**
     * The row was inserted in auto-commit, exactly one row, within the budget, and so is committed and
     * visible to every other connection
     * <p>
     * Committed and visible is all it says. Whether the row is on disk is the metadata database's
     * own setting - H2's write delay, PostgreSQL's {@code synchronous_commit}.
     */
    RECORDED,

    /**
     * Anything else - no lease, no statement, a wrong count, a timeout, a result past the budget, an
     * exception or an {@code Error}
     * <p>
     * Not "no row": a row committed after the budget was spent exists and is not counted. Whoever acts
     * on this treats the audit as missing.
     */
    FAILED
}
