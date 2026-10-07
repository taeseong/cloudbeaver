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
 * Where one metadata lease is in its life
 * <p>
 * A lease starts {@code OPEN}, runs at most one statement ({@code USED}), and is disposed exactly
 * once. Its statement marks it {@code CONTAMINATED} when the session it ran on can no longer be
 * trusted - the query timeout could not be restored, a statement or result could not be closed, or an
 * {@code Error} was thrown while it ran. A contaminated lease is never handed back to the pool as it
 * is.
 * <ul>
 *   <li>{@code RETURNED} - closed normally; the pool has the connection back</li>
 *   <li>{@code INVALIDATED} - aborted and closed; the pool discards it</li>
 *   <li>{@code QUARANTINED} - could not be released; held strongly, in its slot, until shutdown retries it</li>
 *   <li>{@code RESIDUAL} - could not be released after shutdown; held strongly for the rest of the process</li>
 * </ul>
 */
public enum LeaseState {
    OPEN,
    USED,
    CONTAMINATED,
    DISPOSING,
    RETURNED,
    INVALIDATED,
    QUARANTINED,
    RESIDUAL;

    /**
     * Whether disposal has finished
     */
    public boolean isTerminal() {
        return this == RETURNED || this == INVALIDATED || this == QUARANTINED || this == RESIDUAL;
    }
}
