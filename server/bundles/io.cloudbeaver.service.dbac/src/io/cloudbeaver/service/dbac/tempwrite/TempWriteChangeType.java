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

/**
 * State transition recorded in {@code DBAC_TW_HISTORY}
 * <p>
 * History is not a request log. Only a transition that was actually committed gets a row, so a
 * request rejected as {@code CONFLICT_SUPERSEDED} leaves nothing here - that belongs to the audit
 * trail instead. Reading history therefore reconstructs the state the current row went through, with
 * no failed attempts mixed in.
 */
public enum TempWriteChangeType {

    /** A grant became the current row, either on a key that had none or replacing an older one. */
    GRANTED,

    /** An administrator ended an active grant before its expiry. */
    REVOKED,

    /** The grant reached its {@code EXPIRES_AT}; recorded once, by whichever request notices first. */
    EXPIRED,

    /** An active grant was replaced by a newer one on the same key, in that grant's transaction. */
    SUPERSEDED
}
