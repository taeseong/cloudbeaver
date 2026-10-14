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
 * What a grant or revoke did to the metadata database
 */
public enum TempWriteMutationStatus {

    /** The current row and its history event were written and committed together. */
    COMMITTED,

    /** The request was already satisfied - nothing to revoke - so nothing was written. */
    NO_OP,

    /** The key changed after the request started, so the request was refused unchanged. */
    CONFLICT_SUPERSEDED,

    /** Transient contention outlasted the retry limit, so the request failed unchanged. */
    RETRY_EXHAUSTED,

    /**
     * The user-incarnation fence refused the grant, so the request failed unchanged.
     * <p>
     * Either the user does not exist, or the user's lock could not be taken to find out. A grant is
     * issued only to a user that exists while the grant holds that user's read lock, so a deletion
     * cannot commit between the check and the grant.
     */
    USER_FENCE_REFUSED
}
