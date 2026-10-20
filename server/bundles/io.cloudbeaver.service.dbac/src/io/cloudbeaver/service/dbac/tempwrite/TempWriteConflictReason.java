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
 * Why a mutation was refused without changing anything
 * <p>
 * Every value means the same thing to the caller - nothing was written, the current row and the
 * history are exactly as they were - and they differ only in what the coordinator observed.
 */
public enum TempWriteConflictReason {

    /**
     * The stored revision no longer matched the one the request started from.
     * <p>
     * Someone else changed this key in the meantime, so the request describes a world that no
     * longer exists. It is refused rather than retried: retrying would mean re-reading the
     * revision, and a request that adopts the new revision is exactly the delayed grant that must
     * not come back to life after a revoke.
     */
    REVISION_SUPERSEDED,

    /**
     * The write kept losing a genuine race while the revision stayed unchanged.
     * <p>
     * Reached only through transient contention - a competing writer that rolled back, a lock
     * timeout, a deadlock - repeated past the retry limit. Fail-closed: the request fails and
     * nothing is left half applied.
     */
    TRANSIENT_RETRY_EXHAUSTED,

    /**
     * The grant's user does not exist.
     * <p>
     * Observed inside the attempt's own transaction while the user's read lock was held, so no
     * deletion could have been in progress. Not retried: a user that is missing under the lock stays
     * missing.
     */
    USER_MISSING,

    /**
     * The user's read lock could not be taken within the key lock timeout.
     * <p>
     * A deletion or deactivation of that user was holding it. No metadata connection was opened.
     */
    USER_LOCK_TIMEOUT,

    /**
     * The thread was interrupted while waiting for the user's read lock.
     * <p>
     * No metadata connection was opened, and the interrupt is set again before the coordinator
     * returns.
     */
    USER_LOCK_INTERRUPTED
}
