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
import org.jkiss.code.Nullable;

/**
 * Outcome of one grant or revoke, as an explicit value rather than a null or a thrown exception
 * <p>
 * A refused mutation is a normal answer, not a failure: a conflict means the request was correct but
 * arrived too late, and a user-fence refusal means the grant's user does not exist or could not be held
 * against a deletion in time. A metadata database that is broken or unreachable is a different thing
 * entirely and propagates as an exception, because reporting it as "no change" would let a caller
 * mistake a dead store for an empty one.
 */
public record TempWriteMutationResult(
    @NotNull TempWriteMutationStatus status,
    int affectedRows,
    @Nullable Long revision,
    @Nullable String grantId,
    @Nullable TempWriteConflictReason conflictReason,
    int attempts
) {

    /**
     * Refuses a combination the coordinator can never produce
     * <p>
     * A status has its own reasons: none for a commit or a no-op, one for each conflict, and the three
     * user-fence reasons for a fence refusal. A refusal changed no row and names no revision or grant. And
     * no attempt was made exactly when the user's lock was never had - a timeout or an interrupt while
     * waiting for it; every other outcome is the result of at least one attempt.
     */
    public TempWriteMutationResult {
        if (attempts < 0) {
            throw new IllegalArgumentException("Attempts cannot be negative, got " + attempts);
        }
        if (affectedRows < 0) {
            throw new IllegalArgumentException("Affected rows cannot be negative, got " + affectedRows);
        }
        if (!agrees(status, conflictReason)) {
            throw new IllegalArgumentException(
                "Status " + status + " and conflict reason " + conflictReason + " disagree");
        }
        if (conflictReason != null && affectedRows != 0) {
            throw new IllegalArgumentException(
                "A refused mutation cannot have changed " + affectedRows + " rows");
        }
        if (conflictReason != null && (revision != null || grantId != null)) {
            throw new IllegalArgumentException(
                "A refused mutation names no revision or grant, got " + revision + " and " + grantId);
        }
        boolean lockNeverHad = conflictReason == TempWriteConflictReason.USER_LOCK_TIMEOUT
            || conflictReason == TempWriteConflictReason.USER_LOCK_INTERRUPTED;
        if ((attempts == 0) != lockNeverHad) {
            throw new IllegalArgumentException(lockNeverHad
                ? "A refusal before the user's lock makes no attempt, got " + attempts
                : "Every outcome but a refusal before the user's lock makes at least one attempt");
        }
    }

    private static boolean agrees(@NotNull TempWriteMutationStatus status, @Nullable TempWriteConflictReason reason) {
        return switch (status) {
            case COMMITTED, NO_OP -> reason == null;
            case CONFLICT_SUPERSEDED -> reason == TempWriteConflictReason.REVISION_SUPERSEDED;
            case RETRY_EXHAUSTED -> reason == TempWriteConflictReason.TRANSIENT_RETRY_EXHAUSTED;
            case USER_FENCE_REFUSED -> reason == TempWriteConflictReason.USER_MISSING
                || reason == TempWriteConflictReason.USER_LOCK_TIMEOUT
                || reason == TempWriteConflictReason.USER_LOCK_INTERRUPTED;
        };
    }

    /**
     * Builds the result of a committed transition
     */
    @NotNull
    static TempWriteMutationResult committed(long revision, @NotNull String grantId, int attempts) {
        return new TempWriteMutationResult(
            TempWriteMutationStatus.COMMITTED, 1, revision, grantId, null, attempts);
    }

    /**
     * Builds the result of a request that was already satisfied and changed nothing
     */
    @NotNull
    static TempWriteMutationResult noOp(int attempts) {
        return new TempWriteMutationResult(
            TempWriteMutationStatus.NO_OP, 0, null, null, null, attempts);
    }

    /**
     * Builds the result of a request that was overtaken before it could apply
     */
    @NotNull
    static TempWriteMutationResult superseded(int attempts) {
        return new TempWriteMutationResult(
            TempWriteMutationStatus.CONFLICT_SUPERSEDED, 0, null, null,
            TempWriteConflictReason.REVISION_SUPERSEDED, attempts);
    }

    /**
     * Builds the result of a request that lost too many genuine races
     */
    @NotNull
    static TempWriteMutationResult retryExhausted(int attempts) {
        return new TempWriteMutationResult(
            TempWriteMutationStatus.RETRY_EXHAUSTED, 0, null, null,
            TempWriteConflictReason.TRANSIENT_RETRY_EXHAUSTED, attempts);
    }

    /**
     * Builds the result of a grant whose user did not exist, seen by the attempt that read it
     */
    @NotNull
    static TempWriteMutationResult userMissing(int attempt) {
        return new TempWriteMutationResult(
            TempWriteMutationStatus.USER_FENCE_REFUSED, 0, null, null,
            TempWriteConflictReason.USER_MISSING, attempt);
    }

    /**
     * Builds the result of a grant that could not take its user's read lock in time
     */
    @NotNull
    static TempWriteMutationResult userLockTimeout() {
        return new TempWriteMutationResult(
            TempWriteMutationStatus.USER_FENCE_REFUSED, 0, null, null,
            TempWriteConflictReason.USER_LOCK_TIMEOUT, 0);
    }

    /**
     * Builds the result of a grant interrupted while waiting for its user's read lock
     */
    @NotNull
    static TempWriteMutationResult userLockInterrupted() {
        return new TempWriteMutationResult(
            TempWriteMutationStatus.USER_FENCE_REFUSED, 0, null, null,
            TempWriteConflictReason.USER_LOCK_INTERRUPTED, 0);
    }

    /**
     * Whether the metadata database was actually changed
     */
    public boolean isCommitted() {
        return status == TempWriteMutationStatus.COMMITTED;
    }

    /**
     * Whether the request was refused without changing anything
     */
    public boolean isRefused() {
        return conflictReason != null;
    }
}
