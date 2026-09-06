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
 * A refused mutation is a normal answer, not a failure: the conflict cases below all mean the
 * request was correct but arrived too late. A metadata database that is broken or unreachable is a
 * different thing entirely and propagates as an exception, because reporting it as "no change"
 * would let a caller mistake a dead store for an empty one.
 */
public record TempWriteMutationResult(
    @NotNull TempWriteMutationStatus status,
    int affectedRows,
    @Nullable Long revision,
    @Nullable String grantId,
    @Nullable TempWriteConflictReason conflictReason,
    int attempts
) {

    public TempWriteMutationResult {
        if (attempts < 1) {
            throw new IllegalArgumentException("A mutation makes at least one attempt, got " + attempts);
        }
        if (affectedRows < 0) {
            throw new IllegalArgumentException("Affected rows cannot be negative, got " + affectedRows);
        }
        boolean conflicted = status == TempWriteMutationStatus.CONFLICT_SUPERSEDED
            || status == TempWriteMutationStatus.RETRY_EXHAUSTED;
        if (conflicted == (conflictReason == null)) {
            throw new IllegalArgumentException(
                "Status " + status + " and conflict reason " + conflictReason + " disagree");
        }
        if (conflicted && affectedRows != 0) {
            throw new IllegalArgumentException(
                "A refused mutation cannot have changed " + affectedRows + " rows");
        }
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
