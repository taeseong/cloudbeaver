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
 * No metadata lease could be had
 * <p>
 * Deliberately carries nothing a failure brought with it: the message is fixed per reason and there
 * is no cause. A driver or pool message routinely names a JDBC URL, a host or a user, and an exception
 * object that holds one is an exception object some caller will eventually log. What survives of a
 * failed borrow is the failure's class name, which is all the P1 log contract allows anyway.
 */
public final class MetadataUnavailableException extends Exception {

    /**
     * Why no lease was handed out
     */
    public enum Reason {
        /** The source has been shut down */
        CLOSED,
        /** Every slot is quarantined; the source refuses until the process restarts */
        REFUSING,
        /** Every slot is in use; refused at once, without waiting */
        CAPACITY,
        /** The executor would not take the borrow */
        REJECTED,
        /** The budget was spent before the borrow started */
        BUDGET_EXHAUSTED,
        /** The borrow did not finish within the budget */
        TIMEOUT,
        /** The caller was interrupted while waiting; its interrupt status is set again */
        INTERRUPTED,
        /** Opening the connection failed */
        BORROW_FAILED
    }

    private final Reason reason;
    private final String failureClass;

    /**
     * A refusal for {@code reason}, reporting this exception's own class
     */
    public MetadataUnavailableException(@NotNull Reason reason) {
        this(reason, MetadataUnavailableException.class.getName());
    }

    /**
     * A refusal for {@code reason}, reporting the class of the failure behind it
     *
     * @param failureClass a class name, and only that: never a message
     */
    public MetadataUnavailableException(@NotNull Reason reason, @NotNull String failureClass) {
        super("DBAC metadata connection unavailable: " + reason.name(), null, false, false);
        this.reason = reason;
        this.failureClass = failureClass;
    }

    /**
     * Why no lease was handed out
     */
    @NotNull
    public Reason reason() {
        return reason;
    }

    /**
     * The class name to report for this failure: the borrow failure's when there was one, otherwise this exception's
     */
    @NotNull
    public String failureClass() {
        return failureClass;
    }
}
