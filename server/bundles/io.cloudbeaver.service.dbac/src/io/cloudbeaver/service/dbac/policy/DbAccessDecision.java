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
 * The outcome of one write authorization question
 * <p>
 * Two values, and deliberately not a boolean: an {@code AuthorizationDecision} has to carry why it
 * denied, which grant it applied and what an audit layer should record, and a boolean cannot be
 * extended with any of that without every caller changing. Phase 2 section 6 states the same rule.
 * <p>
 * There is no third value. "Unknown" is not a decision this enum can express, because every path
 * that cannot establish an answer must produce {@link #DENY} with a reason - that is what fail-closed
 * means here.
 */
public enum DbAccessDecision {
    /**
     * The write may proceed
     * <p>
     * Reached only through the single ALLOW path in {@link DbAccessPolicyService}: an unrevoked,
     * unexpired grant whose connection snapshot still matches, for an active user, on a supported
     * database, within the clock skew allowance.
     */
    ALLOW,

    /**
     * The write may not proceed
     * <p>
     * Always accompanied by a {@link DenialReason}. A DENY with no reason is a bug, and the record
     * that carries this value refuses to be constructed that way.
     */
    DENY,
}
