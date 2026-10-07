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
 * Hands out metadata leases
 * <p>
 * The only way the policy core reaches the metadata database. A lease carries one statement and is
 * closed with try-with-resources; the decision taken from its value is settled inside the
 * {@code try} block, before the lease is closed.
 */
@FunctionalInterface
public interface MetadataLeaseSource {

    /**
     * Borrows one metadata connection, within {@code budget}
     *
     * @throws MetadataUnavailableException when no lease can be had in time - refused, at capacity,
     *     timed out, interrupted, or the borrow itself failed. Never carries the cause.
     */
    @NotNull
    MetadataLease open(@NotNull MetadataBudget budget, @NotNull MetadataPurpose purpose) throws MetadataUnavailableException;
}
