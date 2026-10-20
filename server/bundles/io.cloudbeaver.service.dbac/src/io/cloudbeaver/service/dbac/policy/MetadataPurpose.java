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
 * What a metadata lease is borrowed for
 * <p>
 * Recorded for logs and accounting only; it changes nothing about how the lease behaves.
 */
public enum MetadataPurpose {
    /** The single authorization statement */
    SNAPSHOT,
    /** The pre-execution audit insert */
    AUDIT,
    /** The check that refuses to delete a user who still holds a grant */
    DELETION_FENCE
}
