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
import org.jkiss.code.Nullable;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;

/**
 * One value bound to a metadata statement parameter
 * <p>
 * Only the two kinds the DBAC statements need. A timestamp is normalized to UTC when it is bound, the
 * way the grant repository writes them.
 *
 * @param kind  how it is bound
 * @param value the value; null binds SQL NULL of that kind
 */
record MetadataBinding(@NotNull Kind kind, @Nullable Object value) {

    /** The bindable kinds */
    enum Kind {
        /** Bound with {@code setString}, or {@code setNull(VARCHAR)} */
        STRING,
        /** Bound with {@code setObject(OffsetDateTime at UTC)}, or {@code setNull(TIMESTAMP_WITH_TIMEZONE)} */
        TIMESTAMP_TZ
    }

    @NotNull
    static MetadataBinding string(@Nullable String value) {
        return new MetadataBinding(Kind.STRING, value);
    }

    @NotNull
    static MetadataBinding timestamp(@Nullable OffsetDateTime value) {
        return new MetadataBinding(Kind.TIMESTAMP_TZ, value == null ? null : value.withOffsetSameInstant(ZoneOffset.UTC));
    }
}
