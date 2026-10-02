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
package io.cloudbeaver.service.dbac.db;

import io.cloudbeaver.model.app.ServletApplication;
import io.cloudbeaver.model.config.WebDatabaseConfig;
import io.cloudbeaver.service.security.db.CBDatabase;
import org.jkiss.code.NotNull;
import org.jkiss.dbeaver.model.sql.schema.SQLSchemaConfig;

import java.util.List;

/**
 * The metadata database, tied to the lifecycle of the DBAC policy service
 * <p>
 * Controllers are built per request and all of them close the same database, so the policy
 * service's lifecycle is bound to this object rather than to any controller. The only thing this
 * class adds is {@link #shutdown()}: it hands the shutdown to the {@link ShutdownLifecycle} it was
 * created with, which stops the policy service, releases what it holds, and only then closes the
 * pool. The class does not know the lifecycle holder; it only holds that one capability.
 */
public class DbacCBDatabase extends CBDatabase {

    /**
     * The one thing the policy lifecycle lets this database do: stop it
     * <p>
     * An implementation is bound, when it is created, to one initialization of the policy service.
     * It moves that initialization's state to stopping, runs its cleanup, calls
     * {@code closeDatabase} - which closes the pool - and marks the state disposed. When there is
     * nothing of its own to stop it only calls {@code closeDatabase}. Either way it calls
     * {@code closeDatabase} at most once per initialization, and a call made while another one is
     * stopping returns only after that one has finished. While the initialization is still running,
     * only its own thread may call it; another thread's call throws {@code IllegalStateException}
     * and closes nothing. It never makes the policy service ready.
     */
    @FunctionalInterface
    public interface ShutdownLifecycle {
        /**
         * Stops whatever this lifecycle owns, then closes the database through {@code closeDatabase}
         */
        void shutdown(@NotNull Runnable closeDatabase);
    }

    private final ShutdownLifecycle lifecycle;

    public DbacCBDatabase(
        @NotNull ServletApplication application,
        @NotNull WebDatabaseConfig databaseConfiguration,
        @NotNull List<SQLSchemaConfig> schemaConfigs,
        @NotNull ShutdownLifecycle lifecycle
    ) {
        super(application, databaseConfiguration, schemaConfigs);
        this.lifecycle = lifecycle;
    }

    /**
     * Stops the policy service bound to this database, then closes the pool
     * <p>
     * Final, so that a subclass cannot close the pool without the policy service being stopped
     * first.
     */
    @Override
    public final void shutdown() {
        lifecycle.shutdown(super::shutdown);
    }
}
