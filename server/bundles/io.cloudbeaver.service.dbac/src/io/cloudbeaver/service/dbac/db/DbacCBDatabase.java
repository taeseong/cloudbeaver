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
import io.cloudbeaver.service.dbac.policy.BoundedMetadataConnections;
import io.cloudbeaver.service.dbac.policy.MetadataLeaseSource;
import io.cloudbeaver.service.security.db.CBDatabase;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.jkiss.dbeaver.Log;
import org.jkiss.dbeaver.model.sql.schema.SQLSchemaConfig;

import java.util.List;
import java.util.UUID;

/**
 * The metadata database, tied to the lifecycle of the DBAC policy service
 * <p>
 * Controllers are built per request and all of them close the same database, so the policy
 * service's lifecycle is bound to this object rather than to any controller. The only thing this
 * class adds is {@link #shutdown()}: it hands the shutdown to the {@link ShutdownLifecycle} it was
 * created with, which stops the policy service, releases what it holds, and only then closes the
 * pool. The class does not know the lifecycle holder; it only holds that one capability.
 * <p>
 * <b>It also owns the bounded metadata source.</b> Every DBAC metadata lease comes from the one
 * {@link BoundedMetadataConnections} this database creates in its constructor, over its own
 * {@code openConnection()}. Consumers get {@link #metadataLeases()}; the shutdown half stays here and
 * runs around the pool close, inside the same close runnable: {@code beginClose}, then the pool,
 * then {@code finishClose}.
 */
public class DbacCBDatabase extends CBDatabase {

    private static final Log log = Log.getLog(DbacCBDatabase.class);

    /** {@code beginClose} of the metadata source failed */
    static final String EVENT_METADATA_BEGIN_CLOSE_FAILED = "DBAC_METADATA_BEGIN_CLOSE_FAILED";
    /**
     * The pool close failed
     * <p>
     * The same code the lifecycle uses for a failed close runnable, so a pool close failure is logged
     * under one code wherever it is caught, and exactly once.
     */
    static final String EVENT_DATABASE_CLOSE_FAILED_IN_DB = "DBAC_LIFECYCLE_DATABASE_CLOSE_FAILED";
    /** {@code finishClose} of the metadata source failed */
    static final String EVENT_METADATA_FINISH_CLOSE_FAILED = "DBAC_METADATA_FINISH_CLOSE_FAILED";

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
    /** Both halves, for the life of this database: the leases it lends and the shutdown it alone runs */
    private final BoundedMetadataConnections.Owned metadata;

    public DbacCBDatabase(
        @NotNull ServletApplication application,
        @NotNull WebDatabaseConfig databaseConfiguration,
        @NotNull List<SQLSchemaConfig> schemaConfigs,
        @NotNull ShutdownLifecycle lifecycle
    ) {
        this(application, databaseConfiguration, schemaConfigs, lifecycle, BoundedMetadataConnections.Tuning.PRODUCTION);
    }

    /**
     * The same, with chosen metadata timings; a test passes a probe here
     */
    protected DbacCBDatabase(
        @NotNull ServletApplication application,
        @NotNull WebDatabaseConfig databaseConfiguration,
        @NotNull List<SQLSchemaConfig> schemaConfigs,
        @NotNull ShutdownLifecycle lifecycle,
        @NotNull BoundedMetadataConnections.Tuning metadataTuning
    ) {
        super(application, databaseConfiguration, schemaConfigs);
        this.lifecycle = lifecycle;
        // Dispatched to this object's openConnection() when a worker borrows, never during construction.
        this.metadata = BoundedMetadataConnections.create(this::openConnection, metadataTuning);
    }

    /**
     * Where every DBAC metadata lease comes from
     * <p>
     * The same source for the life of this database. It refuses once the database has begun to shut down.
     */
    @NotNull
    public MetadataLeaseSource metadataLeases() {
        return metadata.leases();
    }

    /**
     * Stops the policy service bound to this database, then closes the metadata source around the pool
     * <p>
     * Final, so that a subclass cannot close the pool without the policy service being stopped
     * first.
     */
    @Override
    public final void shutdown() {
        lifecycle.shutdown(this::closeMetadataAndPool);
    }

    /**
     * The close runnable: the metadata source's {@code beginClose}, the pool, its {@code finishClose}
     * <p>
     * Every step is attempted whatever the steps before it threw. A {@code RuntimeException} is logged
     * and goes no further; an {@code Error} is logged and the first one is rethrown once all three
     * steps have run, so a later {@code Error} never replaces an earlier one and a
     * {@code RuntimeException} never wins over an {@code Error}. The lifecycle runs this once per
     * initialization, and passes a rethrown {@code Error} on after the holder is disposed.
     */
    private void closeMetadataAndPool() {
        BoundedMetadataConnections.Shutdown shutdown = metadata.shutdown();
        Error firstError = null;
        firstError = phase(EVENT_METADATA_BEGIN_CLOSE_FAILED, shutdown::beginClose, firstError, true);
        firstError = phase(EVENT_DATABASE_CLOSE_FAILED_IN_DB, this::closePool, firstError, false);
        firstError = phase(EVENT_METADATA_FINISH_CLOSE_FAILED, shutdown::finishClose, firstError, true);
        if (firstError != null) {
            throw firstError;
        }
    }

    private void closePool() {
        super.shutdown();
    }

    /**
     * Runs one step, keeping the first {@code Error}
     *
     * @param logRethrownError whether an {@code Error} that becomes the one rethrown is logged here too.
     *     Not for the pool: the lifecycle logs what this runnable throws under the same code, and a pool
     *     close failure is logged once.
     */
    @Nullable
    private static Error phase(@NotNull String eventCode, @NotNull Runnable step, @Nullable Error firstError, boolean logRethrownError) {
        try {
            step.run();
        } catch (RuntimeException e) {
            logFailure(eventCode, e);
        } catch (Error e) {
            if (firstError != null || logRethrownError) {
                logFailure(eventCode, e);
            }
            return firstError == null ? e : firstError;
        }
        return firstError;
    }

    /**
     * Records a failure by event code, a new correlation id and the exception class, never its message or trace
     */
    private static void logFailure(@NotNull String eventCode, @NotNull Throwable failure) {
        try {
            log.error("DBAC metadata database close step failed [event=" + eventCode
                + " EVENT_ID=" + UUID.randomUUID()
                + " exception=" + failure.getClass().getName() + "]");
        } catch (RuntimeException | Error ignored) {
            // Deliberately nothing: the shutdown must not depend on whether it could be logged.
        }
    }
}
