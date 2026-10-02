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
package io.cloudbeaver.service.dbac;

import io.cloudbeaver.model.app.ServletApplication;
import io.cloudbeaver.model.app.ServletAuthApplication;
import io.cloudbeaver.model.config.SMControllerConfiguration;
import io.cloudbeaver.model.config.WebDatabaseConfig;
import io.cloudbeaver.service.dbac.PolicyServiceHolder.CleanupPlan;
import io.cloudbeaver.service.dbac.PolicyServiceHolder.FailureCode;
import io.cloudbeaver.service.dbac.PolicyServiceHolder.Initializing;
import io.cloudbeaver.service.dbac.PolicyServiceHolder.TransitionObserver;
import io.cloudbeaver.service.dbac.db.DbacCBDatabase;
import io.cloudbeaver.service.dbac.db.DbacSchema;
import io.cloudbeaver.service.dbac.policy.DbAccessPolicyConfig;
import io.cloudbeaver.service.dbac.policy.DbAccessPolicyService;
import io.cloudbeaver.service.dbac.policy.enforcement.DeploymentGuard;
import io.cloudbeaver.service.dbac.policy.enforcement.TaintContextCloseHandler;
import io.cloudbeaver.service.security.EmbeddedSecurityControllerFactory;
import io.cloudbeaver.service.security.db.CBDatabase;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.jkiss.dbeaver.DBException;

/**
 * Security controller factory which registers the fork-owned DBAC schema and starts the DBAC policy service
 * <p>
 * The CloudBeaver CE schema config is still added first by {@code CBDatabase}, so CE initialization
 * order and behaviour are unchanged, and the DBAC schema is applied afterwards as a separate module.
 * <p>
 * On top of that this factory owns the lifecycle of the policy service, through the
 * {@link PolicyServiceHolder} it initializes - the server's global one, or a new isolated one for a
 * test. {@link #createAndInitDatabaseInstance} runs once per holder:
 * <ol>
 *     <li>begin the initialization, or refuse with {@code DBException} before the database is even
 *     made if one was ever begun;</li>
 *     <li>let the upstream factory create and initialize the database. {@link #makeDatabase} receives
 *     the initialization token through a private {@code ThreadLocal}, because the upstream signature
 *     cannot carry it, and refuses to make a database outside it. A failure here is the upstream
 *     startup failure: the holder becomes {@code StartupFailed} and the original throwable is
 *     rethrown;</li>
 *     <li>run the deployment guard, build the policy service, register the close handler - in that
 *     order, all before Ready. If any of them refuses or fails with a {@code RuntimeException}, what
 *     was acquired is released at once and the holder becomes {@code Failed}; the database is still
 *     returned, so authentication and reads keep working and it is closed at shutdown;</li>
 *     <li>publish Ready, which is the only way into it.</li>
 * </ol>
 * An {@code Error} in step 3 releases what was acquired, closes the database and rethrows the same
 * {@code Error}. A failure while cleaning up never replaces the original throwable.
 */
public class DbacSecurityControllerFactory<T extends ServletAuthApplication>
    extends EmbeddedSecurityControllerFactory<T> {

    /**
     * Runs the deployment guard for one initialization
     */
    @FunctionalInterface
    public interface Admitter {
        /**
         * Admits or refuses the metadata database, issuing the lease to whoever gets the result
         */
        @NotNull
        DeploymentGuard.Result admit(@NotNull DbacCBDatabase database, @NotNull DeploymentGuard.Revocation revocation);
    }

    /**
     * Builds the policy service over the metadata database
     */
    @FunctionalInterface
    public interface ServiceFactory {
        /**
         * The policy service that reads permissions from {@code database}
         */
        @NotNull
        DbAccessPolicyService create(@NotNull DbacCBDatabase database);
    }

    /**
     * What an isolated factory is built from
     *
     * @param admitter       runs the deployment guard
     * @param registrar      adds and removes the close handler
     * @param sink           where the close handler reports
     * @param serviceFactory builds the policy service
     */
    public record LifecycleSeams(
        @NotNull Admitter admitter,
        @NotNull TaintContextCloseHandler.HandlerRegistrar registrar,
        @NotNull TaintContextCloseHandler.TaintSink sink,
        @NotNull ServiceFactory serviceFactory
    ) {
    }

    private final PolicyServiceHolder holder;
    private final boolean isolated;
    @Nullable
    private final LifecycleSeams seams;
    private final ThreadLocal<Initializing> initToken = new ThreadLocal<>();

    /**
     * The server's factory: it initializes the global holder with the production guard, query manager and service
     */
    public DbacSecurityControllerFactory() {
        this(PolicyServiceHolder.global(), null, false);
    }

    /**
     * An isolated factory, for tests: it always initializes a new holder of its own, never the global one
     */
    protected DbacSecurityControllerFactory(@NotNull TransitionObserver observer, @NotNull LifecycleSeams seams) {
        this(new PolicyServiceHolder(observer), seams, true);
    }

    private DbacSecurityControllerFactory(@NotNull PolicyServiceHolder holder, @Nullable LifecycleSeams seams, boolean isolated) {
        this.holder = holder;
        this.seams = seams;
        this.isolated = isolated;
    }

    /**
     * The holder this factory initializes
     */
    @NotNull
    protected final PolicyServiceHolder holder() {
        return holder;
    }

    @Override
    @NotNull
    protected final CBDatabase createAndInitDatabaseInstance(
        @NotNull T application,
        @NotNull WebDatabaseConfig databaseConfig,
        @NotNull SMControllerConfiguration smConfig
    ) throws DBException {
        Initializing token = holder.beginInit();
        if (token == null) {
            throw new DBException("DBAC does not initialize the metadata database a second time");
        }
        CBDatabase database;
        initToken.set(token);
        try {
            database = super.createAndInitDatabaseInstance(application, databaseConfig, smConfig);
        } catch (DBException e) {
            // The database already closed its pool before rethrowing; nothing else was acquired.
            holder.startupFailed(token, FailureCode.DATABASE_INIT_FAILED);
            throw e;
        } catch (RuntimeException | Error e) {
            abortStartup(token, null, FailureCode.DATABASE_INIT_FAILED);
            throw e;
        } finally {
            initToken.remove();
        }
        DbacCBDatabase created = token.created.get();
        if (created == null || created != database) {
            abortStartup(token, null, FailureCode.DATABASE_INIT_FAILED);
            throw new DBException("DBAC did not create the metadata database it was asked to initialize");
        }
        return admitAndPublish(token, application, created);
    }

    /**
     * Makes the metadata database, only inside this factory's own initialization and only once
     */
    @Override
    @NotNull
    protected final CBDatabase makeDatabase(@NotNull ServletApplication application, @NotNull WebDatabaseConfig databaseConfig) {
        Initializing token = initToken.get();
        if (token == null || token.owner != Thread.currentThread() || holder.current() != token || token.created.get() != null) {
            throw new IllegalStateException("DBAC creates the metadata database only inside its own initialization");
        }
        DbacCBDatabase database = isolated
            ? newDatabase(application, databaseConfig, token.shutdownLifecycle)
            : new DbacCBDatabase(application, databaseConfig, DbacSchema.getSchemaConfigs(), token.shutdownLifecycle);
        if (!token.created.compareAndSet(null, database)) {
            throw new IllegalStateException("DBAC creates one metadata database per initialization");
        }
        return database;
    }

    /**
     * Creates the metadata database of an isolated factory; never called for the server's global holder
     */
    @NotNull
    protected DbacCBDatabase newDatabase(
        @NotNull ServletApplication application,
        @NotNull WebDatabaseConfig databaseConfig,
        @NotNull DbacCBDatabase.ShutdownLifecycle lifecycle
    ) {
        return new DbacCBDatabase(application, databaseConfig, DbacSchema.getSchemaConfigs(), lifecycle);
    }

    /**
     * Steps 3 and 4: guard, service, close handler, then Ready - releasing what was acquired if any fails
     */
    @NotNull
    private CBDatabase admitAndPublish(@NotNull Initializing token, @NotNull T application, @NotNull DbacCBDatabase database) {
        CleanupPlan.Builder pending = CleanupPlan.builder();
        FailureCode step = FailureCode.DEPLOYMENT_CHECK_FAILED;
        DeploymentGuard.Admission admission;
        DbAccessPolicyService service;
        CleanupPlan plan;
        try {
            LifecycleSeams active = seams != null ? seams : productionSeams(application);
            DeploymentGuard.Result result = active.admitter().admit(database, token.revocation);
            if (result instanceof DeploymentGuard.Refused refused) {
                holder.failed(token, database, refused.code());
                return database;
            }
            DeploymentGuard.Admitted admitted = (DeploymentGuard.Admitted) result;
            pending.lease(admitted.leaseRelease());
            admission = admitted.admission();
            step = FailureCode.SERVICE_UNAVAILABLE;
            service = active.serviceFactory().create(database);
            step = FailureCode.QM_HANDLER_UNAVAILABLE;
            TaintContextCloseHandler handler = new TaintContextCloseHandler(active.sink(), () -> holder.accepting(token));
            pending.handler(active.registrar(), handler, active.sink());
            active.registrar().register(handler);
            plan = pending.seal();
        } catch (RuntimeException e) {
            // F4-F6: release at once whatever was acquired; whatever that cleanup hits, the service is Failed
            // and the database is returned (C15 #6). An Error it returns was already logged.
            PolicyServiceHolder.logFailure(PolicyServiceHolder.EVENT_ADMISSION_FAILED, "DBAC policy service did not start", e);
            pending.seal().runAll();
            holder.failed(token, database, step);
            return database;
        } catch (Error e) {
            // F7: release, close the database, StartupFailed, and the same Error goes on (C15 #7, #8)
            PolicyServiceHolder.logFailure(PolicyServiceHolder.EVENT_ADMISSION_FAILED, "DBAC policy service did not start", e);
            abortStartup(token, pending.seal(), step);
            throw e;
        }
        if (holder.ready(token, database, service, admission, plan)) {
            return database;
        }
        // Cannot happen while only this thread changes Initializing; the plan was never published, so run it here.
        PolicyServiceHolder.logEvent(PolicyServiceHolder.EVENT_READY_PUBLISH_FAILED, "DBAC policy service could not be published");
        plan.runAll();
        return database;
    }

    /**
     * Ends a failed startup (C15 #7, #8): pending cleanup, the created database's shutdown, then StartupFailed
     * <p>
     * Every part is attempted. Nothing here throws: what they hit was logged where it happened, and
     * the caller rethrows the original throwable.
     */
    private void abortStartup(@NotNull Initializing token, @Nullable CleanupPlan pending, @NotNull FailureCode code) {
        try {
            if (pending != null) {
                pending.runAll();
            }
        } finally {
            try {
                DbacCBDatabase created = token.created.get();
                if (created != null) {
                    created.shutdown();
                }
            } catch (RuntimeException | Error ignored) {
                // Already logged by the shutdown lifecycle; it must not replace the original throwable.
            } finally {
                holder.startupFailed(token, code);
            }
        }
    }

    @NotNull
    private static LifecycleSeams productionSeams(@NotNull ServletApplication application) {
        DeploymentGuard guard = new DeploymentGuard(DeploymentGuard.Environment.production(application));
        return new LifecycleSeams(
            (database, revocation) -> guard.admit(DeploymentGuard.MetadataTarget.of(database), revocation),
            TaintContextCloseHandler.HandlerRegistrar.QUERY_MANAGER,
            TaintContextCloseHandler.TaintSink.NONE,
            database -> new DbAccessPolicyService(database::openConnection, DbAccessPolicyConfig.defaults())
        );
    }
}
