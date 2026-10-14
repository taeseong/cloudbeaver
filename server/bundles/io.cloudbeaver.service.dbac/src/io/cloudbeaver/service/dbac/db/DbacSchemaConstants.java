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

/**
 * Constants of the fork-owned DBAC (DB access control) metadata schema.
 * <p>
 * This schema is versioned independently from the CloudBeaver CE schema: it has its own
 * module id, its own version table and its own migration script namespace. Nothing here
 * may reference {@code CB_SCHEMA_INFO}.
 */
public final class DbacSchemaConstants {

    /** Module id of this schema. Deliberately different from the CE module id {@code CB_CE}. */
    public static final String SCHEMA_ID = "CB_DBAC";

    /**
     * Version of the schema shipped with this build
     * <p>
     * Version 2 moved every time column from naive {@code TIMESTAMP} to {@code TIMESTAMP WITH TIME
     * ZONE}. A naive column stores whatever wall clock the writing session rendered, so the same
     * instant is stored differently by nodes in different time zones and a grant expires at a
     * different moment depending on which node looks. See {@code db/dbac_schema_update_2.sql}.
     * <p>
     * Version 3 added {@code PROVIDER_ID}, {@code CONFIGURATION_TYPE} and {@code PORT_SNAPSHOT} to
     * {@code DBAC_TW_CURRENT}. Version 2 recorded only driver, host and database, which let a grant
     * survive a port change - the same host and database on a different server instance - and let a
     * connection be switched to a custom JDBC URL, after which the host and database columns stop
     * describing the target at all. The three columns are nullable and the migration leaves them
     * empty on purpose: a version 2 grant was issued without these checks, so it is denied until it
     * is granted again rather than being blessed by a migration. See
     * {@code db/dbac_schema_update_3.sql} and {@code docs/db-access-control-endpoint-identity.md}.
     * <p>
     * Version 4 changes no structure. It marks the start of the user-incarnation fence era, see
     * {@link #USER_FENCE_SINCE_VERSION}: recording it revokes every grant that is not already revoked,
     * in the same transaction, and from then on a user cannot be deleted while holding a live grant
     * and a grant cannot be issued to a user that does not exist. A version 3 build refuses to start on
     * a version 4 database, so there is no going back without restoring a backup taken before the
     * upgrade. See {@code db/dbac_schema_update_4.sql}.
     */
    public static final int CURRENT_SCHEMA_VERSION = 4;

    /**
     * The first schema version whose database is guarded by the user-incarnation fences
     * <p>
     * CloudBeaver gives a user nothing that tells one incarnation of an id from the next, so a grant
     * left behind by a deleted user would be inherited by whoever is created under the same id. Three
     * things close that together, and all three refer to this constant so they cannot drift apart:
     * <ul>
     *     <li>the version manager, which revokes every legacy grant in the transaction that records this
     *     version - nothing written before the fences existed is trusted;</li>
     *     <li>the deletion fence in the DBAC security controller, which refuses to delete a user who still
     *     holds a grant that is neither revoked nor expired;</li>
     *     <li>the grant fence in the TEMP_WRITE coordinator, which issues a grant only while holding the
     *     user's read lock and only to a user that exists.</li>
     * </ul>
     * A build that records this version without the two fences would claim an invariant it does not
     * keep, which is why the migration and the fences ship as one change.
     */
    public static final int USER_FENCE_SINCE_VERSION = 4;

    /**
     * No version is considered obsolete: drop+recreate of this schema is never allowed.
     * <p>
     * This must stay 0. {@code SQLSchemaManager.updateSchema} only enters its {@code dropSchema} branch
     * when {@code schemaVersionObsolete > 0}, and that branch executes {@code DROP ALL OBJECTS}. Raising
     * this value would additionally make {@link #RECOVERY_PENDING_VERSION} drop the whole database.
     */
    public static final int OBSOLETE_SCHEMA_VERSION = 0;

    public static final String CREATE_SCRIPT_PATH = "db/dbac_schema_create";
    public static final String UPDATE_SCRIPT_PREFIX = "db/dbac_schema_update_";

    /** Version table of this module. It is NOT {@code CB_SCHEMA_INFO}. */
    public static final String VERSION_TABLE_NAME = "DBAC_SCHEMA_INFO";

    public static final String TABLE_TW_CURRENT = "DBAC_TW_CURRENT";
    public static final String TABLE_TW_HISTORY = "DBAC_TW_HISTORY";
    public static final String TABLE_AUDIT_EVENT = "DBAC_AUDIT_EVENT";

    /**
     * Value {@link org.jkiss.dbeaver.model.sql.schema.SQLSchemaVersionManager} must return so that
     * {@code SQLSchemaManager} runs the create script instead of an upgrade.
     */
    public static final int SCHEMA_NOT_PRESENT = -1;

    /**
     * Logical version reported when the structure is complete but the version row was lost.
     * <p>
     * It is never stored in {@link #VERSION_TABLE_NAME}; a stored 0 is rejected as unsupported. It exists
     * only to route {@code SQLSchemaManager} into its upgrade branch, which runs
     * {@code dbac_schema_update_1.sql} and then records the version in a transaction it commits itself.
     * Writing the row directly from {@code getCurrentSchemaVersion} would not work: the platform rolls that
     * transaction back immediately afterwards.
     */
    public static final int RECOVERY_PENDING_VERSION = 0;

    /**
     * Lowest version that may ever be written to {@link #VERSION_TABLE_NAME}.
     * <p>
     * {@link #RECOVERY_PENDING_VERSION} sits below it on purpose: it is an in-memory signal to
     * {@code SQLSchemaManager} and must never reach the table, because a stored 0 is rejected as
     * unsupported on the next start.
     */
    public static final int MINIMUM_STORED_VERSION = 1;

    private DbacSchemaConstants() {
        // constants only
    }
}
