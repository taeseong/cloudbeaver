-- DBAC (DB Access Control) fork-owned metadata schema, module CB_DBAC.
-- This schema is versioned independently from the CloudBeaver CE schema (CB_CE).
-- It MUST NOT touch {table_prefix}CB_SCHEMA_INFO.
--
-- Notes for maintainers:
--   * {table_prefix} is a schema qualifier ("<schema>." or ""), substituted before execution.
--   * The migration runner splits this file on ';', so no statement may contain an inner ';'.
--   * Index names are NOT qualified with {table_prefix}: PostgreSQL forbids a schema-qualified
--     index name in CREATE INDEX. Indexes are created in the schema of their table.
--   * Only SQL supported by both H2 and PostgreSQL is used here.
--   * Every statement uses IF NOT EXISTS so the script can be replayed safely. H2 does NOT roll back
--     DDL, so a migration that fails half-way leaves the already created objects behind; the next
--     start must be able to finish the job without manual cleanup. IF NOT EXISTS alone is not
--     sufficient - DbacSchemaValidator additionally verifies the resulting structure.
--   * Where a comment may go, and why it matters. SQLSchemaManager translates the whole file and then
--     splits the result on ';'. The translator drops a comment block that is separated from the next
--     statement by a blank line, and keeps one that sits directly above it as part of that statement.
--     So a comment adjacent to a statement, or inside a column list, is handed to the database - H2
--     rejects a comment between two column definitions outright - and any ';' in such a comment
--     splits the statement in half. Keep explanations in this header block, which is dropped, and
--     keep them free of ';' regardless.
--   * DBAC_TW_CURRENT records which physical database a grant was issued for, in PROVIDER_ID,
--     DRIVER_ID, CONFIGURATION_TYPE, HOST_SNAPSHOT, PORT_SNAPSHOT and DATABASE_SNAPSHOT. All six are
--     compared on every authorization and a difference is GRANT_STALE. All are nullable except
--     DRIVER_ID, because a row written by schema version 2 has no provider, configuration type or
--     port and version 3 does not invent them. Such a row matches no connection and is denied until
--     the grant is issued again.

CREATE TABLE IF NOT EXISTS {table_prefix}DBAC_SCHEMA_INFO
(
    MODULE_ID   VARCHAR(64) NOT NULL,
    VERSION     INTEGER     NOT NULL,
    UPDATE_TIME TIMESTAMP WITH TIME ZONE NOT NULL,

    PRIMARY KEY (MODULE_ID)
);

-- Current TEMP_WRITE state. At most one row per permission key, enforced by the primary key.
CREATE TABLE IF NOT EXISTS {table_prefix}DBAC_TW_CURRENT
(
    USER_ID           VARCHAR(128)  NOT NULL,
    PROJECT_ID        VARCHAR(255)  NOT NULL,
    CONNECTION_ID     VARCHAR(255)  NOT NULL,

    GRANT_ID          VARCHAR(128)  NOT NULL,
    REVISION          BIGINT        NOT NULL,

    GRANTED_BY        VARCHAR(128)  NOT NULL,
    GRANTED_AT TIMESTAMP WITH TIME ZONE NOT NULL,
    EXPIRES_AT TIMESTAMP WITH TIME ZONE NOT NULL,
    REASON            VARCHAR(1000) NOT NULL,

    REVOKED_AT TIMESTAMP WITH TIME ZONE,
    REVOKED_BY        VARCHAR(128),
    REVOKE_REASON     VARCHAR(1000),

    PROVIDER_ID        VARCHAR(128),
    DRIVER_ID          VARCHAR(128) NOT NULL,
    CONFIGURATION_TYPE VARCHAR(32),
    HOST_SNAPSHOT      VARCHAR(255),
    PORT_SNAPSHOT      VARCHAR(16),
    DATABASE_SNAPSHOT  VARCHAR(255),

    PRIMARY KEY (USER_ID, PROJECT_ID, CONNECTION_ID)
);

CREATE INDEX IF NOT EXISTS DBAC_TW_CURRENT_CONN_IDX ON {table_prefix}DBAC_TW_CURRENT (PROJECT_ID, CONNECTION_ID);

-- Append-only history of every current-state change.
CREATE TABLE IF NOT EXISTS {table_prefix}DBAC_TW_HISTORY
(
    EVENT_ID      VARCHAR(128)  NOT NULL,

    GRANT_ID      VARCHAR(128)  NOT NULL,
    CHANGE_TYPE   VARCHAR(16)   NOT NULL,
    CHANGE_TIME TIMESTAMP WITH TIME ZONE NOT NULL,

    USER_ID       VARCHAR(128)  NOT NULL,
    PROJECT_ID    VARCHAR(255)  NOT NULL,
    CONNECTION_ID VARCHAR(255)  NOT NULL,

    ACTOR_ID      VARCHAR(128)  NOT NULL,
    EXPIRES_AT TIMESTAMP WITH TIME ZONE,
    REASON        VARCHAR(1000),
    REVISION      BIGINT        NOT NULL,

    PRIMARY KEY (EVENT_ID)
);

CREATE INDEX IF NOT EXISTS DBAC_TW_HISTORY_USER_IDX ON {table_prefix}DBAC_TW_HISTORY (USER_ID, CHANGE_TIME);

CREATE INDEX IF NOT EXISTS DBAC_TW_HISTORY_CONN_IDX
    ON {table_prefix}DBAC_TW_HISTORY (PROJECT_ID, CONNECTION_ID, CHANGE_TIME);

-- Access-control audit trail.
-- Deliberately has no column for SQL text, SQL parameters, credentials or connection secrets,
-- and no free-form DETAIL column.
CREATE TABLE IF NOT EXISTS {table_prefix}DBAC_AUDIT_EVENT
(
    EVENT_ID           VARCHAR(128) NOT NULL,
    EVENT_TYPE         VARCHAR(32)  NOT NULL,
    EVENT_TIME TIMESTAMP WITH TIME ZONE NOT NULL,

    USER_ID            VARCHAR(128),
    ACTOR_ID           VARCHAR(128),
    PROJECT_ID         VARCHAR(255),
    CONNECTION_ID      VARCHAR(255),
    GRANT_ID           VARCHAR(128),

    OPERATION_CATEGORY VARCHAR(32),
    STATEMENT_TYPE     VARCHAR(32),
    DECISION           VARCHAR(16),
    DENIAL_REASON      VARCHAR(64),
    EXPIRES_AT TIMESTAMP WITH TIME ZONE,

    PRIMARY KEY (EVENT_ID)
);

CREATE INDEX IF NOT EXISTS DBAC_AUDIT_TIME_IDX ON {table_prefix}DBAC_AUDIT_EVENT (EVENT_TIME);

CREATE INDEX IF NOT EXISTS DBAC_AUDIT_USER_IDX ON {table_prefix}DBAC_AUDIT_EVENT (USER_ID, EVENT_TIME);

CREATE INDEX IF NOT EXISTS DBAC_AUDIT_CONN_IDX
    ON {table_prefix}DBAC_AUDIT_EVENT (PROJECT_ID, CONNECTION_ID, EVENT_TIME);
