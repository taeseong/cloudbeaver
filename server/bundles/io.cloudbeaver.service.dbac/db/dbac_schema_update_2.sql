-- DBAC schema version 2: every time column becomes zoned.
--
-- Why this is a migration and not a note for later.
--
-- Version 1 declared TIMESTAMP, which is TIMESTAMP WITHOUT TIME ZONE: a wall-clock reading with no
-- record of the zone it was rendered in. The value written therefore depends on the session's time
-- zone, and the PostgreSQL driver sets that from the client JVM's default. Two application nodes in
-- different zones would write, and compare, different values for the same instant - so a grant would
-- expire at a different moment depending on which node happened to look. Measured: with
-- -Duser.timezone=UTC the server reports LOCALTIMESTAMP 10:35, with Asia/Seoul 19:35, with
-- America/New_York 06:35, all at the same instant. A single node is not safe either: where the zone
-- observes DST, the wall clock repeats, so 2026-11-01 05:30Z and 06:30Z both store as 01:30 in
-- America/New_York and a grant spanning that hour lives an hour longer than it was granted for.
--
-- The alternative considered was forcing every metadata session to UTC. It was rejected: it can be
-- bypassed. Any code that takes a connection from CBDatabase and uses the repository directly - a
-- future audit writer, a maintenance task, a test - would skip the initialisation and be back to
-- session-relative values, silently. A zoned column cannot be bypassed, because the storage itself
-- carries the instant and no session setting can reinterpret it. Measured on both engines: after
-- changing the session zone, a zoned column reads back as the same instant; a naive one does not.
--
-- Notes for maintainers:
--   * ALTER TABLE ... ALTER COLUMN ... SET DATA TYPE is the SQL standard spelling, and is the one
--     form both H2 2.4.240 and PostgreSQL 16.15 accept. H2 also accepts a bare type, PostgreSQL also
--     accepts TYPE, and neither of those is common to both.
--   * The migration runner splits on ';', so no statement may contain an inner ';'.
--   * Re-running this script is safe on both supported engines. There is no IF NOT EXISTS for a
--     column type, but none is needed: ALTER COLUMN ... SET DATA TYPE names the target type rather
--     than a change to apply, so a column that is already TIMESTAMP WITH TIME ZONE ends in the same
--     state. The script is therefore idempotent in effect, which is what recovery depends on.
--     Pinned by a test on H2 only, where recovery actually depends on it (see below). The same was
--     measured by hand on PostgreSQL 16.15 but nothing in the suite holds it there, so treat that
--     half as an observation rather than a guarantee. Note also that "same state" is about the
--     column, not the work: on PostgreSQL a re-run still takes an ACCESS EXCLUSIVE lock and
--     rewrites the indexes over those columns.
--   * How an interrupted run recovers differs by engine, and both routes end fail-closed:
--       - On PostgreSQL the whole script rolls back on a failure part-way. That is not PostgreSQL
--         being transactional on its own: SQLSchemaManager.updateSchema wraps the run in a
--         JDBCTransaction, which turns auto-commit off, and PostgreSQL puts ALTER TABLE inside that
--         transaction. Both halves are needed, so a change to either invalidates this. On the normal path no permanent half-migrated schema exists, because the database
--         is still at version 1 and the next start runs the script again from the beginning.
--       - H2 does not roll DDL back, so some columns can be left converted. That is recoverable
--         rather than broken: the version row is only written after the whole script succeeds, so it
--         still reads 1, and the next start runs this script again. The statements that already ran
--         are no-ops by the point above, and the remaining columns are converted.
--       - If the version row already reads 2 while the structure does not match - a partial run
--         whose version write somehow landed, a column altered by hand, or a re-run that itself
--         fails - DbacSchemaValidator refuses to start. It expects TIMESTAMP WITH TIME ZONE and
--         names the column that is not. Startup stops rather than proceeding on a schema nobody
--         can describe.
--   * Converting an existing naive value interprets it in the migrating session's zone. That is
--     unavoidable and is the reason to migrate before anything writes rows that matter: at version 1
--     no production code writes DBAC_TW_CURRENT, DBAC_TW_HISTORY or DBAC_AUDIT_EVENT at all, so the
--     only pre-existing value is DBAC_SCHEMA_INFO.UPDATE_TIME, which records when a migration ran and
--     is not used for any decision.

ALTER TABLE {table_prefix}DBAC_SCHEMA_INFO ALTER COLUMN UPDATE_TIME SET DATA TYPE TIMESTAMP WITH TIME ZONE;

ALTER TABLE {table_prefix}DBAC_TW_CURRENT ALTER COLUMN GRANTED_AT SET DATA TYPE TIMESTAMP WITH TIME ZONE;

ALTER TABLE {table_prefix}DBAC_TW_CURRENT ALTER COLUMN EXPIRES_AT SET DATA TYPE TIMESTAMP WITH TIME ZONE;

ALTER TABLE {table_prefix}DBAC_TW_CURRENT ALTER COLUMN REVOKED_AT SET DATA TYPE TIMESTAMP WITH TIME ZONE;

ALTER TABLE {table_prefix}DBAC_TW_HISTORY ALTER COLUMN CHANGE_TIME SET DATA TYPE TIMESTAMP WITH TIME ZONE;

ALTER TABLE {table_prefix}DBAC_TW_HISTORY ALTER COLUMN EXPIRES_AT SET DATA TYPE TIMESTAMP WITH TIME ZONE;

ALTER TABLE {table_prefix}DBAC_AUDIT_EVENT ALTER COLUMN EVENT_TIME SET DATA TYPE TIMESTAMP WITH TIME ZONE;

ALTER TABLE {table_prefix}DBAC_AUDIT_EVENT ALTER COLUMN EXPIRES_AT SET DATA TYPE TIMESTAMP WITH TIME ZONE;
