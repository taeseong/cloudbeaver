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
package io.cloudbeaver.test.platform.dbac;

import io.cloudbeaver.service.dbac.db.DbacSchema;
import io.cloudbeaver.service.dbac.db.DbacSchemaConstants;
import org.jkiss.code.NotNull;
import org.jkiss.dbeaver.ext.h2.model.H2SQLDialect;
import org.jkiss.dbeaver.ext.postgresql.model.PostgreDialect;
import org.jkiss.dbeaver.model.impl.sql.BasicSQLDialect;
import org.jkiss.dbeaver.model.runtime.DBRProgressMonitor;
import org.jkiss.dbeaver.model.runtime.LoggingProgressMonitor;
import org.jkiss.dbeaver.model.sql.SQLDialect;
import org.jkiss.dbeaver.model.sql.SQLDialectDDLExtension;
import org.jkiss.dbeaver.model.sql.schema.ClassLoaderScriptSource;
import org.jkiss.dbeaver.model.sql.schema.SQLSchemaScriptSource;
import org.jkiss.dbeaver.model.sql.translate.SQLQueryTranslator;
import org.jkiss.utils.CommonUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.Reader;
import java.util.List;

/**
 * Characterization of what the production migration pipeline actually sends to each database.
 * <p>
 * {@code SQLSchemaManager.executeScript} does three things in a fixed order, and this test reproduces
 * exactly that order rather than an approximation of it:
 * <ol>
 *     <li>{@code scriptSource.openSchemaCreateScript(monitor, targetDialect.getDialectId())} - the script
 *         is looked up per dialect, so the dialect id must be passed;</li>
 *     <li>{@code CommonUtils.normalizeTableNames(text, databaseConfig.getSchema())} - {@code {table_prefix}}
 *         is substituted as plain text, before translation;</li>
 *     <li>{@code SQLQueryTranslator.translateScript(basicSourceDialect, targetDialect, ...)}.</li>
 * </ol>
 * The recovery design depends on step 3 removing {@code IF NOT EXISTS} on PostgreSQL and keeping it on H2,
 * so that behaviour is pinned here with assertions rather than printed to a log.
 */
public class DbacScriptTranslationTest {

    private static final DBRProgressMonitor MONITOR = new LoggingProgressMonitor();

    /** The exact source dialect {@code SQLSchemaManager.executeScript} constructs. */
    private static final BasicSQLDialect SOURCE_DIALECT = new BasicSQLDialect() {
    };

    /**
     * A schema name that needs no quoting on either database, matching what the module requires at
     * runtime. It is only substituted into the script text; nothing is executed here.
     */
    private static final String TEST_SCHEMA = "dbac_translation_probe";

    private static final int EXPECTED_TABLES = 4;
    private static final int EXPECTED_INDEXES = 6;

    /** The only statement {@code dbac_schema_update_1.sql} may translate to, on either database. */
    private static final String STATELESS_PROBE = "SELECT 1";

    /**
     * PostgreSQL: {@code PostgreDialect.supportsCreateIfExists()} returns true, so
     * {@code SQLQueryTranslator.translateStatement} calls {@code CreateTable.setIfNotExists(false)} and the
     * guard is gone. Replaying the create script over existing tables therefore cannot work on PostgreSQL,
     * which is why {@code DbacSchemaVersionManager} recovers there by recording the version only.
     */
    @Test
    public void postgresTranslationDropsIfNotExistsFromCreateTable() throws Exception {
        SQLDialect dialect = new PostgreDialect();
        Assertions.assertTrue(
            dialect instanceof SQLDialectDDLExtension extension && extension.supportsCreateIfExists(),
            "The whole PostgreSQL recovery design rests on this dialect reporting supportsCreateIfExists()");

        List<String> statements = executableStatements(translateCreateScript(dialect));
        Assertions.assertEquals(
            0, countStartingWith(statements, "CREATE TABLE IF NOT EXISTS"),
            "PostgreDialect must lose IF NOT EXISTS on CREATE TABLE. If this ever changes, "
                + "DbacRecoveryPolicy.VERSION_ROW_ONLY can be reconsidered - but not before. "
                + "Statements: " + statements);
        Assertions.assertEquals(
            EXPECTED_TABLES, countStartingWith(statements, "CREATE TABLE"),
            "Every CREATE TABLE must survive translation");
    }

    /**
     * H2: {@code H2SQLDialect} extends {@code GenericSQLDialect} and does not implement
     * {@code SQLDialectDDLExtension}, so nothing rewrites the statement and replay stays valid there.
     */
    @Test
    public void h2TranslationKeepsIfNotExistsOnCreateTable() throws Exception {
        SQLDialect dialect = new H2SQLDialect();
        Assertions.assertFalse(
            dialect instanceof SQLDialectDDLExtension,
            "H2 must not implement SQLDialectDDLExtension, otherwise the translator would strip "
                + "IF NOT EXISTS and the H2 replay recovery would break");

        List<String> statements = executableStatements(translateCreateScript(dialect));
        Assertions.assertEquals(
            EXPECTED_TABLES, countStartingWith(statements, "CREATE TABLE IF NOT EXISTS"),
            "H2 must keep IF NOT EXISTS on every table - the H2 recovery path replays the create script. "
                + "Statements: " + statements);
    }

    /**
     * {@code CREATE INDEX} is not a {@code CreateTable}, so no branch of the translator rewrites it and the
     * guard survives on both databases.
     */
    @Test
    public void createIndexKeepsIfNotExistsOnBothDialects() throws Exception {
        for (SQLDialect dialect : new SQLDialect[]{new H2SQLDialect(), new PostgreDialect()}) {
            List<String> statements = executableStatements(translateCreateScript(dialect));
            Assertions.assertEquals(
                EXPECTED_INDEXES, countStartingWith(statements, "CREATE INDEX IF NOT EXISTS"),
                "CREATE INDEX IF NOT EXISTS must survive translation for " + dialect.getDialectId()
                    + ". Statements: " + statements);
        }
    }

    /**
     * The parser must not silently drop a statement. Counting the statements that come out is the only
     * thing standing between a reformatted script and a schema that is quietly missing an object.
     */
    @Test
    public void translationKeepsEveryStatement() throws Exception {
        for (SQLDialect dialect : new SQLDialect[]{new H2SQLDialect(), new PostgreDialect()}) {
            List<String> statements = executableStatements(translateCreateScript(dialect));
            Assertions.assertEquals(
                EXPECTED_TABLES, countStartingWith(statements, "CREATE TABLE"),
                "Wrong number of CREATE TABLE statements for " + dialect.getDialectId()
                    + ": " + statements);
            Assertions.assertEquals(
                EXPECTED_INDEXES, countStartingWith(statements, "CREATE INDEX"),
                "Wrong number of CREATE INDEX statements for " + dialect.getDialectId()
                    + ": " + statements);
            Assertions.assertEquals(
                EXPECTED_TABLES + EXPECTED_INDEXES, statements.size(),
                "The runner must end up with exactly one statement per object for " + dialect.getDialectId()
                    + ": " + statements);
        }
    }

    /**
     * {@code {table_prefix}} is substituted before translation and must not appear on either side of it.
     * A leftover placeholder would reach the database verbatim and fail at runtime.
     */
    @Test
    public void noTablePrefixPlaceholderSurvives() throws Exception {
        for (SQLDialect dialect : new SQLDialect[]{new H2SQLDialect(), new PostgreDialect()}) {
            String normalized = normalizedScript(scriptSource().openSchemaCreateScript(
                MONITOR, dialect.getDialectId()));
            Assertions.assertFalse(
                normalized.contains("{table_prefix}"),
                "normalizeTableNames must substitute every placeholder for " + dialect.getDialectId());
            Assertions.assertTrue(
                normalized.contains(TEST_SCHEMA + "."),
                "The substituted schema must appear in the script for " + dialect.getDialectId());

            String translated = SQLQueryTranslator.translateScript(
                SOURCE_DIALECT, dialect, SQLQueryTranslator.getDefaultPreferenceStore(), normalized);
            Assertions.assertFalse(
                translated.contains("{table_prefix}"),
                "Translation must not reintroduce the placeholder for " + dialect.getDialectId());
        }
    }

    /**
     * The version-only recovery path on PostgreSQL only works if an update script for version 1 can be
     * resolved: {@code upgradeSchemaVersion} skips the whole step - including the version write - when
     * {@code openSchemaUpdateScript} returns null, which would leave the schema unversioned forever.
     */
    @Test
    public void updateScriptForVersionOneIsResolvableAndTranslates() throws Exception {
        for (SQLDialect dialect : new SQLDialect[]{new H2SQLDialect(), new PostgreDialect()}) {
            Reader reader = scriptSource().openSchemaUpdateScript(MONITOR, 1, dialect.getDialectId());
            Assertions.assertNotNull(
                reader,
                "dbac_schema_update_1.sql must be resolvable for " + dialect.getDialectId()
                    + ", otherwise PostgreSQL version-only recovery never records a version");

            List<String> statements = executableStatements(SQLQueryTranslator.translateScript(
                SOURCE_DIALECT, dialect, SQLQueryTranslator.getDefaultPreferenceStore(),
                normalizedScript(reader)));

            Assertions.assertEquals(
                1, statements.size(),
                "The version 1 update script must stay a single statement for "
                    + dialect.getDialectId() + ", got: " + statements);
            // Exact equality, not "no DDL". The script exists purely to route PostgreSQL version-only
            // recovery into the upgrade branch, so anything that touches state at all is a defect.
            Assertions.assertEquals(
                STATELESS_PROBE, statements.get(0),
                "The version 1 update script must be exactly '" + STATELESS_PROBE + "' for "
                    + dialect.getDialectId());
            Assertions.assertNull(
                DbacScriptStatements.forbiddenFamilyOf(statements.get(0)),
                "The version 1 update script must not belong to any state changing family");

            // Version 2 is the opposite kind of script and is checked as such: it is real DDL, one
            // statement per column, and it must survive translation with its zoned type intact.
            // Pinned at eight because that is how many time columns the schema has - a lost statement
            // would leave one column naive, which is exactly the defect version 2 removes.
            Reader migrationReader = scriptSource().openSchemaUpdateScript(MONITOR, 2, dialect.getDialectId());
            Assertions.assertNotNull(
                migrationReader,
                "dbac_schema_update_2.sql must be resolvable for " + dialect.getDialectId());
            List<String> migration = executableStatements(SQLQueryTranslator.translateScript(
                SOURCE_DIALECT, dialect, SQLQueryTranslator.getDefaultPreferenceStore(),
                normalizedScript(migrationReader)));
            Assertions.assertEquals(
                8, migration.size(),
                "The version 2 migration must alter every time column for " + dialect.getDialectId()
                    + ", got: " + migration);
            for (String statement : migration) {
                // Either spelling is accepted because the invariant is that the column ends up zoned,
                // not how a dialect renders the type name. Losing the zone entirely is the defect.
                String upper = statement.toUpperCase(java.util.Locale.ROOT);
                Assertions.assertTrue(
                    upper.contains("TIME ZONE") || upper.contains("TIMESTAMPTZ"),
                    "Translation must keep the zoned type for " + dialect.getDialectId()
                        + ", got: " + statement);
            }

            // Version 3 adds the endpoint columns. Pinned at three, and the guard clause has to
            // survive translation: without IF NOT EXISTS a replay - PostgreSQL version-only recovery
            // walks 0 to 3, and the version-1 downgrade fixture leaves a version-3 structure behind a
            // version-1 row - would fail on a column that is already there instead of being a no-op.
            Reader endpointReader = scriptSource().openSchemaUpdateScript(MONITOR, 3, dialect.getDialectId());
            Assertions.assertNotNull(
                endpointReader,
                "dbac_schema_update_3.sql must be resolvable for " + dialect.getDialectId());
            List<String> endpointMigration = executableStatements(SQLQueryTranslator.translateScript(
                SOURCE_DIALECT, dialect, SQLQueryTranslator.getDefaultPreferenceStore(),
                normalizedScript(endpointReader)));
            Assertions.assertEquals(
                3, endpointMigration.size(),
                "The version 3 migration must add every endpoint column for " + dialect.getDialectId()
                    + ", got: " + endpointMigration);
            for (String statement : endpointMigration) {
                String upper = statement.toUpperCase(java.util.Locale.ROOT);
                Assertions.assertTrue(
                    upper.contains("ADD COLUMN IF NOT EXISTS"),
                    "Translation must keep the replay guard for " + dialect.getDialectId()
                        + ", got: " + statement);
                Assertions.assertTrue(
                    upper.contains("DBAC_TW_CURRENT"),
                    "Only the current-state table gains endpoint columns, got: " + statement);
            }
            Assertions.assertTrue(
                endpointMigration.stream().anyMatch(one -> one.toUpperCase(java.util.Locale.ROOT)
                    .contains("PORT_SNAPSHOT")),
                "the port column is the one whose absence allowed the succession, got: "
                    + endpointMigration);
        }
    }

    /**
     * Every version from 1 to the shipped one must have an update script, and the version after it must
     * not.
     * <p>
     * {@code SQLSchemaManager.upgradeSchemaVersion} does {@code if (ddlStream == null) continue;} - a
     * missing script is skipped silently and the version it belongs to is never recorded. The next step
     * then expects a predecessor that was never written, its compare-and-set matches nothing, and the
     * installation is stuck refusing to upgrade for good. Since this fork owns its own script namespace,
     * the cheapest guarantee is to require the chain to be contiguous. The upper bound catches the
     * opposite mistake: adding a script without bumping {@code CURRENT_SCHEMA_VERSION}, which would leave
     * it silently unused.
     */
    @Test
    public void updateScriptChainIsContiguous() throws Exception {
        for (SQLDialect dialect : new SQLDialect[]{new H2SQLDialect(), new PostgreDialect()}) {
            for (int version = 1; version <= DbacSchemaConstants.CURRENT_SCHEMA_VERSION; version++) {
                Reader reader = scriptSource().openSchemaUpdateScript(MONITOR, version, dialect.getDialectId());
                Assertions.assertNotNull(
                    reader,
                    "Missing update script for version " + version + " (" + dialect.getDialectId()
                        + "). A gap makes that version unrecordable and blocks every later upgrade.");
                reader.close();
            }
            Reader beyond = scriptSource().openSchemaUpdateScript(
                MONITOR, DbacSchemaConstants.CURRENT_SCHEMA_VERSION + 1, dialect.getDialectId());
            if (beyond != null) {
                beyond.close();
                Assertions.fail("An update script exists for version "
                    + (DbacSchemaConstants.CURRENT_SCHEMA_VERSION + 1)
                    + " but CURRENT_SCHEMA_VERSION is still "
                    + DbacSchemaConstants.CURRENT_SCHEMA_VERSION + ", so it would never run");
            }
        }
    }

    /**
     * The exact-equality check above is only meaningful if it would actually reject a stateful script.
     * This exercises the same assertion against every forbidden family.
     */
    @Test
    public void statefulUpdateScriptWouldBeRejected() {
        for (String prefix : DbacScriptStatements.FORBIDDEN_STATEMENT_PREFIXES) {
            List<String> statements = executableStatements(prefix + " something;\n");
            Assertions.assertEquals(1, statements.size());
            Assertions.assertNotEquals(
                STATELESS_PROBE, statements.get(0),
                "A " + prefix + " script must not pass the statelessness check");
            Assertions.assertEquals(
                prefix, DbacScriptStatements.forbiddenFamilyOf(statements.get(0)),
                "A " + prefix + " script must be recognised as state changing");
        }
    }

    /**
     * {@code dbac_schema_create.sql} explains the runner in its header comment, and that prose contains
     * semicolons. Since {@code executeScript} splits the translated text on {@code ';'}, a comment that
     * survived translation would shatter into fake statements. This pins that it does not happen.
     */
    @Test
    public void commentSemicolonsDoNotBecomeStatements() throws Exception {
        String raw = rawScript(scriptSource().openSchemaCreateScript(MONITOR, null));
        boolean semicolonInsideComment = false;
        for (String line : raw.split("\n")) {
            if (line.trim().startsWith("--") && line.contains(";")) {
                semicolonInsideComment = true;
                break;
            }
        }
        Assertions.assertTrue(
            semicolonInsideComment,
            "Precondition: the create script must contain a semicolon inside a comment, otherwise this "
                + "test proves nothing. Do not 'fix' the script to make this pass.");
        Assertions.assertTrue(
            raw.split(";").length > EXPECTED_TABLES + EXPECTED_INDEXES,
            "Precondition: splitting the untranslated script yields more pieces than there are objects");

        for (SQLDialect dialect : new SQLDialect[]{new H2SQLDialect(), new PostgreDialect()}) {
            List<String> statements = executableStatements(translateCreateScript(dialect));
            Assertions.assertEquals(
                EXPECTED_TABLES + EXPECTED_INDEXES, statements.size(),
                "Comment text must not survive into executable statements for " + dialect.getDialectId()
                    + ": " + statements);
            for (String statement : statements) {
                Assertions.assertTrue(
                    statement.startsWith("CREATE TABLE") || statement.startsWith("CREATE INDEX"),
                    "Every executed statement must be a real object definition, got: " + statement);
            }
        }
    }

    // ---------------------------------------------------------------- helpers

    @NotNull
    private static SQLSchemaScriptSource scriptSource() {
        return new ClassLoaderScriptSource(
            DbacSchema.class.getClassLoader(),
            DbacSchemaConstants.CREATE_SCRIPT_PATH,
            DbacSchemaConstants.UPDATE_SCRIPT_PREFIX);
    }

    @NotNull
    private static String translateCreateScript(@NotNull SQLDialect targetDialect) throws Exception {
        String normalized = normalizedScript(
            scriptSource().openSchemaCreateScript(MONITOR, targetDialect.getDialectId()));
        return SQLQueryTranslator.translateScript(
            SOURCE_DIALECT, targetDialect, SQLQueryTranslator.getDefaultPreferenceStore(), normalized);
    }

    /** Reads a script and substitutes the placeholder exactly the way the migration runner does. */
    @NotNull
    private static String normalizedScript(@NotNull Reader reader) throws Exception {
        return CommonUtils.normalizeTableNames(rawScript(reader), TEST_SCHEMA);
    }

    @NotNull
    private static String rawScript(@NotNull Reader reader) throws Exception {
        try (Reader r = reader) {
            StringBuilder sb = new StringBuilder();
            char[] buffer = new char[4096];
            int read;
            while ((read = r.read(buffer)) > 0) {
                sb.append(buffer, 0, read);
            }
            return sb.toString();
        }
    }

    /**
     * Splits a translated script the way {@code SQLSchemaManager.executeScript} does.
     * Delegates to {@link DbacScriptStatements}, whose exact behaviour is pinned by
     * {@code DbacScriptStatementsTest} - the instrument these tests measure with is itself tested.
     */
    @NotNull
    private static List<String> executableStatements(@NotNull String translatedScript) {
        return DbacScriptStatements.split(translatedScript);
    }

    private static int countStartingWith(@NotNull List<String> statements, @NotNull String keyword) {
        return DbacScriptStatements.countStartingWith(statements, keyword);
    }
}
