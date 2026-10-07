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

import io.cloudbeaver.app.CEAppStarter;
import io.cloudbeaver.service.dbac.DbacEmbeddedSecurityController;
import io.cloudbeaver.service.dbac.DbacEmbeddedSecurityController.SubjectKind;
import io.cloudbeaver.service.dbac.tempwrite.MetadataConnectionSource;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteGrant;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteGrantRepository;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteMutationCoordinator;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteMutationStatus;
import io.cloudbeaver.service.dbac.tempwrite.TempWritePermissionKey;
import io.cloudbeaver.service.security.db.CBDatabase;
import io.cloudbeaver.test.platform.dbac.KeyLockTestSupport.UserDb;
import org.jkiss.code.NotNull;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * P4 identity characterization: what the metadata databases treat as one key, one user, one team
 * <p>
 * The lock registry keys a grant by its three strings and a user by its id, exactly as given - no
 * case folding, trimming or normalisation. That is only sound if the metadata database never treats
 * two different strings as the same row, because then a writer and a reader of one row could hold
 * two different locks. These tests pin that on H2 and PostgreSQL. A failure here is stop condition
 * S1/S2: the lock identity would have to be redesigned around the database's own comparison.
 * <p>
 * Subjects are checked on H2 against the real CloudBeaver schema (an isolated metadata database)
 * and on PostgreSQL against the four tables the subject lookup depends on, created from the
 * product's own {@code cb_schema_create.sql}. The DBAC controller itself is not run on a PostgreSQL
 * metadata database: that integration is NOT VERIFIED.
 */
public class LockIdentityCharacterizationTest {

    private static final String PG_DBAC_SCHEMA = "dbac_pg_keyident";
    private static final String PG_CB_SCHEMA = "dbac_pg_cbident";
    private static final List<String> CB_TABLES = List.of("CB_AUTH_SUBJECT", "CB_CREDENTIALS_PROFILE", "CB_USER", "CB_TEAM");
    private static final Pattern CREATE_TABLE = Pattern.compile("^CREATE TABLE \\{table_prefix}(\\w+)\\s*\\(", Pattern.DOTALL);
    private static final String PROJECT = "id-project";
    private static final String CONNECTION = "id-connection";

    private static UserDb h2;

    private final TempWriteGrantRepository repository = new TempWriteGrantRepository();
    private final List<TempWritePermissionKey> touched = Collections.synchronizedList(new ArrayList<>());

    @BeforeAll
    public static void prepare() throws Exception {
        CEAppStarter.startServerIfNotStarted();
        EnforcementTestSupport.requirePostgres(KeyLockTestSupport.MONITOR);
        KeyLockTestSupport.installDbacSchema(PG_DBAC_SCHEMA);
        KeyLockTestSupport.createSchema(PG_CB_SCHEMA);
        try (Connection connection = KeyLockTestSupport.openPostgres(PG_CB_SCHEMA)) {
            for (String ddl : cbTableDdl()) {
                try (PreparedStatement dbStat = connection.prepareStatement(ddl)) {
                    dbStat.execute();
                }
            }
        }
        h2 = UserDb.open();
    }

    @AfterAll
    public static void cleanUp() throws Exception {
        try {
            if (h2 != null) {
                h2.close();
            }
        } finally {
            KeyLockTestSupport.dropSchema(PG_DBAC_SCHEMA);
            KeyLockTestSupport.dropSchema(PG_CB_SCHEMA);
            Assertions.assertEquals(0, KeyLockTestSupport.countSchemas(PG_DBAC_SCHEMA), "FIXTURE: the DBAC schema was left behind");
            Assertions.assertEquals(0, KeyLockTestSupport.countSchemas(PG_CB_SCHEMA), "FIXTURE: the CB schema was left behind");
        }
    }

    @AfterEach
    public void forgetKeys() throws Exception {
        for (MetadataConnectionSource source : grantSources().values()) {
            try (Connection connection = source.openConnection()) {
                for (TempWritePermissionKey key : new ArrayList<>(touched)) {
                    TempWriteTestSupport.deleteKey(connection, key);
                }
            }
        }
        touched.clear();
    }

    @NotNull
    private static Map<String, MetadataConnectionSource> grantSources() {
        Map<String, MetadataConnectionSource> sources = new LinkedHashMap<>();
        sources.put("H2", () -> EnforcementTestSupport.metadata().openConnection());
        sources.put("PostgreSQL", () -> KeyLockTestSupport.openPostgres(PG_DBAC_SCHEMA));
        return sources;
    }

    /**
     * ID-1: grant keys that differ only in case, a trailing space or Unicode normalisation are different rows
     */
    @Test
    public void id1GrantKeysThatDifferAtAllAreDifferentRows() throws Exception {
        for (Map.Entry<String, MetadataConnectionSource> engine : grantSources().entrySet()) {
            String label = "ID-1 [" + engine.getKey() + "]";
            String n = Long.toHexString(System.nanoTime());
            List<TempWritePermissionKey> keys = List.of(
                remember(new TempWritePermissionKey("dbac-p4-id-alice-" + n, PROJECT, CONNECTION)),
                remember(new TempWritePermissionKey("dbac-p4-id-Alice-" + n, PROJECT, CONNECTION)),
                remember(new TempWritePermissionKey("dbac-p4-id-u1-" + n, PROJECT, CONNECTION)),
                remember(new TempWritePermissionKey("dbac-p4-id-u1-" + n + " ", PROJECT, CONNECTION)),
                remember(new TempWritePermissionKey("dbac-p4-id-café-" + n, PROJECT, CONNECTION)),
                remember(new TempWritePermissionKey("dbac-p4-id-café-" + n, PROJECT, CONNECTION)),
                remember(new TempWritePermissionKey("dbac-p4-id-conn-" + n, PROJECT, "Conn-" + n)),
                remember(new TempWritePermissionKey("dbac-p4-id-conn-" + n, PROJECT, "conn-" + n)));
            TempWriteMutationCoordinator coordinator = TempWriteMutationCoordinator.withoutAuditing(engine.getValue(), repository);
            for (TempWritePermissionKey key : keys) {
                Assertions.assertEquals(TempWriteMutationStatus.COMMITTED, coordinator.grant(TempWriteTestSupport.grantRequest(
                        key, TempWriteGrant.NO_ROW_REVISION, TempWriteTestSupport.DEFAULT_DURATION, "identity")).status(),
                    label + ": a grant for '" + key.userId() + "'/'" + key.connectionId() + "' must find no existing row");
            }
            try (Connection connection = engine.getValue().openConnection()) {
                for (TempWritePermissionKey key : keys) {
                    Assertions.assertEquals(1, TempWriteTestSupport.countCurrent(connection, key), label + ": one row per exact key");
                    Assertions.assertEquals(key, repository.findCurrent(connection, key).orElseThrow().key(),
                        label + ": a lookup must return exactly the key asked for");
                }
            }
        }
    }

    /**
     * ID-2: the subject-type lookup DBAC uses gives the same answer on H2 and PostgreSQL, and matches ids exactly
     */
    @Test
    public void id2SubjectTypeAndIdentityAgreeOnH2AndPostgres() throws Exception {
        String n = Long.toHexString(System.nanoTime());
        String user = "dbac-p4-sub-alice-" + n;
        String team = "dbac-p4-sub-Alice-" + n;
        String unknown = "dbac-p4-sub-x-" + n;
        String composed = "dbac-p4-sub-café-" + n;
        Map<String, String> subjects = new LinkedHashMap<>();
        subjects.put(user, "U");
        subjects.put(team, "R");
        subjects.put(unknown, "X");
        subjects.put(composed, "U");
        Map<String, SubjectKind> expected = new LinkedHashMap<>();
        expected.put(user, SubjectKind.USER);
        expected.put(team, SubjectKind.TEAM);
        expected.put(unknown, SubjectKind.UNKNOWN);
        expected.put(composed, SubjectKind.USER);
        expected.put("dbac-p4-sub-ALICE-" + n, SubjectKind.MISSING);
        expected.put(user + " ", SubjectKind.MISSING);
        expected.put(" " + user, SubjectKind.MISSING);
        expected.put("dbac-p4-sub-café-" + n, SubjectKind.MISSING);

        for (Map.Entry<String, String> subject : subjects.entrySet()) {
            h2.insertRawSubject(subject.getKey(), subject.getValue());
        }
        Map<String, SubjectKind> onH2;
        try (Connection connection = h2.database.plain()) {
            onH2 = kinds(connection, expected.keySet());
        }
        Map<String, SubjectKind> onPostgres;
        try (Connection connection = KeyLockTestSupport.openPostgres(PG_CB_SCHEMA)) {
            for (Map.Entry<String, String> subject : subjects.entrySet()) {
                insertSubject(connection, subject.getKey(), subject.getValue());
            }
            onPostgres = kinds(connection, expected.keySet());
            Assertions.assertTrue(deterministicSubjectIdCollation(connection),
                "ID-2: PostgreSQL must compare CB_AUTH_SUBJECT.SUBJECT_ID with a deterministic collation");
        }
        Assertions.assertEquals(expected, onH2, "ID-2: the subject kinds on H2");
        Assertions.assertEquals(expected, onPostgres, "ID-2: the subject kinds on PostgreSQL");
    }

    /**
     * ID-3: a blank id is an ordinary value - not NULL, and distinct from another blank - on both engines
     */
    @Test
    public void id3BlankIdsAreOrdinaryDistinctValues() throws Exception {
        h2.insertRawSubject("", "U");
        h2.insertRawSubject(" ", "R");
        try {
            try (Connection connection = h2.database.plain()) {
                checkBlanks("ID-3 [H2]", connection);
            }
        } finally {
            try (Connection connection = h2.database.plain()) {
                deleteSubject(connection, "");
                deleteSubject(connection, " ");
            }
        }
        try (Connection connection = KeyLockTestSupport.openPostgres(PG_CB_SCHEMA)) {
            insertSubject(connection, "", "U");
            insertSubject(connection, " ", "R");
            checkBlanks("ID-3 [PostgreSQL]", connection);
        }
    }

    private static void checkBlanks(@NotNull String label, @NotNull Connection connection) throws SQLException {
        Assertions.assertEquals(SubjectKind.USER, DbacEmbeddedSecurityController.readSubjectKind(connection, ""),
            label + ": the empty id is its own subject");
        Assertions.assertEquals(SubjectKind.TEAM, DbacEmbeddedSecurityController.readSubjectKind(connection, " "),
            label + ": a single space is another subject");
        Assertions.assertEquals(SubjectKind.MISSING, DbacEmbeddedSecurityController.readSubjectKind(connection, "  "),
            label + ": two spaces are a third, absent, subject");
        Assertions.assertEquals(0, scalar(connection, "SELECT COUNT(*) FROM {table_prefix}CB_AUTH_SUBJECT WHERE SUBJECT_ID IS NULL"),
            label + ": a blank id is not stored as NULL");
    }

    // ---------------------------------------------------------------- helpers

    @NotNull
    private TempWritePermissionKey remember(@NotNull TempWritePermissionKey key) {
        touched.add(key);
        return key;
    }

    @NotNull
    private static Map<String, SubjectKind> kinds(@NotNull Connection connection, @NotNull Iterable<String> ids) throws SQLException {
        Map<String, SubjectKind> kinds = new LinkedHashMap<>();
        for (String id : ids) {
            kinds.put(id, DbacEmbeddedSecurityController.readSubjectKind(connection, id));
        }
        return kinds;
    }

    private static void insertSubject(@NotNull Connection connection, @NotNull String id, @NotNull String type) throws SQLException {
        try (PreparedStatement dbStat = connection.prepareStatement(
            "INSERT INTO {table_prefix}CB_AUTH_SUBJECT(SUBJECT_ID,SUBJECT_TYPE,IS_SECRET_STORAGE) VALUES(?,?,'N')")) {
            dbStat.setString(1, id);
            dbStat.setString(2, type);
            dbStat.executeUpdate();
        }
    }

    private static void deleteSubject(@NotNull Connection connection, @NotNull String id) throws SQLException {
        try (PreparedStatement dbStat = connection.prepareStatement("DELETE FROM {table_prefix}CB_AUTH_SUBJECT WHERE SUBJECT_ID=?")) {
            dbStat.setString(1, id);
            dbStat.executeUpdate();
        }
    }

    private static int scalar(@NotNull Connection connection, @NotNull String sql) throws SQLException {
        try (PreparedStatement dbStat = connection.prepareStatement(sql);
             ResultSet dbResult = dbStat.executeQuery()) {
            dbResult.next();
            return dbResult.getInt(1);
        }
    }

    private static boolean deterministicSubjectIdCollation(@NotNull Connection connection) throws SQLException {
        try (PreparedStatement dbStat = connection.prepareStatement(
            "SELECT c.collisdeterministic FROM pg_attribute a"
                + " JOIN pg_class t ON t.oid = a.attrelid"
                + " JOIN pg_namespace ns ON ns.oid = t.relnamespace"
                + " JOIN pg_collation c ON c.oid = a.attcollation"
                + " WHERE ns.nspname = ? AND t.relname = 'cb_auth_subject' AND a.attname = 'subject_id'")) {
            dbStat.setString(1, PG_CB_SCHEMA);
            try (ResultSet dbResult = dbStat.executeQuery()) {
                Assertions.assertTrue(dbResult.next(), "FIXTURE: the SUBJECT_ID collation was not found");
                return dbResult.getBoolean(1);
            }
        }
    }

    /** The product's own DDL for the tables the subject lookup depends on, in script order */
    @NotNull
    private static List<String> cbTableDdl() throws Exception {
        String script;
        try (InputStream in = CBDatabase.class.getClassLoader().getResourceAsStream("db/cb_schema_create.sql")) {
            Assertions.assertNotNull(in, "FIXTURE: cb_schema_create.sql was not found");
            script = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        List<String> statements = new ArrayList<>();
        for (String raw : script.split(";")) {
            String statement = raw.lines()
                .filter(line -> !line.trim().startsWith("--"))
                .collect(Collectors.joining("\n"))
                .trim();
            Matcher matcher = CREATE_TABLE.matcher(statement);
            if (matcher.find() && CB_TABLES.contains(matcher.group(1))) {
                statements.add(statement);
            }
        }
        Assertions.assertEquals(CB_TABLES.size(), statements.size(), "FIXTURE: not every needed table was found in cb_schema_create.sql");
        return statements;
    }
}
