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
import io.cloudbeaver.model.app.ServletApplication;
import io.cloudbeaver.model.config.WebDatabaseConfig;
import io.cloudbeaver.service.dbac.PolicyServiceHolder;
import io.cloudbeaver.service.dbac.PolicyServiceHolder.Disposed;
import io.cloudbeaver.service.dbac.PolicyServiceHolder.Failed;
import io.cloudbeaver.service.dbac.PolicyServiceHolder.FailureCode;
import io.cloudbeaver.service.dbac.PolicyServiceHolder.Ready;
import io.cloudbeaver.service.dbac.db.DbacCBDatabase;
import io.cloudbeaver.service.dbac.db.DbacSchema;
import io.cloudbeaver.service.dbac.policy.enforcement.DeploymentGuard;
import io.cloudbeaver.service.security.EmbeddedSecurityControllerFactory;
import io.cloudbeaver.service.security.db.CBDatabase;
import io.cloudbeaver.test.platform.dbac.LifecycleTestSupport.Captured;
import io.cloudbeaver.test.platform.dbac.LifecycleTestSupport.Fixture;
import io.cloudbeaver.test.platform.dbac.LifecycleTestSupport.TestFactory;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.jkiss.dbeaver.model.DBPConnectionInformation;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLTimeoutException;
import java.sql.Statement;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * P3: the deployment guard - what it admits, what it refuses, and the PostgreSQL advisory lock it holds
 * <p>
 * The guard is exercised directly with a described metadata target wherever the database itself is
 * not the point, and through an isolated lifecycle where it is (DG-1, DG-13). The PostgreSQL cases
 * hold and lose a real session-level advisory lock on the test database; with
 * {@code -Ddbac.test.postgres.required=true} an unreachable PostgreSQL fails the class instead of
 * skipping it. DG-12 (the guard runs before the global write lock on every write-gated sequence)
 * needs the P6 gate and is not here.
 * <p>
 * DG-14 - DG-20 (P6-0, R23): a lock session whose connection stops answering is not taken for lost while the
 * backend the guard remembered still holds the exact DBAC lock; only a remembered backend that no longer holds it
 * lets the guard take the lock again or, when another session has it, fail the service. DG-21 (P6-0 H-1): the
 * remembered backend is its pid together with when it started, so a reused pid is not taken for the owner.
 */
public class DeploymentGuardTest {

    private static final String URL = System.getProperty(
        "dbac.test.postgres.url", "jdbc:postgresql://localhost:55432/dbactest");
    private static final String USER = System.getProperty("dbac.test.postgres.user", "postgres");
    private static final String PASSWORD = System.getProperty("dbac.test.postgres.password", "dbactest");

    /** When true, an unreachable PostgreSQL fails the run instead of skipping it */
    private static final boolean REQUIRED =
        Boolean.parseBoolean(System.getProperty("dbac.test.postgres.required", "false"));

    private static final String H2_FILE_URL = "jdbc:h2:/srv/cloudbeaver/workspace/.data/cb.h2v2.dat";
    private static final String H2_MEMORY_URL = "jdbc:h2:mem:testdb";
    /** What the bundled H2 2.1.214 reports as its product version */
    private static final String H2_V2_RELEASE = "2.1.214 (2022-06-13)";
    private static final long TIMEOUT_SECONDS = 20;

    private static Driver driver;
    private static boolean available;
    private static String unusableBecause;

    @BeforeAll
    public static void prepare() throws Exception {
        CEAppStarter.startServerIfNotStarted();
        available = probe();
        if (!available && REQUIRED) {
            Assertions.fail("POSTGRESQL NOT VERIFIED: " + URL + " could not be used and the run required it - " + unusableBecause);
        }
    }

    // ---------------------------------------------------------------- G1

    /**
     * DG-1: without an exact acknowledgement the service fails, and the database it was given keeps serving reads
     */
    @Test
    public void dg1UnacknowledgedDeploymentFailsButKeepsTheDatabaseReadable() throws Exception {
        Fixture fixture = new Fixture();
        DeploymentGuard unacknowledged = new DeploymentGuard(environment(null, true));
        TestFactory factory = fixture.factory((database, revocation) ->
            unacknowledged.admit(DeploymentGuard.MetadataTarget.of(database), revocation));
        factory.realDatabase = true;
        CBDatabase database = factory.init();
        try {
            Failed failed = Assertions.assertInstanceOf(Failed.class, factory.state(),
                "DG-1: a missing dbac.deployment must leave the policy service Failed");
            Assertions.assertEquals(FailureCode.DEPLOYMENT_NOT_ACKNOWLEDGED, failed.code(), "DG-1: the failure code");
            Assertions.assertSame(database, failed.database(), "DG-1: the database must be returned");
            try (Connection connection = database.openConnection();
                 Statement statement = connection.createStatement();
                 ResultSet result = statement.executeQuery("SELECT 1")) {
                Assertions.assertTrue(result.next(), "DG-1: the database must keep serving reads");
            }
        } finally {
            database.shutdown();
        }

        List<String> violations = new ArrayList<>();
        for (String value : new String[]{null, "", " test", "test ", "TEST", "Test", "single_process", "single-process ",
            "SINGLE-PROCESS", "production", "multi-node"}) {
            DeploymentGuard.Result result = new DeploymentGuard(environment(value, true))
                .admit(h2Target(H2_MEMORY_URL), new RecordingRevocation());
            if (!(result instanceof DeploymentGuard.Refused refused && refused.code() == FailureCode.DEPLOYMENT_NOT_ACKNOWLEDGED)) {
                violations.add("dbac.deployment=" + quote(value) + " must be refused, got " + result);
            }
        }
        expectAdmitted(new DeploymentGuard(environment(DeploymentGuard.MODE_SINGLE_PROCESS, false)), h2Target(H2_FILE_URL),
            "single-process with a local H2 file", violations);
        expectAdmitted(new DeploymentGuard(environment(DeploymentGuard.MODE_TEST, true)), h2Target(H2_MEMORY_URL),
            "test with the test bundle", violations);
        Assertions.assertEquals(List.of(), violations, "DG-1: only the exact values single-process and test are acknowledgements");

        AtomicReference<String> property = new AtomicReference<>(DeploymentGuard.MODE_TEST);
        RecordingRevocation recorded = new RecordingRevocation();
        DeploymentGuard.Result watched = new DeploymentGuard(new DeploymentGuard.Environment(property::get, () -> null, () -> true,
            () -> false, () -> false)).admit(h2Target(H2_MEMORY_URL), recorded);
        DeploymentGuard.Admitted admitted = Assertions.assertInstanceOf(DeploymentGuard.Admitted.class, watched,
            "DG-1: test mode with the test bundle must be admitted");
        Assertions.assertTrue(admitted.admission().assertSingleProcess(),
            "DG-1: an unchanged property on H2, which holds no lease, must let the caller proceed");
        property.set(DeploymentGuard.MODE_SINGLE_PROCESS);
        Assertions.assertFalse(admitted.admission().assertSingleProcess(), "DG-1: a changed dbac.deployment must deny the caller");
        Assertions.assertEquals(List.of(FailureCode.DEPLOYMENT_PROPERTY_CHANGED), recorded.codes,
            "DG-1: a changed dbac.deployment must revoke with DEPLOYMENT_PROPERTY_CHANGED");
        property.set(null);
        Assertions.assertFalse(admitted.admission().assertSingleProcess(), "DG-1: a removed dbac.deployment must deny the caller");

        AtomicReference<String> live = new AtomicReference<>(DeploymentGuard.MODE_TEST);
        DeploymentGuard liveGuard = new DeploymentGuard(new DeploymentGuard.Environment(live::get, () -> null, () -> true,
            () -> false, () -> false));
        Fixture endToEnd = new Fixture();
        TestFactory endToEndFactory = endToEnd.factory((stub, revocation) -> liveGuard.admit(h2Target(H2_MEMORY_URL), revocation));
        CBDatabase endToEndDatabase = endToEndFactory.init();
        try {
            Ready ready = Assertions.assertInstanceOf(Ready.class, endToEndFactory.state(), "DG-1: the policy service must be Ready");
            Assertions.assertTrue(ready.admission().assertSingleProcess(), "DG-1: the ready admission must let the caller proceed");
            live.set(DeploymentGuard.MODE_SINGLE_PROCESS);
            Assertions.assertFalse(ready.admission().assertSingleProcess(), "DG-1: after the property changed the caller is denied");
            Failed revoked = Assertions.assertInstanceOf(Failed.class, endToEndFactory.state(),
                "DG-1: the guard's revocation must reach the holder: Ready -> Failed");
            Assertions.assertEquals(FailureCode.DEPLOYMENT_PROPERTY_CHANGED, revoked.code(), "DG-1: the revocation code");
        } finally {
            endToEndDatabase.shutdown();
        }
        Assertions.assertInstanceOf(Disposed.class, endToEndFactory.state(), "DG-1: the revoked service must still stop to Disposed");
    }

    // ---------------------------------------------------------------- G4, G5 H2

    /**
     * DG-3: the H2 URL contract - local embedded files with no setting but FILE_LOCK=FILE, nothing else
     */
    @Test
    public void dg3H2UrlContractAcceptsOnlyLocalFilesWithAFileLock() {
        char b = '\\';
        List<Object[]> table = new ArrayList<>(List.of(
            // accepted local files
            row(H2_FILE_URL, false, null),
            row("jdbc:h2:C:/cloudbeaver/workspace/.data/cb.h2v2.dat", false, null),
            row("jdbc:h2:C:" + b + "cloudbeaver" + b + "workspace" + b + ".data" + b + "cb.h2v2.dat", false, null),
            row("jdbc:h2:file:/srv/cb/db", false, null),
            row("jdbc:h2:file:C:/cb/db", false, null),
            row("jdbc:h2:/srv/cb/db;FILE_LOCK=FILE", false, null),
            row("jdbc:h2:/srv/cb/db;file_lock=file", false, null),
            row("jdbc:h2:/srv/cb/db;FILE_LOCK=File", false, null),
            row("jdbc:h2:/srv/cb/db;", false, null),
            row("jdbc:h2:/srv/cb/db;;FILE_LOCK=FILE;", false, null),
            row("jdbc:h2:/srv/AUTO_SERVER=TRUE/db", false, null),
            row("jdbc:h2:C:/srv/IGNORE_UNKNOWN_SETTINGS=TRUE/db", false, null),
            // in-memory
            row(H2_MEMORY_URL, true, null),
            row(H2_MEMORY_URL, false, FailureCode.H2_IN_MEMORY),
            row("jdbc:h2:MEM:x", false, FailureCode.H2_IN_MEMORY),
            row("jdbc:h2:.", false, FailureCode.H2_IN_MEMORY),
            row("jdbc:h2:.", true, null),
            // a path relative to the working directory, in either mode
            row("jdbc:h2:./cb.h2v2.dat", false, FailureCode.H2_URL_UNSUPPORTED),
            row("jdbc:h2:./cb.h2v2.dat", true, FailureCode.H2_URL_UNSUPPORTED),
            row("jdbc:h2:../srv/cb/db", false, FailureCode.H2_URL_UNSUPPORTED),
            row("jdbc:h2:file:./cb.h2v2.dat", false, FailureCode.H2_URL_UNSUPPORTED),
            row("jdbc:h2:file:./cb.h2v2.dat", true, FailureCode.H2_URL_UNSUPPORTED),
            row("jdbc:h2:file:../srv/cb/db", false, FailureCode.H2_URL_UNSUPPORTED),
            row("jdbc:h2:file:.", false, FailureCode.H2_URL_UNSUPPORTED),
            row("jdbc:h2:file:.", true, FailureCode.H2_URL_UNSUPPORTED),
            // nothing left after file: (C16), in either mode
            row("jdbc:h2:file:", false, FailureCode.H2_URL_UNSUPPORTED),
            row("jdbc:h2:file:", true, FailureCode.H2_URL_UNSUPPORTED),
            row("jdbc:h2:file:;FILE_LOCK=FILE", false, FailureCode.H2_URL_UNSUPPORTED),
            row("jdbc:h2:file:;FILE_LOCK=FILE", true, FailureCode.H2_URL_UNSUPPORTED),
            row("jdbc:h2:file:;", false, FailureCode.H2_URL_UNSUPPORTED),
            // the current policy, recorded and not changed by C16: the guard accepts these three; H2 decides where they are
            row("jdbc:h2:data/db", false, null),
            row("jdbc:h2:~/db", false, null),
            row("jdbc:h2:file:~/db;FILE_LOCK=FILE", false, null),
            row("jdbc:h2:" + b + "srv" + b + "db", false, null),
            row("jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1", true, FailureCode.H2_SETTING_UNSUPPORTED),
            // remote
            row("jdbc:h2:tcp://localhost/x", false, FailureCode.H2_REMOTE),
            row("jdbc:h2:ssl://h/x", false, FailureCode.H2_REMOTE),
            row("jdbc:h2:TCP://localhost/x", true, FailureCode.H2_REMOTE),
            // the file: prefix only in lower case
            row("jdbc:h2:FILE:/srv/x", false, FailureCode.H2_URL_UNSUPPORTED),
            // UNC and authority-style paths: H2 opens these as embedded files on another machine
            row("jdbc:h2://server/share/db", false, FailureCode.H2_NETWORK_PATH),
            row("jdbc:h2:" + b + b + "server" + b + "share" + b + "db", false, FailureCode.H2_NETWORK_PATH),
            row("jdbc:h2:file://server/share/db", false, FailureCode.H2_NETWORK_PATH),
            row("jdbc:h2:file:" + b + b + "server" + b + "share" + b + "db", false, FailureCode.H2_NETWORK_PATH),
            row("jdbc:h2:/" + b + "server" + b + "share" + b + "db", false, FailureCode.H2_NETWORK_PATH),
            row("jdbc:h2:" + b + "/server/share/db", false, FailureCode.H2_NETWORK_PATH),
            row("jdbc:h2:////server/share/db", false, FailureCode.H2_NETWORK_PATH),
            row("jdbc:h2:" + b + b + "?" + b + "C:" + b + "tmp" + b + "db", false, FailureCode.H2_NETWORK_PATH),
            row("jdbc:h2:" + b + b + "." + b + "C:" + b + "tmp" + b + "db", false, FailureCode.H2_NETWORK_PATH),
            row("jdbc:h2://server/share/db;FILE_LOCK=FILE", true, FailureCode.H2_NETWORK_PATH),
            // file system providers and unknown subprotocols
            row("jdbc:h2:split:/tmp/x", false, FailureCode.H2_SUBPROTOCOL_UNSUPPORTED),
            row("jdbc:h2:nio:/tmp/x", false, FailureCode.H2_SUBPROTOCOL_UNSUPPORTED),
            row("jdbc:h2:zip:/tmp/x.zip!/db", false, FailureCode.H2_SUBPROTOCOL_UNSUPPORTED),
            row("jdbc:h2:memFS:/x", false, FailureCode.H2_SUBPROTOCOL_UNSUPPORTED),
            row("jdbc:h2:file:split:C:/tmp/x", false, FailureCode.H2_SUBPROTOCOL_UNSUPPORTED),
            row("jdbc:h2:file:tcp://localhost/x", false, FailureCode.H2_SUBPROTOCOL_UNSUPPORTED),
            row("jdbc:h2:C:/tmp/a:b", false, FailureCode.H2_SUBPROTOCOL_UNSUPPORTED),
            row("jdbc:h2:C:x", false, FailureCode.H2_SUBPROTOCOL_UNSUPPORTED),
            row("jdbc:h2:CC:/x", false, FailureCode.H2_SUBPROTOCOL_UNSUPPORTED),
            // settings
            row("jdbc:h2:/srv/cb/db;AUTO_SERVER=TRUE", false, FailureCode.H2_SETTING_UNSUPPORTED),
            row("jdbc:h2:/srv/cb/db;auto_server=false", false, FailureCode.H2_SETTING_UNSUPPORTED),
            row("jdbc:h2:/srv/cb/db;IGNORE_UNKNOWN_SETTINGS=TRUE;AUTO_SERVER=TRUE", false, FailureCode.H2_SETTING_UNSUPPORTED),
            row("jdbc:h2:/srv/cb/db;INIT=RUNSCRIPT FROM 'x'", false, FailureCode.H2_SETTING_UNSUPPORTED),
            row("jdbc:h2:/srv/cb/db; FILE_LOCK=FILE", false, FailureCode.H2_SETTING_UNSUPPORTED),
            row("jdbc:h2:/srv/cb/db;FILE_LOCK", false, FailureCode.H2_SETTING_UNSUPPORTED),
            row("jdbc:h2:/srv/cb/db;FILE_LOCK=FILE;FILE_LOCK=FILE", false, FailureCode.H2_SETTING_UNSUPPORTED),
            row("jdbc:h2:/srv/cb/db;FILE_LOCK=FILE;file_lock=file", false, FailureCode.H2_SETTING_UNSUPPORTED),
            row("jdbc:h2:/srv/cb/db;FILE_LOCK=NO", false, FailureCode.H2_FILE_LOCK_UNSUPPORTED),
            row("jdbc:h2:/srv/cb/db;FILE_LOCK=SOCKET", false, FailureCode.H2_FILE_LOCK_UNSUPPORTED),
            row("jdbc:h2:/srv/cb/db;FILE_LOCK=FS", false, FailureCode.H2_FILE_LOCK_UNSUPPORTED),
            row("jdbc:h2:/srv/cb/db;FILE_LOCK=SERIALIZED", false, FailureCode.H2_FILE_LOCK_UNSUPPORTED),
            row("jdbc:h2:/srv/cb/db;FILE_LOCK=", false, FailureCode.H2_FILE_LOCK_UNSUPPORTED),
            row("jdbc:h2:/srv/cb/db;FILE_LOCK=FILE ", false, FailureCode.H2_FILE_LOCK_UNSUPPORTED),
            // H2's escape character in the settings
            row("jdbc:h2:/srv/cb/db;AUTO" + b + "_SERVER=TRUE", false, FailureCode.H2_URL_UNSUPPORTED),
            row("jdbc:h2:/srv/cb/db;FILE_LOCK=FILE" + b + ";AUTO_SERVER=TRUE", false, FailureCode.H2_URL_UNSUPPORTED),
            row("jdbc:h2:/srv/cb/db;FILE_LOCK=N" + b + "O", false, FailureCode.H2_URL_UNSUPPORTED),
            // prefix and characters
            row("JDBC:H2:/srv/cb/db", false, FailureCode.H2_URL_UNSUPPORTED),
            row("jdbc:h2:", false, FailureCode.H2_URL_UNSUPPORTED),
            row("jdbc:postgresql://localhost/db", false, FailureCode.H2_URL_UNSUPPORTED),
            row("jdbc:h2:/srv/cb/db\n;AUTO_SERVER=TRUE", false, FailureCode.H2_URL_UNSUPPORTED),
            row("jdbc:h2:/srv/cb/d\tb", false, FailureCode.H2_URL_UNSUPPORTED),
            row("jdbc:h2:/srv/c" + (char) 0xE9 + "/db", false, FailureCode.H2_URL_UNSUPPORTED)
        ));
        List<String> violations = new ArrayList<>();
        for (Object[] entry : table) {
            String url = (String) entry[0];
            boolean inMemoryAllowed = (Boolean) entry[1];
            FailureCode expected = (FailureCode) entry[2];
            FailureCode actual = DeploymentGuard.h2UrlRefusal(url, inMemoryAllowed);
            if (actual != expected) {
                violations.add(visible(url) + (inMemoryAllowed ? " [test]" : " [production]") + ": expected "
                    + (expected == null ? "accepted" : expected) + ", got " + (actual == null ? "accepted" : actual));
            }
        }

        final RecordingRevocation revocation = new RecordingRevocation();
        expectRefused(new DeploymentGuard(new DeploymentGuard.Environment(() -> DeploymentGuard.MODE_SINGLE_PROCESS,
            () -> "C:/cloudbeaver/urlmap.properties", () -> false, () -> false, () -> false)),
            h2Target(H2_FILE_URL), FailureCode.H2_URL_REMAPPED, "h2.urlMap set", violations);
        expectAdmitted(new DeploymentGuard(new DeploymentGuard.Environment(() -> DeploymentGuard.MODE_SINGLE_PROCESS,
            () -> "", () -> false, () -> false, () -> false)), h2Target(H2_FILE_URL), "h2.urlMap empty", violations);
        DeploymentGuard production = new DeploymentGuard(environment(DeploymentGuard.MODE_SINGLE_PROCESS, false));
        expectRefused(production, new DeploymentGuard.MetadataTarget("MySQL", "8.4.0", "jdbc:mysql://db/cb", "mysql8", 100,
            failingSource()), FailureCode.METADATA_ENGINE_UNSUPPORTED, "MySQL metadata", violations);
        expectRefused(production, new DeploymentGuard.MetadataTarget("H2", H2_V2_RELEASE, "jdbc:postgresql://db/cb", "h2_embedded_v2", 100,
            failingSource()), FailureCode.METADATA_ENGINE_UNSUPPORTED, "H2 product with a PostgreSQL URL", violations);
        expectRefused(production, new DeploymentGuard.MetadataTarget("PostgreSQL", "16.4", H2_FILE_URL, "h2_embedded_v2", 100,
            failingSource()), FailureCode.METADATA_ENGINE_UNSUPPORTED, "PostgreSQL product with an H2 URL", violations);
        expectRefused(production, new DeploymentGuard.MetadataTarget(null, H2_V2_RELEASE, H2_FILE_URL, "h2_embedded_v2", 100,
            failingSource()), FailureCode.METADATA_ENGINE_UNSUPPORTED, "no product name", violations);
        // G4 for H2: the driver id and the release H2 reports must be one of the verified pairs
        String[][] releases = {
            {"h2_embedded", "1.4.199 (2019-03-13)", "refused"},
            {"h2_embedded_v2", "2.4.240 (2025-09-22)", "refused"},
            {"h2_embedded_v3", H2_V2_RELEASE, "refused"},
            {"h2_embedded_v2", null, "refused"},
            {"h2_embedded_v2", "2.1.2140", "refused"},
            {"h2_embedded_v2", "2.2.224 (2023-09-17)", "refused"},
            {"h2_embedded_v2", " 2.1.214", "refused"},
            {null, H2_V2_RELEASE, "refused"},
            {"h2_embedded_v2", "2.1.214", "admitted"},
            {"h2_embedded_v2", H2_V2_RELEASE, "admitted"},
            {"h2_embedded_v3", "2.4.240 (2025-09-22)", "admitted"},
        };
        for (String[] release : releases) {
            DeploymentGuard.MetadataTarget target = new DeploymentGuard.MetadataTarget("H2", release[1], H2_FILE_URL, release[0], 100,
                failingSource());
            String label = "driver " + release[0] + " reporting " + quote(release[1]);
            if ("admitted".equals(release[2])) {
                expectAdmitted(production, target, label, violations);
            } else {
                expectRefused(production, target, FailureCode.METADATA_ENGINE_UNSUPPORTED, label, violations);
            }
        }
        expectRefused(production, h2Target("jdbc:h2://fileserver/cbshare/cb.h2v2.dat"), FailureCode.H2_NETWORK_PATH,
            "UNC metadata through admit", violations);
        Assertions.assertEquals(List.of(), revocation.codes, "DG-3: admission must never revoke anything");
        Assertions.assertEquals(List.of(), violations, "DG-3: the H2 URL and engine contract");
    }

    // ---------------------------------------------------------------- G5 PostgreSQL

    /**
     * DG-4: another holder of the advisory lock, a pool too small to spare it, or no connection refuse the deployment
     */
    @Test
    public void dg4AnotherHolderOfTheAdvisoryLockRefusesTheDeployment() throws Exception {
        requirePostgres();
        List<String> violations = new ArrayList<>();
        DeploymentGuard guard = new DeploymentGuard(environment(DeploymentGuard.MODE_SINGLE_PROCESS, false));
        try (Connection other = open()) {
            Assertions.assertTrue(tryLock(other), "FIXTURE: the competing session could not take the advisory lock");
            try {
                RecordingSource source = new RecordingSource();
                DeploymentGuard.Result result = guard.admit(postgresTarget(source, 100), new RecordingRevocation());
                if (!(result instanceof DeploymentGuard.Refused refused && refused.code() == FailureCode.ADVISORY_LOCK_HELD)) {
                    violations.add("a lock held by another session must refuse with ADVISORY_LOCK_HELD, got " + result);
                }
                if (source.opened.size() != 1 || !source.opened.get(0).isClosed()) {
                    violations.add("the refused lock connection must be opened once and closed, opened=" + source.opened.size());
                }
            } finally {
                unlock(other);
            }
        }

        RecordingSource broken = new RecordingSource();
        expectRefused(guard, postgresTarget(() -> {
            Connection connection = broken.open();
            connection.close();
            return connection;
        }, 100), FailureCode.ADVISORY_LOCK_UNAVAILABLE, "the lock query fails on the opened connection", violations);
        if (broken.opened.size() != 1) {
            violations.add("the failing lock connection must be opened once, opened=" + broken.opened.size());
        }

        RecordingSource small = new RecordingSource();
        expectRefused(guard, postgresTarget(small, 1), FailureCode.POOL_TOO_SMALL, "maxConnections=1", violations);
        if (!small.opened.isEmpty()) {
            violations.add("a pool too small must be refused before any connection is opened");
        }
        expectRefused(guard, new DeploymentGuard.MetadataTarget("PostgreSQL", "16.4", URL, "postgres-jdbc", 100, failingSource()),
            FailureCode.ADVISORY_LOCK_UNAVAILABLE, "no connection", violations);

        RecordingSource free = new RecordingSource();
        DeploymentGuard.Result admitted = guard.admit(postgresTarget(free, 100), new RecordingRevocation());
        try {
            if (!(admitted instanceof DeploymentGuard.Admitted)) {
                violations.add("a free advisory lock must be admitted, got " + admitted);
            }
            try (Connection other = open()) {
                if (tryLock(other)) {
                    unlock(other);
                    violations.add("while admitted, another session must not get the advisory lock");
                }
            }
        } finally {
            if (admitted instanceof DeploymentGuard.Admitted lease) {
                lease.leaseRelease().run();
            }
        }
        try (Connection other = open()) {
            if (!tryLock(other)) {
                violations.add("after the lease is released another session must get the advisory lock");
            } else {
                unlock(other);
            }
        }
        Assertions.assertEquals(List.of(), violations, "DG-4: PostgreSQL startup outcomes");
    }

    /**
     * DG-5: a lock session that died is replaced exactly once, even under concurrent checks, and the caller proceeds
     */
    @Test
    public void dg5ALostLockSessionIsReacquiredOnceAndTheRequestProceeds() throws Exception {
        requirePostgres();
        RecordingSource source = new RecordingSource();
        RecordingRevocation revocation = new RecordingRevocation();
        DeploymentGuard.Result result = new DeploymentGuard(environment(DeploymentGuard.MODE_SINGLE_PROCESS, false))
            .admit(postgresTarget(source, 100), revocation);
        DeploymentGuard.Admitted admitted = Assertions.assertInstanceOf(DeploymentGuard.Admitted.class, result,
            "DG-5: a free advisory lock must be admitted");
        try {
            Assertions.assertEquals(1, source.opened.size(), "DG-5: admission must open one lock connection");
            Assertions.assertEquals(List.of(source.pids.get(0)), lockHolders(), "DG-5: the admitted session must hold the lock");
            Assertions.assertTrue(admitted.admission().assertSingleProcess(), "DG-5: a live lock session lets the caller proceed");
            Assertions.assertEquals(1, source.opened.size(), "DG-5: a live lock session must not be replaced");

            terminate(source.pids.get(0));
            Assertions.assertTrue(admitted.admission().assertSingleProcess(),
                "DG-5: a lost but free lock is taken again and the caller proceeds");
            Assertions.assertEquals(2, source.opened.size(), "DG-5: the lost session must be replaced exactly once");
            Assertions.assertEquals(List.of(source.pids.get(1)), lockHolders(), "DG-5: the new session must hold the lock");
            Assertions.assertEquals(List.of(), revocation.codes, "DG-5: re-acquiring must not fail the service");

            terminate(source.pids.get(1));
            CyclicBarrier barrier = new CyclicBarrier(8);
            List<Boolean> answers = Collections.synchronizedList(new ArrayList<>());
            List<Thread> threads = new ArrayList<>();
            for (int i = 0; i < 8; i++) {
                Thread thread = new Thread(() -> {
                    try {
                        barrier.await(TIMEOUT_SECONDS, TimeUnit.SECONDS);
                        answers.add(admitted.admission().assertSingleProcess());
                    } catch (Exception e) {
                        answers.add(null);
                    }
                }, "dbac-dg5-check-" + i);
                threads.add(thread);
                thread.start();
            }
            for (Thread thread : threads) {
                thread.join(TimeUnit.SECONDS.toMillis(TIMEOUT_SECONDS));
            }
            Assertions.assertEquals(Collections.nCopies(8, Boolean.TRUE), answers, "DG-5: every concurrent check must proceed");
            Assertions.assertEquals(3, source.opened.size(), "DG-5: eight concurrent checks must replace the session exactly once");
            Assertions.assertEquals(List.of(source.pids.get(2)), lockHolders(), "DG-5: the replacing session must hold the lock");
            Assertions.assertEquals(List.of(), revocation.codes, "DG-5: re-acquiring must not fail the service");
        } finally {
            admitted.leaseRelease().run();
        }
        Assertions.assertEquals(List.of(), lockHolders(), "DG-5: releasing the lease must free the lock");
    }

    /**
     * DG-6: when another session took the lock after ours died, the service is failed and nothing is opened again
     */
    @Test
    public void dg6ALockTakenByAnotherProcessFailsTheService() throws Exception {
        requirePostgres();
        RecordingSource source = new RecordingSource();
        RecordingRevocation revocation = new RecordingRevocation();
        DeploymentGuard.Result result = new DeploymentGuard(environment(DeploymentGuard.MODE_SINGLE_PROCESS, false))
            .admit(postgresTarget(source, 100), revocation);
        DeploymentGuard.Admitted admitted = Assertions.assertInstanceOf(DeploymentGuard.Admitted.class, result,
            "DG-6: a free advisory lock must be admitted");
        try (Connection other = open()) {
            try {
                Assertions.assertEquals(1, source.opened.size(), "DG-6: admission must open one lock connection");
                terminate(source.pids.get(0));
                Assertions.assertTrue(waitForLock(other), "FIXTURE: the competing session could not take the freed lock");

                Assertions.assertFalse(admitted.admission().assertSingleProcess(), "DG-6: a lock held elsewhere must deny the caller");
                Assertions.assertEquals(List.of(FailureCode.ADVISORY_LOCK_LOST), revocation.codes,
                    "DG-6: the service must be failed with ADVISORY_LOCK_LOST exactly once");
                Assertions.assertEquals(2, source.opened.size(), "DG-6: one re-acquire attempt must have been made");
                Assertions.assertTrue(source.opened.get(0).isClosed() && source.opened.get(1).isClosed(),
                    "DG-6: both the dead and the refused connection must be closed");

                Assertions.assertFalse(admitted.admission().assertSingleProcess(), "DG-6: a lost lease keeps denying");
                Assertions.assertEquals(2, source.opened.size(), "DG-6: a lost lease must not try again");
                Assertions.assertEquals(1, revocation.codes.size(), "DG-6: a lost lease must not revoke again");
            } finally {
                unlock(other);
            }
        } finally {
            admitted.leaseRelease().run();
        }
    }

    // ---------------------------------------------------------------- R23: the remembered backend

    /**
     * DG-14: a lock connection that stops answering while its backend still holds the lock is kept, and the caller proceeds
     * <p>
     * {@code isValid} reports false, but the backend that took the lock at admission still holds it: nothing is
     * replaced, nothing revoked, and each check opens one connection to look and closes it again - also for eight
     * checks at once. Releasing the lease then frees the lock.
     */
    @Test
    public void dg14ASilentLockSessionThatStillHoldsTheLockIsKept() throws Exception {
        requirePostgres();
        List<String> violations = new ArrayList<>();
        ControlledSource source = new ControlledSource();
        RecordingRevocation revocation = new RecordingRevocation();
        DeploymentGuard.Admitted admitted = admit(source, revocation);
        int owner = source.pids.get(0);
        try {
            source.invalid.add(0);
            for (int i = 0; i < 3; i++) {
                if (!admitted.admission().assertSingleProcess()) {
                    violations.add("check " + i + ": a silent session whose backend holds the lock must let the caller proceed");
                }
            }
            expectEquals(violations, "owner checks made", 3, source.checks.get());
            List<Boolean> answers = concurrentChecks(admitted, 8);
            expectEquals(violations, "eight concurrent checks", Collections.nCopies(8, Boolean.TRUE), answers);
            expectEquals(violations, "revocations", List.of(), revocation.codes);
            expectEquals(violations, "lock holders", List.of(owner), lockHolders());
            if (source.handed.get(0).isClosed()) {
                violations.add("the silent lock connection must be kept");
            }
            for (int i = 1; i < source.handed.size(); i++) {
                if (!source.handed.get(i).isClosed()) {
                    violations.add("the connection opened for check " + i + " must be closed");
                }
            }
            expectEquals(violations, "connections opened: one at admission and one per check", 12, source.handed.size());
        } finally {
            admitted.leaseRelease().run();
        }
        expectEquals(violations, "lock holders after the release", List.of(), lockHolders());
        Assertions.assertEquals(List.of(), violations, "DG-14");
    }

    /**
     * DG-15: a dead lock session is replaced by a new one, which is remembered from then on - once, under concurrent checks
     */
    @Test
    public void dg15ADeadLockSessionIsReplacedAndTheNewOneIsRemembered() throws Exception {
        requirePostgres();
        List<String> violations = new ArrayList<>();
        ControlledSource source = new ControlledSource();
        RecordingRevocation revocation = new RecordingRevocation();
        DeploymentGuard.Admitted admitted = admit(source, revocation);
        try {
            terminate(source.pids.get(0));
            if (!admitted.admission().assertSingleProcess()) {
                violations.add("a dead session whose lock is free must be replaced and the caller proceed");
            }
            expectEquals(violations, "connections after the replacement", 2, source.handed.size());
            expectEquals(violations, "lock holders after the replacement", List.of(pidAt(source, 1)), lockHolders());

            source.invalid.add(1);
            if (!admitted.admission().assertSingleProcess()) {
                violations.add("the replacing session is the remembered owner: silent but holding, the caller proceeds");
            }
            expectEquals(violations, "lock holders while the new owner is silent", List.of(pidAt(source, 1)), lockHolders());
            expectEquals(violations, "connections: the silent new owner is not replaced", 3, source.handed.size());

            if (source.pids.size() > 1) {
                terminate(source.pids.get(1));
            }
            List<Boolean> answers = concurrentChecks(admitted, 8);
            expectEquals(violations, "eight concurrent checks after the second death", Collections.nCopies(8, Boolean.TRUE), answers);
            expectEquals(violations, "connections: replaced exactly once more", 4, source.handed.size());
            expectEquals(violations, "lock holders after the concurrent replacement", List.of(pidAt(source, 3)), lockHolders());
            expectEquals(violations, "revocations", List.of(), revocation.codes);
        } finally {
            admitted.leaseRelease().run();
        }
        expectEquals(violations, "lock holders after the release", List.of(), lockHolders());
        Assertions.assertEquals(List.of(), violations, "DG-15");
    }

    /**
     * DG-16: when the remembered backend no longer holds the lock and another session does, the service fails exactly once
     * <p>
     * Once with the backend dead, once with it alive but silent and without the lock. Either way the caller is
     * denied, the service is failed with ADVISORY_LOCK_LOST once, and later checks deny without opening anything.
     */
    @Test
    public void dg16ALockTakenElsewhereFailsTheServiceOnce() throws Exception {
        requirePostgres();
        List<String> violations = new ArrayList<>();
        for (boolean dead : new boolean[]{true, false}) {
            String what = dead ? "the owner died: " : "the owner is silent and let the lock go: ";
            ControlledSource source = new ControlledSource();
            RecordingRevocation revocation = new RecordingRevocation();
            DeploymentGuard.Admitted admitted = admit(source, revocation);
            try (Connection other = open()) {
                try {
                    if (dead) {
                        terminate(source.pids.get(0));
                    } else {
                        unlock(source.raw.get(0));
                        source.invalid.add(0);
                    }
                    Assertions.assertTrue(waitForLock(other), "FIXTURE: the competing session could not take the lock");
                    if (admitted.admission().assertSingleProcess()) {
                        violations.add(what + "a lock held elsewhere must deny the caller");
                    }
                    expectEquals(violations, what + "revocations", List.of(FailureCode.ADVISORY_LOCK_LOST), revocation.codes);
                    int opened = source.handed.size();
                    if (admitted.admission().assertSingleProcess()) {
                        violations.add(what + "a lost lease keeps denying");
                    }
                    expectEquals(violations, what + "connections opened after the loss", opened, source.handed.size());
                    expectEquals(violations, what + "revocations after a second check", 1, revocation.codes.size());
                    for (int i = 0; i < source.handed.size(); i++) {
                        if (!source.handed.get(i).isClosed()) {
                            violations.add(what + "connection " + i + " must be closed once the lease is lost");
                        }
                    }
                } finally {
                    unlock(other);
                }
            } finally {
                admitted.leaseRelease().run();
            }
        }
        Assertions.assertEquals(List.of(), violations, "DG-16");
    }

    /**
     * DG-17: only the exact DBAC lock counts - not another advisory lock of the same backend, nor the same key in share mode
     * <p>
     * The remembered backend gives the DBAC lock up and takes another key, and the same two halves as a pair of
     * int keys, while another session takes the DBAC lock: denied. Then the backend holds the DBAC key in share
     * mode only: denied too.
     */
    @Test
    public void dg17OnlyTheExactLockCountsAsHeld() throws Exception {
        requirePostgres();
        List<String> violations = new ArrayList<>();
        long key = DeploymentGuard.ADVISORY_LOCK_KEY;
        ControlledSource source = new ControlledSource();
        RecordingRevocation revocation = new RecordingRevocation();
        DeploymentGuard.Admitted admitted = admit(source, revocation);
        try (Connection other = open()) {
            try {
                Connection owner = source.raw.get(0);
                execute(owner, "SELECT pg_advisory_unlock(" + key + ")");
                execute(owner, "SELECT pg_advisory_lock(" + (key + 1) + ")");
                execute(owner, "SELECT pg_advisory_lock(" + (int) (key >>> 32) + ", " + (int) key + ")");
                Assertions.assertTrue(tryLock(other), "FIXTURE: the competing session could not take the DBAC lock");
                Assertions.assertEquals(2, advisoryLocksOf(source.pids.get(0)), "FIXTURE: the owner must hold two other advisory locks");
                source.invalid.add(0);
                if (admitted.admission().assertSingleProcess()) {
                    violations.add("another advisory lock of the remembered backend must not count as the DBAC lock");
                }
                expectEquals(violations, "revocations, other locks", List.of(FailureCode.ADVISORY_LOCK_LOST), revocation.codes);
            } finally {
                unlock(other);
            }
        } finally {
            admitted.leaseRelease().run();
        }

        ControlledSource shared = new ControlledSource();
        RecordingRevocation sharedRevocation = new RecordingRevocation();
        DeploymentGuard.Admitted sharedAdmitted = admit(shared, sharedRevocation);
        try {
            Connection owner = shared.raw.get(0);
            execute(owner, "SELECT pg_advisory_unlock(" + key + ")");
            execute(owner, "SELECT pg_advisory_lock_shared(" + key + ")");
            shared.invalid.add(0);
            if (sharedAdmitted.admission().assertSingleProcess()) {
                violations.add("the DBAC key held in share mode must not count as the DBAC lock");
            }
            expectEquals(violations, "revocations, share mode", List.of(FailureCode.ADVISORY_LOCK_LOST), sharedRevocation.codes);
        } finally {
            sharedAdmitted.leaseRelease().run();
        }
        expectEquals(violations, "lock holders after both", List.of(), lockHolders());
        Assertions.assertEquals(List.of(), violations, "DG-17");
    }

    /**
     * DG-18: a remembered backend that is only waiting for the DBAC lock does not hold it, and the check does not wait for it
     */
    @Test
    public void dg18AnOwnerOnlyWaitingForTheLockDoesNotHoldIt() throws Exception {
        requirePostgres();
        List<String> violations = new ArrayList<>();
        ControlledSource source = new ControlledSource();
        RecordingRevocation revocation = new RecordingRevocation();
        DeploymentGuard.Admitted admitted = admit(source, revocation);
        KeyLockTestSupport.Worker<Object> waiting = null;
        try (Connection other = open()) {
            try {
                Connection owner = source.raw.get(0);
                final int ownerPid = source.pids.get(0);
                unlock(owner);
                Assertions.assertTrue(tryLock(other), "FIXTURE: the competing session could not take the DBAC lock");
                waiting = KeyLockTestSupport.Worker.start("dbac-dg18-owner-waits", () -> {
                    execute(owner, "SELECT pg_advisory_lock(" + DeploymentGuard.ADVISORY_LOCK_KEY + ")");
                    return null;
                });
                Assertions.assertTrue(awaitWaitingFor(ownerPid), "FIXTURE: the owner must be waiting for the DBAC lock");
                source.invalid.add(0);
                KeyLockTestSupport.Worker<Boolean> check = KeyLockTestSupport.Worker.start("dbac-dg18-check",
                    () -> admitted.admission().assertSingleProcess());
                if (!check.done.await(10, TimeUnit.SECONDS)) {
                    violations.add("the check must not wait for the busy owner session");
                } else if (!Boolean.FALSE.equals(check.result) || check.error != null) {
                    violations.add("an owner only waiting for the lock must deny the caller, got " + check.result + " / " + check.error);
                }
                expectEquals(violations, "revocations", List.of(FailureCode.ADVISORY_LOCK_LOST), revocation.codes);
            } finally {
                unlock(other);
            }
        } finally {
            if (waiting != null) {
                Assertions.assertTrue(waiting.awaitDone(), "FIXTURE: the owner's wait did not end");
            }
            admitted.leaseRelease().run();
        }
        expectEquals(violations, "lock holders after the case", List.of(), lockHolders());
        Assertions.assertEquals(List.of(), violations, "DG-18");
    }

    /**
     * DG-19: an owner check that fails or runs out of time denies the caller, revokes nothing and keeps the lease; its log names no detail
     */
    @Test
    public void dg19AFailedOrHungOwnerCheckDeniesWithoutRevoking() throws Throwable {
        requirePostgres();
        List<String> violations = new ArrayList<>();
        ControlledSource source = new ControlledSource();
        RecordingRevocation revocation = new RecordingRevocation();
        DeploymentGuard.Admitted admitted = admit(source, revocation);
        int owner = source.pids.get(0);
        try {
            source.invalid.add(0);
            boolean[] answers = new boolean[2];
            long[] hungMillis = new long[1];
            final Captured captured = LifecycleTestSupport.captureLogs(() -> {
                source.fault = CheckFault.THROWS;
                answers[0] = admitted.admission().assertSingleProcess();
                source.fault = CheckFault.HANGS;
                long start = System.nanoTime();
                answers[1] = admitted.admission().assertSingleProcess();
                hungMillis[0] = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
                source.fault = CheckFault.NONE;
            });
            if (answers[0]) {
                violations.add("an owner check that throws must deny the caller");
            }
            if (answers[1]) {
                violations.add("an owner check that runs out of time must deny the caller");
            }
            if (hungMillis[0] > 9_000) {
                violations.add("an owner check that hangs must be cut off by its timeout, took " + hungMillis[0] + "ms");
            }
            if (source.timeouts.isEmpty() || source.timeouts.stream().anyMatch(seconds -> seconds < 1 || seconds > 5)) {
                violations.add("every owner check needs a query timeout of 1-5 seconds, got " + source.timeouts);
            }
            expectEquals(violations, "revocations", List.of(), revocation.codes);
            expectEquals(violations, "lock holders", List.of(owner), lockHolders());
            if (!admitted.admission().assertSingleProcess()) {
                violations.add("once the check works again, the silent owner that holds the lock lets the caller proceed");
            }
            violations.addAll(LifecycleTestSupport.logContractViolations(captured, List.of(
                LifecycleTestSupport.SECRET_MARKER, "pg.internal.example", "pg_locks", "owner check refused", "ran out of time",
                "jdbc:postgresql:")));
            if (captured.dbacMessages().stream().noneMatch(m -> m.contains("event=DBAC_ADVISORY_LOCK_FAILED"))) {
                violations.add("a failed owner check must be logged as DBAC_ADVISORY_LOCK_FAILED, got " + captured.dbacMessages());
            }
        } finally {
            admitted.leaseRelease().run();
        }
        Assertions.assertEquals(List.of(), violations, "DG-19");
    }

    /**
     * DG-20: releasing the lease frees the remembered owner's lock and ends its session - the first owner, or the one that replaced it
     */
    @Test
    public void dg20ReleasingTheLeaseFreesTheRememberedOwnersLock() throws Exception {
        requirePostgres();
        List<String> violations = new ArrayList<>();
        for (boolean replaced : new boolean[]{false, true}) {
            String what = replaced ? "after a replacement: " : "the first owner: ";
            ControlledSource source = new ControlledSource();
            DeploymentGuard.Admitted admitted = admit(source, new RecordingRevocation());
            int owner;
            try {
                if (replaced) {
                    terminate(source.pids.get(0));
                }
                source.invalid.add(0);
                if (!admitted.admission().assertSingleProcess()) {
                    violations.add(what + "the check must let the caller proceed");
                }
                owner = pidAt(source, replaced ? 1 : 0);
                if (!lockHolders().equals(List.of(owner))) {
                    violations.add(what + "the remembered owner must hold the lock, holders " + lockHolders());
                }
            } finally {
                admitted.leaseRelease().run();
            }
            if (advisoryLocksOf(owner) != 0 || !lockHolders().isEmpty()) {
                violations.add(what + "the released owner must hold no advisory lock, holders " + lockHolders());
            }
            if (!sessionEnded(owner)) {
                violations.add(what + "the released owner's session must end");
            }
        }
        Assertions.assertEquals(List.of(), violations, "DG-20");
    }

    /**
     * DG-21: the owner is a backend's pid together with when that backend started - a reused pid is not the owner
     * <p>
     * PID reuse is made, not waited for. Owner A takes the lock and dies, backend B takes the lock, and the lease is
     * made to remember B's pid with A's start - what a recycled pid looks like. The guard must deny, fail the service
     * exactly once and keep denying, without taking a new lease. The case also checks what the identity is made of:
     * the lease remembers the pid and the start that the lock statement itself reported, and the exact pair lets a
     * silent owner through; reacquisition replaces both together; a lock statement that reports no start refuses
     * admission and reacquisition and keeps no lock; an owner look-up whose answer is missing, doubled, ambiguous or
     * about a backend of unknown start denies without revoking.
     */
    @Test
    public void dg21AReusedPidIsNotTheOwner() throws Exception {
        requirePostgres();
        List<String> violations = new ArrayList<>();
        ControlledSource source = new ControlledSource();
        RecordingRevocation revocation = new RecordingRevocation();
        DeploymentGuard.Admitted admitted = admit(source, revocation);
        try {
            int pidA = source.pids.get(0);
            OffsetDateTime startA = backendStartOf(pidA);
            expectEquals(violations, "the owner remembered at admission", java.util.Arrays.asList(pidA, startA), ownerOf(admitted));
            source.invalid.add(0);
            if (!admitted.admission().assertSingleProcess()) {
                violations.add("the exact pid and start, silent but holding the lock, must let the caller proceed");
            }
            terminate(pidA);
            try (Connection b = open()) {
                try {
                    Assertions.assertTrue(waitForLock(b), "FIXTURE: backend B could not take the lock");
                    int pidB = pid(b);
                    setOwner(admitted, pidB, startA);
                    final int opened = source.handed.size();
                    int allowed = 0;
                    for (int i = 0; i < 3; i++) {
                        allowed += admitted.admission().assertSingleProcess() ? 1 : 0;
                    }
                    expectEquals(violations, "callers let through once the pid was reused", 0, allowed);
                    expectEquals(violations, "revocations after the pid was reused", List.of(FailureCode.ADVISORY_LOCK_LOST),
                        revocation.codes);
                    expectEquals(violations, "connections opened: one look, no new lease", opened + 1, source.handed.size());
                    expectEquals(violations, "lock holders after the pid was reused", List.of(pidB), lockHolders());
                } finally {
                    unlock(b);
                }
            }
        } finally {
            admitted.leaseRelease().run();
        }

        ControlledSource second = new ControlledSource();
        RecordingRevocation secondRevocation = new RecordingRevocation();
        DeploymentGuard.Admitted reacquiring = admit(second, secondRevocation);
        try {
            terminate(second.pids.get(0));
            second.lockWithoutStart = true;
            if (reacquiring.admission().assertSingleProcess()) {
                violations.add("a reacquisition whose lock statement reports no backend start must deny");
            }
            if (second.pids.size() > 1 && !sessionEnded(second.pids.get(1))) {
                violations.add("the session of a reacquisition without a start must be ended");
            }
            expectEquals(violations, "lock holders after a reacquisition without a start", List.of(), lockHolders());
            second.lockWithoutStart = false;
            if (!reacquiring.admission().assertSingleProcess()) {
                violations.add("a reacquisition that reports its start must let the caller proceed");
            }
            int pidNew = pidAt(second, second.pids.size() - 1);
            expectEquals(violations, "the owner after reacquisition", java.util.Arrays.asList(pidNew, backendStartOf(pidNew)),
                ownerOf(reacquiring));
            expectEquals(violations, "lock holders after reacquisition", List.of(pidNew), lockHolders());
            expectEquals(violations, "revocations around the reacquisition", List.of(), secondRevocation.codes);
        } finally {
            reacquiring.leaseRelease().run();
        }

        ControlledSource startless = new ControlledSource();
        startless.lockWithoutStart = true;
        DeploymentGuard.Result refused = new DeploymentGuard(environment(DeploymentGuard.MODE_SINGLE_PROCESS, false))
            .admit(postgresTarget(startless, 100), new RecordingRevocation());
        if (!(refused instanceof DeploymentGuard.Refused refusal && refusal.code() == FailureCode.ADVISORY_LOCK_UNAVAILABLE)) {
            violations.add("an admission whose lock statement reports no backend start must be refused, got " + refused);
            if (refused instanceof DeploymentGuard.Admitted wronglyAdmitted) {
                wronglyAdmitted.leaseRelease().run();
            }
        }
        if (!startless.handed.isEmpty() && (!startless.handed.get(0).isClosed() || !sessionEnded(startless.pids.get(0)))) {
            violations.add("the refused admission's connection must be closed and its session ended");
        }
        expectEquals(violations, "lock holders after a refused admission", List.of(), lockHolders());

        ControlledSource looked = new ControlledSource();
        RecordingRevocation lookedRevocation = new RecordingRevocation();
        DeploymentGuard.Admitted looking = admit(looked, lookedRevocation);
        try {
            looked.invalid.add(0);
            for (CheckFault answer : List.of(CheckFault.NO_ROW, CheckFault.TWO_ROWS, CheckFault.COUNT_TWO, CheckFault.UNKNOWN_START)) {
                looked.fault = answer;
                if (looking.admission().assertSingleProcess()) {
                    violations.add("an owner look-up answering " + answer + " must deny the caller");
                }
            }
            looked.fault = CheckFault.NONE;
            expectEquals(violations, "revocations after unusable owner answers", List.of(), lookedRevocation.codes);
            if (!looking.admission().assertSingleProcess()) {
                violations.add("once the look-up answers again, the silent owner that holds the lock lets the caller proceed");
            }
        } finally {
            looking.leaseRelease().run();
        }
        expectEquals(violations, "lock holders after the case", List.of(), lockHolders());
        Assertions.assertEquals(List.of(), violations, "DG-21");
    }

    /** When the backend with this pid started, as PostgreSQL reports it, or null when there is none */
    @Nullable
    private static OffsetDateTime backendStartOf(int pid) throws SQLException {
        try (Connection connection = open();
             PreparedStatement statement = connection.prepareStatement("SELECT backend_start FROM pg_stat_activity WHERE pid = ?")) {
            statement.setInt(1, pid);
            try (ResultSet result = statement.executeQuery()) {
                return result.next() ? result.getObject(1, OffsetDateTime.class) : null;
            }
        }
    }

    /**
     * The owner the lease remembers, read by reflection: [pid, backend start], with a null start where the lease keeps none
     */
    @NotNull
    private static List<Object> ownerOf(@NotNull DeploymentGuard.Admitted admitted) throws ReflectiveOperationException {
        Object lease = leaseOf(admitted);
        java.lang.reflect.Field field = lease.getClass().getDeclaredField("owner");
        field.setAccessible(true);
        if (field.getType() == int.class) {
            return java.util.Arrays.asList(field.getInt(lease), null);
        }
        Object owner = field.get(lease);
        List<Object> parts = new ArrayList<>();
        for (java.lang.reflect.RecordComponent component : owner.getClass().getRecordComponents()) {
            java.lang.reflect.Method accessor = component.getAccessor();
            accessor.setAccessible(true);
            parts.add(accessor.invoke(owner));
        }
        return parts;
    }

    /**
     * Makes the lease remember {@code pid} with {@code start} - the state a recycled pid leaves behind; only a case can make it
     */
    private static void setOwner(
        @NotNull DeploymentGuard.Admitted admitted,
        int pid,
        @NotNull OffsetDateTime start
    ) throws ReflectiveOperationException {
        Object lease = leaseOf(admitted);
        java.lang.reflect.Field field = lease.getClass().getDeclaredField("owner");
        field.setAccessible(true);
        if (field.getType() == int.class) {
            field.setInt(lease, pid);
            return;
        }
        java.lang.reflect.Constructor<?> constructor = field.getType().getDeclaredConstructor(int.class, OffsetDateTime.class);
        constructor.setAccessible(true);
        field.set(lease, constructor.newInstance(pid, start));
    }

    @NotNull
    private static Object leaseOf(@NotNull DeploymentGuard.Admitted admitted) throws ReflectiveOperationException {
        Object admission = admitted.admission();
        java.lang.reflect.Field field = admission.getClass().getDeclaredField("lease");
        field.setAccessible(true);
        return field.get(admission);
    }

    @NotNull
    private static DeploymentGuard.Admitted admit(@NotNull ControlledSource source, @NotNull RecordingRevocation revocation) {
        DeploymentGuard.Result result = new DeploymentGuard(environment(DeploymentGuard.MODE_SINGLE_PROCESS, false))
            .admit(postgresTarget(source, 100), revocation);
        DeploymentGuard.Admitted admitted = Assertions.assertInstanceOf(DeploymentGuard.Admitted.class, result,
            "FIXTURE: a free advisory lock must be admitted");
        Assertions.assertEquals(1, source.handed.size(), "FIXTURE: admission must open one lock connection");
        return admitted;
    }

    /** The pid of the {@code index}th connection the source opened, or -1 when it opened fewer */
    private static int pidAt(@NotNull ControlledSource source, int index) {
        return index < source.pids.size() ? source.pids.get(index) : -1;
    }

    @NotNull
    private static List<Boolean> concurrentChecks(@NotNull DeploymentGuard.Admitted admitted, int threads) throws InterruptedException {
        CyclicBarrier barrier = new CyclicBarrier(threads);
        List<Boolean> answers = Collections.synchronizedList(new ArrayList<>());
        List<Thread> started = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            Thread thread = new Thread(() -> {
                try {
                    barrier.await(TIMEOUT_SECONDS, TimeUnit.SECONDS);
                    answers.add(admitted.admission().assertSingleProcess());
                } catch (Exception e) {
                    answers.add(null);
                }
            }, "dbac-dg-check-" + i);
            started.add(thread);
            thread.start();
        }
        for (Thread thread : started) {
            thread.join(TimeUnit.SECONDS.toMillis(TIMEOUT_SECONDS));
        }
        return new ArrayList<>(answers);
    }

    private static void expectEquals(
        @NotNull List<String> violations,
        @NotNull String what,
        @Nullable Object expected,
        @Nullable Object actual
    ) {
        if (!java.util.Objects.equals(expected, actual)) {
            violations.add(what + ": expected " + expected + ", got " + actual);
        }
    }

    // ---------------------------------------------------------------- G1, G2, G3

    /**
     * DG-7: a declared multi-node or distributed application is refused - the declaration is honoured, never relied on
     */
    @Test
    public void dg7DeclaredMultiNodeOrDistributedIsRefused() {
        List<String> violations = new ArrayList<>();
        expectRefused(new DeploymentGuard(new DeploymentGuard.Environment(() -> DeploymentGuard.MODE_SINGLE_PROCESS,
            () -> null, () -> false, () -> true, () -> false)), h2Target(H2_FILE_URL), FailureCode.MULTI_NODE_DECLARED,
            "multi-node declared", violations);
        expectRefused(new DeploymentGuard(new DeploymentGuard.Environment(() -> DeploymentGuard.MODE_SINGLE_PROCESS,
            () -> null, () -> false, () -> false, () -> true)), h2Target(H2_FILE_URL), FailureCode.MULTI_NODE_DECLARED,
            "distributed declared", violations);
        expectAdmitted(new DeploymentGuard(environment(DeploymentGuard.MODE_SINGLE_PROCESS, false)), h2Target(H2_FILE_URL),
            "neither declared", violations);
        Assertions.assertEquals(List.of(), violations, "DG-7: declared multi-node signals");
    }

    /**
     * DG-8: every refusal is logged with a fixed code and a correlation id - never a URL, host, value or message
     */
    @Test
    public void dg8RefusalsAreLoggedByCodeOnly() throws Throwable {
        String secret = LifecycleTestSupport.SECRET_MARKER;
        DeploymentGuard production = new DeploymentGuard(environment(DeploymentGuard.MODE_SINGLE_PROCESS, false));
        DeploymentGuard remapped = new DeploymentGuard(new DeploymentGuard.Environment(() -> DeploymentGuard.MODE_SINGLE_PROCESS,
            () -> "/etc/" + secret + "/urlmap.properties", () -> false, () -> false, () -> false));
        List<DeploymentGuard.Result> results = new ArrayList<>();
        Captured captured = LifecycleTestSupport.captureLogs(() -> {
            results.add(production.admit(h2Target("jdbc:h2://fileserver.internal.example/cbshare/" + secret + ".dat"),
                new RecordingRevocation()));
            results.add(production.admit(h2Target("jdbc:h2:" + '\\' + '\\' + "fileserver.internal.example" + '\\' + "cbshare"
                + '\\' + "cb.h2v2.dat"), new RecordingRevocation()));
            results.add(remapped.admit(h2Target(H2_FILE_URL), new RecordingRevocation()));
            results.add(production.admit(h2Target("jdbc:h2:/srv/cb/db;PASSWORD=" + secret), new RecordingRevocation()));
            results.add(production.admit(new DeploymentGuard.MetadataTarget("PostgreSQL", "16.4",
                "jdbc:postgresql://pg.internal.example:5432/cb?password=" + secret, "postgres-jdbc", 100, () -> {
                    throw new SQLException("FATAL: password authentication failed for user cbadmin at pg.internal.example " + secret);
                }), new RecordingRevocation()));
            results.add(production.admit(h2Target("jdbc:h2:mem:" + secret), new RecordingRevocation()));
        });
        List<FailureCode> codes = results.stream()
            .map(r -> r instanceof DeploymentGuard.Refused refused ? refused.code() : null)
            .toList();
        Assertions.assertEquals(List.of(FailureCode.H2_NETWORK_PATH, FailureCode.H2_NETWORK_PATH, FailureCode.H2_URL_REMAPPED,
            FailureCode.H2_SETTING_UNSUPPORTED, FailureCode.ADVISORY_LOCK_UNAVAILABLE, FailureCode.H2_IN_MEMORY), codes,
            "DG-8: every case must be refused with its code");
        List<String> violations = new ArrayList<>(LifecycleTestSupport.logContractViolations(captured, List.of(
            secret, "fileserver.internal.example", "cbshare", "pg.internal.example", "cbadmin", "jdbc:h2:", "jdbc:postgresql:",
            "urlmap.properties", "password authentication", "PASSWORD=")));
        for (FailureCode code : codes) {
            if (code != null && captured.dbacMessages().stream().noneMatch(m -> m.contains("event=DBAC_DEPLOYMENT_REFUSED")
                && m.contains("code=" + code))) {
                violations.add("no DBAC_DEPLOYMENT_REFUSED entry with code=" + code);
            }
        }
        if (captured.dbacMessages().size() < codes.size()) {
            violations.add("expected at least " + codes.size() + " DBAC log entries, got " + captured.dbacMessages().size());
        }
        Assertions.assertEquals(List.of(), violations, "DG-8: refusal logs must follow the P1 contract, got " + captured.dbacMessages());
    }

    /**
     * DG-9: an in-memory H2 metadata database is refused in production - nothing could see a second process
     */
    @Test
    public void dg9InMemoryH2IsRefusedInProduction() {
        List<String> violations = new ArrayList<>();
        expectRefused(new DeploymentGuard(environment(DeploymentGuard.MODE_SINGLE_PROCESS, true)), h2Target(H2_MEMORY_URL),
            FailureCode.H2_IN_MEMORY, "mem with single-process, even with the test bundle", violations);
        expectRefused(new DeploymentGuard(environment(DeploymentGuard.MODE_SINGLE_PROCESS, false)), h2Target("jdbc:h2:mem:"),
            FailureCode.H2_IN_MEMORY, "anonymous mem", violations);
        Assertions.assertEquals(List.of(), violations, "DG-9: in-memory H2 in production");
    }

    /**
     * DG-10: test mode is refused where the test bundle is not installed
     */
    @Test
    public void dg10TestModeWithoutTheTestBundleIsRefused() {
        List<String> violations = new ArrayList<>();
        expectRefused(new DeploymentGuard(environment(DeploymentGuard.MODE_TEST, false)), h2Target(H2_MEMORY_URL),
            FailureCode.TEST_MODE_WITHOUT_TEST_BUNDLE, "test without the bundle (memory)", violations);
        expectRefused(new DeploymentGuard(environment(DeploymentGuard.MODE_TEST, false)), h2Target(H2_FILE_URL),
            FailureCode.TEST_MODE_WITHOUT_TEST_BUNDLE, "test without the bundle (file)", violations);
        Assertions.assertEquals(List.of(), violations, "DG-10: test mode needs the test bundle");
    }

    /**
     * DG-11: test mode with the bundle is admitted with one warning, and the suite set it before the server started
     */
    @Test
    public void dg11TestModeIsAdmittedWithAWarningAndTheSuiteSetItBeforeTheServerStarted() throws Throwable {
        DeploymentGuard guard = new DeploymentGuard(environment(DeploymentGuard.MODE_TEST, true));
        DeploymentGuard.Result[] result = new DeploymentGuard.Result[1];
        Captured captured = LifecycleTestSupport.captureLogs(
            () -> result[0] = guard.admit(h2Target(H2_MEMORY_URL), new RecordingRevocation()));
        DeploymentGuard.Admitted admitted = Assertions.assertInstanceOf(DeploymentGuard.Admitted.class, result[0],
            "DG-11: test mode with the test bundle must be admitted");
        Assertions.assertEquals(DeploymentGuard.MODE_TEST, admitted.admission().deploymentMode(), "DG-11: the admitted mode");
        Assertions.assertEquals(1, captured.dbacMessages().stream().filter(m -> m.contains("event=DBAC_DEPLOYMENT_TEST_MODE")).count(),
            "DG-11: test mode must be announced with exactly one warning, got " + captured.dbacMessages());
        Assertions.assertEquals(List.of(), LifecycleTestSupport.logContractViolations(captured, List.of("jdbc:h2:")),
            "DG-11: the warning must follow the P1 contract");

        Assertions.assertEquals(DeploymentGuard.MODE_TEST, System.getProperty(DeploymentGuard.DEPLOYMENT_PROPERTY),
            "DG-11: CEServerTestSuite's @BeforeSuite must have set dbac.deployment=test");
        PolicyServiceHolder.State global = PolicyServiceHolder.global().current();
        Ready ready = Assertions.assertInstanceOf(Ready.class, global,
            "DG-11: the server's policy service must be Ready, which it only is if dbac.deployment=test was set before the server started");
        Assertions.assertEquals(DeploymentGuard.MODE_TEST, ready.admission().deploymentMode(),
            "DG-11: the server must have been admitted in test mode");
        Assertions.assertSame(EmbeddedSecurityControllerFactory.getDbInstance(), ready.database(),
            "DG-11: the global holder must hold the server's metadata database");
    }

    // ---------------------------------------------------------------- DG-13

    /**
     * DG-13: shutting the database down releases the advisory lock, and no lock is taken again afterwards
     */
    @Test
    public void dg13ShutdownReleasesTheAdvisoryLock() throws Exception {
        requirePostgres();
        RecordingSource source = new RecordingSource();
        DeploymentGuard guard = new DeploymentGuard(environment(DeploymentGuard.MODE_TEST, true));
        Fixture fixture = new Fixture();
        TestFactory factory = fixture.factory((database, revocation) -> guard.admit(postgresTarget(source, 100), revocation));
        CBDatabase database = factory.init();
        boolean shutDown = false;
        try (Connection other = open()) {
            final Ready ready = Assertions.assertInstanceOf(Ready.class, factory.state(), "DG-13: the policy service must be Ready");
            Assertions.assertEquals(1, source.opened.size(), "DG-13: one lock connection must be held");
            Assertions.assertFalse(tryLock(other), "DG-13: while running, another session must not get the advisory lock");

            database.shutdown();
            shutDown = true;
            Assertions.assertInstanceOf(Disposed.class, factory.state(), "DG-13: the holder must be Disposed");
            Assertions.assertTrue(source.opened.get(0).isClosed(), "DG-13: the lock connection must be closed");
            Assertions.assertEquals(List.of(), lockHolders(), "DG-13: no session may hold the advisory lock after shutdown");
            Assertions.assertTrue(tryLock(other), "DG-13: after shutdown another session must get the advisory lock");
            unlock(other);

            Assertions.assertFalse(ready.admission().assertSingleProcess(), "DG-13: after shutdown a check must deny");
            Assertions.assertEquals(1, source.opened.size(), "DG-13: after shutdown the lock must not be taken again");
        } finally {
            if (!shutDown) {
                database.shutdown();
            }
        }

        // The production path: MetadataTarget.of over the real CloudBeaver pool (DBCP behind InternalProxyConnection)
        PooledPostgres pooled = new PooledPostgres(LifecycleTestSupport.application(), postgresConfig(), Runnable::run);
        pooled.initialize();
        DeploymentGuard.Result pooledResult = null;
        try {
            pooledResult = guard.admit(DeploymentGuard.MetadataTarget.of(pooled), new RecordingRevocation());
            DeploymentGuard.Admitted pooledLease = Assertions.assertInstanceOf(DeploymentGuard.Admitted.class, pooledResult,
                "DG-13: the pooled metadata database must be admitted");
            List<Integer> holders = lockHolders();
            Assertions.assertEquals(1, holders.size(), "DG-13: one pooled session must hold the advisory lock");
            pooledLease.leaseRelease().run();
            Assertions.assertEquals(List.of(), lockHolders(), "DG-13: releasing the lease must free the lock while the pool stays open");
            Assertions.assertTrue(sessionEnded(holders.get(0)),
                "DG-13: the aborted lock session must be ended, not handed back to the pool");
            try (Connection connection = pooled.openConnection();
                 Statement statement = connection.createStatement();
                 ResultSet result = statement.executeQuery("SELECT 1")) {
                Assertions.assertTrue(result.next(), "DG-13: the pool must keep serving after the lease is released");
            }
        } finally {
            // the lease is idempotent; releasing it again here only matters when an assertion above failed
            if (pooledResult instanceof DeploymentGuard.Admitted admitted) {
                admitted.leaseRelease().run();
            }
            pooled.shutdown();
        }

        Fixture pooledFixture = new Fixture();
        TestFactory pooledFactory = pooledFixture.factory((metadata, revocation) ->
            guard.admit(DeploymentGuard.MetadataTarget.of(metadata), revocation));
        pooledFactory.config = postgresConfig();
        pooledFactory.databaseMaker = PooledPostgres::new;
        CBDatabase pooledDatabase = pooledFactory.init();
        boolean pooledShutDown = false;
        try {
            final Ready pooledReady = Assertions.assertInstanceOf(Ready.class, pooledFactory.state(),
                "DG-13: the pooled policy service must be Ready");
            List<Integer> holders = lockHolders();
            Assertions.assertEquals(1, holders.size(), "DG-13: one pooled session must hold the advisory lock");
            pooledDatabase.shutdown();
            pooledShutDown = true;
            Assertions.assertInstanceOf(Disposed.class, pooledFactory.state(), "DG-13: the pooled holder must be Disposed");
            Assertions.assertEquals(List.of(), lockHolders(), "DG-13: no session may hold the lock after the pooled shutdown");
            Assertions.assertTrue(sessionEnded(holders.get(0)), "DG-13: the pooled lock session must be ended at shutdown");
            Assertions.assertThrows(Exception.class, pooledDatabase::openConnection, "DG-13: the pool must be closed after shutdown");
            Assertions.assertFalse(pooledReady.admission().assertSingleProcess(), "DG-13: after the pooled shutdown a check must deny");
            Assertions.assertEquals(List.of(), lockHolders(), "DG-13: the denied check must not take the lock again");
        } finally {
            if (!pooledShutDown) {
                pooledDatabase.shutdown();
            }
        }
    }

    /**
     * A metadata database with the real CloudBeaver connection pool over the test PostgreSQL, and no CloudBeaver schema
     * <p>
     * {@link #initialize()} only builds the pool {@code CBDatabase} builds and records what the
     * database reports, which is everything the guard reads; the pool and its shutdown are the
     * production ones.
     */
    private static final class PooledPostgres extends DbacCBDatabase {
        PooledPostgres(@NotNull ServletApplication application, @NotNull WebDatabaseConfig config, @NotNull ShutdownLifecycle lifecycle) {
            super(application, config, DbacSchema.getSchemaConfigs(), lifecycle);
        }

        @Override
        public void initialize() {
            dataSource = initConnectionPool(driver, "PostgreSQL JDBC Driver");
            dbConnectionInformation = new DBPConnectionInformation(URL, "postgres-jdbc", "PostgreSQL", "test");
        }
    }

    @NotNull
    private static WebDatabaseConfig postgresConfig() {
        WebDatabaseConfig config = new WebDatabaseConfig();
        config.setDriver("postgres-jdbc");
        config.setUrl(URL);
        config.setUser(USER);
        config.setPassword(PASSWORD);
        return config;
    }

    /** Whether the backend has left pg_stat_activity, waiting for it to do so */
    private static boolean sessionEnded(int pid) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(TIMEOUT_SECONDS);
        try (Connection admin = open();
             PreparedStatement statement = admin.prepareStatement("SELECT count(*) FROM pg_stat_activity WHERE pid = ?")) {
            statement.setInt(1, pid);
            while (System.nanoTime() < deadline) {
                try (ResultSet result = statement.executeQuery()) {
                    result.next();
                    if (result.getInt(1) == 0) {
                        return true;
                    }
                }
                Thread.sleep(20);
            }
        }
        return false;
    }

    // ---------------------------------------------------------------- helpers

    @NotNull
    private static DeploymentGuard.Environment environment(@Nullable String deployment, boolean testBundle) {
        return new DeploymentGuard.Environment(() -> deployment, () -> null, () -> testBundle, () -> false, () -> false);
    }

    @NotNull
    private static DeploymentGuard.MetadataTarget h2Target(@NotNull String url) {
        return new DeploymentGuard.MetadataTarget("H2", H2_V2_RELEASE, url, "h2_embedded_v2", 100, failingSource());
    }

    @NotNull
    private static DeploymentGuard.MetadataTarget postgresTarget(@NotNull DeploymentGuard.LockConnectionSource source, int maxConnections) {
        return new DeploymentGuard.MetadataTarget("PostgreSQL", "16.4", URL, "postgres-jdbc", maxConnections, source);
    }

    @NotNull
    private static DeploymentGuard.LockConnectionSource failingSource() {
        return () -> {
            throw new SQLException("FIXTURE: no lock connection for this target");
        };
    }

    @NotNull
    private static Object[] row(@NotNull String url, boolean inMemoryAllowed, @Nullable FailureCode expected) {
        return new Object[]{url, inMemoryAllowed, expected};
    }

    private static void expectRefused(
        @NotNull DeploymentGuard guard,
        @NotNull DeploymentGuard.MetadataTarget target,
        @NotNull FailureCode expected,
        @NotNull String label,
        @NotNull List<String> violations
    ) {
        DeploymentGuard.Result result = guard.admit(target, new RecordingRevocation());
        if (!(result instanceof DeploymentGuard.Refused refused && refused.code() == expected)) {
            violations.add(label + ": expected Refused(" + expected + "), got " + result);
            if (result instanceof DeploymentGuard.Admitted admitted) {
                admitted.leaseRelease().run();
            }
        }
    }

    private static void expectAdmitted(
        @NotNull DeploymentGuard guard,
        @NotNull DeploymentGuard.MetadataTarget target,
        @NotNull String label,
        @NotNull List<String> violations
    ) {
        DeploymentGuard.Result result = guard.admit(target, new RecordingRevocation());
        if (result instanceof DeploymentGuard.Admitted admitted) {
            admitted.leaseRelease().run();
        } else {
            violations.add(label + ": expected Admitted, got " + result);
        }
    }

    @NotNull
    private static String quote(@Nullable String value) {
        return value == null ? "<absent>" : "'" + value + "'";
    }

    @NotNull
    private static String visible(@NotNull String text) {
        StringBuilder builder = new StringBuilder();
        for (char c : text.toCharArray()) {
            if (c < 0x20 || c > 0x7e) {
                builder.append(String.format("<U+%04X>", (int) c));
            } else {
                builder.append(c);
            }
        }
        return builder.toString();
    }

    /** Records every revocation and reports it as having changed the state */
    private static final class RecordingRevocation implements DeploymentGuard.Revocation {
        final List<FailureCode> codes = Collections.synchronizedList(new ArrayList<>());

        @Override
        public boolean revoke(@NotNull FailureCode code) {
            codes.add(code);
            return true;
        }
    }

    /** Opens raw PostgreSQL connections for the guard, remembering each one and its backend pid */
    private static final class RecordingSource implements DeploymentGuard.LockConnectionSource {
        final List<Connection> opened = Collections.synchronizedList(new ArrayList<>());
        final List<Integer> pids = Collections.synchronizedList(new ArrayList<>());

        @NotNull
        @Override
        public Connection open() throws SQLException {
            Connection connection = DeploymentGuardTest.open();
            pids.add(pid(connection));
            opened.add(connection);
            return connection;
        }
    }

    /** How an owner check on a connection the guard opens later goes */
    private enum CheckFault {
        NONE,
        /** It fails at once, with a message full of things a log must not repeat */
        THROWS,
        /** It runs until its query timeout, or for twenty seconds when it has none, and then fails */
        HANGS,
        /** It answers with no row */
        NO_ROW,
        /** It answers with two rows of nothing held */
        TWO_ROWS,
        /** It answers that the backend holds the lock twice */
        COUNT_TWO,
        /** It answers that the backend holds the lock, and that nothing tells when that backend started */
        UNKNOWN_START;

        /** The rows of a made-up answer, or null when the real look-up runs */
        @Nullable
        long[][] rows() {
            return switch (this) {
                case NO_ROW -> new long[0][];
                case TWO_ROWS -> new long[][]{{0, 0, 0}, {0, 0, 0}};
                case COUNT_TWO -> new long[][]{{2, 2, 0}};
                case UNKNOWN_START -> new long[][]{{1, 0, 1}};
                default -> null;
            };
        }
    }

    /**
     * Opens raw PostgreSQL connections for the guard, as {@link RecordingSource} does, wrapped so a case can make one
     * of them report itself invalid while its session lives on, and can make the guard's owner checks fail or hang
     */
    private static final class ControlledSource implements DeploymentGuard.LockConnectionSource {
        final List<Connection> raw = Collections.synchronizedList(new ArrayList<>());
        final List<Connection> handed = Collections.synchronizedList(new ArrayList<>());
        final List<Integer> pids = Collections.synchronizedList(new ArrayList<>());
        /** The connections, by the order they were opened in, whose {@code isValid} answers false */
        final Set<Integer> invalid = ConcurrentHashMap.newKeySet();
        /** The query timeout, in seconds, each owner check was given */
        final List<Integer> timeouts = Collections.synchronizedList(new ArrayList<>());
        final AtomicInteger checks = new AtomicInteger();
        volatile CheckFault fault = CheckFault.NONE;
        /** Whether the lock statement's third column - when its backend started - reads as missing */
        volatile boolean lockWithoutStart;

        @NotNull
        @Override
        public synchronized Connection open() throws SQLException {
            Connection connection = DeploymentGuardTest.open();
            int index = raw.size();
            raw.add(connection);
            pids.add(pid(connection));
            Connection proxy = MetadataTestSupport.proxy(Connection.class, (self, method, args) -> switch (method.getName()) {
                case "isValid" -> !invalid.contains(index) && connection.isValid((Integer) args[0]);
                case "prepareStatement" -> prepare(connection, (String) args[0]);
                case "hashCode" -> System.identityHashCode(self);
                case "equals" -> self == args[0];
                default -> invokeOn(connection, method, args);
            });
            handed.add(proxy);
            return proxy;
        }

        @NotNull
        private PreparedStatement prepare(@NotNull Connection connection, @NotNull String sql) throws SQLException {
            if (sql.contains("pg_try_advisory_lock") && lockWithoutStart) {
                PreparedStatement lock = connection.prepareStatement(sql);
                return MetadataTestSupport.proxy(PreparedStatement.class, (self, method, args) -> switch (method.getName()) {
                    case "executeQuery" -> withoutThirdColumn(lock.executeQuery());
                    case "hashCode" -> System.identityHashCode(self);
                    case "equals" -> self == args[0];
                    default -> invokeOn(lock, method, args);
                });
            }
            if (!sql.contains("pg_locks")) {
                return connection.prepareStatement(sql);
            }
            checks.incrementAndGet();
            CheckFault now = fault;
            if (now == CheckFault.THROWS) {
                throw new SQLException("FATAL: owner check refused at pg.internal.example for " + LifecycleTestSupport.SECRET_MARKER
                    + " in SELECT ... FROM pg_locks", "08006");
            }
            long[][] madeUp = now.rows();
            PreparedStatement real = now == CheckFault.HANGS || madeUp != null ? null : connection.prepareStatement(sql);
            int[] timeout = {0};
            return MetadataTestSupport.proxy(PreparedStatement.class, (self, method, args) -> {
                switch (method.getName()) {
                    case "setQueryTimeout" -> {
                        timeout[0] = (Integer) args[0];
                        timeouts.add(timeout[0]);
                    }
                    case "executeQuery" -> {
                        if (madeUp != null) {
                            return answer(madeUp);
                        }
                        if (real == null) {
                            Thread.sleep(TimeUnit.SECONDS.toMillis(timeout[0] > 0 ? timeout[0] : 20));
                            throw new SQLTimeoutException("FIXTURE: the owner check ran out of time at pg.internal.example");
                        }
                    }
                    case "hashCode" -> {
                        return System.identityHashCode(self);
                    }
                    case "equals" -> {
                        return self == args[0];
                    }
                    default -> {
                    }
                }
                if (real == null) {
                    return method.getReturnType() == boolean.class ? Boolean.FALSE : null;
                }
                return invokeOn(real, method, args);
            });
        }
    }

    /** The real lock result, except that its third column reads as SQL NULL */
    @NotNull
    private static ResultSet withoutThirdColumn(@NotNull ResultSet result) {
        boolean[] lastWasThird = {false};
        return MetadataTestSupport.proxy(ResultSet.class, (self, method, args) -> {
            String name = method.getName();
            if (name.startsWith("get") && args != null && args.length > 0 && Integer.valueOf(3).equals(args[0])) {
                lastWasThird[0] = true;
                return zeroOf(method.getReturnType());
            }
            if (name.equals("wasNull") && lastWasThird[0]) {
                return true;
            }
            if (name.startsWith("get")) {
                lastWasThird[0] = false;
            }
            return switch (name) {
                case "hashCode" -> System.identityHashCode(self);
                case "equals" -> self == args[0];
                default -> invokeOn(result, method, args);
            };
        });
    }

    /** What a getter of this type returns for SQL NULL */
    @Nullable
    private static Object zeroOf(@NotNull Class<?> type) {
        if (type == boolean.class) {
            return Boolean.FALSE;
        }
        if (type == int.class) {
            return 0;
        }
        if (type == long.class) {
            return 0L;
        }
        if (type == double.class) {
            return 0.0d;
        }
        return null;
    }

    /** A made-up owner look-up answer: these rows of numbers, read by column */
    @NotNull
    private static ResultSet answer(@NotNull long[][] rows) {
        int[] at = {-1};
        return MetadataTestSupport.proxy(ResultSet.class, (self, method, args) -> switch (method.getName()) {
            case "next" -> ++at[0] < rows.length;
            case "getLong" -> rows[at[0]][(Integer) args[0] - 1];
            case "getInt" -> (int) rows[at[0]][(Integer) args[0] - 1];
            case "wasNull", "isClosed" -> false;
            case "close" -> null;
            case "hashCode" -> System.identityHashCode(self);
            case "equals" -> self == args[0];
            default -> throw new SQLException("FIXTURE: a made-up answer has no " + method.getName());
        });
    }

    @Nullable
    private static Object invokeOn(
        @NotNull Object target,
        @NotNull java.lang.reflect.Method method,
        @Nullable Object[] args
    ) throws Throwable {
        try {
            return method.invoke(target, args);
        } catch (java.lang.reflect.InvocationTargetException e) {
            throw e.getTargetException();
        }
    }

    private static void execute(@NotNull Connection connection, @NotNull String sql) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.executeQuery(sql).close();
        }
    }

    /** How many advisory locks the backend holds in this database, of any key and mode */
    private static int advisoryLocksOf(int pid) throws SQLException {
        try (Connection connection = open();
             PreparedStatement statement = connection.prepareStatement(
                 "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND granted AND pid = ?")) {
            statement.setInt(1, pid);
            try (ResultSet result = statement.executeQuery()) {
                result.next();
                return result.getInt(1);
            }
        }
    }

    /** Whether the backend shows up waiting - not granted - for an advisory lock, waiting for it to do so */
    private static boolean awaitWaitingFor(int pid) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(TIMEOUT_SECONDS);
        try (Connection connection = open();
             PreparedStatement statement = connection.prepareStatement(
                 "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted AND pid = ?")) {
            statement.setInt(1, pid);
            while (System.nanoTime() < deadline) {
                try (ResultSet result = statement.executeQuery()) {
                    result.next();
                    if (result.getInt(1) == 1) {
                        return true;
                    }
                }
                Thread.sleep(20);
            }
        }
        return false;
    }

    // ---------------------------------------------------------------- PostgreSQL

    private static void requirePostgres() {
        Assumptions.assumeTrue(available, "PostgreSQL is not reachable at " + URL + " - " + unusableBecause);
    }

    private static boolean tryLock(@NotNull Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("SELECT pg_try_advisory_lock(?)")) {
            statement.setLong(1, DeploymentGuard.ADVISORY_LOCK_KEY);
            try (ResultSet result = statement.executeQuery()) {
                result.next();
                return result.getBoolean(1);
            }
        }
    }

    private static void unlock(@NotNull Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("SELECT pg_advisory_unlock_all()")) {
            statement.executeQuery().close();
        }
    }

    /** Tries the lock until the terminated holder's session is gone */
    private static boolean waitForLock(@NotNull Connection connection) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(TIMEOUT_SECONDS);
        while (System.nanoTime() < deadline) {
            if (tryLock(connection)) {
                return true;
            }
            Thread.sleep(50);
        }
        return false;
    }

    private static int pid(@NotNull Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery("SELECT pg_backend_pid()")) {
            result.next();
            return result.getInt(1);
        }
    }

    /** Ends a backend and waits until it is gone, as a crashed or killed session would be */
    private static void terminate(int pid) throws Exception {
        try (Connection admin = open()) {
            try (PreparedStatement statement = admin.prepareStatement("SELECT pg_terminate_backend(?)")) {
                statement.setInt(1, pid);
                statement.executeQuery().close();
            }
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(TIMEOUT_SECONDS);
            while (System.nanoTime() < deadline) {
                try (PreparedStatement statement = admin.prepareStatement("SELECT count(*) FROM pg_stat_activity WHERE pid = ?")) {
                    statement.setInt(1, pid);
                    try (ResultSet result = statement.executeQuery()) {
                        result.next();
                        if (result.getInt(1) == 0) {
                            return;
                        }
                    }
                }
                Thread.sleep(20);
            }
            throw new IllegalStateException("FIXTURE: backend " + pid + " did not terminate");
        }
    }

    /** The pids of the sessions holding the DBAC advisory lock in this database */
    @NotNull
    private static List<Integer> lockHolders() throws SQLException {
        long key = DeploymentGuard.ADVISORY_LOCK_KEY;
        try (Connection connection = open();
             PreparedStatement statement = connection.prepareStatement(
                 "SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND granted"
                     + " AND database = (SELECT oid FROM pg_database WHERE datname = current_database())"
                     + " AND classid::bigint = ? AND objid::bigint = ? AND objsubid = 1 ORDER BY pid")) {
            statement.setLong(1, (key >>> 32) & 0xFFFFFFFFL);
            statement.setLong(2, key & 0xFFFFFFFFL);
            List<Integer> pids = new ArrayList<>();
            try (ResultSet result = statement.executeQuery()) {
                while (result.next()) {
                    pids.add(result.getInt(1));
                }
            }
            return pids;
        }
    }

    private static boolean probe() {
        try {
            driver = loadDriver();
        } catch (Exception e) {
            driver = null;
            unusableBecause = "the PostgreSQL JDBC driver could not be loaded (" + e + ")";
            return false;
        }
        try (Connection connection = open()) {
            return connection.isValid(5);
        } catch (Exception e) {
            unusableBecause = "connecting failed (" + e + ")";
            return false;
        }
    }

    @NotNull
    private static Connection open() throws SQLException {
        Properties properties = new Properties();
        properties.setProperty("user", USER);
        properties.setProperty("password", PASSWORD);
        Connection connection = driver.connect(URL, properties);
        if (connection == null) {
            throw new SQLException("The PostgreSQL driver did not accept " + URL);
        }
        return connection;
    }

    @NotNull
    private static Driver loadDriver() throws Exception {
        File jar = findDriverJar();
        if (jar == null) {
            throw new IllegalStateException("PostgreSQL JDBC driver jar not found under deploy/drivers");
        }
        URLClassLoader loader = new URLClassLoader(new URL[]{jar.toURI().toURL()}, Driver.class.getClassLoader());
        return (Driver) Class.forName("org.postgresql.Driver", true, loader).getDeclaredConstructor().newInstance();
    }

    @Nullable
    private static File findDriverJar() {
        File dir = new File(System.getProperty("user.dir"));
        for (int i = 0; i < 6 && dir != null; i++, dir = dir.getParentFile()) {
            File[] jars = new File(dir, "deploy/drivers/postgresql").listFiles((d, name) ->
                name.startsWith("postgresql-") && name.endsWith(".jar"));
            if (jars != null && jars.length > 0) {
                return jars[0];
            }
        }
        return null;
    }
}
