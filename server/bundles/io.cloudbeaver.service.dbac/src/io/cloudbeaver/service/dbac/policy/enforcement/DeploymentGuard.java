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
package io.cloudbeaver.service.dbac.policy.enforcement;

import io.cloudbeaver.model.app.ServletApplication;
import io.cloudbeaver.service.dbac.PolicyServiceHolder.FailureCode;
import io.cloudbeaver.service.security.db.CBDatabase;
import org.eclipse.core.runtime.Platform;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.jkiss.dbeaver.Log;
import org.jkiss.dbeaver.model.DBPConnectionInformation;
import org.jkiss.dbeaver.runtime.DBWorkbench;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * Admits the policy service only on a deployment it can keep to one process
 * <p>
 * DBAC's write enforcement keeps its locks and its transaction taint in the JVM, so two server
 * processes sharing one metadata database would each believe they alone decide. This guard runs
 * once, after the metadata database has been initialized and before the policy service may become
 * ready, and refuses anything it cannot hold to one process:
 * <ul>
 *     <li>G1 the operator acknowledged the deployment: {@code dbac.deployment} is exactly
 *     {@code single-process} or {@code test};</li>
 *     <li>G2 test mode is only accepted where the test bundle is installed;</li>
 *     <li>G3 the application does not declare itself multi-node or distributed. In CE both are
 *     hard-coded false - they are declarations, never a detection;</li>
 *     <li>G4 the metadata engine is H2 or PostgreSQL, and the product name agrees with the URL. For
 *     H2 the driver id and the release H2 reports must be a verified pair: {@code h2_embedded_v2}
 *     with 2.1.214, {@code h2_embedded_v3} with 2.4.240;</li>
 *     <li>G5 H2: the URL is an embedded local file that H2 locks against a second process (or an
 *     in-memory database in test mode). PostgreSQL: a session-level advisory lock is taken on a
 *     connection that is kept for as long as the service runs.</li>
 * </ul>
 * A network filesystem cannot be told from a local path and is not supported; the guard does not
 * try to detect it. Neither is a PostgreSQL metadata database reached through a transaction- or
 * statement-pooling proxy (such as PgBouncer in those modes), nor an engine that only speaks the
 * PostgreSQL protocol: a session-level advisory lock needs one server session per connection, and
 * the product name the driver reports cannot tell these apart.
 * <p>
 * Every refusal is logged with a fixed code and a correlation id only - never the URL, a host, a
 * value or an exception message.
 */
public final class DeploymentGuard {

    /** The system property the operator sets to acknowledge the deployment */
    public static final String DEPLOYMENT_PROPERTY = "dbac.deployment";
    /** {@link #DEPLOYMENT_PROPERTY} value for a production server: one process per metadata database */
    public static final String MODE_SINGLE_PROCESS = "single-process";
    /** {@link #DEPLOYMENT_PROPERTY} value for the test server, accepted only with the test bundle */
    public static final String MODE_TEST = "test";
    /** H2's own URL remapping property; set at all, it could replace the URL this guard checked */
    public static final String H2_URL_MAP_PROPERTY = "h2.urlMap";
    /** The bundle that only the test runtime contains */
    public static final String TEST_BUNDLE = "io.cloudbeaver.test.platform";
    /**
     * The PostgreSQL advisory lock key
     * <p>
     * The first eight bytes of SHA-256({@code "io.cloudbeaver.service.dbac/single-process-lock/v1"}),
     * read as a signed big-endian long ({@code 0x8CE36BC91C95B81D}). Advisory locks are scoped to the
     * database; the schema and table prefix are deliberately not mixed in, so that two servers on
     * one database always contend, whatever their schema settings.
     */
    public static final long ADVISORY_LOCK_KEY = -8294667577174149091L;
    /** The lock connection is held for good, so a pool smaller than this would leave none for requests */
    public static final int MIN_POOL_CONNECTIONS = 2;

    /**
     * Moves the ready policy service to failed; the only lifecycle change the guard can make
     */
    @FunctionalInterface
    public interface Revocation {
        /**
         * Fails the policy service this was issued for, if it is still ready
         *
         * @return whether this call made the change
         */
        boolean revoke(@NotNull FailureCode code);
    }

    /**
     * Where the guard opens a connection to hold the advisory lock on
     */
    @FunctionalInterface
    public interface LockConnectionSource {
        /**
         * A connection to the metadata database that the guard will own
         */
        @NotNull
        Connection open() throws SQLException;
    }

    /**
     * What an admitted deployment keeps checking on every enforcement entry
     */
    public interface Admission {
        /**
         * The {@link #DEPLOYMENT_PROPERTY} value that was acknowledged at startup
         */
        @NotNull
        String deploymentMode();

        /**
         * Confirms the deployment is still the one that was admitted
         * <p>
         * The deployment property must still hold its startup value, and on PostgreSQL the lock
         * session must still be alive; if it is not, the lock is taken again on a new connection,
         * exactly once per loss. A lock another process took in the meantime, or a changed property,
         * fails the policy service through its {@link Revocation}.
         *
         * @return whether the caller may proceed
         */
        boolean assertSingleProcess();
    }

    /**
     * What {@link #admit} decided
     */
    public sealed interface Result permits Admitted, Refused {
    }

    /**
     * Admitted, with the admission to keep and the one way to release what it holds
     *
     * @param admission    kept by the ready policy service
     * @param leaseRelease releases the advisory lock connection, if any; safe to call more than once
     */
    public record Admitted(@NotNull Admission admission, @NotNull Runnable leaseRelease) implements Result {
    }

    /**
     * Refused, for the given reason; nothing is held
     */
    public record Refused(@NotNull FailureCode code) implements Result {
    }

    /**
     * The inputs that do not come from the metadata database
     *
     * @param deploymentProperty  the current {@link #DEPLOYMENT_PROPERTY} value, or null
     * @param urlMapProperty      the current {@link #H2_URL_MAP_PROPERTY} value, or null
     * @param testBundlePresent   whether {@link #TEST_BUNDLE} is installed
     * @param multiNodeDeclared   whether the application declares itself multi-node
     * @param distributedDeclared whether the application declares itself distributed
     */
    public record Environment(
        @NotNull Supplier<String> deploymentProperty,
        @NotNull Supplier<String> urlMapProperty,
        @NotNull BooleanSupplier testBundlePresent,
        @NotNull BooleanSupplier multiNodeDeclared,
        @NotNull BooleanSupplier distributedDeclared
    ) {
        /**
         * The environment a production server runs in
         */
        @NotNull
        public static Environment production(@NotNull ServletApplication application) {
            return new Environment(
                () -> System.getProperty(DEPLOYMENT_PROPERTY),
                () -> System.getProperty(H2_URL_MAP_PROPERTY),
                () -> Platform.getBundle(TEST_BUNDLE) != null,
                application::isMultiNode,
                DBWorkbench::isDistributed
            );
        }
    }

    /**
     * What the guard needs to know about the metadata database
     *
     * @param productName    the engine the database reported when it was initialized, or null
     * @param productVersion the engine version the database reported, or null
     * @param resolvedUrl    the JDBC URL with variables resolved, exactly as the pool uses it
     * @param driverId       the configured driver id, or null
     * @param maxConnections the pool's maximum size
     * @param connections    where the PostgreSQL lock connection is opened
     */
    public record MetadataTarget(
        @Nullable String productName,
        @Nullable String productVersion,
        @NotNull String resolvedUrl,
        @Nullable String driverId,
        int maxConnections,
        @NotNull LockConnectionSource connections
    ) {
        /**
         * Describes an initialized metadata database
         */
        @NotNull
        public static MetadataTarget of(@NotNull CBDatabase database) {
            DBPConnectionInformation information = database.getMetaDataInfo();
            return new MetadataTarget(
                information == null ? null : information.getProductName(),
                information == null ? null : information.getProductVersion(),
                database.getDatabaseConfig().getResolvedUrl(),
                database.getDatabaseConfig().getDriver(),
                database.getDatabaseConfig().getPool().getMaxConnections(),
                database::openConnection
            );
        }
    }

    /** Logged for every refusal, with its {@link FailureCode} */
    private static final String EVENT_REFUSED = "DBAC_DEPLOYMENT_REFUSED";
    /** Logged, as a warning, when the test deployment is admitted */
    private static final String EVENT_TEST_MODE = "DBAC_DEPLOYMENT_TEST_MODE";
    /** Logged when an admitted deployment is revoked, with its {@link FailureCode} */
    private static final String EVENT_REVOKED = "DBAC_DEPLOYMENT_REVOKED";
    /** Logged when opening, locking or checking the advisory lock connection failed */
    private static final String EVENT_LOCK_FAILED = "DBAC_ADVISORY_LOCK_FAILED";
    /** Logged when closing an advisory lock connection failed */
    private static final String EVENT_LOCK_RELEASE_FAILED = "DBAC_ADVISORY_LOCK_RELEASE_FAILED";
    /** Logged when the deployment could not be checked again */
    private static final String EVENT_CHECK_FAILED = "DBAC_DEPLOYMENT_CHECK_FAILED";

    private static final String H2_PREFIX = "jdbc:h2:";
    private static final String POSTGRES_PREFIX = "jdbc:postgresql:";
    private static final String PRODUCT_H2 = "H2";
    private static final String PRODUCT_POSTGRES = "PostgreSQL";
    /** The H2 drivers accepted, each with the one H2 release it must actually report */
    private static final Map<String, String> H2_DRIVER_VERSIONS = Map.of(
        "h2_embedded_v2", "2.1.214",
        "h2_embedded_v3", "2.4.240"
    );
    private static final String FILE_PREFIX = "file:";
    private static final String FILE_LOCK = "FILE_LOCK";
    private static final String FILE_LOCK_FILE = "FILE";
    private static final int LOCK_CHECK_TIMEOUT_SECONDS = 1;

    /** The release of a deployment that holds nothing */
    private static final Runnable NOTHING_TO_RELEASE = () -> {
    };

    private static final Log log = Log.getLog(DeploymentGuard.class);

    private final Environment environment;

    public DeploymentGuard(@NotNull Environment environment) {
        this.environment = environment;
    }

    /**
     * Checks G1-G5 against the metadata database, once, at startup
     * <p>
     * On PostgreSQL an admitted result holds the advisory lock connection; whoever receives it owns
     * its {@link Admitted#leaseRelease()}. A refused result holds nothing.
     */
    @NotNull
    public Result admit(@NotNull MetadataTarget target, @NotNull Revocation revocation) {
        String mode = environment.deploymentProperty().get();
        if (!MODE_SINGLE_PROCESS.equals(mode) && !MODE_TEST.equals(mode)) {
            return refuse(FailureCode.DEPLOYMENT_NOT_ACKNOWLEDGED);
        }
        boolean testMode = MODE_TEST.equals(mode);
        if (testMode && !environment.testBundlePresent().getAsBoolean()) {
            return refuse(FailureCode.TEST_MODE_WITHOUT_TEST_BUNDLE);
        }
        if (environment.multiNodeDeclared().getAsBoolean() || environment.distributedDeclared().getAsBoolean()) {
            return refuse(FailureCode.MULTI_NODE_DECLARED);
        }
        String url = target.resolvedUrl();
        if (PRODUCT_H2.equals(target.productName()) && url.startsWith(H2_PREFIX)) {
            return admitH2(mode, testMode, target, revocation);
        }
        if (PRODUCT_POSTGRES.equals(target.productName()) && url.startsWith(POSTGRES_PREFIX)) {
            return admitPostgres(mode, testMode, target, revocation);
        }
        return refuse(FailureCode.METADATA_ENGINE_UNSUPPORTED);
    }

    @NotNull
    private Result admitH2(@NotNull String mode, boolean testMode, @NotNull MetadataTarget target, @NotNull Revocation revocation) {
        // G4: the driver id and the release H2 itself reported must be one of the verified pairs
        String release = target.driverId() == null ? null : H2_DRIVER_VERSIONS.get(target.driverId());
        String reported = target.productVersion();
        if (release == null || reported == null || !(reported.equals(release) || reported.startsWith(release + " "))) {
            return refuse(FailureCode.METADATA_ENGINE_UNSUPPORTED);
        }
        String urlMap = environment.urlMapProperty().get();
        if (urlMap != null && !urlMap.isEmpty()) {
            return refuse(FailureCode.H2_URL_REMAPPED);
        }
        FailureCode refusal = h2UrlRefusal(target.resolvedUrl(), testMode);
        if (refusal != null) {
            return refuse(refusal);
        }
        return admitted(mode, testMode, null, revocation);
    }

    @NotNull
    private Result admitPostgres(@NotNull String mode, boolean testMode, @NotNull MetadataTarget target, @NotNull Revocation revocation) {
        if (target.maxConnections() < MIN_POOL_CONNECTIONS) {
            return refuse(FailureCode.POOL_TOO_SMALL);
        }
        Connection connection;
        try {
            connection = target.connections().open();
        } catch (SQLException | RuntimeException e) {
            logFailure(EVENT_LOCK_FAILED, "DBAC could not open the advisory lock connection", e);
            return refuse(FailureCode.ADVISORY_LOCK_UNAVAILABLE);
        }
        boolean locked;
        try {
            locked = tryLock(connection);
        } catch (SQLException | RuntimeException e) {
            logFailure(EVENT_LOCK_FAILED, "DBAC could not take the advisory lock", e);
            release(connection, false);
            return refuse(FailureCode.ADVISORY_LOCK_UNAVAILABLE);
        }
        if (!locked) {
            release(connection, false);
            return refuse(FailureCode.ADVISORY_LOCK_HELD);
        }
        return admitted(mode, testMode, new LeaseOwner(target.connections(), connection), revocation);
    }

    @NotNull
    private Result admitted(@NotNull String mode, boolean testMode, @Nullable LeaseOwner lease, @NotNull Revocation revocation) {
        if (testMode) {
            try {
                log.warn("DBAC deployment admitted in test mode; never use it in production [event=" + EVENT_TEST_MODE
                    + " EVENT_ID=" + UUID.randomUUID() + "]");
            } catch (RuntimeException | Error ignored) {
                // Deliberately nothing: admission must not depend on whether it could be logged.
            }
        }
        return new Admitted(new CheckedAdmission(mode, lease, revocation), lease == null ? NOTHING_TO_RELEASE : lease::close);
    }

    /**
     * Why an H2 metadata URL is refused, or null when it is accepted
     * <p>
     * The URL is split at its first raw {@code ;}, exactly where H2 splits it; nothing before that
     * point is ever read as a setting. Only an embedded file path (or, when allowed, an in-memory
     * database) is accepted, and the only setting accepted is {@code FILE_LOCK=FILE}.
     */
    @Nullable
    public static FailureCode h2UrlRefusal(@NotNull String resolvedUrl, boolean inMemoryAllowed) {
        // H3: the exact prefix, printable ASCII only
        if (!resolvedUrl.startsWith(H2_PREFIX)) {
            return FailureCode.H2_URL_UNSUPPORTED;
        }
        for (int i = 0; i < resolvedUrl.length(); i++) {
            char c = resolvedUrl.charAt(i);
            if (c < 0x20 || c > 0x7E) {
                return FailureCode.H2_URL_UNSUPPORTED;
            }
        }
        // H4: split where H2 splits - the first raw ';'; what precedes it is never a setting
        String rest = resolvedUrl.substring(H2_PREFIX.length());
        int semicolon = rest.indexOf(';');
        String database = semicolon < 0 ? rest : rest.substring(0, semicolon);
        String settings = semicolon < 0 ? "" : rest.substring(semicolon + 1);
        if (database.isEmpty()) {
            return FailureCode.H2_URL_UNSUPPORTED;
        }
        String lower = database.toLowerCase(Locale.ROOT);
        // H5: in-memory, only where a second process cannot matter; "." alone is H2's in-memory name
        if (lower.startsWith("mem:") || database.equals(".")) {
            return inMemoryAllowed ? settingsRefusal(settings) : FailureCode.H2_IN_MEMORY;
        }
        // H6: remote
        if (lower.startsWith("tcp:") || lower.startsWith("ssl:")) {
            return FailureCode.H2_REMOTE;
        }
        // H7: only the lower-case file: prefix, which is the only one H2 strips
        String path;
        if (database.startsWith(FILE_PREFIX)) {
            path = database.substring(FILE_PREFIX.length());
        } else if (lower.startsWith(FILE_PREFIX)) {
            return FailureCode.H2_URL_UNSUPPORTED;
        } else {
            path = database;
        }
        // H7a: nothing left after file: names no file (C16)
        if (path.isEmpty()) {
            return FailureCode.H2_URL_UNSUPPORTED;
        }
        // H5a: a path relative to the working directory depends on where the server was started
        if (path.startsWith(".")) {
            return FailureCode.H2_URL_UNSUPPORTED;
        }
        // H8a: UNC and authority-style paths open a file on another machine
        if (path.length() >= 2 && isSeparator(path.charAt(0)) && isSeparator(path.charAt(1))) {
            return FailureCode.H2_NETWORK_PATH;
        }
        // H8: no ':' at all, except one drive letter followed by a separator
        int colon = path.indexOf(':');
        if (colon >= 0) {
            boolean driveLetter = colon == 1 && isAsciiLetter(path.charAt(0)) && path.length() > 2
                && isSeparator(path.charAt(2)) && path.indexOf(':', 2) < 0;
            if (!driveLetter) {
                return FailureCode.H2_SUBPROTOCOL_UNSUPPORTED;
            }
        }
        return settingsRefusal(settings);
    }

    /** H9-H14: no escape character, well-formed keys, no repeated key, and only FILE_LOCK=FILE */
    @Nullable
    private static FailureCode settingsRefusal(@NotNull String settings) {
        if (settings.isEmpty()) {
            return null;
        }
        if (settings.indexOf('\\') >= 0) {
            return FailureCode.H2_URL_UNSUPPORTED;
        }
        Set<String> seen = new HashSet<>();
        for (String segment : settings.split(";", -1)) {
            if (segment.isEmpty()) {
                continue;
            }
            int equals = segment.indexOf('=');
            if (equals < 0) {
                return FailureCode.H2_SETTING_UNSUPPORTED;
            }
            String key = segment.substring(0, equals);
            if (!isSettingKey(key)) {
                return FailureCode.H2_SETTING_UNSUPPORTED;
            }
            String upper = key.toUpperCase(Locale.ROOT);
            if (!seen.add(upper) || !FILE_LOCK.equals(upper)) {
                return FailureCode.H2_SETTING_UNSUPPORTED;
            }
            if (!FILE_LOCK_FILE.equalsIgnoreCase(segment.substring(equals + 1))) {
                return FailureCode.H2_FILE_LOCK_UNSUPPORTED;
            }
        }
        return null;
    }

    private static boolean isSeparator(char c) {
        return c == '/' || c == '\\';
    }

    private static boolean isAsciiLetter(char c) {
        return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z';
    }

    private static boolean isSettingKey(@NotNull String key) {
        if (key.isEmpty()) {
            return false;
        }
        for (int i = 0; i < key.length(); i++) {
            char c = key.charAt(i);
            if (!isAsciiLetter(c) && c != '_') {
                return false;
            }
        }
        return true;
    }

    @NotNull
    private static Result refuse(@NotNull FailureCode code) {
        logCode(EVENT_REFUSED, "DBAC deployment refused; write-gated operations stay denied", code);
        return new Refused(code);
    }

    private static boolean tryLock(@NotNull Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("SELECT pg_try_advisory_lock(?)")) {
            statement.setLong(1, ADVISORY_LOCK_KEY);
            try (ResultSet result = statement.executeQuery()) {
                return result.next() && result.getBoolean(1);
            }
        }
    }

    /**
     * Closes a lock connection for good: unlock (when held), abort, close
     * <p>
     * A pooled connection's {@code close()} only returns it to the pool, and a session-level lock
     * survives that. Aborting first makes the pool discard the connection instead, which ends the
     * session and with it any lock the unlock could not release.
     */
    private static void release(@NotNull Connection connection, boolean held) {
        if (held) {
            try (PreparedStatement statement = connection.prepareStatement("SELECT pg_advisory_unlock(?)")) {
                statement.setLong(1, ADVISORY_LOCK_KEY);
                statement.executeQuery().close();
            } catch (SQLException | RuntimeException ignored) {
                // The session may already be gone, which released the lock as well.
            }
        }
        try {
            connection.abort(Runnable::run);
        } catch (SQLException | RuntimeException e) {
            logFailure(EVENT_LOCK_RELEASE_FAILED, "DBAC could not abort the advisory lock connection", e);
        }
        try {
            connection.close();
        } catch (SQLException | RuntimeException e) {
            logFailure(EVENT_LOCK_RELEASE_FAILED, "DBAC could not close the advisory lock connection", e);
        }
    }

    private static void logFailure(@NotNull String eventCode, @NotNull String summary, @NotNull Throwable failure) {
        try {
            log.error(summary + " [event=" + eventCode
                + " EVENT_ID=" + UUID.randomUUID()
                + " exception=" + failure.getClass().getName() + "]");
        } catch (RuntimeException | Error ignored) {
            // Deliberately nothing: the decision must not depend on whether it could be logged.
        }
    }

    private static void logCode(@NotNull String eventCode, @NotNull String summary, @NotNull FailureCode code) {
        try {
            log.error(summary + " [event=" + eventCode + " EVENT_ID=" + UUID.randomUUID() + " code=" + code + "]");
        } catch (RuntimeException | Error ignored) {
            // Deliberately nothing: the decision must not depend on whether it could be logged.
        }
    }

    /**
     * The admission an admitted deployment keeps
     */
    private final class CheckedAdmission implements Admission {
        private final String mode;
        @Nullable
        private final LeaseOwner lease;
        private final Revocation revocation;

        private CheckedAdmission(@NotNull String mode, @Nullable LeaseOwner lease, @NotNull Revocation revocation) {
            this.mode = mode;
            this.lease = lease;
            this.revocation = revocation;
        }

        @NotNull
        @Override
        public String deploymentMode() {
            return mode;
        }

        @Override
        public boolean assertSingleProcess() {
            try {
                if (!mode.equals(environment.deploymentProperty().get())) {
                    revoke(FailureCode.DEPLOYMENT_PROPERTY_CHANGED);
                    return false;
                }
                return lease == null || lease.ensureHeld(this::revoke);
            } catch (RuntimeException e) {
                logFailure(EVENT_CHECK_FAILED, "DBAC could not check the deployment again", e);
                return false;
            }
        }

        private void revoke(@NotNull FailureCode code) {
            if (revocation.revoke(code)) {
                logCode(EVENT_REVOKED, "DBAC deployment revoked; write-gated operations are denied from now on", code);
            }
        }
    }

    /**
     * Owns the advisory lock connection; G, the lock that serializes replacing and releasing it
     * <p>
     * G is never held while another lock is requested. The connection is replaced at most once per
     * loss - a check that waited for G finds it already replaced - and never after {@link #close()},
     * which is final: a closed or lost lease never opens a connection again.
     */
    private static final class LeaseOwner {
        private final ReentrantLock guard = new ReentrantLock();
        private final LockConnectionSource source;
        @Nullable
        private volatile Connection current;
        private boolean closed;

        private LeaseOwner(@NotNull LockConnectionSource source, @NotNull Connection connection) {
            this.source = source;
            this.current = connection;
        }

        /**
         * Whether the lock is held, taking it again on a new connection - new lock first, old connection after
         *
         * @param lost told once, when another session holds the lock
         */
        private boolean ensureHeld(@NotNull Consumer<FailureCode> lost) {
            Connection seen = current;
            if (seen != null && isAlive(seen)) {
                return true;
            }
            guard.lock();
            try {
                if (closed) {
                    return false;
                }
                if (current != seen) {
                    return current != null;
                }
                Connection fresh;
                try {
                    fresh = source.open();
                } catch (SQLException | RuntimeException e) {
                    logFailure(EVENT_LOCK_FAILED, "DBAC could not reopen the advisory lock connection", e);
                    return false;
                }
                boolean locked;
                try {
                    locked = tryLock(fresh);
                } catch (SQLException | RuntimeException e) {
                    logFailure(EVENT_LOCK_FAILED, "DBAC could not take the advisory lock again", e);
                    release(fresh, false);
                    return false;
                }
                if (locked) {
                    current = fresh;
                    if (seen != null) {
                        release(seen, true);
                    }
                    return true;
                }
                release(fresh, false);
                if (seen != null) {
                    release(seen, true);
                }
                current = null;
                closed = true;
                lost.accept(FailureCode.ADVISORY_LOCK_LOST);
                return false;
            } finally {
                guard.unlock();
            }
        }

        /** Releases the lock connection for good; later calls do nothing */
        private void close() {
            guard.lock();
            try {
                if (closed) {
                    return;
                }
                closed = true;
                Connection held = current;
                current = null;
                if (held != null) {
                    release(held, true);
                }
            } finally {
                guard.unlock();
            }
        }

        private static boolean isAlive(@NotNull Connection connection) {
            try {
                return connection.isValid(LOCK_CHECK_TIMEOUT_SECONDS);
            } catch (SQLException | RuntimeException e) {
                return false;
            }
        }
    }
}
