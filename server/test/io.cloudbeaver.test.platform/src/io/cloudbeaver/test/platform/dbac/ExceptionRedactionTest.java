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
import io.cloudbeaver.service.dbac.policy.AuthorizationDecision;
import io.cloudbeaver.service.dbac.policy.DbAccessPolicyConfig;
import io.cloudbeaver.service.dbac.policy.DbAccessPolicyService;
import io.cloudbeaver.service.dbac.policy.DbOperationCategory;
import io.cloudbeaver.service.dbac.policy.DenialReason;
import io.cloudbeaver.service.dbac.policy.WriteAuthorizationRequest;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.jkiss.dbeaver.Log;
import org.jkiss.dbeaver.model.DBPDataSourceContainer;
import org.jkiss.dbeaver.model.app.DBPDataSourceRegistry;
import org.jkiss.dbeaver.model.app.DBPProject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The two places the policy core logs a failure, and the contract that governs what they write
 * <p>
 * The <b>permission-store read catch</b> and the <b>unexpected authorization catch</b> in
 * {@code DbAccessPolicyService} used to hand the exception object to the logger, so its message and
 * stack trace were written out. A metadata pool or driver message routinely carries a JDBC URL, a
 * host, or a property value. Slice 4a may not add a production caller of {@code authorize()} until
 * both are redacted, which is why these are the first tests to go green.
 * <p>
 * The contract, checked in full on every run so that a partial fix shows which clauses are still
 * open:
 * <ul>
 *     <li>neither the exception's message nor any URL, host, user or password fragment of it is
 *     logged;</li>
 *     <li>the exception's class name is logged;</li>
 *     <li>a correlation id is logged as {@code EVENT_ID=<UUID>}, and it is new for every event;</li>
 *     <li>a fixed event code names which of the two failures it was;</li>
 *     <li>the key is logged when it was already established, and a fixed placeholder when not;</li>
 *     <li>each key id is encoded, so a hostile id cannot break the line or forge a field;</li>
 *     <li>the exception object is not handed to the logger, and no stack trace is written;</li>
 *     <li>a logger that fails does not change the decision - same reason, same key or no key.</li>
 * </ul>
 * Text is captured through the platform log's per-thread writer ({@code Log.setLogWriter}, a
 * {@code ThreadLocal}), and what reaches the logger through a {@code Log.Listener} filtered to the
 * calling thread. Each test first proves both captures work (K3): without that, "absent" would pass
 * whether or not anything was redacted.
 */
public class ExceptionRedactionTest {

    private static final String USER = "redaction-user";
    private static final String PROJECT = "redaction-project";
    private static final String CONNECTION = "redaction-connection";
    private static final String HOST = "db.internal.example";
    private static final String DATABASE = "customer_prod";

    /** A key built to break a naive log line: CR/LF and a forged correlation id, then field syntax */
    private static final String FORGED_EVENT_ID = "EVENT_ID=00000000-0000-0000-0000-000000000000";
    private static final String HOSTILE_USER = "evil\r\n" + FORGED_EVENT_ID + " forged";
    private static final String HOSTILE_PROJECT = "proj] 100% x=y z";
    private static final String HOSTILE_CONNECTION = "conn/key=forged";

    private static final String MARKER_F10 = "dbac-f10-secret-7c21";
    private static final String MARKER_F11 = "dbac-f11-secret-3e9d";
    private static final String MARKER_PROBE = "dbac-capture-probe-5a0b";

    private static final Pattern UUID_PATTERN =
        Pattern.compile("(?i)\\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\b");
    private static final Pattern EVENT_ID_PATTERN =
        Pattern.compile("(?i)EVENT_ID=([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b");

    /** The event codes and the no-key placeholder the policy core logs; a log contract, so pinned here */
    private static final String EVENT_STORE_READ_FAILED = "event=DBAC_PERMISSION_STORE_READ_FAILED";
    private static final String EVENT_AUTHORIZATION_FAILED = "event=DBAC_AUTHORIZATION_FAILED";
    private static final String KEY_UNRESOLVED = "key=<unresolved>";

    private static final Log log = Log.getLog(ExceptionRedactionTest.class);

    @BeforeAll
    public static void startServer() throws Exception {
        CEAppStarter.startServerIfNotStarted();
    }

    /**
     * F10: the permission-store read catch logs by class, code and correlation id only
     * <p>
     * Two ordinary events, one with a hostile key, and one with a logger that fails.
     */
    @Test
    public void f10PermissionStoreFailureIsLoggedWithoutItsMessage() throws Exception {
        final String k3 = assertCaptureWorks();
        String message = "Connection to jdbc:postgresql://metadata.internal.invalid:5432/cb?user=cbadmin&password="
            + MARKER_F10 + " refused";
        List<String> fragments = List.of("jdbc:postgresql://", "metadata.internal.invalid", "user=cbadmin", "password=", MARKER_F10);
        DbAccessPolicyService service = new DbAccessPolicyService(() -> {
            throw new SQLException(message);
        }, DbAccessPolicyConfig.defaults());

        Captured first = authorizeCapturing(service, USER, PolicyTestSupport.container(PROJECT, CONNECTION, HOST, DATABASE));
        Captured second = authorizeCapturing(service, USER, PolicyTestSupport.container(PROJECT, CONNECTION, HOST, DATABASE));
        Captured hostile = authorizeCapturing(service, HOSTILE_USER,
            PolicyTestSupport.container(HOSTILE_PROJECT, HOSTILE_CONNECTION, HOST, DATABASE));
        final LoggerFailure loggerFails = authorizeWithFailingLogger(service, USER,
            PolicyTestSupport.container(PROJECT, CONNECTION, HOST, DATABASE));

        Assertions.assertEquals(DenialReason.PERMISSION_STORE_UNAVAILABLE, first.decision().denialReason(),
            "FIXTURE F10: the failure must come from the permission-store read");
        Assertions.assertNotNull(first.decision().key(), "FIXTURE F10: the key is established before the store is read");
        Assertions.assertEquals(DenialReason.PERMISSION_STORE_UNAVAILABLE, hostile.decision().denialReason(),
            "FIXTURE F10: the hostile key must reach the same catch");
        List<String> violations = new ArrayList<>(redactionViolations(List.of(first, second), message, fragments,
            SQLException.class.getName(), EVENT_STORE_READ_FAILED, "key=" + first.decision().key().describe()));
        hostileKeyViolations(hostile, message, fragments, SQLException.class.getName(), EVENT_STORE_READ_FAILED)
            .forEach(violation -> violations.add("hostile key: " + violation));
        loggerFailureViolations(loggerFails, first.decision())
            .forEach(violation -> violations.add("failing logger: " + violation));
        Assertions.assertTrue(violations.isEmpty(), "F10 (permission-store read catch): " + String.join("; ", violations) + "; " + k3);
    }

    /**
     * F11: the unexpected authorization catch logs by class, code and correlation id only, with or without a key
     * <p>
     * The container resolves its identity normally and then throws from {@code getDriver()}, which
     * is the first thing the policy core asks after the key exists. Identity resolution checks that
     * the project's registry hands back this very object ({@code ContainerIdentityResolver}), so the
     * wrapper carries a project and registry that point at itself rather than at the fixture it
     * wraps. The same catch also handles a failure before any key exists - here the container's
     * {@code getId()} throws - and then has to log a fixed placeholder, not something it went back to
     * the failing container for. Both shapes are also run with a logger that fails.
     */
    @Test
    public void f11UnexpectedFailureIsLoggedWithoutItsMessage() throws Exception {
        final String k3 = assertCaptureWorks();
        String message = "driver accessor failed for jdbc:postgresql://target.internal.invalid:5432/prod user=admin password="
            + MARKER_F11;
        List<String> fragments = List.of("jdbc:postgresql://", "target.internal.invalid", "user=admin", "password=", MARKER_F11);
        DbAccessPolicyService service = new DbAccessPolicyService(() -> {
            throw new SQLException("F11 must fail before the permission store is read");
        }, DbAccessPolicyConfig.defaults());

        Captured first = authorizeCapturing(service, USER, failingContainer(PROJECT, CONNECTION, message));
        Captured second = authorizeCapturing(service, USER, failingContainer(PROJECT, CONNECTION, message));
        Captured hostile = authorizeCapturing(service, HOSTILE_USER, failingContainer(HOSTILE_PROJECT, HOSTILE_CONNECTION, message));
        Captured beforeKey = authorizeCapturing(service, USER,
            PolicyTestSupport.builder(PROJECT, CONNECTION).identityFails().build());
        final LoggerFailure loggerFailsWithKey = authorizeWithFailingLogger(service, USER, failingContainer(PROJECT, CONNECTION, message));
        final LoggerFailure loggerFailsBeforeKey = authorizeWithFailingLogger(service, USER,
            PolicyTestSupport.builder(PROJECT, CONNECTION).identityFails().build());

        Assertions.assertEquals(DenialReason.PERMISSION_STORE_UNAVAILABLE, first.decision().denialReason(),
            "FIXTURE F11: the unexpected failure must become a store-unavailable denial");
        Assertions.assertNotNull(first.decision().key(), "FIXTURE F11: the key must have been resolved before the failure");
        Assertions.assertEquals(DenialReason.PERMISSION_STORE_UNAVAILABLE, hostile.decision().denialReason(),
            "FIXTURE F11: the hostile key must reach the same catch");
        Assertions.assertEquals(DenialReason.PERMISSION_STORE_UNAVAILABLE, beforeKey.decision().denialReason(),
            "FIXTURE F11: a failure before the key must also become a store-unavailable denial");
        Assertions.assertNull(beforeKey.decision().key(), "FIXTURE F11: the before-key failure must leave no key");
        List<String> violations = new ArrayList<>(redactionViolations(List.of(first, second), message, fragments,
            IllegalStateException.class.getName(), EVENT_AUTHORIZATION_FAILED, "key=" + first.decision().key().describe()));
        hostileKeyViolations(hostile, message, fragments, IllegalStateException.class.getName(), EVENT_AUTHORIZATION_FAILED)
            .forEach(violation -> violations.add("hostile key: " + violation));
        redactionViolations(List.of(beforeKey), "container disposed", List.of("container disposed"),
            IllegalStateException.class.getName(), EVENT_AUTHORIZATION_FAILED, KEY_UNRESOLVED)
            .forEach(violation -> violations.add("before the key: " + violation));
        loggerFailureViolations(loggerFailsWithKey, first.decision())
            .forEach(violation -> violations.add("failing logger, key resolved: " + violation));
        loggerFailureViolations(loggerFailsBeforeKey, beforeKey.decision())
            .forEach(violation -> violations.add("failing logger, key unresolved: " + violation));
        Assertions.assertTrue(violations.isEmpty(),
            "F11 (unexpected authorization catch): " + String.join("; ", violations) + "; " + k3);
    }

    // ---------------------------------------------------------------- the contract

    /** One authorization and everything the calling thread logged while it ran */
    private record Captured(
        @NotNull AuthorizationDecision decision,
        @NotNull String text,
        @NotNull List<String> dbacMessages,
        @NotNull List<Throwable> dbacThrowables
    ) {
        /** The UUID logged as {@code EVENT_ID=<UUID>}, or null when there is none in that form */
        @Nullable
        String eventId() {
            Matcher matcher = EVENT_ID_PATTERN.matcher(text);
            return matcher.find() ? matcher.group(1) : null;
        }

        boolean hasAnyUuid() {
            return UUID_PATTERN.matcher(text).find();
        }
    }

    /**
     * Every clause of the redaction contract that the captured events break, empty when none
     * <p>
     * All clauses are checked on every event, so a partial fix shows exactly which are still open.
     */
    @NotNull
    private static List<String> redactionViolations(
        @NotNull List<Captured> events,
        @NotNull String exceptionMessage,
        @NotNull List<String> fragments,
        @NotNull String exceptionClass,
        @NotNull String eventCode,
        @NotNull String keyText
    ) {
        List<String> violations = new ArrayList<>();
        List<String> eventIds = new ArrayList<>();
        for (Captured captured : events) {
            if (captured.dbacMessages().isEmpty()) {
                violations.add("the failure is not logged at all");
            }
            if (captured.text().contains(exceptionMessage)) {
                violations.add("the exception message is logged");
            }
            for (String fragment : fragments) {
                if (captured.text().contains(fragment)) {
                    violations.add("the log contains '" + fragment + "'");
                }
            }
            if (!captured.text().contains(exceptionClass)) {
                violations.add("the exception class " + exceptionClass + " is not logged");
            }
            String eventId = captured.eventId();
            if (eventId == null) {
                violations.add(captured.hasAnyUuid() ? "the correlation UUID is not logged as EVENT_ID=<UUID>"
                    : "no correlation UUID is logged");
            } else {
                eventIds.add(eventId.toLowerCase());
            }
            if (!captured.text().contains(eventCode)) {
                violations.add("the event code '" + eventCode + "' is not logged");
            }
            if (!captured.text().contains(keyText)) {
                violations.add("'" + keyText + "' is not logged");
            }
            if (captured.dbacThrowables().stream().anyMatch(t -> t != null)) {
                violations.add("the exception object is handed to the logger");
            }
            if (captured.text().contains("\tat ")) {
                violations.add("a stack trace is written");
            }
        }
        if (eventIds.size() != eventIds.stream().distinct().count()) {
            violations.add("the EVENT_ID is not new for each event");
        }
        return violations.stream().distinct().toList();
    }

    /**
     * The contract for an event whose key ids were chosen to break the entry
     * <p>
     * Besides the ordinary clauses: the logged message is one line, the forged correlation id does
     * not appear, there is exactly one {@code EVENT_ID=}, {@code event=} and {@code key=} field, the
     * field block is closed only at its end, and each id appears in its encoded form.
     */
    @NotNull
    private static List<String> hostileKeyViolations(
        @NotNull Captured hostile,
        @NotNull String exceptionMessage,
        @NotNull List<String> fragments,
        @NotNull String exceptionClass,
        @NotNull String eventCode
    ) {
        String user = encoded(HOSTILE_USER);
        String project = encoded(HOSTILE_PROJECT);
        String connection = encoded(HOSTILE_CONNECTION);
        List<String> violations = new ArrayList<>(redactionViolations(List.of(hostile), exceptionMessage, fragments,
            exceptionClass, eventCode, "key=" + user + "/" + project + "/" + connection + "]"));
        if (hostile.dbacMessages().size() != 1) {
            violations.add("expected exactly one DBAC log message, found " + hostile.dbacMessages().size());
            return violations;
        }
        String logged = hostile.dbacMessages().get(0);
        if (logged.indexOf('\r') >= 0 || logged.indexOf('\n') >= 0) {
            violations.add("the log message is not one line (raw CR or LF)");
        }
        if (logged.contains(FORGED_EVENT_ID)) {
            violations.add("the forged " + FORGED_EVENT_ID + " appears");
        }
        for (String token : List.of("EVENT_ID=", "event=", "key=")) {
            int found = occurrences(logged, token);
            if (found != 1) {
                violations.add("expected exactly one '" + token + "' field, found " + found);
            }
        }
        if (occurrences(logged, "]") != 1 || !logged.endsWith("]")) {
            violations.add("a raw ']' closes the field block early");
        }
        for (String component : List.of(user, project, connection)) {
            if (!logged.contains(component)) {
                violations.add("the encoded key component '" + component + "' is not logged");
            }
        }
        System.out.println("[DBAC S1] hostile key: " + eventCode + ", message lines="
            + logged.lines().count() + ", EVENT_ID= x" + occurrences(logged, "EVENT_ID=")
            + ", event= x" + occurrences(logged, "event=") + ", key= x" + occurrences(logged, "key="));
        return violations;
    }

    @NotNull
    private static String encoded(@NotNull String id) {
        return URLEncoder.encode(id, StandardCharsets.UTF_8);
    }

    private static int occurrences(@NotNull String text, @NotNull String token) {
        int count = 0;
        for (int at = text.indexOf(token); at >= 0; at = text.indexOf(token, at + token.length())) {
            count++;
        }
        return count;
    }

    @NotNull
    private static WriteAuthorizationRequest request(@NotNull String userId, @NotNull DBPDataSourceContainer container) {
        return WriteAuthorizationRequest.of(userId, container, DbOperationCategory.TRANSACTION_COMMIT);
    }

    @NotNull
    private static Captured authorizeCapturing(
        @NotNull DbAccessPolicyService service,
        @NotNull String userId,
        @NotNull DBPDataSourceContainer container
    ) {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        Thread caller = Thread.currentThread();
        List<String> messages = Collections.synchronizedList(new ArrayList<>());
        List<Throwable> throwables = Collections.synchronizedList(new ArrayList<>());
        Log.Listener listener = (message, t) -> {
            if (Thread.currentThread() == caller && message != null && String.valueOf(message).contains("DBAC")) {
                messages.add(String.valueOf(message));
                throwables.add(t);
            }
        };
        PrintStream previous = Log.getLogWriter();
        Log.setLogWriter(new PrintStream(buffer, true, StandardCharsets.UTF_8));
        Log.addListener(listener);
        AuthorizationDecision decision;
        try {
            decision = service.authorize(request(userId, container));
        } finally {
            Log.removeListener(listener);
            Log.setLogWriter(previous);
        }
        Captured captured = new Captured(decision, buffer.toString(StandardCharsets.UTF_8), new ArrayList<>(messages),
            new ArrayList<>(throwables));
        for (int i = 0; i < captured.dbacMessages().size(); i++) {
            System.out.println("[DBAC S1] redaction capture: throwable=" + captured.dbacThrowables().get(i)
                + " message=" + captured.dbacMessages().get(i));
        }
        return captured;
    }

    // ---------------------------------------------------------------- a logger that fails

    /** What one authorization returned - or threw - while the logger failed on the DBAC event */
    private record LoggerFailure(
        @Nullable AuthorizationDecision decision,
        @Nullable Throwable escaped,
        int listenerCalls
    ) {
    }

    /**
     * Runs one authorization with a {@code Log.Listener} that throws when it receives the DBAC event
     * <p>
     * The platform log only reaches its listeners while a writer is set for the thread, so one is
     * set for the duration. Both are removed in {@code finally}. Anything that escapes
     * {@code authorize()} is caught here and returned, so that a regression reads as a broken
     * clause, not as a test error.
     */
    @NotNull
    private static LoggerFailure authorizeWithFailingLogger(
        @NotNull DbAccessPolicyService service,
        @NotNull String userId,
        @NotNull DBPDataSourceContainer container
    ) {
        Thread caller = Thread.currentThread();
        AtomicInteger calls = new AtomicInteger();
        Log.Listener failing = (message, t) -> {
            if (Thread.currentThread() == caller && message != null && String.valueOf(message).contains("DBAC")) {
                calls.incrementAndGet();
                throw new IllegalStateException("DBAC test: the logger failed");
            }
        };
        PrintStream previous = Log.getLogWriter();
        Log.setLogWriter(new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8));
        Log.addListener(failing);
        LoggerFailure result;
        try {
            result = new LoggerFailure(service.authorize(request(userId, container)), null, calls.get());
        } catch (RuntimeException | Error e) {
            result = new LoggerFailure(null, e, calls.get());
        } finally {
            Log.removeListener(failing);
            Log.setLogWriter(previous);
        }
        System.out.println("[DBAC S1] failing logger: listener calls=" + result.listenerCalls()
            + (result.escaped() != null ? ", authorize() threw " + result.escaped().getClass().getName()
                : ", decision=" + result.decision().denialReason() + ", key=" + (result.decision().key() == null ? "none" : "resolved")));
        return result;
    }

    /**
     * The decision taken while the logger failed must be the one taken while it worked
     * <p>
     * Same reason, and the same key - or the same absence of one - as the ordinary run of the same
     * catch, which the caller has already checked is {@code PERMISSION_STORE_UNAVAILABLE}.
     */
    @NotNull
    private static List<String> loggerFailureViolations(@NotNull LoggerFailure run, @NotNull AuthorizationDecision expected) {
        List<String> violations = new ArrayList<>();
        if (run.listenerCalls() != 1) {
            violations.add("the failing listener was called " + run.listenerCalls() + " times, expected exactly once");
        }
        if (run.escaped() != null) {
            violations.add("authorize() threw " + run.escaped().getClass().getName() + " instead of returning its decision");
            return violations;
        }
        AuthorizationDecision decision = run.decision();
        if (decision == null || decision.denialReason() != DenialReason.PERMISSION_STORE_UNAVAILABLE) {
            violations.add("the decision is not PERMISSION_STORE_UNAVAILABLE");
        }
        if (decision != null && !Objects.equals(expected.key(), decision.key())) {
            violations.add("the key changed (expected " + (expected.key() == null ? "none" : "the resolved key") + ")");
        }
        if (!expected.equals(decision)) {
            violations.add("the decision differs from the one taken while the logger worked");
        }
        return violations;
    }

    /** A container whose identity resolves and whose driver accessor then fails with the given message */
    @NotNull
    private static DBPDataSourceContainer failingContainer(
        @NotNull String projectId,
        @NotNull String connectionId,
        @NotNull String message
    ) {
        DBPDataSourceContainer healthy = PolicyTestSupport.container(projectId, connectionId, HOST, DATABASE);
        DBPProject healthyProject = healthy.getProject();
        DBPDataSourceRegistry healthyRegistry = healthyProject.getDataSourceRegistry();
        DBPDataSourceContainer[] self = new DBPDataSourceContainer[1];
        DBPDataSourceRegistry registry = proxy(DBPDataSourceRegistry.class, (proxy, method, args) ->
            "getDataSource".equals(method.getName()) ? self[0] : delegate(healthyRegistry, method, args));
        DBPProject project = proxy(DBPProject.class, (proxy, method, args) ->
            "getDataSourceRegistry".equals(method.getName()) ? registry : delegate(healthyProject, method, args));
        self[0] = proxy(DBPDataSourceContainer.class, (proxy, method, args) -> switch (method.getName()) {
            case "getProject" -> project;
            case "getDriver" -> throw new IllegalStateException(message);
            default -> delegate(healthy, method, args);
        });
        return self[0];
    }

    @SuppressWarnings("unchecked")
    @NotNull
    private static <T> T proxy(@NotNull Class<T> type, @NotNull InvocationHandler handler) {
        return (T) Proxy.newProxyInstance(ExceptionRedactionTest.class.getClassLoader(), new Class<?>[]{type}, handler);
    }

    @Nullable
    private static Object delegate(@NotNull Object target, @NotNull Method method, @Nullable Object[] args) throws Throwable {
        try {
            return method.invoke(target, args);
        } catch (InvocationTargetException e) {
            throw e.getTargetException();
        }
    }

    // ---------------------------------------------------------------- K3

    /**
     * K3: both captures see an exception, the writer is invisible to another thread, and both are restored
     * <p>
     * The other thread is confirmed to have actually run and finished, by latch and flag, before
     * its view of the writer is taken as evidence.
     */
    @NotNull
    private static String assertCaptureWorks() throws InterruptedException {
        PrintStream before = Log.getLogWriter();
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        Thread caller = Thread.currentThread();
        AtomicReference<Throwable> heard = new AtomicReference<>();
        Log.Listener listener = (message, t) -> {
            if (Thread.currentThread() == caller && String.valueOf(message).contains(MARKER_PROBE)) {
                heard.set(t);
            }
        };
        PrintStream capturing = new PrintStream(buffer, true, StandardCharsets.UTF_8);
        AtomicReference<PrintStream> seenByOtherThread = new AtomicReference<>();
        AtomicBoolean otherRan = new AtomicBoolean();
        CountDownLatch otherFinished = new CountDownLatch(1);
        Thread other = new Thread(() -> {
            seenByOtherThread.set(Log.getLogWriter());
            otherRan.set(true);
            otherFinished.countDown();
        }, "dbac-k3-probe");

        Log.setLogWriter(capturing);
        Log.addListener(listener);
        boolean finished;
        try {
            log.error("DBAC capture probe " + MARKER_PROBE, new IllegalStateException(MARKER_PROBE));
            other.start();
            finished = otherFinished.await(5, TimeUnit.SECONDS);
            other.join(TimeUnit.SECONDS.toMillis(5));
        } finally {
            Log.removeListener(listener);
            Log.setLogWriter(before);
        }

        String probe = buffer.toString(StandardCharsets.UTF_8);
        Assertions.assertTrue(probe.contains("java.lang.IllegalStateException: " + MARKER_PROBE),
            "FIXTURE K3: the writer capture did not receive an exception; F10/F11 would pass vacuously");
        Assertions.assertNotNull(heard.get(), "FIXTURE K3: the listener capture did not receive the exception object");
        Assertions.assertTrue(finished && otherRan.get() && !other.isAlive(),
            "FIXTURE K3: the cross-thread probe did not run to completion");
        Assertions.assertNotSame(capturing, seenByOtherThread.get(), "FIXTURE K3: the capture leaked to another thread");
        Assertions.assertSame(before, Log.getLogWriter(), "FIXTURE K3: the capture was not restored");
        return "K3: writer and listener captures work, the writer is thread-local and both were restored";
    }
}
