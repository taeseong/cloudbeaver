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
package io.cloudbeaver.service.dbac.policy;

import org.jkiss.code.NotNull;

/**
 * Why a write was denied
 * <p>
 * These are codes, not sentences. The user-facing text lives in {@link #messageCode()} and is
 * deliberately coarse: Phase 2 section 6 notes that {@code DBWebException.getExtensions()} puts a
 * stack trace into the GraphQL response, so a denial must not carry anything that would be worth
 * reading by an attacker. Nothing here names a table, a host, a SQL statement or an exception.
 * <p>
 * <b>Which of these this slice can actually produce.</b> The policy core implemented in this slice
 * evaluates identity, operation category, target DBMS, the metadata snapshot and clock skew. Values
 * marked below as reserved exist so that the enum does not have to change when the transaction state
 * machine, the audit writer and the admin API arrive - but nothing in this slice returns them, and
 * this slice does not claim to implement the checks behind them.
 */
public enum DenialReason {

    // ---------------------------------------------------------------- produced by this slice

    /**
     * No current row for this user, project and connection
     * <p>
     * The default state of the system. READ_ONLY is what a user has when nobody granted anything.
     */
    NO_GRANT("dbac.denied.no_grant", "Temporary write access has not been granted."),

    /**
     * The grant exists but its expiry has passed, measured by the metadata database clock
     * <p>
     * The boundary is exclusive: {@code EXPIRES_AT == now} is expired. A grant that runs out during
     * an open editor session denies the next write without a reconnect, because there is no cache.
     */
    GRANT_EXPIRED("dbac.denied.expired", "Temporary write access has expired."),

    /**
     * The grant was revoked, whether or not its expiry has passed
     */
    GRANT_REVOKED("dbac.denied.revoked", "Temporary write access has been revoked."),

    /**
     * The grant no longer describes the connection it was granted for
     * <p>
     * A connection id can be reused after a connection is deleted and another created, and a
     * connection's configuration can be repointed at another server without its id changing. Six
     * values recorded with the grant - provider, driver, configuration type, host, port and database
     * - are compared against the connection's stored configuration <b>and</b> against the
     * configuration it was actually opened with, and any mismatch is refused rather than guessed at.
     * A grant written before schema version 3 cannot supply all six and is refused for that reason.
     */
    GRANT_STALE("dbac.denied.stale", "Temporary write access does not match this connection."),

    /**
     * The user is disabled, deleted, or has no row in the CloudBeaver user table
     */
    USER_INACTIVE("dbac.denied.user_inactive", "This account cannot perform write operations."),

    /**
     * The connection could not be confirmed against the project's live registry
     * <p>
     * Also covers a container whose project or registry has gone away underneath it.
     */
    CONNECTION_UNKNOWN("dbac.denied.connection_unknown", "This connection could not be verified."),

    /**
     * There is no usable identity: no user id, or the shared anonymous project
     * <p>
     * Anonymous sessions all share one project id, so a grant there would leak to every anonymous
     * user. Refused before any lookup.
     */
    IDENTITY_MISSING("dbac.denied.identity_missing", "Write operations require an identified user."),

    /**
     * The permission store could not be read
     * <p>
     * A failure to read permissions is never treated as "no permissions found" - the two are
     * different facts and only one of them is safe to act on.
     */
    PERMISSION_STORE_UNAVAILABLE("dbac.denied.store_unavailable", "Write access cannot be verified right now."),

    /**
     * This node's clock differs from the metadata database clock by more than the allowance
     * <p>
     * Expiry itself is decided by the database, so skew does not change the answer; what it signals
     * is that this node's own reasoning about time - timeouts, log correlation, anything a later
     * slice adds - cannot be trusted, so writes stop until it is fixed.
     */
    CLOCK_SKEW_EXCEEDED("dbac.denied.clock_skew", "Server time is out of sync; write access is suspended."),

    /**
     * The operation category is not one this gate authorizes
     * <p>
     * Covers both a category that is not write-gated at all (asking the write gate about a read is a
     * wiring mistake, not a permission question) and any category added later without a rule.
     */
    OPERATION_UNSUPPORTED("dbac.denied.operation_unsupported", "This operation is not permitted."),

    /**
     * The target database is not one this fork can reason about
     * <p>
     * Only PostgreSQL and MySQL are in scope. Everything else - including the databases that ship
     * under the same DBeaver provider and even the same JDBC driver class - is refused, because a
     * statement classifier tuned for one dialect makes no promises about another.
     */
    DBMS_UNSUPPORTED("dbac.denied.dbms_unsupported", "This database type is not supported for write access."),

    /**
     * The connection is configured in a way whose physical target cannot be identified safely
     * <p>
     * A grant is only meaningful if the server can say which physical database it applies to. Some
     * configurations make that undecidable from stored state: a custom JDBC URL (the platform hands
     * the url to the driver verbatim, so the host and port fields stop describing the target), an
     * enabled network handler (a tunnel rewrites host and port at connect time; a proxy reroutes the
     * socket), a config profile (handlers are injected at connect time and are not in the stored
     * list), a driver substitution (url and connect properties are replaced by code the
     * configuration does not describe), a variable expression that is only resolved at connect time,
     * a routing property such as {@code socketFactory}, or a missing host, port or database.
     * <p>
     * Refused rather than guessed. See {@code docs/db-access-control-endpoint-identity.md} section 3
     * for the full list and the evidence behind each entry. This is a denial about the connection's
     * shape, not about the grant, so it happens whether or not a grant exists - and it happens after
     * the key is known, so it is auditable.
     */
    ENDPOINT_UNSUPPORTED(
        "dbac.denied.endpoint_unsupported",
        "This connection is configured in a way that write access cannot be verified for."),

    // ---------------------------------------------------------------- reserved, not produced here

    /**
     * Reserved for the transaction state machine (Phase 2 section 9). Not produced in this slice.
     */
    TRANSACTION_TAINTED("dbac.denied.transaction_tainted", "This transaction can no longer be committed."),

    /**
     * Reserved for the transaction state machine (Phase 2 section 9.4). Not produced in this slice.
     */
    CONNECTION_BLOCKED("dbac.denied.connection_blocked", "This connection is blocked."),

    /**
     * Reserved for the transaction state machine (Phase 2 section 4, rule 11). Not produced here.
     */
    GRANT_SUPERSEDED("dbac.denied.superseded", "Temporary write access was replaced."),

    /**
     * Reserved for the audit layer (Phase 2 section 11.1). Not produced in this slice, because
     * nothing writes {@code DBAC_AUDIT_EVENT} yet.
     */
    AUDIT_WRITE_FAILED("dbac.denied.audit_failed", "Write access cannot be recorded right now."),

    /**
     * Reserved for the SQL classifier. Not produced in this slice, which has no classifier.
     */
    STATEMENT_NOT_ALLOWLISTED("dbac.denied.statement", "This statement is not permitted.");

    private final String messageCode;
    private final String userMessage;

    DenialReason(@NotNull String messageCode, @NotNull String userMessage) {
        this.messageCode = messageCode;
        this.userMessage = userMessage;
    }

    /**
     * A stable code a UI can localise
     */
    @NotNull
    public String messageCode() {
        return messageCode;
    }

    /**
     * A short, safe sentence
     * <p>
     * Safe means it names no host, no database, no table, no statement and no internal state. It
     * tells the user what happened to their permission, not what the server looks like inside.
     */
    @NotNull
    public String userMessage() {
        return userMessage;
    }

    /**
     * Whether this slice's policy core is allowed to return this reason
     * <p>
     * This is the declared partition, pinned by a test so that moving a value across the line is a
     * deliberate edit rather than a side effect. It records intent; it does not by itself prove that
     * a reserved value is unreachable - that holds because nothing in the policy package names one,
     * which is checked separately. A later slice moves a value across this line and its test with it.
     */
    public boolean producedByPolicyCore() {
        return switch (this) {
            case TRANSACTION_TAINTED, CONNECTION_BLOCKED, GRANT_SUPERSEDED,
                 AUDIT_WRITE_FAILED, STATEMENT_NOT_ALLOWLISTED -> false;
            default -> true;
        };
    }
}
