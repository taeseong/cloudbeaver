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
import org.jkiss.code.Nullable;
import org.jkiss.dbeaver.Log;

import java.time.Duration;

/**
 * The two numbers the policy core is allowed to be configured with
 * <p>
 * Deliberately a plain immutable record built by whoever constructs the service, rather than a
 * reader that reaches into CloudBeaver's server configuration. Phase 2 section 12.4 limits how much
 * upstream this fork may touch, and nothing in this slice is wired into the server yet, so inventing
 * a configuration binding now would be a change with no caller. When the admin API lands it can read
 * {@code dbacMaxClockSkewSeconds} and the grant duration limit from wherever the product keeps them
 * and hand them here - the seam is this record and it does not need to move.
 * <p>
 * <b>A bad setting never disables a check.</b> That holds on both routes in, by different means.
 * {@link #sanitized} is the route for external configuration: zero, negative, absurd and missing all
 * become the documented default there, so a typo in a config file cannot turn a guard off. The
 * canonical constructor is the route for code, and it <b>throws</b> on the same values rather than
 * substituting anything, so a caller that builds a configuration by hand cannot hand the service a
 * limit the sanitizer would have rejected. Neither route can produce "no limit".
 */
public record DbAccessPolicyConfig(
    @NotNull Duration clockSkewThreshold,
    @NotNull Duration maxGrantDuration
) {
    private static final Log log = Log.getLog(DbAccessPolicyConfig.class);

    /**
     * Phase 2 section 8.1 {@code dbacMaxClockSkewSeconds}, default 5
     */
    public static final Duration DEFAULT_CLOCK_SKEW_THRESHOLD = Duration.ofSeconds(5);

    /**
     * The longest a single TEMP_WRITE grant may run
     * <p>
     * Four hours. Long enough for a maintenance window, short enough that forgetting to revoke is
     * not the same as granting permanently.
     */
    public static final Duration DEFAULT_MAX_GRANT_DURATION = Duration.ofMinutes(240);

    /**
     * An upper bound on the skew threshold itself
     * <p>
     * Without this, a setting of one day would make the skew guard meaningless while still looking
     * configured. Anything above this is treated as a mistake and replaced by the default.
     */
    private static final Duration MAX_SENSIBLE_SKEW = Duration.ofMinutes(5);

    /**
     * An upper bound on the grant duration limit itself, for the same reason
     */
    private static final Duration MAX_SENSIBLE_GRANT_DURATION = Duration.ofHours(24);

    /**
     * Rejects every value the sanitizer would have replaced
     * <p>
     * The ceilings are enforced <b>here</b>, not only in {@link #sanitized}, because this
     * constructor is public: a caller can build the record directly and hand it to the service, and
     * a check that lived only in the sanitizer would be a suggestion. A day-long skew threshold
     * would leave the guard looking configured while accepting any clock; a week-long grant ceiling
     * would leave the duration limit looking enforced while permitting a grant nobody would call
     * temporary.
     * <p>
     * The bounds are inclusive: a value exactly equal to a ceiling is accepted, one nanosecond
     * beyond it is not. {@link #sanitized} turns a rejected external value into the documented
     * default and logs it; nothing turns a rejected value into an absent limit.
     */
    public DbAccessPolicyConfig {
        requireInRange(clockSkewThreshold, MAX_SENSIBLE_SKEW, "clock skew threshold");
        requireInRange(maxGrantDuration, MAX_SENSIBLE_GRANT_DURATION, "maximum grant duration");
    }

    private static void requireInRange(
        @NotNull Duration value,
        @NotNull Duration ceiling,
        @NotNull String what
    ) {
        if (value.isNegative() || value.isZero()) {
            throw new IllegalArgumentException("The " + what + " must be positive, got " + value);
        }
        if (value.compareTo(ceiling) > 0) {
            throw new IllegalArgumentException(
                "The " + what + " may not exceed " + ceiling + ", got " + value
                    + "; a limit this large is indistinguishable from no limit");
        }
    }

    /**
     * The configuration used when nothing is configured
     */
    @NotNull
    public static DbAccessPolicyConfig defaults() {
        return new DbAccessPolicyConfig(DEFAULT_CLOCK_SKEW_THRESHOLD, DEFAULT_MAX_GRANT_DURATION);
    }

    /**
     * Builds a configuration from values that may be absent or wrong
     * <p>
     * Every rejected value is logged with what it was and what replaced it, because a silent
     * substitution is how an operator ends up believing a limit is in force that is not.
     *
     * @param skewSeconds seconds, or null when unset
     * @param maxGrantMinutes minutes, or null when unset
     */
    @NotNull
    public static DbAccessPolicyConfig sanitized(
        @Nullable Integer skewSeconds,
        @Nullable Integer maxGrantMinutes
    ) {
        Duration skew = sanitize(
            skewSeconds == null ? null : Duration.ofSeconds(skewSeconds),
            DEFAULT_CLOCK_SKEW_THRESHOLD, MAX_SENSIBLE_SKEW, "clock skew threshold");
        Duration grant = sanitize(
            maxGrantMinutes == null ? null : Duration.ofMinutes(maxGrantMinutes),
            DEFAULT_MAX_GRANT_DURATION, MAX_SENSIBLE_GRANT_DURATION, "maximum grant duration");
        return new DbAccessPolicyConfig(skew, grant);
    }

    @NotNull
    private static Duration sanitize(
        @Nullable Duration value,
        @NotNull Duration fallback,
        @NotNull Duration ceiling,
        @NotNull String what
    ) {
        if (value == null) {
            return fallback;
        }
        if (value.isZero() || value.isNegative()) {
            log.warn("DBAC " + what + " was configured as " + value
                + ", which would disable the check; using " + fallback + " instead");
            return fallback;
        }
        if (value.compareTo(ceiling) > 0) {
            log.warn("DBAC " + what + " was configured as " + value
                + ", which is beyond anything this check can be useful at; using " + fallback + " instead");
            return fallback;
        }
        return value;
    }
}
