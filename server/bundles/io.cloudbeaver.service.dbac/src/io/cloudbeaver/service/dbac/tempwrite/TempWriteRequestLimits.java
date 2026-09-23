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
package io.cloudbeaver.service.dbac.tempwrite;

import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;

import java.time.Duration;

/**
 * The rules a TEMP_WRITE grant request has to satisfy before anything is stored
 * <p>
 * Lives here rather than in the policy package because {@link TempWriteGrantRequest} is the existing
 * creation path and calls into it - putting the rules in the policy package would point the
 * dependency the wrong way. The admin API of a later slice validates the same way by calling the
 * same methods, so there is one definition of "too long" and "no reason given" rather than two that
 * drift.
 * <p>
 * <b>Nothing is clamped.</b> A request for six hours when the limit is four is refused, not silently
 * shortened to four. An operator who asked for six and was given four without being told would
 * believe write access ends at a time it does not, and would plan around the wrong moment.
 * <p>
 * <b>A missing or broken limit is not an absent limit.</b> Nothing in this class treats null as
 * "unbounded" - null means "use {@link #DEFAULT_MAX_DURATION}". A caller that has a configured
 * ceiling should sanitize it through {@code DbAccessPolicyConfig}, which replaces zero, negative and
 * absurd values with the documented default.
 * <p>
 * <b>No caller passes a configured ceiling today.</b> {@link TempWriteGrantRequest} passes null, so
 * the effective limit is always four hours. There is no configuration reader for
 * {@code tempWriteMaxDurationMinutes} in this fork yet, and until one exists this limit must not be
 * described as configurable.
 */
public final class TempWriteRequestLimits {

    /**
     * The longest reason the schema can store
     * <p>
     * {@code REASON VARCHAR(1000)} in both {@code DBAC_TW_CURRENT} and {@code DBAC_TW_HISTORY}.
     * Checking it here turns a truncation or a driver error deep inside a transaction into a plain
     * rejection at the edge, where the caller can still do something about it.
     */
    public static final int MAX_REASON_LENGTH = 1000;

    /**
     * The default ceiling on a single grant, used when no configuration says otherwise
     * <p>
     * Four hours. Kept in step with {@code DbAccessPolicyConfig.DEFAULT_MAX_GRANT_DURATION}; a test
     * pins the two together so they cannot drift apart.
     */
    public static final Duration DEFAULT_MAX_DURATION = Duration.ofMinutes(240);

    private TempWriteRequestLimits() {
    }

    /**
     * Checks a requested duration against the ceiling
     *
     * @param maxDuration the ceiling. Null means "use the default" - never "no ceiling".
     * @throws IllegalArgumentException if the duration is zero, negative, or beyond the ceiling
     */
    public static void checkDuration(@Nullable Duration duration, @Nullable Duration maxDuration) {
        if (duration == null) {
            throw new IllegalArgumentException("A TEMP_WRITE grant requires a duration");
        }
        if (duration.isZero() || duration.isNegative()) {
            throw new IllegalArgumentException("A TEMP_WRITE grant requires a positive duration, got " + duration);
        }
        Duration ceiling = maxDuration == null ? DEFAULT_MAX_DURATION : maxDuration;
        if (duration.compareTo(ceiling) > 0) {
            throw new IllegalArgumentException(
                "A TEMP_WRITE grant may not exceed " + ceiling + ", got " + duration
                    + "; ask for a shorter period rather than expecting it to be shortened for you");
        }
    }

    /**
     * Checks a reason and returns the form that should be stored
     * <p>
     * Trimmed, because trailing whitespace is not a reason. Length is measured after trimming so a
     * reason padded to 1001 characters by spaces is accepted at its real length rather than refused
     * for something the user cannot see.
     * <p>
     * <b>Control characters are refused, not removed.</b> A reason reaches a log line and an audit
     * row, and both are read line by line; a carriage return or a newline inside one value lets the
     * rest of a reason be read as a separate record, which is how a forged audit entry gets written
     * by someone who can only supply a reason. The Unicode line and paragraph separators do the same
     * in any reader that honours them, and a NUL truncates in anything that reaches C.
     * <p>
     * Refused rather than stripped or replaced, because stripping changes what the reason says
     * without telling anyone: an administrator who typed two lines would find one stored, and the
     * stored text would be evidence of something nobody wrote. A rejection at the edge is visible
     * and correctable.
     *
     * @throws IllegalArgumentException if the reason is null, blank, too long after trimming, or
     *     carries a control character, a line separator or a paragraph separator
     */
    @NotNull
    public static String checkReason(@Nullable String reason) {
        if (reason == null || reason.isBlank()) {
            throw new IllegalArgumentException("A TEMP_WRITE grant requires a reason");
        }
        String trimmed = reason.trim();
        if (trimmed.length() > MAX_REASON_LENGTH) {
            throw new IllegalArgumentException(
                "A TEMP_WRITE reason may not exceed " + MAX_REASON_LENGTH
                    + " characters, got " + trimmed.length());
        }
        checkPrintable(trimmed);
        return trimmed;
    }

    /**
     * The Unicode line separator, which breaks a line in readers that honour it
     */
    private static final char LINE_SEPARATOR = '\u2028';

    /**
     * The Unicode paragraph separator, likewise
     */
    private static final char PARAGRAPH_SEPARATOR = '\u2029';

    /**
     * Refuses a reason that could break the line it is written on
     * <p>
     * {@code Character.isISOControl} covers {@code \r}, {@code \n}, NUL and the rest of both C0 and
     * C1 ranges; the two Unicode separators are named separately because they are not ISO control
     * characters and would otherwise pass. The offending code point is reported as an escape rather
     * than echoed, so the diagnostic cannot itself carry the break.
     */
    private static void checkPrintable(@NotNull String reason) {
        for (int i = 0; i < reason.length(); i++) {
            char c = reason.charAt(i);
            if (Character.isISOControl(c) || c == LINE_SEPARATOR || c == PARAGRAPH_SEPARATOR) {
                throw new IllegalArgumentException(
                    "A TEMP_WRITE reason may not contain control characters or line separators; found"
                        + " U+" + String.format("%04X", (int) c) + " at index " + i);
            }
        }
    }
}
