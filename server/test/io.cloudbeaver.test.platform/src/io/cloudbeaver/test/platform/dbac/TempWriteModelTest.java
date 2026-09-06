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

import io.cloudbeaver.service.dbac.tempwrite.MetadataDbTime;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteChangeType;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteConflictReason;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteGrant;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteGrantRequest;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteMutationResult;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteMutationStatus;
import io.cloudbeaver.service.dbac.tempwrite.TempWritePermissionKey;
import io.cloudbeaver.service.dbac.tempwrite.TempWriteRevokeRequest;
import org.jkiss.code.NotNull;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

/**
 * The TEMP_WRITE model refuses values that must never reach storage
 * <p>
 * These need no database. They cover the rejections that exist because storage is the last layer
 * that can still say no: a blank identifier or the anonymous project would produce a grant nobody
 * can attribute or revoke, and a revision below one would break the ordering the whole
 * compare-and-set depends on.
 */
public class TempWriteModelTest {

    private static final MetadataDbTime NOW =
        MetadataDbTime.of(Instant.parse("2026-09-04T12:00:00Z"));

    @Test
    public void keyRejectsBlankUser() {
        assertRejected(() -> new TempWritePermissionKey(" ", "proj", "conn"), "userId");
    }

    @Test
    public void keyRejectsBlankProject() {
        assertRejected(() -> new TempWritePermissionKey("user", "", "conn"), "projectId");
    }

    @Test
    public void keyRejectsBlankConnection() {
        assertRejected(() -> new TempWritePermissionKey("user", "proj", ""), "connectionId");
    }

    /**
     * A grant on the anonymous project would apply to whoever is unauthenticated at the time
     */
    @Test
    public void keyRejectsAnonymousProject() {
        assertRejected(
            () -> new TempWritePermissionKey("user", TempWritePermissionKey.ANONYMOUS_PROJECT_ID, "conn"),
            "anonymous");
    }

    @Test
    public void keyAcceptsAProjectMerelyContainingAnonymous() {
        TempWritePermissionKey key = new TempWritePermissionKey("user", "anonymous-team", "conn");
        Assertions.assertEquals("anonymous-team", key.projectId());
    }

    /**
     * Revision 0 means "no row", so it must never appear on a stored one
     */
    @Test
    public void storedGrantRejectsRevisionBelowOne() {
        assertRejected(
            () -> grant(TempWriteGrant.NO_ROW_REVISION),
            "revision");
    }

    @Test
    public void storedGrantAcceptsFirstRevision() {
        Assertions.assertEquals(TempWriteGrant.FIRST_REVISION, grant(TempWriteGrant.FIRST_REVISION).revision());
    }

    /**
     * A grant with no reason is unattributable, so it is refused before it can be stored
     */
    @Test
    public void grantRequestRejectsBlankReason() {
        assertRejected(
            () -> new TempWriteGrantRequest(
                new TempWritePermissionKey("user", "proj", "conn"), "g", "admin",
                Duration.ofMinutes(30), "   ", "postgres-jdbc", null, null, 0L),
            "reason");
    }

    @Test
    public void revokeRequestRejectsBlankReason() {
        assertRejected(
            () -> new TempWriteRevokeRequest(
                new TempWritePermissionKey("user", "proj", "conn"), "admin", " ", 0L),
            "reason");
    }

    @Test
    public void revokeRequestRejectsNegativeStartRevision() {
        assertRejected(
            () -> new TempWriteRevokeRequest(
                new TempWritePermissionKey("user", "proj", "conn"), "admin", "reason", -1L),
            "revision");
    }

    /**
     * A refused mutation may never report rows changed, whatever the caller passes
     */
    @Test
    public void refusedResultCannotReportChangedRows() {
        assertRejected(
            () -> new TempWriteMutationResult(
                TempWriteMutationStatus.CONFLICT_SUPERSEDED, 1, null, null,
                TempWriteConflictReason.REVISION_SUPERSEDED, 1),
            "rows");
    }

    /**
     * Status and conflict reason cannot disagree, in either direction
     */
    @Test
    public void resultStatusAndConflictReasonMustAgree() {
        assertRejected(
            () -> new TempWriteMutationResult(
                TempWriteMutationStatus.COMMITTED, 1, 1L, "g", TempWriteConflictReason.REVISION_SUPERSEDED, 1),
            "disagree");
        assertRejected(
            () -> new TempWriteMutationResult(
                TempWriteMutationStatus.RETRY_EXHAUSTED, 0, null, null, null, 1),
            "disagree");
    }

    @Test
    public void changeTypeCoversEveryTransitionTheSchemaDeclares() {
        Assertions.assertEquals(4, TempWriteChangeType.values().length);
        for (String declared : new String[]{"GRANTED", "REVOKED", "EXPIRED", "SUPERSEDED"}) {
            Assertions.assertNotNull(TempWriteChangeType.valueOf(declared));
        }
    }

    /**
     * The instant survives the round trip through the form JDBC binds
     * <p>
     * Pinned because schema version 2 stores an instant rather than a wall clock. If the round trip
     * ever stopped being exact, every expiry would be wrong by whatever offset crept in.
     */
    @Test
    public void metadataTimeRoundTripsThroughItsStoredForm() {
        Assertions.assertEquals(NOW.instant(), NOW.stored().toInstant());
        Assertions.assertEquals(NOW, MetadataDbTime.ofStored(NOW.stored()));
    }

    /**
     * The same instant read at any offset is the same value, which is the point of a zoned column
     */
    @Test
    public void metadataTimeIgnoresTheOffsetItIsReadAt() {
        Assertions.assertEquals(
            NOW,
            MetadataDbTime.ofStored(NOW.instant().atOffset(java.time.ZoneOffset.ofHours(9))));
        Assertions.assertEquals(
            NOW,
            MetadataDbTime.ofStored(NOW.instant().atOffset(java.time.ZoneOffset.ofHours(-5))));
    }

    /**
     * Advancing a reading moves both views by exactly the duration
     */
    @Test
    public void metadataTimeAdvancesBothViewsEqually() {
        Duration duration = Duration.ofMinutes(90);
        MetadataDbTime later = NOW.plus(duration);
        Assertions.assertEquals(duration, Duration.between(NOW.instant(), later.instant()));
        Assertions.assertEquals(duration, Duration.between(NOW.stored(), later.stored()));
    }

    /**
     * Nanosecond precision survives in Java, so any loss observed later belongs to the database
     */
    @Test
    public void metadataTimeKeepsSubSecondPrecisionInJava() {
        Instant precise = Instant.parse("2026-09-04T12:00:00.123456789Z");
        MetadataDbTime value = MetadataDbTime.of(precise);
        Assertions.assertEquals(precise, value.instant());
        Assertions.assertEquals(123_456_789, value.instant().getNano());
    }

    /**
     * The revoked form carries the revoke, and cannot be built at a revision that does not advance
     * <p>
     * This is what the audit sink and any later observer is handed, so a wrong revision here would be
     * recorded as a transition that never happened. The guard exists because the caller passes the
     * revision separately from the row.
     */
    @Test
    public void revokedFormCarriesTheRevokeAndAdvancesTheRevision() {
        TempWriteGrant active = grant(TempWriteGrant.FIRST_REVISION);
        MetadataDbTime revokedAt = NOW.plus(Duration.ofMinutes(5));
        TempWriteGrant revoked = active.asRevoked(2L, revokedAt, "admin-2", "no longer needed");

        Assertions.assertEquals(2L, revoked.revision());
        Assertions.assertEquals(revokedAt, revoked.revokedAt());
        Assertions.assertEquals("admin-2", revoked.revokedBy());
        Assertions.assertEquals("no longer needed", revoked.revokeReason());
        Assertions.assertTrue(revoked.isRevoked());
        // Everything that identifies the grant survives, so the record is about the same grant.
        Assertions.assertEquals(active.grantId(), revoked.grantId());
        Assertions.assertEquals(active.grantedAt(), revoked.grantedAt());
        Assertions.assertEquals(active.expiresAt(), revoked.expiresAt());
        Assertions.assertFalse(active.isRevoked(), "the original must not be mutated");

        assertRejected(() -> active.asRevoked(1L, revokedAt, "admin-2", "same"), "revision");
        assertRejected(() -> active.asRevoked(0L, revokedAt, "admin-2", "lower"), "revision");
    }

    @NotNull
    private static TempWriteGrant grant(long revision) {
        return new TempWriteGrant(
            new TempWritePermissionKey("user", "proj", "conn"),
            "grant-1",
            revision,
            "admin",
            NOW,
            NOW.plus(Duration.ofMinutes(30)),
            "reason",
            null,
            null,
            null,
            "postgres-jdbc",
            null,
            null);
    }

    private static void assertRejected(
        @NotNull Runnable construction,
        @NotNull String expectedInMessage
    ) {
        IllegalArgumentException failure =
            Assertions.assertThrows(IllegalArgumentException.class, construction::run);
        Assertions.assertTrue(
            failure.getMessage().toLowerCase(java.util.Locale.ROOT)
                .contains(expectedInMessage.toLowerCase(java.util.Locale.ROOT)),
            "Message should mention " + expectedInMessage + " but was: " + failure.getMessage());
    }
}
