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

import io.cloudbeaver.service.dbac.tempwrite.EndpointSnapshot;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.jkiss.dbeaver.model.DBPDataSourceContainer;
import org.jkiss.dbeaver.model.connection.DBPConnectionConfiguration;
import org.jkiss.dbeaver.model.connection.DBPDriver;
import org.jkiss.dbeaver.model.connection.DBPDriverConfigurationType;
import org.jkiss.dbeaver.model.net.DBWHandlerConfiguration;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Turns a live connection into the endpoint identity a grant is checked against, or refuses to
 * <p>
 * Two jobs, and they are separate on purpose. First decide whether this connection's physical target
 * is knowable from stored configuration at all; only then read the six values that identify it. A
 * connection whose target is not knowable is refused with {@link DenialReason#ENDPOINT_UNSUPPORTED}
 * rather than fingerprinted on a guess, because a fingerprint over values the connection does not
 * actually use is worse than no fingerprint: it looks precise and is not.
 * <p>
 * <b>Both the stored configuration and the one in use.</b> An earlier version read only
 * {@code container.getConnectionConfiguration()}, on the grounds that
 * {@code getActualConnectionConfiguration()} is a connect-time copy an SSH tunnel rewrites -
 * host becomes {@code 127.0.0.1}, port becomes a randomly chosen local port. That reasoning was
 * wrong, and independent review found the hole it left: CloudBeaver edits a connection's stored
 * configuration in place and does not disconnect it, so an operator can grant on one endpoint,
 * point the connection at a second one, open it with a read, point it back, and write down the
 * socket that is still attached to the second server. The stored side matches the grant again by
 * then. The tunnel argument does not justify the omission either, because a connection with an
 * enabled handler is refused outright before any fingerprint is taken, and a profile's injected
 * handlers appear only on the resolved side - so reading both cannot introduce the instability
 * it warned about. Both fingerprints must match the grant.
 * <p>
 * <b>No credential is read, stored or logged.</b> Besides the six values that make up the
 * identity, this class reads {@code getConfigurationType()}, {@code getConfigProfileName()},
 * {@code getConfigProfileSource()}, {@code getAuthModelId()} - the id of an authentication model,
 * never its credentials - and, for the url gate, {@code getUrl()} together with
 * {@code DBPDriver.getSampleURL()} and {@code DBPDriver.getConnectionURL(configuration)}. It never
 * calls {@code getUserName}, {@code getUserPassword}, {@code getAuthProperties},
 * {@code getRuntimeAttribute}, {@code toString()}, or any handler accessor beyond
 * {@code isEnabled()}. The two property maps are consulted for their <em>key sets</em> only - see
 * {@link ConnectionPropertyAllowlist} - and no value is ever read out of either.
 * <p>
 * The three url accessors need saying out loud, because an earlier version of this paragraph listed
 * {@code getUrl} and {@code getAuthModel()} among the calls this class never makes - and the url
 * gate made both of those false. A url can embed {@code {user}:{password}@}, and
 * {@code getConnectionURL} reaches {@code getAuthModel()} inside the PostgreSQL provider. What the
 * guarantee rests on is not that the values are unread but that <b>none of them leaves this
 * method</b>: they are compared in local variables, no url or template is placed in an
 * {@link EndpointSnapshot}, a decision, an audit payload, an exception message or a log line, and
 * this class holds no logger at all. {@code DbAccessPolicyTest.urlGateRefusalsCarryNoCredential}
 * plants a sentinel in both the stored url and the template and asserts the rendered decision
 * carries neither.
 * <p>
 * The rationale for each refusal, with the platform code it is based on, is written down in
 * {@code docs/db-access-control-endpoint-identity.md} section 3.
 */
final class EndpointFingerprints {

    /**
     * The opener of a DBeaver variable expression
     * <p>
     * A stored value containing one is a template, not an address: variables are expanded into the
     * connect-time copy only, so the effective endpoint is not knowable from what is stored.
     * Resolving it here would duplicate platform logic and could resolve differently than the
     * connect path does.
     */
    private static final String VARIABLE_OPENER = "${";

    /**
     * The only authentication model whose configuration cannot decide where the connection goes
     * <p>
     * {@code PostgreDataSourceProvider.getConnectionURL} asks the auth model for a complete URL
     * <em>before</em> it looks at the configuration type, and returns it verbatim if it gets one -
     * so an auth model that implements {@code DBPDataSourceURLProvider} chooses the endpoint and the
     * host, port and database fields are never consulted. No auth model in CE or in the platform
     * does that today, but {@code authModelId} is editable over the API and a fork or a later
     * edition could add one, at which point this gate is what stops it being silent.
     * <p>
     * Blank means the same thing: {@code native} is declared {@code default="true"}.
     */
    private static final String NATIVE_AUTH_MODEL_ID = "native";

    private static final int MIN_PORT = 1;
    private static final int MAX_PORT = 65535;

    /**
     * Either the endpoint identity, or the reason it could not be established
     * <p>
     * Two identities, not one, and a grant has to match both.
     * <ul>
     *   <li>{@code declared} is what the stored configuration says the connection is.</li>
     *   <li>{@code inUse} is what the connection was actually opened against. The platform copies the
     *       configuration at connect time and keeps that copy until disconnect, so an edit made while
     *       a connection is live changes {@code declared} and leaves {@code inUse} alone.</li>
     * </ul>
     * Comparing only {@code declared} leaves a hole: grant on one endpoint, edit the port to a second
     * one, connect - a read, which is not write-gated - then edit the port back and write. The stored
     * configuration matches the grant again, while the statement runs down the socket opened to the
     * second server. Requiring both to match closes it.
     * <p>
     * <b>The two are not always the same object when the connection is closed.</b> Measured on
     * {@code DataSourceDescriptor}: {@code connect} takes its copy before any socket work, and the
     * failure handler clears {@code dataSource} without clearing that copy; the only code that
     * clears it is {@code disconnect}, which returns early when {@code dataSource} is already null.
     * So after a connection attempt that failed, {@code isConnected()} is false while this still
     * reports a separate, pre-attempt copy. Nothing here depends on the two being identical - both
     * are fingerprinted by the same rules and both must match - and the fail-closed direction is
     * preserved: if the stored configuration moved after that failed attempt, the copy disagrees and
     * the write is denied. Do <b>not</b> add an {@code isConnected()} shortcut on the strength of an
     * assumption that they are the same object when idle.
     */
    record Result(
        @Nullable EndpointSnapshot declared,
        @Nullable EndpointSnapshot inUse,
        @Nullable DenialReason failure
    ) {
        Result {
            if ((declared == null) != (failure != null) || (inUse == null) != (failure != null)) {
                throw new IllegalArgumentException(
                    "An endpoint result is either both fingerprints or a failure, never a mixture");
            }
        }

        boolean ok() {
            return failure == null;
        }

        /**
         * Whether a grant recorded for {@code stored} still describes this connection
         * <p>
         * Both sides have to agree. A stored side that cannot say - a row written before schema
         * version 3 - is a mismatch rather than a wildcard, and is rejected by the caller.
         */
        boolean matches(@NotNull EndpointSnapshot stored) {
            return declared != null && inUse != null
                && declared.matches(stored) && inUse.matches(stored);
        }
    }

    private EndpointFingerprints() {
    }

    /**
     * Reads the endpoint identity of a connection, or says why it cannot be read
     * <p>
     * The driver allowlist is <b>not</b> checked here - the caller does that first, so that an
     * out-of-scope database reports as {@code DBMS_UNSUPPORTED} rather than being lumped in with a
     * configuration problem.
     */
    @NotNull
    static Result of(@NotNull DBPDataSourceContainer container) {
        // A substituted driver replaces both the URL and the connect properties from code the
        // configuration does not describe, so nothing stored here identifies the target.
        try {
            if (container.getDriverSubstitution() != null) {
                return unsupported();
            }
        } catch (RuntimeException e) {
            return unsupported();
        }

        DBPDriver driver = container.getDriver();
        if (driver == null) {
            return unsupported();
        }
        String providerId = driver.getProviderId();
        String driverId = driver.getId();
        if (isBlank(providerId) || isBlank(driverId)) {
            return unsupported();
        }

        DBPConnectionConfiguration declared = container.getConnectionConfiguration();
        if (declared == null) {
            return unsupported();
        }
        EndpointSnapshot declaredEndpoint = fingerprint(providerId, driverId, driver, declared);
        if (declaredEndpoint == null) {
            return unsupported();
        }

        // What the connection was actually opened against, which is the case a stored-only
        // comparison cannot see. Usually the platform hands back the stored configuration itself and
        // this is the same object, but not always: a connection attempt that failed leaves a
        // separate pre-attempt copy behind even though the connection is closed. Either way the same
        // rules are applied to it, so the code does not need to know which case it is in.
        DBPConnectionConfiguration inUse;
        try {
            inUse = container.getActualConnectionConfiguration();
        } catch (RuntimeException e) {
            return unsupported();
        }
        if (inUse == null) {
            return unsupported();
        }
        EndpointSnapshot inUseEndpoint = inUse == declared
            ? declaredEndpoint
            : fingerprint(providerId, driverId, driver, inUse);
        if (inUseEndpoint == null) {
            return unsupported();
        }

        return new Result(declaredEndpoint, inUseEndpoint, null);
    }

    /**
     * Reads the six values that identify one configuration's endpoint, or null when it has none
     * <p>
     * Applied to the stored configuration and to the connect-time copy alike, so a rule cannot hold
     * for one and not the other.
     */
    @Nullable
    private static EndpointSnapshot fingerprint(
        @NotNull String providerId,
        @NotNull String driverId,
        @NotNull DBPDriver driver,
        @NotNull DBPConnectionConfiguration configuration
    ) {
        // The mode says which fields the UI edits. It does not say which url is used - see the url
        // check further down, which is the thing that makes these fields trustworthy.
        DBPDriverConfigurationType configurationType = configuration.getConfigurationType();
        if (configurationType != DBPDriverConfigurationType.MANUAL) {
            return null;
        }
        // An auth model that supplies its own URL decides the endpoint before the mode is consulted.
        String authModelId = configuration.getAuthModelId();
        if (!isBlank(authModelId) && !NATIVE_AUTH_MODEL_ID.equals(authModelId)) {
            return null;
        }
        if (hasEnabledHandler(configuration)) {
            return null;
        }
        // A profile contributes handlers at connect time that are not in the connection's own
        // handler list, so an empty handler list does not mean an unrouted connection.
        if (!isBlank(configuration.getConfigProfileName()) || !isBlank(configuration.getConfigProfileSource())) {
            return null;
        }
        // The stored url has to be the one these fields describe, or the fields are decoration.
        //
        // An earlier version of this class asserted the opposite - "mode comes from
        // getConfigurationType() and from nothing else, a non-empty url proves nothing" - and that
        // was wrong in the unsafe direction. Independent review found it. What actually opens the
        // socket is JDBCDataSource.getConnectionURL, which returns connectionInfo.getUrl() verbatim
        // whenever it is non-empty and only falls back to generating one when it is empty
        // (JDBCDataSource.java:402-408); neither the PostgreSQL nor the MySQL data source overrides
        // it. And CloudBeaver's own connection API stores a client-supplied url without touching
        // host, port or database - WebDataSourceUtils.setMainProperties returns as soon as the url
        // is non-empty - while leaving configurationType alone when the request omits it. So a
        // MANUAL connection could name one server in the six fingerprinted fields and connect to a
        // different one entirely, and both fingerprints would still match the grant.
        //
        // The first half of the old comment was true and is why this is a comparison rather than a
        // refusal: every MANUAL connection saved through either UI carries a generated url, so
        // refusing a non-empty url would refuse every connection. What is refused is a url the
        // configuration would not generate. The url itself is never stored or hashed - a generic
        // driver template can carry {user}:{password}@, which must not reach the permission store.
        //
        // The comparison is only worth anything if the driver has a URL template to generate from,
        // so that is checked first. A blank template is not a missing detail - it is the endpoint
        // rule itself being absent. The platform decides between several generation paths on
        // per-driver predicates (isSampleURLForced, isSampleURLApplicable,
        // supportsCustomConnectionURL), and one of the routines they reach,
        // DatabaseURL.generateUrlByTemplate(String, ...), returns connectionInfo.getUrl() unchanged
        // when the template is blank. Where that route is taken the comparison below becomes
        // storedUrl.equals(storedUrl) - true for any url at all - and the six fields stop proving
        // anything. Which route today's four allowlisted drivers take was not the basis for this
        // check: an endpoint whose generation rule cannot be established is refused, so the answer
        // does not depend on platform predicates this fork does not own and cannot pin.
        String sampleUrl;
        try {
            sampleUrl = driver.getSampleURL();
        } catch (RuntimeException e) {
            // An Error is deliberately not caught. The service's outer handler turns one into a
            // keyed denial, which is the existing contract for a failure this class cannot describe.
            return null;
        }
        if (isBlank(sampleUrl)) {
            return null;
        }

        String storedUrl = configuration.getUrl();
        if (!isBlank(storedUrl)) {
            String generated;
            try {
                generated = driver.getConnectionURL(configuration);
            } catch (Exception e) {
                // Cannot establish what this configuration would generate, so cannot establish that
                // the stored url matches it. Covers the checked DBException the platform declares
                // and any RuntimeException a provider raises; an Error again reaches the service.
                return null;
            }
            if (generated == null || !storedUrl.equals(generated)) {
                return null;
            }
        }
        // An allowlist, not a denylist: a property key nobody has classified makes the endpoint
        // unidentifiable, whatever its value. Keys only - no value is read.
        if (!ConnectionPropertyAllowlist.allKeysAllowed(
            providerId, driverId, configuration.getProperties(), configuration.getProviderProperties())
        ) {
            return null;
        }

        String host = configuration.getHostName();
        String port = configuration.getHostPort();
        String database = configuration.getDatabaseName();

        if (isBlank(host) || isBlank(database)) {
            return null;
        }
        // An absent port is refused rather than replaced by the driver default. No platform code
        // substitutes a default - the URL builder omits the ":port" section entirely when the field
        // is empty - so equating "" with 5432 would rest on vendor JAR behaviour that is not in any
        // of these repositories and is not pinned to a driver version.
        if (isBlank(port) || !isUsablePort(port)) {
            return null;
        }
        if (carriesVariable(host) || carriesVariable(port) || carriesVariable(database)
            || carriesVariable(configuration.getServerName())
        ) {
            return null;
        }
        return new EndpointSnapshot(
            providerId, driverId, configurationType.name(), host, port, database);
    }

    /**
     * Whether any network handler is switched on
     * <p>
     * Only {@code isEnabled()} is called, which is a plain field. {@code getType()} deliberately is
     * not: it resolves through the handler's descriptor and, when the configuration has none, goes
     * to {@code DBWorkbench.getPlatform()} and throws if the handler is unknown. Since any enabled
     * handler is refused, the type is not needed, and not needing it keeps a decision path free of
     * both a platform dependency and an exception.
     */
    private static boolean hasEnabledHandler(@NotNull DBPConnectionConfiguration configuration) {
        List<DBWHandlerConfiguration> handlers = configuration.getHandlers();
        if (handlers == null) {
            return false;
        }
        for (DBWHandlerConfiguration handler : handlers) {
            if (handler != null && handler.isEnabled()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Whether a port is a plain number the platform will pass through unchanged
     * <p>
     * Digits only, and inside the TCP range. Whitespace, a sign, leading zeros and anything
     * non-numeric are refused rather than normalised: the platform copies the string into the URL
     * literally, so what such a value connects to is decided inside the vendor driver.
     */
    private static boolean isUsablePort(@NotNull String port) {
        if (port.length() > 5) {
            return false;
        }
        for (int i = 0; i < port.length(); i++) {
            if (port.charAt(i) < '0' || port.charAt(i) > '9') {
                return false;
            }
        }
        // A leading zero is refused rather than normalised. The platform copies the string into the
        // URL literally, so what "05432" connects to is decided inside a vendor driver; and the
        // comparison against a stored grant is textual, so "05432" and "5432" are two identities for
        // what may be one server. Accepting both spellings would mean the same endpoint had two
        // fingerprints, and refusing the odd one keeps the mapping single-valued.
        if (port.length() > 1 && port.charAt(0) == '0') {
            return false;
        }
        int value = Integer.parseInt(port);
        return value >= MIN_PORT && value <= MAX_PORT;
    }

    private static boolean carriesVariable(@Nullable String value) {
        return value != null && value.contains(VARIABLE_OPENER);
    }

    private static boolean isBlank(@Nullable String value) {
        return value == null || value.isBlank();
    }

    @NotNull
    private static Result unsupported() {
        return new Result(null, null, DenialReason.ENDPOINT_UNSUPPORTED);
    }
}
