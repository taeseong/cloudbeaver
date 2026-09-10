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

import java.util.Map;
import java.util.Set;

/**
 * Which connection-property keys a connection may carry and still have an identifiable endpoint
 * <p>
 * An allowlist, not a denylist. The previous version named five keys that were known to reroute a
 * connection and accepted everything else, and its own comment admitted the list could not be proved
 * complete. Independent review rejected that: an endpoint identity cannot rest on a list of the
 * dangers somebody happened to think of. So the rule is inverted - a key that is not named here
 * makes the connection ineligible, whatever its value.
 * <p>
 * <b>Why an empty driver-property list is the right starting point.</b> Measured on this fork: the
 * stored {@code properties} map of an ordinary web-created PostgreSQL or MySQL connection is
 * <em>empty</em>. CloudBeaver's frontend strips every driver property whose value equals the driver
 * default before sending it, and the plugin.xml defaults ({@code loginTimeout},
 * {@code connectTimeout}, {@code escapeSyntaxCallMode} and the rest) live on the driver descriptor
 * rather than on any connection. So refusing every driver property costs nothing in the ordinary
 * case, and it means this class makes <b>no claim at all</b> about which of pgjdbc's 92 or
 * Connector/J's 267 recognised property names are harmless. Widening the list is a per-key decision
 * that needs its own recorded justification - see
 * {@code docs/db-access-control-endpoint-identity.md} section 3.2 - and this class is deliberately
 * the wrong place to guess.
 * <p>
 * <b>The two maps are different key spaces, and both fail closed.</b> Only
 * {@code DBPConnectionConfiguration.properties} reaches {@code Driver.connect}:
 * {@code JDBCDataSource.getAllConnectionProperties} builds the JDBC {@code Properties} from the
 * provider's internal properties, the driver descriptor's defaults and this map, and
 * {@code providerProperties} appears nowhere in that chain. Provider properties are DBeaver's own
 * behaviour switches. They still get an allowlist, with the same "unknown means refuse" rule, both
 * because two of them are translated into driver properties by provider code and because a key
 * nobody has classified is a key nobody has thought about.
 * <p>
 * <b>Comparison is exact.</b> Byte-for-byte {@code equals} against the sets below: no trimming, no
 * case folding, no prefix or substring matching, no normalisation of the incoming key. That matches
 * how the drivers themselves read this map - pgjdbc looks up {@code Properties.getProperty(name)}
 * with the exact string and its only case-insensitive aliasing applies to URL query keys, which this
 * fork refuses outright by refusing URL mode; Connector/J marks each property key case-sensitive or
 * not individually, and every one of its eleven case-insensitive keys is a routing or credential key
 * that is refused anyway. A permissive comparison on our side would accept spellings the driver then
 * treats as a different, unrecognised property - or as the real one.
 * <p>
 * <b>No value is ever read.</b> Only the key sets are inspected. A property value can be a password,
 * a key path, a URL or a class name, so nothing here reads one, and nothing here puts a key or a
 * value into a decision, an audit payload or a log line.
 */
public final class ConnectionPropertyAllowlist {

    /**
     * Driver properties a connection may carry
     * <p>
     * Empty for every supported driver, on purpose - see the class note. This is a map from the
     * driver identity to its own set so that widening the list for one driver cannot widen it for
     * another: pgjdbc and Connector/J share almost no property names, and a key that is inert in one
     * can be meaningful in the other.
     */
    private static final Map<String, Set<String>> DRIVER_PROPERTIES = Map.of(
        "postgresql:postgres-jdbc", Set.of(),
        "postgresql:postgresql", Set.of(),
        "mysql:mysql8", Set.of(),
        "mysql:mysql5", Set.of()
    );

    /**
     * Provider properties a connection may carry
     * <p>
     * <b>MySQL: {@code @dbeaver-show-all-dbs@}, and only because it has to be.</b> It is declared in
     * the MySQL extension's own {@code plugin.xml} with {@code defaultValue="false"}, and
     * CloudBeaver's frontend sends provider-property defaults without stripping them - so an
     * ordinary web-created MySQL connection stores it. Refusing it would refuse every such
     * connection. It is safe to ignore for endpoint purposes on two counts: it never reaches the
     * driver, and what it changes is which databases the navigator lists.
     * <p>
     * <b>PostgreSQL: nothing.</b> An earlier version allowed the same key for PostgreSQL on the
     * grounds that it "means the same thing under both providers". That was wrong, and independent
     * review caught it: the key is {@code MySQLConstants.PROP_SHOW_ALL_DBS} and is declared only by
     * the MySQL extension. PostgreSQL's counterpart is {@code @dbeaver-show-non-default-db@}, which
     * declares no default, and no PostgreSQL provider property declares one - so an ordinary
     * PostgreSQL connection stores an empty provider map and needs nothing allowed. The consequence
     * is recorded rather than left implicit: a PostgreSQL connection that sets <em>any</em> provider
     * property - "Show all databases", "Show template databases", a user role, and the rest - is
     * refused, and cannot hold temporary write access until it is unset.
     * <p>
     * Deliberately absent from every row: {@code @dbeaver-serverTimezone@} and
     * {@code @dbeaver-use-prepared-statements-db@}. Those are the two provider properties that
     * provider code translates into something the driver receives, so they belong with driver
     * properties rather than here, and neither has been justified as harmless.
     * {@code @dbeaver-show-non-default-db@} is absent too, and not only because nothing needs it:
     * PostgreSQL opens a separate JDBC connection per database, so allowing it would let a grant
     * checked against one database be used against another - see the design note.
     */
    private static final Map<String, Set<String>> PROVIDER_PROPERTIES = Map.of(
        "postgresql:postgres-jdbc", Set.of(),
        "postgresql:postgresql", Set.of(),
        "mysql:mysql8", Set.of("@dbeaver-show-all-dbs@"),
        "mysql:mysql5", Set.of("@dbeaver-show-all-dbs@")
    );

    private ConnectionPropertyAllowlist() {
    }

    /**
     * Whether every key in both maps is one this driver is allowed to carry
     * <p>
     * A driver that is not in the tables answers false for any non-empty map. That cannot normally
     * happen - the caller has already checked the driver against
     * {@link SupportedTargetDatabase} - but an unknown driver with unknown properties is exactly the
     * case that must not fall through to "allowed".
     *
     * @param properties the stored driver-property keys, or null
     * @param providerProperties the stored provider-property keys, or null
     */
    public static boolean allKeysAllowed(
        @NotNull String providerId,
        @NotNull String driverId,
        @Nullable Map<String, String> properties,
        @Nullable Map<String, String> providerProperties
    ) {
        String driver = providerId + ":" + driverId;
        return allKeysIn(properties, DRIVER_PROPERTIES.get(driver))
            && allKeysIn(providerProperties, PROVIDER_PROPERTIES.get(driver));
    }

    /**
     * Whether every key of a map is in the allowed set
     * <p>
     * A null allowed set means the driver is not described here, which allows nothing. Only keys are
     * read; the map's values are never touched.
     */
    private static boolean allKeysIn(
        @Nullable Map<String, String> map,
        @Nullable Set<String> allowed
    ) {
        if (map == null || map.isEmpty()) {
            return true;
        }
        if (allowed == null) {
            return false;
        }
        for (String key : map.keySet()) {
            if (key == null || !allowed.contains(key)) {
                return false;
            }
        }
        return true;
    }

    /**
     * The allowed driver-property keys, so a test can assert the list rather than restate it
     */
    @NotNull
    public static Set<String> driverProperties(@NotNull String providerId, @NotNull String driverId) {
        Set<String> allowed = DRIVER_PROPERTIES.get(providerId + ":" + driverId);
        return allowed == null ? Set.of() : allowed;
    }

    /**
     * The allowed provider-property keys, likewise
     */
    @NotNull
    public static Set<String> providerProperties(@NotNull String providerId, @NotNull String driverId) {
        Set<String> allowed = PROVIDER_PROPERTIES.get(providerId + ":" + driverId);
        return allowed == null ? Set.of() : allowed;
    }

    /**
     * How many drivers the tables describe, pinned by a test alongside the driver allowlist
     */
    public static int describedDriverCount() {
        return DRIVER_PROPERTIES.size();
    }
}
