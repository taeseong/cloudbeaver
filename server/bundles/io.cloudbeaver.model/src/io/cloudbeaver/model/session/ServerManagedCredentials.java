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
package io.cloudbeaver.model.session;

import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.jkiss.dbeaver.model.DBPDataSourceContainer;
import org.jkiss.dbeaver.model.connection.DBPConnectionConfiguration;
import org.jkiss.dbeaver.model.runtime.DBRProgressMonitor;

import java.util.Collection;
import java.util.Map;
import java.util.Objects;

/**
 * Where a server-side component supplies the database credential of the connections it governs
 * <p>
 * A governed connection takes its credential from the server, never from the client and never from what is stored
 * with the connection. The web session asks the installed {@link Provider} whether it governs a connection; if it
 * does, the provider alone fills the connect-time copy of the configuration, or refuses. The default provider governs
 * nothing, so a server that installs none behaves as it always did.
 * <p>
 * This class knows nothing about the component that installs a provider, so the session does not depend on it.
 */
public final class ServerManagedCredentials {

    /** The only message a refusal carries: it names no connection, endpoint, reference or credential */
    public static final String REFUSAL_MESSAGE = "The connection is refused by the server-managed credential policy";

    /**
     * Supplies the credential of the connections it governs
     * <p>
     * Implementations are used concurrently and keep no credential they supplied.
     */
    public interface Provider {

        /** Whether the server supplies this connection's credential */
        boolean governs(@NotNull DBPDataSourceContainer container);

        /**
         * Puts the read credential into the connect-time copy of a governed connection's configuration, or refuses
         *
         * @param connectTimeCopy          the configuration the connect uses - never the one that is saved
         * @param clientCredentialsPresent whether the client sent credentials for this connection
         * @param explicitConnect          whether the connect runs inside {@link #explicitConnect}
         * @throws Refusal when the connection must not connect
         */
        void supplyReadCredential(
            @NotNull DBPDataSourceContainer container,
            @NotNull DBPConnectionConfiguration connectTimeCopy,
            boolean clientCredentialsPresent,
            boolean explicitConnect
        );

        /**
         * Checks, right after a governed connect, that the database session runs as the credential that was supplied
         *
         * @throws Refusal when it does not, or when that cannot be established; the caller disconnects
         */
        void verifyConnected(@NotNull DBPDataSourceContainer container, @NotNull DBRProgressMonitor monitor);

        /** Records that a client sent credentials for a governed connection, and returns the refusal to raise */
        @NotNull
        Refusal refuseClientInput(@NotNull DBPDataSourceContainer container);

        /** Records that a governed connect failed, and returns the refusal to raise in place of the failure */
        @NotNull
        Refusal connectFailed(@NotNull DBPDataSourceContainer container, @NotNull Throwable failure);
    }

    /** A refused governed connection: the fixed message, no cause and no stack trace */
    public static final class Refusal extends RuntimeException {
        public Refusal() {
            super(REFUSAL_MESSAGE, null, false, false);
        }
    }

    /** Puts back the provider that was installed before a {@link #swap} */
    public interface Installation extends AutoCloseable {
        @Override
        void close();
    }

    /** Ends an {@link #explicitConnect} scope */
    public interface Scope extends AutoCloseable {
        @Override
        void close();
    }

    /** Governs nothing */
    public static final Provider NONE = new Provider() {
        @Override
        public boolean governs(@NotNull DBPDataSourceContainer container) {
            return false;
        }

        @Override
        public void supplyReadCredential(
            @NotNull DBPDataSourceContainer container,
            @NotNull DBPConnectionConfiguration connectTimeCopy,
            boolean clientCredentialsPresent,
            boolean explicitConnect
        ) {
            throw new Refusal();
        }

        @Override
        public void verifyConnected(@NotNull DBPDataSourceContainer container, @NotNull DBRProgressMonitor monitor) {
            throw new Refusal();
        }

        @NotNull
        @Override
        public Refusal refuseClientInput(@NotNull DBPDataSourceContainer container) {
            return new Refusal();
        }

        @NotNull
        @Override
        public Refusal connectFailed(@NotNull DBPDataSourceContainer container, @NotNull Throwable failure) {
            return new Refusal();
        }
    };

    private static final ThreadLocal<DBPDataSourceContainer> EXPLICIT_CONNECT = new ThreadLocal<>();
    private static volatile Provider current = NONE;

    private ServerManagedCredentials() {
    }

    @NotNull
    public static Provider provider() {
        return current;
    }

    /**
     * Installs the server's provider
     * <p>
     * Once, over the default: a provider that is in place is never replaced quietly.
     */
    public static synchronized void install(@NotNull Provider provider) {
        Objects.requireNonNull(provider, "provider");
        if (current != NONE) {
            throw new IllegalStateException("A server-managed credential provider is already installed");
        }
        current = provider;
    }

    /**
     * Replaces the provider until the returned installation is closed - a test seam, never server configuration
     */
    @NotNull
    public static synchronized Installation swap(@NotNull Provider provider) {
        Objects.requireNonNull(provider, "provider");
        Provider previous = current;
        current = provider;
        return new Installation() {
            private boolean closed;

            @Override
            public void close() {
                synchronized (ServerManagedCredentials.class) {
                    if (!closed) {
                        closed = true;
                        current = previous;
                    }
                }
            }
        };
    }

    /**
     * Marks the calling thread's connect of {@code container} as one a client asked for explicitly
     * <p>
     * Only a connect inside this scope may receive a governed credential. Any other connect of a governed connection -
     * a platform reconnect, a navigator that opens the connection on its own - is refused, so that every governed
     * connect goes through the entry point that also reports its failure without detail.
     */
    @NotNull
    public static Scope explicitConnect(@NotNull DBPDataSourceContainer container) {
        DBPDataSourceContainer previous = EXPLICIT_CONNECT.get();
        EXPLICIT_CONNECT.set(container);
        return () -> {
            if (previous == null) {
                EXPLICIT_CONNECT.remove();
            } else {
                EXPLICIT_CONNECT.set(previous);
            }
        };
    }

    public static boolean isExplicitConnect(@NotNull DBPDataSourceContainer container) {
        return EXPLICIT_CONNECT.get() == container;
    }

    /** Whether client input carries a credential: an auth property with a non-empty value, or any network credential */
    public static boolean carriesCredentials(
        @Nullable Map<String, ?> authProperties,
        @Nullable Collection<?> networkCredentials
    ) {
        if (networkCredentials != null && !networkCredentials.isEmpty()) {
            return true;
        }
        if (authProperties != null) {
            for (Object value : authProperties.values()) {
                if (value != null && !String.valueOf(value).isEmpty()) {
                    return true;
                }
            }
        }
        return false;
    }
}
