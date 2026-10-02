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

import org.jkiss.code.NotNull;
import org.jkiss.dbeaver.Log;
import org.jkiss.dbeaver.model.exec.DBCExecutionContext;
import org.jkiss.dbeaver.model.qm.QMExecutionHandler;
import org.jkiss.dbeaver.model.qm.QMUtils;
import org.jkiss.dbeaver.runtime.qm.DefaultExecutionHandler;

import java.util.UUID;
import java.util.function.BooleanSupplier;

/**
 * Tells the taint sink when an execution context closes
 * <p>
 * A close is reported synchronously on the closing thread, and a sever or a reconnect is not
 * reported at all (CH-7). In P3 the production sink does nothing, because nothing can be tainted
 * before enforcement is wired; the transaction taint registry takes its place in P5.
 * <p>
 * The handler has no way to change the policy lifecycle. It reports a close only while
 * {@code accepting} says the lifecycle it belongs to is ready or failed, so a close after the
 * service has started stopping is ignored.
 */
public final class TaintContextCloseHandler extends DefaultExecutionHandler {

    /**
     * Where closes are reported, and what the lifecycle clears when it stops
     */
    public interface TaintSink {
        /** Records nothing; the P3 production sink, until the taint registry exists */
        TaintSink NONE = new TaintSink() {
            @Override
            public void contextClosed(long contextId) {
                // nothing can be tainted before enforcement is wired
            }

            @Override
            public void clear() {
                // nothing to clear
            }
        };

        /**
         * The execution context with this id was closed
         */
        void contextClosed(long contextId);

        /**
         * Forgets everything; called once, when the policy service stops
         */
        void clear();
    }

    /**
     * How the handler is added to and removed from the query manager
     */
    public interface HandlerRegistrar {
        /** The platform query manager */
        HandlerRegistrar QUERY_MANAGER = new HandlerRegistrar() {
            @Override
            public void register(@NotNull QMExecutionHandler handler) {
                QMUtils.registerHandler(handler);
            }

            @Override
            public void unregister(@NotNull QMExecutionHandler handler) {
                QMUtils.unregisterHandler(handler);
            }
        };

        /**
         * Starts delivering query manager events to the handler
         */
        void register(@NotNull QMExecutionHandler handler);

        /**
         * Stops delivering query manager events to the handler
         */
        void unregister(@NotNull QMExecutionHandler handler);
    }

    /** Logged when a close could not be reported: the accepting check or the sink failed */
    private static final String EVENT_SINK_FAILED = "DBAC_TAINT_SINK_CLOSE_FAILED";

    private static final Log log = Log.getLog(TaintContextCloseHandler.class);

    private final TaintSink sink;
    private final BooleanSupplier accepting;

    public TaintContextCloseHandler(@NotNull TaintSink sink, @NotNull BooleanSupplier accepting) {
        this.sink = sink;
        this.accepting = accepting;
    }

    @NotNull
    @Override
    public String getHandlerName() {
        return "DBAC transaction taint close handler";
    }

    /**
     * Reports the close to the sink while the lifecycle accepts it
     * <p>
     * Nothing it hits leaves it (C16): a {@code RuntimeException} or an {@code Error} from the
     * accepting check or from the sink is logged by event code, correlation id and exception class
     * only, and a log that cannot be written is ignored. Otherwise the query manager would log what
     * reached it with its message and stack trace, and an {@code Error} would leave its dispatcher.
     */
    @Override
    public void handleContextClose(@NotNull DBCExecutionContext context) {
        try {
            if (accepting.getAsBoolean()) {
                sink.contextClosed(context.getContextId());
            }
        } catch (RuntimeException | Error e) {
            try {
                log.error("DBAC taint close handler failed on a context close [event=" + EVENT_SINK_FAILED
                    + " EVENT_ID=" + UUID.randomUUID() + " exception=" + e.getClass().getName() + "]");
            } catch (RuntimeException | Error ignored) {
                // Deliberately nothing: a close must not fail because it could not be logged.
            }
        }
    }
}
