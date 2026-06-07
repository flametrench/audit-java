// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.audit;

import java.time.Instant;
import java.util.Map;

/**
 * An immutable, append-only audit event (ADR 0019).
 *
 * <p>Instances are returned by {@link InMemoryAuditStore#get}. They are never
 * constructed directly by callers — use {@link AuditEventInput} as the write
 * input and let the store assign {@code id} and {@code recordedAt}.
 *
 * <p>All fields follow the ADR 0019 normative shape. Optional fields are null
 * when absent (not present in the event).
 */
public record AuditEvent(
        String id,                        // aud_<32hex>; UUIDv7 underneath
        Instant occurredAt,               // emitter clock
        Instant recordedAt,               // server-authoritative; set on write
        String actorUsrId,                // usr_<32hex> or null (system/pre-auth)
        Auth auth,                        // null when no established principal
        OnBehalf onBehalf,               // null when no delegated agent
        String action,                    // adopter-namespaced, opaque to the primitive
        Target target,
        Scope scope,                      // null for global/system events
        Outcome outcome,
        Map<String, Object> metadata,     // free-form; adopter layering
        Map<String, Object> context       // null if not supplied; request context
) {}
