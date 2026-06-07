// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.audit;

import java.time.Instant;
import java.util.Map;

/**
 * Input for {@link InMemoryAuditStore#write}. The store assigns {@code id} and
 * {@code recordedAt}; emitters MUST NOT supply them (ADR 0019).
 */
public record AuditEventInput(
        Instant occurredAt,
        String actorUsrId,                // null for system/pre-auth events
        Auth auth,                        // null when no established principal
        OnBehalf onBehalf,               // null when no delegated agent
        String action,
        Target target,
        Scope scope,                      // null for global/system events
        Outcome outcome,
        Map<String, Object> metadata,
        Map<String, Object> context       // null if not supplied
) {}
