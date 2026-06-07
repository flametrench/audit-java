// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.audit;

/**
 * Optional authentication context carried on an AuditEvent.
 * Absent when there is no established principal (pre-auth / anonymous / failed login).
 *
 * <p>ADR 0019 constraint: exactly one of {@code sessionId}, {@code patId},
 * {@code shareId}, {@code systemId} is non-null and MUST match {@code kind}.
 * Validated by {@link InMemoryAuditStore#write}.
 */
public record Auth(
        String kind,       // "session" | "pat" | "share" | "system" (ADR 0016)
        String sessionId,  // non-null IFF kind = "session"
        String patId,      // non-null IFF kind = "pat"
        String shareId,    // non-null IFF kind = "share"
        String systemId    // non-null IFF kind = "system"
) {}
