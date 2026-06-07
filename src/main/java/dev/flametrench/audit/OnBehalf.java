// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.audit;

/**
 * Present IFF a delegated non-human actor performed the action.
 * Orthogonal to {@link Auth#kind()} — an agent typically authenticates with
 * a session or PAT; {@code on_behalf} is a different axis (ADR 0019).
 */
public record OnBehalf(
        String agentId  // opaque, adopter-defined; not parsed by this primitive
) {}
