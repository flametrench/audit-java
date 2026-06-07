// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.audit;

/**
 * Optional tenancy boundary the action occurred within.
 * Absent for global / non-org-scoped events (login, system actions with no resolvable scope).
 */
public record Scope(String kind, String id) {}
