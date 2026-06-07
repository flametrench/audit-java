// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.audit;

/**
 * The entity the audited action acted upon.
 *
 * <p>{@code kind} is a Flametrench entity type (e.g. "usr", "org") or an adopter
 * {@code object_type} ({@code ^[a-z]{2,6}$}). {@code id} is a Flametrench wire id
 * or an opaque adopter string — the primitive does not decode adopter ids.
 */
public record Target(String kind, String id) {}
