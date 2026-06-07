// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.audit;

/**
 * Raised by {@code write} when the supplied event fails shape validation.
 * The {@code field} names the offending part of the event (e.g. "auth",
 * "outcome", "actor_usr_id", "size") per ADR 0019 §Errors.
 */
public class InvalidFormatError extends AuditError {

    private final String field;

    public InvalidFormatError(String field) {
        super("Invalid format for field: " + field);
        this.field = field;
    }

    public String field() {
        return field;
    }
}
