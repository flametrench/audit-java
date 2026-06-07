// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.audit;

public class NotFoundError extends AuditError {
    public NotFoundError(String id) {
        super("Audit event not found: " + id);
    }
}
