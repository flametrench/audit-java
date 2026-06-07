// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.audit;

public class AuditError extends RuntimeException {
    public AuditError(String message) {
        super(message);
    }
}
