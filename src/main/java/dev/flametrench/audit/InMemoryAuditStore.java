// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.audit;

import dev.flametrench.ids.Id;

import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Reference in-memory AuditStore. Behaviorally spec-conformant for ADR 0019:
 * append-only (no update/delete), durable-before-return (synchronous put),
 * server-authoritative {@code recorded_at}, and shape validation on write.
 */
public class InMemoryAuditStore {

    private final Map<String, AuditEvent> events = new LinkedHashMap<>();
    private final Clock clock;

    public InMemoryAuditStore() {
        this(Clock.systemUTC());
    }

    public InMemoryAuditStore(Clock clock) {
        this.clock = clock;
    }

    /**
     * Append an audit event. Validates shape per ADR 0019 §Errors, assigns
     * {@code id} and {@code recorded_at}, and durably records before returning.
     *
     * @return the {@code aud_<32hex>} id of the newly recorded event
     * @throws InvalidFormatError if the event fails shape validation
     */
    public String write(AuditEventInput input) {
        validate(input);

        String id = Id.generate("aud");

        Instant recordedAt = Instant.now(clock);

        AuditEvent event = new AuditEvent(
                id,
                input.occurredAt(),
                recordedAt,
                input.actorUsrId(),
                input.auth(),
                input.onBehalf(),
                input.action(),
                input.target(),
                input.scope(),
                input.outcome(),
                input.metadata(),
                input.context()
        );

        events.put(id, event);
        return id;
    }

    /**
     * Fetch an event by id.
     *
     * @throws NotFoundError if no event with the given id exists
     */
    public AuditEvent get(String id) {
        AuditEvent event = events.get(id);
        if (event == null) throw new NotFoundError(id);
        return event;
    }

    private void validate(AuditEventInput input) {
        if (input.actorUsrId() != null && !Id.isValid(input.actorUsrId(), "usr")) {
            throw new InvalidFormatError("actor_usr_id");
        }
        if (input.auth() != null) {
            validateAuth(input.auth());
        }
    }

    private void validateAuth(Auth auth) {
        int count = 0;
        if (auth.sessionId() != null) count++;
        if (auth.patId() != null) count++;
        if (auth.shareId() != null) count++;
        if (auth.systemId() != null) count++;

        boolean kindMatch = switch (auth.kind()) {
            case "session" -> count == 1 && auth.sessionId() != null;
            case "pat"     -> count == 1 && auth.patId() != null;
            case "share"   -> count == 1 && auth.shareId() != null;
            case "system"  -> count == 1 && auth.systemId() != null;
            default        -> false;
        };

        if (!kindMatch) {
            throw new InvalidFormatError("auth");
        }
    }
}
