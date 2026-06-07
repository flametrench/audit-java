// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.audit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.flametrench.ids.Id;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Flametrench v0.4 conformance suite — Java / JUnit 5 harness for the audit capability.
 *
 * <p>Implements the state-machine fixture format. Each test:
 * <ol>
 *   <li>Pre-allocates fresh usr_ IDs for declared named users.</li>
 *   <li>Creates a fresh InMemoryAuditStore.</li>
 *   <li>Walks the steps list, resolving {var} references, invoking ops,
 *       capturing return values, and asserting superset-match on expected results.</li>
 * </ol>
 *
 * <p>Superset matching (result ⊇ expected): every key/value in the expected
 * object must appear in the actual result. Fields not listed in expected
 * (e.g. {@code recorded_at}) are not checked — they are SDK unit-test territory.
 */
class ConformanceTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Pattern VAR_PATTERN = Pattern.compile("^\\{([a-z_][a-z0-9_]*)\\}$");

    private static final DateTimeFormatter MILLIS_Z =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC);

    private static JsonNode loadFixture(String relativePath) throws IOException {
        String resource = "/conformance/fixtures/" + relativePath;
        try (InputStream in = ConformanceTest.class.getResourceAsStream(resource)) {
            if (in == null) throw new IOException("Fixture not found: " + resource);
            return MAPPER.readTree(in);
        }
    }

    private static Object resolveVars(Object value, Map<String, Object> variables) {
        if (value instanceof String s) {
            Matcher m = VAR_PATTERN.matcher(s);
            if (m.matches()) {
                String name = m.group(1);
                if (!variables.containsKey(name)) {
                    throw new IllegalStateException("Unknown variable in fixture: {" + name + "}");
                }
                return variables.get(name);
            }
            return s;
        }
        if (value instanceof List<?> list) {
            List<Object> out = new ArrayList<>(list.size());
            for (Object item : list) out.add(resolveVars(item, variables));
            return out;
        }
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : map.entrySet()) {
                out.put((String) e.getKey(), resolveVars(e.getValue(), variables));
            }
            return out;
        }
        return value;
    }

    private static Object jsonToPlain(JsonNode node) {
        if (node == null || node.isNull()) return null;
        if (node.isTextual()) return node.asText();
        if (node.isInt() || node.isLong()) return node.asLong();
        if (node.isDouble() || node.isFloat()) return node.asDouble();
        if (node.isBoolean()) return node.asBoolean();
        if (node.isArray()) {
            List<Object> out = new ArrayList<>();
            for (JsonNode child : node) out.add(jsonToPlain(child));
            return out;
        }
        if (node.isObject()) {
            Map<String, Object> out = new LinkedHashMap<>();
            Iterator<Map.Entry<String, JsonNode>> it = node.fields();
            while (it.hasNext()) {
                Map.Entry<String, JsonNode> e = it.next();
                out.put(e.getKey(), jsonToPlain(e.getValue()));
            }
            return out;
        }
        throw new IllegalStateException("Unhandled JSON node type: " + node.getNodeType());
    }

    @SuppressWarnings("unchecked")
    private static Auth buildAuth(Object raw) {
        if (raw == null) return null;
        Map<String, Object> m = (Map<String, Object>) raw;
        return new Auth(
                (String) m.get("kind"),
                (String) m.get("session_id"),
                (String) m.get("pat_id"),
                (String) m.get("share_id"),
                (String) m.get("system_id")
        );
    }

    @SuppressWarnings("unchecked")
    private static OnBehalf buildOnBehalf(Object raw) {
        if (raw == null) return null;
        Map<String, Object> m = (Map<String, Object>) raw;
        return new OnBehalf((String) m.get("agent_id"));
    }

    @SuppressWarnings("unchecked")
    private static Target buildTarget(Object raw) {
        Map<String, Object> m = (Map<String, Object>) raw;
        return new Target((String) m.get("kind"), (String) m.get("id"));
    }

    @SuppressWarnings("unchecked")
    private static Scope buildScope(Object raw) {
        if (raw == null) return null;
        Map<String, Object> m = (Map<String, Object>) raw;
        return new Scope((String) m.get("kind"), (String) m.get("id"));
    }

    private static Map<String, Object> eventToMap(AuditEvent event) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", event.id());
        map.put("occurred_at", MILLIS_Z.format(event.occurredAt()));
        map.put("recorded_at", MILLIS_Z.format(event.recordedAt()));
        map.put("actor_usr_id", event.actorUsrId());
        if (event.auth() != null) {
            Map<String, Object> auth = new LinkedHashMap<>();
            auth.put("kind", event.auth().kind());
            if (event.auth().sessionId() != null) auth.put("session_id", event.auth().sessionId());
            if (event.auth().patId() != null) auth.put("pat_id", event.auth().patId());
            if (event.auth().shareId() != null) auth.put("share_id", event.auth().shareId());
            if (event.auth().systemId() != null) auth.put("system_id", event.auth().systemId());
            map.put("auth", auth);
        }
        if (event.onBehalf() != null) {
            map.put("on_behalf", Map.of("agent_id", event.onBehalf().agentId()));
        }
        map.put("action", event.action());
        map.put("target", Map.of("kind", event.target().kind(), "id", event.target().id()));
        if (event.scope() != null) {
            map.put("scope", Map.of("kind", event.scope().kind(), "id", event.scope().id()));
        }
        map.put("outcome", event.outcome().name());
        map.put("metadata", event.metadata());
        if (event.context() != null) {
            map.put("context", event.context());
        }
        return map;
    }

    @SuppressWarnings("unchecked")
    private static Object invokeOp(
            InMemoryAuditStore store, String op, Map<String, Object> args
    ) {
        return switch (op) {
            case "write" -> {
                Instant occurredAt = Instant.parse((String) args.get("occurred_at"));
                String actorUsrId = (String) args.get("actor_usr_id");
                Auth auth = buildAuth(args.get("auth"));
                OnBehalf onBehalf = buildOnBehalf(args.get("on_behalf"));
                String action = (String) args.get("action");
                Target target = buildTarget(args.get("target"));
                Scope scope = buildScope(args.get("scope"));
                Outcome outcome = Outcome.valueOf((String) args.get("outcome"));
                Map<String, Object> metadata = (Map<String, Object>) args.get("metadata");
                Map<String, Object> context = (Map<String, Object>) args.get("context");

                AuditEventInput input = new AuditEventInput(
                        occurredAt, actorUsrId, auth, onBehalf, action,
                        target, scope, outcome, metadata, context
                );
                String id = store.write(input);
                // Return as map so captures{"aud_id": "id"} resolves via map key lookup
                yield Map.of("id", id);
            }
            case "get" -> {
                AuditEvent event = store.get((String) args.get("id"));
                yield eventToMap(event);
            }
            default -> throw new IllegalStateException("Unknown fixture op: " + op);
        };
    }

    @SuppressWarnings("unchecked")
    private static void assertSuperset(Object actual, Object expected, String path) {
        if (expected instanceof Map<?, ?> expectedMap) {
            assertInstanceOf(Map.class, actual, "Expected Map at " + path);
            Map<String, Object> actualMap = (Map<String, Object>) actual;
            for (Map.Entry<?, ?> entry : expectedMap.entrySet()) {
                String key = (String) entry.getKey();
                assertTrue(actualMap.containsKey(key),
                        "Missing key '" + key + "' at " + path);
                assertSuperset(actualMap.get(key), entry.getValue(), path + "." + key);
            }
        } else {
            assertEquals(expected, actual, "Mismatch at " + path);
        }
    }

    @SuppressWarnings("unchecked")
    private static void runTest(JsonNode test) {
        InMemoryAuditStore store = new InMemoryAuditStore();
        Map<String, Object> variables = new HashMap<>();

        if (test.has("users")) {
            for (JsonNode userName : test.get("users")) {
                variables.put(userName.asText(), Id.generate("usr"));
            }
        }

        for (JsonNode step : test.get("steps")) {
            String op = step.get("op").asText();
            Map<String, Object> resolvedInput = (Map<String, Object>) resolveVars(
                    jsonToPlain(step.get("input")), variables);

            JsonNode expected = step.get("expected");
            if (expected != null && expected.has("error")) {
                // Error-path assertions not in write-event-shape.json but supported for completeness
                fail("Unexpected expected error in fixture: " + expected.get("error").asText());
            }

            Object result = invokeOp(store, op, resolvedInput);

            if (expected != null && expected.has("result")) {
                Object expectedResult = resolveVars(jsonToPlain(expected.get("result")), variables);
                assertSuperset(result, expectedResult, "result");
            }

            JsonNode captures = step.get("captures");
            if (captures != null) {
                Iterator<Map.Entry<String, JsonNode>> it = captures.fields();
                while (it.hasNext()) {
                    Map.Entry<String, JsonNode> e = it.next();
                    String capturePath = e.getValue().asText();
                    Object captured = result instanceof Map<?, ?> map
                            ? ((Map<?, ?>) map).get(capturePath)
                            : result;
                    variables.put(e.getKey(), captured);
                }
            }
        }

        assertTrue(true);
    }

    private List<DynamicTest> conformanceTests(String fixturePath) throws IOException {
        JsonNode fixture = loadFixture(fixturePath);
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode t : fixture.get("tests")) {
            String id = t.get("id").asText();
            String desc = t.get("description").asText();
            tests.add(DynamicTest.dynamicTest("[" + id + "] " + desc, () -> runTest(t)));
        }
        return tests;
    }

    @TestFactory
    List<DynamicTest> writeEventShape() throws IOException {
        return conformanceTests("audit/write-event-shape.json");
    }
}
