# Changelog

All notable changes to this project will be documented in this file.

## [v0.4.0] — 2026-06-07

### Added
- Initial release: audit primitive implementing [ADR 0019](https://github.com/flametrench/spec/blob/main/decisions/0019-audit-primitive.md) (append-only, identity- and tenancy-aware action logging).
- `AuditEvent` record: full wire shape with `id` (aud_<32hex>/UUIDv7), `occurred_at`, `recorded_at`, `actor_usr_id`, optional `auth` (session/pat/share/system), optional `on_behalf`, `action`, `target`, optional `scope`, `outcome` enum (success/failure/denied/pending), `metadata`, optional `context`.
- `InMemoryAuditStore`: reference in-memory implementation with `write()` (validates, sets `id` and `recorded_at`, returns aud_id) and `get()`.
- `InvalidFormatError` with `field()` discriminator; `NotFoundError`.
- Conformance test harness wired to `audit/write-event-shape.json` (spec@d170484, 7 tests, superset matching).
