# CLAUDE.md -- netray-common

## Rules

- No Co-Authored-By for Claude in commits
- Scoped changes only: no formatting mixed with functional changes, no unrelated modifications
- No heavy deps for minor convenience; no speculative flags/config/abstractions without a caller
- Don't bypass failing checks (`--no-verify`, `#[allow(...)]`) without explaining why
- No PII, real emails, or real domains (use example.com) in test data, docs, commits
- `TODO("reason")` over hidden guesses; conventional commits (`feat:`, `fix:`, `refactor:`, etc.)

## Engineering Principles

KISS · YAGNI · DRY (rule of three) · SRP · Fail Fast · Secure by Default · Reversibility · Performance

- **Rust patterns**: Use idiomatic Rust (enums, traits, iterators). Leverage the type system to prevent invalid states.

## Project Overview

**netray-common** is a shared utility crate for the [netray.info](https://netray.info) service ecosystem. It provides cross-cutting concerns (IP extraction, error formatting, rate limiting, security headers) used by multiple backend services.

- **Author**: Lukas Pustina | **License**: MIT
- **MSRV**: 1.75

## CI/CD

Workflow rules: [`specs/rules/workflow-rules.md`](../specs/rules/workflow-rules.md) in the netray.info meta repo. Follow those rules when creating or modifying any `.github/workflows/*.yml` file.

Workflows: `ci.yml` (PR gate: fmt, clippy, test, audit). No release automation — publish to crates.io is a manual `cargo publish`.

## Build & Test

```sh
cargo test                   # run all tests
cargo clippy -- -D warnings  # lint
cargo fmt                    # format
cargo fmt -- --check         # check formatting
```

## Architecture

```
netray-common/
  Cargo.toml
  src/
    lib.rs                   # crate root, re-exports modules
    ip_extract.rs            # real client IP extraction from proxy headers
    error.rs                 # structured JSON error responses (ApiError trait)
    rate_limit.rs            # keyed + global rate limiting (governor wrappers)
    security_headers.rs      # axum middleware for CSP, HSTS, X-Frame-Options, etc.
    telemetry.rs             # tracing-subscriber init + optional OTel OTLP export
```

### Modules

| Module | Purpose |
|--------|---------|
| `ip_extract` | `IpExtractor` checks proxy headers (CF-Connecting-IP, X-Real-IP, X-Forwarded-For) only when the peer IP is in the trusted proxy CIDR list. Safe default: empty list ignores all headers. |
| `error` | `ApiError` trait + `into_error_response()` produces `{"error": {"code": "...", "message": "..."}}` JSON. Adds `Retry-After` header for rate-limited responses. |
| `rate_limit` | `check_keyed_cost` and `check_direct_cost` wrap governor's GCRA limiter. Emit `{prefix}_rate_limit_hits_total` metrics on rejection. |
| `security_headers` | `security_headers_layer()` returns an axum middleware closure. Sets CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy. Supports relaxed CSP for docs paths. |
| `telemetry` | `init_subscriber()` sets up tracing-subscriber with env filter + optional OTel OTLP layer. `TelemetryConfig` (log_format, enabled, otlp_endpoint, service_name, sample_rate). `shutdown()` flushes spans. All tools must use this -- see [`specs/rules/logging-rules.md`](../specs/rules/logging-rules.md). |

## Key Dependencies

- `axum` 0.8 -- HTTP types (HeaderMap, StatusCode, IntoResponse, middleware)
- `governor` 0.10 -- GCRA rate limiting
- `ip_network` 0.4 -- CIDR parsing and matching for trusted proxies
- `metrics` 0.24 -- Rate limit rejection counters
- `serde` -- JSON serialization for error responses
- `tracing` -- Structured logging

## Common Patterns

- **Safe defaults**: `IpExtractor` with no trusted proxies returns the peer IP directly, preventing IP spoofing.
- **Bare IP auto-promotion**: Individual IPs like `10.0.0.1` are promoted to `/32` (IPv4) or `/128` (IPv6) for consistent CIDR matching.
- **Right-to-left XFF walk**: `X-Forwarded-For` is walked from right to left, skipping trusted proxies, to find the real client IP.
- **Error trait pattern**: Each service defines its own error enum and implements `ApiError`. The shared `into_error_response` handles serialization.
- **Metrics prefix**: Rate limit functions take a `metrics_prefix` so each service gets distinct counter names.
