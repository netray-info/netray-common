# CLAUDE.md -- netray-common

## Rules

- Do NOT add a `Co-Authored-By` line for Claude in commit messages.
- Don't add heavy dependencies for minor convenience -- check if existing deps already cover the need.
- Don't mix formatting-only changes with functional changes in the same commit.
- Don't modify unrelated modules "while you're in there" -- keep changes scoped.
- Don't add speculative flags, config options, or abstractions without a current caller.
- Don't bypass failing checks (`--no-verify`, `#[allow(...)]`) without explaining why.
- Don't hide behavior changes inside refactor commits -- separate them.
- Don't include PII, real email addresses, or real domains (other than example.com) in test data, docs, or commits.
- If uncertain about an implementation detail, leave a concrete `TODO("reason")` rather than a hidden guess.

## Engineering Principles

- **Performance**: Prioritize efficient algorithms and data structures. Avoid unnecessary allocations and copies.
- **Rust patterns**: Use idiomatic Rust constructs (enums, traits, iterators) for clarity and safety. Leverage type system to prevent invalid states.
- **KISS**: Simplest solution that works. Three similar lines beat a premature abstraction.
- **YAGNI**: Don't build for hypothetical future requirements -- solve the current problem.
- **DRY + Rule of Three**: Tolerate duplication until the third occurrence, then extract.
- **SRP**: Each module/struct has one reason to change. Split when responsibilities diverge.
- **Fail Fast**: Validate at boundaries, return errors early, don't silently swallow failures.
- **Secure by Default**: Sanitize external input, no PII in logs, prefer safe APIs.
- **Reversibility**: Prefer changes that are easy to undo. Small commits over monolithic ones.

## Project Overview

**netray-common** is a shared utility crate for the [netray.info](https://netray.info) service ecosystem. It provides cross-cutting concerns (IP extraction, error formatting, rate limiting, security headers) used by multiple backend services.

- **Author**: Lukas Pustina | **License**: MIT
- **MSRV**: 1.75

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
```

### Modules

| Module | Purpose |
|--------|---------|
| `ip_extract` | `IpExtractor` checks proxy headers (CF-Connecting-IP, X-Real-IP, X-Forwarded-For) only when the peer IP is in the trusted proxy CIDR list. Safe default: empty list ignores all headers. |
| `error` | `ApiError` trait + `into_error_response()` produces `{"error": {"code": "...", "message": "..."}}` JSON. Adds `Retry-After` header for rate-limited responses. |
| `rate_limit` | `check_keyed_cost` and `check_direct_cost` wrap governor's GCRA limiter. Emit `{prefix}_rate_limit_hits_total` metrics on rejection. |
| `security_headers` | `security_headers_layer()` returns an axum middleware closure. Sets CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy. Supports relaxed CSP for docs paths. |

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
