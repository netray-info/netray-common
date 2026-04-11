# Changelog

All notable changes to this project will be documented in this file.

## 0.7.0 (2026-04-11)

### Added

- Add BackendClient and expand EcosystemConfig to 6 fields (b04e751)

## 0.6.0 (2026-04-10)

### Added

- Add network_role to IP enrichment (fa5f207)

## 0.5.4 (2026-04-09)

### Added

- Add build_error_response() for logging-free error responses (848c79c)

## 0.5.3 (2026-04-08)

### Changed

- Add telemetry self-announcement INFO log after subscriber initialization (telemetry.rs)
- Elevate EnrichmentClient failure logs from DEBUG to WARN with service/url fields (enrichment.rs)

## 0.5.2 (2026-04-08)

### Changed

- CI: allow CDLA-Permissive-2.0 license for webpki-roots (26ddbcf)
- CI: fix deprecated deny.toml keys for cargo-deny-action@v2 (04e013e)
- CI: fix --locked failures for library crate without committed Cargo.lock (cda16cd)
- CI: align workflows with netray.info workflow-rules spec (639ccf9)

## 0.5.1 (2026-04-08)

- Bump reqwest 0.12→0.13, opentelemetry 0.28→0.31, tracing-opentelemetry 0.29→0.32.

## 0.5.0 (2026-04-07)

- Add request_id propagation to EnrichmentClient via `X-Request-Id` header.
- Add Makefile for local testing and publishing.
- Fix clippy and rustfmt violations.

## 0.2.1 (2026-03-11)

- Pre-parse static security header values at construction time.
- Sanitize `extra_script_src` entries in CSP (reject entries with `;` or newlines).
- Fix `relaxed_csp_path_prefix` matching paths like `/docs-evil` as `/docs`.
- Log 4xx client errors at warn level.
- Remove redundant `Display` bound on `into_error_response`.
- Add `#[must_use]` on `IpExtractor::is_empty()`.
- Add README, CLAUDE.md, crate-level docs, CI workflow.

## 0.2.0 (2026-03-11)

- Made CIDR support unconditional; removed `cidr` feature flag.
- `ip_network` is now a required dependency.
- Bare IPs in trusted proxy lists are auto-promoted to /32 (IPv4) or /128 (IPv6).

## 0.1.0

- Initial release with `ip_extract`, `error`, `rate_limit`, and `security_headers` modules.
