# Changelog

All notable changes to this project will be documented in this file.

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
