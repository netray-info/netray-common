# Changelog

All notable changes to this project will be documented in this file.

## 0.2.0 (2026-03-11)

- Made CIDR support unconditional; removed `cidr` feature flag.
- `ip_network` is now a required dependency.
- Bare IPs in trusted proxy lists are auto-promoted to /32 (IPv4) or /128 (IPv6).

## 0.1.0

- Initial release with `ip_extract`, `error`, `rate_limit`, and `security_headers` modules.
