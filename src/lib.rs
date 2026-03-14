//! Shared utilities for the netray.info service ecosystem.
//!
//! This crate provides cross-cutting concerns used by multiple backend services:
//!
//! - [`ip_extract`] -- Extract real client IP from proxy headers with trusted-proxy CIDR matching.
//! - [`error`] -- Structured JSON error responses via the [`error::ApiError`] trait.
//! - [`rate_limit`] -- Keyed and global rate limiting wrappers around `governor`.
//! - [`security_headers`] -- Axum middleware for CSP, HSTS, and other security headers.
//!
//! # Example
//!
//! ```rust
//! use netray_common::ip_extract::IpExtractor;
//!
//! let extractor = IpExtractor::new(&["10.0.0.0/8".to_string()]).unwrap();
//! // extractor.extract(&headers, peer_addr) returns the real client IP
//! ```

pub mod error;
pub mod ip_extract;
pub mod ip_filter;
#[cfg(feature = "middleware")]
pub mod middleware;
pub mod rate_limit;
pub mod security_headers;
