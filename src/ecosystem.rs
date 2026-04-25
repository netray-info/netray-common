//! Ecosystem service URL configuration shared across netray.info services.

use serde::{Deserialize, Serialize};

/// Public-facing URLs for the services in the netray.info ecosystem.
///
/// These URLs are served to browser frontends (via `/api/meta` or `/meta`)
/// for cross-tool navigation. They go through Traefik and are subject to
/// public rate limits. Fields set to `None` are omitted from serialization.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema))]
pub struct EcosystemConfig {
    /// Public base URL of the IP enrichment service (ip.netray.info).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_base_url: Option<String>,
    /// Public base URL of the DNS inspector service (dns.netray.info).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_base_url: Option<String>,
    /// Public base URL of the TLS inspector service (tls.netray.info).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_base_url: Option<String>,
    /// Public base URL of the HTTP inspector service (http.netray.info).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_base_url: Option<String>,
    /// Public base URL of the email inspector service (email.netray.info).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_base_url: Option<String>,
    /// Public base URL of the unified health checker (lens.netray.info).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lens_base_url: Option<String>,
}

impl EcosystemConfig {
    /// Returns `true` if at least one URL is configured.
    pub fn has_any(&self) -> bool {
        self.ip_base_url.is_some()
            || self.dns_base_url.is_some()
            || self.tls_base_url.is_some()
            || self.http_base_url.is_some()
            || self.email_base_url.is_some()
            || self.lens_base_url.is_some()
    }
}

// ---------------------------------------------------------------------------
// EcosystemMeta — canonical /api/meta response shape
// ---------------------------------------------------------------------------

/// Canonical `/api/meta` response shape returned by every netray.info service.
///
/// Hand-mirrored by `tests/acceptance/schemas/ecosystem-meta.schema.json`
/// in the meta repo; keep them in sync when this struct changes.
///
/// `site_name` is the canonical service identifier — the legacy `service`
/// key from beacon's old shape is removed. All fields are required: services
/// that do not orchestrate other services (i.e. anything other than lens)
/// shall populate `ecosystem` with empty strings rather than omitting the
/// object, so the response shape is uniform.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema))]
pub struct EcosystemMeta {
    /// Canonical service identifier, e.g. `"ifconfig-rs"`, `"beacon"`,
    /// `"lens"`. Replaces the legacy `service` field.
    pub site_name: String,
    /// Service binary version, e.g. `"0.5.1"`.
    pub version: String,
    /// URLs of sibling services. Populated by lens; other services use
    /// empty strings so the shape stays uniform.
    pub ecosystem: EcosystemUrls,
    /// Service-specific feature flags, e.g. `{"geoip": true}`. The contract
    /// is "present as an object"; key names are not constrained by the schema.
    pub features: serde_json::Map<String, serde_json::Value>,
    /// Service-specific limits, e.g. `{"max_targets": 10}`. Same contract
    /// as `features`.
    pub limits: serde_json::Map<String, serde_json::Value>,
    /// Summary of the rate-limit policy in effect for this service.
    pub rate_limit: RateLimitSummary,
}

/// Public URLs of sibling services in the netray.info ecosystem.
///
/// Differs from [`EcosystemConfig`] (which uses `Option<String>` for nav
/// configuration loaded from TOML) — every field is required and populated
/// with the empty string when not applicable. This keeps the wire shape
/// uniform across all six services, simplifying the acceptance schema.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema))]
pub struct EcosystemUrls {
    pub ip_base_url: String,
    pub dns_base_url: String,
    pub tls_base_url: String,
    pub http_base_url: String,
    pub email_base_url: String,
    pub lens_base_url: String,
}

impl From<&EcosystemConfig> for EcosystemUrls {
    fn from(c: &EcosystemConfig) -> Self {
        Self {
            ip_base_url: c.ip_base_url.clone().unwrap_or_default(),
            dns_base_url: c.dns_base_url.clone().unwrap_or_default(),
            tls_base_url: c.tls_base_url.clone().unwrap_or_default(),
            http_base_url: c.http_base_url.clone().unwrap_or_default(),
            email_base_url: c.email_base_url.clone().unwrap_or_default(),
            lens_base_url: c.lens_base_url.clone().unwrap_or_default(),
        }
    }
}

/// Compact summary of the rate-limit policy (per-IP and global).
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema))]
pub struct RateLimitSummary {
    pub per_ip_per_minute: u32,
    pub per_ip_burst: u32,
    pub global_per_minute: u32,
    pub global_burst: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meta_round_trips_with_uniform_shape() {
        let meta = EcosystemMeta {
            site_name: "ifconfig-rs".into(),
            version: "0.21.0".into(),
            ecosystem: EcosystemUrls::default(),
            features: serde_json::Map::new(),
            limits: serde_json::Map::new(),
            rate_limit: RateLimitSummary::default(),
        };
        let s = serde_json::to_string(&meta).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        // All required keys are present even when empty.
        for key in [
            "site_name",
            "version",
            "ecosystem",
            "features",
            "limits",
            "rate_limit",
        ] {
            assert!(v.get(key).is_some(), "missing key {key}");
        }
        // No `service` alias.
        assert!(v.get("service").is_none());
        // ecosystem object always has all six keys.
        let eco = v.get("ecosystem").and_then(|e| e.as_object()).unwrap();
        for key in [
            "ip_base_url",
            "dns_base_url",
            "tls_base_url",
            "http_base_url",
            "email_base_url",
            "lens_base_url",
        ] {
            assert!(eco.contains_key(key), "ecosystem missing {key}");
        }
    }

    #[test]
    fn ecosystem_urls_from_config() {
        let cfg = EcosystemConfig {
            ip_base_url: Some("https://ip.netray.info".into()),
            ..Default::default()
        };
        let urls = EcosystemUrls::from(&cfg);
        assert_eq!(urls.ip_base_url, "https://ip.netray.info");
        assert_eq!(urls.dns_base_url, ""); // unset -> empty string
    }
}
