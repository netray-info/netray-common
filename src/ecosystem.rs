//! Ecosystem service URL configuration shared across netray.info services.

/// Public-facing URLs for the services in the netray.info ecosystem.
///
/// These URLs are served to browser frontends (via `/api/meta` or `/meta`)
/// for cross-tool navigation. They go through Traefik and are subject to
/// public rate limits. Fields set to `None` are omitted from serialization.
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
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
