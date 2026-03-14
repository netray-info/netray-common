//! Ecosystem service URL configuration shared across netray.info services.

/// URLs for the other services in the netray.info ecosystem.
///
/// Each service may expose a subset of these fields. Fields set to `None`
/// mean the corresponding integration is disabled.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct EcosystemConfig {
    /// Public base URL of the IP enrichment service (ip.netray.info).
    pub ip_url: Option<String>,
    /// Public base URL of the DNS inspector service (dns.netray.info).
    pub dns_url: Option<String>,
    /// Public base URL of the TLS inspector service (tls.netray.info).
    pub tls_url: Option<String>,
}
