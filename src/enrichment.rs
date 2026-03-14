//! IP enrichment client for the netray.info service ecosystem.
//!
//! Provides a shared client for fetching ASN, cloud provider, and threat-flag
//! metadata from an ifconfig-rs compatible API. Gates the `moka` TTL cache
//! behind the `enrichment-cache` feature flag.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use futures::stream::{FuturesUnordered, StreamExt};
use serde::{Deserialize, Serialize};

/// Cloud provider metadata from the enrichment API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema))]
pub struct CloudInfo {
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub service: Option<String>,
}

/// Metadata about a single IP address from the enrichment API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema))]
pub struct IpInfo {
    #[serde(default)]
    pub asn: Option<u32>,
    #[serde(default)]
    pub org: Option<String>,
    /// IP classification: "cloud", "datacenter", "residential", "vpn", etc.
    #[serde(default, rename = "type")]
    pub ip_type: Option<String>,
    #[serde(default)]
    pub cloud: Option<CloudInfo>,
    #[serde(default)]
    pub is_tor: bool,
    #[serde(default)]
    pub is_vpn: bool,
    #[serde(default)]
    pub is_datacenter: bool,
    #[serde(default)]
    pub is_spamhaus: bool,
    #[serde(default)]
    pub is_c2: bool,
}

/// Returns `true` for any IP address that should not be sent to the enrichment
/// API — private, reserved, or special-purpose ranges including CGNAT
/// (100.64.0.0/10).
///
/// Uses the unified [`crate::target_policy`] blocklist.
pub fn is_private_ip(ip: IpAddr) -> bool {
    !crate::target_policy::is_allowed_target(ip)
}

/// HTTP client for IP enrichment lookups against an ifconfig-rs compatible API.
///
/// Use the `enrichment-cache` feature to enable an in-memory TTL cache
/// (1024 entries, 300 s TTL) that avoids redundant lookups within a request
/// fan-out.
pub struct EnrichmentClient {
    client: reqwest::Client,
    base_url: String,
    metrics_label: Option<&'static str>,
    #[cfg(feature = "enrichment-cache")]
    cache: moka::future::Cache<IpAddr, Option<IpInfo>>,
}

impl EnrichmentClient {
    /// Returns the base URL of the enrichment API (without trailing slash).
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Create a new enrichment client.
    ///
    /// - `base_url` – ifconfig API base URL (e.g. `https://ip.netray.info`)
    /// - `timeout` – per-request HTTP timeout
    /// - `user_agent` – `User-Agent` header value sent to the enrichment API
    /// - `metrics_label` – when `Some`, emit Prometheus counters tagged with
    ///   `service = <label>`. Pass `None` to skip metrics.
    pub fn new(
        base_url: &str,
        timeout: Duration,
        user_agent: &'static str,
        metrics_label: Option<&'static str>,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent(user_agent)
            .pool_max_idle_per_host(5)
            .pool_idle_timeout(std::time::Duration::from_secs(90))
            .build()
            .expect("failed to build enrichment HTTP client");

        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_owned(),
            metrics_label,
            #[cfg(feature = "enrichment-cache")]
            cache: moka::future::Cache::builder()
                .max_capacity(1024)
                .time_to_live(Duration::from_secs(300))
                .build(),
        }
    }

    /// Probe reachability with a HEAD request and a 2-second timeout.
    ///
    /// Returns `true` if the service responds with an HTTP status below 500.
    /// Non-fatal: network errors and timeouts return `false`.
    pub async fn is_reachable(&self) -> bool {
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
        {
            Ok(c) => c,
            Err(_) => return false,
        };
        client
            .head(&self.base_url)
            .send()
            .await
            .map(|r| r.status().as_u16() < 500)
            .unwrap_or(false)
    }

    /// Look up metadata for a single IP.
    ///
    /// Returns `None` for private/blocked IPs (no request sent) and on any
    /// HTTP or parse error (non-fatal).
    pub async fn lookup(&self, ip: IpAddr) -> Option<IpInfo> {
        if is_private_ip(ip) {
            return None;
        }

        #[cfg(feature = "enrichment-cache")]
        if let Some(cached) = self.cache.get(&ip).await {
            if let Some(svc) = self.metrics_label {
                metrics::counter!("enrichment_cache_hits_total", "service" => svc).increment(1);
            }
            return cached;
        }

        if let Some(svc) = self.metrics_label {
            metrics::counter!("enrichment_requests_total", "service" => svc).increment(1);
        }

        let url = format!("{}/network/json?ip={}", self.base_url, ip);
        let result = match self.client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => resp.json::<IpInfo>().await.ok(),
            Ok(resp) => {
                tracing::debug!(ip = %ip, status = %resp.status(), "enrichment lookup failed");
                None
            }
            Err(e) => {
                tracing::debug!(ip = %ip, error = %e, "enrichment lookup error");
                None
            }
        };

        #[cfg(feature = "enrichment-cache")]
        self.cache.insert(ip, result.clone()).await;

        result
    }

    /// Look up metadata for multiple IPs concurrently.
    ///
    /// Deduplicates the input and silently skips private/blocked IPs.
    /// Returns only the IPs for which enrichment succeeded.
    pub async fn lookup_batch(&self, ips: &[IpAddr]) -> HashMap<IpAddr, IpInfo> {
        let mut seen = std::collections::HashSet::new();
        let futs: FuturesUnordered<_> = ips
            .iter()
            .copied()
            .filter(|ip| seen.insert(*ip))
            .map(|ip| async move { (ip, self.lookup(ip).await) })
            .collect();

        futs.filter_map(|(ip, info)| async move { info.map(|i| (ip, i)) })
            .collect()
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserializes_full_response() {
        let json = r#"{
            "type": "cloud",
            "asn": 16509,
            "org": "Amazon.com, Inc.",
            "cloud": { "provider": "AWS", "region": "us-east-1", "service": "EC2" },
            "is_tor": false, "is_vpn": false, "is_datacenter": true,
            "is_spamhaus": false, "is_c2": false
        }"#;
        let info: IpInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.asn, Some(16509));
        assert_eq!(info.ip_type.as_deref(), Some("cloud"));
        assert!(info.is_datacenter);
        assert!(!info.is_tor);
        let cloud = info.cloud.unwrap();
        assert_eq!(cloud.provider.as_deref(), Some("AWS"));
        assert_eq!(cloud.region.as_deref(), Some("us-east-1"));
    }

    #[test]
    fn deserializes_minimal_response() {
        let json = r#"{}"#;
        let info: IpInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.asn, None);
        assert_eq!(info.org, None);
        assert!(!info.is_tor);
    }

    #[test]
    fn lookup_skips_private_ips() {
        // is_blocked_ip covers all private ranges
        assert!(crate::ip_filter::is_blocked_ip("127.0.0.1".parse().unwrap()));
        assert!(crate::ip_filter::is_blocked_ip("10.0.0.1".parse().unwrap()));
        assert!(crate::ip_filter::is_blocked_ip("::1".parse().unwrap()));
        assert!(crate::ip_filter::is_blocked_ip("fc00::1".parse().unwrap()));
    }

    #[test]
    fn public_ips_not_blocked() {
        assert!(!crate::ip_filter::is_blocked_ip("8.8.8.8".parse().unwrap()));
        assert!(!crate::ip_filter::is_blocked_ip("1.1.1.1".parse().unwrap()));
        assert!(!crate::ip_filter::is_blocked_ip("2606:4700::1".parse().unwrap()));
    }

    #[test]
    fn is_private_ip_blocks_standard_ranges() {
        assert!(is_private_ip("127.0.0.1".parse().unwrap()));
        assert!(is_private_ip("10.0.0.1".parse().unwrap()));
        assert!(is_private_ip("192.168.1.1".parse().unwrap()));
        assert!(is_private_ip("172.16.0.1".parse().unwrap()));
        assert!(is_private_ip("::1".parse().unwrap()));
        assert!(is_private_ip("fc00::1".parse().unwrap()));
    }

    #[test]
    fn is_private_ip_blocks_cgnat() {
        assert!(is_private_ip("100.64.0.1".parse().unwrap()));
        assert!(is_private_ip("100.127.255.255".parse().unwrap()));
    }

    #[test]
    fn is_private_ip_allows_public() {
        assert!(!is_private_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_private_ip("1.1.1.1".parse().unwrap()));
        assert!(!is_private_ip("2606:4700::1".parse().unwrap()));
    }
}
