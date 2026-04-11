//! IP enrichment client for the netray.info service ecosystem.
//!
//! Provides a shared client for fetching ASN, cloud provider, and threat-flag
//! metadata from an ifconfig-rs compatible API. When the `backend` feature is
//! enabled, delegates HTTP transport, concurrency limiting, caching, and metrics
//! to [`crate::backend::BackendClient`].

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
    /// ASN network role from ipverse/as-metadata (e.g. "Midsize Transit", "Access Provider").
    #[serde(default)]
    pub network_role: Option<String>,
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
/// When built with the `backend` feature, delegates transport to
/// [`crate::backend::BackendClient`] for semaphore-based concurrency limiting,
/// caching, and metrics. Otherwise uses a standalone `reqwest::Client` with
/// optional `moka` cache (behind `enrichment-cache`).
pub struct EnrichmentClient {
    #[cfg(feature = "backend")]
    backend: crate::backend::BackendClient,
    #[cfg(not(feature = "backend"))]
    client: reqwest::Client,
    base_url: String,
    #[cfg(not(feature = "backend"))]
    metrics_label: Option<&'static str>,
    #[cfg(all(feature = "enrichment-cache", not(feature = "backend")))]
    cache: moka::future::Cache<IpAddr, Option<IpInfo>>,
}

impl EnrichmentClient {
    /// Returns the base URL of the enrichment API (without trailing slash).
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Create a new enrichment client.
    ///
    /// - `base_url` -- ifconfig API base URL (e.g. `https://ip.netray.info`)
    /// - `timeout` -- per-request HTTP timeout
    /// - `user_agent` -- `User-Agent` header value sent to the enrichment API
    /// - `metrics_label` -- when `Some`, emit Prometheus counters tagged with
    ///   `service = <label>`. Pass `None` to skip metrics.
    pub fn new(
        base_url: &str,
        timeout: Duration,
        user_agent: &'static str,
        metrics_label: Option<&'static str>,
    ) -> Self {
        let trimmed = base_url.trim_end_matches('/').to_owned();

        #[cfg(feature = "backend")]
        {
            let config = crate::backend::BackendConfig {
                url: Some(trimmed.clone()),
                timeout_ms: timeout.as_millis() as u64,
                max_concurrent: 20,
                cache_ttl_secs: if cfg!(feature = "enrichment-cache") {
                    300
                } else {
                    0
                },
                cache_capacity: 1024,
            };
            let backend = crate::backend::BackendClient::new(
                &config,
                "ifconfig",
                metrics_label.unwrap_or(""),
            )
            .expect("BackendClient::new returned None with Some(url)");
            let _ = user_agent; // user_agent is baked into BackendClient's reqwest::Client
            Self {
                backend,
                base_url: trimmed,
            }
        }

        #[cfg(not(feature = "backend"))]
        {
            let client = reqwest::Client::builder()
                .timeout(timeout)
                .user_agent(user_agent)
                .pool_max_idle_per_host(5)
                .pool_idle_timeout(std::time::Duration::from_secs(90))
                .build()
                .expect("failed to build enrichment HTTP client");

            Self {
                client,
                base_url: trimmed,
                metrics_label,
                #[cfg(feature = "enrichment-cache")]
                cache: moka::future::Cache::builder()
                    .max_capacity(1024)
                    .time_to_live(Duration::from_secs(300))
                    .build(),
            }
        }
    }

    /// Probe reachability with a HEAD request and a 2-second timeout.
    ///
    /// Returns `true` if the service responds with an HTTP status below 500.
    /// Non-fatal: network errors and timeouts return `false`.
    pub async fn is_reachable(&self) -> bool {
        #[cfg(feature = "backend")]
        {
            self.backend
                .head("/")
                .await
                .map(|s| s.as_u16() < 500)
                .unwrap_or(false)
        }

        #[cfg(not(feature = "backend"))]
        {
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
    }

    /// Look up metadata for a single IP.
    ///
    /// Returns `None` for private/blocked IPs (no request sent) and on any
    /// HTTP or parse error (non-fatal).
    pub async fn lookup(&self, ip: IpAddr, request_id: Option<&str>) -> Option<IpInfo> {
        if is_private_ip(ip) {
            return None;
        }

        #[cfg(feature = "backend")]
        {
            let path = format!("/network/json?ip={}", ip);
            match self.backend.get(&path, request_id).await {
                Ok((_status, body)) => {
                    tracing::debug!(ip = %ip, service = "ifconfig", "enrichment lookup succeeded");
                    serde_json::from_slice::<IpInfo>(&body).ok()
                }
                Err(e) => {
                    tracing::warn!(ip = %ip, service = "ifconfig", error = %e, "enrichment lookup error");
                    None
                }
            }
        }

        #[cfg(not(feature = "backend"))]
        {
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
            let mut req = self.client.get(&url);
            if let Some(rid) = request_id {
                req = req.header("X-Request-Id", rid);
            }
            let result = match req.send().await {
                Ok(resp) if resp.status().is_success() => {
                    tracing::debug!(ip = %ip, service = "ifconfig", url = %url, "enrichment lookup succeeded");
                    resp.json::<IpInfo>().await.ok()
                }
                Ok(resp) => {
                    tracing::warn!(ip = %ip, service = "ifconfig", url = %url, status = %resp.status(), "enrichment lookup failed");
                    None
                }
                Err(e) => {
                    tracing::warn!(ip = %ip, service = "ifconfig", url = %url, error = %e, "enrichment lookup error");
                    None
                }
            };

            #[cfg(feature = "enrichment-cache")]
            self.cache.insert(ip, result.clone()).await;

            result
        }
    }

    /// Look up metadata for multiple IPs concurrently.
    ///
    /// Deduplicates the input and silently skips private/blocked IPs.
    /// Returns only the IPs for which enrichment succeeded.
    pub async fn lookup_batch(
        &self,
        ips: &[IpAddr],
        request_id: Option<&str>,
    ) -> HashMap<IpAddr, IpInfo> {
        let rid = request_id.map(|s| s.to_owned());
        let mut seen = std::collections::HashSet::new();
        let futs: FuturesUnordered<_> = ips
            .iter()
            .copied()
            .filter(|ip| seen.insert(*ip))
            .map(|ip| {
                let rid = rid.clone();
                async move { (ip, self.lookup(ip, rid.as_deref()).await) }
            })
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
        assert!(crate::ip_filter::is_blocked_ip(
            "127.0.0.1".parse().unwrap()
        ));
        assert!(crate::ip_filter::is_blocked_ip("10.0.0.1".parse().unwrap()));
        assert!(crate::ip_filter::is_blocked_ip("::1".parse().unwrap()));
        assert!(crate::ip_filter::is_blocked_ip("fc00::1".parse().unwrap()));
    }

    #[test]
    fn public_ips_not_blocked() {
        assert!(!crate::ip_filter::is_blocked_ip("8.8.8.8".parse().unwrap()));
        assert!(!crate::ip_filter::is_blocked_ip("1.1.1.1".parse().unwrap()));
        assert!(!crate::ip_filter::is_blocked_ip(
            "2606:4700::1".parse().unwrap()
        ));
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

    // T5: EnrichmentClient calls /network/json with X-Request-Id (backend feature)
    #[cfg(feature = "backend")]
    #[tokio::test]
    async fn lookup_calls_network_json_with_request_id() {
        use std::sync::Arc;

        let received = Arc::new(tokio::sync::Mutex::new((String::new(), String::new())));
        let recv = received.clone();

        let app = axum::Router::new().route(
            "/network/json",
            axum::routing::get(move |
                headers: axum::http::HeaderMap,
                axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
            | {
                let recv = recv.clone();
                async move {
                    let ip = params.get("ip").cloned().unwrap_or_default();
                    let rid = headers
                        .get("x-request-id")
                        .map(|v| v.to_str().unwrap().to_owned())
                        .unwrap_or_default();
                    *recv.lock().await = (ip, rid);
                    axum::Json(serde_json::json!({
                        "asn": 15169,
                        "org": "Google LLC",
                        "type": "cloud"
                    }))
                }
            }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.ok(); });

        let client = EnrichmentClient::new(
            &format!("http://{addr}"),
            Duration::from_secs(5),
            "test",
            None,
        );

        let result = client
            .lookup("8.8.8.8".parse().unwrap(), Some("req-abc-123"))
            .await;
        assert!(result.is_some(), "lookup should return Some for valid IP");

        let info = result.unwrap();
        assert_eq!(info.asn, Some(15169));
        assert_eq!(info.org.as_deref(), Some("Google LLC"));

        let (captured_ip, captured_rid) = &*received.lock().await;
        assert_eq!(captured_ip, "8.8.8.8", "should query for the requested IP");
        assert_eq!(captured_rid, "req-abc-123", "should propagate X-Request-Id");
    }
}
