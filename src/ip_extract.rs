use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use axum::http::HeaderMap;

/// A trusted proxy entry that can match against an IP address.
///
/// With the default features, only individual IP addresses are supported.
/// With the `cidr` feature enabled, CIDR ranges (e.g. `10.0.0.0/8`) are
/// also accepted.
#[derive(Debug, Clone)]
enum TrustedProxy {
    Exact(IpAddr),
    #[cfg(feature = "cidr")]
    Cidr(ip_network::IpNetwork),
}

impl TrustedProxy {
    fn contains(&self, ip: IpAddr) -> bool {
        match self {
            Self::Exact(addr) => *addr == ip,
            #[cfg(feature = "cidr")]
            Self::Cidr(net) => net.contains(ip),
        }
    }
}

/// Extracts the real client IP from proxy headers.
///
/// When deployed behind a reverse proxy (Cloudflare, nginx, Caddy), the direct
/// peer IP is the proxy, not the actual client. This extractor checks proxy headers
/// in priority order (CF-Connecting-IP, X-Real-IP, X-Forwarded-For) but only when
/// the peer IP is in the configured trusted proxy list.
///
/// **Safe default**: When `trusted_proxies` is empty, all proxy headers are ignored
/// and the peer address is returned directly. This prevents IP spoofing when no
/// proxy is configured.
#[derive(Debug)]
pub struct IpExtractor {
    trusted_proxies: Vec<TrustedProxy>,
}

impl IpExtractor {
    /// Create a new extractor from a list of trusted proxy strings.
    ///
    /// Without the `cidr` feature, returns an error if any entry contains `/`
    /// (looks like a CIDR range). With the `cidr` feature, CIDR ranges are
    /// accepted alongside individual IPs.
    ///
    /// Invalid IP strings (that are not valid CIDR when the feature is enabled)
    /// are skipped with a warning.
    pub fn new(trusted_proxy_strs: &[String]) -> Result<Self, String> {
        let mut proxies = Vec::with_capacity(trusted_proxy_strs.len());

        for s in trusted_proxy_strs {
            if s.contains('/') {
                #[cfg(not(feature = "cidr"))]
                {
                    return Err(format!(
                        "trusted_proxies entry {s:?} looks like a CIDR range \
                         -- only individual IP addresses are supported (enable the `cidr` feature for CIDR support)"
                    ));
                }
                #[cfg(feature = "cidr")]
                {
                    match s.parse::<ip_network::IpNetwork>() {
                        Ok(net) => proxies.push(TrustedProxy::Cidr(net)),
                        Err(_) => {
                            tracing::warn!(entry = %s, "trusted_proxies CIDR entry is not valid -- skipped");
                        }
                    }
                    continue;
                }
            }

            match IpAddr::from_str(s) {
                Ok(ip) => proxies.push(TrustedProxy::Exact(ip)),
                Err(_) => {
                    tracing::warn!(entry = %s, "trusted_proxies entry is not a valid IP address -- skipped");
                }
            }
        }

        Ok(Self {
            trusted_proxies: proxies,
        })
    }

    /// Returns true if no trusted proxies are configured.
    pub fn is_empty(&self) -> bool {
        self.trusted_proxies.is_empty()
    }

    /// Extract the real client IP from headers and peer address.
    ///
    /// Priority:
    /// 1. If no trusted proxies configured, return peer IP (safe default).
    /// 2. If peer IP is not trusted, return peer IP (untrusted source).
    /// 3. Try `CF-Connecting-IP` header (Cloudflare).
    /// 4. Try `X-Real-IP` header (nginx).
    /// 5. Try rightmost non-trusted IP in `X-Forwarded-For`.
    /// 6. Fall back to peer IP.
    pub fn extract(&self, headers: &HeaderMap, peer_addr: SocketAddr) -> IpAddr {
        if self.trusted_proxies.is_empty() {
            return peer_addr.ip();
        }

        if !self.is_trusted(peer_addr.ip()) {
            return peer_addr.ip();
        }

        self.extract_cf_connecting_ip(headers)
            .or_else(|| self.extract_x_real_ip(headers))
            .or_else(|| self.extract_x_forwarded_for(headers))
            .unwrap_or_else(|| peer_addr.ip())
    }

    fn is_trusted(&self, ip: IpAddr) -> bool {
        self.trusted_proxies.iter().any(|p| p.contains(ip))
    }

    fn extract_cf_connecting_ip(&self, headers: &HeaderMap) -> Option<IpAddr> {
        headers
            .get("cf-connecting-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| IpAddr::from_str(s.trim()).ok())
    }

    fn extract_x_real_ip(&self, headers: &HeaderMap) -> Option<IpAddr> {
        headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| IpAddr::from_str(s.trim()).ok())
    }

    /// Walk `X-Forwarded-For` right-to-left, returning the rightmost IP that is
    /// not in the trusted proxy set.
    fn extract_x_forwarded_for(&self, headers: &HeaderMap) -> Option<IpAddr> {
        let value = headers.get("x-forwarded-for")?.to_str().ok()?;
        value
            .rsplit(',')
            .filter_map(|s| IpAddr::from_str(s.trim()).ok())
            .find(|ip| !self.is_trusted(*ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn peer(addr: &str) -> SocketAddr {
        addr.parse().unwrap()
    }

    fn extractor(proxies: &[&str]) -> IpExtractor {
        IpExtractor::new(&proxies.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn no_proxies_returns_peer_ip() {
        let ext = extractor(&[]);
        let headers = HeaderMap::new();
        assert_eq!(
            ext.extract(&headers, peer("1.2.3.4:12345")),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn no_proxies_ignores_all_headers() {
        let ext = extractor(&[]);
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", HeaderValue::from_static("5.6.7.8"));
        headers.insert("x-real-ip", HeaderValue::from_static("9.10.11.12"));
        headers.insert("x-forwarded-for", HeaderValue::from_static("13.14.15.16"));

        assert_eq!(
            ext.extract(&headers, peer("1.2.3.4:12345")),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn untrusted_peer_returns_peer_ip() {
        let ext = extractor(&["10.0.0.1"]);
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", HeaderValue::from_static("5.6.7.8"));

        assert_eq!(
            ext.extract(&headers, peer("1.2.3.4:12345")),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn trusted_peer_uses_cf_connecting_ip() {
        let ext = extractor(&["10.0.0.1"]);
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", HeaderValue::from_static("203.0.114.50"));

        assert_eq!(
            ext.extract(&headers, peer("10.0.0.1:443")),
            "203.0.114.50".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn cf_connecting_ip_with_whitespace() {
        let ext = extractor(&["10.0.0.1"]);
        let mut headers = HeaderMap::new();
        headers.insert(
            "cf-connecting-ip",
            HeaderValue::from_static(" 203.0.114.50 "),
        );

        assert_eq!(
            ext.extract(&headers, peer("10.0.0.1:443")),
            "203.0.114.50".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn cf_connecting_ip_invalid_falls_through() {
        let ext = extractor(&["10.0.0.1"]);
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", HeaderValue::from_static("not-an-ip"));
        headers.insert("x-real-ip", HeaderValue::from_static("5.6.7.8"));

        assert_eq!(
            ext.extract(&headers, peer("10.0.0.1:443")),
            "5.6.7.8".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn trusted_peer_uses_x_real_ip() {
        let ext = extractor(&["10.0.0.1"]);
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", HeaderValue::from_static("5.6.7.8"));

        assert_eq!(
            ext.extract(&headers, peer("10.0.0.1:443")),
            "5.6.7.8".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn cf_connecting_ip_takes_priority_over_x_real_ip() {
        let ext = extractor(&["10.0.0.1"]);
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", HeaderValue::from_static("1.1.1.1"));
        headers.insert("x-real-ip", HeaderValue::from_static("2.2.2.2"));

        assert_eq!(
            ext.extract(&headers, peer("10.0.0.1:443")),
            "1.1.1.1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn x_forwarded_for_single_ip() {
        let ext = extractor(&["10.0.0.1"]);
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.114.50"));

        assert_eq!(
            ext.extract(&headers, peer("10.0.0.1:443")),
            "203.0.114.50".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn x_forwarded_for_rightmost_untrusted() {
        let ext = extractor(&["10.0.0.1", "10.0.0.2"]);
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("99.99.99.99, 5.6.7.8, 10.0.0.2"),
        );

        assert_eq!(
            ext.extract(&headers, peer("10.0.0.1:443")),
            "5.6.7.8".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn x_forwarded_for_all_trusted_returns_peer() {
        let ext = extractor(&["10.0.0.1", "10.0.0.2", "10.0.0.3"]);
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("10.0.0.3, 10.0.0.2"),
        );

        assert_eq!(
            ext.extract(&headers, peer("10.0.0.1:443")),
            "10.0.0.1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn x_forwarded_for_with_whitespace() {
        let ext = extractor(&["10.0.0.1"]);
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("  5.6.7.8 , 10.0.0.1 "),
        );

        assert_eq!(
            ext.extract(&headers, peer("10.0.0.1:443")),
            "5.6.7.8".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn x_forwarded_for_with_invalid_entries() {
        let ext = extractor(&["10.0.0.1"]);
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("5.6.7.8, garbage, not-ip"),
        );

        assert_eq!(
            ext.extract(&headers, peer("10.0.0.1:443")),
            "5.6.7.8".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn no_headers_returns_peer() {
        let ext = extractor(&["10.0.0.1"]);
        let headers = HeaderMap::new();

        assert_eq!(
            ext.extract(&headers, peer("10.0.0.1:443")),
            "10.0.0.1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn ipv6_peer_and_header() {
        let ext = extractor(&["::1"]);
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-real-ip",
            HeaderValue::from_static("2001:4860:4860::8888"),
        );

        assert_eq!(
            ext.extract(&headers, peer("[::1]:443")),
            "2001:4860:4860::8888".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn ipv6_in_x_forwarded_for() {
        let ext = extractor(&["::1"]);
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("2606:4700::1, ::1"),
        );

        assert_eq!(
            ext.extract(&headers, peer("[::1]:443")),
            "2606:4700::1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn invalid_proxy_strings_are_skipped() {
        let ext = IpExtractor::new(&[
            "10.0.0.1".to_string(),
            "not-an-ip".to_string(),
            "".to_string(),
            "10.0.0.2".to_string(),
        ])
        .unwrap();
        assert_eq!(ext.trusted_proxies.len(), 2);
    }

    #[cfg(not(feature = "cidr"))]
    #[test]
    fn cidr_entry_returns_error_without_feature() {
        let err =
            IpExtractor::new(&["10.0.0.1".to_string(), "10.0.0.0/8".to_string()]).unwrap_err();
        assert!(err.contains("CIDR"), "unexpected error: {err}");
    }

    #[cfg(not(feature = "cidr"))]
    #[test]
    fn ipv6_cidr_entry_returns_error_without_feature() {
        let err = IpExtractor::new(&["2001:db8::/32".to_string()]).unwrap_err();
        assert!(err.contains("CIDR"), "unexpected error: {err}");
    }

    #[cfg(feature = "cidr")]
    #[test]
    fn cidr_trusted_proxy_matches_subnet() {
        let ext = IpExtractor::new(&["10.0.0.0/8".to_string()]).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", HeaderValue::from_static("1.2.3.4"));

        assert_eq!(
            ext.extract(&headers, peer("10.0.0.5:443")),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
    }

    #[cfg(feature = "cidr")]
    #[test]
    fn cidr_xff_skips_trusted_ranges() {
        let ext = IpExtractor::new(&["10.0.0.0/8".to_string(), "172.16.0.0/12".to_string()])
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("8.8.8.8, 10.0.0.1, 172.16.0.1"),
        );

        assert_eq!(
            ext.extract(&headers, peer("172.16.0.1:443")),
            "8.8.8.8".parse::<IpAddr>().unwrap()
        );
    }

    #[cfg(feature = "cidr")]
    #[test]
    fn cidr_mixed_exact_and_range() {
        let ext =
            IpExtractor::new(&["10.0.0.0/8".to_string(), "192.168.1.1".to_string()]).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", HeaderValue::from_static("5.6.7.8"));

        // Exact match
        assert_eq!(
            ext.extract(&headers, peer("192.168.1.1:443")),
            "5.6.7.8".parse::<IpAddr>().unwrap()
        );
        // CIDR match
        assert_eq!(
            ext.extract(&headers, peer("10.99.99.99:443")),
            "5.6.7.8".parse::<IpAddr>().unwrap()
        );
    }
}
