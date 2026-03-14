//! Unified target IP validation — SSRF blocklist covering all special ranges.
//!
//! This module is the single authoritative source for deciding whether an IP
//! address is safe to contact as an outbound target. It covers every reserved
//! or special-purpose range:
//!
//! - Loopback (127.0.0.0/8, ::1)
//! - Unspecified (0.0.0.0, ::)
//! - RFC 1918 private (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
//! - Link-local (169.254.0.0/16, fe80::/10)
//! - CGNAT (100.64.0.0/10, RFC 6598)
//! - Multicast (224.0.0.0/4, ff00::/8)
//! - Broadcast (255.255.255.255)
//! - Documentation (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32)
//! - IPv6 ULA (fc00::/7)
//! - IPv6 deprecated site-local (fec0::/10)
//! - IPv4-mapped IPv6 (::ffff:x.x.x.x — delegates to IPv4 check)
//! - 6to4 (2002::/16 — checks embedded IPv4)
//! - NAT64 well-known prefix (64:ff9b::/96)

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Returns `true` if the IP address is a safe, publicly-routable target.
///
/// Returns `false` for any reserved, private, or special-purpose address
/// as listed in the module documentation.
pub fn is_allowed_target(ip: IpAddr) -> bool {
    !is_blocked_target(ip)
}

fn is_blocked_target(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_blocked_v4(v4);
            }
            is_blocked_v6(v6)
        }
    }
}

fn is_blocked_v4(v4: Ipv4Addr) -> bool {
    if v4.is_loopback() {
        return true;
    }
    if v4.is_unspecified() {
        return true;
    }
    if v4.is_multicast() {
        return true;
    }
    if v4.is_broadcast() {
        return true;
    }
    // RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    if v4.is_private() {
        return true;
    }
    // Link-local: 169.254.0.0/16
    if v4.is_link_local() {
        return true;
    }
    let o = v4.octets();
    // CGNAT: 100.64.0.0/10 (RFC 6598)
    if o[0] == 100 && (o[1] & 0xC0) == 64 {
        return true;
    }
    // Documentation: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (RFC 5737)
    if (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
    {
        return true;
    }
    false
}

fn is_blocked_v6(v6: Ipv6Addr) -> bool {
    if v6.is_loopback() {
        return true;
    }
    if v6.is_unspecified() {
        return true;
    }
    if v6.is_multicast() {
        return true;
    }
    let segs = v6.segments();
    // Link-local: fe80::/10
    if (segs[0] & 0xFFC0) == 0xFE80 {
        return true;
    }
    // ULA: fc00::/7
    if (segs[0] & 0xFE00) == 0xFC00 {
        return true;
    }
    // Deprecated site-local: fec0::/10
    if (segs[0] & 0xFFC0) == 0xFEC0 {
        return true;
    }
    // Documentation: 2001:db8::/32
    if segs[0] == 0x2001 && segs[1] == 0x0DB8 {
        return true;
    }
    // 6to4: 2002::/16 — check embedded IPv4
    if segs[0] == 0x2002 {
        let embedded = Ipv4Addr::new(
            (segs[1] >> 8) as u8,
            (segs[1] & 0xFF) as u8,
            (segs[2] >> 8) as u8,
            (segs[2] & 0xFF) as u8,
        );
        return is_blocked_v4(embedded);
    }
    // NAT64 well-known prefix: 64:ff9b::/96
    if segs[0] == 0x0064
        && segs[1] == 0xFF9B
        && segs[2] == 0
        && segs[3] == 0
        && segs[4] == 0
        && segs[5] == 0
    {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- loopback ----

    #[test]
    fn blocks_ipv4_loopback() {
        assert!(!is_allowed_target("127.0.0.1".parse().unwrap()));
        assert!(!is_allowed_target("127.255.255.255".parse().unwrap()));
    }

    #[test]
    fn blocks_ipv6_loopback() {
        assert!(!is_allowed_target("::1".parse().unwrap()));
    }

    // ---- unspecified ----

    #[test]
    fn blocks_ipv4_unspecified() {
        assert!(!is_allowed_target("0.0.0.0".parse().unwrap()));
    }

    #[test]
    fn blocks_ipv6_unspecified() {
        assert!(!is_allowed_target("::".parse().unwrap()));
    }

    // ---- RFC 1918 ----

    #[test]
    fn blocks_rfc1918() {
        assert!(!is_allowed_target("10.0.0.1".parse().unwrap()));
        assert!(!is_allowed_target("172.16.0.1".parse().unwrap()));
        assert!(!is_allowed_target("172.31.255.255".parse().unwrap()));
        assert!(!is_allowed_target("192.168.1.1".parse().unwrap()));
    }

    // ---- link-local ----

    #[test]
    fn blocks_link_local_ipv4() {
        assert!(!is_allowed_target("169.254.1.1".parse().unwrap()));
        assert!(!is_allowed_target("169.254.255.255".parse().unwrap()));
    }

    #[test]
    fn blocks_link_local_ipv6() {
        assert!(!is_allowed_target("fe80::1".parse().unwrap()));
        assert!(!is_allowed_target("febf::ffff".parse().unwrap()));
    }

    // ---- CGNAT ----

    #[test]
    fn blocks_cgnat() {
        assert!(!is_allowed_target("100.64.0.0".parse().unwrap()));
        assert!(!is_allowed_target("100.64.0.1".parse().unwrap()));
        assert!(!is_allowed_target("100.127.255.255".parse().unwrap()));
    }

    #[test]
    fn allows_100_outside_cgnat() {
        assert!(is_allowed_target("100.63.255.255".parse().unwrap()));
        assert!(is_allowed_target("100.128.0.0".parse().unwrap()));
    }

    // ---- multicast ----

    #[test]
    fn blocks_multicast_ipv4() {
        assert!(!is_allowed_target("224.0.0.1".parse().unwrap()));
        assert!(!is_allowed_target("239.255.255.255".parse().unwrap()));
    }

    #[test]
    fn blocks_multicast_ipv6() {
        assert!(!is_allowed_target("ff02::1".parse().unwrap()));
    }

    // ---- broadcast ----

    #[test]
    fn blocks_broadcast() {
        assert!(!is_allowed_target("255.255.255.255".parse().unwrap()));
    }

    // ---- documentation ----

    #[test]
    fn blocks_documentation_ipv4() {
        assert!(!is_allowed_target("192.0.2.1".parse().unwrap()));
        assert!(!is_allowed_target("198.51.100.1".parse().unwrap()));
        assert!(!is_allowed_target("203.0.113.1".parse().unwrap()));
    }

    #[test]
    fn blocks_documentation_ipv6() {
        assert!(!is_allowed_target("2001:db8::1".parse().unwrap()));
        assert!(!is_allowed_target(
            "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()
        ));
    }

    // ---- ULA ----

    #[test]
    fn blocks_ipv6_ula() {
        assert!(!is_allowed_target("fc00::1".parse().unwrap()));
        assert!(!is_allowed_target("fd00::1".parse().unwrap()));
    }

    // ---- deprecated site-local ----

    #[test]
    fn blocks_deprecated_site_local() {
        assert!(!is_allowed_target("fec0::1".parse().unwrap()));
        assert!(!is_allowed_target("feff::1".parse().unwrap()));
    }

    // ---- IPv4-mapped IPv6 ----

    #[test]
    fn blocks_ipv4_mapped_private() {
        assert!(!is_allowed_target("::ffff:10.0.0.1".parse().unwrap()));
        assert!(!is_allowed_target("::ffff:192.168.1.1".parse().unwrap()));
        assert!(!is_allowed_target("::ffff:127.0.0.1".parse().unwrap()));
        assert!(!is_allowed_target("::ffff:100.64.0.1".parse().unwrap()));
    }

    #[test]
    fn allows_ipv4_mapped_public() {
        assert!(is_allowed_target("::ffff:1.1.1.1".parse().unwrap()));
    }

    // ---- 6to4 ----

    #[test]
    fn blocks_6to4_private() {
        // 2002:c0a8:0101:: embeds 192.168.1.1
        assert!(!is_allowed_target("2002:c0a8:0101::".parse().unwrap()));
    }

    #[test]
    fn allows_6to4_public() {
        // 2002:0101:0101:: embeds 1.1.1.1
        assert!(is_allowed_target("2002:0101:0101::".parse().unwrap()));
    }

    // ---- NAT64 ----

    #[test]
    fn blocks_nat64() {
        assert!(!is_allowed_target("64:ff9b::".parse().unwrap()));
        assert!(!is_allowed_target("64:ff9b::1".parse().unwrap()));
    }

    // ---- public IPs allowed ----

    #[test]
    fn allows_public_ipv4() {
        assert!(is_allowed_target("1.1.1.1".parse().unwrap()));
        assert!(is_allowed_target("8.8.8.8".parse().unwrap()));
        assert!(is_allowed_target("9.9.9.9".parse().unwrap()));
    }

    #[test]
    fn allows_public_ipv6() {
        assert!(is_allowed_target("2001:4860:4860::8888".parse().unwrap()));
        assert!(is_allowed_target("2606:4700:4700::1111".parse().unwrap()));
    }
}
