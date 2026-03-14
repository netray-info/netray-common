use std::net::{IpAddr, Ipv4Addr};

/// Returns true if the IP address should be blocked for outbound requests
/// (SSRF prevention). Covers all address families and special ranges.
pub fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_v4(v4),
        IpAddr::V6(v6) => {
            // IPv4-mapped: ::ffff:x.x.x.x — delegate to IPv4 check
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
    // RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    if v4.is_private() {
        return true;
    }
    // Link-local: 169.254.0.0/16
    if v4.is_link_local() {
        return true;
    }
    // CGNAT: 100.64.0.0/10 (RFC 6598)
    let o = v4.octets();
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

fn is_blocked_v6(v6: std::net::Ipv6Addr) -> bool {
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
    use std::net::{Ipv4Addr, Ipv6Addr};

    // ---- loopback ----

    #[test]
    fn blocks_ipv4_loopback() {
        assert!(is_blocked_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(is_blocked_ip("127.0.0.1".parse().unwrap()));
        assert!(is_blocked_ip("127.255.255.255".parse().unwrap()));
    }

    #[test]
    fn blocks_ipv6_loopback() {
        assert!(is_blocked_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(is_blocked_ip("::1".parse().unwrap()));
    }

    // ---- unspecified ----

    #[test]
    fn blocks_ipv4_unspecified() {
        assert!(is_blocked_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert!(is_blocked_ip("0.0.0.0".parse().unwrap()));
    }

    #[test]
    fn blocks_ipv6_unspecified() {
        assert!(is_blocked_ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        assert!(is_blocked_ip("::".parse().unwrap()));
    }

    // ---- multicast ----

    #[test]
    fn blocks_ipv4_multicast() {
        assert!(is_blocked_ip("224.0.0.0".parse().unwrap()));
        assert!(is_blocked_ip("224.0.0.1".parse().unwrap()));
        assert!(is_blocked_ip("239.255.255.255".parse().unwrap()));
    }

    #[test]
    fn blocks_ipv6_multicast() {
        assert!(is_blocked_ip("ff02::1".parse().unwrap()));
        assert!(is_blocked_ip("ff00::".parse().unwrap()));
    }

    // ---- RFC 1918 ----

    #[test]
    fn blocks_rfc1918_10() {
        assert!(is_blocked_ip("10.0.0.0".parse().unwrap()));
        assert!(is_blocked_ip("10.0.0.1".parse().unwrap()));
        assert!(is_blocked_ip("10.255.255.255".parse().unwrap()));
    }

    #[test]
    fn blocks_rfc1918_172_16() {
        assert!(is_blocked_ip("172.16.0.0".parse().unwrap()));
        assert!(is_blocked_ip("172.16.0.1".parse().unwrap()));
        assert!(is_blocked_ip("172.31.255.255".parse().unwrap()));
    }

    #[test]
    fn blocks_rfc1918_192_168() {
        assert!(is_blocked_ip("192.168.0.0".parse().unwrap()));
        assert!(is_blocked_ip("192.168.1.1".parse().unwrap()));
        assert!(is_blocked_ip("192.168.255.255".parse().unwrap()));
    }

    // ---- link-local ----

    #[test]
    fn blocks_ipv4_link_local() {
        assert!(is_blocked_ip("169.254.0.0".parse().unwrap()));
        assert!(is_blocked_ip("169.254.1.1".parse().unwrap()));
        assert!(is_blocked_ip("169.254.255.255".parse().unwrap()));
    }

    #[test]
    fn blocks_ipv6_link_local() {
        assert!(is_blocked_ip("fe80::1".parse().unwrap()));
        assert!(is_blocked_ip("febf::ffff".parse().unwrap()));
    }

    // ---- CGNAT ----

    #[test]
    fn blocks_cgnat() {
        assert!(is_blocked_ip("100.64.0.0".parse().unwrap()));
        assert!(is_blocked_ip("100.64.0.1".parse().unwrap()));
        assert!(is_blocked_ip("100.127.255.255".parse().unwrap()));
    }

    #[test]
    fn allows_100_outside_cgnat() {
        assert!(!is_blocked_ip("100.63.255.255".parse().unwrap()));
        assert!(!is_blocked_ip("100.128.0.0".parse().unwrap()));
    }

    // ---- documentation ----

    #[test]
    fn blocks_documentation_ipv4() {
        assert!(is_blocked_ip("192.0.2.0".parse().unwrap()));
        assert!(is_blocked_ip("192.0.2.1".parse().unwrap()));
        assert!(is_blocked_ip("198.51.100.0".parse().unwrap()));
        assert!(is_blocked_ip("198.51.100.1".parse().unwrap()));
        assert!(is_blocked_ip("203.0.113.0".parse().unwrap()));
        assert!(is_blocked_ip("203.0.113.1".parse().unwrap()));
    }

    #[test]
    fn blocks_documentation_ipv6() {
        assert!(is_blocked_ip("2001:db8::1".parse().unwrap()));
        assert!(is_blocked_ip("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()));
    }

    // ---- ULA ----

    #[test]
    fn blocks_ipv6_ula() {
        assert!(is_blocked_ip("fc00::1".parse().unwrap()));
        assert!(is_blocked_ip("fd00::1".parse().unwrap()));
        assert!(is_blocked_ip("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()));
    }

    // ---- IPv4-mapped IPv6 ----

    #[test]
    fn blocks_ipv4_mapped_private() {
        assert!(is_blocked_ip("::ffff:10.0.0.1".parse().unwrap()));
        assert!(is_blocked_ip("::ffff:192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn blocks_ipv4_mapped_loopback() {
        assert!(is_blocked_ip("::ffff:127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn blocks_ipv4_mapped_cgnat() {
        assert!(is_blocked_ip("::ffff:100.64.0.1".parse().unwrap()));
    }

    #[test]
    fn allows_ipv4_mapped_public() {
        assert!(!is_blocked_ip("::ffff:1.1.1.1".parse().unwrap()));
    }

    // ---- 6to4 ----

    #[test]
    fn blocks_6to4_private() {
        // 2002:c0a8:0101:: embeds 192.168.1.1
        assert!(is_blocked_ip("2002:c0a8:0101::".parse().unwrap()));
    }

    #[test]
    fn blocks_6to4_loopback() {
        // 2002:7f00:0001:: embeds 127.0.0.1
        assert!(is_blocked_ip("2002:7f00:0001::".parse().unwrap()));
    }

    #[test]
    fn allows_6to4_public() {
        // 2002:0101:0101:: embeds 1.1.1.1
        assert!(!is_blocked_ip("2002:0101:0101::".parse().unwrap()));
    }

    // ---- NAT64 ----

    #[test]
    fn blocks_nat64_prefix() {
        assert!(is_blocked_ip("64:ff9b::".parse().unwrap()));
        assert!(is_blocked_ip("64:ff9b::1".parse().unwrap()));
        assert!(is_blocked_ip("64:ff9b::7f00:1".parse().unwrap()));
    }

    // ---- public IPs ----

    #[test]
    fn allows_public_ipv4() {
        assert!(!is_blocked_ip("1.1.1.1".parse().unwrap()));
        assert!(!is_blocked_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_blocked_ip("9.9.9.9".parse().unwrap()));
    }

    #[test]
    fn allows_public_ipv6() {
        assert!(!is_blocked_ip("2001:4860:4860::8888".parse().unwrap()));
        assert!(!is_blocked_ip("2606:4700:4700::1111".parse().unwrap()));
    }

    // ---- boundary tests ----

    #[test]
    fn boundary_172_rfc1918() {
        assert!(is_blocked_ip("172.31.255.255".parse().unwrap()));
        assert!(!is_blocked_ip("172.32.0.0".parse().unwrap()));
        assert!(!is_blocked_ip("172.15.255.255".parse().unwrap()));
    }

    #[test]
    fn boundary_loopback_v4() {
        assert!(is_blocked_ip("127.0.0.0".parse().unwrap()));
        assert!(!is_blocked_ip("126.255.255.255".parse().unwrap()));
        assert!(!is_blocked_ip("128.0.0.0".parse().unwrap()));
    }

    #[test]
    fn boundary_multicast_v4() {
        assert!(is_blocked_ip("224.0.0.0".parse().unwrap()));
        assert!(!is_blocked_ip("223.255.255.255".parse().unwrap()));
    }
}
