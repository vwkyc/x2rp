//! SSRF / IP safety guards shared between server and connectors.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Extract the embedded IPv4 from an IPv4-mapped (::ffff:0:0/96, RFC 4291) or
/// NAT64-synthesized (64:ff9b::/96, RFC 6052) IPv6 address. Both let an IPv4-blocked
/// target (e.g. cloud metadata) be re-encoded as an IPv6 literal to dodge the V4 checks.
fn to_ipv4_synthesized(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = v6.to_ipv4_mapped() {
        return Some(v4);
    }
    let s = v6.segments();
    (s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0)
        .then(|| Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8))
}

/// Check if an IP is a cloud metadata endpoint.
fn is_metadata_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4 == Ipv4Addr::new(169, 254, 169, 254) // AWS/GCP/Azure IMDS
                || v4 == Ipv4Addr::new(100, 100, 100, 200) // Alibaba Cloud metadata
                || v4 == Ipv4Addr::new(168, 63, 129, 16) // Azure WireServer / host agent
        }
        IpAddr::V6(v6) => {
            // AWS EC2 IPv6 IMDS ULA prefix fd00:ec2::/32 (host ::254 is the usual target).
            let s = v6.segments();
            s[0] == 0xfd00 && s[1] == 0x0ec2
        }
    }
}

/// Check if an IP is "strictly dangerous" (Metadata / Link-Local / Multicast).
///
/// Use this when private LAN IPs and loopback are allowed (e.g. connector targets) but
/// link-local, metadata, and multicast/broadcast addresses must still be blocked.
pub fn is_strictly_dangerous_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_link_local() // 169.254.0.0/16 (includes 169.254.169.254)
                || v4.is_unspecified() // 0.0.0.0
                || v4.is_multicast() // 224.0.0.0/4
                || v4 == Ipv4Addr::BROADCAST // 255.255.255.255
                || is_metadata_ip(IpAddr::V4(v4)) // Cloud metadata endpoints
        }
        IpAddr::V6(v6) => {
            v6.is_unspecified() // ::
                || v6.is_multicast() // ff00::/8
                || v6.is_unicast_link_local() // fe80::/10
                || is_metadata_ip(IpAddr::V6(v6)) // Cloud metadata endpoints
                || to_ipv4_synthesized(v6).is_some_and(|v4| is_strictly_dangerous_ip(IpAddr::V4(v4)))
        }
    }
}

/// True if `ip` is valid as a **direct (no-connector)** upstream on the x2rp host:
/// loopback, including its v4-mapped form. NAT64 (`64:ff9b::7f00:1`) is *not* loopback:
/// it routes to a translator. LAN/remote origins must use a connector.
pub fn is_local_direct_target_ip(ip: IpAddr) -> bool {
    ip.to_canonical().is_loopback()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test IP")
    }

    #[test]
    fn metadata_ip_detection_matches_expected_ranges() {
        for meta in [
            "169.254.169.254",
            "100.100.100.200",
            "168.63.129.16",
            "fd00:ec2::254",
            "fd00:ec2::1",
        ] {
            assert!(is_metadata_ip(ip(meta)), "{meta}");
        }
        assert!(!is_metadata_ip(ip("8.8.8.8")));
    }

    #[test]
    fn strictly_dangerous_ip_blocks_link_local_metadata_and_multicast() {
        // NAT64-synthesized (RFC 6052) metadata IP must not bypass the V4 check.
        for bad in [
            "169.254.1.1",
            "fe80::1",
            "fd00:ec2::254",
            "224.0.0.1",
            "255.255.255.255",
            "ff02::1",
            "64:ff9b::a9fe:a9fe",
        ] {
            assert!(is_strictly_dangerous_ip(ip(bad)), "{bad}");
        }
        // Loopback, public, and a NAT64-synthesized public address stay allowed.
        for ok in [
            "127.0.0.1",
            "::1",
            "1.1.1.1",
            "2606:4700:4700::1111",
            "64:ff9b::101:101",
        ] {
            assert!(!is_strictly_dangerous_ip(ip(ok)), "{ok}");
        }
    }

    #[test]
    fn local_direct_target_allows_loopback_only() {
        for ok in ["127.0.0.1", "127.0.0.2", "::1", "::ffff:127.0.0.1"] {
            assert!(is_local_direct_target_ip(ip(ok)), "{ok}");
        }
        for bad in [
            "10.0.0.1",
            "192.168.1.1",
            "1.1.1.1",
            "169.254.169.254",
            "64:ff9b::7f00:1",
        ] {
            assert!(!is_local_direct_target_ip(ip(bad)), "{bad}");
        }
    }
}
