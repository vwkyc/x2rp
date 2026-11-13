//! IP and SSRF validation helpers shared between server and connector.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Returns true for loopback targets on the server host, including IPv4-mapped forms.
/// Translated NAT64 addresses (e.g. `64:ff9b::7f00:1`) stay rejected.
pub fn is_local_direct_target_ip(ip: IpAddr) -> bool {
    ip.to_canonical().is_loopback()
}

/// Blocks link-local, unspecified/0/8, multicast/broadcast, local NAT64, and metadata IPs
/// even when private LAN targets are permitted.
pub fn is_strictly_dangerous_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.octets()[0] == 0 // 0.0.0.0/8
                || v4.is_link_local() // 169.254.0.0/16
                || v4.is_multicast() // 224.0.0.0/4
                || v4 == Ipv4Addr::BROADCAST
                || is_metadata_ip(IpAddr::V4(v4))
        }
        IpAddr::V6(v6) => {
            v6.is_unspecified()
                || v6.is_unicast_link_local() // fe80::/10
                || v6.is_multicast() // ff00::/8
                // Reject the RFC 8215 local-use NAT64 block (`64:ff9b:1::/48`) because prefix
                // boundaries vary per deployment.
                || v6.segments()[..3] == [0x0064, 0xff9b, 0x0001]
                || is_metadata_ip(IpAddr::V6(v6))
                || to_ipv4_synthesized(v6)
                    .is_some_and(|v4| is_strictly_dangerous_ip(IpAddr::V4(v4)))
        }
    }
}

/// Returns true if `ip` is a known cloud instance metadata or host-agent address.
pub fn is_metadata_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4 == Ipv4Addr::new(169, 254, 169, 254)
                || v4 == Ipv4Addr::new(100, 100, 100, 200)
                || v4 == Ipv4Addr::new(168, 63, 129, 16)
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            (s[0] == 0xfd00 && s[1] == 0x0ec2)
                || v6 == Ipv6Addr::new(0xfd20, 0x00ce, 0, 0, 0, 0, 0, 0x0254)
                || v6 == Ipv6Addr::new(0xfd00, 0x00c1, 0, 0, 0, 0, 0xa9fe, 0xa9fe)
                || to_ipv4_synthesized(v6).is_some_and(|v4| is_metadata_ip(IpAddr::V4(v4)))
                || any_local_nat64_v4(v6, |v4| is_metadata_ip(IpAddr::V4(v4)))
        }
    }
}

/// Decodes IPv4 addresses embedded via IPv4-mapped (`::ffff:0:0/96`) or well-known NAT64 (`64:ff9b::/96`).
fn to_ipv4_synthesized(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = v6.to_ipv4_mapped() {
        return Some(v4);
    }
    let s = v6.segments();
    (s[..6] == [0x0064, 0xff9b, 0, 0, 0, 0])
        .then(|| Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8))
}

/// Matches an IPv4 predicate against RFC 6052 `/48`, `/56`, `/64`, and `/96` layouts inside `64:ff9b:1::/48`.
fn any_local_nat64_v4(v6: Ipv6Addr, mut pred: impl FnMut(Ipv4Addr) -> bool) -> bool {
    let b = v6.octets();
    if b[..6] != [0x00, 0x64, 0xff, 0x9b, 0x00, 0x01] {
        return false;
    }
    pred(Ipv4Addr::new(b[12], b[13], b[14], b[15]))
        || (b[8] == 0
            && ((b[13..16] == [0; 3] && pred(Ipv4Addr::new(b[9], b[10], b[11], b[12])))
                || (b[12..16] == [0; 4] && pred(Ipv4Addr::new(b[7], b[9], b[10], b[11])))
                || (b[11..16] == [0; 5] && pred(Ipv4Addr::new(b[6], b[7], b[9], b[10])))))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test IP")
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
            "64:ff9b:1:7f00:0000:0100::",
            "::7f00:1",
        ] {
            assert!(!is_local_direct_target_ip(ip(bad)), "{bad}");
        }
    }

    #[test]
    fn strictly_dangerous_ip_blocks_link_local_metadata_and_multicast() {
        for bad in [
            "0.0.0.0",
            "0.0.0.1",
            "169.254.1.1",
            "fe80::1",
            "224.0.0.1",
            "255.255.255.255",
            "ff02::1",
            "fd00:ec2::254",
            "fd20:ce::254",
            "fd00:c1::a9fe:a9fe",
            "::ffff:0.0.0.1",
            "::ffff:169.254.169.254",
            "64:ff9b::0.0.0.1",
            "64:ff9b::a9fe:a9fe",
            "64:ff9b:1:a9fe:00a9:fe00::",
            "64:ff9b:1:6464:0064:c800::",
            "64:ff9b:1:fffe::a9fe:a9fe",
            "64:ff9b:1:0808:0008:0800::",
        ] {
            assert!(is_strictly_dangerous_ip(ip(bad)), "{bad}");
        }
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
    fn metadata_ip_detection_matches_expected_ranges() {
        for meta in [
            "169.254.169.254",
            "100.100.100.200",
            "168.63.129.16",
            "fd00:ec2::254",
            "fd00:ec2::1",
            "fd20:ce::254",
            "fd00:c1::a9fe:a9fe",
            "::ffff:169.254.169.254",
            "64:ff9b::a9fe:a9fe",
            "64:ff9b:1:fffe::a9fe:a9fe",
            "64:ff9b:1:1:00a9:fea9:fe00:0",
            "64:ff9b:1:00a9:00fe:a9fe::",
            "64:ff9b:1:a9fe:00a9:fe00::",
            "64:ff9b:1:6464:0064:c800::",
            "64:ff9b:1:a83f:0081:1000::",
        ] {
            assert!(is_metadata_ip(ip(meta)), "{meta}");
        }
        for ok in [
            "8.8.8.8",
            "2001:db8::1",
            "64:ff9b::0808:0808",
            "64:ff9b:1:0808:0008:0800::",
            "64:ff9b:1:fffe::0808:0808",
        ] {
            assert!(!is_metadata_ip(ip(ok)), "{ok}");
        }
    }
}
