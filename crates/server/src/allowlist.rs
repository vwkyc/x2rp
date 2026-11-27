//! Per-resource client allowlists: a resource may admit only listed IPs and CIDR blocks.

use std::net::IpAddr;

use ipnet::{IpNet, Ipv4Net};

/// Normalize IPv4-mapped IPv6 CIDRs (`::ffff:203.0.113.0/120` -> `203.0.113.0/24`)
/// so they match peer addresses canonicalized via `IpAddr::to_canonical`.
fn normalize_net(net: IpNet) -> IpNet {
    match net {
        IpNet::V6(v6) if v6.prefix_len() >= 96 => match v6.addr().to_ipv4_mapped() {
            Some(v4) => Ipv4Net::new(v4, v6.prefix_len() - 96).map_or(net, IpNet::V4),
            None => net,
        },
        _ => net,
    }
}

/// Parse allowlist entries: a CIDR (`203.0.113.0/24`) or a bare address. Blank
/// entries are skipped; anything else unparseable is an error.
pub fn parse(entries: &[String]) -> Result<Vec<IpNet>, String> {
    entries
        .iter()
        .map(|raw| raw.trim())
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            entry
                .parse::<IpNet>()
                .or_else(|_| entry.parse::<IpAddr>().map(IpNet::from))
                .map(normalize_net)
                .map_err(|_| format!("invalid client allowlist entry: {entry}"))
        })
        .collect()
}

/// An empty allowlist admits everyone. IPv4-mapped IPv6 peers match their IPv4 entries.
pub fn admits(allowlist: &[IpNet], client: IpAddr) -> bool {
    let client = client.to_canonical();
    allowlist.is_empty() || allowlist.iter().any(|net| net.contains(&client))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidrs_and_bare_addresses_admit_only_their_members() {
        let list = parse(&["203.0.113.0/24".into(), " 2001:db8::1 ".into(), "".into()]).unwrap();
        assert!(admits(&list, "203.0.113.9".parse().unwrap()));
        assert!(
            admits(&list, "::ffff:203.0.113.9".parse().unwrap()),
            "v4-mapped peer"
        );
        assert!(admits(&list, "2001:db8::1".parse().unwrap()));
        assert!(!admits(&list, "198.51.100.1".parse().unwrap()));
        assert!(
            admits(&[], "198.51.100.1".parse().unwrap()),
            "empty list admits all"
        );
        let mapped = parse(&["::ffff:198.51.100.0/120".into()]).unwrap();
        assert!(admits(&mapped, "198.51.100.7".parse().unwrap()));
        assert!(!admits(&mapped, "198.51.101.7".parse().unwrap()));
        assert!(parse(&["not-an-ip".into()]).is_err());
    }
}
