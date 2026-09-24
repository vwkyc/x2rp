//! Per-resource client allowlists: a resource may admit only listed IPs and CIDR blocks.

use std::net::IpAddr;

use ipnet::IpNet;

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
        assert!(parse(&["not-an-ip".into()]).is_err());
    }
}
