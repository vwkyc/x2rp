//! Host-side helpers shared by the server and the connector.

use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::process::Command;

/// `systemctl status` for `service`. A stopped unit exits non-zero; that is an
/// answer, not an error.
pub fn cmd_status(service: &str) -> io::Result<()> {
    Command::new("systemctl")
        .args(["status", service, "--no-pager"])
        .status()
        .map(drop)
}

/// Follow `service`'s journal.
pub fn cmd_logs(service: &str) -> io::Result<()> {
    Command::new("journalctl")
        .args(["-fu", service, "--no-pager"])
        .status()
        .map(drop)
}

/// Cap secret file reads so a misconfigured symlink/FIFO/huge file cannot OOM the process.
const MAX_SECRET_FILE_BYTES: u64 = 1024 * 1024;

/// Encode bytes as lowercase hex.
pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Read a secret regular file owned by us with mode at most `max_mode`. Uses
/// `O_NOFOLLOW | O_NONBLOCK` so a misconfigured symlink or FIFO fails immediately
/// rather than blocking.
pub fn read_secret_file(path: &Path, max_mode: u32) -> io::Result<Vec<u8>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("secret path {} is not a regular file", path.display()),
        ));
    }
    if metadata.len() > MAX_SECRET_FILE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "secret file {} exceeds {MAX_SECRET_FILE_BYTES} bytes",
                path.display()
            ),
        ));
    }
    let mode = metadata.permissions().mode() & 0o777;
    // Owner must be the process euid: a world-unreadable file can still be another user's.
    let euid = unsafe { libc::geteuid() };
    if mode & !max_mode != 0 || metadata.uid() != euid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "secret file {} must be owned by uid {euid} with mode at most {max_mode:03o} (has uid {}, mode {mode:03o})",
                path.display(),
                metadata.uid()
            ),
        ));
    }
    let mut buf = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_SECRET_FILE_BYTES + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_SECRET_FILE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "secret file {} exceeds {MAX_SECRET_FILE_BYTES} bytes",
                path.display()
            ),
        ));
    }
    Ok(buf)
}

/// One DNS label: 1-63 ASCII alphanumerics or hyphens, not starting or ending with a hyphen.
pub fn is_valid_label(label: &str) -> bool {
    (1..=63).contains(&label.len())
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// A hostname: dot-separated valid DNS labels, at most 253 bytes.
pub fn is_valid_host(host: &str) -> bool {
    !host.is_empty() && host.len() <= 253 && host.split('.').all(is_valid_label)
}

/// A hostname with at least two labels.
pub fn is_valid_domain(domain: &str) -> bool {
    domain.contains('.') && is_valid_host(domain)
}

/// Reject non-canonical numeric IPv4 shorthands (decimal, hex, octal, 2/3-part)
/// that `Ipv4Addr` rejects but `getaddrinfo` may accept.
fn is_noncanonical_ipv4_shorthand(host: &str) -> bool {
    let mut parts = host.split('.');
    parts.clone().count() <= 4
        && parts.all(|p| {
            !p.is_empty()
                && p.strip_prefix("0x")
                    .or_else(|| p.strip_prefix("0X"))
                    .map_or_else(
                        || p.bytes().all(|b| b.is_ascii_digit()),
                        |h| !h.is_empty() && h.bytes().all(|b| b.is_ascii_hexdigit()),
                    )
        })
        && host.parse::<Ipv4Addr>().is_err()
}

/// Strict `http(s)://host[:port][/]` origin parser shared by server validation,
/// server proxying, and connector dialing.
///
/// Returns `(unbracketed_host, port, use_tls)`. Rejects userinfo, paths other than
/// `/` or empty, queries, fragments, control/whitespace chars, port 0, invalid IPv6
/// literals, and non-canonical numeric IPv4 shorthands.
pub fn parse_http_origin(raw: &str) -> Result<(&str, u16, bool), &'static str> {
    if raw
        .bytes()
        .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err("Invalid target URL");
    }
    let (scheme, rest) = raw.split_once("://").ok_or("Invalid scheme")?;
    let tls = if scheme.eq_ignore_ascii_case("http") {
        false
    } else if scheme.eq_ignore_ascii_case("https") {
        true
    } else {
        return Err("Invalid scheme");
    };
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    if authority.contains(['/', '?', '#']) {
        return Err("Target must not include a path or query");
    }
    if authority.contains('@') {
        return Err("Target must not include userinfo");
    }
    if authority.is_empty() {
        return Err("Missing host");
    }

    let parse_port = |port_str: &str| -> Result<u16, &'static str> {
        if port_str.is_empty() || !port_str.bytes().all(|b| b.is_ascii_digit()) {
            return Err("Invalid port");
        }
        let port: u16 = port_str.parse().map_err(|_| "Invalid port")?;
        if port == 0 {
            return Err("Invalid port");
        }
        Ok(port)
    };
    let default_port = if tls { 443 } else { 80 };

    let (host, port) = if let Some(after_open) = authority.strip_prefix('[') {
        let (inner, tail) = after_open.split_once(']').ok_or("Invalid host")?;
        inner.parse::<Ipv6Addr>().map_err(|_| "Invalid host")?;
        let port = match tail {
            "" => default_port,
            _ => parse_port(tail.strip_prefix(':').ok_or("Invalid port")?)?,
        };
        (inner, port)
    } else {
        let (host, port) = match authority.split_once(':') {
            Some((h, p)) => (h, parse_port(p)?),
            None => (authority, default_port),
        };
        if host.is_empty() || host.len() > 253 {
            return Err("Invalid host");
        }
        if host.parse::<IpAddr>().is_err()
            && (!is_valid_host(host) || is_noncanonical_ipv4_shorthand(host))
        {
            return Err("Invalid host");
        }
        (host, port)
    };

    Ok((host, port, tls))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_http_origin_validates_strictly() {
        for (url, host, port, tls) in [
            ("http://127.0.0.1:8080", "127.0.0.1", 8080, false),
            ("http://127.0.0.1/", "127.0.0.1", 80, false),
            ("HTTPS://example.com", "example.com", 443, true),
            ("https://[2001:db8::1]:8443", "2001:db8::1", 8443, true),
            ("http://[::1]", "::1", 80, false),
            ("http://nas:8080", "nas", 8080, false),
        ] {
            assert_eq!(parse_http_origin(url), Ok((host, port, tls)), "{url}");
        }
        for bad in [
            "ftp://127.0.0.1:21",
            "http://user@127.0.0.1:80",
            "http://127.0.0.1:80/path",
            "http://127.0.0.1:80?q=1",
            "http://127.0.0.1:0",
            "http://",
            "http://[not-ipv6]:80",
            "http://2852039166:80",
            "http://0xa9fea9fe:80",
            "http://0251.0376.0251.0376:80",
        ] {
            assert!(parse_http_origin(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn domains_are_dotted_hostnames() {
        assert!(is_valid_domain("example.com"));
        for bad in ["", "localhost", "-a.com", "a..com", "a_b.com", "a/b.com"] {
            assert!(!is_valid_domain(bad), "{bad}");
        }
    }
}
