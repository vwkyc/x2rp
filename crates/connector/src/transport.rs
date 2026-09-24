//! What both relay transports share: where the server is, how to reach it, and
//! how to reach a backend.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpStream;

const BACKEND_CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

pub(crate) struct TransportConfig {
    /// `https://host[:port]`, already normalized.
    pub server: String,
    pub token: String,
    /// Hex-encoded 32-byte QUIC obfuscation secret.
    pub obfuscation_secret: String,
    /// Admin-set: skip QUIC entirely and use WSS only (restricted-network mode).
    pub force_wss: bool,
}

impl TransportConfig {
    /// Server host (IPv6 unbracketed, as SNI and the resolver want it) and port.
    pub fn host_port(&self) -> io::Result<(String, u16)> {
        host_port(&self.server)
    }
}

/// `host` and port (the scheme's default unless given) of an http(s) URL.
fn host_port(url: &str) -> io::Result<(String, u16)> {
    let url = reqwest::Url::parse(url)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{url}: {e}")))?;
    let host = url.host_str().unwrap_or_default().trim_matches(['[', ']']);
    let port = url.port_or_known_default().unwrap_or(443);
    Ok((host.to_string(), port))
}

/// Resolve the server and try each address in turn, returning the first that
/// connects or the last error.
pub(crate) async fn connect_any<T, F, Fut>(
    config: &TransportConfig,
    mut attempt: F,
) -> io::Result<T>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: Future<Output = io::Result<T>>,
{
    let (host, port) = config.host_port()?;
    let mut last_error = io::Error::other(format!("Could not resolve {host}"));
    for addr in tokio::net::lookup_host((host.as_str(), port)).await? {
        match attempt(addr).await {
            Ok(value) => return Ok(value),
            Err(err) => {
                tracing::debug!("Transport connect attempt to {addr} failed: {err}");
                last_error = err;
            }
        }
    }
    Err(last_error)
}

/// Resolve + SSRF-check + TCP-connect the backend a `Connect` names
/// (`http://host[:port]`) under one deadline.
pub(crate) async fn connect_backend(target: &str) -> io::Result<TcpStream> {
    let (host, port) = host_port(target)?;
    let connect = async {
        let resolved: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|e| io::Error::other(format!("failed to resolve {host}: {e}")))?
            .collect();
        let safe: Vec<SocketAddr> = resolved
            .iter()
            .copied()
            .filter(|addr| !x2rp_proto::ssrf::is_strictly_dangerous_ip(addr.ip()))
            .collect();
        if safe.is_empty() {
            let why = if resolved.is_empty() {
                "did not resolve to any address"
            } else {
                "resolved only to restricted addresses"
            };
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{host} {why}"),
            ));
        }
        TcpStream::connect(&safe[..]).await
    };
    let stream = tokio::time::timeout(BACKEND_CONNECT_TIMEOUT, connect)
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "backend connect to {target} timed out after {}s",
                    BACKEND_CONNECT_TIMEOUT.as_secs()
                ),
            )
        })??;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

#[cfg(test)]
mod tests {
    #[test]
    fn host_port_applies_scheme_defaults_and_unbrackets_ipv6() {
        for (url, host, port) in [
            ("https://x2rp.example.com", "x2rp.example.com", 443),
            ("https://x2rp.example.com:8443", "x2rp.example.com", 8443),
            ("http://192.168.1.10", "192.168.1.10", 80),
            ("https://[2001:db8::1]", "2001:db8::1", 443),
            ("http://[::1]:8080", "::1", 8080),
        ] {
            assert_eq!(
                super::host_port(url).unwrap(),
                (host.to_string(), port),
                "{url}"
            );
        }
    }
}
