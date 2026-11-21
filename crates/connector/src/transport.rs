//! What both relay transports share: where the server is, how to reach it, and
//! how to reach a backend.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const BACKEND_CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const SERVER_DNS_TIMEOUT: Duration = Duration::from_secs(10);
const SETTINGS_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_SETTINGS_RESPONSE_BYTES: usize = 16 * 1024;

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
        let (host, port, tls) = x2rp_proto::parse_http_origin(&self.server).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("{}: {e}", self.server))
        })?;
        if !tls {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "server must use https://",
            ));
        }
        Ok((host.to_string(), port))
    }
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
    let addrs = tokio::time::timeout(
        SERVER_DNS_TIMEOUT,
        tokio::net::lookup_host((host.as_str(), port)),
    )
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!("DNS lookup timed out for {host}"),
        )
    })??;
    let mut last_error = io::Error::other(format!("Could not resolve {host}"));
    for addr in addrs {
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

/// Minimal bounded HTTPS/1.1 GET (no redirects) for `/api/connector/settings`.
pub(crate) async fn https_get(
    config: &TransportConfig,
    path: &str,
    tls_config: &Arc<rustls::ClientConfig>,
) -> io::Result<(u16, Vec<u8>)> {
    let (host, port) = config.host_port()?;
    let server_name = rustls::pki_types::ServerName::try_from(host.clone()).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid SNI {host}: {e}"),
        )
    })?;
    let host_header = match (host.contains(':'), port) {
        (true, 443) => format!("[{host}]"),
        (true, p) => format!("[{host}]:{p}"),
        (false, 443) => host,
        (false, p) => format!("{host}:{p}"),
    };
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host_header}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
        config.token
    );
    let connector = tokio_rustls::TlsConnector::from(Arc::clone(tls_config));

    tokio::time::timeout(SETTINGS_TIMEOUT, async {
        let mut tls = connect_any(config, |addr| {
            let (connector, server_name) = (connector.clone(), server_name.clone());
            async move {
                // Per-address connect cap so a blackholed IPv6 falls back to IPv4 within SETTINGS_TIMEOUT.
                tokio::time::timeout(Duration::from_secs(2), async {
                    let tcp = TcpStream::connect(addr).await?;
                    let _ = tcp.set_nodelay(true);
                    connector.connect(server_name, tcp).await
                })
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "settings connect timed out")
                })?
            }
        })
        .await?;
        tls.write_all(request.as_bytes()).await?;
        tls.flush().await?;

        let mut raw = Vec::new();
        tls.take((MAX_SETTINGS_RESPONSE_BYTES + 1) as u64)
            .read_to_end(&mut raw)
            .await?;
        if raw.len() > MAX_SETTINGS_RESPONSE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "response too large",
            ));
        }
        parse_http1_response(&raw)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "settings request timed out"))?
}

fn bad_http(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn parse_http1_response(raw: &[u8]) -> io::Result<(u16, Vec<u8>)> {
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| bad_http("incomplete HTTP"))?;
    let head = std::str::from_utf8(&raw[..end]).map_err(|_| bad_http("invalid HTTP headers"))?;
    let mut lines = head.split("\r\n");
    let mut parts = lines.next().unwrap_or_default().split(' ');
    if !matches!(parts.next(), Some("HTTP/1.1" | "HTTP/1.0")) {
        return Err(bad_http("unsupported HTTP version"));
    }
    let status: u16 = parts
        .next()
        .unwrap_or_default()
        .parse()
        .map_err(|_| bad_http("bad HTTP status"))?;

    let (mut chunked, mut content_length) = (false, None);
    for (name, val) in lines.filter_map(|l| l.split_once(':')) {
        if name.eq_ignore_ascii_case("transfer-encoding")
            && val.to_ascii_lowercase().contains("chunked")
        {
            chunked = true;
        } else if name.eq_ignore_ascii_case("content-length") {
            content_length = val.trim().parse::<usize>().ok();
        }
    }

    let body = &raw[end + 4..];
    let decoded = if chunked {
        decode_chunked(body)?
    } else if let Some(len) = content_length {
        body.get(..len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "truncated body"))?
            .to_vec()
    } else {
        body.to_vec()
    };
    Ok((status, decoded))
}

fn decode_chunked(mut data: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let crlf = data
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| bad_http("bad chunk"))?;
        let hex = std::str::from_utf8(&data[..crlf])
            .map_err(|_| bad_http("bad chunk"))?
            .split(';')
            .next()
            .unwrap_or_default()
            .trim();
        let size = usize::from_str_radix(hex, 16).map_err(|_| bad_http("bad chunk size"))?;
        data = &data[crlf + 2..];
        if size == 0 {
            return Ok(out);
        }
        let end = size
            .checked_add(2)
            .ok_or_else(|| bad_http("chunk size overflow"))?;
        if data.get(size..end) != Some(b"\r\n") {
            return Err(bad_http("truncated chunk"));
        }
        out.extend_from_slice(&data[..size]);
        data = &data[end..];
    }
}

/// Resolve + SSRF-check + TCP-connect the backend a `Connect` names
/// (`http://host[:port]`) under one deadline. Rejects `https://` and non-origin URLs.
pub(crate) async fn connect_backend(target: &str) -> io::Result<TcpStream> {
    let (host, port, tls) = x2rp_proto::parse_http_origin(target)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{target}: {e}")))?;
    if tls {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{target}: connector targets must use http://"),
        ));
    }
    let connect = async {
        let resolved: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
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
    use super::*;

    #[test]
    fn parse_http1_handles_content_length_and_chunked() {
        assert_eq!(
            parse_http1_response(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n{\"ok\":true}")
                .unwrap(),
            (200, b"{\"ok\":true}".to_vec())
        );
        assert_eq!(
            parse_http1_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n").unwrap(),
            (200, b"hello world".to_vec())
        );
    }

    #[tokio::test]
    async fn connect_backend_rejects_https_targets() {
        assert_eq!(
            connect_backend("https://127.0.0.1:8443")
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
