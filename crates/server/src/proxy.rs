//! Pingora edge: routes each HTTPS request by `Host` to an origin on this host or
//! behind a relay connector.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, LazyLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use http::{StatusCode, header};
use ipnet::IpNet;
use parking_lot::RwLock;
use pingora_core::connectors::L4Connect;
use pingora_core::prelude::*;
use pingora_core::protocols::l4::virt::{VirtualSockOpt, VirtualSocket, VirtualSocketStream};
use pingora_core::protocols::l4::{socket::SocketAddr as L4Addr, stream::Stream};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{FailToProxy, ProxyHttp, Session};

use crate::connector_manager::{ConnectorManager, ConnectorRegistry};
use crate::rate_limit::{RateLimiter, client_key, is_auth_sensitive_path};
use crate::security_headers::append_standard_security_headers;

/// Shared with the create/update SSRF gate: same deadline to admit a resource as to route it.
pub const DNS_LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);
const DNS_CACHE_TTL: Duration = Duration::from_secs(60);

/// Port the admin API binds, and the one port no proxied origin may point at. The
/// bind, the `upstream_peer` guard and the create/update SSRF guard all read it, so
/// a change cannot leave one behind guarding someone else's origin.
pub const ADMIN_API_PORT: u16 = 8800;

/// Upstream of the admin console: x2rp's own admin API, not a proxied origin.
/// Pinned to [`ADMIN_API_PORT`] by `admin_api_target_matches_the_port`.
const ADMIN_API_TARGET: &str = "http://127.0.0.1:8800";

/// Subdomain of the admin vhost's resource. `_` is not a valid resource subdomain,
/// so no user resource can claim it.
const ADMIN_SUBDOMAIN: &str = "_admin";

/// Hostname from an HTTP `Host` header: strip the optional port, and the brackets
/// around an IPv6 literal (`[::1]:443` -> `::1`, `example.com:8080` -> `example.com`).
///
/// Deliberately does **not** trim. httparse leaves trailing OWS, so trimming would let
/// `Host: x2rp.example.com ` reach the admin vhost, and a routing decision must not be
/// reachable through a byte the client chose. A padded Host 404s instead.
pub fn host_header_hostname(raw: &str) -> &str {
    if let Some(rest) = raw.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(raw);
    }
    raw.split(':').next().unwrap_or(raw)
}

/// Parse an `http`/`https` target URL into (host, port, use_tls).
fn parse_target_url(target: &str) -> Option<(String, u16, bool)> {
    let uri = target.parse::<http::Uri>().ok()?;
    let tls = match uri.scheme_str()? {
        "https" => true,
        "http" => false,
        _ => return None,
    };
    let host = uri.host()?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
    Some((host.to_string(), port, tls))
}

fn default_fail_status_code(e: &Error) -> u16 {
    match e.etype() {
        ErrorType::HTTPStatus(code) => *code,
        _ => match e.esource() {
            ErrorSource::Upstream => StatusCode::BAD_GATEWAY.as_u16(),
            ErrorSource::Downstream => match e.etype() {
                ErrorType::WriteError | ErrorType::ReadError | ErrorType::ConnectionClosed => 0,
                _ => StatusCode::BAD_REQUEST.as_u16(),
            },
            ErrorSource::Internal | ErrorSource::Unset => {
                StatusCode::INTERNAL_SERVER_ERROR.as_u16()
            }
        },
    }
}

/// `client METHOD host/target` for a log line, formatted only if the line is emitted.
struct RequestLine<'a>(&'a Session, &'a str);

impl std::fmt::Display for RequestLine<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let req = self.0.req_header();
        let host = req
            .headers
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("-");
        let target = req
            .uri
            .path_and_query()
            .map_or(req.uri.path(), http::uri::PathAndQuery::as_str);
        write!(f, "{} {} {host}{target}", self.1, req.method)
    }
}

/// The client's `X-Request-Id` if it is short and plain (`[A-Za-z0-9_-]`, at most
/// 128 bytes), so a caller can trace its own request; otherwise a fresh one. The
/// charset keeps a client-chosen value from forging log lines or response headers.
fn request_id_from_headers(headers: &http::HeaderMap) -> String {
    headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| {
            (1..=128).contains(&v.len())
                && v.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
        .map_or_else(crate::api::random_hex::<8>, str::to_string)
}

/// Edge-generated error: plain text naming the status, e.g. `403 Forbidden`.
async fn send_error_response(
    session: &mut Session,
    request_id: &str,
    status: StatusCode,
) -> Result<bool> {
    let body = Bytes::from(status.to_string());
    let mut resp = ResponseHeader::build(status, None)?;
    resp.insert_header(header::CONTENT_TYPE, "text/plain; charset=utf-8")?;
    resp.insert_header(header::CONTENT_LENGTH, body.len().to_string())?;
    resp.insert_header(header::CONNECTION, "close")?;
    resp.insert_header(header::CACHE_CONTROL, "no-store")?;
    resp.insert_header("X-Request-Id", request_id)?;
    if status == StatusCode::TOO_MANY_REQUESTS {
        resp.insert_header(header::RETRY_AFTER, "60")?;
    }
    append_standard_security_headers(&mut resp);
    session.write_response_header(Box::new(resp), false).await?;
    session.write_response_body(Some(body), true).await?;
    Ok(true)
}

/// A v4-mapped v6 peer must reduce to its v4 form, or the same client keys a
/// different rate-limit entry, and misses its v4 allowlist entries, depending on
/// which stack it arrived on.
fn client_ip_from_peer(addr: Option<&SocketAddr>) -> String {
    addr.map(|a| a.ip().to_canonical().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Relay pipe buffer per direction, about a loopback socket's.
const RELAY_PIPE_BYTES: usize = 64 * 1024;

/// Relay upstream. Each connection Pingora opens is an in-memory pipe (no syscalls
/// or fds, unlike a socketpair) whose far end the connector manager turns into one
/// tunnel.
struct RelayConnect {
    manager: Arc<ConnectorManager>,
    target: String,
}

impl std::fmt::Debug for RelayConnect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "relay to {}", self.target)
    }
}

#[async_trait]
impl L4Connect for RelayConnect {
    async fn connect(&self, _addr: &L4Addr) -> Result<Stream> {
        let (ours, theirs) = tokio::io::duplex(RELAY_PIPE_BYTES);
        self.manager
            .bridge(&self.target, theirs)
            .map_err(|e| Error::explain(ErrorType::ConnectRefused, e))?;
        Ok(VirtualSocketStream::new(Box::new(RelayPipe(ours))).into())
    }
}

/// Pingora's end of the pipe. A local type, because `VirtualSocket` is pingora's
/// trait and `DuplexStream` tokio's.
#[derive(Debug)]
struct RelayPipe(tokio::io::DuplexStream);

impl VirtualSocket for RelayPipe {
    /// No socket underneath, so nothing to tune.
    fn set_socket_option(&self, _: VirtualSockOpt) -> std::io::Result<()> {
        Ok(())
    }
}

impl tokio::io::AsyncRead for RelayPipe {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for RelayPipe {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

/// Proxy configuration for a single resource
#[derive(Debug)]
pub struct ProxyResource {
    pub subdomain: String,
    pub target: String,
    /// Reached through this relay connector; `None` proxies to an origin on this host.
    pub connector_id: Option<String>,
    /// Client allowlist; empty admits everyone. `None` when the stored entries no
    /// longer parse, which admits no one.
    pub allowed_clients: Option<Vec<IpNet>>,
}

impl ProxyResource {
    /// Runtime view of a persisted resource, shared by the boot-time load and the
    /// live create/update path so a new field cannot be set on one and forgotten on
    /// the other.
    pub fn from_resource(resource: &crate::api::Resource) -> Self {
        let allowed_clients = crate::allowlist::parse(&resource.allowed_client_cidrs)
            .inspect_err(|e| {
                tracing::error!("Resource {}: {e}; denying every client", resource.subdomain);
            })
            .ok();
        Self {
            subdomain: resource.subdomain.clone(),
            target: resource.target.clone(),
            connector_id: resource.connector_id.clone(),
            allowed_clients,
        }
    }

    fn is_admin(&self) -> bool {
        self.subdomain == ADMIN_SUBDOMAIN
    }
}

/// Shared proxy context
pub struct ProxyContext {
    resources: RwLock<HashMap<String, Arc<ProxyResource>>>,
    /// Keyed by resource origins only, so it stays as small as the route table.
    dns_cache: DashMap<String, (Instant, Vec<SocketAddr>)>,
    domain: String,
    rate_limiter: RateLimiter,
    pub connectors: Arc<ConnectorRegistry>,
}

impl ProxyContext {
    pub fn new(domain: &str, connectors: Arc<ConnectorRegistry>) -> Self {
        Self {
            resources: RwLock::default(),
            dns_cache: DashMap::new(),
            domain: crate::api::normalize_domain(domain),
            rate_limiter: RateLimiter::default(),
            connectors,
        }
    }

    fn fqdn(&self, subdomain: &str) -> String {
        format!("{subdomain}.{}", self.domain).to_lowercase()
    }

    pub fn set_resource(&self, resource: ProxyResource) {
        let fqdn = self.fqdn(&resource.subdomain);
        self.resources.write().insert(fqdn, Arc::new(resource));
    }

    pub fn remove_resource(&self, subdomain: &str) {
        self.resources.write().remove(&self.fqdn(subdomain));
    }

    /// Keep cache and limiter state bounded even when traffic goes idle.
    /// Driven every minute by `main`.
    pub fn maintenance_tick(&self) {
        self.dns_cache
            .retain(|_, (created, _)| created.elapsed() < DNS_CACHE_TTL);
        self.rate_limiter.cleanup_stale();
    }

    /// First address of `host` that `allowed` admits. Names are cached briefly, and
    /// every use re-checks the address, so DNS rebinding cannot slip one past.
    async fn resolve_host(
        &self,
        host: &str,
        port: u16,
        allowed: impl Fn(IpAddr) -> bool,
    ) -> Option<SocketAddr> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return allowed(ip).then(|| SocketAddr::new(ip, port));
        }
        let key = format!("{host}:{port}");
        let cached = self
            .dns_cache
            .get(&key)
            .filter(|entry| entry.0.elapsed() < DNS_CACHE_TTL)
            .map(|entry| entry.1.clone());
        let addrs = match cached {
            Some(addrs) => addrs,
            None => {
                let lookup = tokio::net::lookup_host(key.as_str());
                let addrs: Vec<SocketAddr> = tokio::time::timeout(DNS_LOOKUP_TIMEOUT, lookup)
                    .await
                    .ok()?
                    .ok()?
                    .collect();
                self.dns_cache.insert(key, (Instant::now(), addrs.clone()));
                addrs
            }
        };
        addrs.into_iter().find(|addr| allowed(addr.ip()))
    }
}

/// Per-request context
#[derive(Default)]
pub struct RequestCtx {
    resource: Option<Arc<ProxyResource>>,
    client_ip: String,
    /// Set first in `request_filter`; the same ID tags every log line and response
    /// this request produces.
    request_id: String,
    /// Relay resources only: the connector tunnel, resolved in `request_filter`.
    relay: Option<Arc<RelayConnect>>,
}

/// The HTTPS edge, registered with Pingora on :443.
pub struct Gateway {
    ctx: Arc<ProxyContext>,
}

impl Gateway {
    pub fn new(ctx: Arc<ProxyContext>) -> Self {
        Self { ctx }
    }
}

#[async_trait]
impl ProxyHttp for Gateway {
    type CTX = RequestCtx;

    fn new_ctx(&self) -> Self::CTX {
        RequestCtx::default()
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        ctx.request_id = request_id_from_headers(&session.req_header().headers);
        ctx.client_ip = client_ip_from_peer(session.client_addr().and_then(|a| a.as_inet()));

        let host = session
            .req_header()
            .headers
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .map(host_header_hostname)
            .unwrap_or_default()
            .to_ascii_lowercase();
        // Only x2rp.<domain> is the admin console; the apex is not.
        let is_admin_host = host.strip_prefix("x2rp.") == Some(self.ctx.domain.as_str());

        // Admin login draws the strict tier; everything else the media-friendly one.
        // Keyed per IPv6 /64, or rotating the interface ID would reset the budget.
        let limiter = &self.ctx.rate_limiter;
        let tier = if is_admin_host && is_auth_sensitive_path(session.req_header().uri.path()) {
            &limiter.auth
        } else {
            &limiter.general
        };
        if !tier.check(&client_key(&ctx.client_ip)) {
            tracing::warn!(
                "Rate limit exceeded: {} [req:{}]",
                RequestLine(session, &ctx.client_ip),
                ctx.request_id
            );
            return send_error_response(session, &ctx.request_id, StatusCode::TOO_MANY_REQUESTS)
                .await;
        }

        let resource = if is_admin_host {
            static ADMIN: LazyLock<Arc<ProxyResource>> = LazyLock::new(|| {
                Arc::new(ProxyResource {
                    subdomain: ADMIN_SUBDOMAIN.to_string(),
                    target: ADMIN_API_TARGET.to_string(),
                    connector_id: None,
                    allowed_clients: Some(Vec::new()),
                })
            });
            Arc::clone(&ADMIN)
        } else {
            let Some(resource) = self.ctx.resources.read().get(&host).cloned() else {
                return send_error_response(session, &ctx.request_id, StatusCode::NOT_FOUND).await;
            };
            resource
        };

        // `None` is a stored allowlist that no longer parses: fail closed.
        let admitted = resource.allowed_clients.as_deref().is_some_and(|nets| {
            ctx.client_ip
                .parse()
                .is_ok_and(|ip| crate::allowlist::admits(nets, ip))
        });
        if !admitted {
            tracing::warn!(
                "Client not on allowlist: {} [req:{}]",
                RequestLine(session, &ctx.client_ip),
                ctx.request_id
            );
            return send_error_response(session, &ctx.request_id, StatusCode::FORBIDDEN).await;
        }

        if let Some(connector_id) = &resource.connector_id {
            let Some(manager) = self.ctx.connectors.get(connector_id) else {
                tracing::warn!(
                    "Connector {connector_id} offline for {host} [req:{}]",
                    ctx.request_id
                );
                return send_error_response(
                    session,
                    &ctx.request_id,
                    StatusCode::SERVICE_UNAVAILABLE,
                )
                .await;
            };
            ctx.relay = Some(Arc::new(RelayConnect {
                manager,
                target: resource.target.clone(),
            }));
        }

        ctx.resource = Some(resource);
        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let resource = ctx
            .resource
            .as_ref()
            .ok_or_else(|| Error::new(ErrorType::InternalError))?;

        if let Some(relay) = &ctx.relay {
            // The path is never dialed (`custom_l4` connects); it only keys the pool.
            let path = format!("/x2rp-relay/{}", resource.subdomain);
            let mut peer = HttpPeer::new_uds(&path, false, String::new())?;
            peer.options.custom_l4 = Some(relay.clone());
            return Ok(Box::new(peer));
        }

        let Some((host, port, tls)) = parse_target_url(&resource.target) else {
            tracing::error!("Invalid target URL: {}", resource.target);
            return Err(Error::new(ErrorType::ConnectError));
        };

        // No connector: a same-host origin, and never the local admin API (control plane).
        let is_admin = resource.is_admin();
        if !is_admin && port == ADMIN_API_PORT {
            tracing::warn!(
                "Block origin to admin API port {} for resource {}",
                ADMIN_API_PORT,
                resource.subdomain
            );
            return Err(Error::new(ErrorType::ConnectError));
        }

        // DNS-rebinding / SSRF guard: resolve and validate the target IP.
        let peer_addr = self
            .ctx
            .resolve_host(&host, port, x2rp_proto::ssrf::is_local_direct_target_ip)
            .await
            .ok_or_else(|| {
                tracing::warn!("Block DNS/SSRF: {host} resolves to no allowed IP");
                Error::new(ErrorType::ConnectError)
            })?;

        tracing::debug!(
            "Connecting to upstream: {} ({}) (TLS: {})",
            host,
            peer_addr,
            tls
        );

        let mut peer = HttpPeer::new(peer_addr, tls, host);
        peer.options.connection_timeout = Some(Duration::from_secs(10));
        peer.options.read_timeout = Some(Duration::from_secs(300));
        peer.options.write_timeout = Some(Duration::from_secs(300));
        peer.options.tcp_keepalive = Some(pingora_core::protocols::TcpKeepalive {
            idle: Duration::from_secs(60),
            interval: Duration::from_secs(15),
            count: 4,
            user_timeout: Duration::from_secs(75),
        });

        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // Replace whatever the client sent: origins trust these to name the real peer.
        upstream_request.remove_header("Forwarded");
        upstream_request.insert_header("X-Forwarded-For", &ctx.client_ip)?;
        upstream_request.insert_header("X-Real-IP", &ctx.client_ip)?;
        // Always "https": Gateway is only registered on the TLS listener ([::]:443). Port 80 traffic is handled by run_http_redirect and never reaches this path.
        upstream_request.insert_header("X-Forwarded-Proto", "https")?;
        // Origins build absolute URLs (redirects, reset links) from this. Every request
        // here was routed by its Host, so that Host is the one to forward.
        if let Some(host) = upstream_request.headers.get(header::HOST).cloned() {
            upstream_request.insert_header("X-Forwarded-Host", host)?;
        }

        // One tunnel per request: pooled, an idle one would hold a connector stream
        // slot, so have the origin close it after this response. Upgrades
        // (WebSocket) keep their own `Connection`.
        let is_upgrade = upstream_request.headers.contains_key(header::UPGRADE);
        if ctx.relay.is_some() && !is_upgrade {
            upstream_request.insert_header(header::CONNECTION, "close")?;
        }

        Ok(())
    }

    async fn upstream_response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        append_standard_security_headers(upstream_response);
        upstream_response.insert_header("X-Request-Id", &ctx.request_id)?;
        Ok(())
    }

    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &Error,
        ctx: &mut Self::CTX,
    ) -> FailToProxy {
        let code = default_fail_status_code(e);
        if code > 0 {
            let status = StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            if let Err(err) = send_error_response(session, &ctx.request_id, status).await {
                tracing::error!("Failed to send {code} response downstream: {err}");
            }
        }
        FailToProxy {
            error_code: code,
            can_reuse_downstream: false,
        }
    }

    async fn logging(&self, session: &mut Session, e: Option<&Error>, ctx: &mut Self::CTX) {
        let status = session.response_written().map_or(0, |r| r.status.as_u16());
        let line = RequestLine(session, &ctx.client_ip);
        let id = &ctx.request_id;
        match e {
            // Client hang-up mid-response is routine (browser abort, Range seek).
            Some(error)
                if matches!(
                    error.etype(),
                    ErrorType::ReadError | ErrorType::WriteError | ErrorType::ConnectionClosed
                ) && matches!(
                    error.esource(),
                    ErrorSource::Downstream | ErrorSource::Unset
                ) =>
            {
                tracing::debug!("{line} {status} - client aborted: {error} [req:{id}]")
            }
            Some(error) => tracing::error!("{line} {status} - ERROR: {error} [req:{id}]"),
            None if status >= 500 => tracing::error!("{line} {status} [req:{id}]"),
            // 4xx is enforcement, already logged where it was decided.
            None if status >= 400 => tracing::debug!("{line} {status} [req:{id}]"),
            None => tracing::info!("{line} {status} [req:{id}]"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use x2rp_proto::Message;

    /// The guards read `ADMIN_API_PORT`; the admin vhost dials `ADMIN_API_TARGET`.
    /// A const string cannot interpolate, so pin the two here.
    #[test]
    fn admin_api_target_matches_the_port() {
        assert_eq!(
            parse_target_url(ADMIN_API_TARGET).map(|(_, port, _)| port),
            Some(ADMIN_API_PORT)
        );
    }

    #[test]
    fn host_header_hostname_strips_ports_and_ipv6_brackets() {
        assert_eq!(host_header_hostname("example.com"), "example.com");
        assert_eq!(host_header_hostname("example.com:8080"), "example.com");
        assert_eq!(host_header_hostname("[::1]:443"), "::1");
        assert_eq!(host_header_hostname("[2001:db8::1]"), "2001:db8::1");
        assert_eq!(host_header_hostname(""), "");
    }

    /// httparse leaves trailing OWS on a header value. Trimming it here would let
    /// `Host: x2rp.<domain> ` route to the admin vhost from one client-chosen byte.
    #[test]
    fn host_header_hostname_keeps_padding_out_of_the_admin_vhost() {
        assert_eq!(
            host_header_hostname("x2rp.example.com "),
            "x2rp.example.com ",
            "a padded Host must not normalise onto the admin vhost"
        );
    }

    #[test]
    fn client_ip_from_peer_reduces_v4_mapped_peers() {
        let mapped: SocketAddr = "[::ffff:203.0.113.9]:44321".parse().expect("peer addr");
        assert_eq!(client_ip_from_peer(Some(&mapped)), "203.0.113.9");

        let v6: SocketAddr = "[2001:db8::1]:443".parse().expect("peer addr");
        assert_eq!(client_ip_from_peer(Some(&v6)), "2001:db8::1");

        assert_eq!(client_ip_from_peer(None), "unknown");
    }

    /// A client-supplied ID is echoed into logs and a response header, so only a
    /// short, plain one is honoured; anything else gets a fresh ID.
    #[test]
    fn request_id_honours_only_plain_client_ids() {
        let with = |value: &str| {
            let mut headers = http::HeaderMap::new();
            headers.insert("x-request-id", value.parse().expect("header value"));
            request_id_from_headers(&headers)
        };
        assert_eq!(with("trace_42-ab"), "trace_42-ab");
        for hostile in ["a b", "x\"y", "id]z", &"a".repeat(129), ""] {
            let id = with(hostile);
            assert_ne!(id, hostile);
            assert!(!id.is_empty() && id.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
        }
        assert_ne!(
            request_id_from_headers(&http::HeaderMap::new()),
            request_id_from_headers(&http::HeaderMap::new())
        );
    }

    /// Parsed once at publish time; an entry that no longer parses must deny
    /// everyone rather than collapse to the empty, admit-all list.
    #[test]
    fn from_resource_parses_the_allowlist_and_fails_closed() {
        let resource = |cidrs: &[&str]| crate::api::Resource {
            id: "r1".into(),
            subdomain: "app".into(),
            target: "http://127.0.0.1:8080".into(),
            enabled: true,
            connector_id: None,
            allowed_client_cidrs: cidrs.iter().map(|c| c.to_string()).collect(),
        };
        let parsed = ProxyResource::from_resource(&resource(&["203.0.113.0/24"]));
        assert_eq!(
            parsed.allowed_clients,
            Some(vec!["203.0.113.0/24".parse().expect("cidr")])
        );
        assert_eq!(
            ProxyResource::from_resource(&resource(&[])).allowed_clients,
            Some(Vec::new())
        );
        assert_eq!(
            ProxyResource::from_resource(&resource(&["not-an-ip"])).allowed_clients,
            None
        );
    }

    /// Each connection Pingora opens to a relay route becomes one tunnel `Connect`.
    #[tokio::test]
    async fn relay_connect_opens_a_tunnel_per_connection() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let manager = Arc::new(ConnectorManager::new(
            "c".to_string(),
            crate::connector_manager::Link::Wss(tx),
        ));
        let relay = RelayConnect {
            manager,
            target: "http://10.0.0.1:80".to_string(),
        };
        let addr = L4Addr::Inet("127.0.0.1:1".parse().expect("addr"));
        relay.connect(&addr).await.expect("relay pipe");
        match rx.recv().await {
            Some(Message::Connect { target, .. }) => assert_eq!(target, "http://10.0.0.1:80"),
            other => panic!("expected Connect, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn resolve_host_revalidates_cached_entries_for_current_policy() {
        let ctx = ProxyContext::new("", Arc::default());
        let cached = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)), 443);
        ctx.dns_cache.insert(
            "invalid.invalid:443".to_string(),
            (Instant::now(), vec![cached]),
        );

        assert_eq!(
            ctx.resolve_host("invalid.invalid", 443, |_| true).await,
            Some(cached)
        );
        assert!(
            ctx.resolve_host("invalid.invalid", 443, |_| false)
                .await
                .is_none(),
            "a cached address must still pass the caller's policy"
        );
    }
}
