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
use crate::rate_limit::{ClientKey, RateLimiter, client_key, is_auth_sensitive_path};
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

/// Strict RFC 9110 `Host` parser returning the bare hostname or IPv6 literal
/// (unbracketed). Rejects empty values, whitespace/control chars, invalid ports,
/// credentials (`@`), non-IPv6 bracketed hosts, and trailing garbage.
pub fn parse_host_header(raw: &str) -> Option<&str> {
    if raw.is_empty()
        || raw
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return None;
    }
    let valid_port = |port: &str| {
        !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) && port.parse::<u16>().is_ok()
    };
    if let Some(rest) = raw.strip_prefix('[') {
        let (inner, after) = rest.split_once(']')?;
        inner.parse::<std::net::Ipv6Addr>().ok()?;
        match after {
            "" => Some(inner),
            _ => after
                .strip_prefix(':')
                .is_some_and(valid_port)
                .then_some(inner),
        }
    } else {
        let host = match raw.split_once(':') {
            Some((h, port)) => {
                if !valid_port(port) {
                    return None;
                }
                h
            }
            None => raw,
        };
        if host.is_empty()
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        {
            return None;
        }
        Some(host)
    }
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

/// `client METHOD host/path` for a log line (omits query strings to avoid leaking
/// tokens/secrets into INFO access logs), formatted only if emitted.
struct RequestLine<'a>(&'a Session, Option<IpAddr>);

impl std::fmt::Display for RequestLine<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let req = self.0.req_header();
        let host = req
            .headers
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .or_else(|| req.uri.authority().map(http::uri::Authority::as_str))
            .unwrap_or("-");
        match self.1 {
            Some(ip) => write!(f, "{ip} {} {host}{}", req.method, req.uri.path()),
            None => write!(f, "unknown {} {host}{}", req.method, req.uri.path()),
        }
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
    resp.insert_header(header::CACHE_CONTROL, "no-store")?;
    resp.insert_header("X-Request-Id", request_id)?;
    if status == StatusCode::TOO_MANY_REQUESTS {
        resp.insert_header(header::RETRY_AFTER, "60")?;
    }
    append_standard_security_headers(&mut resp);
    // Tell Pingora to close the downstream connection (a manual `Connection: close`
    // header is overwritten by Pingora's HTTP/1 `prepare_response_header`).
    session.set_keepalive(None);
    session.write_response_header(Box::new(resp), false).await?;
    session.write_response_body(Some(body), true).await?;
    Ok(true)
}

/// Canonical IP of the peer (v4-mapped v6 reduced to v4) so rate limits and
/// allowlists match regardless of which IP stack a connection arrived on.
fn client_ip_from_peer(addr: Option<&SocketAddr>) -> Option<IpAddr> {
    addr.map(|a| a.ip().to_canonical())
}

/// RFC 9110 §7.8 upgrade check: both `Upgrade` header and `Connection: upgrade` token.
fn is_http_upgrade(headers: &http::HeaderMap) -> bool {
    headers.contains_key(header::UPGRADE)
        && headers
            .get_all(header::CONNECTION)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .any(|v| {
                v.split(',')
                    .any(|tok| tok.trim().eq_ignore_ascii_case("upgrade"))
            })
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
        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
        self.manager
            .bridge_cancellable(&self.target, theirs, Some(cancel_rx))
            .map_err(|e| Error::explain(ErrorType::ConnectRefused, e))?;
        Ok(VirtualSocketStream::new(Box::new(RelayPipe {
            stream: ours,
            _cancel: cancel_tx,
        }))
        .into())
    }
}

/// Pingora's end of the pipe. Dropping `RelayPipe` drops `_cancel`,
/// immediately cancelling the connector tunnel and freeing its stream slot.
#[derive(Debug)]
struct RelayPipe {
    stream: tokio::io::DuplexStream,
    _cancel: tokio::sync::oneshot::Sender<()>,
}

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
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for RelayPipe {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
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

type DnsCacheEntry = (Instant, Arc<[SocketAddr]>);

/// Shared proxy context
pub struct ProxyContext {
    resources: RwLock<HashMap<String, Arc<ProxyResource>>>,
    /// Keyed by resource origins only, so it stays as small as the route table.
    dns_cache: RwLock<HashMap<String, DnsCacheEntry>>,
    domain: String,
    rate_limiter: RateLimiter,
    pub connectors: Arc<ConnectorRegistry>,
}

impl ProxyContext {
    pub fn new(domain: &str, connectors: Arc<ConnectorRegistry>) -> Self {
        Self {
            resources: RwLock::default(),
            dns_cache: RwLock::default(),
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

    /// Atomically replace `old_subdomain` with `new` under a single write lock so
    /// live edits never expose a transient 404 window.
    pub fn replace_resource(&self, old_subdomain: &str, new: Option<ProxyResource>) {
        let old_fqdn = self.fqdn(old_subdomain);
        let new_entry = new.map(|r| (self.fqdn(&r.subdomain), Arc::new(r)));
        let mut map = self.resources.write();
        map.remove(&old_fqdn);
        if let Some((fqdn, res)) = new_entry {
            map.insert(fqdn, res);
        }
    }

    /// Keep cache and limiter state bounded even when traffic goes idle.
    /// Driven every minute by `main`.
    pub fn maintenance_tick(&self) {
        self.dns_cache
            .write()
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
            .read()
            .get(&key)
            .filter(|(created, _)| created.elapsed() < DNS_CACHE_TTL)
            .map(|(_, addrs)| Arc::clone(addrs));
        let addrs = match cached {
            Some(addrs) => addrs,
            None => {
                let lookup = tokio::net::lookup_host(key.as_str());
                let addrs: Arc<[SocketAddr]> = tokio::time::timeout(DNS_LOOKUP_TIMEOUT, lookup)
                    .await
                    .ok()?
                    .ok()?
                    .collect();
                self.dns_cache
                    .write()
                    .insert(key, (Instant::now(), Arc::clone(&addrs)));
                addrs
            }
        };
        addrs.iter().copied().find(|addr| allowed(addr.ip()))
    }
}

/// Per-request context
#[derive(Default)]
pub struct RequestCtx {
    resource: Option<Arc<ProxyResource>>,
    /// Canonical lowercase routing hostname (without `:port`) from `parse_host_header`.
    host: String,
    client_ip: Option<IpAddr>,
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

        let req_header = session.req_header();
        let parsed_host = req_header
            .headers
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .or_else(|| req_header.uri.authority().map(http::uri::Authority::as_str))
            .and_then(parse_host_header)
            .map(str::to_ascii_lowercase);
        // Only x2rp.<domain> is the admin console; the apex is not.
        let is_admin_host = parsed_host
            .as_deref()
            .is_some_and(|h| h.strip_prefix("x2rp.") == Some(self.ctx.domain.as_str()));

        // Admin login draws the strict tier; everything else the media-friendly one.
        // Keyed per IPv6 /64, or rotating the interface ID would reset the budget.
        let limiter = &self.ctx.rate_limiter;
        let tier = if is_admin_host && is_auth_sensitive_path(req_header.uri.path()) {
            &limiter.auth
        } else {
            &limiter.general
        };
        let limit_key = ctx.client_ip.map_or(ClientKey::Unknown, client_key);
        if !tier.check(limit_key) {
            tracing::warn!(
                "Rate limit exceeded: {} [req:{}]",
                RequestLine(session, ctx.client_ip),
                ctx.request_id
            );
            return send_error_response(session, &ctx.request_id, StatusCode::TOO_MANY_REQUESTS)
                .await;
        }

        let Some(host) = parsed_host else {
            return send_error_response(session, &ctx.request_id, StatusCode::BAD_REQUEST).await;
        };
        ctx.host = host;
        let host = ctx.host.as_str();

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
            let Some(resource) = self.ctx.resources.read().get(host).cloned() else {
                return send_error_response(session, &ctx.request_id, StatusCode::NOT_FOUND).await;
            };
            resource
        };

        // `None` is a stored allowlist that no longer parses: fail closed.
        let admitted = resource.allowed_clients.as_deref().is_some_and(|nets| {
            ctx.client_ip
                .is_some_and(|ip| crate::allowlist::admits(nets, ip))
        });
        if !admitted {
            tracing::warn!(
                "Client not on allowlist: {} [req:{}]",
                RequestLine(session, ctx.client_ip),
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
            // Defense in depth: relay connectors open plain TCP and never support https:// targets.
            if !matches!(
                x2rp_proto::parse_http_origin(&resource.target),
                Ok((_, _, false))
            ) {
                tracing::error!(
                    "Invalid relay target URL (must be http://): {}",
                    resource.target
                );
                return Err(Error::new(ErrorType::ConnectError));
            }
            // The path is never dialed (`custom_l4` connects); it only keys the pool.
            let path = format!("/x2rp-relay/{}", resource.subdomain);
            let mut peer = HttpPeer::new_uds(&path, false, String::new())?;
            peer.options.custom_l4 = Some(relay.clone());
            // Never pool relay streams across requests (`HttpPeer::new_uds` defaults `idle_timeout` to `None`).
            peer.options.idle_timeout = Some(Duration::ZERO);
            peer.options.read_timeout = Some(Duration::from_secs(300));
            peer.options.write_timeout = Some(Duration::from_secs(300));
            return Ok(Box::new(peer));
        }

        let Ok((host, port, tls)) = x2rp_proto::parse_http_origin(&resource.target) else {
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
            .resolve_host(host, port, x2rp_proto::ssrf::is_local_direct_target_ip)
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

        let mut peer = HttpPeer::new(peer_addr, tls, host.to_string());
        peer.options.connection_timeout = Some(Duration::from_secs(10));
        peer.options.total_connection_timeout = Some(Duration::from_secs(15));
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
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // Replace whatever the client sent: origins trust these to name the real peer.
        let client_ip = ctx
            .client_ip
            .map_or_else(|| "unknown".to_string(), |ip| ip.to_string());
        upstream_request.remove_header("Forwarded");
        upstream_request.remove_header("X-Scheme");
        upstream_request.insert_header("X-Forwarded-For", &client_ip)?;
        upstream_request.insert_header("X-Real-IP", &client_ip)?;
        // Always "https" / 443: Gateway is only registered on the TLS listener ([::]:443).
        upstream_request.insert_header("X-Forwarded-Proto", "https")?;
        upstream_request.insert_header("X-Forwarded-Port", "443")?;
        upstream_request.insert_header("X-Request-Id", &ctx.request_id)?;
        // Forward the canonical routing host; only rebuild `Host` if a `:port` was sent.
        if !ctx.host.is_empty() {
            if upstream_request
                .headers
                .get(header::HOST)
                .is_some_and(|v| v.as_bytes().contains(&b':'))
            {
                upstream_request.insert_header(header::HOST, &ctx.host)?;
            }
            upstream_request.insert_header("X-Forwarded-Host", &ctx.host)?;
        } else {
            upstream_request.remove_header("X-Forwarded-Host");
        }

        // One tunnel per request: pooled, an idle one would hold a connector stream
        // slot, so have the origin close it after this response. Require a real upgrade
        // on both the downstream request (so bare `Upgrade: websocket` cannot ride
        // Pingora's synthesized `Connection: Upgrade`) and the sanitized upstream request
        // (so non-WebSocket upgrades stripped by Pingora still get `Connection: close`).
        if ctx.relay.is_some()
            && !(is_http_upgrade(&session.req_header().headers)
                && is_http_upgrade(&upstream_request.headers))
        {
            upstream_request.remove_header(&header::UPGRADE);
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
        if code > 0 && session.response_written().is_none() {
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
        let line = RequestLine(session, ctx.client_ip);
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
            x2rp_proto::parse_http_origin(ADMIN_API_TARGET)
                .ok()
                .map(|(_, port, _)| port),
            Some(ADMIN_API_PORT)
        );
    }

    #[test]
    fn parse_host_header_strips_ports_and_ipv6_brackets() {
        assert_eq!(parse_host_header("example.com"), Some("example.com"));
        assert_eq!(parse_host_header("example.com:8080"), Some("example.com"));
        assert_eq!(parse_host_header("[::1]:443"), Some("::1"));
        assert_eq!(parse_host_header("[2001:db8::1]"), Some("2001:db8::1"));
        assert_eq!(parse_host_header(""), None);
    }

    /// Reject trailing OWS, non-IPv6 brackets, invalid ports, and suffix junk so
    /// malformed `Host` headers can neither hit the admin vhost nor smuggle headers.
    #[test]
    fn parse_host_header_rejects_malformed_and_padded_hosts() {
        for bad in [
            "x2rp.example.com ",
            " x2rp.example.com",
            "[x2rp.example.com]junk",
            "[app.example.com]:443",
            "x2rp.example.com:junk",
            "app.example.com:443/x",
            "app.example.com:",
            "app.example.com:99999",
            "app.example.com:+443",
            "user@app.example.com",
            "[::1]junk",
        ] {
            assert_eq!(parse_host_header(bad), None, "{bad} must be rejected");
        }
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
        let pipe = relay.connect(&addr).await.expect("relay pipe");
        let stream_id = match rx.recv().await {
            Some(Message::Connect { stream_id, target }) => {
                assert_eq!(target, "http://10.0.0.1:80");
                stream_id
            }
            other => panic!("expected Connect, got {other:?}"),
        };
        // Dropping the pipe cancels the pending tunnel and sends Reset immediately.
        drop(pipe);
        match tokio::time::timeout(Duration::from_secs(1), rx.recv()).await {
            Ok(Some(Message::Reset { stream_id: reset })) => assert_eq!(reset, stream_id),
            other => panic!("expected Reset on pipe drop, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn resolve_host_revalidates_cached_entries_for_current_policy() {
        let ctx = ProxyContext::new("", Arc::default());
        let cached = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)), 443);
        ctx.dns_cache.write().insert(
            "invalid.invalid:443".to_string(),
            (Instant::now(), Arc::from([cached])),
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
