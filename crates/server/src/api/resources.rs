use axum::{
    Json,
    extract::{Path, State},
};
use http::HeaderMap;
use serde::Deserialize;
use std::net::IpAddr;
use x2rp_proto::ssrf::{is_local_direct_target_ip, is_strictly_dangerous_ip};

use crate::proxy::{ADMIN_API_PORT, DNS_LOOKUP_TIMEOUT, ProxyResource};

use super::{GlobalState, Resource, is_valid_host, is_valid_label, random_hex, verify_admin};

/// Present-or-absent double option: missing → None, null → Some(None), value → Some(Some(v)).
/// Lets JSON `null` clear an optional field on update.
fn deserialize_present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Some(T::deserialize(deserializer)?))
}

fn normalize_connector_id(connector_id: Option<String>) -> Option<String> {
    connector_id
        .map(|id| id.trim().to_string())
        .filter(|id| !id.is_empty())
}

fn normalize_subdomain(subdomain: &str) -> String {
    subdomain.trim().to_ascii_lowercase()
}

fn subdomain_in_use(resources: &[Resource], candidate: &str, exclude_id: Option<&str>) -> bool {
    resources.iter().any(|resource| {
        exclude_id != Some(resource.id.as_str())
            && resource.subdomain.eq_ignore_ascii_case(candidate)
    })
}

/// A DNS label, and not the admin host.
fn validate_subdomain(subdomain: &str) -> Result<(), http::StatusCode> {
    if !is_valid_label(subdomain) {
        tracing::warn!("Invalid subdomain: {}", subdomain);
        return Err(http::StatusCode::BAD_REQUEST);
    }
    if ["x2rp", "www"].contains(&subdomain) {
        tracing::warn!("Attempt to use reserved subdomain: {}", subdomain);
        return Err(http::StatusCode::FORBIDDEN);
    }
    Ok(())
}

fn parse_allowlist(entries: &[String]) -> Result<Vec<String>, http::StatusCode> {
    crate::allowlist::parse(entries)
        .map(|nets| nets.iter().map(ToString::to_string).collect())
        .map_err(|e| {
            tracing::warn!("Invalid client allowlist: {}", e);
            http::StatusCode::BAD_REQUEST
        })
}

/// SSRF protection for targets on **this host** (no connector): every resolved
/// address must be loopback. [`ADMIN_API_PORT`] is the local admin API and must
/// never be published. Resolving to nothing fails: tokio's `lookup_host` may
/// succeed with an empty iterator, and an empty allow-all would be a bypass.
async fn check_ssrf_local(host: &str, port: u16) -> Result<(), &'static str> {
    const UNRESOLVED: &str = "Target hostname could not be resolved";
    if port == ADMIN_API_PORT {
        return Err("Targets on this host must not use the local admin API port");
    }
    // A literal IP parses without a DNS query.
    let Ok(Ok(addrs)) =
        tokio::time::timeout(DNS_LOOKUP_TIMEOUT, tokio::net::lookup_host((host, port))).await
    else {
        return Err(UNRESOLVED);
    };
    let addrs: Vec<_> = addrs.collect();
    if addrs.is_empty() {
        return Err(UNRESOLVED);
    }
    if addrs
        .iter()
        .all(|addr| is_local_direct_target_ip(addr.ip()))
    {
        Ok(())
    } else {
        Err(
            "Targets without a connector must be on this host (127.0.0.1 / ::1 / localhost); use a connector for LAN or remote services",
        )
    }
}

/// SSRF protection for **connector-routed** targets: a literal IP must not be
/// link-local, multicast or cloud metadata. A hostname is checked where it
/// resolves, by the connector, since only its DNS can answer for a LAN name.
fn check_ssrf_strict(host: &str) -> Result<(), &'static str> {
    match host.parse::<IpAddr>() {
        Ok(ip) if is_strictly_dangerous_ip(ip) => {
            Err("Target is a restricted link-local/metadata IP")
        }
        _ => Ok(()),
    }
}

/// `http(s)://host[:port]` with no path or query → (unbracketed host, port).
fn parse_http_target_host_port(target: &str) -> Result<(String, u16), &'static str> {
    let uri: http::Uri = target.parse().map_err(|_| "Invalid target URL")?;
    let scheme = uri.scheme_str().ok_or("Invalid scheme")?;
    if scheme != "http" && scheme != "https" {
        return Err("Invalid scheme");
    }
    if let Some(path_and_query) = uri.path_and_query()
        && (!matches!(path_and_query.path(), "" | "/") || path_and_query.query().is_some())
    {
        return Err("Target must not include a path or query");
    }
    let host = uri.host().ok_or("Missing host")?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let port = uri
        .port_u16()
        .unwrap_or(if scheme == "https" { 443 } else { 80 });
    Ok((host.to_string(), port))
}

/// Shape and SSRF gate, before any state lock is taken. Shared by create and
/// update so the two cannot drift into admitting different origins.
async fn validate_target(target: &str, connector_id: Option<&str>) -> Result<(), http::StatusCode> {
    let (host, port) = parse_http_target_host_port(target).map_err(|reason| {
        tracing::warn!("Invalid target {target}: {reason}");
        http::StatusCode::BAD_REQUEST
    })?;
    if host.parse::<IpAddr>().is_err() && !is_valid_host(&host) {
        tracing::warn!("Invalid target host: {target}");
        return Err(http::StatusCode::BAD_REQUEST);
    }
    // The connector opens plain TCP to the origin; TLS to it is not supported.
    if connector_id.is_some() && target.starts_with("https") {
        tracing::warn!("Connector targets must be http://: {target}");
        return Err(http::StatusCode::BAD_REQUEST);
    }
    let ssrf = match connector_id {
        Some(_) => check_ssrf_strict(&host),
        None => check_ssrf_local(&host, port).await,
    };
    ssrf.map_err(|reason| {
        tracing::warn!("SSRF blocked for target {target}: {reason}");
        http::StatusCode::FORBIDDEN
    })
}

fn publish(state: &GlobalState, resource: &Resource) {
    if resource.enabled {
        state
            .proxy_ctx
            .set_resource(ProxyResource::from_resource(resource));
    } else {
        state.proxy_ctx.remove_resource(&resource.subdomain);
    }
}

pub async fn list_resources(
    State(state): State<GlobalState>,
    headers: HeaderMap,
) -> Result<Json<Vec<Resource>>, http::StatusCode> {
    if !verify_admin(&state, &headers).await {
        return Err(http::StatusCode::UNAUTHORIZED);
    }
    Ok(Json(state.state.read().await.resources.clone()))
}

#[derive(Deserialize)]
pub struct CreateResourceRequest {
    pub subdomain: String,
    pub target: String,
    #[serde(default)]
    pub connector_id: Option<String>,
    #[serde(default)]
    pub allowed_client_cidrs: Vec<String>,
}

pub async fn create_resource(
    State(state): State<GlobalState>,
    headers: HeaderMap,
    Json(req): Json<CreateResourceRequest>,
) -> Result<Json<Resource>, http::StatusCode> {
    if !verify_admin(&state, &headers).await {
        return Err(http::StatusCode::UNAUTHORIZED);
    }
    let subdomain = normalize_subdomain(&req.subdomain);
    validate_subdomain(&subdomain)?;
    let connector_id = normalize_connector_id(req.connector_id);
    let allowed_client_cidrs = parse_allowlist(&req.allowed_client_cidrs)?;
    validate_target(&req.target, connector_id.as_deref()).await?;

    let mut s = state.state.write().await;
    if subdomain_in_use(&s.resources, &subdomain, None) {
        return Err(http::StatusCode::CONFLICT);
    }
    if let Some(cid) = connector_id.as_deref()
        && !s.connectors.contains_key(cid)
    {
        tracing::warn!("Resource {subdomain} references unknown connector {cid}");
        return Err(http::StatusCode::BAD_REQUEST);
    }

    let resource = Resource {
        id: random_hex::<16>(),
        subdomain,
        target: req.target,
        enabled: true,
        connector_id,
        allowed_client_cidrs,
    };
    s.resources.push(resource.clone());
    if let Err(e) = s.save() {
        s.resources.retain(|r| r.id != resource.id);
        tracing::error!("Failed to save resource {}: {}", resource.id, e);
        return Err(http::StatusCode::INTERNAL_SERVER_ERROR);
    }
    publish(&state, &resource);
    tracing::info!("Created resource: {}.{}", resource.subdomain, s.domain);
    Ok(Json(resource))
}

#[derive(Deserialize)]
pub struct UpdateResourceRequest {
    pub subdomain: Option<String>,
    pub target: Option<String>,
    pub enabled: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_present")]
    pub connector_id: Option<Option<String>>,
    pub allowed_client_cidrs: Option<Vec<String>>,
}

pub async fn update_resource(
    State(state): State<GlobalState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<UpdateResourceRequest>,
) -> Result<Json<Resource>, http::StatusCode> {
    if !verify_admin(&state, &headers).await {
        return Err(http::StatusCode::UNAUTHORIZED);
    }
    let subdomain = req.subdomain.as_deref().map(normalize_subdomain);
    if let Some(subdomain) = subdomain.as_deref() {
        validate_subdomain(subdomain)?;
    }
    let allowlist = req
        .allowed_client_cidrs
        .as_deref()
        .map(parse_allowlist)
        .transpose()?;

    let current = {
        let s = state.state.read().await;
        s.resources
            .iter()
            .find(|r| r.id == id)
            .cloned()
            .ok_or(http::StatusCode::NOT_FOUND)?
    };
    let mut resource = current.clone();
    if let Some(subdomain) = subdomain {
        resource.subdomain = subdomain;
    }
    if let Some(target) = req.target {
        resource.target = target;
    }
    if let Some(connector_id) = req.connector_id {
        resource.connector_id = normalize_connector_id(connector_id);
    }
    if let Some(enabled) = req.enabled {
        resource.enabled = enabled;
    }
    if let Some(allowlist) = allowlist {
        resource.allowed_client_cidrs = allowlist;
    }
    validate_target(&resource.target, resource.connector_id.as_deref()).await?;

    let mut s = state.state.write().await;
    if subdomain_in_use(&s.resources, &resource.subdomain, Some(&id)) {
        return Err(http::StatusCode::CONFLICT);
    }
    if let Some(cid) = resource.connector_id.as_deref()
        && !s.connectors.contains_key(cid)
    {
        tracing::warn!("Resource update references unknown connector {cid}");
        return Err(http::StatusCode::BAD_REQUEST);
    }
    let idx = s
        .resources
        .iter()
        .position(|r| r.id == id)
        .ok_or(http::StatusCode::NOT_FOUND)?;
    let old = std::mem::replace(&mut s.resources[idx], resource.clone());
    if let Err(e) = s.save() {
        s.resources[idx] = old;
        tracing::error!("Failed to save resource {}: {}", id, e);
        return Err(http::StatusCode::INTERNAL_SERVER_ERROR);
    }
    // Routes are keyed by subdomain: drop the old name before publishing the new one.
    state.proxy_ctx.remove_resource(&old.subdomain);
    publish(&state, &resource);
    tracing::info!("Updated resource: {}", id);
    Ok(Json(resource))
}

pub async fn delete_resource(
    State(state): State<GlobalState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<http::StatusCode, http::StatusCode> {
    if !verify_admin(&state, &headers).await {
        return Err(http::StatusCode::UNAUTHORIZED);
    }
    let mut s = state.state.write().await;
    let index = s
        .resources
        .iter()
        .position(|r| r.id == id)
        .ok_or(http::StatusCode::NOT_FOUND)?;
    let removed = s.resources.remove(index);
    if let Err(e) = s.save() {
        // Restore, so memory matches disk (retry-safe).
        s.resources.insert(index, removed);
        tracing::error!("Failed to save resource deletion {}: {}", id, e);
        return Err(http::StatusCode::INTERNAL_SERVER_ERROR);
    }
    state.proxy_ctx.remove_resource(&removed.subdomain);
    tracing::info!("Deleted resource: {}", id);
    Ok(http::StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::{check_ssrf_local, check_ssrf_strict, validate_target};

    /// The one gate create and update both route through, so a regression here
    /// silently changes what *either* endpoint accepts.
    #[tokio::test]
    async fn validate_target_enforces_shape_and_ssrf() {
        // No connector is a same-host reverse proxy; with one, the LAN.
        assert!(validate_target("http://127.0.0.1:8080", None).await.is_ok());
        assert!(
            validate_target("http://192.168.1.10:8080", None)
                .await
                .is_err()
        );
        assert!(
            validate_target("http://192.168.1.10:8080", Some("c"))
                .await
                .is_ok()
        );
        assert!(
            validate_target("https://192.168.1.10:8443", Some("c"))
                .await
                .is_err()
        );
        assert!(
            validate_target("http://169.254.169.254:80", Some("c"))
                .await
                .is_err()
        );
        // A LAN name only the connector's DNS knows: checked where it resolves.
        assert!(
            validate_target("http://nas.invalid:8080", Some("c"))
                .await
                .is_ok()
        );
        assert!(
            validate_target("tcp://192.168.1.10:22", None)
                .await
                .is_err()
        );
        assert!(
            validate_target("http://127.0.0.1:8080/path", None)
                .await
                .is_err()
        );
    }

    /// "Same-host reverse proxy" versus "LAN via connector". Literal IPs only (no
    /// lookup), so this asserts policy rather than DNS.
    #[tokio::test]
    async fn ssrf_gates_admit_only_their_own_address_class() {
        assert!(check_ssrf_local("127.0.0.1", 8080).await.is_ok());
        assert!(check_ssrf_local("::1", 8080).await.is_ok());
        assert!(check_ssrf_local("192.168.1.10", 8080).await.is_err());
        assert!(check_ssrf_local("1.1.1.1", 80).await.is_err());
        // The admin API is never a publishable origin, loopback or not.
        assert!(check_ssrf_local("127.0.0.1", 8800).await.is_err());

        assert!(check_ssrf_strict("192.168.1.10").is_ok());
        assert!(check_ssrf_strict("10.0.0.5").is_ok());
        assert!(check_ssrf_strict("169.254.169.254").is_err());
        // v4-mapped and NAT64-synthesized metadata must not dodge the v4 check.
        assert!(check_ssrf_strict("::ffff:169.254.169.254").is_err());
        assert!(check_ssrf_strict("64:ff9b::a9fe:a9fe").is_err());
    }

    /// A name on this host that resolves to nothing must fail closed.
    #[tokio::test]
    async fn unresolvable_local_target_is_denied() {
        assert!(check_ssrf_local("invalid.invalid", 443).await.is_err());
    }
}
