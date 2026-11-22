use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

pub mod auth_api;
pub mod connectors;
pub mod resources;
pub mod setup_api;

pub use auth_api::*;
pub use connectors::*;
pub use resources::*;
pub use setup_api::*;
pub use x2rp_proto::{is_valid_domain, is_valid_host, is_valid_label};

pub(crate) const STATE_FILE: &str = "/var/lib/x2rp/state.json";

/// Admin session (HttpOnly) and CSRF (readable by the admin UI). `__Host-` requires
/// Secure + Path=/ + no Domain, so neither cookie ever reaches a proxied site.
pub(crate) const ADMIN_SESSION_COOKIE: &str = "__Host-x2rp_session";
pub(crate) const ADMIN_CSRF_COOKIE: &str = "__Host-x2rp_csrf";

pub(crate) fn normalize_domain(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connector {
    pub id: String,
    pub name: String,
    pub token_hash: String,
    /// Skip QUIC and connect over WebSocket only (restricted networks).
    pub force_wss: bool,
    pub last_seen: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resource {
    pub id: String,
    pub subdomain: String,
    pub target: String,
    pub enabled: bool,
    /// Reached through this connector; `None` proxies to a service on this host.
    pub connector_id: Option<String>,
    /// Client IPs and CIDR blocks admitted to this resource. Empty admits everyone.
    pub allowed_client_cidrs: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct ServerConfig {
    /// Cloudflare API token for DNS-01 ACME challenges (wildcard TLS).
    pub cf_api_token: String,
    /// Shared secret for the QUIC tunnel's UDP obfuscation.
    pub obfuscation_secret: String,
}

/// Hand-written for the same reason as [`x2rp_proto::Message`]'s: a derive would put
/// the Cloudflare token and the QUIC obfuscation secret into any `{:?}` that ever
/// reaches a log.
impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfig")
            .field("cf_api_token", &"[redacted]")
            .field("obfuscation_secret", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct AppState {
    pub server_config: ServerConfig,
    pub connectors: HashMap<String, Connector>,
    pub resources: Vec<Resource>,
    pub initialized: bool,
    pub domain: String,
    pub admin_password_hash: Option<String>,
    /// Where `save` writes; `None` is [`STATE_FILE`]. Only tests set it, so a test
    /// run as root can never overwrite a live install's state.
    #[serde(skip)]
    pub state_file: Option<PathBuf>,
}

impl AppState {
    /// Load state from disk. Missing file → empty default (first install).
    /// Existing but unreadable/corrupt/bad-perms file → hard error (never wipe via setup).
    pub fn load() -> anyhow::Result<Self> {
        let data = match x2rp_proto::read_secret_file(Path::new(STATE_FILE), 0o600) {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => anyhow::bail!(
                "state file {STATE_FILE} could not be safely loaded: {e}. Fix permissions/ownership or restore a backup; refusing to start empty."
            ),
        };
        let mut state: Self = serde_json::from_slice(&data).map_err(|e| {
            anyhow::anyhow!(
                "state file {STATE_FILE} is corrupt ({e}). Restore a backup; refusing to start empty."
            )
        })?;
        state.domain = normalize_domain(&state.domain);
        Ok(state)
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let path = self.state_file.as_deref().unwrap_or(Path::new(STATE_FILE));
        save_secure_file(path, serde_json::to_string_pretty(self)?.as_bytes())?;
        Ok(())
    }
}

pub(crate) fn connector_from_token<'a>(state: &'a AppState, token: &str) -> Option<&'a Connector> {
    let hash = hash_token(token);
    state
        .connectors
        .values()
        .find(|c| crate::auth::constant_time_eq(c.token_hash.as_bytes(), hash.as_bytes()))
}

#[derive(Clone)]
pub struct GlobalState {
    pub state: Arc<RwLock<AppState>>,
    pub auth: Arc<crate::auth::AuthService>,
    pub proxy_ctx: Arc<crate::proxy::ProxyContext>,
}

/// `N` random bytes, hex-encoded: tokens, session ids, record ids.
pub fn random_hex<const N: usize>() -> String {
    x2rp_proto::encode_hex(&rand::random::<[u8; N]>())
}

pub fn hash_token(token: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, token.as_bytes());
    x2rp_proto::encode_hex(digest.as_ref())
}

/// A connector's token from `Authorization: Bearer <token>` (RFC 6750: one or more
/// spaces after the scheme).
pub(crate) fn bearer_token(headers: &http::HeaderMap) -> Option<&str> {
    let value = headers.get(http::header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    let token = token.trim_start_matches(' ');
    (scheme.eq_ignore_ascii_case("bearer")
        && (1..=x2rp_proto::MAX_AUTH_TOKEN_LEN).contains(&token.len()))
    .then_some(token)
}

/// Save raw bytes to a file with secure permissions (0600): write a fresh temp
/// file, fsync, rename over the target, fsync the directory. Never a torn file.
pub(crate) fn save_secure_file(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    std::fs::create_dir_all(parent)?;
    // `create_new` on a random name: no pre-planted file or symlink can be reused.
    let tmp_path = path.with_extension(format!("tmp.{}", random_hex::<8>()));
    let write_res = (|| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)?;
        std::io::Write::write_all(&mut file, data)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp_path, path)?;
        std::fs::File::open(parent)?.sync_all()
    })();
    if write_res.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    write_res
}

/// Check if request has valid admin authentication (refreshes session idle deadline).
pub async fn verify_admin(state: &GlobalState, headers: &http::HeaderMap) -> bool {
    state.state.read().await.initialized
        && extract_cookie_header(headers, ADMIN_SESSION_COOKIE)
            .is_some_and(|sid| state.auth.validate_admin_session(sid))
}

/// Read-endpoint auth check: when `X-Passive-Poll: 1` is set (periodic UI refresh),
/// validates without refreshing the idle deadline so unattended tabs still time out.
pub(crate) async fn verify_admin_read(state: &GlobalState, headers: &http::HeaderMap) -> bool {
    let passive = headers.get("x-passive-poll").and_then(|v| v.to_str().ok()) == Some("1");
    state.state.read().await.initialized
        && extract_cookie_header(headers, ADMIN_SESSION_COOKIE).is_some_and(|sid| {
            if passive {
                state.auth.check_admin_session(sid)
            } else {
                state.auth.validate_admin_session(sid)
            }
        })
}

/// Extract a named cookie across all `Cookie` headers (RFC 6265 / RFC 9113)
/// without rejecting unrelated `obs-text` cookies.
pub(crate) fn extract_cookie_header<'a>(
    headers: &'a http::HeaderMap,
    name: &str,
) -> Option<&'a str> {
    let target = name.as_bytes();
    headers.get_all(http::header::COOKIE).iter().find_map(|h| {
        h.as_bytes().split(|&b| b == b';').find_map(|c| {
            let mut parts = c.trim_ascii().splitn(2, |&b| b == b'=');
            match (parts.next(), parts.next()) {
                (Some(k), Some(v)) if k == target => std::str::from_utf8(v).ok(),
                _ => None,
            }
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_leaks_server_secrets() {
        let config = ServerConfig {
            cf_api_token: "cf-secret-token".into(),
            obfuscation_secret: "quic-obfuscation-secret".into(),
        };
        let out = format!("{config:?}");
        assert!(
            !out.contains("cf-secret-token") && !out.contains("quic-obfuscation-secret"),
            "{out}"
        );
        // The state that embeds it inherits the redaction.
        let state = AppState {
            server_config: config,
            ..Default::default()
        };
        let out = format!("{state:?}");
        assert!(
            !out.contains("cf-secret-token") && !out.contains("quic-obfuscation-secret"),
            "{out}"
        );
    }

    #[test]
    fn connector_lookup_resolves_only_known_tokens() {
        let mut state = AppState::default();
        state.connectors.insert(
            "c1".into(),
            Connector {
                id: "c1".into(),
                name: "c1".into(),
                token_hash: hash_token("token-1"),
                force_wss: false,
                last_seen: None,
            },
        );
        assert_eq!(
            connector_from_token(&state, "token-1").map(|c| c.id.as_str()),
            Some("c1")
        );
        assert!(connector_from_token(&state, "token-2").is_none());
    }

    #[test]
    fn bearer_token_parsing_is_case_insensitive() {
        let token = |value: &str| {
            let mut headers = http::HeaderMap::new();
            headers.insert(http::header::AUTHORIZATION, value.parse().expect("header"));
            bearer_token(&headers).map(str::to_string)
        };
        for header in [
            "Bearer token-123",
            "bearer token-123",
            "BEARER token-123",
            "Bearer   token-123",
        ] {
            assert_eq!(token(header).as_deref(), Some("token-123"), "{header}");
        }
        let too_long = format!("Bearer {}", "a".repeat(x2rp_proto::MAX_AUTH_TOKEN_LEN + 1));
        for bad in [
            "token-123",
            "Bearer",
            "Bearer ",
            "Basic token-123",
            &too_long,
        ] {
            assert!(token(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn extract_cookie_tolerates_unrelated_obs_text_cookies() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            http::HeaderValue::from_bytes(b"legacy=\xff\xfe; __Host-x2rp_session=abc123")
                .expect("valid obs-text header value"),
        );
        assert_eq!(
            extract_cookie_header(&headers, ADMIN_SESSION_COOKIE),
            Some("abc123")
        );
    }
}
