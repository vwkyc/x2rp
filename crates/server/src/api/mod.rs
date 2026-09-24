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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServerConfig {
    /// Cloudflare API token for DNS-01 ACME challenges (wildcard TLS).
    pub cf_api_token: String,
    /// Shared secret for the QUIC tunnel's UDP obfuscation.
    pub obfuscation_secret: String,
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
    state.connectors.values().find(|c| c.token_hash == hash)
}

#[derive(Clone)]
pub struct GlobalState {
    pub state: Arc<RwLock<AppState>>,
    pub auth: Arc<crate::auth::AuthService>,
    pub proxy_ctx: Arc<crate::proxy::ProxyContext>,
}

/// `N` random bytes, hex-encoded: tokens, session ids, record ids.
pub fn random_hex<const N: usize>() -> String {
    hex::encode(rand::random::<[u8; N]>())
}

pub fn hash_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(token.as_bytes()))
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

    let parent = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    // `create_new` on a random name: no pre-planted file or symlink can be reused.
    let tmp_path = path.with_extension(format!("tmp.{}", random_hex::<8>()));
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
}

/// One DNS label: 1-63 alphanumerics or hyphens, not starting or ending with a hyphen.
pub(crate) fn is_valid_label(label: &str) -> bool {
    (1..=63).contains(&label.len())
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// A hostname: dot-separated labels.
pub(crate) fn is_valid_host(host: &str) -> bool {
    host.len() <= 253 && host.split('.').all(is_valid_label)
}

/// A hostname with at least two labels.
pub fn is_valid_domain(domain: &str) -> bool {
    domain.contains('.') && is_valid_host(domain)
}

/// Check if request has valid admin authentication.
pub async fn verify_admin(state: &GlobalState, headers: &http::HeaderMap) -> bool {
    state.state.read().await.initialized
        && headers
            .get(http::header::COOKIE)
            .and_then(|h| h.to_str().ok())
            .and_then(|cookies| extract_cookie(cookies, ADMIN_SESSION_COOKIE))
            .is_some_and(|sid| state.auth.validate_admin_session(sid))
}

pub(crate) fn extract_cookie<'a>(cookies: &'a str, name: &str) -> Option<&'a str> {
    cookies.split(';').find_map(|c| {
        let (k, v) = c.trim().split_once('=')?;
        (k == name).then_some(v)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn domains_are_dotted_hostnames() {
        assert!(is_valid_domain("example.com"));
        for bad in ["", "localhost", "-a.com", "a..com", "a_b.com", "a/b.com"] {
            assert!(!is_valid_domain(bad), "{bad}");
        }
    }
}
