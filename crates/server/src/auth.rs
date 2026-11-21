//! Admin authentication: Argon2id password hashes and session-bound CSRF tokens.

use crate::api::random_hex;

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use anyhow::Result;
use argon2::{Algorithm, Argon2, Params, PasswordHasher, PasswordVerifier, Version};
use parking_lot::RwLock;

const SESSION_IDLE_TTL: Duration = Duration::from_secs(300);
pub(crate) const SESSION_ABSOLUTE_TTL_SECS: u64 = 28800;
const SESSION_ABSOLUTE_TTL: Duration = Duration::from_secs(SESSION_ABSOLUTE_TTL_SECS);
const MAX_ADMIN_SESSIONS: usize = 1_000;
pub const ADMIN_PASSWORD_MIN_LEN: usize = 12;
pub const ADMIN_PASSWORD_MAX_LEN: usize = 128;

/// Admin UI session: opaque session id + CSRF secret bound to that session.
struct AdminSession {
    csrf_token: String,
    created_at: Instant,
    last_access: Instant,
}

#[derive(Default)]
pub struct AuthService {
    admin_sessions: RwLock<HashMap<String, AdminSession>>,
}

impl AuthService {
    /// Returns `(session_id, csrf_token)`. The CSRF token is bound to this session only.
    pub fn create_admin_session(&self) -> (String, String) {
        let session_id = random_hex::<32>();
        let csrf_token = random_hex::<32>();
        let now = Instant::now();
        let mut sessions = self.admin_sessions.write();
        evict_if_full(&mut sessions, now);
        sessions.insert(
            session_id.clone(),
            AdminSession {
                csrf_token: csrf_token.clone(),
                created_at: now,
                last_access: now,
            },
        );
        (session_id, csrf_token)
    }

    /// Validate an active session and refresh its idle deadline.
    pub fn validate_admin_session(&self, session_id: &str) -> bool {
        let now = Instant::now();
        let mut sessions = self.admin_sessions.write();
        let Some(session) = sessions.get_mut(session_id) else {
            return false;
        };
        if admin_session_expired(session, now) {
            sessions.remove(session_id);
            return false;
        }
        session.last_access = now;
        true
    }

    /// Validate an active session without refreshing `last_access` (passive UI polls).
    pub fn check_admin_session(&self, session_id: &str) -> bool {
        let now = Instant::now();
        self.admin_sessions
            .read()
            .get(session_id)
            .is_some_and(|session| !admin_session_expired(session, now))
    }

    /// True when the CSRF token matches the one issued for this session (constant-time).
    pub fn validate_admin_csrf(&self, session_id: &str, csrf_token: &str) -> bool {
        let now = Instant::now();
        self.admin_sessions
            .read()
            .get(session_id)
            .is_some_and(|session| {
                !admin_session_expired(session, now)
                    && constant_time_eq(session.csrf_token.as_bytes(), csrf_token.as_bytes())
            })
    }

    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        self.admin_sessions
            .write()
            .retain(|_, session| !admin_session_expired(session, now));
    }
}

/// Anyone who can post to the login endpoint can mint sessions, so the map is
/// capped atomically: expired sessions go first, then the least recently used.
fn evict_if_full(sessions: &mut HashMap<String, AdminSession>, now: Instant) {
    if sessions.len() < MAX_ADMIN_SESSIONS {
        return;
    }
    sessions.retain(|_, session| !admin_session_expired(session, now));
    let excess = (sessions.len() + 1).saturating_sub(MAX_ADMIN_SESSIONS);
    if excess == 0 {
        return;
    }
    let mut oldest: Vec<(String, Instant)> = sessions
        .iter()
        .map(|(key, session)| (key.clone(), session.last_access))
        .collect();
    let remove_count = excess.min(oldest.len());
    if remove_count < oldest.len() {
        oldest.select_nth_unstable_by_key(remove_count - 1, |(_, last_access)| *last_access);
    }
    for (key, _) in oldest.into_iter().take(remove_count) {
        sessions.remove(&key);
    }
}

/// Constant-time equality for equal-length secrets (CSRF tokens, etc.). Different
/// lengths return false immediately: length is not secret for fixed-size tokens.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

fn admin_session_expired(session: &AdminSession, now: Instant) -> bool {
    now.saturating_duration_since(session.last_access) > SESSION_IDLE_TTL
        || now.saturating_duration_since(session.created_at) > SESSION_ABSOLUTE_TTL
}

/// Argon2id per OWASP recommendations (m=9216, t=4, p=1).
fn argon2id() -> Argon2<'static> {
    let params = Params::new(9216, 4, 1, None).expect("constant Argon2 params are valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

pub fn hash_password(password: &str) -> Result<String> {
    // Salt drawn from the OS RNG by argon2 itself.
    let hash = argon2id()
        .hash_password(password.as_bytes())
        .map_err(|e| anyhow::anyhow!("Password hashing failed: {}", e))?;
    Ok(hash.to_string())
}

pub async fn hash_password_async(password: String) -> Result<String> {
    tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .map_err(|e| anyhow::anyhow!("Password hashing task failed: {}", e))?
}

/// Each verify holds its Argon2 memory for the whole run, and one client's login
/// burst would otherwise allocate all of them at once. There is one admin.
const ARGON2_MAX_CONCURRENT: usize = 2;
static VERIFY_SLOTS: LazyLock<Arc<tokio::sync::Semaphore>> =
    LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(ARGON2_MAX_CONCURRENT)));

/// Verify an Argon2id password hash on a blocking thread while holding a permit
/// inside that thread so a client disconnecting mid-hash cannot leak concurrency.
/// Returns `None` if all verification slots remain saturated past the wait budget.
pub async fn verify_password_async(password: String, hash: String) -> Option<bool> {
    let permit = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        VERIFY_SLOTS.clone().acquire_owned(),
    )
    .await
    .ok()?
    .ok()?;
    Some(
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            verify_password_hash(&password, &hash)
        })
        .await
        .unwrap_or(false),
    )
}

/// Parameters come from the stored PHC string, not `argon2id()`'s.
fn verify_password_hash(password: &str, hash: &str) -> bool {
    argon2id()
        .verify_password(password.as_bytes(), hash)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A leaked permit wedges every later login, so check the answers and the count.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_verifies_are_correct_and_release_their_permits() {
        const PASSWORD: &str = "a-strong-test-password";
        let hash = hash_password(PASSWORD).expect("password hash should build");

        let tasks: Vec<_> = (0..ARGON2_MAX_CONCURRENT * 2)
            .map(|i| {
                let attempt = if i % 2 == 0 {
                    PASSWORD
                } else {
                    "wrong-password"
                };
                tokio::spawn(verify_password_async(attempt.to_string(), hash.clone()))
            })
            .collect();
        for (i, task) in tasks.into_iter().enumerate() {
            assert_eq!(
                task.await.expect("verify task should join"),
                Some(i % 2 == 0),
                "verify {i}"
            );
        }
        assert_eq!(
            VERIFY_SLOTS.available_permits(),
            ARGON2_MAX_CONCURRENT,
            "a permit leaked"
        );
    }

    /// An installed server's admin hash was written by argon2 0.5. If a later
    /// release stopped verifying it, the admin would be locked out.
    #[test]
    fn hashes_from_earlier_argon2_releases_still_verify() {
        // argon2 0.5.3, these parameters, salt "saltsaltsaltsalt", "compat-vector-pw".
        const HASH: &str = "$argon2id$v=19$m=9216,t=4,p=1$c2FsdHNhbHRzYWx0c2FsdA$k+YJy7fjLPBHMk9HdGP0Wj+vgdeYtCb5YPjZI6D2pbE";
        assert!(verify_password_hash("compat-vector-pw", HASH));
        assert!(!verify_password_hash("compat-vector-px", HASH));

        let fresh = hash_password("compat-vector-pw").expect("hash");
        assert!(
            fresh.starts_with("$argon2id$v=19$m=9216,t=4,p=1$"),
            "{fresh}"
        );
        assert!(verify_password_hash("compat-vector-pw", &fresh));
    }

    #[test]
    fn constant_time_eq_matches_equal_secrets() {
        assert!(constant_time_eq(
            b"same-token-value!!",
            b"same-token-value!!"
        ));
        assert!(!constant_time_eq(
            b"same-token-value!!",
            b"same-token-value!?"
        ));
        assert!(!constant_time_eq(b"short", b"longer-value"));
    }

    #[test]
    fn admin_session_expires_on_idle_and_on_absolute_age() {
        let auth = AuthService::default();
        for (created_ago, idle_for) in [
            (SESSION_ABSOLUTE_TTL_SECS + 1, 0),
            (2000, SESSION_IDLE_TTL.as_secs() + 1),
        ] {
            let (sid, csrf) = auth.create_admin_session();
            assert!(auth.validate_admin_session(&sid) && auth.validate_admin_csrf(&sid, &csrf));
            {
                let mut sessions = auth.admin_sessions.write();
                let session = sessions.get_mut(&sid).expect("session");
                let now = Instant::now();
                session.created_at = now - Duration::from_secs(created_ago);
                session.last_access = now - Duration::from_secs(idle_for);
            }
            assert!(!auth.validate_admin_session(&sid));
            assert!(!auth.admin_sessions.read().contains_key(&sid));
        }
    }

    #[test]
    fn passive_check_does_not_refresh_idle_deadline() {
        let auth = AuthService::default();
        let (sid, _) = auth.create_admin_session();
        let backdated = Instant::now() - Duration::from_secs(100);
        auth.admin_sessions
            .write()
            .get_mut(&sid)
            .expect("session")
            .last_access = backdated;
        assert!(auth.check_admin_session(&sid));
        assert_eq!(auth.admin_sessions.read()[&sid].last_access, backdated);
    }

    #[test]
    fn session_map_is_capped() {
        let auth = AuthService::default();
        for _ in 0..MAX_ADMIN_SESSIONS + 5 {
            auth.create_admin_session();
        }
        assert!(auth.admin_sessions.read().len() <= MAX_ADMIN_SESSIONS);
    }
}
