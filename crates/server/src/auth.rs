//! Admin authentication: Argon2id password hashes and session-bound CSRF tokens.

use crate::api::random_hex;

use std::time::SystemTime;

use anyhow::Result;
use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use dashmap::DashMap;

const SESSION_IDLE_TTL_SECS: u64 = 300;
pub(crate) const SESSION_ABSOLUTE_TTL_SECS: u64 = 28800;
const MAX_ADMIN_SESSIONS: usize = 1_000;
pub const ADMIN_PASSWORD_MIN_LEN: usize = 12;
pub const ADMIN_PASSWORD_MAX_LEN: usize = 128;

/// Admin UI session: opaque session id + CSRF secret bound to that session.
struct AdminSession {
    csrf_token: String,
    created_at: SystemTime,
    last_access: SystemTime,
}

#[derive(Default)]
pub struct AuthService {
    admin_sessions: DashMap<String, AdminSession>,
}

impl AuthService {
    /// Returns `(session_id, csrf_token)`. The CSRF token is bound to this session only.
    pub fn create_admin_session(&self) -> (String, String) {
        self.make_room();
        let session_id = random_hex::<32>();
        let csrf_token = random_hex::<32>();
        let now = SystemTime::now();
        self.admin_sessions.insert(
            session_id.clone(),
            AdminSession {
                csrf_token: csrf_token.clone(),
                created_at: now,
                last_access: now,
            },
        );
        (session_id, csrf_token)
    }

    pub fn validate_admin_session(&self, session_id: &str) -> bool {
        if let Some(mut session) = self.admin_sessions.get_mut(session_id) {
            if admin_session_expired(&session) {
                drop(session);
                self.admin_sessions.remove(session_id);
                return false;
            }
            session.last_access = SystemTime::now();
            return true;
        }
        false
    }

    /// True when the CSRF token matches the one issued for this session (constant-time).
    pub fn validate_admin_csrf(&self, session_id: &str, csrf_token: &str) -> bool {
        self.admin_sessions.get(session_id).is_some_and(|session| {
            !admin_session_expired(&session)
                && constant_time_eq(session.csrf_token.as_bytes(), csrf_token.as_bytes())
        })
    }

    /// Anyone who can post to the login endpoint can mint sessions, so the map is
    /// capped: expired sessions go first, then the least recently used.
    fn make_room(&self) {
        if self.admin_sessions.len() < MAX_ADMIN_SESSIONS {
            return;
        }
        self.cleanup_expired();
        let excess = (self.admin_sessions.len() + 1).saturating_sub(MAX_ADMIN_SESSIONS);
        let mut oldest: Vec<(String, SystemTime)> = self
            .admin_sessions
            .iter()
            .map(|entry| (entry.key().clone(), entry.last_access))
            .collect();
        oldest.sort_by_key(|(_, last_access)| *last_access);
        for (key, _) in oldest.into_iter().take(excess) {
            self.admin_sessions.remove(&key);
        }
    }

    pub fn cleanup_expired(&self) {
        self.admin_sessions
            .retain(|_, session| !admin_session_expired(session));
    }
}

/// Constant-time equality for equal-length secrets (CSRF tokens, etc.). Different
/// lengths return false immediately: length is not secret for fixed-size tokens.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

fn admin_session_expired(session: &AdminSession) -> bool {
    elapsed_secs_since(session.last_access) > SESSION_IDLE_TTL_SECS
        || elapsed_secs_since(session.created_at) > SESSION_ABSOLUTE_TTL_SECS
}

/// Argon2id per OWASP recommendations (m=9216, t=4, p=1).
fn argon2id() -> Argon2<'static> {
    let params = Params::new(9216, 4, 1, None).expect("constant Argon2 params are valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = argon2id()
        .hash_password(password.as_bytes(), &salt)
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
static VERIFY_SLOTS: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(ARGON2_MAX_CONCURRENT);

pub async fn verify_password_async(password: String, hash: String) -> bool {
    // Static semaphore, never closed: the error arm is unreachable, and denies.
    let Ok(_permit) = VERIFY_SLOTS.acquire().await else {
        return false;
    };
    tokio::task::spawn_blocking(move || verify_password_hash(&password, &hash))
        .await
        .unwrap_or(false)
}

fn verify_password_hash(password: &str, hash: &str) -> bool {
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    PasswordHash::new(hash).is_ok_and(|parsed| {
        argon2id()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    })
}

fn elapsed_secs_since(timestamp: SystemTime) -> u64 {
    SystemTime::now()
        .duration_since(timestamp)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

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
                i % 2 == 0,
                "verify {i}"
            );
        }
        assert_eq!(
            VERIFY_SLOTS.available_permits(),
            ARGON2_MAX_CONCURRENT,
            "a permit leaked"
        );
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
            (2000, SESSION_IDLE_TTL_SECS + 1),
        ] {
            let (sid, csrf) = auth.create_admin_session();
            assert!(auth.validate_admin_session(&sid) && auth.validate_admin_csrf(&sid, &csrf));
            {
                let mut session = auth.admin_sessions.get_mut(&sid).expect("session");
                session.created_at = SystemTime::now() - Duration::from_secs(created_ago);
                session.last_access = SystemTime::now() - Duration::from_secs(idle_for);
            }
            assert!(!auth.validate_admin_session(&sid));
            assert!(!auth.admin_sessions.contains_key(&sid));
        }
    }

    #[test]
    fn session_map_is_capped() {
        let auth = AuthService::default();
        for _ in 0..MAX_ADMIN_SESSIONS + 5 {
            auth.create_admin_session();
        }
        assert!(auth.admin_sessions.len() <= MAX_ADMIN_SESSIONS);
    }
}
