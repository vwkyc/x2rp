//! TLS Certificate Management
//!
//! Obtains and renews wildcard TLS certificates from Let's Encrypt
//! using ACME DNS-01 validation via Cloudflare DNS API.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, bail};
use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus, RetryPolicy,
};
use serde::Deserialize;

pub const CERT_FILE: &str = "/var/lib/x2rp/certs/fullchain.pem";
pub const KEY_FILE: &str = "/var/lib/x2rp/certs/privkey.pem";
const ACME_ACCOUNT_FILE: &str = "/var/lib/x2rp/acme_account.json";
const RENEWAL_THRESHOLD_DAYS: i64 = 30;
const DNS_PROPAGATION_WAIT: Duration = Duration::from_secs(60);

pub struct CertManager {
    domain: String,
    cf_api_token: String,
}

fn dns01_record_name(identifier: &Identifier, fallback_domain: &str) -> String {
    match identifier {
        Identifier::Dns(name) => {
            format!(
                "_acme-challenge.{}",
                name.strip_prefix("*.").unwrap_or(name)
            )
        }
        _ => format!("_acme-challenge.{fallback_domain}"),
    }
}

/// Days until the leaf certificate expires; `None` if it is missing or unreadable.
fn days_until_expiry() -> Option<i64> {
    let pem_bytes = std::fs::read(CERT_FILE).ok()?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(&pem_bytes).ok()?;
    let (_, cert) = x509_parser::parse_x509_certificate(&pem.contents).ok()?;
    Some((cert.validity().not_after.timestamp() - chrono::Utc::now().timestamp()) / 86400)
}

impl CertManager {
    pub fn new(domain: String, cf_api_token: String) -> Self {
        Self {
            domain,
            cf_api_token,
        }
    }

    /// Obtain or renew via Let's Encrypt when the certificate or its key is missing,
    /// or it expires within [`RENEWAL_THRESHOLD_DAYS`]. `Ok(true)` when it did.
    pub async fn ensure_certs(&self) -> anyhow::Result<bool> {
        match days_until_expiry() {
            Some(days) if days >= RENEWAL_THRESHOLD_DAYS && Path::new(KEY_FILE).exists() => {
                tracing::info!("TLS certificate valid ({days} days until expiry)");
                return Ok(false);
            }
            Some(_) => tracing::info!("TLS certificate expiring soon, renewing..."),
            None => tracing::info!("No TLS certificate found, obtaining from Let's Encrypt..."),
        }
        self.obtain_certificate().await?;
        Ok(true)
    }

    async fn obtain_certificate(&self) -> anyhow::Result<()> {
        let account = load_or_create_account().await?;
        let identifiers = [
            Identifier::Dns(self.domain.clone()),
            Identifier::Dns(format!("*.{}", self.domain)),
        ];
        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .context("Failed to create ACME order")?;

        let cf = CloudflareDns::new(&self.cf_api_token);
        let zone_id = cf
            .find_zone_id(&self.domain)
            .await
            .context("Failed to find Cloudflare zone")?;

        let mut record_ids = Vec::new();
        let validated = self
            .validate(&mut order, &cf, &zone_id, &mut record_ids)
            .await;
        // Always clean up DNS TXT records
        for id in &record_ids {
            if let Err(e) = cf.delete_txt_record(&zone_id, id).await {
                tracing::warn!("Failed to clean up DNS TXT record {id}: {e}");
            }
        }
        validated?;

        // instant-acme generates the key pair and the CSR for the order's identifiers.
        let key_pem = order.finalize().await.context("ACME finalize failed")?;
        let cert_chain_pem = order
            .poll_certificate(&RetryPolicy::default())
            .await
            .context("ACME certificate download failed")?;
        // Key first: the certificate is the commit. A crash or failed write between the
        // two leaves the old, expiring certificate, which the next start renews. The
        // other order would leave a fresh certificate with the old key: `ensure_certs`
        // skips it and every start fails to load the pair.
        crate::api::save_secure_file(Path::new(KEY_FILE), key_pem.as_bytes())?;
        crate::api::save_secure_file(Path::new(CERT_FILE), cert_chain_pem.as_bytes())?;
        tracing::info!("✓ TLS certificate saved to {CERT_FILE}");
        Ok(())
    }

    async fn validate(
        &self,
        order: &mut instant_acme::Order,
        cf: &CloudflareDns,
        zone_id: &str,
        record_ids: &mut Vec<String>,
    ) -> anyhow::Result<()> {
        let mut authorizations = order.authorizations();
        while let Some(auth) = authorizations.next().await {
            let mut auth = auth?;
            let record_name = dns01_record_name(auth.identifier().identifier, &self.domain);
            let challenge = auth
                .challenge(ChallengeType::Dns01)
                .context("No DNS-01 challenge in authorization")?;
            let dns_value = challenge.key_authorization().dns_value();
            tracing::info!("Creating DNS TXT: {record_name} = {}…", &dns_value[..8]);
            record_ids.push(
                cf.create_txt_record(zone_id, &record_name, &dns_value)
                    .await?,
            );
        }

        // A fixed wait, not a resolver poll: recursive views lag the authoritative one.
        tracing::info!(
            "Waiting {}s for DNS propagation before ACME validation...",
            DNS_PROPAGATION_WAIT.as_secs()
        );
        tokio::time::sleep(DNS_PROPAGATION_WAIT).await;

        let mut authorizations = order.authorizations();
        while let Some(auth) = authorizations.next().await {
            let mut auth = auth?;
            let mut challenge = auth
                .challenge(ChallengeType::Dns01)
                .context("No DNS-01 challenge in authorization")?;
            challenge.set_ready().await?;
        }

        let retry = RetryPolicy::new()
            .initial_delay(Duration::from_secs(5))
            .backoff(1.0)
            .timeout(Duration::from_secs(180));
        let status = order.poll_ready(&retry).await?;
        if status == OrderStatus::Ready {
            tracing::info!("ACME validation succeeded");
            return Ok(());
        }
        let mut authorizations = order.authorizations();
        while let Some(Ok(auth)) = authorizations.next().await {
            for ch in &auth.challenges {
                tracing::error!(
                    "ACME {:?}: challenge {:?} {:?} error={:?}",
                    auth.identifier(),
                    ch.r#type,
                    ch.status,
                    ch.error
                );
            }
        }
        bail!("ACME validation failed (order {status:?})")
    }
}

async fn load_or_create_account() -> anyhow::Result<Account> {
    let path = Path::new(ACME_ACCOUNT_FILE);
    if path.exists() {
        let creds: AccountCredentials =
            serde_json::from_slice(&x2rp_proto::read_secret_file(path, 0o600)?)?;
        return Ok(Account::builder()?.from_credentials(creds).await?);
    }

    tracing::info!("Creating new ACME account...");
    let (account, creds) = Account::builder()?
        .create(
            &NewAccount {
                contact: &[],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            LetsEncrypt::Production.url().to_string(),
            None,
        )
        .await?;
    crate::api::save_secure_file(path, serde_json::to_string_pretty(&creds)?.as_bytes())?;
    Ok(account)
}

// ── Cloudflare DNS API ──────────────────────────────────────────────────────

struct CloudflareDns {
    api_token: String,
    client: reqwest::Client,
}

#[derive(Deserialize)]
struct CfResponse<T> {
    success: bool,
    result: T,
    errors: Vec<CfError>,
}

impl<T> CfResponse<T> {
    fn into_result(self, context: &str) -> anyhow::Result<T> {
        if self.success {
            return Ok(self.result);
        }
        let msgs: Vec<&str> = self.errors.iter().map(|e| e.message.as_str()).collect();
        bail!("{}: {}", context, msgs.join(", "));
    }
}

#[derive(Deserialize)]
struct CfError {
    message: String,
}

#[derive(Deserialize)]
struct CfId {
    id: String,
}

const CF_API: &str = "https://api.cloudflare.com/client/v4/zones";

impl CloudflareDns {
    fn new(api_token: &str) -> Self {
        Self {
            api_token: api_token.to_string(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("failed to build HTTP client"),
        }
    }

    async fn find_zone_id(&self, domain: &str) -> anyhow::Result<String> {
        let resp: CfResponse<Vec<CfId>> = self
            .client
            // The domain passed `is_valid_domain` at setup: nothing to escape.
            .get(format!("{CF_API}?name={domain}"))
            .bearer_auth(&self.api_token)
            .send()
            .await
            .context("Cloudflare API request failed")?
            .json()
            .await
            .context("Invalid Cloudflare API response")?;

        resp.into_result("Cloudflare zone lookup failed")?
            .into_iter()
            .next()
            .map(|zone| zone.id)
            .with_context(|| {
                format!("No Cloudflare zone found for '{domain}', check your API token permissions")
            })
    }

    async fn create_txt_record(
        &self,
        zone_id: &str,
        name: &str,
        content: &str,
    ) -> anyhow::Result<String> {
        let resp: CfResponse<CfId> = self
            .client
            .post(format!("{CF_API}/{zone_id}/dns_records"))
            .bearer_auth(&self.api_token)
            .json(&serde_json::json!({
                "type": "TXT",
                "name": name,
                "content": content,
                "ttl": 120
            }))
            .send()
            .await?
            .json()
            .await?;
        Ok(resp.into_result("Failed to create TXT record")?.id)
    }

    async fn delete_txt_record(&self, zone_id: &str, record_id: &str) -> anyhow::Result<()> {
        self.client
            .delete(format!("{CF_API}/{zone_id}/dns_records/{record_id}"))
            .bearer_auth(&self.api_token)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}

/// The certificate every TLS listener serves, the HTTPS proxy and QUIC alike. A
/// renewal swaps it in place, so neither listener restarts and no connection drops.
#[derive(Debug)]
pub struct CertStore {
    cert_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
    current: parking_lot::RwLock<std::sync::Arc<rustls::sign::CertifiedKey>>,
}

impl CertStore {
    pub fn load(cert_path: &str, key_path: &str) -> anyhow::Result<std::sync::Arc<Self>> {
        let (cert_path, key_path) = (Path::new(cert_path), Path::new(key_path));
        let current = load_certified_key(cert_path, key_path)?;
        Ok(std::sync::Arc::new(Self {
            cert_path: cert_path.to_path_buf(),
            key_path: key_path.to_path_buf(),
            current: parking_lot::RwLock::new(std::sync::Arc::new(current)),
        }))
    }

    /// Serve the certificate now on disk from the next handshake on. On error the
    /// old one stays in service.
    pub fn reload(&self) -> anyhow::Result<()> {
        let fresh = load_certified_key(&self.cert_path, &self.key_path)?;
        *self.current.write() = std::sync::Arc::new(fresh);
        Ok(())
    }

    pub fn current(&self) -> std::sync::Arc<rustls::sign::CertifiedKey> {
        self.current.read().clone()
    }
}

impl rustls::server::ResolvesServerCert for CertStore {
    fn resolve(
        &self,
        _hello: rustls::server::ClientHello<'_>,
    ) -> Option<std::sync::Arc<rustls::sign::CertifiedKey>> {
        Some(self.current())
    }
}

/// The chain and its key, checked to belong together. Collecting the chain's
/// Results rather than filtering them keeps a corrupt intermediate from silently
/// shortening it.
fn load_certified_key(
    cert_path: &Path,
    key_path: &Path,
) -> anyhow::Result<rustls::sign::CertifiedKey> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

    let cert_pem =
        std::fs::read(cert_path).with_context(|| format!("reading {}", cert_path.display()))?;
    // Refuses a key readable by anyone but us.
    let key_pem = x2rp_proto::read_secret_file(key_path, 0o600)
        .with_context(|| format!("reading TLS private key {}", key_path.display()))?;
    let chain = CertificateDer::pem_slice_iter(&cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("parsing {}", cert_path.display()))?;
    let key = PrivateKeyDer::from_pem_slice(&key_pem)
        .with_context(|| format!("parsing {}", key_path.display()))?;
    let provider = rustls::crypto::CryptoProvider::get_default()
        .context("no rustls crypto provider installed")?;
    rustls::sign::CertifiedKey::from_der(chain, key, provider)
        .context("the TLS certificate and key do not match")
}

#[cfg(test)]
mod tests {
    use super::{CertStore, dns01_record_name};
    use instant_acme::Identifier;

    /// What a renewal relies on: `reload` puts the new certificate in service, and a
    /// bad file on disk leaves the old one serving instead of taking TLS down.
    #[test]
    fn reload_swaps_the_certificate_and_keeps_it_on_a_bad_file() {
        use std::os::unix::fs::PermissionsExt;

        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().expect("tempdir");
        let (cert, key) = (
            dir.path().join("fullchain.pem"),
            dir.path().join("privkey.pem"),
        );
        let write = |name: &str| {
            let issued = rcgen::generate_simple_self_signed(vec![name.to_string()]).expect("cert");
            std::fs::write(&cert, issued.cert.pem()).expect("write cert");
            std::fs::write(&key, issued.signing_key.serialize_pem()).expect("write key");
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).expect("chmod");
            issued.cert.der().clone()
        };

        let first = write("old.example");
        let store = CertStore::load(cert.to_str().unwrap(), key.to_str().unwrap()).expect("load");
        assert_eq!(store.current().cert[0], first);

        let second = write("new.example");
        store.reload().expect("reload");
        assert_eq!(
            store.current().cert[0],
            second,
            "the renewed cert is served"
        );

        std::fs::write(&cert, "not a certificate").expect("corrupt");
        assert!(store.reload().is_err());
        assert_eq!(
            store.current().cert[0],
            second,
            "a bad file keeps the last good cert"
        );
    }

    #[test]
    fn dns01_record_name_strips_wildcard_prefix() {
        for name in ["*.example.com", "example.com"] {
            assert_eq!(
                dns01_record_name(&Identifier::Dns(name.to_string()), "fallback.example"),
                "_acme-challenge.example.com"
            );
        }
    }
}
