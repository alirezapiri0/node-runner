//! Google service-account authentication.
//!
//! A service account has no interactive login, so instead of an OAuth consent
//! flow this performs the JWT bearer grant: sign an assertion with the account's
//! RSA key, exchange it for a one-hour access token, cache the token until it
//! expires. There is no refresh token to go stale and nothing to re-authorise,
//! which is exactly why the service-account approach was chosen over user OAuth.
//!
//! The access token is held in `Zeroizing` memory and never logged. The token
//! carries no user's authority: it can only act as the service account, whose
//! reach is limited to whatever has been shared with it.

use std::sync::Mutex;
use std::time::Duration;

use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use ring::rand::SystemRandom;
use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};
use zeroize::Zeroizing;

use super::DriveError;

/// The subset of the service-account JSON this app uses.
///
/// `private_key` is deliberately not `Clone` and is wrapped in `Zeroizing`, so
/// the PEM text does not accumulate copies.
pub struct ServiceAccount {
    pub client_email: String,
    /// Present only for domain-wide delegation setups.
    pub subject: Option<String>,
    token_uri: String,
    private_key_pem: Zeroizing<String>,
}

impl ServiceAccount {
    /// Parse the JSON key file downloaded from Google Cloud.
    pub fn from_json(raw: &str) -> Result<Self, DriveError> {
        let value: serde_json::Value = serde_json::from_str(raw).map_err(|e| {
            DriveError::Config(format!("service account JSON is not valid JSON: {e}"))
        })?;

        let client_email = value["client_email"]
            .as_str()
            .ok_or_else(|| DriveError::Config("service account JSON has no client_email".into()))?
            .to_string();
        let private_key_pem = value["private_key"]
            .as_str()
            .ok_or_else(|| DriveError::Config("service account JSON has no private_key".into()))?;

        if !private_key_pem.contains("PRIVATE KEY") {
            return Err(DriveError::Config(
                "private_key does not look like a PEM block".into(),
            ));
        }

        // Optional, and only meaningful with domain-wide delegation: the user to
        // impersonate. Without it the token acts as the service account itself.
        let subject = value["subject"].as_str().map(str::to_string);

        Ok(Self {
            client_email,
            subject,
            token_uri: value["token_uri"]
                .as_str()
                .unwrap_or("https://oauth2.googleapis.com/token")
                .to_string(),
            private_key_pem: Zeroizing::new(private_key_pem.to_string()),
        })
    }

    /// The Drive scope. `drive.file` would be narrower but only grants access to
    /// files the app itself created, which breaks as soon as a folder is moved or
    /// shared by a human -- so the scope chosen here is `drive`, and the
    /// *containment* comes from sharing exactly one folder with the account.
    /// See `docs/SETUP.md`.
    pub const DRIVE_SCOPE: &'static str = "https://www.googleapis.com/auth/drive";

    /// Exchange a signed assertion for an access token.
    pub async fn access_token(
        &self,
        http: &reqwest::Client,
        now_unix: u64,
    ) -> Result<Zeroizing<String>, DriveError> {
        let assertion = self.build_assertion(now_unix)?;

        let response = http
            .post(&self.token_uri)
            .timeout(Duration::from_secs(20))
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", assertion.as_str()),
            ])
            .send()
            .await
            .map_err(|e| DriveError::Network(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            let detail: String = body.chars().take(400).collect();
            return Err(DriveError::Auth { status, detail });
        }

        let value: serde_json::Value = response
            .json()
            .await
            .map_err(|e| DriveError::Response(e.to_string()))?;

        let token = value["access_token"].as_str().ok_or_else(|| {
            DriveError::Response("token response contained no access_token".into())
        })?;

        Ok(Zeroizing::new(token.to_string()))
    }

    /// Build and sign the JWT assertion.
    fn build_assertion(&self, now_unix: u64) -> Result<Zeroizing<String>, DriveError> {
        let header = serde_json::json!({ "alg": "RS256", "typ": "JWT" });

        // One hour, minus a minute of clock skew. Longer would be rejected;
        // shorter would mean more token round trips than necessary.
        let mut claims = serde_json::json!({
            "iss": self.client_email,
            "scope": Self::DRIVE_SCOPE,
            "aud": self.token_uri,
            "iat": now_unix,
            "exp": now_unix + 3_540,
        });
        if let Some(subject) = &self.subject {
            claims["sub"] = serde_json::Value::String(subject.clone());
        }

        let header_b64 = Base64UrlUnpadded::encode_string(
            serde_json::to_string(&header)
                .map_err(|e| DriveError::Config(e.to_string()))?
                .as_bytes(),
        );
        let claims_b64 = Base64UrlUnpadded::encode_string(
            serde_json::to_string(&claims)
                .map_err(|e| DriveError::Config(e.to_string()))?
                .as_bytes(),
        );

        let signing_input = format!("{header_b64}.{claims_b64}");

        let der = pem_to_der(&self.private_key_pem)?;
        let key_pair = RsaKeyPair::from_pkcs8(&der).map_err(|e| {
            DriveError::Config(format!("private key is not a valid RSA PKCS#8 key: {e}"))
        })?;

        let mut signature = vec![0u8; key_pair.public().modulus_len()];
        key_pair
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                signing_input.as_bytes(),
                &mut signature,
            )
            .map_err(|e| DriveError::Config(format!("failed to sign the assertion: {e}")))?;

        let sig_b64 = Base64UrlUnpadded::encode_string(&signature);
        Ok(Zeroizing::new(format!("{signing_input}.{sig_b64}")))
    }
}

impl std::fmt::Debug for ServiceAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceAccount")
            .field("client_email", &self.client_email)
            .field("subject", &self.subject)
            .field("private_key", &"[redacted]")
            .finish()
    }
}

/// Extract the DER bytes from a PEM block, ignoring headers and line wrapping.
fn pem_to_der(pem: &str) -> Result<Vec<u8>, DriveError> {
    let body: String = pem
        .lines()
        .filter(|line| !line.trim_start().starts_with("-----"))
        .map(str::trim)
        .collect();
    Base64::decode_vec(&body)
        .map_err(|e| DriveError::Config(format!("private key PEM body is not valid base64: {e}")))
}

/// Assertion lifetime, and therefore how long a cached token stays usable.
const TOKEN_LIFETIME_SECS: u64 = 3_540;

/// Cached access token with its expiry.
#[derive(Default)]
pub struct TokenCache {
    inner: Mutex<Option<(Zeroizing<String>, u64)>>,
}

impl TokenCache {
    /// Return a token, refreshing it when fewer than five minutes remain.
    ///
    /// The mutex is held only for the two short synchronous reads and writes
    /// around the network call, never across the `.await`: a slow token refresh
    /// must not block unrelated Drive requests, and a guard held across an await
    /// would make the command futures non-`Send`.
    pub async fn get_or_refresh(
        &self,
        http: &reqwest::Client,
        account: &ServiceAccount,
        now_unix: u64,
    ) -> Result<Zeroizing<String>, DriveError> {
        if let Some(token) = self.cached(now_unix)? {
            return Ok(token);
        }

        let token = account.access_token(http, now_unix).await?;
        {
            let mut guard = self
                .inner
                .lock()
                .map_err(|_| DriveError::Config("token cache is poisoned".into()))?;
            *guard = Some((
                Zeroizing::new(token.as_str().to_string()),
                now_unix + TOKEN_LIFETIME_SECS,
            ));
        }
        Ok(token)
    }

    fn cached(&self, now_unix: u64) -> Result<Option<Zeroizing<String>>, DriveError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| DriveError::Config("token cache is poisoned".into()))?;
        Ok(match guard.as_ref() {
            Some((token, expires_at)) if *expires_at > now_unix + 300 => {
                Some(Zeroizing::new(token.as_str().to_string()))
            }
            _ => None,
        })
    }

    /// Drop the cache so the next call re-authenticates.
    pub fn invalidate(&self) {
        if let Ok(mut guard) = self.inner.lock() {
            *guard = None;
        }
    }
}
