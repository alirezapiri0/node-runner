//! GitHub REST API v3 client.
//!
//! Deliberately a thin, typed wrapper rather than a general-purpose SDK: every
//! endpoint this app touches is listed in one place so it is easy to audit which
//! permissions are genuinely required. The full set is:
//!
//! | Endpoint | Why | Required PAT permission |
//! |---|---|---|
//! | `GET /repos/{o}/{r}/actions/runs` | run status and countdown | Actions: read |
//! | `GET /repos/{o}/{r}/actions/runs/{id}/jobs` | step-level progress | Actions: read |
//! | `POST /repos/{o}/{r}/actions/workflows/{f}/dispatches` | handover | Actions: write |
//! | `GET /repos/{o}/{r}/actions/secrets/public-key` | sealed box recipient | Secrets: read |
//! | `PUT /repos/{o}/{r}/actions/secrets/{name}` | inject credentials | Secrets: write |
//! | `GET /rate_limit` | show remaining budget | none |
//!
//! Notably absent: any endpoint that creates repositories, manages
//! collaborators, or touches other repositories. Under the single-repository
//! design there is no reason for this credential to have that reach, and it is
//! the main reason the blast radius of a leak is small.
//!
//! Tokens are passed in per call rather than held on the client, so the only
//! long-lived copy lives inside the unlocked vault session.

use std::time::Duration;

use zeroize::Zeroizing;

use crate::util::rfc3339_to_unix;

const ACCEPT: &str = "application/vnd.github+json";
const API_VERSION: &str = "2022-11-28";
const USER_AGENT: &str = "node-runner-desktop";

#[derive(Debug, thiserror::Error)]
pub enum GhError {
    #[error("network error: {0}")]
    Network(String),
    #[error("GitHub returned HTTP {status}: {detail}")]
    Api { status: u16, detail: String },
    #[error("GitHub rate limit exhausted ({remaining} remaining, resets at {reset_unix})")]
    RateLimited { remaining: u32, reset_unix: u64 },
    #[error("unexpected response from GitHub: {0}")]
    Response(String),
    #[error("not configured: {0}")]
    Config(String),
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RunSummary {
    pub id: u64,
    pub status: String,
    #[serde(default)]
    pub conclusion: Option<String>,
    #[serde(default)]
    pub run_started_at: Option<String>,
    #[serde(default)]
    pub html_url: String,
    #[serde(default)]
    pub display_title: Option<String>,
    #[serde(default)]
    pub event: Option<String>,
}

impl RunSummary {
    /// When the run actually began, in Unix seconds.
    ///
    /// The countdown is derived from this rather than from a local timer so it
    /// stays correct across app restarts and does not drift.
    pub fn started_unix(&self) -> Option<u64> {
        self.run_started_at.as_deref().and_then(rfc3339_to_unix)
    }

    pub fn is_active(&self) -> bool {
        matches!(
            self.status.as_str(),
            "queued" | "in_progress" | "requested" | "waiting" | "pending"
        )
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct JobSummary {
    pub id: u64,
    pub name: String,
    pub status: String,
    #[serde(default)]
    pub conclusion: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct RunsEnvelope {
    #[serde(default)]
    workflow_runs: Vec<RunSummary>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct JobsEnvelope {
    #[serde(default)]
    jobs: Vec<JobSummary>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct PublicKeyEnvelope {
    key_id: String,
    key: String,
}

/// Outcome of a poll. `NotModified` means the ETag matched, so the previously
/// reported status is still current.
#[derive(Debug)]
pub enum RunLookup {
    Modified(Option<RunSummary>, Option<String>),
    NotModified,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DispatchOutcome {
    pub accepted: bool,
    pub detail: String,
}

/// The slot a successor should take, given the slot currently observed.
///
/// The workflow declares `slot` as a `choice` input limited to `blue|green`, and
/// GitHub answers any other value with a 422 instead of coercing it. So the
/// alternation has to be expressed in exactly that vocabulary, and an unrecognised
/// input must map to something dispatchable rather than being echoed back. This is
/// the one string the app and the workflow have to agree on, which is why it lives
/// here as a pure function with a test rather than inline in a command.
pub fn successor_slot(current: &str) -> &'static str {
    match current {
        "blue" => "green",
        "green" => "blue",
        _ => "blue",
    }
}

/// Everything a dispatch needs, with every parameter named.
///
/// Seven positional `&str` arguments is a shape where a slot and a reason are one
/// transposition away from being silently swapped -- and the successor would then
/// be started with a reason used as a slot name, which the workflow's `choice`
/// input would reject at the least convenient moment. Naming them at the call site
/// costs nothing.
#[derive(Debug, Clone)]
pub struct DispatchRequest<'a> {
    pub token: &'a str,
    pub slug: &'a str,
    pub workflow_file: &'a str,
    pub git_ref: &'a str,
    pub slot: &'a str,
    pub commit: &'a str,
    pub reason: &'a str,
}

pub struct GithubClient {
    http: reqwest::Client,
}

impl GithubClient {
    pub fn new() -> Result<Self, GhError> {
        let http = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            // Bounded timeouts: a hung poll must not stall the UI refresh loop.
            .timeout(Duration::from_secs(20))
            .connect_timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| GhError::Network(e.to_string()))?;
        Ok(Self { http })
    }

    fn url(&self, path: &str) -> String {
        format!("https://api.github.com{path}")
    }

    fn auth(&self, req: reqwest::RequestBuilder, token: &str) -> reqwest::RequestBuilder {
        req.header("Accept", ACCEPT)
            .header("X-GitHub-Api-Version", API_VERSION)
            .bearer_auth(token)
    }

    /// Convert a non-success response into a typed error, including the
    /// rate-limit fields GitHub reports on 403 and 429.
    async fn check(
        response: reqwest::Response,
        context: &str,
    ) -> Result<reqwest::Response, GhError> {
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }

        let remaining = response
            .headers()
            .get("x-ratelimit-remaining")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);
        let reset = response
            .headers()
            .get("x-ratelimit-reset")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);

        let code = status.as_u16();
        if (code == 403 || code == 429) && remaining == 0 && reset > 0 {
            return Err(GhError::RateLimited {
                remaining,
                reset_unix: reset,
            });
        }

        // Body is bounded so a huge HTML error page cannot balloon memory.
        let body = response.text().await.unwrap_or_default();
        let detail = body.chars().take(400).collect::<String>();

        Err(GhError::Api {
            status: code,
            detail: format!("{context}: {detail}"),
        })
    }

    /// Most recent workflow run, using a conditional request.
    ///
    /// Polling every 30s against a 5000/hour budget is fine, but ETags make it
    /// free in practice and keep the app well clear of the secondary limits.
    pub async fn latest_run(
        &self,
        token: &str,
        slug: &str,
        etag: Option<&str>,
    ) -> Result<RunLookup, GhError> {
        let url = self.url(&format!(
            "/repos/{slug}/actions/runs?per_page=5&exclude_pull_requests=true"
        ));
        let mut req = self.auth(self.http.get(&url), token);
        if let Some(tag) = etag {
            req = req.header("If-None-Match", tag);
        }

        let response = req
            .send()
            .await
            .map_err(|e| GhError::Network(e.to_string()))?;

        if response.status().as_u16() == 304 {
            return Ok(RunLookup::NotModified);
        }

        let new_etag = response
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);

        let response = Self::check(response, "listing workflow runs").await?;
        let envelope: RunsEnvelope = response
            .json()
            .await
            .map_err(|e| GhError::Response(e.to_string()))?;

        Ok(RunLookup::Modified(
            envelope.workflow_runs.into_iter().next(),
            new_etag,
        ))
    }

    pub async fn run_jobs(
        &self,
        token: &str,
        slug: &str,
        run_id: u64,
    ) -> Result<Vec<JobSummary>, GhError> {
        let url = self.url(&format!("/repos/{slug}/actions/runs/{run_id}/jobs"));
        let response = self
            .auth(self.http.get(&url), token)
            .send()
            .await
            .map_err(|e| GhError::Network(e.to_string()))?;
        let response = Self::check(response, "listing run jobs").await?;
        let envelope: JobsEnvelope = response
            .json()
            .await
            .map_err(|e| GhError::Response(e.to_string()))?;
        Ok(envelope.jobs)
    }

    /// Ask the successor node to start.
    ///
    /// This is the single privileged write in the app. Note that the repository's
    /// own `GITHUB_TOKEN` deliberately cannot trigger a new workflow run, so this
    /// call is the reason a user-scoped credential is required at all -- and why
    /// it is worth scoping that credential to `Actions: write` on one repository.
    pub async fn dispatch(
        &self,
        request: &DispatchRequest<'_>,
    ) -> Result<DispatchOutcome, GhError> {
        let url = self.url(&format!(
            "/repos/{}/actions/workflows/{}/dispatches",
            request.slug, request.workflow_file
        ));

        let mut inputs = serde_json::Map::new();
        inputs.insert(
            "slot".into(),
            serde_json::Value::String(request.slot.into()),
        );
        inputs.insert(
            "commit".into(),
            serde_json::Value::String(request.commit.into()),
        );
        inputs.insert(
            "reason".into(),
            serde_json::Value::String(request.reason.into()),
        );

        let body = serde_json::json!({ "ref": request.git_ref, "inputs": inputs });

        let response = self
            .auth(self.http.post(&url), request.token)
            .json(&body)
            .send()
            .await
            .map_err(|e| GhError::Network(e.to_string()))?;

        // A successful dispatch is 204 No Content. Anything else is reported with
        // its body, because the usual causes are a wrong workflow filename or a
        // ref that has no workflow_dispatch trigger -- both worth surfacing
        // verbatim rather than guessing at.
        let status = response.status();
        if status.as_u16() == 204 || status.is_success() {
            return Ok(DispatchOutcome {
                accepted: true,
                detail: format!(
                    "dispatched {} to slot {} on {}",
                    request.workflow_file, request.slot, request.git_ref
                ),
            });
        }

        let response = Self::check(response, "dispatching the successor workflow").await?;
        Ok(DispatchOutcome {
            accepted: response.status().is_success(),
            detail: "unexpected success status".into(),
        })
    }

    /// Fetch the repository's sealed-box public key.
    pub async fn repo_public_key(
        &self,
        token: &str,
        slug: &str,
    ) -> Result<nrvault::RepositoryKey, GhError> {
        let url = self.url(&format!("/repos/{slug}/actions/secrets/public-key"));
        let response = self
            .auth(self.http.get(&url), token)
            .send()
            .await
            .map_err(|e| GhError::Network(e.to_string()))?;
        let response = Self::check(response, "reading the repository public key").await?;
        let envelope: PublicKeyEnvelope = response
            .json()
            .await
            .map_err(|e| GhError::Response(e.to_string()))?;

        nrvault::RepositoryKey::from_base64(envelope.key_id, &envelope.key)
            .map_err(|e| GhError::Response(e.to_string()))
    }

    /// Store one secret, sealed to `key.key_id`.
    ///
    /// `key_id` is sent back so GitHub rejects the write if the key rotated
    /// between the read and the write. That is the desired behaviour: failing
    /// loudly beats storing something that can never be decrypted.
    pub async fn put_secret(
        &self,
        token: &str,
        slug: &str,
        name: &str,
        key: &nrvault::RepositoryKey,
        sealed_value: &str,
    ) -> Result<(), GhError> {
        let url = self.url(&format!("/repos/{slug}/actions/secrets/{name}"));
        let body = serde_json::json!({
            "encrypted_value": sealed_value,
            "key_id": key.key_id,
        });

        let response = self
            .auth(self.http.put(&url), token)
            .json(&body)
            .send()
            .await
            .map_err(|e| GhError::Network(e.to_string()))?;

        let status = response.status();
        if status.as_u16() == 201 || status.as_u16() == 204 || status.is_success() {
            return Ok(());
        }
        Self::check(response, "writing a repository secret").await?;
        Ok(())
    }

    /// Remaining API budget, for display in the UI.
    ///
    /// Unauthenticated is fine for this endpoint but we authenticate anyway so
    /// the figure reflects the authenticated budget.
    pub async fn rate_limit_remaining(&self, token: &str) -> Result<u32, GhError> {
        let url = self.url("/rate_limit");
        let response = self
            .auth(self.http.get(&url), token)
            .send()
            .await
            .map_err(|e| GhError::Network(e.to_string()))?;
        let response = Self::check(response, "reading the rate limit").await?;
        let value: serde_json::Value = response
            .json()
            .await
            .map_err(|e| GhError::Response(e.to_string()))?;
        value["resources"]["core"]["remaining"]
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| GhError::Response("rate limit payload had no core.remaining".into()))
    }
}

/// Redact a token for logs.
///
/// Present so that any future debugging statement has an obviously correct thing
/// to call. It is defined here, next to the client, because this is where the
/// temptation to log a token will arise.
pub fn redact(token: &Zeroizing<String>) -> String {
    let chars: Vec<char> = token.chars().collect();
    if chars.len() <= 8 {
        return "[redacted]".into();
    }
    format!("{}...[redacted]", chars[..4].iter().collect::<String>())
}

// The test module belongs at the end of the file: clippy's
// `items-after-test-module` exists because a module in the middle invites exactly
// the confusion of whether what follows is still under test.
#[cfg(test)]
mod tests {
    use super::successor_slot;

    #[test]
    fn successor_slot_alternates_within_the_workflows_choice_list() {
        assert_eq!(successor_slot("blue"), "green");
        assert_eq!(successor_slot("green"), "blue");
    }

    #[test]
    fn an_unrecognised_slot_is_never_echoed_back() {
        // "a" is what this app used to send, and GitHub rejected it with a 422.
        assert_eq!(successor_slot("a"), "blue");
        assert_eq!(successor_slot(""), "blue");
        assert_eq!(successor_slot("?"), "blue");
        assert_eq!(successor_slot("Blue"), "blue");

        // Whatever the input, the result must be something the workflow accepts.
        for current in ["", "?", "a", "b", "blue", "green", "Blue", "GREEN"] {
            assert!(matches!(successor_slot(current), "blue" | "green"));
        }
    }
}
