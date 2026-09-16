//! Drive REST client: heartbeat, kill switch, and the snapshot ledger.
//!
//! Scope note: this client is the *only* thing in the app that can reach the
//! user's Drive, and it is reached only through a service account whose access
//! is bounded by which folders have been shared with it. It cannot enumerate the
//! user's Drive, because it was never granted access to anything else. See
//! `docs/SETUP.md`.
//!
//! The writes here are deliberately tiny and idempotent: a heartbeat line, and a
//! kill switch marker. A snapshot is never uploaded from the desktop, so a
//! misbehaving desktop can at worst disturb a marker file.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::jwt::{ServiceAccount, TokenCache};
use super::DriveError;
use crate::util::rfc3339_to_unix;

const DRIVE_API: &str = "https://www.googleapis.com/drive/v3";
const DRIVE_UPLOAD: &str = "https://www.googleapis.com/upload/drive/v3";

/// Folder the runner writes under, and the names of the markers inside it.
pub const SNAPSHOT_FOLDER_NAME: &str = "snapshots";
pub const HEARTBEAT_FILE_NAME: &str = "heartbeat.json";
pub const KILLSWITCH_FILE_NAME: &str = "KILLSWITCH.json";

/// One item in Drive.
#[derive(Debug, Clone, Serialize)]
pub struct DriveEntry {
    pub id: String,
    pub name: String,
    pub modified_unix: Option<u64>,
    pub size: Option<u64>,
    /// True for a folder, so the ledger can show snapshots rather than blobs.
    pub is_folder: bool,
}

#[derive(Debug, Deserialize)]
struct FileListEnvelope {
    #[serde(default)]
    files: Vec<FileResource>,
}

#[derive(Debug, Deserialize)]
struct FileResource {
    id: String,
    name: String,
    #[serde(default)]
    modified_time: Option<String>,
    #[serde(default)]
    size: Option<String>,
    #[serde(default)]
    mime_type: String,
}

impl FileResource {
    fn into_entry(self) -> DriveEntry {
        DriveEntry {
            id: self.id,
            name: self.name,
            modified_unix: self.modified_time.as_deref().and_then(rfc3339_to_unix),
            size: self.size.and_then(|s| s.parse().ok()),
            is_folder: self.mime_type == "application/vnd.google-apps.folder",
        }
    }
}

/// The runner's liveness record.
///
/// Doubles as the "live logs" channel. GitHub's REST API only serves run logs
/// *after* a run completes, so a real-time log view is impossible through the
/// API alone; the runner appends to a bounded tail here instead. The dashboard
/// labels it as a relayed tail rather than pretending it is a live stream.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Heartbeat {
    #[serde(default)]
    pub run_id: Option<u64>,
    #[serde(default)]
    pub slot: String,
    #[serde(default)]
    pub phase: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub commit: String,
    #[serde(default)]
    pub heartbeat_unix: Option<u64>,
    #[serde(default)]
    pub frozen_pids: u32,
    #[serde(default)]
    pub bytes_uploaded: Option<u64>,
    #[serde(default)]
    pub log_tail: Vec<String>,
}

/// The stop marker.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KillSwitch {
    #[serde(default)]
    pub engaged: bool,
    #[serde(default)]
    pub at_unix: u64,
    #[serde(default)]
    pub note: String,
}

pub struct DriveClient {
    http: reqwest::Client,
    account: ServiceAccount,
    folder_id: String,
    tokens: TokenCache,
}

impl DriveClient {
    pub fn new(service_account_json: &str, folder_id: &str) -> Result<Self, DriveError> {
        if folder_id.trim().is_empty() {
            return Err(DriveError::Config(
                "no Drive folder id configured; set it in Settings".into(),
            ));
        }
        Ok(Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .connect_timeout(Duration::from_secs(10))
                .build()
                .map_err(|e| DriveError::Network(e.to_string()))?,
            account: ServiceAccount::from_json(service_account_json)?,
            folder_id: folder_id.to_string(),
            tokens: TokenCache::default(),
        })
    }

    async fn token(&self) -> Result<Zeroizing<String>, DriveError> {
        self.tokens
            .get_or_refresh(&self.http, &self.account, nrvault::now_unix())
            .await
    }

    async fn get_json(&self, url: &str, context: &str) -> Result<serde_json::Value, DriveError> {
        let token = self.token().await?;
        let response = self
            .http
            .get(url)
            .bearer_auth(token.as_str())
            .send()
            .await
            .map_err(|e| DriveError::Network(e.to_string()))?;

        if !response.status().is_success() {
            return Err(self.classify(response, context).await);
        }
        response
            .json()
            .await
            .map_err(|e| DriveError::Response(e.to_string()))
    }

    async fn classify(&self, response: reqwest::Response, context: &str) -> DriveError {
        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();
        let detail: String = body.chars().take(400).collect();
        // 401/403 on a service account almost always means "not shared with the
        // service account", which is the single most common setup mistake. Say so.
        if status == 401 || status == 403 {
            return DriveError::Auth {
                status,
                detail: format!("{context}: {detail}"),
            };
        }
        DriveError::Api {
            status,
            detail: format!("{context}: {detail}"),
        }
    }

    /// List the direct children of a folder.
    async fn list_children(&self, parent: &str) -> Result<Vec<DriveEntry>, DriveError> {
        let query = format!("'{}' in parents and trashed = false", escape_query(parent));
        let url = format!(
            "{DRIVE_API}/files?q={}&fields=files(id,name,modifiedTime,size,mimeType)&pageSize=200&orderBy=modifiedTime desc",
            urlencode(&query)
        );
        let value = self.get_json(&url, "listing the backup folder").await?;
        let envelope: FileListEnvelope =
            serde_json::from_value(value).map_err(|e| DriveError::Response(e.to_string()))?;
        Ok(envelope
            .files
            .into_iter()
            .map(FileResource::into_entry)
            .collect())
    }

    async fn find_child(&self, name: &str) -> Result<Option<DriveEntry>, DriveError> {
        Ok(self
            .list_children(&self.folder_id)
            .await?
            .into_iter()
            .find(|e| e.name == name))
    }

    /// The snapshot folders, newest first. This is the backup ledger.
    pub async fn list_snapshots(&self) -> Result<Vec<DriveEntry>, DriveError> {
        let Some(folder) = self.find_child(SNAPSHOT_FOLDER_NAME).await? else {
            return Ok(Vec::new());
        };
        Ok(self
            .list_children(&folder.id)
            .await?
            .into_iter()
            .filter(|e| e.is_folder)
            .collect())
    }

    async fn read_text(&self, entry: &DriveEntry) -> Result<String, DriveError> {
        let token = self.token().await?;
        let url = format!("{DRIVE_API}/files/{}?alt=media", entry.id);
        let response = self
            .http
            .get(&url)
            .bearer_auth(token.as_str())
            .send()
            .await
            .map_err(|e| DriveError::Network(e.to_string()))?;
        if !response.status().is_success() {
            return Err(self.classify(response, "reading a marker file").await);
        }
        response
            .text()
            .await
            .map_err(|e| DriveError::Network(e.to_string()))
    }

    pub async fn heartbeat(&self) -> Result<Option<Heartbeat>, DriveError> {
        let Some(entry) = self.find_child(HEARTBEAT_FILE_NAME).await? else {
            return Ok(None);
        };
        let text = self.read_text(&entry).await?;
        match serde_json::from_str(&text) {
            Ok(beat) => Ok(Some(beat)),
            // A partially written heartbeat is expected during a handover; it is
            // not an error worth surfacing, just a frame to skip.
            Err(_) => Ok(None),
        }
    }

    pub async fn killswitch(&self) -> Result<KillSwitch, DriveError> {
        let Some(entry) = self.find_child(KILLSWITCH_FILE_NAME).await? else {
            return Ok(KillSwitch::default());
        };
        let text = self.read_text(&entry).await?;
        Ok(serde_json::from_str(&text).unwrap_or_default())
    }

    /// Write the stop marker, creating it if it does not exist.
    pub async fn set_killswitch(&self, engaged: bool, note: &str) -> Result<(), DriveError> {
        let marker = KillSwitch {
            engaged,
            at_unix: nrvault::now_unix(),
            note: note.to_string(),
        };
        let body =
            serde_json::to_vec_pretty(&marker).map_err(|e| DriveError::Response(e.to_string()))?;

        match self.find_child(KILLSWITCH_FILE_NAME).await? {
            Some(existing) => self.update_file(&existing.id, &body).await,
            None => {
                let metadata = format!(
                    r#"{{"name":"{}","parents":["{}"]}}"#,
                    KILLSWITCH_FILE_NAME,
                    escape_query(&self.folder_id)
                );
                self.create_file(&metadata, &body).await
            }
        }
    }

    async fn update_file(&self, file_id: &str, body: &[u8]) -> Result<(), DriveError> {
        let token = self.token().await?;
        let url = format!("{DRIVE_UPLOAD}/files/{file_id}?uploadType=media");
        let response = self
            .http
            .patch(&url)
            .bearer_auth(token.as_str())
            .header("Content-Type", "application/json")
            .body(body.to_vec())
            .send()
            .await
            .map_err(|e| DriveError::Network(e.to_string()))?;
        if !response.status().is_success() {
            return Err(self
                .classify(response, "updating the kill switch marker")
                .await);
        }
        Ok(())
    }

    /// Multipart upload, written by hand rather than pulling in a multipart
    /// crate: it is twenty lines and one fewer dependency in the binary.
    async fn create_file(&self, metadata_json: &str, body: &[u8]) -> Result<(), DriveError> {
        const BOUNDARY: &str = "node_runner_boundary_7f3a";
        let mut payload: Vec<u8> = Vec::with_capacity(body.len() + metadata_json.len() + 256);
        payload.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
        payload.extend_from_slice(b"Content-Type: application/json; charset=UTF-8\r\n\r\n");
        payload.extend_from_slice(metadata_json.as_bytes());
        payload.extend_from_slice(format!("\r\n--{BOUNDARY}\r\n").as_bytes());
        payload.extend_from_slice(b"Content-Type: application/json\r\n\r\n");
        payload.extend_from_slice(body);
        payload.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());

        let token = self.token().await?;
        let url = format!("{DRIVE_UPLOAD}/files?uploadType=multipart&fields=id");
        let response = self
            .http
            .post(&url)
            .bearer_auth(token.as_str())
            .header(
                "Content-Type",
                format!("multipart/related; boundary={BOUNDARY}"),
            )
            .body(payload)
            .send()
            .await
            .map_err(|e| DriveError::Network(e.to_string()))?;

        if !response.status().is_success() {
            return Err(self
                .classify(response, "creating the kill switch marker")
                .await);
        }
        Ok(())
    }
}

impl std::fmt::Debug for DriveClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DriveClient")
            .field("account", &self.account)
            .field("folder_id", &crate::util::truncate(&self.folder_id, 12))
            .finish()
    }
}

/// Escape a value for use inside a Drive `q` expression.
fn escape_query(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\'', "\\'")
}

/// Percent-encode a query string value.
///
/// Hand-rolled to avoid a URL crate; the alphabet is unreserved characters plus
/// the few Drive needs verbatim.
fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len() * 2);
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'~'
            | b'='
            | b'('
            | b')'
            | b'\'' => out.push(byte as char),
            b' ' => out.push_str("%20"),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}
