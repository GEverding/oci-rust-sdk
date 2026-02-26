//! OCI Object Storage client.
//!
//! Provides [`ObjectStorageClient`] for interacting with the
//! [Oracle Cloud Infrastructure Object Storage](https://docs.oracle.com/en-us/iaas/Content/Object/home.htm) service.
//!
//! # Operations
//! - [`ObjectStorageClient::list_objects`] — List objects with prefix filtering and pagination
//! - [`ObjectStorageClient::restore_objects`] — Restore archived objects
//! - [`ObjectStorageClient::head_object`] — Get object metadata
//! - [`ObjectStorageClient::get_object`] — Streaming object download
//! - [`ObjectStorageClient::put_object`] — Upload objects
//! - [`ObjectStorageClient::upload_file`] — High-level multipart upload with parallel parts
//! - [`ObjectStorageClient::create_multipart_upload`] — Low-level: initiate multipart upload
//! - [`ObjectStorageClient::upload_part`] — Low-level: upload a single part
//! - [`ObjectStorageClient::commit_multipart_upload`] — Low-level: commit multipart upload
//! - [`ObjectStorageClient::abort_multipart_upload`] — Low-level: abort multipart upload
//! - [`ObjectStorageClient::create_preauthenticated_request`] — Create a pre-authenticated request (PAR)
//! - [`ObjectStorageClient::get_preauthenticated_request`] — Get PAR details
//! - [`ObjectStorageClient::list_preauthenticated_requests`] — List PARs
//! - [`ObjectStorageClient::delete_preauthenticated_request`] — Delete a PAR
//!
//! # Example
//! ```no_run
//! use oci_sdk::objectstorage::{ObjectStorageClient, ListObjectsRequest};
//! use oci_sdk::auth::ConfigFileAuth;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let auth = ConfigFileAuth::from_file(None, None)?;
//! let client = ObjectStorageClient::new(auth, "my-namespace", None).await?;
//!
//! let request = ListObjectsRequest {
//!     prefix: Some("data/"),
//!     limit: Some(100),
//!     ..Default::default()
//! };
//! let resp = client.list_objects("my-bucket", &request).await?;
//! for obj in &resp.objects {
//!     println!("{}", obj.name);
//! }
//! # Ok(())
//! # }
//! ```

use crate::auth::{encode_body, AuthProvider};
use chrono::Utc;
use futures_core::Stream;
use futures_util::StreamExt;
use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tracing::warn;

/// Errors returned by [`ObjectStorageClient`] operations.
#[derive(Debug, thiserror::Error)]
pub enum ObjectStorageError {
    /// An authentication or request-signing failure.
    #[error("auth error: {0}")]
    Auth(#[from] crate::auth::AuthError),

    /// An underlying HTTP transport error from `reqwest`.
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    /// OCI returned HTTP 429; back off before retrying.
    #[error(
        "rate limited: retry after {retry_after_secs:?}s (opc-request-id: {opc_request_id:?})"
    )]
    RateLimited {
        /// OCI correlation ID for the throttled request.
        opc_request_id: Option<String>,
        /// Suggested back-off in seconds from the `Retry-After` header, if present.
        retry_after_secs: Option<u64>,
    },

    /// OCI returned a non-2xx, non-429 status code with a structured error body.
    #[error("api error {status}: {code} - {message} (opc-request-id: {opc_request_id:?})")]
    Api {
        /// HTTP status code.
        status: u16,
        /// OCI error code string (e.g. `"BucketNotFound"`).
        code: String,
        /// Human-readable error message from OCI.
        message: String,
        /// OCI correlation ID for the failed request.
        opc_request_id: Option<String>,
    },

    /// JSON serialization or deserialization failed.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// A constructed HTTP header value was invalid.
    #[error("invalid header: {0}")]
    InvalidHeader(#[from] reqwest::header::InvalidHeaderValue),

    /// I/O error reading from source.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Deserialize)]
struct OciErrorResponse {
    code: String,
    message: String,
}

/// Object Storage tier controlling cost and retrieval latency.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub enum StorageTier {
    /// Default tier — low latency, highest cost.
    Standard,
    /// Reduced-cost tier for infrequently accessed data.
    InfrequentAccess,
    /// Lowest-cost tier; objects must be restored before download. See [`ArchivalState`].
    Archive,
}

/// Lifecycle state of an [`Archive`](StorageTier::Archive)-tier object.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub enum ArchivalState {
    /// Object is in cold storage and cannot be downloaded yet.
    Archived,
    /// Restore is in progress; download not yet available.
    Restoring,
    /// Object has been restored and is available for download until the restore window expires.
    Restored,
}

/// Details for restoring an archived object.
///
/// Use the builder pattern to construct:
/// ```
/// # use oci_sdk::objectstorage::RestoreObjectsDetails;
/// let details = RestoreObjectsDetails::new("my-object.tar")
///     .hours(48)
///     .version_id("abc123");
/// ```
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreObjectsDetails {
    /// Full object name (including any prefix path) to restore.
    pub object_name: String,
    /// How long (in hours) the restored object remains accessible. Must be 1–240.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hours: Option<u32>,
    /// Specific object version to restore; omit for the latest version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,
}

impl RestoreObjectsDetails {
    /// Create restore details for the given object name.
    ///
    /// Default restore duration is 24 hours (set by OCI when `hours` is omitted).
    pub fn new(object_name: impl Into<String>) -> Self {
        Self {
            object_name: object_name.into(),
            hours: None,
            version_id: None,
        }
    }

    /// Set the number of hours the restored object will be available (1–240).
    ///
    /// Validated when passed to [`ObjectStorageClient::restore_objects`].
    pub fn hours(mut self, hours: u32) -> Self {
        self.hours = Some(hours);
        self
    }

    /// Set the version ID of the object to restore.
    pub fn version_id(mut self, version_id: impl Into<String>) -> Self {
        self.version_id = Some(version_id.into());
        self
    }
}

/// Response from [`ObjectStorageClient::restore_objects`].
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[must_use]
pub struct RestoreObjectsResponse {
    /// OCI correlation ID for the restore request.
    pub opc_request_id: Option<String>,
}

/// Parameters for [`ObjectStorageClient::list_objects`].
///
/// All fields are optional. Paginate by passing the previous response's
/// [`ListObjectsResponse::next_start_with`] as `start` on the next call.
#[derive(Debug, Default)]
pub struct ListObjectsRequest<'a> {
    /// Return only objects whose names begin with this string.
    pub prefix: Option<&'a str>,
    /// Return objects whose names are lexicographically ≥ this value (inclusive lower bound).
    pub start: Option<&'a str>,
    /// Return objects whose names are lexicographically < this value (exclusive upper bound).
    pub end: Option<&'a str>,
    /// Group objects sharing a common prefix up to this delimiter into [`ListObjectsResponse::prefixes`].
    pub delimiter: Option<&'a str>,
    /// Maximum number of objects to return per page (OCI default: 1000).
    pub limit: Option<u32>,
    /// Comma-separated extra fields to include on each [`ObjectSummary`] (e.g. `"size,etag,timeCreated,md5,storageTier,archivalState"`).
    pub fields: Option<&'a str>,
    /// Return objects whose names are lexicographically > this value (exclusive lower bound, alternative to `start`).
    pub start_after: Option<&'a str>,
}

/// Summary of a single object returned by [`ObjectStorageClient::list_objects`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObjectSummary {
    /// Object name including any prefix path (e.g. `"data/2024/file.parquet"`).
    pub name: String,
    /// Object size in bytes; present only when `fields` includes `"size"`.
    #[serde(default)]
    pub size: Option<u64>,
    /// Entity tag for conditional requests; present only when `fields` includes `"etag"`.
    #[serde(default)]
    pub etag: Option<String>,
    /// RFC 3339 creation timestamp; present only when `fields` includes `"timeCreated"`.
    #[serde(default)]
    pub time_created: Option<String>,
    /// Base64-encoded MD5 of the object content; present only when `fields` includes `"md5"`.
    #[serde(default)]
    pub md5: Option<String>,
    /// Storage tier; present only when `fields` includes `"storageTier"`.
    #[serde(default)]
    pub storage_tier: Option<StorageTier>,
    /// Archival lifecycle state; present only when `fields` includes `"archivalState"`.
    #[serde(default)]
    pub archival_state: Option<ArchivalState>,
}

/// Response from [`ObjectStorageClient::list_objects`].
///
/// If [`next_start_with`](Self::next_start_with) is `Some`, pass it as
/// [`ListObjectsRequest::start`] to fetch the next page.
#[must_use]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListObjectsResponse {
    /// Objects matching the request parameters.
    pub objects: Vec<ObjectSummary>,
    /// Common prefixes when a `delimiter` was specified; empty otherwise.
    #[serde(default)]
    pub prefixes: Vec<String>,
    /// Pagination cursor — pass as [`ListObjectsRequest::start`] to get the next page; `None` on the last page.
    pub next_start_with: Option<String>,
    /// OCI correlation ID for the list request.
    #[serde(skip)]
    pub opc_request_id: Option<String>,
}

/// Object metadata returned by [`ObjectStorageClient::head_object`].
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[must_use]
pub struct ObjectMetadata {
    /// Archival lifecycle state; `None` for non-Archive-tier objects.
    pub archival_state: Option<ArchivalState>,
    /// Storage tier of the object.
    pub storage_tier: Option<StorageTier>,
    /// Object size in bytes.
    pub content_length: Option<u64>,
    /// Entity tag for conditional requests (quotes stripped).
    pub etag: Option<String>,
    /// OCI correlation ID for the head request.
    pub opc_request_id: Option<String>,
}

/// Streaming response from [`ObjectStorageClient::get_object`].
///
/// Consume `stream` with [`futures_util::StreamExt::next`] or wrap it with
/// `tokio_util::io::StreamReader` for `AsyncRead` access.
#[must_use]
pub struct GetObjectResponse {
    /// OCI correlation ID for the get request.
    pub opc_request_id: Option<String>,
    /// Total object size in bytes from the `Content-Length` header, if present.
    pub content_length: Option<u64>,
    /// Entity tag for the object (quotes stripped).
    pub etag: Option<String>,
    /// Byte stream of the object body; yields `bytes::Bytes` chunks.
    pub stream: Pin<Box<dyn Stream<Item = Result<bytes::Bytes, ObjectStorageError>> + Send>>,
}

// Can't auto-derive Debug due to the stream field
impl std::fmt::Debug for GetObjectResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GetObjectResponse")
            .field("opc_request_id", &self.opc_request_id)
            .field("content_length", &self.content_length)
            .field("etag", &self.etag)
            .field("stream", &"<streaming>")
            .finish()
    }
}

// ── Multipart Upload Types ───────────────────────────────────────────────────

/// Configuration for high-level multipart upload via [`ObjectStorageClient::upload_file`].
pub struct MultipartUploadConfig {
    /// Part size in bytes. Default: 128 MiB. Minimum: 10 MiB (except last part).
    pub part_size: usize,
    /// Maximum number of parts uploaded concurrently. Default: 8.
    pub concurrency: usize,
    /// Optional progress callback invoked after each part completes.
    pub progress: Option<Arc<dyn Fn(ProgressEvent) + Send + Sync>>,
}

impl Default for MultipartUploadConfig {
    fn default() -> Self {
        Self {
            part_size: 128 * 1024 * 1024, // 128 MiB
            concurrency: 8,
            progress: None,
        }
    }
}

// Manual Debug since Fn trait isn't Debug
impl std::fmt::Debug for MultipartUploadConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultipartUploadConfig")
            .field("part_size", &self.part_size)
            .field("concurrency", &self.concurrency)
            .field("progress", &self.progress.as_ref().map(|_| "<callback>"))
            .finish()
    }
}

/// Progress update from a multipart upload or download.
#[derive(Debug, Clone)]
pub struct ProgressEvent {
    /// Bytes transferred so far (cumulative).
    pub bytes_transferred: u64,
    /// Total bytes if known (e.g., from file size).
    pub total_bytes: Option<u64>,
    /// Part number that just completed (for multipart uploads).
    pub part_number: Option<u32>,
    /// What kind of progress event this is.
    pub kind: ProgressKind,
}

/// The kind of progress event.
#[derive(Debug, Clone, PartialEq)]
pub enum ProgressKind {
    /// A single part finished uploading.
    PartCompleted,
    /// The entire upload finished.
    UploadCompleted,
}

/// Details for creating a multipart upload.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateMultipartUploadDetails {
    /// Object name (including prefix path).
    pub object: String,
    /// Content type of the final object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Storage tier for the object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_tier: Option<StorageTier>,
    /// Custom metadata key-value pairs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<std::collections::HashMap<String, String>>,
}

/// Response from creating a multipart upload.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[must_use]
pub struct MultipartUpload {
    /// Object Storage namespace.
    pub namespace: String,
    /// Bucket name.
    pub bucket: String,
    /// Object name.
    pub object: String,
    /// Unique upload ID — used in all subsequent part operations.
    pub upload_id: String,
    /// Time the upload was created (RFC 3339).
    #[serde(default)]
    pub time_created: Option<String>,
    /// Storage tier.
    #[serde(default)]
    pub storage_tier: Option<String>,
}

/// A part to include in a commit operation.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommitMultipartUploadPartDetails {
    /// Part number (1-based).
    pub part_num: u32,
    /// ETag returned from upload_part.
    pub etag: String,
}

/// Details for committing a multipart upload.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommitMultipartUploadDetails {
    /// Parts to commit, ordered by part number.
    pub parts_to_commit: Vec<CommitMultipartUploadPartDetails>,
}

/// Summary of an uploaded part.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MultipartUploadPartSummary {
    /// Part number.
    pub part_number: u32,
    /// ETag of the part.
    pub etag: String,
    /// MD5 hash of the part.
    #[serde(default)]
    pub md5: Option<String>,
    /// Size in bytes.
    #[serde(default)]
    pub size: Option<u64>,
}

/// Response from [`ObjectStorageClient::upload_file`].
#[derive(Debug)]
#[must_use]
pub struct UploadFileResponse {
    /// OCI request ID from the commit operation.
    pub opc_request_id: Option<String>,
    /// ETag of the committed object.
    pub etag: Option<String>,
    /// Total bytes uploaded across all parts.
    pub total_bytes: u64,
    /// Number of parts uploaded.
    pub parts_uploaded: u32,
}

// ── PAR Types ────────────────────────────────────────────────────────────────

/// Access type for a pre-authenticated request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PreauthAccessType {
    /// Read a specific object.
    ObjectRead,
    /// Write a specific object.
    ObjectWrite,
    /// Read and write a specific object.
    ObjectReadWrite,
    /// Read any object in the bucket/prefix.
    AnyObjectRead,
    /// Write any object in the bucket/prefix.
    AnyObjectWrite,
    /// Read and write any object in the bucket/prefix.
    AnyObjectReadWrite,
}

/// Bucket listing action for PAR with AnyObject access.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BucketListingAction {
    /// Deny list operations.
    Deny,
    /// Allow listing objects.
    ListObjects,
}

/// Details for creating a pre-authenticated request.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePreauthenticatedRequestDetails {
    /// User-friendly name for the PAR.
    pub name: String,
    /// Access type (read, write, readwrite, etc.).
    pub access_type: PreauthAccessType,
    /// Expiration time (RFC 3339 format).
    pub time_expires: String,
    /// Object name — required for Object* access types, optional for AnyObject* types.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_name: Option<String>,
    /// Whether list operations are allowed (only for AnyObject* types).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bucket_listing_action: Option<BucketListingAction>,
}

/// Pre-authenticated request as returned at creation time.
///
/// **Important:** The `access_uri` and `full_url` are only available at creation time.
/// They cannot be retrieved later via [`ObjectStorageClient::get_preauthenticated_request`].
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[must_use]
pub struct PreauthenticatedRequest {
    /// Unique PAR identifier.
    pub id: String,
    /// User-friendly name.
    pub name: String,
    /// Access type.
    pub access_type: PreauthAccessType,
    /// Object name (if scoped to a specific object).
    #[serde(default)]
    pub object_name: Option<String>,
    /// Expiration time.
    pub time_expires: String,
    /// Creation time.
    #[serde(default)]
    pub time_created: Option<String>,
    /// Access URI (only at creation time).
    #[serde(default)]
    pub access_uri: Option<String>,
    /// Full URL = service_endpoint + access_uri (computed client-side, not from API).
    #[serde(skip)]
    pub full_url: Option<String>,
}

/// Pre-authenticated request summary (returned by get/list — no access_uri).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[must_use]
pub struct PreauthenticatedRequestSummary {
    /// Unique PAR identifier.
    pub id: String,
    /// User-friendly name.
    pub name: String,
    /// Access type.
    pub access_type: PreauthAccessType,
    /// Object name (if scoped to a specific object).
    #[serde(default)]
    pub object_name: Option<String>,
    /// Expiration time.
    pub time_expires: String,
    /// Creation time.
    #[serde(default)]
    pub time_created: Option<String>,
}

#[derive(Debug, Clone)]
enum RequestBody {
    Json(String),
    Bytes(bytes::Bytes, String), // (data, content_type)
    None,
}

/// Authenticated client for the OCI Object Storage service.
///
/// Construct with [`ObjectStorageClient::new`] (default pool settings) or
/// [`ObjectStorageClient::with_client`] (custom `reqwest::Client`).
pub struct ObjectStorageClient<A: AuthProvider> {
    auth: A,
    client: reqwest::Client,
    namespace: String,
    service_endpoint: String,
}

impl<A: AuthProvider> std::fmt::Debug for ObjectStorageClient<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObjectStorageClient")
            .field("namespace", &self.namespace)
            .field("service_endpoint", &self.service_endpoint)
            .finish_non_exhaustive()
    }
}

impl<A: AuthProvider> ObjectStorageClient<A> {
    /// Create a client with a default connection pool.
    ///
    /// Pool defaults: 64 idle connections per host, 90 s idle timeout, 60 s TCP keepalive,
    /// 30 s request timeout. If `region` is `None`, it is resolved from `auth`.
    pub async fn new(
        auth: A,
        namespace: impl Into<String>,
        region: Option<&str>,
    ) -> Result<Self, ObjectStorageError> {
        let region = match region {
            Some(r) => r.to_string(),
            None => auth.get_region().await?,
        };
        let service_endpoint = format!("https://objectstorage.{}.oraclecloud.com", region);
        let client = reqwest::Client::builder()
            .pool_max_idle_per_host(64)
            .pool_idle_timeout(Duration::from_secs(90))
            .tcp_keepalive(Duration::from_secs(60))
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self {
            auth,
            client,
            namespace: namespace.into(),
            service_endpoint,
        })
    }

    /// Create a client with a caller-supplied `reqwest::Client` for custom pool tuning.
    ///
    /// Use this when you need to share a client across services or configure TLS/proxy settings.
    pub async fn with_client(
        auth: A,
        namespace: impl Into<String>,
        region: Option<&str>,
        client: reqwest::Client,
    ) -> Result<Self, ObjectStorageError> {
        let region = match region {
            Some(r) => r.to_string(),
            None => auth.get_region().await?,
        };
        let service_endpoint = format!("https://objectstorage.{}.oraclecloud.com", region);
        Ok(Self {
            auth,
            client,
            namespace: namespace.into(),
            service_endpoint,
        })
    }

    async fn sign_and_send_inner(
        &self,
        method: &str,
        path: &str,
        body: RequestBody,
    ) -> Result<(reqwest::Response, Option<String>), ObjectStorageError> {
        let (response, opc_request_id) = self.do_signed_request(method, path, &body).await?;
        let status = response.status();

        // On 401, invalidate credentials and retry once with fresh auth
        if status.as_u16() == 401 {
            warn!(
                opc_request_id = opc_request_id.as_deref().unwrap_or("-"),
                "Got 401, invalidating credentials and retrying"
            );
            // Consume body to free the connection
            let _ = response.text().await;
            self.auth.invalidate_credentials().await;
            return self.do_signed_request(method, path, &body).await;
        }

        Ok((response, opc_request_id))
    }

    async fn do_signed_request(
        &self,
        method: &str,
        path: &str,
        body: &RequestBody,
    ) -> Result<(reqwest::Response, Option<String>), ObjectStorageError> {
        let mut headers = HeaderMap::with_capacity(8);

        let date = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        headers.insert("date", date.parse()?);

        let body_bytes: Option<bytes::Bytes> = match body {
            RequestBody::Json(s) => {
                headers.insert("content-type", "application/json".parse()?);
                headers.insert("content-length", s.len().to_string().parse()?);
                headers.insert("x-content-sha256", encode_body(s).parse()?);
                Some(bytes::Bytes::from(s.clone()))
            }
            RequestBody::Bytes(data, content_type) => {
                use base64::Engine;
                use sha2::{Digest, Sha256};
                let hash = Sha256::digest(data);
                let sha256 = base64::engine::general_purpose::STANDARD.encode(hash);
                headers.insert("content-type", content_type.parse()?);
                headers.insert("content-length", data.len().to_string().parse()?);
                headers.insert("x-content-sha256", sha256.parse()?);
                Some(data.clone())
            }
            RequestBody::None => None,
        };

        self.auth
            .sign_request(&mut headers, method, path, &self.service_endpoint)
            .await?;

        let url = format!("{}{}", self.service_endpoint, path);
        let request_builder = match method {
            "get" => self.client.get(&url),
            "post" => self.client.post(&url),
            "put" => self.client.put(&url),
            "delete" => self.client.delete(&url),
            "head" => self.client.head(&url),
            _ => {
                return Err(ObjectStorageError::Api {
                    status: 0,
                    code: "UnsupportedMethod".to_string(),
                    message: format!("unsupported HTTP method: {}", method),
                    opc_request_id: None,
                })
            }
        };

        let mut request_builder = request_builder.headers(headers);
        if let Some(b) = body_bytes {
            request_builder = request_builder.body(b);
        }

        let response = request_builder.send().await?;

        let opc_request_id = response
            .headers()
            .get("opc-request-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_owned());

        let status = response.status();

        if status.as_u16() == 429 {
            let retry_after_secs = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok());
            let _ = response.text().await;
            return Err(ObjectStorageError::RateLimited {
                opc_request_id,
                retry_after_secs,
            });
        }

        if !status.is_success() {
            let status_u16 = status.as_u16();
            let body_text = response.text().await.unwrap_or_default();
            let (code, message) = match serde_json::from_str::<OciErrorResponse>(&body_text) {
                Ok(err) => (err.code, err.message),
                Err(_) => ("Unknown".to_string(), body_text),
            };
            return Err(ObjectStorageError::Api {
                status: status_u16,
                code,
                message,
                opc_request_id,
            });
        }

        Ok((response, opc_request_id))
    }

    async fn sign_and_send(
        &self,
        method: &str,
        path: &str,
        body: Option<String>,
    ) -> Result<(reqwest::Response, Option<String>), ObjectStorageError> {
        let rb = match body {
            Some(s) => RequestBody::Json(s),
            None => RequestBody::None,
        };
        self.sign_and_send_inner(method, path, rb).await
    }

    /// Restore an [`Archive`](StorageTier::Archive)-tier object so it can be downloaded.
    ///
    /// `details.hours` must be in the range 1–240; returns
    /// [`ObjectStorageError::Api`] with code `"InvalidParameter"` otherwise.
    pub async fn restore_objects(
        &self,
        bucket: &str,
        details: &RestoreObjectsDetails,
    ) -> Result<RestoreObjectsResponse, ObjectStorageError> {
        if let Some(hours) = details.hours {
            if !(1..=240).contains(&hours) {
                return Err(ObjectStorageError::Api {
                    status: 0,
                    code: "InvalidParameter".to_string(),
                    message: format!("hours must be between 1 and 240, got {}", hours),
                    opc_request_id: None,
                });
            }
        }
        let path = format!(
            "/n/{}/b/{}/actions/restoreObjects",
            urlencoding::encode(&self.namespace),
            urlencoding::encode(bucket),
        );
        let body = serde_json::to_string(details)?;
        let (response, opc_request_id) = self.sign_and_send("post", &path, Some(body)).await?;
        // Consume body to ensure connection is returned to pool cleanly
        let _ = response.text().await;
        Ok(RestoreObjectsResponse { opc_request_id })
    }

    /// List objects in a bucket with optional filtering and pagination.
    ///
    /// Paginate by passing [`ListObjectsResponse::next_start_with`] as
    /// [`ListObjectsRequest::start`] on each subsequent call until `next_start_with` is `None`.
    pub async fn list_objects(
        &self,
        bucket: &str,
        request: &ListObjectsRequest<'_>,
    ) -> Result<ListObjectsResponse, ObjectStorageError> {
        let base = format!(
            "/n/{}/b/{}/o",
            urlencoding::encode(&self.namespace),
            urlencoding::encode(bucket),
        );
        let mut params: Vec<String> = Vec::with_capacity(7);

        if let Some(v) = request.prefix {
            params.push(format!("prefix={}", urlencoding::encode(v)));
        }
        if let Some(v) = request.start {
            params.push(format!("start={}", urlencoding::encode(v)));
        }
        if let Some(v) = request.end {
            params.push(format!("end={}", urlencoding::encode(v)));
        }
        if let Some(v) = request.delimiter {
            params.push(format!("delimiter={}", urlencoding::encode(v)));
        }
        if let Some(v) = request.limit {
            params.push(format!("limit={}", v));
        }
        if let Some(v) = request.fields {
            params.push(format!("fields={}", v));
        }
        if let Some(v) = request.start_after {
            params.push(format!("startAfter={}", urlencoding::encode(v)));
        }

        let path = if params.is_empty() {
            base
        } else {
            format!("{}?{}", base, params.join("&"))
        };
        let (response, opc_request_id) = self.sign_and_send("get", &path, None).await?;
        let mut list: ListObjectsResponse = response.json().await?;
        list.opc_request_id = opc_request_id;
        Ok(list)
    }

    /// Fetch metadata for an object without downloading its body.
    ///
    /// Returns [`ObjectMetadata`] with storage tier, archival state, size, and ETag.
    /// Use [`ObjectStorageClient::get_object`] to download the content.
    pub async fn head_object(
        &self,
        bucket: &str,
        object_name: &str,
    ) -> Result<ObjectMetadata, ObjectStorageError> {
        let path = format!(
            "/n/{}/b/{}/o/{}",
            urlencoding::encode(&self.namespace),
            urlencoding::encode(bucket),
            urlencoding::encode(object_name),
        );
        let (response, opc_request_id) = self.sign_and_send("head", &path, None).await?;

        let (archival_state, storage_tier, content_length, etag) = {
            let headers = response.headers();

            let archival_state = headers
                .get("archival-state")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| match s {
                    "Archived" => Some(ArchivalState::Archived),
                    "Restoring" => Some(ArchivalState::Restoring),
                    "Restored" => Some(ArchivalState::Restored),
                    _ => None,
                });

            let storage_tier = headers
                .get("storage-tier")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| match s {
                    "Standard" => Some(StorageTier::Standard),
                    "InfrequentAccess" => Some(StorageTier::InfrequentAccess),
                    "Archive" => Some(StorageTier::Archive),
                    _ => None,
                });

            let content_length = headers
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok());

            let etag = headers
                .get("etag")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim_matches('"').to_string());

            (archival_state, storage_tier, content_length, etag)
        };

        // HEAD responses have no body, but explicitly drop to return connection to pool
        drop(response);

        Ok(ObjectMetadata {
            archival_state,
            storage_tier,
            content_length,
            etag,
            opc_request_id,
        })
    }

    /// Download an object as a streaming response.
    ///
    /// Returns a [`GetObjectResponse`] whose `stream` field yields `bytes::Bytes` chunks.
    /// Use [`futures_util::StreamExt::next`] to consume chunks, or wrap with
    /// `tokio_util::io::StreamReader` for `AsyncRead` access.
    ///
    /// # Example
    /// ```no_run
    /// use futures_util::StreamExt;
    /// // let resp = client.get_object("bucket", "key").await?;
    /// // while let Some(chunk) = resp.stream.next().await { ... }
    /// ```
    pub async fn get_object(
        &self,
        bucket: &str,
        object_name: &str,
    ) -> Result<GetObjectResponse, ObjectStorageError> {
        let path = format!(
            "/n/{}/b/{}/o/{}",
            urlencoding::encode(&self.namespace),
            urlencoding::encode(bucket),
            urlencoding::encode(object_name),
        );
        let (response, opc_request_id) = self.sign_and_send("get", &path, None).await?;

        let content_length = response
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());

        let etag = response
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim_matches('"').to_string());

        let stream = response
            .bytes_stream()
            .map(|r| r.map_err(ObjectStorageError::Http));

        Ok(GetObjectResponse {
            opc_request_id,
            content_length,
            etag,
            stream: Box::pin(stream),
        })
    }

    /// Upload an object to a bucket.
    ///
    /// Returns the OCI request ID on success.
    ///
    /// **Note:** The entire `body` must fit in memory because OCI requires an
    /// `x-content-sha256` header computed over the full body before the request is sent.
    /// For objects larger than ~100 MB, use [`ObjectStorageClient::upload_file`] instead.
    pub async fn put_object(
        &self,
        bucket: &str,
        object_name: &str,
        body: bytes::Bytes,
        content_type: Option<&str>,
    ) -> Result<Option<String>, ObjectStorageError> {
        let path = format!(
            "/n/{}/b/{}/o/{}",
            urlencoding::encode(&self.namespace),
            urlencoding::encode(bucket),
            urlencoding::encode(object_name),
        );
        let ct = content_type.unwrap_or("application/octet-stream");
        let (response, opc_request_id) = self
            .sign_and_send_inner("put", &path, RequestBody::Bytes(body, ct.to_string()))
            .await?;
        // Consume body to ensure connection is returned to pool cleanly
        let _ = response.text().await;
        Ok(opc_request_id)
    }

    // ── Multipart Upload Operations ─────────────────────────────────

    /// Initiate a multipart upload. Returns the upload ID and metadata.
    pub async fn create_multipart_upload(
        &self,
        bucket: &str,
        details: &CreateMultipartUploadDetails,
    ) -> Result<MultipartUpload, ObjectStorageError> {
        let path = format!(
            "/n/{}/b/{}/u",
            urlencoding::encode(&self.namespace),
            urlencoding::encode(bucket),
        );
        let body = serde_json::to_string(details)?;
        let (response, _opc_request_id) = self.sign_and_send("post", &path, Some(body)).await?;
        let upload: MultipartUpload = response.json().await?;
        Ok(upload)
    }

    /// Upload a single part of a multipart upload. Returns the ETag for this part.
    ///
    /// The `data` must be at least 10 MiB (except for the last part).
    pub async fn upload_part(
        &self,
        bucket: &str,
        object_name: &str,
        upload_id: &str,
        part_num: u32,
        data: bytes::Bytes,
    ) -> Result<String, ObjectStorageError> {
        let path = format!(
            "/n/{}/b/{}/u/{}?uploadId={}&uploadPartNum={}",
            urlencoding::encode(&self.namespace),
            urlencoding::encode(bucket),
            urlencoding::encode(object_name),
            urlencoding::encode(upload_id),
            part_num,
        );
        let ct = "application/octet-stream".to_string();
        let (response, _opc_request_id) = self
            .sign_and_send_inner("put", &path, RequestBody::Bytes(data, ct))
            .await?;
        let etag = response
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim_matches('"').to_string())
            .unwrap_or_default();
        // Consume body to return connection to pool
        let _ = response.text().await;
        Ok(etag)
    }

    /// Commit a multipart upload after all parts have been uploaded.
    pub async fn commit_multipart_upload(
        &self,
        bucket: &str,
        object_name: &str,
        upload_id: &str,
        details: &CommitMultipartUploadDetails,
    ) -> Result<(Option<String>, Option<String>), ObjectStorageError> {
        let path = format!(
            "/n/{}/b/{}/u/{}?uploadId={}",
            urlencoding::encode(&self.namespace),
            urlencoding::encode(bucket),
            urlencoding::encode(object_name),
            urlencoding::encode(upload_id),
        );
        let body = serde_json::to_string(details)?;
        let (response, opc_request_id) = self.sign_and_send("post", &path, Some(body)).await?;
        let etag = response
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim_matches('"').to_string());
        let _ = response.text().await;
        Ok((opc_request_id, etag))
    }

    /// Abort a multipart upload and discard all uploaded parts.
    pub async fn abort_multipart_upload(
        &self,
        bucket: &str,
        object_name: &str,
        upload_id: &str,
    ) -> Result<(), ObjectStorageError> {
        let path = format!(
            "/n/{}/b/{}/u/{}?uploadId={}",
            urlencoding::encode(&self.namespace),
            urlencoding::encode(bucket),
            urlencoding::encode(object_name),
            urlencoding::encode(upload_id),
        );
        let (response, _) = self.sign_and_send("delete", &path, None).await?;
        let _ = response.text().await;
        Ok(())
    }

    /// List in-progress multipart uploads for a bucket.
    pub async fn list_multipart_uploads(
        &self,
        bucket: &str,
    ) -> Result<Vec<MultipartUpload>, ObjectStorageError> {
        let path = format!(
            "/n/{}/b/{}/u",
            urlencoding::encode(&self.namespace),
            urlencoding::encode(bucket),
        );
        let (response, _) = self.sign_and_send("get", &path, None).await?;
        let uploads: Vec<MultipartUpload> = response.json().await?;
        Ok(uploads)
    }

    /// List parts of a multipart upload.
    pub async fn list_multipart_upload_parts(
        &self,
        bucket: &str,
        object_name: &str,
        upload_id: &str,
    ) -> Result<Vec<MultipartUploadPartSummary>, ObjectStorageError> {
        let path = format!(
            "/n/{}/b/{}/u/{}?uploadId={}",
            urlencoding::encode(&self.namespace),
            urlencoding::encode(bucket),
            urlencoding::encode(object_name),
            urlencoding::encode(upload_id),
        );
        let (response, _) = self.sign_and_send("get", &path, None).await?;
        let parts: Vec<MultipartUploadPartSummary> = response.json().await?;
        Ok(parts)
    }

    // ── High-Level Upload ───────────────────────────────────────────

    /// Upload a large object using multipart upload with parallel parts.
    ///
    /// Reads from `source` in chunks of `config.part_size` (default 128 MiB),
    /// uploads parts concurrently (default 8), and commits on success.
    /// On failure, automatically aborts the multipart upload.
    ///
    /// Memory usage: at most `config.concurrency * config.part_size` bytes in flight.
    pub async fn upload_file(
        &self,
        bucket: &str,
        object_name: &str,
        mut source: impl AsyncRead + Send + Unpin,
        total_size: Option<u64>,
        config: Option<MultipartUploadConfig>,
    ) -> Result<UploadFileResponse, ObjectStorageError> {
        let config = config.unwrap_or_default();

        // 1. Create multipart upload
        let details = CreateMultipartUploadDetails {
            object: object_name.to_string(),
            content_type: None,
            storage_tier: None,
            metadata: None,
        };
        let upload = self.create_multipart_upload(bucket, &details).await?;
        let upload_id = upload.upload_id.clone();

        // 2. Read chunks and upload parts concurrently
        let result = self
            .upload_parts(
                bucket,
                object_name,
                &upload_id,
                &mut source,
                total_size,
                &config,
            )
            .await;

        // 3. Handle result — commit or abort
        match result {
            Ok((parts, total_bytes)) => {
                let commit_details = CommitMultipartUploadDetails {
                    parts_to_commit: parts
                        .iter()
                        .map(|(num, etag)| CommitMultipartUploadPartDetails {
                            part_num: *num,
                            etag: etag.clone(),
                        })
                        .collect(),
                };
                let (opc_request_id, etag) = self
                    .commit_multipart_upload(bucket, object_name, &upload_id, &commit_details)
                    .await?;

                if let Some(ref progress) = config.progress {
                    progress(ProgressEvent {
                        bytes_transferred: total_bytes,
                        total_bytes: total_size,
                        part_number: None,
                        kind: ProgressKind::UploadCompleted,
                    });
                }

                Ok(UploadFileResponse {
                    opc_request_id,
                    etag,
                    total_bytes,
                    parts_uploaded: parts.len() as u32,
                })
            }
            Err(e) => {
                // Best-effort abort — don't mask the original error
                let _ = self
                    .abort_multipart_upload(bucket, object_name, &upload_id)
                    .await;
                Err(e)
            }
        }
    }

    /// Internal: read chunks and upload parts with bounded concurrency.
    async fn upload_parts(
        &self,
        bucket: &str,
        object_name: &str,
        upload_id: &str,
        source: &mut (impl AsyncRead + Send + Unpin),
        total_size: Option<u64>,
        config: &MultipartUploadConfig,
    ) -> Result<(Vec<(u32, String)>, u64), ObjectStorageError> {
        use futures_util::stream::{self, StreamExt as _};

        let mut part_num: u32 = 0;
        let mut total_bytes: u64 = 0;
        let mut parts: Vec<(u32, String)> = Vec::new();
        let mut pending_futs = Vec::new();

        loop {
            // Read a chunk
            let mut buf = Vec::with_capacity(config.part_size);
            let bytes_read = read_exact_or_eof(source, &mut buf, config.part_size).await?;
            if bytes_read == 0 {
                break;
            }

            part_num += 1;
            total_bytes += bytes_read as u64;
            let data = bytes::Bytes::from(buf);
            let current_part = part_num;

            // Create a future for this part upload
            let bucket_owned = bucket.to_string();
            let object_owned = object_name.to_string();
            let upload_id_owned = upload_id.to_string();

            pending_futs.push((
                current_part,
                data,
                bucket_owned,
                object_owned,
                upload_id_owned,
                total_bytes,
            ));

            // When we hit concurrency limit or end of file, flush
            if pending_futs.len() >= config.concurrency || bytes_read < config.part_size {
                let futs: Vec<_> = pending_futs
                    .drain(..)
                    .map(|(pn, data, b, o, uid, cumulative_bytes)| {
                        let progress = config.progress.clone();
                        let ts = total_size;
                        async move {
                            let etag = self.upload_part(&b, &o, &uid, pn, data).await?;
                            if let Some(ref cb) = progress {
                                cb(ProgressEvent {
                                    bytes_transferred: cumulative_bytes,
                                    total_bytes: ts,
                                    part_number: Some(pn),
                                    kind: ProgressKind::PartCompleted,
                                });
                            }
                            Ok::<(u32, String), ObjectStorageError>((pn, etag))
                        }
                    })
                    .collect();

                let results: Vec<_> = stream::iter(futs)
                    .buffer_unordered(config.concurrency)
                    .collect()
                    .await;

                for result in results {
                    parts.push(result?);
                }

                if bytes_read < config.part_size {
                    break;
                }
            }
        }

        // Sort parts by part number (buffer_unordered may reorder)
        parts.sort_by_key(|(num, _)| *num);
        Ok((parts, total_bytes))
    }

    // ── Pre-Authenticated Requests ──────────────────────────────────

    /// Create a pre-authenticated request (PAR) for a bucket or object.
    ///
    /// **Important:** The returned [`PreauthenticatedRequest::access_uri`] and
    /// [`PreauthenticatedRequest::full_url`] are only available at creation time.
    pub async fn create_preauthenticated_request(
        &self,
        bucket: &str,
        details: &CreatePreauthenticatedRequestDetails,
    ) -> Result<PreauthenticatedRequest, ObjectStorageError> {
        let path = format!(
            "/n/{}/b/{}/p",
            urlencoding::encode(&self.namespace),
            urlencoding::encode(bucket),
        );
        let body = serde_json::to_string(details)?;
        let (response, _) = self.sign_and_send("post", &path, Some(body)).await?;
        let mut par: PreauthenticatedRequest = response.json().await?;
        // Construct the full URL from service endpoint + access URI
        if let Some(ref uri) = par.access_uri {
            par.full_url = Some(format!("{}{}", self.service_endpoint, uri));
        }
        Ok(par)
    }

    /// Get details of a pre-authenticated request (without the access URI).
    pub async fn get_preauthenticated_request(
        &self,
        bucket: &str,
        par_id: &str,
    ) -> Result<PreauthenticatedRequestSummary, ObjectStorageError> {
        let path = format!(
            "/n/{}/b/{}/p/{}",
            urlencoding::encode(&self.namespace),
            urlencoding::encode(bucket),
            urlencoding::encode(par_id),
        );
        let (response, _) = self.sign_and_send("get", &path, None).await?;
        let par: PreauthenticatedRequestSummary = response.json().await?;
        Ok(par)
    }

    /// List all pre-authenticated requests for a bucket.
    pub async fn list_preauthenticated_requests(
        &self,
        bucket: &str,
    ) -> Result<Vec<PreauthenticatedRequestSummary>, ObjectStorageError> {
        let path = format!(
            "/n/{}/b/{}/p",
            urlencoding::encode(&self.namespace),
            urlencoding::encode(bucket),
        );
        let (response, _) = self.sign_and_send("get", &path, None).await?;
        let pars: Vec<PreauthenticatedRequestSummary> = response.json().await?;
        Ok(pars)
    }

    /// Delete a pre-authenticated request.
    pub async fn delete_preauthenticated_request(
        &self,
        bucket: &str,
        par_id: &str,
    ) -> Result<(), ObjectStorageError> {
        let path = format!(
            "/n/{}/b/{}/p/{}",
            urlencoding::encode(&self.namespace),
            urlencoding::encode(bucket),
            urlencoding::encode(par_id),
        );
        let (response, _) = self.sign_and_send("delete", &path, None).await?;
        let _ = response.text().await;
        Ok(())
    }
}

/// Read exactly `max_bytes` or until EOF from an async reader.
async fn read_exact_or_eof(
    reader: &mut (impl AsyncRead + Unpin),
    buf: &mut Vec<u8>,
    max_bytes: usize,
) -> Result<usize, ObjectStorageError> {
    let mut total = 0;
    buf.resize(max_bytes, 0);
    while total < max_bytes {
        let n = reader.read(&mut buf[total..]).await?;
        if n == 0 {
            break;
        }
        total += n;
    }
    buf.truncate(total);
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── RestoreObjectsDetails serialization ──────────────────────────────────

    #[test]
    fn test_restore_objects_details_serialize_with_hours_no_version_id() {
        let details = RestoreObjectsDetails {
            object_name: "test.tar".into(),
            hours: Some(48),
            version_id: None,
        };
        let json = serde_json::to_string(&details).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["objectName"], "test.tar");
        assert_eq!(v["hours"], 48);
        assert!(v.get("versionId").is_none(), "versionId should be absent");
    }

    #[test]
    fn test_restore_objects_details_serialize_all_fields() {
        let details = RestoreObjectsDetails {
            object_name: "test.tar".into(),
            hours: Some(48),
            version_id: Some("abc123".into()),
        };
        let json = serde_json::to_string(&details).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["objectName"], "test.tar");
        assert_eq!(v["hours"], 48);
        assert_eq!(v["versionId"], "abc123");
    }

    #[test]
    fn test_restore_objects_details_serialize_only_object_name() {
        let details = RestoreObjectsDetails {
            object_name: "test.tar".into(),
            hours: None,
            version_id: None,
        };
        let json = serde_json::to_string(&details).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["objectName"], "test.tar");
        assert!(v.get("hours").is_none(), "hours should be absent");
        assert!(v.get("versionId").is_none(), "versionId should be absent");
    }

    // ── ListObjectsResponse deserialization ──────────────────────────────────

    #[test]
    fn test_list_objects_response_deserialize_full() {
        let json = r#"{
            "objects": [
                {"name": "a/b/c.txt", "size": 1024, "storageTier": "Archive", "archivalState": "Restored", "timeCreated": "2024-01-01T00:00:00Z"},
                {"name": "a/b/d.txt"}
            ],
            "prefixes": ["a/b/sub/"],
            "nextStartWith": "a/b/e.txt"
        }"#;

        let resp: ListObjectsResponse = serde_json::from_str(json).unwrap();

        assert_eq!(resp.objects.len(), 2);

        let first = &resp.objects[0];
        assert_eq!(first.name, "a/b/c.txt");
        assert_eq!(first.size, Some(1024));
        assert_eq!(first.storage_tier, Some(StorageTier::Archive));
        assert_eq!(first.archival_state, Some(ArchivalState::Restored));
        assert_eq!(first.time_created.as_deref(), Some("2024-01-01T00:00:00Z"));

        let second = &resp.objects[1];
        assert_eq!(second.name, "a/b/d.txt");
        assert!(second.size.is_none());
        assert!(second.storage_tier.is_none());
        assert!(second.archival_state.is_none());
        assert!(second.etag.is_none());
        assert!(second.md5.is_none());
        assert!(second.time_created.is_none());

        assert_eq!(resp.prefixes, vec!["a/b/sub/"]);
        assert_eq!(resp.next_start_with.as_deref(), Some("a/b/e.txt"));
    }

    #[test]
    fn test_list_objects_response_deserialize_last_page() {
        let json = r#"{
            "objects": [{"name": "x.txt"}],
            "nextStartWith": null
        }"#;

        let resp: ListObjectsResponse = serde_json::from_str(json).unwrap();

        assert_eq!(resp.objects.len(), 1);
        assert_eq!(resp.objects[0].name, "x.txt");
        assert!(resp.next_start_with.is_none());
        assert!(resp.prefixes.is_empty(), "prefixes should default to empty");
    }

    // ── OciErrorResponse deserialization ────────────────────────────────────

    #[test]
    fn test_oci_error_response_deserialize() {
        let json = r#"{"code":"BucketNotFound","message":"The bucket 'foo' does not exist"}"#;
        let err: OciErrorResponse = serde_json::from_str(json).unwrap();
        assert_eq!(err.code, "BucketNotFound");
        assert_eq!(err.message, "The bucket 'foo' does not exist");
    }

    #[test]
    fn test_oci_error_response_deserialize_malformed_returns_err() {
        let result = serde_json::from_str::<OciErrorResponse>("not json at all");
        assert!(result.is_err());
    }

    // ── StorageTier deserialization ──────────────────────────────────────────

    #[test]
    fn test_storage_tier_deserialize_standard() {
        let tier: StorageTier = serde_json::from_str(r#""Standard""#).unwrap();
        assert_eq!(tier, StorageTier::Standard);
    }

    #[test]
    fn test_storage_tier_deserialize_infrequent_access() {
        let tier: StorageTier = serde_json::from_str(r#""InfrequentAccess""#).unwrap();
        assert_eq!(tier, StorageTier::InfrequentAccess);
    }

    #[test]
    fn test_storage_tier_deserialize_archive() {
        let tier: StorageTier = serde_json::from_str(r#""Archive""#).unwrap();
        assert_eq!(tier, StorageTier::Archive);
    }

    // ── ArchivalState deserialization ────────────────────────────────────────

    #[test]
    fn test_archival_state_deserialize_archived() {
        let state: ArchivalState = serde_json::from_str(r#""Archived""#).unwrap();
        assert_eq!(state, ArchivalState::Archived);
    }

    #[test]
    fn test_archival_state_deserialize_restoring() {
        let state: ArchivalState = serde_json::from_str(r#""Restoring""#).unwrap();
        assert_eq!(state, ArchivalState::Restoring);
    }

    #[test]
    fn test_archival_state_deserialize_restored() {
        let state: ArchivalState = serde_json::from_str(r#""Restored""#).unwrap();
        assert_eq!(state, ArchivalState::Restored);
    }

    // ── ListObjectsRequest default ───────────────────────────────────────────

    #[test]
    fn test_list_objects_request_default_all_none() {
        let req = ListObjectsRequest::default();
        assert!(req.prefix.is_none());
        assert!(req.start.is_none());
        assert!(req.end.is_none());
        assert!(req.delimiter.is_none());
        assert!(req.limit.is_none());
        assert!(req.fields.is_none());
        assert!(req.start_after.is_none());
    }

    // ── Multipart types ─────────────────────────────────────────────

    #[test]
    fn test_create_multipart_upload_details_serialize() {
        let details = CreateMultipartUploadDetails {
            object: "test/file.bin".to_string(),
            content_type: Some("application/octet-stream".to_string()),
            storage_tier: None,
            metadata: None,
        };
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&details).unwrap()).unwrap();
        assert_eq!(json["object"], "test/file.bin");
        assert_eq!(json["contentType"], "application/octet-stream");
        assert!(json.get("storageTier").is_none());
        assert!(json.get("metadata").is_none());
    }

    #[test]
    fn test_commit_multipart_upload_details_serialize() {
        let details = CommitMultipartUploadDetails {
            parts_to_commit: vec![
                CommitMultipartUploadPartDetails {
                    part_num: 1,
                    etag: "etag1".to_string(),
                },
                CommitMultipartUploadPartDetails {
                    part_num: 2,
                    etag: "etag2".to_string(),
                },
            ],
        };
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&details).unwrap()).unwrap();
        let parts = json["partsToCommit"].as_array().unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0]["partNum"], 1);
        assert_eq!(parts[0]["etag"], "etag1");
        assert_eq!(parts[1]["partNum"], 2);
        assert_eq!(parts[1]["etag"], "etag2");
    }

    #[test]
    fn test_multipart_upload_deserialize() {
        let json = r#"{"namespace":"ns","bucket":"b","object":"obj","uploadId":"uid-123","timeCreated":"2024-01-01T00:00:00Z","storageTier":"Standard"}"#;
        let upload: MultipartUpload = serde_json::from_str(json).unwrap();
        assert_eq!(upload.namespace, "ns");
        assert_eq!(upload.upload_id, "uid-123");
        assert_eq!(upload.storage_tier, Some("Standard".to_string()));
    }

    #[test]
    fn test_multipart_upload_config_defaults() {
        let config = MultipartUploadConfig::default();
        assert_eq!(config.part_size, 128 * 1024 * 1024);
        assert_eq!(config.concurrency, 8);
        assert!(config.progress.is_none());
    }

    #[test]
    fn test_progress_kind_equality() {
        assert_eq!(ProgressKind::PartCompleted, ProgressKind::PartCompleted);
        assert_ne!(ProgressKind::PartCompleted, ProgressKind::UploadCompleted);
    }

    // ── PAR types ───────────────────────────────────────────────────

    #[test]
    fn test_create_par_details_serialize() {
        let details = CreatePreauthenticatedRequestDetails {
            name: "my-par".to_string(),
            access_type: PreauthAccessType::ObjectRead,
            time_expires: "2025-12-31T23:59:59Z".to_string(),
            object_name: Some("data/file.csv".to_string()),
            bucket_listing_action: None,
        };
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&details).unwrap()).unwrap();
        assert_eq!(json["name"], "my-par");
        assert_eq!(json["accessType"], "ObjectRead");
        assert_eq!(json["timeExpires"], "2025-12-31T23:59:59Z");
        assert_eq!(json["objectName"], "data/file.csv");
        assert!(json.get("bucketListingAction").is_none());
    }

    #[test]
    fn test_create_par_details_serialize_any_object_with_listing() {
        let details = CreatePreauthenticatedRequestDetails {
            name: "bucket-par".to_string(),
            access_type: PreauthAccessType::AnyObjectReadWrite,
            time_expires: "2025-12-31T23:59:59Z".to_string(),
            object_name: None,
            bucket_listing_action: Some(BucketListingAction::ListObjects),
        };
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&details).unwrap()).unwrap();
        assert_eq!(json["accessType"], "AnyObjectReadWrite");
        assert_eq!(json["bucketListingAction"], "ListObjects");
        assert!(json.get("objectName").is_none());
    }

    #[test]
    fn test_par_response_deserialize() {
        let json = r#"{
            "id": "par-123",
            "name": "my-par",
            "accessType": "ObjectRead",
            "objectName": "data/file.csv",
            "timeExpires": "2025-12-31T23:59:59Z",
            "timeCreated": "2024-01-01T00:00:00Z",
            "accessUri": "/p/abc123/n/ns/b/bucket/o/data/file.csv"
        }"#;
        let par: PreauthenticatedRequest = serde_json::from_str(json).unwrap();
        assert_eq!(par.id, "par-123");
        assert_eq!(par.access_type, PreauthAccessType::ObjectRead);
        assert_eq!(
            par.access_uri.as_deref(),
            Some("/p/abc123/n/ns/b/bucket/o/data/file.csv")
        );
        assert!(par.full_url.is_none()); // full_url is computed client-side, not deserialized
    }

    #[test]
    fn test_par_summary_deserialize() {
        let json = r#"{
            "id": "par-123",
            "name": "my-par",
            "accessType": "AnyObjectRead",
            "timeExpires": "2025-12-31T23:59:59Z",
            "timeCreated": "2024-01-01T00:00:00Z"
        }"#;
        let par: PreauthenticatedRequestSummary = serde_json::from_str(json).unwrap();
        assert_eq!(par.id, "par-123");
        assert_eq!(par.access_type, PreauthAccessType::AnyObjectRead);
        assert!(par.object_name.is_none());
    }

    #[test]
    fn test_preauth_access_type_roundtrip() {
        let types = vec![
            PreauthAccessType::ObjectRead,
            PreauthAccessType::ObjectWrite,
            PreauthAccessType::ObjectReadWrite,
            PreauthAccessType::AnyObjectRead,
            PreauthAccessType::AnyObjectWrite,
            PreauthAccessType::AnyObjectReadWrite,
        ];
        for t in types {
            let json = serde_json::to_string(&t).unwrap();
            let back: PreauthAccessType = serde_json::from_str(&json).unwrap();
            assert_eq!(t, back);
        }
    }

    #[test]
    fn test_bucket_listing_action_roundtrip() {
        let actions = vec![BucketListingAction::Deny, BucketListingAction::ListObjects];
        for a in actions {
            let json = serde_json::to_string(&a).unwrap();
            let back: BucketListingAction = serde_json::from_str(&json).unwrap();
            assert_eq!(a, back);
        }
    }

    // ── B. RestoreObjectsDetails builder pattern ─────────────────────────────

    #[test]
    fn test_restore_objects_details_builder_new_only() {
        let d = RestoreObjectsDetails::new("archive/data.tar");
        assert_eq!(d.object_name, "archive/data.tar");
        assert!(d.hours.is_none());
        assert!(d.version_id.is_none());
    }

    #[test]
    fn test_restore_objects_details_builder_chain() {
        let d = RestoreObjectsDetails::new("obj.tar")
            .hours(72)
            .version_id("v-abc-123");
        assert_eq!(d.object_name, "obj.tar");
        assert_eq!(d.hours, Some(72));
        assert_eq!(d.version_id.as_deref(), Some("v-abc-123"));
    }

    #[test]
    fn test_restore_objects_details_builder_hours_only() {
        let d = RestoreObjectsDetails::new("obj.tar").hours(1);
        assert_eq!(d.hours, Some(1));
        assert!(d.version_id.is_none());
    }

    #[test]
    fn test_restore_objects_details_builder_version_id_only() {
        let d = RestoreObjectsDetails::new("obj.tar").version_id("ver-999");
        assert!(d.hours.is_none());
        assert_eq!(d.version_id.as_deref(), Some("ver-999"));
    }

    // ── B. ProgressEvent construction ────────────────────────────────────────

    #[test]
    fn test_progress_event_part_completed() {
        let ev = ProgressEvent {
            bytes_transferred: 134_217_728,
            total_bytes: Some(268_435_456),
            part_number: Some(1),
            kind: ProgressKind::PartCompleted,
        };
        assert_eq!(ev.bytes_transferred, 134_217_728);
        assert_eq!(ev.total_bytes, Some(268_435_456));
        assert_eq!(ev.part_number, Some(1));
        assert_eq!(ev.kind, ProgressKind::PartCompleted);
    }

    #[test]
    fn test_progress_event_upload_completed_no_total() {
        let ev = ProgressEvent {
            bytes_transferred: 42,
            total_bytes: None,
            part_number: None,
            kind: ProgressKind::UploadCompleted,
        };
        assert!(ev.total_bytes.is_none());
        assert!(ev.part_number.is_none());
        assert_eq!(ev.kind, ProgressKind::UploadCompleted);
    }

    // ── B. MultipartUploadConfig debug format ────────────────────────────────

    #[test]
    fn test_multipart_upload_config_debug_no_callback() {
        let config = MultipartUploadConfig::default();
        let s = format!("{:?}", config);
        assert!(s.contains("part_size"), "debug should include part_size");
        assert!(
            s.contains("concurrency"),
            "debug should include concurrency"
        );
        assert!(s.contains("None"), "progress should show None");
    }

    #[test]
    fn test_multipart_upload_config_debug_with_callback() {
        let config = MultipartUploadConfig {
            part_size: 10 * 1024 * 1024,
            concurrency: 4,
            progress: Some(Arc::new(|_ev| {})),
        };
        let s = format!("{:?}", config);
        assert!(
            s.contains("<callback>"),
            "progress callback should show <callback>"
        );
    }

    // ── B. GetObjectResponse debug format ────────────────────────────────────

    #[test]
    fn test_get_object_response_debug_shows_streaming_placeholder() {
        use futures_util::stream;
        let resp = GetObjectResponse {
            opc_request_id: Some("req-123".to_string()),
            content_length: Some(1024),
            etag: Some("abc".to_string()),
            stream: Box::pin(stream::empty::<Result<bytes::Bytes, ObjectStorageError>>()),
        };
        let s = format!("{:?}", resp);
        assert!(
            s.contains("<streaming>"),
            "stream field should show <streaming>"
        );
        assert!(s.contains("req-123"));
    }

    // ── C. ObjectStorageError Display formatting ─────────────────────────────

    #[test]
    fn test_error_display_rate_limited_with_both_fields() {
        let err = ObjectStorageError::RateLimited {
            opc_request_id: Some("req-abc".to_string()),
            retry_after_secs: Some(30),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("rate limited"),
            "should say 'rate limited': {msg}"
        );
        assert!(msg.contains("30"), "should include retry_after_secs: {msg}");
        assert!(
            msg.contains("req-abc"),
            "should include opc_request_id: {msg}"
        );
    }

    #[test]
    fn test_error_display_rate_limited_no_fields() {
        let err = ObjectStorageError::RateLimited {
            opc_request_id: None,
            retry_after_secs: None,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("rate limited"),
            "should say 'rate limited': {msg}"
        );
        assert!(
            msg.contains("None"),
            "should show None for missing fields: {msg}"
        );
    }

    #[test]
    fn test_error_display_api_error() {
        let err = ObjectStorageError::Api {
            status: 404,
            code: "BucketNotFound".to_string(),
            message: "The bucket 'foo' does not exist".to_string(),
            opc_request_id: Some("req-xyz".to_string()),
        };
        let msg = err.to_string();
        assert!(msg.contains("404"), "should include status: {msg}");
        assert!(msg.contains("BucketNotFound"), "should include code: {msg}");
        assert!(
            msg.contains("The bucket 'foo' does not exist"),
            "should include message: {msg}"
        );
        assert!(
            msg.contains("req-xyz"),
            "should include opc_request_id: {msg}"
        );
    }

    #[test]
    fn test_error_display_api_error_no_request_id() {
        let err = ObjectStorageError::Api {
            status: 403,
            code: "NotAuthenticated".to_string(),
            message: "Signature verification failed".to_string(),
            opc_request_id: None,
        };
        let msg = err.to_string();
        assert!(msg.contains("403"), "should include status: {msg}");
        assert!(
            msg.contains("NotAuthenticated"),
            "should include code: {msg}"
        );
    }

    #[test]
    fn test_error_display_serialization() {
        let inner = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        let err = ObjectStorageError::Serialization(inner);
        let msg = err.to_string();
        assert!(
            msg.contains("serialization error"),
            "should say 'serialization error': {msg}"
        );
    }

    #[test]
    fn test_error_display_io() {
        let inner = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "unexpected eof");
        let err = ObjectStorageError::Io(inner);
        let msg = err.to_string();
        assert!(msg.contains("io error"), "should say 'io error': {msg}");
    }

    // ── D. Edge cases in deserialization ─────────────────────────────────────

    #[test]
    fn test_list_objects_response_empty_objects() {
        let json = r#"{"objects":[],"nextStartWith":null}"#;
        let resp: ListObjectsResponse = serde_json::from_str(json).unwrap();
        assert!(resp.objects.is_empty(), "objects should be empty");
        assert!(resp.prefixes.is_empty(), "prefixes should default to empty");
        assert!(resp.next_start_with.is_none());
    }

    #[test]
    fn test_object_summary_unknown_storage_tier_fails() {
        // StorageTier has no #[serde(other)] so unknown variants should fail
        let json = r#"{"name":"obj.txt","storageTier":"Glacier"}"#;
        let result = serde_json::from_str::<ObjectSummary>(json);
        assert!(
            result.is_err(),
            "unknown storageTier should fail deserialization"
        );
    }

    #[test]
    fn test_object_summary_unknown_archival_state_fails() {
        // ArchivalState has no #[serde(other)] so unknown variants should fail
        let json = r#"{"name":"obj.txt","archivalState":"Thawing"}"#;
        let result = serde_json::from_str::<ObjectSummary>(json);
        assert!(
            result.is_err(),
            "unknown archivalState should fail deserialization"
        );
    }

    #[test]
    fn test_object_summary_minimal_only_name() {
        let json = r#"{"name":"bare-minimum.txt"}"#;
        let obj: ObjectSummary = serde_json::from_str(json).unwrap();
        assert_eq!(obj.name, "bare-minimum.txt");
        assert!(obj.size.is_none());
        assert!(obj.etag.is_none());
        assert!(obj.time_created.is_none());
        assert!(obj.md5.is_none());
        assert!(obj.storage_tier.is_none());
        assert!(obj.archival_state.is_none());
    }

    #[test]
    fn test_object_summary_all_fields() {
        let json = r#"{
            "name": "data/2024/file.parquet",
            "size": 5368709120,
            "etag": "\"abc123def456\"",
            "timeCreated": "2024-06-15T12:00:00Z",
            "md5": "rL0Y20zC+Fzt72VPzMSk2A==",
            "storageTier": "Standard",
            "archivalState": "Archived"
        }"#;
        let obj: ObjectSummary = serde_json::from_str(json).unwrap();
        assert_eq!(obj.name, "data/2024/file.parquet");
        assert_eq!(obj.size, Some(5_368_709_120));
        assert_eq!(obj.etag.as_deref(), Some("\"abc123def456\""));
        assert_eq!(obj.time_created.as_deref(), Some("2024-06-15T12:00:00Z"));
        assert_eq!(obj.md5.as_deref(), Some("rL0Y20zC+Fzt72VPzMSk2A=="));
        assert_eq!(obj.storage_tier, Some(StorageTier::Standard));
        assert_eq!(obj.archival_state, Some(ArchivalState::Archived));
    }

    #[test]
    fn test_par_response_deserialize_minimal_no_optional_fields() {
        // PAR returned by get (no access_uri, no objectName, no timeCreated)
        let json = r#"{
            "id": "par-min",
            "name": "minimal-par",
            "accessType": "AnyObjectWrite",
            "timeExpires": "2026-01-01T00:00:00Z"
        }"#;
        let par: PreauthenticatedRequest = serde_json::from_str(json).unwrap();
        assert_eq!(par.id, "par-min");
        assert_eq!(par.access_type, PreauthAccessType::AnyObjectWrite);
        assert!(par.object_name.is_none());
        assert!(par.time_created.is_none());
        assert!(par.access_uri.is_none());
        assert!(par.full_url.is_none());
    }

    #[test]
    fn test_multipart_upload_deserialize_minimal() {
        // Only required fields — optional ones should default to None
        let json =
            r#"{"namespace":"my-ns","bucket":"my-bucket","object":"my-obj","uploadId":"uid-xyz"}"#;
        let upload: MultipartUpload = serde_json::from_str(json).unwrap();
        assert_eq!(upload.namespace, "my-ns");
        assert_eq!(upload.bucket, "my-bucket");
        assert_eq!(upload.object, "my-obj");
        assert_eq!(upload.upload_id, "uid-xyz");
        assert!(upload.time_created.is_none());
        assert!(upload.storage_tier.is_none());
    }

    #[test]
    fn test_multipart_upload_part_summary_deserialize_full() {
        let json = r#"{"partNumber":3,"etag":"etag-part3","md5":"abc==","size":10485760}"#;
        let part: MultipartUploadPartSummary = serde_json::from_str(json).unwrap();
        assert_eq!(part.part_number, 3);
        assert_eq!(part.etag, "etag-part3");
        assert_eq!(part.md5.as_deref(), Some("abc=="));
        assert_eq!(part.size, Some(10_485_760));
    }

    #[test]
    fn test_multipart_upload_part_summary_deserialize_minimal() {
        let json = r#"{"partNumber":1,"etag":"etag-only"}"#;
        let part: MultipartUploadPartSummary = serde_json::from_str(json).unwrap();
        assert_eq!(part.part_number, 1);
        assert_eq!(part.etag, "etag-only");
        assert!(part.md5.is_none());
        assert!(part.size.is_none());
    }

    #[test]
    fn test_create_multipart_upload_details_serialize_with_storage_tier_and_metadata() {
        let mut meta = std::collections::HashMap::new();
        meta.insert("x-custom-key".to_string(), "custom-value".to_string());
        let details = CreateMultipartUploadDetails {
            object: "big-file.bin".to_string(),
            content_type: None,
            storage_tier: Some(StorageTier::Archive),
            metadata: Some(meta),
        };
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&details).unwrap()).unwrap();
        assert_eq!(json["object"], "big-file.bin");
        assert!(
            json.get("contentType").is_none(),
            "contentType should be absent"
        );
        assert_eq!(json["storageTier"], "Archive");
        assert_eq!(json["metadata"]["x-custom-key"], "custom-value");
    }

    #[test]
    fn test_storage_tier_serialize_roundtrip() {
        for tier in [
            StorageTier::Standard,
            StorageTier::InfrequentAccess,
            StorageTier::Archive,
        ] {
            let json = serde_json::to_string(&tier).unwrap();
            let back: StorageTier = serde_json::from_str(&json).unwrap();
            assert_eq!(tier, back, "roundtrip failed for {json}");
        }
    }

    #[test]
    fn test_archival_state_serialize_roundtrip() {
        for state in [
            ArchivalState::Archived,
            ArchivalState::Restoring,
            ArchivalState::Restored,
        ] {
            let json = serde_json::to_string(&state).unwrap();
            let back: ArchivalState = serde_json::from_str(&json).unwrap();
            assert_eq!(state, back, "roundtrip failed for {json}");
        }
    }

    #[test]
    fn test_commit_multipart_upload_details_serialize_empty_parts() {
        let details = CommitMultipartUploadDetails {
            parts_to_commit: vec![],
        };
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&details).unwrap()).unwrap();
        let parts = json["partsToCommit"].as_array().unwrap();
        assert!(
            parts.is_empty(),
            "empty parts_to_commit should serialize as []"
        );
    }

    // ── F. read_exact_or_eof ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_read_exact_or_eof_reads_full_when_data_available() {
        let data = b"hello world 1234";
        let mut reader = tokio::io::BufReader::new(&data[..]);
        let mut buf = Vec::new();
        let n = read_exact_or_eof(&mut reader, &mut buf, 16).await.unwrap();
        assert_eq!(n, 16);
        assert_eq!(buf, b"hello world 1234");
    }

    #[tokio::test]
    async fn test_read_exact_or_eof_partial_when_eof_before_max() {
        let data = b"short";
        let mut reader = tokio::io::BufReader::new(&data[..]);
        let mut buf = Vec::new();
        let n = read_exact_or_eof(&mut reader, &mut buf, 1024)
            .await
            .unwrap();
        assert_eq!(n, 5, "should read exactly what's available");
        assert_eq!(buf, b"short");
    }

    #[tokio::test]
    async fn test_read_exact_or_eof_empty_reader_returns_zero() {
        let data: &[u8] = b"";
        let mut reader = tokio::io::BufReader::new(data);
        let mut buf = Vec::new();
        let n = read_exact_or_eof(&mut reader, &mut buf, 128).await.unwrap();
        assert_eq!(n, 0, "empty reader should return 0");
        assert!(buf.is_empty());
    }

    #[tokio::test]
    async fn test_read_exact_or_eof_exactly_max_bytes() {
        // Data is exactly max_bytes — should read all and not hang
        let data = vec![0xABu8; 64];
        let mut reader = tokio::io::BufReader::new(data.as_slice());
        let mut buf = Vec::new();
        let n = read_exact_or_eof(&mut reader, &mut buf, 64).await.unwrap();
        assert_eq!(n, 64);
        assert_eq!(buf.len(), 64);
        assert!(buf.iter().all(|&b| b == 0xAB));
    }

    #[tokio::test]
    async fn test_read_exact_or_eof_truncates_buf_to_bytes_read() {
        // Verify buf is truncated to actual bytes read, not padded with zeros
        let data = b"abc";
        let mut reader = tokio::io::BufReader::new(&data[..]);
        let mut buf = Vec::new();
        let n = read_exact_or_eof(&mut reader, &mut buf, 100).await.unwrap();
        assert_eq!(n, 3);
        assert_eq!(
            buf.len(),
            3,
            "buf should be truncated to bytes read, not max_bytes"
        );
        assert_eq!(&buf, b"abc");
    }

    #[tokio::test]
    async fn test_read_exact_or_eof_max_bytes_zero() {
        let data = b"some data";
        let mut reader = tokio::io::BufReader::new(&data[..]);
        let mut buf = Vec::new();
        let n = read_exact_or_eof(&mut reader, &mut buf, 0).await.unwrap();
        assert_eq!(n, 0, "max_bytes=0 should read nothing");
        assert!(buf.is_empty());
    }
}
