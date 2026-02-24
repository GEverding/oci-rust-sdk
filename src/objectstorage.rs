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
use std::time::Duration;

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

#[derive(Debug)]
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
        let mut headers = HeaderMap::with_capacity(8);

        let date = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        headers.insert("date", date.parse()?);

        let body_bytes: Option<bytes::Bytes> = match body {
            RequestBody::Json(s) => {
                headers.insert("content-type", "application/json".parse()?);
                headers.insert("content-length", s.len().to_string().parse()?);
                headers.insert("x-content-sha256", encode_body(&s).parse()?);
                Some(bytes::Bytes::from(s)) // zero-copy: reuses String's allocation
            }
            RequestBody::Bytes(data, content_type) => {
                use base64::Engine;
                use sha2::{Digest, Sha256};
                let hash = Sha256::digest(&data);
                let sha256 = base64::engine::general_purpose::STANDARD.encode(hash);
                headers.insert("content-type", content_type.parse()?);
                headers.insert("content-length", data.len().to_string().parse()?);
                headers.insert("x-content-sha256", sha256.parse()?);
                Some(data) // already owned, no clone needed
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
            // consume body to free connection
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
    /// For objects larger than ~100 MB, use multipart upload (not yet implemented).
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
}
