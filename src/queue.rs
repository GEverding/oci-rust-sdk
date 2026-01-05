//! OCI Queue service client
//!
//! This module provides a client for interacting with OCI's Queue service,
//! enabling message-based communication between distributed applications.

use crate::auth::{encode_body, AuthError, AuthProvider};
use chrono::Utc;
use reqwest::header::HeaderMap;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Deserialize an ID that may come as string or integer from the API
fn deserialize_id<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Visitor;

    struct IdVisitor;

    impl<'de> Visitor<'de> for IdVisitor {
        type Value = Option<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string or integer")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_any(IdInnerVisitor).map(Some)
        }
    }

    struct IdInnerVisitor;

    impl<'de> Visitor<'de> for IdInnerVisitor {
        type Value = String;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string or integer")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> {
            Ok(v.to_string())
        }

        fn visit_string<E>(self, v: String) -> Result<Self::Value, E> {
            Ok(v)
        }

        fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E> {
            Ok(v.to_string())
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
            Ok(v.to_string())
        }
    }

    deserializer.deserialize_option(IdVisitor)
}

/// Error types specific to Queue operations
#[derive(Debug, thiserror::Error)]
pub enum QueueError {
    #[error("Authentication error: {0}")]
    AuthError(#[from] AuthError),
    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Queue operation failed: {0}")]
    OperationError(String),
    #[error("Invalid header value: {0}")]
    HeaderError(#[from] reqwest::header::ToStrError),
    #[error("Invalid header parse: {0}")]
    HeaderParseError(String),
}

/// A message to be published to a queue
#[derive(Debug, Clone, Serialize)]
pub struct QueueMessage {
    /// The message content (base64 encoded by the service)
    pub content: String,
    /// Optional metadata for the message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Request body for publishing messages
#[derive(Debug, Serialize)]
struct PutMessagesRequest {
    messages: Vec<PutMessageEntry>,
}

#[derive(Debug, Serialize)]
struct PutMessageEntry {
    content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<serde_json::Value>,
}

/// Response from publishing messages
#[derive(Debug, Deserialize)]
pub struct PutMessagesResponse {
    pub messages: Vec<PutMessageResult>,
}

#[derive(Debug, Deserialize)]
pub struct PutMessageResult {
    #[serde(deserialize_with = "deserialize_id")]
    pub id: Option<String>,
    #[serde(rename = "expireAfter")]
    pub expire_after: Option<String>,
}

/// A message received from a queue
#[derive(Debug, Deserialize)]
pub struct ReceivedMessage {
    pub id: String,
    pub content: String,
    pub receipt: String,
    #[serde(rename = "deliveryCount")]
    pub delivery_count: u32,
    #[serde(rename = "visibleAfter")]
    pub visible_after: Option<String>,
    #[serde(rename = "expireAfter")]
    pub expire_after: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

/// Response from getting messages
#[derive(Debug, Deserialize)]
pub struct GetMessagesResponse {
    pub messages: Vec<ReceivedMessage>,
}

/// Request to update message visibility
#[derive(Debug, Serialize)]
struct UpdateMessageRequest {
    #[serde(rename = "visibilityInSeconds")]
    visibility_in_seconds: u32,
}

/// Request to update multiple messages
#[derive(Debug, Serialize)]
struct UpdateMessagesRequest {
    entries: Vec<UpdateMessageEntry>,
}

#[derive(Debug, Serialize)]
struct UpdateMessageEntry {
    receipt: String,
    #[serde(rename = "visibilityInSeconds")]
    visibility_in_seconds: u32,
}

/// Response from updating messages
#[derive(Debug, Deserialize)]
pub struct UpdateMessagesResponse {
    pub entries: Vec<UpdateMessageResult>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateMessageResult {
    pub id: Option<String>,
    pub error: Option<MessageError>,
}

#[derive(Debug, Deserialize)]
pub struct MessageError {
    pub code: String,
    pub message: String,
}

/// Request to delete multiple messages
#[derive(Debug, Serialize)]
struct DeleteMessagesRequest {
    entries: Vec<DeleteMessageEntry>,
}

#[derive(Debug, Serialize)]
struct DeleteMessageEntry {
    receipt: String,
}

/// Queue statistics
#[derive(Debug, Deserialize)]
pub struct QueueStats {
    #[serde(rename = "visibleMessages")]
    pub visible_messages: u64,
    #[serde(rename = "inFlightMessages")]
    pub in_flight_messages: u64,
    #[serde(rename = "sizeInBytes")]
    pub size_in_bytes: u64,
}

/// Client for the OCI Queue service
///
/// # Example
///
/// ```no_run
/// use oci_sdk::auth::InstancePrincipalAuth;
/// use oci_sdk::queue::QueueClient;
/// use std::sync::Arc;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     // Use Instance Principal authentication
///     let auth = Arc::new(InstancePrincipalAuth::new(Some("us-ashburn-1".to_string())));
///
///     // Create Queue client
///     let queue = QueueClient::new(
///         auth,
///         "ocid1.queue.oc1..example",
///         None,
///     ).await?;
///
///     // Send a message
///     queue.put_message("Hello, World!".to_string(), None).await?;
///
///     Ok(())
/// }
/// ```
pub struct QueueClient {
    auth: Arc<dyn AuthProvider>,
    queue_id: String,
    service_endpoint: String,
    http_client: reqwest::Client,
}

impl QueueClient {
    /// Create a new Queue client
    ///
    /// # Arguments
    /// * `auth` - Authentication provider
    /// * `queue_id` - The OCID of the queue
    /// * `service_endpoint` - Optional custom endpoint. If None, uses the standard endpoint.
    pub async fn new(
        auth: Arc<dyn AuthProvider>,
        queue_id: impl Into<String>,
        service_endpoint: Option<String>,
    ) -> Result<Self, QueueError> {
        let region = auth.get_region().await?;
        let queue_id = queue_id.into();

        // Queue service uses a different endpoint pattern
        let endpoint = service_endpoint.unwrap_or_else(|| {
            format!(
                "https://cell-1.queue.messaging.{}.oci.oraclecloud.com",
                region
            )
        });

        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Ok(Self {
            auth,
            queue_id,
            service_endpoint: endpoint,
            http_client,
        })
    }

    /// Create a Queue client with explicit endpoint (useful for testing or specific cell routing)
    pub fn with_endpoint(
        auth: Arc<dyn AuthProvider>,
        queue_id: impl Into<String>,
        endpoint: String,
    ) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            auth,
            queue_id: queue_id.into(),
            service_endpoint: endpoint,
            http_client,
        }
    }

    fn create_date_header() -> String {
        Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string()
    }

    /// Put a single message to the queue
    pub async fn put_message(
        &self,
        content: String,
        metadata: Option<serde_json::Value>,
    ) -> Result<PutMessagesResponse, QueueError> {
        self.put_messages(vec![QueueMessage { content, metadata }])
            .await
    }

    /// Put multiple messages to the queue (max 20 per batch)
    pub async fn put_messages(
        &self,
        messages: Vec<QueueMessage>,
    ) -> Result<PutMessagesResponse, QueueError> {
        if messages.is_empty() {
            return Err(QueueError::ConfigError("No messages to send".to_string()));
        }
        if messages.len() > 20 {
            return Err(QueueError::ConfigError(
                "Maximum 20 messages per batch".to_string(),
            ));
        }

        let request = PutMessagesRequest {
            messages: messages
                .into_iter()
                .map(|m| PutMessageEntry {
                    content: m.content,
                    metadata: m.metadata,
                })
                .collect(),
        };

        let body = serde_json::to_string(&request)?;
        let path = format!("/20210201/queues/{}/messages", self.queue_id);

        let mut headers = HeaderMap::new();
        headers.insert(
            "date",
            Self::create_date_header()
                .parse()
                .map_err(|_| QueueError::HeaderParseError("date header".to_string()))?,
        );
        headers.insert(
            "content-type",
            "application/json"
                .parse()
                .map_err(|_| QueueError::HeaderParseError("content-type header".to_string()))?,
        );
        headers.insert(
            "content-length",
            body.len()
                .to_string()
                .parse()
                .map_err(|_| QueueError::HeaderParseError("content-length header".to_string()))?,
        );
        headers.insert(
            "x-content-sha256",
            encode_body(&body)
                .parse()
                .map_err(|_| QueueError::HeaderParseError("x-content-sha256 header".to_string()))?,
        );

        self.auth
            .sign_request(&mut headers, "post", &path, &self.service_endpoint)
            .await?;

        let response = self
            .http_client
            .post(format!("{}{}", self.service_endpoint, path))
            .headers(headers)
            .body(body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(QueueError::OperationError(format!(
                "Put messages failed: {} - {}",
                status, body
            )));
        }

        let result: PutMessagesResponse = response.json().await?;
        Ok(result)
    }

    /// Get messages from the queue
    ///
    /// # Arguments
    /// * `limit` - Maximum number of messages to retrieve (default: 1, max: 32)
    /// * `visibility_in_seconds` - How long messages are invisible after retrieval (default: 30)
    /// * `timeout_in_seconds` - Long polling timeout (default: 0, max: 30)
    pub async fn get_messages(
        &self,
        limit: Option<u32>,
        visibility_in_seconds: Option<u32>,
        timeout_in_seconds: Option<u32>,
    ) -> Result<GetMessagesResponse, QueueError> {
        let limit = limit.unwrap_or(1).min(32);
        let visibility = visibility_in_seconds.unwrap_or(30);
        let timeout = timeout_in_seconds.unwrap_or(0).min(30);

        let path = format!(
            "/20210201/queues/{}/messages?limit={}&visibilityInSeconds={}&timeoutInSeconds={}",
            self.queue_id, limit, visibility, timeout
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            "date",
            Self::create_date_header()
                .parse()
                .map_err(|_| QueueError::HeaderParseError("date header".to_string()))?,
        );

        self.auth
            .sign_request(&mut headers, "get", &path, &self.service_endpoint)
            .await?;

        let response = self
            .http_client
            .get(format!("{}{}", self.service_endpoint, path))
            .headers(headers)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(QueueError::OperationError(format!(
                "Get messages failed: {} - {}",
                status, body
            )));
        }

        let result: GetMessagesResponse = response.json().await?;
        Ok(result)
    }

    /// Delete a message from the queue using its receipt
    pub async fn delete_message(&self, receipt: &str) -> Result<(), QueueError> {
        let path = format!(
            "/20210201/queues/{}/messages/{}",
            self.queue_id,
            urlencoding::encode(receipt)
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            "date",
            Self::create_date_header()
                .parse()
                .map_err(|_| QueueError::HeaderParseError("date header".to_string()))?,
        );

        self.auth
            .sign_request(&mut headers, "delete", &path, &self.service_endpoint)
            .await?;

        let response = self
            .http_client
            .delete(format!("{}{}", self.service_endpoint, path))
            .headers(headers)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(QueueError::OperationError(format!(
                "Delete message failed: {} - {}",
                status, body
            )));
        }

        Ok(())
    }

    /// Update message visibility (extend or release the visibility timeout)
    pub async fn update_message(
        &self,
        receipt: &str,
        visibility_in_seconds: u32,
    ) -> Result<(), QueueError> {
        let request = UpdateMessageRequest {
            visibility_in_seconds,
        };

        let body = serde_json::to_string(&request)?;
        let path = format!(
            "/20210201/queues/{}/messages/{}",
            self.queue_id,
            urlencoding::encode(receipt)
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            "date",
            Self::create_date_header()
                .parse()
                .map_err(|_| QueueError::HeaderParseError("date header".to_string()))?,
        );
        headers.insert(
            "content-type",
            "application/json"
                .parse()
                .map_err(|_| QueueError::HeaderParseError("content-type header".to_string()))?,
        );
        headers.insert(
            "content-length",
            body.len()
                .to_string()
                .parse()
                .map_err(|_| QueueError::HeaderParseError("content-length header".to_string()))?,
        );
        headers.insert(
            "x-content-sha256",
            encode_body(&body)
                .parse()
                .map_err(|_| QueueError::HeaderParseError("x-content-sha256 header".to_string()))?,
        );

        let response = self
            .http_client
            .put(format!("{}{}", self.service_endpoint, path))
            .headers(headers)
            .body(body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(QueueError::OperationError(format!(
                "Update message failed: {} - {}",
                status, body
            )));
        }

        Ok(())
    }

    /// Update visibility of multiple messages
    pub async fn update_messages(
        &self,
        updates: Vec<(String, u32)>, // (receipt, visibility_in_seconds)
    ) -> Result<UpdateMessagesResponse, QueueError> {
        if updates.is_empty() {
            return Err(QueueError::ConfigError("No updates provided".to_string()));
        }

        let request = UpdateMessagesRequest {
            entries: updates
                .into_iter()
                .map(|(receipt, visibility)| UpdateMessageEntry {
                    receipt,
                    visibility_in_seconds: visibility,
                })
                .collect(),
        };

        let body = serde_json::to_string(&request)?;
        let path = format!(
            "/20210201/queues/{}/messages/actions/updateMessages",
            self.queue_id
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            "date",
            Self::create_date_header()
                .parse()
                .map_err(|_| QueueError::HeaderParseError("date header".to_string()))?,
        );
        headers.insert(
            "content-type",
            "application/json"
                .parse()
                .map_err(|_| QueueError::HeaderParseError("content-type header".to_string()))?,
        );
        headers.insert(
            "content-length",
            body.len()
                .to_string()
                .parse()
                .map_err(|_| QueueError::HeaderParseError("content-length header".to_string()))?,
        );
        headers.insert(
            "x-content-sha256",
            encode_body(&body)
                .parse()
                .map_err(|_| QueueError::HeaderParseError("x-content-sha256 header".to_string()))?,
        );

        self.auth
            .sign_request(&mut headers, "post", &path, &self.service_endpoint)
            .await?;

        let response = self
            .http_client
            .post(format!("{}{}", self.service_endpoint, path))
            .body(body)
            .headers(headers)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(QueueError::OperationError(format!(
                "Update messages failed: {} - {}",
                status, body
            )));
        }

        let result: UpdateMessagesResponse = response.json().await?;
        Ok(result)
    }

    /// Get queue statistics
    pub async fn get_stats(&self) -> Result<QueueStats, QueueError> {
        let path = format!("/20210201/queues/{}/stats", self.queue_id);

        let mut headers = HeaderMap::new();
        headers.insert(
            "date",
            Self::create_date_header()
                .parse()
                .map_err(|_| QueueError::HeaderParseError("date header".to_string()))?,
        );

        self.auth
            .sign_request(&mut headers, "get", &path, &self.service_endpoint)
            .await?;

        let response = self
            .http_client
            .get(format!("{}{}", self.service_endpoint, path))
            .headers(headers)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(QueueError::OperationError(format!(
                "Get stats failed: {} - {}",
                status, body
            )));
        }

        let result: QueueStats = response.json().await?;
        Ok(result)
    }

    /// Get the raw response (useful for debugging or custom handling)
    pub async fn get_messages_raw(&self, path_params: &str) -> Result<Response, QueueError> {
        let path = format!("/20210201/queues/{}/messages{}", self.queue_id, path_params);

        let mut headers = HeaderMap::new();
        headers.insert(
            "date",
            Self::create_date_header()
                .parse()
                .map_err(|_| QueueError::HeaderParseError("date header".to_string()))?,
        );

        self.auth
            .sign_request(&mut headers, "get", &path, &self.service_endpoint)
            .await?;

        let response = self
            .http_client
            .get(format!("{}{}", self.service_endpoint, path))
            .headers(headers)
            .send()
            .await?;

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_queue_message_serialization() {
        let msg = QueueMessage {
            content: "test".to_string(),
            metadata: Some(serde_json::json!({"key": "value"})),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("test"));
        assert!(json.contains("key"));
    }
}
