use crate::auth::{AuthError, AuthProvider};
use crate::base_client::{encode_body, sign_request};
use chrono::{DateTime, Utc};
use reqwest::header::HeaderMap;
use reqwest::Response;
use serde::{Deserialize, Serialize};
// Remove unused import
use std::sync::Arc;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum QueueError {
    #[error("Authentication error: {0}")]
    AuthError(#[from] AuthError),
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),
    #[error("JSON parsing error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Queue configuration error: {0}")]
    ConfigError(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QueueMessage {
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublishMessageRequest {
    pub messages: Vec<QueueMessage>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublishMessageResponse {
    pub entries: Vec<PublishMessageEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublishMessageEntry {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_details: Option<String>,
}

pub struct QueueClientBuilder {
    auth_provider: Option<Arc<dyn AuthProvider>>,
    queue_id: Option<String>,
    endpoint: Option<String>,
    region: Option<String>,
}

impl QueueClientBuilder {
    pub fn new() -> Self {
        Self {
            auth_provider: None,
            queue_id: None,
            endpoint: None,
            region: None,
        }
    }

    pub fn auth_provider(mut self, auth_provider: Arc<dyn AuthProvider>) -> Self {
        self.auth_provider = Some(auth_provider);
        self
    }

    pub fn queue_id<S: Into<String>>(mut self, queue_id: S) -> Self {
        self.queue_id = Some(queue_id.into());
        self
    }

    pub fn endpoint<S: Into<String>>(mut self, endpoint: S) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    pub fn region<S: Into<String>>(mut self, region: S) -> Self {
        self.region = Some(region.into());
        self
    }

    pub async fn build(self) -> Result<QueueClient, QueueError> {
        let auth_provider = self
            .auth_provider
            .ok_or_else(|| QueueError::ConfigError("Auth provider is required".to_string()))?;

        let queue_id = self
            .queue_id
            .ok_or_else(|| QueueError::ConfigError("Queue ID is required".to_string()))?;

        let region = if let Some(region) = self.region {
            region
        } else {
            auth_provider.get_region().await?
        };

        let endpoint = if let Some(endpoint) = self.endpoint {
            endpoint
        } else {
            format!("https://messaging.{}.oci.oraclecloud.com", region)
        };

        Ok(QueueClient {
            auth_provider,
            queue_id,
            endpoint,
            region,
        })
    }
}

impl Default for QueueClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}
#[derive(Clone)]
pub struct QueueClient {
    auth_provider: Arc<dyn AuthProvider>,
    queue_id: String,
    endpoint: String,
    #[allow(dead_code)]
    region: String,
}

impl QueueClient {
    pub fn builder() -> QueueClientBuilder {
        QueueClientBuilder::new()
    }

    /// Publish messages to the queue
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use oci_sdk::auth::ConfigFileAuth;
    /// use oci_sdk::queue::{QueueClient, QueueMessage};
    /// use std::sync::Arc;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let auth = ConfigFileAuth::from_file(None, None)?;
    ///     let queue_client = QueueClient::builder()
    ///         .auth_provider(Arc::new(auth))
    ///         .queue_id("ocid1.queue.oc1.region.example")
    ///         .build()
    ///         .await?;
    ///
    ///     let messages = vec![
    ///         QueueMessage {
    ///             content: "Hello, Queue!".to_string(),
    ///             metadata: None,
    ///         },
    ///     ];
    ///
    ///     let response = queue_client.put_messages(messages).await?;
    ///     println!("Published messages: {:?}", response);
    ///
    ///     Ok(())
    /// }
    /// ```
    pub async fn put_messages(
        &self,
        messages: Vec<QueueMessage>,
    ) -> Result<PublishMessageResponse, QueueError> {
        let client = reqwest::Client::new();

        let request_body = PublishMessageRequest { messages };
        let body = serde_json::to_string(&request_body)?;

        let mut headers = HeaderMap::new();

        let now: DateTime<Utc> = Utc::now();
        headers.insert(
            "date",
            now.to_rfc2822().replace("+0000", "GMT").parse().unwrap(),
        );
        headers.insert("x-content-sha256", encode_body(&body).parse().unwrap());
        headers.insert("content-length", body.len().to_string().parse().unwrap());
        headers.insert("content-type", "application/json".parse().unwrap());

        let path = format!("/20210201/queues/{}/messages", self.queue_id);

        sign_request(
            self.auth_provider.as_ref(),
            &mut headers,
            "put",
            &path,
            &self.endpoint,
        )
        .await?;

        let response = client
            .put(format!("{}{}", self.endpoint, path))
            .body(body)
            .headers(headers)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(QueueError::ConfigError(format!(
                "HTTP {}: {}",
                status, error_text
            )));
        }

        let publish_response: PublishMessageResponse = response.json().await?;
        Ok(publish_response)
    }

    /// Publish a single message to the queue
    pub async fn put_message(
        &self,
        content: String,
        metadata: Option<serde_json::Value>,
    ) -> Result<PublishMessageResponse, QueueError> {
        let message = QueueMessage { content, metadata };
        self.put_messages(vec![message]).await
    }

    /// Get queue statistics
    pub async fn get_stats(&self) -> Result<Response, QueueError> {
        let client = reqwest::Client::new();

        let mut headers = HeaderMap::new();

        let now: DateTime<Utc> = Utc::now();
        headers.insert(
            "date",
            now.to_rfc2822().replace("+0000", "GMT").parse().unwrap(),
        );

        let path = format!("/20210201/queues/{}/stats", self.queue_id);

        sign_request(
            self.auth_provider.as_ref(),
            &mut headers,
            "get",
            &path,
            &self.endpoint,
        )
        .await?;

        let response = client
            .get(format!("{}{}", self.endpoint, path))
            .headers(headers)
            .send()
            .await?;

        Ok(response)
    }

    /// Get messages from the queue
    pub async fn get_messages(
        &self,
        visibility_timeout_in_seconds: Option<i32>,
        timeout_in_seconds: Option<i32>,
        limit: Option<i32>,
    ) -> Result<Response, QueueError> {
        let client = reqwest::Client::new();

        let mut headers = HeaderMap::new();

        let now: DateTime<Utc> = Utc::now();
        headers.insert(
            "date",
            now.to_rfc2822().replace("+0000", "GMT").parse().unwrap(),
        );

        let mut path = format!("/20210201/queues/{}/messages", self.queue_id);
        let mut query_params = Vec::new();

        if let Some(timeout) = visibility_timeout_in_seconds {
            query_params.push(format!("visibilityTimeoutInSeconds={}", timeout));
        }
        if let Some(timeout) = timeout_in_seconds {
            query_params.push(format!("timeoutInSeconds={}", timeout));
        }
        if let Some(limit) = limit {
            query_params.push(format!("limit={}", limit));
        }

        if !query_params.is_empty() {
            path = format!("{}?{}", path, query_params.join("&"));
        }

        sign_request(
            self.auth_provider.as_ref(),
            &mut headers,
            "get",
            &path,
            &self.endpoint,
        )
        .await?;

        let response = client
            .get(format!("{}{}", self.endpoint, path))
            .headers(headers)
            .send()
            .await?;

        Ok(response)
    }

    /// Delete a message from the queue
    pub async fn delete_message(&self, message_receipt: &str) -> Result<Response, QueueError> {
        let client = reqwest::Client::new();

        let mut headers = HeaderMap::new();

        let now: DateTime<Utc> = Utc::now();
        headers.insert(
            "date",
            now.to_rfc2822().replace("+0000", "GMT").parse().unwrap(),
        );

        let path = format!(
            "/20210201/queues/{}/messages/{}",
            self.queue_id, message_receipt
        );

        sign_request(
            self.auth_provider.as_ref(),
            &mut headers,
            "delete",
            &path,
            &self.endpoint,
        )
        .await?;

        let response = client
            .delete(format!("{}{}", self.endpoint, path))
            .headers(headers)
            .send()
            .await?;

        Ok(response)
    }

    /// Put messages using OCI CLI (useful for instance principal authentication)
    /// This method bypasses HTTP client and uses OCI CLI directly
    pub async fn put_messages_via_cli(
        &self,
        messages: Vec<QueueMessage>,
        cli_path: Option<&str>,
    ) -> Result<PublishMessageResponse, QueueError> {
        let cli_path = cli_path.unwrap_or("oci");
        
        // For now, handle single message (CLI is easier with single messages)
        if messages.len() != 1 {
            return Err(QueueError::ConfigError(
                "CLI method currently supports only single messages".to_string(),
            ));
        }

        let message = &messages[0];
        
        // Prepare CLI command
        let mut cmd = tokio::process::Command::new(cli_path);
        cmd.args(&[
            "queue", "message", "put",
            "--queue-id", &self.queue_id,
            "--message", &message.content,
        ]);

        // Add metadata if present
        if let Some(ref metadata) = message.metadata {
            let metadata_str = serde_json::to_string(metadata)
                .map_err(|e| QueueError::JsonError(e))?;
            cmd.args(&["--metadata", &metadata_str]);
        }

        // Execute command
        let output = cmd.output().await
            .map_err(|e| QueueError::ConfigError(format!("Failed to execute OCI CLI: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(QueueError::ConfigError(format!(
                "OCI CLI command failed: {}", stderr
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        
        // Parse CLI output (OCI CLI typically returns JSON)
        if stdout.trim().is_empty() {
            // Some CLI commands don't return data on success, create a mock response
            return Ok(PublishMessageResponse {
                entries: vec![PublishMessageEntry {
                    id: "cli-generated-id".to_string(),
                    error: None,
                    error_details: None,
                }],
            });
        }

        // Try to parse as JSON
        match serde_json::from_str::<PublishMessageResponse>(&stdout) {
            Ok(response) => Ok(response),
            Err(_) => {
                // If parsing fails, create a success response
                Ok(PublishMessageResponse {
                    entries: vec![PublishMessageEntry {
                        id: "cli-success".to_string(),
                        error: None,
                        error_details: None,
                    }],
                })
            }
        }
    }

    /// Put a single message using OCI CLI
    pub async fn put_message_via_cli(
        &self,
        content: String,
        metadata: Option<serde_json::Value>,
        cli_path: Option<&str>,
    ) -> Result<PublishMessageResponse, QueueError> {
        let message = QueueMessage { content, metadata };
        self.put_messages_via_cli(vec![message], cli_path).await
    }

    /// Check if OCI CLI is available and configured for queue operations
    pub async fn check_cli_availability(cli_path: Option<&str>) -> bool {
        let cli_path = cli_path.unwrap_or("oci");
        
        match tokio::process::Command::new(cli_path)
            .args(&["queue", "--help"])
            .output()
            .await
        {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_queue_message_serialization() {
        use serde_json::json;
        let message = QueueMessage {
            content: "test message".to_string(),
            metadata: Some(json!({"key": "value"})),
        };

        let json_str = serde_json::to_string(&message).unwrap();
        assert!(json_str.contains("test message"));
        assert!(json_str.contains("metadata"));
    }

    #[test]
    fn test_publish_request_serialization() {
        let messages = vec![QueueMessage {
            content: "test".to_string(),
            metadata: None,
        }];

        let request = PublishMessageRequest { messages };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("messages"));
        assert!(json.contains("test"));
    }
}
