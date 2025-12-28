use crate::auth::{encode_body, AuthProvider};
use chrono::Utc;
use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RunLifecycleState {
    Accepted,
    InProgress,
    Canceling,
    Canceled,
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Run {
    pub id: String,
    pub application_id: String,
    pub compartment_id: String,
    pub display_name: String,
    pub lifecycle_state: RunLifecycleState,
    pub time_created: String,
    pub time_updated: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_duration_in_milliseconds: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_read_in_bytes: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_written_in_bytes: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifecycle_details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunSummary {
    pub id: String,
    pub application_id: String,
    pub compartment_id: String,
    pub display_name: String,
    pub lifecycle_state: RunLifecycleState,
    pub time_created: String,
    pub time_updated: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_duration_in_milliseconds: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRunDetails {
    pub application_id: String,
    pub compartment_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configuration: Option<HashMap<String, String>>,
}

impl CreateRunDetails {
    pub fn new(application_id: impl Into<String>, compartment_id: impl Into<String>) -> Self {
        Self {
            application_id: application_id.into(),
            compartment_id: compartment_id.into(),
            display_name: None,
            arguments: None,
            configuration: None,
        }
    }

    pub fn display_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = Some(name.into());
        self
    }

    pub fn arguments(mut self, args: Vec<String>) -> Self {
        self.arguments = Some(args);
        self
    }

    pub fn configuration(mut self, config: HashMap<String, String>) -> Self {
        self.configuration = Some(config);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunLogSummary {
    pub name: String,
    pub run_id: String,
    pub size_in_bytes: i64,
    pub source: String,
    #[serde(rename = "type")]
    pub log_type: String,
}

#[derive(Debug, Clone, Default)]
pub struct ListRunsParams {
    pub application_id: Option<String>,
    pub lifecycle_state: Option<RunLifecycleState>,
    pub display_name: Option<String>,
    pub limit: Option<u32>,
    pub page: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum DataFlowError {
    #[error("Authentication error: {0}")]
    AuthError(#[from] crate::auth::AuthError),
    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),
    #[error("API error (status {status}): {message}")]
    ApiError { status: u16, message: String },
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("Header error: {0}")]
    HeaderError(String),
}

/// Client for the OCI DataFlow service
pub struct DataFlowClient<A: AuthProvider> {
    auth: A,
    client: reqwest::Client,
    region: String,
}

impl<A: AuthProvider> DataFlowClient<A> {
    /// Create a new DataFlow client
    ///
    /// # Arguments
    /// * `auth` - Authentication provider
    /// * `region` - OCI region
    pub fn new(auth: A, region: impl Into<String>) -> Self {
        Self {
            auth,
            client: reqwest::Client::new(),
            region: region.into(),
        }
    }

    fn base_url(&self) -> String {
        format!(
            "https://dataflow.{}.oci.oraclecloud.com/20200129",
            self.region
        )
    }

    fn create_date_header() -> String {
        Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string()
    }

    /// Helper to sign request and send
    async fn sign_and_send(
        &self,
        method: &str,
        path: &str,
        body: Option<String>,
    ) -> Result<reqwest::Response, DataFlowError> {
        let mut headers = HeaderMap::new();

        // Add date header
        headers.insert(
            "date",
            Self::create_date_header()
                .parse()
                .map_err(|_| DataFlowError::HeaderError("Invalid date header".to_string()))?,
        );

        // Add content-type and body-related headers if body exists
        if let Some(ref body_str) = body {
            headers.insert(
                "content-type",
                "application/json".parse().map_err(|_| {
                    DataFlowError::HeaderError("Invalid content-type header".to_string())
                })?,
            );
            headers.insert(
                "content-length",
                body_str.len().to_string().parse().map_err(|_| {
                    DataFlowError::HeaderError("Invalid content-length header".to_string())
                })?,
            );
            headers.insert(
                "x-content-sha256",
                encode_body(body_str).parse().map_err(|_| {
                    DataFlowError::HeaderError("Invalid x-content-sha256 header".to_string())
                })?,
            );
        }

        // Sign the request
        self.auth
            .sign_request(&mut headers, method, path, &self.base_url())
            .await?;

        // Build and send the request
        let url = format!("{}{}", self.base_url(), path);
        let mut request_builder = match method {
            "get" => self.client.get(&url),
            "post" => self.client.post(&url),
            "put" => self.client.put(&url),
            "delete" => self.client.delete(&url),
            _ => {
                return Err(DataFlowError::HeaderError(format!(
                    "Unsupported HTTP method: {}",
                    method
                )))
            }
        };

        request_builder = request_builder.headers(headers);

        if let Some(body_str) = body {
            request_builder = request_builder.body(body_str);
        }

        let response = request_builder.send().await?;

        // Check for error responses
        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            return Err(DataFlowError::ApiError {
                status,
                message: body,
            });
        }

        Ok(response)
    }

    /// Get details of a specific run
    pub async fn get_run(&self, run_id: &str) -> Result<Run, DataFlowError> {
        let path = format!("/runs/{}", run_id);
        let response = self.sign_and_send("get", &path, None).await?;
        let run: Run = response.json().await?;
        Ok(run)
    }

    /// Create and start a new run for an application
    pub async fn create_run(&self, details: CreateRunDetails) -> Result<Run, DataFlowError> {
        let body = serde_json::to_string(&details)?;
        let response = self.sign_and_send("post", "/runs", Some(body)).await?;
        let run: Run = response.json().await?;
        Ok(run)
    }

    /// Cancel a running job
    pub async fn cancel_run(&self, run_id: &str) -> Result<Run, DataFlowError> {
        let path = format!("/runs/{}", run_id);
        let body = serde_json::json!({
            "lifecycleState": "CANCELING"
        });
        let body_str = serde_json::to_string(&body)?;
        let response = self.sign_and_send("put", &path, Some(body_str)).await?;
        let run: Run = response.json().await?;
        Ok(run)
    }

    /// Download a specific log file as bytes
    pub async fn get_run_log(
        &self,
        run_id: &str,
        log_name: &str,
    ) -> Result<Vec<u8>, DataFlowError> {
        let path = format!("/runs/{}/logs/{}", run_id, log_name);
        let response = self.sign_and_send("get", &path, None).await?;
        let bytes = response.bytes().await?;
        Ok(bytes.to_vec())
    }

    /// Download a specific log file as string (convenience method)
    pub async fn get_run_log_text(
        &self,
        run_id: &str,
        log_name: &str,
    ) -> Result<String, DataFlowError> {
        let bytes = self.get_run_log(run_id, log_name).await?;
        String::from_utf8(bytes)
            .map_err(|e| DataFlowError::HeaderError(format!("Invalid UTF-8 in log: {}", e)))
    }

    /// List available log files for a run
    pub async fn list_run_logs(
        &self,
        run_id: &str,
        limit: Option<u32>,
        page: Option<&str>,
    ) -> Result<Vec<RunLogSummary>, DataFlowError> {
        let mut path = format!("/runs/{}/logs", run_id);

        let mut has_params = false;
        if let Some(l) = limit {
            path.push_str(&format!("?limit={}", l));
            has_params = true;
        }
        if let Some(p) = page {
            path.push_str(if has_params { "&" } else { "?" });
            path.push_str(&format!("page={}", p));
        }

        let response = self.sign_and_send("get", &path, None).await?;
        let logs: Vec<RunLogSummary> = response.json().await?;
        Ok(logs)
    }

    /// List runs in a compartment
    pub async fn list_runs(
        &self,
        compartment_id: &str,
        params: Option<ListRunsParams>,
    ) -> Result<Vec<RunSummary>, DataFlowError> {
        let mut path = format!("/runs?compartmentId={}", compartment_id);

        if let Some(p) = params {
            if let Some(app_id) = p.application_id {
                path.push_str(&format!("&applicationId={}", urlencoding::encode(&app_id)));
            }
            if let Some(state) = p.lifecycle_state {
                let state_str = serde_json::to_string(&state)?.trim_matches('"').to_string();
                path.push_str(&format!("&lifecycleState={}", state_str));
            }
            if let Some(name) = p.display_name {
                path.push_str(&format!("&displayName={}", urlencoding::encode(&name)));
            }
            if let Some(limit) = p.limit {
                path.push_str(&format!("&limit={}", limit));
            }
            if let Some(page) = p.page {
                path.push_str(&format!("&page={}", urlencoding::encode(&page)));
            }
        }

        let response = self.sign_and_send("get", &path, None).await?;
        let runs: Vec<RunSummary> = response.json().await?;
        Ok(runs)
    }
}
