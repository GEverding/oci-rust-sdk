//! OCI NoSQL Database service client
//!
//! This module provides a client for interacting with OCI's NoSQL Database service.

use crate::auth::{encode_body, AuthError, AuthProvider};
use chrono::Utc;
use reqwest::header::HeaderMap;
use reqwest::Response;
use serde::Serialize;
use std::sync::Arc;

/// Query details for NoSQL queries
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryDetails {
    pub compartment_id: String,
    pub statement: String,
}

/// Table limits configuration
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TableLimits {
    pub max_read_units: u32,
    pub max_write_units: u32,
    pub max_storage_in_g_bs: u32,
}

/// Details for creating a NoSQL table
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTableDetails {
    pub name: String,
    pub compartment_id: String,
    pub ddl_statement: String,
    pub table_limits: TableLimits,
}

/// Client for the OCI NoSQL Database service
pub struct Nosql {
    auth: Arc<dyn AuthProvider>,
    service_endpoint: String,
    http_client: reqwest::Client,
}

impl Nosql {
    /// Creates a new NoSQL client
    ///
    /// # Arguments
    /// * `auth` - Authentication provider
    /// * `service_endpoint` - Optional custom endpoint
    ///
    /// # Example
    /// ```no_run
    /// use oci_sdk::auth::ConfigFileAuth;
    /// use oci_sdk::nosql::Nosql;
    /// use std::sync::Arc;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let auth = Arc::new(ConfigFileAuth::from_file(None, None)?);
    ///     let nosql = Nosql::new(auth, None).await?;
    ///     Ok(())
    /// }
    /// ```
    pub async fn new(
        auth: Arc<dyn AuthProvider>,
        service_endpoint: Option<String>,
    ) -> Result<Self, AuthError> {
        let region = auth.get_region().await?;
        let endpoint = service_endpoint
            .unwrap_or_else(|| format!("https://nosql.{}.oci.oraclecloud.com", region));

        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Ok(Self {
            auth,
            service_endpoint: endpoint,
            http_client,
        })
    }

    fn create_date_header() -> String {
        Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string()
    }

    /// Create a new NoSQL table
    pub async fn create_table(
        &self,
        create_table_details: CreateTableDetails,
    ) -> Result<Response, AuthError> {
        let body = serde_json::to_string(&create_table_details)
            .map_err(|e| AuthError::ConfigError(format!("JSON serialization error: {}", e)))?;

        let mut headers = HeaderMap::new();
        headers.insert(
            "date",
            Self::create_date_header()
                .parse()
                .map_err(|e| AuthError::ConfigError(format!("Invalid date header: {}", e)))?,
        );
        headers.insert(
            "x-content-sha256",
            encode_body(&body).parse().map_err(|e| {
                AuthError::ConfigError(format!("Invalid x-content-sha256 header: {}", e))
            })?,
        );
        headers.insert(
            "content-length",
            body.len().to_string().parse().map_err(|e| {
                AuthError::ConfigError(format!("Invalid content-length header: {}", e))
            })?,
        );
        headers.insert(
            "content-type",
            "application/json".parse().map_err(|e| {
                AuthError::ConfigError(format!("Invalid content-type header: {}", e))
            })?,
        );

        let path = "/20190828/tables";

        self.auth
            .sign_request(&mut headers, "post", path, &self.service_endpoint)
            .await?;

        let response = self
            .http_client
            .post(format!("{}{}", self.service_endpoint, path))
            .body(body)
            .headers(headers)
            .send()
            .await
            .map_err(AuthError::from)?;

        Ok(response)
    }

    /// Execute a NoSQL query
    pub async fn query(
        &self,
        query_details: QueryDetails,
        limit: u32,
    ) -> Result<Response, AuthError> {
        let body = serde_json::to_string(&query_details)
            .map_err(|e| AuthError::ConfigError(format!("JSON serialization error: {}", e)))?;

        let mut headers = HeaderMap::new();
        headers.insert(
            "date",
            Self::create_date_header()
                .parse()
                .map_err(|e| AuthError::ConfigError(format!("Invalid date header: {}", e)))?,
        );
        headers.insert(
            "x-content-sha256",
            encode_body(&body).parse().map_err(|e| {
                AuthError::ConfigError(format!("Invalid x-content-sha256 header: {}", e))
            })?,
        );
        headers.insert(
            "content-length",
            body.len().to_string().parse().map_err(|e| {
                AuthError::ConfigError(format!("Invalid content-length header: {}", e))
            })?,
        );
        headers.insert(
            "content-type",
            "application/json".parse().map_err(|e| {
                AuthError::ConfigError(format!("Invalid content-type header: {}", e))
            })?,
        );

        let path = format!("/20190828/query?limit={}", limit);

        self.auth
            .sign_request(&mut headers, "post", &path, &self.service_endpoint)
            .await?;

        let response = self
            .http_client
            .post(format!("{}{}", self.service_endpoint, path))
            .body(body)
            .headers(headers)
            .send()
            .await
            .map_err(AuthError::from)?;

        Ok(response)
    }

    /// Get a table by name
    pub async fn get_table(
        &self,
        table_name_or_id: &str,
        compartment_id: &str,
    ) -> Result<Response, AuthError> {
        let path = format!(
            "/20190828/tables/{}?compartmentId={}",
            table_name_or_id, compartment_id
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            "date",
            Self::create_date_header()
                .parse()
                .map_err(|e| AuthError::ConfigError(format!("Invalid date header: {}", e)))?,
        );

        self.auth
            .sign_request(&mut headers, "get", &path, &self.service_endpoint)
            .await?;

        let response = self
            .http_client
            .get(format!("{}{}", self.service_endpoint, path))
            .headers(headers)
            .send()
            .await
            .map_err(AuthError::from)?;

        Ok(response)
    }

    /// List tables in a compartment
    pub async fn list_tables(&self, compartment_id: &str) -> Result<Response, AuthError> {
        let path = format!("/20190828/tables?compartmentId={}", compartment_id);

        let mut headers = HeaderMap::new();
        headers.insert(
            "date",
            Self::create_date_header()
                .parse()
                .map_err(|e| AuthError::ConfigError(format!("Invalid date header: {}", e)))?,
        );

        self.auth
            .sign_request(&mut headers, "get", &path, &self.service_endpoint)
            .await?;

        let response = self
            .http_client
            .get(format!("{}{}", self.service_endpoint, path))
            .headers(headers)
            .send()
            .await
            .map_err(AuthError::from)?;

        Ok(response)
    }

    /// Delete a table
    pub async fn delete_table(
        &self,
        table_name_or_id: &str,
        compartment_id: &str,
    ) -> Result<Response, AuthError> {
        let path = format!(
            "/20190828/tables/{}?compartmentId={}",
            table_name_or_id, compartment_id
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            "date",
            Self::create_date_header()
                .parse()
                .map_err(|e| AuthError::ConfigError(format!("Invalid date header: {}", e)))?,
        );

        self.auth
            .sign_request(&mut headers, "delete", &path, &self.service_endpoint)
            .await?;

        let response = self
            .http_client
            .delete(format!("{}{}", self.service_endpoint, path))
            .headers(headers)
            .send()
            .await
            .map_err(AuthError::from)?;

        Ok(response)
    }
}
