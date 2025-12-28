//! OCI Identity and Access Management (IAM) service client
//!
//! This module provides a client for interacting with OCI's Identity service,
//! which manages users, groups, policies, and other IAM resources.

use chrono::Utc;
use reqwest::{header::HeaderMap, Response};
use std::sync::Arc;

use crate::auth::{AuthError, AuthProvider};

/// Client for the OCI Identity service
pub struct Identity {
    auth: Arc<dyn AuthProvider>,
    service_endpoint: String,
    http_client: reqwest::Client,
}

impl Identity {
    /// Creates a new Identity client
    ///
    /// # Arguments
    /// * `auth` - Authentication provider (ConfigFileAuth, InstancePrincipalAuth, etc.)
    /// * `service_endpoint` - Optional custom endpoint. If None, uses the standard endpoint for the region.
    ///
    /// # Example
    /// ```no_run
    /// use oci_sdk::auth::ConfigFileAuth;
    /// use oci_sdk::identity::Identity;
    /// use std::sync::Arc;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let auth = Arc::new(ConfigFileAuth::from_file(None, None)?);
    ///     let identity = Identity::new(auth, None).await?;
    ///     Ok(())
    /// }
    /// ```
    pub async fn new(
        auth: Arc<dyn AuthProvider>,
        service_endpoint: Option<String>,
    ) -> Result<Self, AuthError> {
        let region = auth.get_region().await?;
        let endpoint = service_endpoint.unwrap_or_else(|| {
            format!("https://identity.{}.oci.oraclecloud.com", region)
        });

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

    /// Helper to create date header in RFC2822 format
    fn create_date_header() -> String {
        Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string()
    }

    /// Get the current authenticated user's details
    ///
    /// Note: This only works with API key authentication, as it requires a user OCID.
    /// For Instance Principal or Workload Identity, use other methods.
    pub async fn get_current_user(&self) -> Result<Response, AuthError> {
        // For config file auth, we can get the user from tenancy
        // For instance principal, this doesn't apply - use get_compartment instead
        let tenancy = self.auth.get_tenancy_id().await?;

        let path = format!("/20160918/tenancies/{}", tenancy);

        let mut headers = HeaderMap::new();
        headers.insert("date", Self::create_date_header().parse().unwrap());

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

    /// Get details of a specific user by OCID
    pub async fn get_user(&self, user_ocid: &str) -> Result<Response, AuthError> {
        let path = format!("/20160918/users/{}", user_ocid);

        let mut headers = HeaderMap::new();
        headers.insert("date", Self::create_date_header().parse().unwrap());

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

    /// List users in a compartment
    pub async fn list_users(&self, compartment_id: &str) -> Result<Response, AuthError> {
        let path = format!("/20160918/users?compartmentId={}", compartment_id);

        let mut headers = HeaderMap::new();
        headers.insert("date", Self::create_date_header().parse().unwrap());

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

    /// Get details of a compartment
    pub async fn get_compartment(&self, compartment_id: &str) -> Result<Response, AuthError> {
        let path = format!("/20160918/compartments/{}", compartment_id);

        let mut headers = HeaderMap::new();
        headers.insert("date", Self::create_date_header().parse().unwrap());

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

    /// List compartments in a tenancy or parent compartment
    pub async fn list_compartments(&self, compartment_id: &str) -> Result<Response, AuthError> {
        let path = format!("/20160918/compartments?compartmentId={}", compartment_id);

        let mut headers = HeaderMap::new();
        headers.insert("date", Self::create_date_header().parse().unwrap());

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

    /// Get the tenancy details
    pub async fn get_tenancy(&self) -> Result<Response, AuthError> {
        let tenancy_id = self.auth.get_tenancy_id().await?;
        let path = format!("/20160918/tenancies/{}", tenancy_id);

        let mut headers = HeaderMap::new();
        headers.insert("date", Self::create_date_header().parse().unwrap());

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
}
