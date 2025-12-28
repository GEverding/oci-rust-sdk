//! OCI Vault Secrets service client
//!
//! Simple client for retrieving secrets from OCI Vault.

use crate::auth::{AuthError, AuthProvider};
use chrono::Utc;
use reqwest::header::HeaderMap;
use serde::Deserialize;
use std::sync::Arc;

/// A secret bundle retrieved from Vault
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretBundle {
    /// The OCID of the secret
    pub secret_id: String,
    /// The version number
    pub version_number: u64,
    /// The secret content
    pub secret_bundle_content: SecretBundleContent,
    /// Time when the secret was created
    pub time_created: Option<String>,
    /// The version name (if set)
    pub version_name: Option<String>,
    /// Lifecycle stages
    pub stages: Option<Vec<String>>,
}

/// The actual secret content
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretBundleContent {
    /// Content type: "BASE64"
    pub content_type: String,
    /// Base64-encoded secret value
    pub content: String,
}

impl SecretBundle {
    /// Decode the secret content from base64
    pub fn decode_content(&self) -> Result<String, base64::DecodeError> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let bytes = STANDARD.decode(&self.secret_bundle_content.content)?;
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }
}

/// Client for OCI Vault Secrets service
///
/// # Example
///
/// ```no_run
/// use oci_sdk::auth::InstancePrincipalAuth;
/// use oci_sdk::secrets::SecretsClient;
/// use std::sync::Arc;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let auth = Arc::new(InstancePrincipalAuth::new(None));
///     let secrets = SecretsClient::new(auth, None).await?;
///
///     let secret = secrets.get_secret("ocid1.vaultsecret.oc1..xxx").await?;
///     println!("Secret value: {}", secret.decode_content()?);
///     Ok(())
/// }
/// ```
pub struct SecretsClient {
    auth: Arc<dyn AuthProvider>,
    service_endpoint: String,
    http_client: reqwest::Client,
}

impl SecretsClient {
    /// Create a new Secrets client
    pub async fn new(
        auth: Arc<dyn AuthProvider>,
        service_endpoint: Option<String>,
    ) -> Result<Self, AuthError> {
        let region = auth.get_region().await?;
        let endpoint = service_endpoint.unwrap_or_else(|| {
            format!("https://secrets.vaults.{}.oci.oraclecloud.com", region)
        });

        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
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

    /// Get a secret by its OCID (retrieves the current/latest version)
    pub async fn get_secret(&self, secret_id: &str) -> Result<SecretBundle, AuthError> {
        let path = format!("/20180608/secretbundles/{}", secret_id);

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

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AuthError::MetadataError(format!(
                "Get secret failed: {} - {}",
                status, body
            )));
        }

        response.json().await.map_err(AuthError::from)
    }

    /// Get a specific version of a secret
    pub async fn get_secret_version(
        &self,
        secret_id: &str,
        version_number: u64,
    ) -> Result<SecretBundle, AuthError> {
        let path = format!(
            "/20180608/secretbundles/{}?versionNumber={}",
            secret_id, version_number
        );

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

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AuthError::MetadataError(format!(
                "Get secret version failed: {} - {}",
                status, body
            )));
        }

        response.json().await.map_err(AuthError::from)
    }
}
