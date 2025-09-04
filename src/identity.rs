use chrono::{DateTime, Utc};
use reqwest::{header::HeaderMap, Response};
use std::sync::Arc;

use crate::{
    auth::{AuthError, AuthProvider},
    base_client::sign_request,
    config::AuthConfig,
};

pub struct Identity {
    auth_provider: Arc<dyn AuthProvider>,
    service_endpoint: String,
}

// Legacy struct for backward compatibility
#[deprecated(since = "0.3.0", note = "Use Identity with AuthProvider instead")]
#[allow(dead_code)]
pub struct LegacyIdentity {
    config: AuthConfig,
    service_endpoint: String,
}

impl Identity {
    ///Creates a new `Identity` which is the client necessary to interact with this type of object on OCI.
    ///
    ///## Example 1
    ///```no_run
    ///use oci_sdk::{
    ///    auth::ConfigFileAuth,
    ///    identity::{Identity},
    ///};
    ///use std::sync::Arc;
    ///
    ///let auth_provider = Arc::new(ConfigFileAuth::from_file(None, None).unwrap());
    ///let identity = Identity::new(auth_provider, None).await.unwrap();
    ///```
    ///
    /// ## Example 2
    ///
    ///```rust,no_run
    ///use oci_sdk::{
    ///    auth::InstancePrincipalAuth,
    ///    identity::{Identity},
    ///};
    ///use std::sync::Arc;
    ///
    ///let auth_provider = Arc::new(InstancePrincipalAuth::new(None));
    ///let identity = Identity::new(auth_provider, None).await.unwrap();
    ///```
    ///Returns the Identity client.
    pub async fn new(
        auth_provider: Arc<dyn AuthProvider>,
        service_endpoint: Option<String>,
    ) -> Result<Identity, AuthError> {
        let region = auth_provider.get_region().await?;
        let se =
            service_endpoint.unwrap_or(format!("https://identity.{}.oci.oraclecloud.com", region));

        Ok(Identity {
            auth_provider,
            service_endpoint: se,
        })
    }

    pub async fn get_current_user(
        &self,
    ) -> Result<Response, Box<dyn std::error::Error + Send + Sync>> {
        let client = reqwest::Client::new();

        let mut headers = HeaderMap::new();

        let now: DateTime<Utc> = Utc::now();
        headers.insert(
            "date",
            now.to_rfc2822().replace("+0000", "GMT").parse().unwrap(),
        );

        // For instance principals, we need to get the user from token info
        // For config file auth, we can use the configured user
        let _tenancy_id = self.auth_provider.get_tenancy_id().await?;
        let path = "/20160918/users/me".to_string(); // Use 'me' endpoint for current user

        sign_request(
            self.auth_provider.as_ref(),
            &mut headers,
            "get",
            &path,
            &self.service_endpoint,
        )
        .await?;

        let response = client
            .get(format!("{}{}", self.service_endpoint, path))
            .headers(headers)
            .send()
            .await?;

        Ok(response)
    }

    pub async fn get_user(
        &self,
        user_ocid: String,
    ) -> Result<Response, Box<dyn std::error::Error + Send + Sync>> {
        let client = reqwest::Client::new();

        let mut headers = HeaderMap::new();

        let now: DateTime<Utc> = Utc::now();
        headers.insert(
            "date",
            now.to_rfc2822().replace("+0000", "GMT").parse().unwrap(),
        );

        let path = format!("/20160918/users/{}", user_ocid);

        sign_request(
            self.auth_provider.as_ref(),
            &mut headers,
            "get",
            &path,
            &self.service_endpoint,
        )
        .await?;

        let response = client
            .get(format!("{}{}", self.service_endpoint, path))
            .headers(headers)
            .send()
            .await?;

        Ok(response)
    }

    pub async fn list_users(
        &self,
        compartment_id: String,
    ) -> Result<Response, Box<dyn std::error::Error + Send + Sync>> {
        let client = reqwest::Client::new();

        let mut headers = HeaderMap::new();

        let now: DateTime<Utc> = Utc::now();
        headers.insert(
            "date",
            now.to_rfc2822().replace("+0000", "GMT").parse().unwrap(),
        );

        let path = format!("/20160918/users?compartmentId={}", compartment_id);

        sign_request(
            self.auth_provider.as_ref(),
            &mut headers,
            "get",
            &path,
            &self.service_endpoint,
        )
        .await?;

        let response = client
            .get(format!("{}{}", self.service_endpoint, path))
            .headers(headers)
            .send()
            .await?;

        Ok(response)
    }
}

// Legacy implementation for backward compatibility
#[allow(deprecated)]
impl LegacyIdentity {
    pub fn new(config: AuthConfig, service_endpoint: Option<String>) -> LegacyIdentity {
        let se = service_endpoint.unwrap_or(format!(
            "https://identity.{}.oci.oraclecloud.com",
            config.region
        ));
        LegacyIdentity {
            config,
            service_endpoint: se,
        }
    }

    // Note: Legacy methods are not implemented as they require OpenSSL
    // Users should migrate to the new Identity struct with AuthProvider
}
