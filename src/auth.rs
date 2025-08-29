use async_trait::async_trait;
use aws_lc_rs::signature::{RsaKeyPair, RSA_PKCS1_SHA256};
use base64::{engine::general_purpose, Engine as _};
// Remove unused imports
use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Failed to load private key: {0}")]
    KeyLoadError(String),
    #[error("Failed to sign request: {0}")]
    SigningError(String),
    #[error("Failed to get instance metadata: {0}")]
    MetadataError(String),
    #[error("Token expired or invalid")]
    TokenExpired,
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),
    #[error("JSON parsing error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InstancePrincipalToken {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    #[serde(skip, default = "SystemTime::now")]
    pub expires_at: SystemTime,
}

impl InstancePrincipalToken {
    pub fn is_expired(&self) -> bool {
        SystemTime::now() > self.expires_at
    }

    pub fn is_expiring_soon(&self, buffer_seconds: u64) -> bool {
        let buffer_time = self.expires_at - Duration::from_secs(buffer_seconds);
        SystemTime::now() > buffer_time
    }
}

#[async_trait]
pub trait AuthProvider: Send + Sync {
    async fn sign_request(
        &self,
        headers: &mut HeaderMap,
        method: &str,
        path: &str,
        host: &str,
    ) -> Result<(), AuthError>;

    async fn get_tenancy_id(&self) -> Result<String, AuthError>;
    async fn get_region(&self) -> Result<String, AuthError>;
}

pub struct ConfigFileAuth {
    pub user: String,
    pub fingerprint: String,
    pub tenancy: String,
    pub region: String,
    pub key_pair: RsaKeyPair,
}

impl ConfigFileAuth {
    pub fn new(
        user: String,
        key_file: String,
        fingerprint: String,
        tenancy: String,
        region: String,
        passphrase: Option<String>,
    ) -> Result<Self, AuthError> {
        let key_content = std::fs::read_to_string(&key_file)
            .map_err(|e| AuthError::KeyLoadError(format!("Failed to read key file: {}", e)))?;

        let key_pair = Self::load_private_key(&key_content, passphrase.as_deref())?;

        Ok(ConfigFileAuth {
            user,
            fingerprint,
            tenancy,
            region,
            key_pair,
        })
    }

    fn load_private_key(
        pem_content: &str,
        _passphrase: Option<&str>,
    ) -> Result<RsaKeyPair, AuthError> {
        // Remove PEM headers and footers, and decode base64
        let pem_content = pem_content
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<Vec<&str>>()
            .join("");

        let der_bytes = general_purpose::STANDARD
            .decode(pem_content)
            .map_err(|e| AuthError::InvalidKeyFormat(format!("Base64 decode error: {}", e)))?;

        RsaKeyPair::from_pkcs8(&der_bytes)
            .map_err(|e| AuthError::InvalidKeyFormat(format!("PKCS8 parse error: {:?}", e)))
    }

    pub fn from_file(file_path: Option<String>, profile_name: Option<String>) -> Result<Self, AuthError> {
        use configparser::ini::Ini;

        let fp = if let Some(path) = file_path {
            path
        } else {
            let home_dir = home::home_dir()
                .ok_or_else(|| AuthError::KeyLoadError("Cannot determine home directory".to_string()))?;
            format!("{}/.oci/config", home_dir.to_string_lossy())
        };

        let pn = profile_name.unwrap_or_else(|| "DEFAULT".to_string());

        let config_content = std::fs::read_to_string(&fp)
            .map_err(|e| AuthError::KeyLoadError(format!("Config file '{}' not found: {}", fp, e)))?;

        let mut config = Ini::new();
        config
            .read(config_content)
            .map_err(|e| AuthError::KeyLoadError(format!("Invalid config file: {}", e)))?;

        let user = config
            .get(&pn, "user")
            .ok_or_else(|| AuthError::KeyLoadError("Missing 'user' in config".to_string()))?;
        let key_file = config
            .get(&pn, "key_file")
            .ok_or_else(|| AuthError::KeyLoadError("Missing 'key_file' in config".to_string()))?;
        let fingerprint = config
            .get(&pn, "fingerprint")
            .ok_or_else(|| AuthError::KeyLoadError("Missing 'fingerprint' in config".to_string()))?;
        let tenancy = config
            .get(&pn, "tenancy")
            .ok_or_else(|| AuthError::KeyLoadError("Missing 'tenancy' in config".to_string()))?;
        let region = config
            .get(&pn, "region")
            .ok_or_else(|| AuthError::KeyLoadError("Missing 'region' in config".to_string()))?;
        let passphrase = config.get(&pn, "passphrase");

        Self::new(user, key_file, fingerprint, tenancy, region, passphrase)
    }
}

#[async_trait]
impl AuthProvider for ConfigFileAuth {
    async fn sign_request(
        &self,
        headers: &mut HeaderMap,
        method: &str,
        path: &str,
        host: &str,
    ) -> Result<(), AuthError> {
        // Remove unused import - we'll use the signing directly

        let date = headers
            .get("date")
            .ok_or_else(|| AuthError::SigningError("Missing date header".to_string()))?
            .to_str()
            .map_err(|e| AuthError::SigningError(format!("Invalid date header: {}", e)))?;

        let host = host.replace("http://", "").replace("https://", "");

        let mut data = format!("date: {}\n(request-target): {} {}\nhost: {}", date, method, path, host);
        let mut headers_auth = String::from("date (request-target) host");

        if let Some(content_length) = headers.get("content-length") {
            let content_length_str = content_length
                .to_str()
                .map_err(|e| AuthError::SigningError(format!("Invalid content-length header: {}", e)))?;
            data = format!("{}\ncontent-length: {}", data, content_length_str);
            headers_auth = format!("{} content-length", headers_auth);
        }

        if let Some(content_type) = headers.get("content-type") {
            let content_type_str = content_type
                .to_str()
                .map_err(|e| AuthError::SigningError(format!("Invalid content-type header: {}", e)))?;
            data = format!("{}\ncontent-type: {}", data, content_type_str);
            headers_auth = format!("{} content-type", headers_auth);
        }

        if let Some(content_sha256) = headers.get("x-content-sha256") {
            let content_sha256_str = content_sha256
                .to_str()
                .map_err(|e| AuthError::SigningError(format!("Invalid x-content-sha256 header: {}", e)))?;
            data = format!("{}\nx-content-sha256: {}", data, content_sha256_str);
            headers_auth = format!("{} x-content-sha256", headers_auth);
        }

        use aws_lc_rs::rand::SystemRandom;
        let rng = SystemRandom::new();
        let mut signature = vec![0u8; self.key_pair.public_modulus_len()];
        self.key_pair
            .sign(&RSA_PKCS1_SHA256, &rng, data.as_bytes(), &mut signature)
            .map_err(|e| AuthError::SigningError(format!("Signing failed: {:?}", e)))?;

        let b64_signature = general_purpose::STANDARD.encode(&signature);
        let key_id = format!("{}/{}/{}", self.tenancy, self.user, self.fingerprint);
        let authorization = format!(
            "Signature algorithm=\"rsa-sha256\",headers=\"{}\",keyId=\"{}\",signature=\"{}\",version=\"1\"",
            headers_auth, key_id, b64_signature
        );

        headers.insert("authorization", authorization.parse().unwrap());
        Ok(())
    }

    async fn get_tenancy_id(&self) -> Result<String, AuthError> {
        Ok(self.tenancy.clone())
    }

    async fn get_region(&self) -> Result<String, AuthError> {
        Ok(self.region.clone())
    }
}

pub struct InstancePrincipalAuth {
    token_manager: crate::token_manager::InstancePrincipalTokenManager,
    tenancy_id: Arc<RwLock<Option<String>>>,
    region: String,
    metadata_base_url: String,
}

impl InstancePrincipalAuth {
    pub fn new(region: Option<String>) -> Self {
        let region = region.unwrap_or_else(|| "us-ashburn-1".to_string());
        
        // Create token manager with custom config for OCI
        let config = crate::token_manager::TokenManagerConfig {
            refresh_buffer: Duration::from_secs(300), // 5 minutes before expiry
            check_interval: Duration::from_secs(60),  // Check every minute
            max_waiters: 50,
            auto_refresh: true,
        };
        
        let token_manager = crate::token_manager::InstancePrincipalTokenManager::new(
            Some(region.clone()), 
            Some(config)
        );
        
        Self {
            token_manager,
            tenancy_id: Arc::new(RwLock::new(None)),
            region,
            metadata_base_url: "http://169.254.169.254/opc/v2".to_string(),
        }
    }

    /// Get a valid token, automatically refreshing if needed
    async fn get_valid_token(&self) -> Result<String, AuthError> {
        self.token_manager
            .get_token()
            .await
            .map_err(|e| match e {
                crate::token_manager::TokenError::Expired => AuthError::TokenExpired,
                crate::token_manager::TokenError::MetadataError(msg) => AuthError::MetadataError(msg),
                crate::token_manager::TokenError::HttpError(e) => AuthError::HttpError(e),
                crate::token_manager::TokenError::JsonError(e) => AuthError::JsonError(e),
                crate::token_manager::TokenError::RefreshFailed(msg) => AuthError::MetadataError(msg),
            })
    }

    /// Force refresh the token
    pub async fn refresh_token(&self) -> Result<(), AuthError> {
        self.token_manager
            .refresh_token()
            .await
            .map(|_| ())
            .map_err(|e| match e {
                crate::token_manager::TokenError::Expired => AuthError::TokenExpired,
                crate::token_manager::TokenError::MetadataError(msg) => AuthError::MetadataError(msg),
                crate::token_manager::TokenError::HttpError(e) => AuthError::HttpError(e),
                crate::token_manager::TokenError::JsonError(e) => AuthError::JsonError(e),
                crate::token_manager::TokenError::RefreshFailed(msg) => AuthError::MetadataError(msg),
            })
    }

    /// Get token information for monitoring/debugging
    pub async fn get_token_info(&self) -> Option<crate::token_manager::TokenInfo> {
        self.token_manager.get_token_info().await
    }

    /// Check if the token manager has a token
    pub async fn has_token(&self) -> bool {
        self.token_manager.has_token().await
    }

    /// Stop the background token refresh (useful for cleanup)
    pub async fn stop(&self) {
        self.token_manager.stop().await;
    }

    async fn get_tenancy_from_metadata(&self) -> Result<String, AuthError> {
        {
            let tenancy_guard = self.tenancy_id.read().await;
            if let Some(ref tenancy) = *tenancy_guard {
                return Ok(tenancy.clone());
            }
        }

        // Get metadata token for tenancy lookup
        let client = reqwest::Client::new();
        let metadata_response = client
            .put(&format!("{}/identity/token", self.metadata_base_url))
            .header("Metadata-Flavor", "Oracle")
            .header("Authorization", "Bearer Oracle")
            .send()
            .await?;

        if !metadata_response.status().is_success() {
            return Err(AuthError::MetadataError(format!(
                "Failed to get metadata token: {}",
                metadata_response.status()
            )));
        }

        let metadata_token = metadata_response.text().await?;
        
        let response = client
            .get(&format!("{}/identity/tenancy", self.metadata_base_url))
            .header("Metadata-Flavor", "Oracle")
            .header("Authorization", &format!("Bearer {}", metadata_token))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(AuthError::MetadataError(format!(
                "Failed to get tenancy from metadata: {}",
                response.status()
            )));
        }

        let tenancy_id = response.text().await?;
        *self.tenancy_id.write().await = Some(tenancy_id.clone());
        
        Ok(tenancy_id)
    }
}

#[async_trait]
impl AuthProvider for InstancePrincipalAuth {
    async fn sign_request(
        &self,
        headers: &mut HeaderMap,
        _method: &str,
        _path: &str,
        _host: &str,
    ) -> Result<(), AuthError> {
        let token = self.get_valid_token().await?;
        headers.insert("authorization", format!("Bearer {}", token).parse().unwrap());
        Ok(())
    }

    async fn get_tenancy_id(&self) -> Result<String, AuthError> {
        self.get_tenancy_from_metadata().await
    }

    async fn get_region(&self) -> Result<String, AuthError> {
        Ok(self.region.clone())
    }
}

// The start_token_refresh_task function is no longer needed
// Token refresh is now handled automatically by the TokenManager
