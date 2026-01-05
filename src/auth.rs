//! Authentication providers for OCI SDK
//!
//! This module provides different authentication mechanisms:
//! - `ConfigFileAuth`: API key-based authentication from ~/.oci/config
//! - `InstancePrincipalAuth`: Authentication using OCI compute instance identity
//! - `OkeWorkloadIdentityAuth`: Authentication for workloads running in OKE

use async_trait::async_trait;
use aws_lc_rs::rsa::KeySize;
use aws_lc_rs::signature::{KeyPair, RsaKeyPair, RSA_PKCS1_SHA256};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use reqwest::header::HeaderMap;
use serde::Deserialize;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, warn};
use x509_parser::prelude::*;

/// Errors that can occur during authentication
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
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

/// Trait for authentication providers
///
/// Implementors of this trait can sign OCI API requests and provide
/// tenancy and region information.
#[async_trait]
pub trait AuthProvider: Send + Sync {
    /// Sign a request by adding the Authorization header
    async fn sign_request(
        &self,
        headers: &mut HeaderMap,
        method: &str,
        path: &str,
        host: &str,
    ) -> Result<(), AuthError>;

    /// Get the tenancy OCID
    async fn get_tenancy_id(&self) -> Result<String, AuthError>;

    /// Get the region identifier
    async fn get_region(&self) -> Result<String, AuthError>;
}

/// Compute SHA256 hash of body and return base64-encoded result
pub fn encode_body(body: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body.as_bytes());
    let result = hasher.finalize();
    BASE64.encode(result)
}

/// Build the signing string and sign it with the provided key pair
fn sign_request_with_key(
    key_pair: &RsaKeyPair,
    key_id: &str,
    headers: &HeaderMap,
    method: &str,
    path: &str,
    host: &str,
) -> Result<String, AuthError> {
    let date = headers
        .get("date")
        .ok_or_else(|| AuthError::SigningError("Missing date header".to_string()))?
        .to_str()
        .map_err(|e| AuthError::SigningError(format!("Invalid date header: {}", e)))?;

    // Extract just the host portion, handling full URLs or bare hostnames
    let host = if host.starts_with("http://") || host.starts_with("https://") {
        // Parse as URL to extract host
        reqwest::Url::parse(host)
            .ok()
            .and_then(|u| {
                u.host_str().map(|h| {
                    // Include port if non-standard
                    if let Some(port) = u.port() {
                        format!("{}:{}", h, port)
                    } else {
                        h.to_string()
                    }
                })
            })
            .unwrap_or_else(|| host.to_string())
    } else {
        // Already just a hostname, use as-is
        host.to_string()
    };

    // Build signing string
    let mut data = format!(
        "date: {}\n(request-target): {} {}\nhost: {}",
        date, method, path, host
    );
    let mut headers_list = String::from("date (request-target) host");

    if let Some(content_length) = headers.get("content-length") {
        let cl = content_length
            .to_str()
            .map_err(|e| AuthError::SigningError(format!("Invalid content-length: {}", e)))?;
        data.push_str(&format!("\ncontent-length: {}", cl));
        headers_list.push_str(" content-length");
    }

    if let Some(content_type) = headers.get("content-type") {
        let ct = content_type
            .to_str()
            .map_err(|e| AuthError::SigningError(format!("Invalid content-type: {}", e)))?;
        data.push_str(&format!("\ncontent-type: {}", ct));
        headers_list.push_str(" content-type");
    }

    if let Some(content_sha256) = headers.get("x-content-sha256") {
        let cs = content_sha256
            .to_str()
            .map_err(|e| AuthError::SigningError(format!("Invalid x-content-sha256: {}", e)))?;
        data.push_str(&format!("\nx-content-sha256: {}", cs));
        headers_list.push_str(" x-content-sha256");
    }

    // Sign the data
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let mut signature = vec![0u8; key_pair.public_modulus_len()];
    key_pair
        .sign(&RSA_PKCS1_SHA256, &rng, data.as_bytes(), &mut signature)
        .map_err(|e| AuthError::SigningError(format!("Signing failed: {:?}", e)))?;

    let b64_signature = BASE64.encode(&signature);

    Ok(format!(
        "Signature algorithm=\"rsa-sha256\",headers=\"{}\",keyId=\"{}\",signature=\"{}\",version=\"1\"",
        headers_list, key_id, b64_signature
    ))
}

/// Map short region codes to full region identifiers
fn normalize_region(region: &str) -> String {
    match region.to_lowercase().as_str() {
        // North America
        "iad" => "us-ashburn-1",
        "phx" => "us-phoenix-1",
        "sjc" => "us-sanjose-1",
        "ord" => "us-chicago-1",
        // EMEA
        "fra" => "eu-frankfurt-1",
        "lhr" => "uk-london-1",
        "ams" => "eu-amsterdam-1",
        "zrh" => "eu-zurich-1",
        // APAC
        "nrt" => "ap-tokyo-1",
        "kix" => "ap-osaka-1",
        "icn" => "ap-seoul-1",
        "syd" => "ap-sydney-1",
        "mel" => "ap-melbourne-1",
        "bom" => "ap-mumbai-1",
        "hyd" => "ap-hyderabad-1",
        "sin" => "ap-singapore-1",
        // South America
        "gru" => "sa-saopaulo-1",
        "vcp" => "sa-vinhedo-1",
        // Middle East
        "jed" => "me-jeddah-1",
        "dxb" => "me-dubai-1",
        // If already full name or unknown, return as-is
        other => return other.to_string(),
    }
    .to_string()
}

// ============================================================================
// Config File Authentication (API Key)
// ============================================================================

/// Authentication using API key from OCI config file
pub struct ConfigFileAuth {
    pub user: String,
    pub fingerprint: String,
    pub tenancy: String,
    pub region: String,
    key_pair: RsaKeyPair,
}

impl ConfigFileAuth {
    /// Create a new ConfigFileAuth with explicit parameters
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

        Ok(Self {
            user,
            fingerprint,
            tenancy,
            region,
            key_pair,
        })
    }

    /// Load authentication from OCI config file
    ///
    /// # Arguments
    /// * `file_path` - Path to config file (defaults to ~/.oci/config)
    /// * `profile_name` - Profile name (defaults to "DEFAULT")
    pub fn from_file(
        file_path: Option<String>,
        profile_name: Option<String>,
    ) -> Result<Self, AuthError> {
        use configparser::ini::Ini;

        let fp = match file_path {
            Some(path) => path,
            None => {
                let home_dir = home::home_dir().ok_or_else(|| {
                    AuthError::ConfigError("Cannot determine home directory".to_string())
                })?;
                format!("{}/.oci/config", home_dir.to_string_lossy())
            }
        };

        let pn = profile_name.unwrap_or_else(|| "DEFAULT".to_string());

        let config_content = std::fs::read_to_string(&fp).map_err(|e| {
            AuthError::ConfigError(format!("Config file '{}' not found: {}", fp, e))
        })?;

        let mut config = Ini::new();
        config
            .read(config_content)
            .map_err(|e| AuthError::ConfigError(format!("Invalid config file: {}", e)))?;

        let user = config
            .get(&pn, "user")
            .ok_or_else(|| AuthError::ConfigError("Missing 'user' in config".to_string()))?;
        let key_file = config
            .get(&pn, "key_file")
            .ok_or_else(|| AuthError::ConfigError("Missing 'key_file' in config".to_string()))?;
        let fingerprint = config
            .get(&pn, "fingerprint")
            .ok_or_else(|| AuthError::ConfigError("Missing 'fingerprint' in config".to_string()))?;
        let tenancy = config
            .get(&pn, "tenancy")
            .ok_or_else(|| AuthError::ConfigError("Missing 'tenancy' in config".to_string()))?;
        let region = config
            .get(&pn, "region")
            .ok_or_else(|| AuthError::ConfigError("Missing 'region' in config".to_string()))?;
        let passphrase = config.get(&pn, "passphrase");

        Self::new(user, key_file, fingerprint, tenancy, region, passphrase)
    }

    fn load_private_key(
        pem_content: &str,
        passphrase: Option<&str>,
    ) -> Result<RsaKeyPair, AuthError> {
        // Handle encrypted keys if passphrase provided
        if passphrase.is_some() && !passphrase.unwrap().is_empty() {
            return Err(AuthError::KeyLoadError(
                "Encrypted keys not yet supported with aws-lc-rs. Please use an unencrypted key."
                    .to_string(),
            ));
        }

        // Parse PEM and extract DER bytes
        let pem = ::pem::parse(pem_content)
            .map_err(|e| AuthError::InvalidKeyFormat(format!("PEM parse error: {}", e)))?;

        // Try PKCS8 first, then PKCS1
        RsaKeyPair::from_pkcs8(pem.contents())
            .or_else(|_| RsaKeyPair::from_der(pem.contents()))
            .map_err(|e| AuthError::InvalidKeyFormat(format!("Key parse error: {:?}", e)))
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
        let key_id = format!("{}/{}/{}", self.tenancy, self.user, self.fingerprint);
        let authorization =
            sign_request_with_key(&self.key_pair, &key_id, headers, method, path, host)?;
        headers.insert(
            "authorization",
            authorization.parse().map_err(|e| {
                AuthError::SigningError(format!("Invalid authorization header: {}", e))
            })?,
        );
        Ok(())
    }

    async fn get_tenancy_id(&self) -> Result<String, AuthError> {
        Ok(self.tenancy.clone())
    }

    async fn get_region(&self) -> Result<String, AuthError> {
        Ok(self.region.clone())
    }
}

// ============================================================================
// Instance Principal Authentication
// ============================================================================

/// Security token and key material fetched from IMDS
struct InstanceCredentials {
    security_token: String,
    session_key_pair: RsaKeyPair, // Session key pair for signing API requests
    expires_at: SystemTime,
}

impl std::fmt::Debug for InstanceCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstanceCredentials")
            .field("security_token", &"[REDACTED]")
            .field("private_key", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Response from the federation endpoint
#[derive(Debug, Deserialize)]
struct FederationResponse {
    token: String,
}

/// Response from instance metadata
#[derive(Debug, Deserialize)]
struct InstanceMetadata {
    #[serde(rename = "tenantId")]
    tenant_id: Option<String>,
    #[serde(rename = "compartmentId")]
    compartment_id: Option<String>,
}

/// Authentication using OCI Instance Principals
///
/// This authenticator fetches credentials from the Instance Metadata Service (IMDS)
/// and uses them to sign requests. It automatically refreshes credentials before expiry.
///
/// # Example
/// ```no_run
/// use oci_sdk::auth::InstancePrincipalAuth;
/// use std::sync::Arc;
///
/// #[tokio::main]
/// async fn main() {
///     let auth = Arc::new(InstancePrincipalAuth::new(None));
///     // Use with service clients...
/// }
/// ```
pub struct InstancePrincipalAuth {
    credentials: Arc<RwLock<Option<InstanceCredentials>>>,
    region: Arc<RwLock<Option<String>>>,
    tenancy_id: Arc<RwLock<Option<String>>>,
    metadata_base_url: String,
    federation_endpoint: Option<String>,
    refresh_buffer_secs: u64,
}

impl InstancePrincipalAuth {
    /// Create a new Instance Principal authenticator
    ///
    /// # Arguments
    /// * `region` - Optional region override. If not provided, will be fetched from IMDS.
    pub fn new(region: Option<String>) -> Self {
        Self {
            credentials: Arc::new(RwLock::new(None)),
            region: Arc::new(RwLock::new(region)),
            tenancy_id: Arc::new(RwLock::new(None)),
            metadata_base_url: "http://169.254.169.254/opc/v2".to_string(),
            federation_endpoint: None,
            refresh_buffer_secs: 300, // 5 minutes before expiry
        }
    }

    /// Create with a custom federation endpoint (for testing)
    pub fn with_federation_endpoint(mut self, endpoint: String) -> Self {
        self.federation_endpoint = Some(endpoint);
        self
    }

    /// Create with a custom metadata URL (for testing)
    pub fn with_metadata_url(mut self, url: String) -> Self {
        self.metadata_base_url = url;
        self
    }

    async fn get_http_client(&self) -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    }

    /// Fetch region from IMDS
    async fn fetch_region(&self) -> Result<String, AuthError> {
        // Check cache first
        {
            let guard = self.region.read().await;
            if let Some(ref region) = *guard {
                return Ok(region.clone());
            }
        }

        let client = self.get_http_client().await;

        // Try to get region from instance metadata
        let response = client
            .get(&format!("{}/instance/region", self.metadata_base_url))
            .header("Authorization", "Bearer Oracle")
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(AuthError::MetadataError(format!(
                "Failed to get region: {}",
                response.status()
            )));
        }

        let region = response.text().await?;
        let region = normalize_region(region.trim());

        *self.region.write().await = Some(region.clone());
        Ok(region)
    }

    /// Fetch the leaf certificate and private key from IMDS
    async fn fetch_certificate_and_key(&self) -> Result<(String, String, String), AuthError> {
        let client = self.get_http_client().await;

        // Get the identity certificate
        let cert_response = client
            .get(&format!("{}/identity/cert.pem", self.metadata_base_url))
            .header("Authorization", "Bearer Oracle")
            .send()
            .await?;

        if !cert_response.status().is_success() {
            return Err(AuthError::MetadataError(format!(
                "Failed to get certificate: {}",
                cert_response.status()
            )));
        }
        let cert = cert_response.text().await?;

        // Get the private key
        let key_response = client
            .get(&format!("{}/identity/key.pem", self.metadata_base_url))
            .header("Authorization", "Bearer Oracle")
            .send()
            .await?;

        if !key_response.status().is_success() {
            return Err(AuthError::MetadataError(format!(
                "Failed to get private key: {}",
                key_response.status()
            )));
        }
        let private_key = key_response.text().await?;

        // Get the intermediate certificate
        let intermediate_response = client
            .get(&format!(
                "{}/identity/intermediate.pem",
                self.metadata_base_url
            ))
            .header("Authorization", "Bearer Oracle")
            .send()
            .await?;

        let intermediate_cert = if intermediate_response.status().is_success() {
            intermediate_response.text().await?
        } else {
            String::new()
        };

        Ok((cert, intermediate_cert, private_key))
    }

    /// Get the federation endpoint for the region
    async fn get_federation_endpoint(&self) -> Result<String, AuthError> {
        if let Some(ref endpoint) = self.federation_endpoint {
            return Ok(endpoint.clone());
        }

        let region = self.fetch_region().await?;
        Ok(format!("https://auth.{}.oraclecloud.com/v1/x509", region))
    }

    /// Exchange certificate for security token via federation endpoint
    /// Returns (security_token, session_key_pair)
    async fn fetch_security_token(
        &self,
        cert: &str,
        intermediate_cert: &str,
        leaf_key_pair: &RsaKeyPair,
    ) -> Result<(String, RsaKeyPair), AuthError> {
        let federation_url = self.get_federation_endpoint().await?;
        let client = self.get_http_client().await;

        // Generate a NEW session key pair for signing subsequent API requests
        let session_key_pair = Self::generate_session_keypair()?;
        let session_public_pem = Self::keypair_to_public_pem(&session_key_pair)?;

        // Sanitize PEM strings for base64 encoding
        let cert_sanitized = Self::sanitize_pem(cert);
        let session_public_sanitized = Self::sanitize_pem(&session_public_pem);

        // Create the X509 federation request body
        let body = serde_json::json!({
            "certificate": cert_sanitized,
            "publicKey": session_public_sanitized, // Send SESSION key's public key
            "intermediateCertificates": if intermediate_cert.is_empty() {
                Vec::<String>::new()
            } else {
                vec![Self::sanitize_pem(intermediate_cert)]
            },
            "purpose": "DEFAULT"
        });

        let body_str = serde_json::to_string(&body)?;

        // Sign this request with the LEAF certificate's private key
        let date = chrono::Utc::now()
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string();

        let mut headers = HeaderMap::new();
        headers.insert(
            "date",
            date.parse()
                .map_err(|e| AuthError::SigningError(format!("Invalid date header: {}", e)))?,
        );
        headers.insert(
            "content-type",
            "application/json".parse().map_err(|e| {
                AuthError::SigningError(format!("Invalid content-type header: {}", e))
            })?,
        );
        headers.insert(
            "content-length",
            body_str.len().to_string().parse().map_err(|e| {
                AuthError::SigningError(format!("Invalid content-length header: {}", e))
            })?,
        );
        headers.insert(
            "x-content-sha256",
            encode_body(&body_str).parse().map_err(|e| {
                AuthError::SigningError(format!("Invalid x-content-sha256 header: {}", e))
            })?,
        );

        // Parse the federation URL to get host and path
        let url = reqwest::Url::parse(&federation_url)
            .map_err(|e| AuthError::ConfigError(format!("Invalid federation URL: {}", e)))?;
        let host = url.host_str().unwrap_or("auth.oraclecloud.com");
        let path = url.path();

        // Build keyId: {tenancy_id}/fed-x509/{sha1_fingerprint}
        let tenancy_id = Self::extract_tenancy_from_cert(cert)?;
        let cert_fingerprint = Self::compute_cert_fingerprint(cert)?;
        let key_id = format!("{}/fed-x509/{}", tenancy_id, cert_fingerprint);

        let rng = aws_lc_rs::rand::SystemRandom::new();

        // Build signing string
        let date_header = headers
            .get("date")
            .ok_or_else(|| AuthError::SigningError("Missing date header".to_string()))?
            .to_str()
            .map_err(|e| AuthError::SigningError(format!("Invalid date header: {}", e)))?;
        let sha256_header = headers
            .get("x-content-sha256")
            .ok_or_else(|| AuthError::SigningError("Missing x-content-sha256 header".to_string()))?
            .to_str()
            .map_err(|e| {
                AuthError::SigningError(format!("Invalid x-content-sha256 header: {}", e))
            })?;

        let signing_string = format!(
            "date: {}\n(request-target): post {}\nhost: {}\ncontent-length: {}\ncontent-type: application/json\nx-content-sha256: {}",
            date_header,
            path,
            host,
            body_str.len(),
            sha256_header
        );

        // Sign with the LEAF certificate's private key
        let mut signature = vec![0u8; leaf_key_pair.public_modulus_len()];
        leaf_key_pair
            .sign(
                &RSA_PKCS1_SHA256,
                &rng,
                signing_string.as_bytes(),
                &mut signature,
            )
            .map_err(|e| AuthError::SigningError(format!("Federation signing failed: {:?}", e)))?;

        let b64_signature = BASE64.encode(&signature);

        let authorization = format!(
            "Signature algorithm=\"rsa-sha256\",headers=\"date (request-target) host content-length content-type x-content-sha256\",keyId=\"{}\",signature=\"{}\",version=\"1\"",
            key_id,
            b64_signature
        );

        let response = client
            .post(&federation_url)
            .header("date", date_header)
            .header("content-type", "application/json")
            .header("x-content-sha256", sha256_header)
            .header("authorization", &authorization)
            .body(body_str)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AuthError::MetadataError(format!(
                "Federation request failed: {} - {}",
                status, body
            )));
        }

        let fed_response: FederationResponse = response.json().await?;
        Ok((fed_response.token, session_key_pair))
    }

    /// Compute SHA1 fingerprint of certificate (OCI uses SHA1, not SHA256)
    fn compute_cert_fingerprint(cert_pem: &str) -> Result<String, AuthError> {
        let pem = ::pem::parse(cert_pem)
            .map_err(|e| AuthError::InvalidKeyFormat(format!("Invalid cert PEM: {}", e)))?;

        let mut hasher = Sha1::new();
        hasher.update(pem.contents());
        let result = hasher.finalize();

        // Format as colon-separated uppercase hex
        let hex: Vec<String> = result.iter().map(|b| format!("{:02X}", b)).collect();
        Ok(hex.join(":"))
    }

    /// Extract tenancy OCID from certificate subject
    fn extract_tenancy_from_cert(cert_pem: &str) -> Result<String, AuthError> {
        let pem = ::pem::parse(cert_pem)
            .map_err(|e| AuthError::InvalidKeyFormat(format!("Invalid cert PEM: {}", e)))?;

        let (_, cert) = X509Certificate::from_der(pem.contents())
            .map_err(|e| AuthError::InvalidKeyFormat(format!("Failed to parse cert: {}", e)))?;

        // Look for tenancy OCID in subject fields
        // OCI stores tenancy with prefixes: "opc-tenant:" or "opc-identity:"
        for attr in cert.subject().iter_attributes() {
            if let Ok(value) = attr.as_str() {
                if let Some(tenancy) = value.strip_prefix("opc-tenant:") {
                    return Ok(tenancy.trim().to_string());
                }
                if let Some(tenancy) = value.strip_prefix("opc-identity:") {
                    return Ok(tenancy.trim().to_string());
                }
                // Fallback: check for direct OCID (legacy behavior)
                if value.starts_with("ocid1.tenancy.") {
                    return Ok(value.trim().to_string());
                }
            }
        }

        Err(AuthError::InvalidKeyFormat(
            "No tenancy OCID found in certificate subject".to_string(),
        ))
    }

    /// Generate a new RSA 2048 session key pair
    fn generate_session_keypair() -> Result<RsaKeyPair, AuthError> {
        RsaKeyPair::generate(KeySize::Rsa2048).map_err(|e| {
            AuthError::KeyLoadError(format!("Failed to generate session key: {:?}", e))
        })
    }

    /// Extract public key from RsaKeyPair in PEM format (SPKI/X.509 format)
    fn keypair_to_public_pem(key_pair: &RsaKeyPair) -> Result<String, AuthError> {
        // aws_lc_rs returns PKCS#1 RSAPublicKey format (modulus + exponent)
        // but OCI expects SubjectPublicKeyInfo (SPKI) format
        let pkcs1_der = key_pair.public_key().as_ref();

        // Wrap PKCS#1 in SPKI structure:
        // SEQUENCE {
        //   SEQUENCE {
        //     OBJECT IDENTIFIER rsaEncryption (1.2.840.113549.1.1.1)
        //     NULL
        //   }
        //   BIT STRING { <pkcs1_der> }
        // }

        // AlgorithmIdentifier for RSA: SEQUENCE { OID, NULL }
        // OID 1.2.840.113549.1.1.1 = rsaEncryption
        let algorithm_identifier: &[u8] = &[
            0x30, 0x0D, // SEQUENCE, length 13
            0x06, 0x09, // OBJECT IDENTIFIER, length 9
            0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, // 1.2.840.113549.1.1.1
            0x05, 0x00, // NULL
        ];

        // BIT STRING wrapper for the public key
        // BIT STRING tag (0x03) + length + unused bits (0x00) + pkcs1_der
        let bit_string_len = 1 + pkcs1_der.len(); // 1 byte for unused bits + key data
        let mut bit_string = Vec::with_capacity(3 + bit_string_len);
        bit_string.push(0x03); // BIT STRING tag

        // Encode length
        if bit_string_len < 128 {
            bit_string.push(bit_string_len as u8);
        } else {
            // Long form: 0x82 means "length encoded in next 2 bytes"
            bit_string.push(0x82);
            bit_string.push((bit_string_len >> 8) as u8);
            bit_string.push((bit_string_len & 0xFF) as u8);
        }

        bit_string.push(0x00); // No unused bits
        bit_string.extend_from_slice(pkcs1_der);

        // Build the outer SEQUENCE
        let content_len = algorithm_identifier.len() + bit_string.len();
        let mut spki_der = Vec::with_capacity(4 + content_len);
        spki_der.push(0x30); // SEQUENCE tag

        // Encode length (will be > 127, so use long form)
        spki_der.push(0x82); // Long form, 2 bytes follow
        spki_der.push((content_len >> 8) as u8);
        spki_der.push((content_len & 0xFF) as u8);

        spki_der.extend_from_slice(algorithm_identifier);
        spki_der.extend_from_slice(&bit_string);

        // Encode as PEM
        let pem_obj = ::pem::Pem::new("PUBLIC KEY", spki_der);
        Ok(::pem::encode(&pem_obj))
    }

    /// Sanitize PEM by removing headers/footers and newlines for base64 encoding
    fn sanitize_pem(pem_str: &str) -> String {
        pem_str
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("")
    }

    /// Refresh credentials from IMDS
    async fn refresh_credentials(&self) -> Result<(), AuthError> {
        // Fetch certificate and key from IMDS
        let (cert, intermediate_cert, private_key_pem) = self.fetch_certificate_and_key().await?;

        // Parse the LEAF certificate's private key
        let pem = ::pem::parse(&private_key_pem)
            .map_err(|e| AuthError::InvalidKeyFormat(format!("Invalid key PEM: {}", e)))?;

        let leaf_key_pair = RsaKeyPair::from_pkcs8(pem.contents())
            .or_else(|_| RsaKeyPair::from_der(pem.contents()))
            .map_err(|e| AuthError::InvalidKeyFormat(format!("Key parse error: {:?}", e)))?;

        // Exchange for security token (returns token + session key pair)
        let (security_token, session_key_pair) = self
            .fetch_security_token(&cert, &intermediate_cert, &leaf_key_pair)
            .await?;

        // Security tokens typically expire in 1 hour
        let expires_at = SystemTime::now() + Duration::from_secs(3600);

        *self.credentials.write().await = Some(InstanceCredentials {
            security_token,
            session_key_pair, // Store the session key pair for signing API requests
            expires_at,
        });

        Ok(())
    }

    /// Get valid credentials, refreshing if needed
    async fn get_credentials(&self) -> Result<(), AuthError> {
        {
            let guard = self.credentials.read().await;
            if let Some(ref creds) = *guard {
                let buffer = Duration::from_secs(self.refresh_buffer_secs);
                if creds.expires_at > SystemTime::now() + buffer {
                    return Ok(());
                }
            }
        }

        self.refresh_credentials().await
    }

    /// Fetch tenancy ID from instance metadata
    async fn fetch_tenancy_id(&self) -> Result<String, AuthError> {
        // Check cache
        {
            let guard = self.tenancy_id.read().await;
            if let Some(ref id) = *guard {
                return Ok(id.clone());
            }
        }

        let client = self.get_http_client().await;

        let response = client
            .get(&format!("{}/instance/", self.metadata_base_url))
            .header("Authorization", "Bearer Oracle")
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(AuthError::MetadataError(format!(
                "Failed to get instance metadata: {}",
                response.status()
            )));
        }

        let metadata: InstanceMetadata = response.json().await?;

        // tenantId might be in the metadata, or we extract from compartmentId
        let tenancy = metadata
            .tenant_id
            .or(metadata.compartment_id)
            .ok_or_else(|| AuthError::MetadataError("No tenancy ID in metadata".to_string()))?;

        *self.tenancy_id.write().await = Some(tenancy.clone());
        Ok(tenancy)
    }
}

#[async_trait]
impl AuthProvider for InstancePrincipalAuth {
    async fn sign_request(
        &self,
        headers: &mut HeaderMap,
        method: &str,
        path: &str,
        host: &str,
    ) -> Result<(), AuthError> {
        // Ensure we have valid credentials
        self.get_credentials().await?;

        let guard = self.credentials.read().await;
        let creds = guard.as_ref().ok_or(AuthError::TokenExpired)?;

        // For Instance Principal, the key ID format is: ST$<security_token>
        let key_id = format!("ST${}", creds.security_token);

        // Sign with the SESSION key pair (not the leaf cert key)
        let authorization = sign_request_with_key(
            &creds.session_key_pair,
            &key_id,
            headers,
            method,
            path,
            host,
        )?;

        headers.insert(
            "authorization",
            authorization.parse().map_err(|e| {
                AuthError::SigningError(format!("Invalid authorization header: {}", e))
            })?,
        );
        Ok(())
    }

    async fn get_tenancy_id(&self) -> Result<String, AuthError> {
        self.fetch_tenancy_id().await
    }

    async fn get_region(&self) -> Result<String, AuthError> {
        self.fetch_region().await
    }
}

// ============================================================================
// OKE Workload Identity Authentication
// ============================================================================

/// Token response from proxymux endpoint
#[derive(Debug, Deserialize)]
struct ProxymuxResponse {
    token: String,
}

/// Authentication for workloads running in Oracle Kubernetes Engine (OKE)
///
/// Uses the in-cluster proxymux service to exchange K8s service account tokens
/// for OCI resource principal session tokens.
///
/// # Prerequisites
/// - Running in OKE cluster with Workload Identity enabled
/// - KUBERNETES_SERVICE_HOST environment variable set
/// - Service account token mounted at /var/run/secrets/kubernetes.io/serviceaccount/token
/// - CA cert mounted at /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
pub struct OkeWorkloadIdentityAuth {
    credentials: Arc<RwLock<Option<InstanceCredentials>>>,
    region: Option<String>,
    service_host: String,
    service_port: u16,
    sa_token_path: String,
    #[allow(dead_code)] // Used during build to configure http_client
    sa_cert_path: String,
    http_client: reqwest::Client,
    imds_client: reqwest::Client,
}

impl OkeWorkloadIdentityAuth {
    const DEFAULT_SA_TOKEN_PATH: &'static str =
        "/var/run/secrets/kubernetes.io/serviceaccount/token";
    const DEFAULT_SA_CERT_PATH: &'static str =
        "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
    const PROXYMUX_PORT: u16 = 12250;
    const PROXYMUX_PATH: &'static str = "/resourcePrincipalSessionTokens";
    const IMDS_BASE_URL: &'static str = "http://169.254.169.254/opc/v2";

    /// Create from environment variables
    pub fn new() -> Result<Self, AuthError> {
        Self::builder().build()
    }

    /// Builder for explicit configuration
    pub fn builder() -> OkeWorkloadIdentityAuthBuilder {
        OkeWorkloadIdentityAuthBuilder::default()
    }

    /// Sanitize public key PEM - remove headers/footers and newlines
    fn sanitize_public_key(pem: &str) -> String {
        pem.lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("")
    }

    /// Generate RSA 2048 session keypair
    fn generate_session_keypair() -> Result<RsaKeyPair, AuthError> {
        RsaKeyPair::generate(KeySize::Rsa2048).map_err(|e| {
            AuthError::InvalidKeyFormat(format!("Failed to generate keypair: {:?}", e))
        })
    }

    /// Extract public key from keypair as PEM (SPKI format)
    fn extract_public_key_pem(key_pair: &RsaKeyPair) -> Result<String, AuthError> {
        let pkcs1_der = key_pair.public_key().as_ref();

        // Wrap PKCS#1 in SPKI structure
        let spki_der = {
            let mut spki = Vec::new();

            // SEQUENCE tag + length placeholder
            spki.push(0x30);
            let len_pos = spki.len();
            spki.push(0x00); // placeholder

            // AlgorithmIdentifier SEQUENCE
            spki.extend_from_slice(&[
                0x30, 0x0d, // SEQUENCE, length 13
                0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
                0x01, // OID rsaEncryption
                0x05, 0x00, // NULL
            ]);

            // BIT STRING containing PKCS#1 public key
            spki.push(0x03); // BIT STRING tag
            let bit_string_len = pkcs1_der.len() + 1;
            if bit_string_len < 128 {
                spki.push(bit_string_len as u8);
            } else {
                spki.push(0x82);
                spki.push((bit_string_len >> 8) as u8);
                spki.push((bit_string_len & 0xff) as u8);
            }
            spki.push(0x00); // no unused bits
            spki.extend_from_slice(pkcs1_der);

            // Fix outer SEQUENCE length
            let total_len = spki.len() - 2;
            if total_len < 128 {
                spki[len_pos] = total_len as u8;
            } else {
                spki.insert(len_pos, 0x82);
                spki.insert(len_pos + 1, (total_len >> 8) as u8);
                spki.insert(len_pos + 2, (total_len & 0xff) as u8);
            }

            spki
        };

        let pem = ::pem::Pem::new("PUBLIC KEY", spki_der);
        Ok(::pem::encode(&pem))
    }

    /// Read K8s service account token
    fn read_sa_token(&self) -> Result<String, AuthError> {
        debug!(path = %self.sa_token_path, "Reading K8s service account token");
        std::fs::read_to_string(&self.sa_token_path)
            .map(|s| {
                let token = s.trim().to_string();
                let token_preview = if token.len() > 20 {
                    format!("{}...{}", &token[..10], &token[token.len()-10..])
                } else {
                    "[short]".to_string()
                };
                debug!(path = %self.sa_token_path, token_preview = %token_preview, "Successfully read SA token");
                token
            })
            .map_err(|e| {
                error!(path = %self.sa_token_path, error = %e, "Failed to read K8s SA token");
                AuthError::ConfigError(format!(
                    "Failed to read K8s SA token at {}: {}",
                    self.sa_token_path, e
                ))
            })
    }

    /// Fetch resource principal session token from proxymux
    #[instrument(skip(self), fields(host = %self.service_host, port = %self.service_port))]
    async fn fetch_session_token(&self) -> Result<InstanceCredentials, AuthError> {
        debug!("Starting session token fetch from proxymux");

        let sa_token = self.read_sa_token()?;
        let session_key_pair = Self::generate_session_keypair()?;
        let public_key_pem = Self::extract_public_key_pem(&session_key_pair)?;
        let sanitized_key = Self::sanitize_public_key(&public_key_pem);

        let url = format!(
            "https://{}:{}{}",
            self.service_host,
            self.service_port,
            Self::PROXYMUX_PATH
        );

        debug!(
            url = %url,
            service_host = %self.service_host,
            service_port = %self.service_port,
            "Calling proxymux endpoint"
        );

        let body = serde_json::json!({
            "podKey": sanitized_key
        });

        let response = self
            .http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", sa_token))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;

        let status = response.status();
        debug!(status = %status, "Received response from proxymux");

        if !status.is_success() {
            let headers = response.headers().clone();
            let body = response.text().await.unwrap_or_default();

            warn!(
                status = %status,
                status_code = status.as_u16(),
                body = %body,
                headers = ?headers,
                url = %url,
                service_host = %self.service_host,
                service_port = %self.service_port,
                "Proxymux request failed"
            );

            return Err(AuthError::MetadataError(format!(
                "Proxymux request failed: {} - {}",
                status, body
            )));
        }

        // Response is base64-encoded JSON
        let response_text = response.text().await?;
        debug!(
            response_len = response_text.len(),
            "Received base64-encoded response"
        );

        let decoded = BASE64.decode(response_text.as_bytes()).map_err(|e| {
            error!(error = %e, "Failed to decode base64 response");
            AuthError::InvalidKeyFormat(format!("Failed to decode response: {}", e))
        })?;

        let proxymux_response: ProxymuxResponse = serde_json::from_slice(&decoded)?;

        // Parse JWT to get expiry
        let parts: Vec<&str> = proxymux_response.token.split('.').collect();
        if parts.len() != 3 {
            error!("Invalid JWT format: expected 3 parts, got {}", parts.len());
            return Err(AuthError::InvalidKeyFormat(
                "Invalid JWT format".to_string(),
            ));
        }

        let payload = BASE64.decode(parts[1]).map_err(|e| {
            error!(error = %e, "Failed to decode JWT payload");
            AuthError::InvalidKeyFormat(format!("Failed to decode JWT: {}", e))
        })?;

        let claims: serde_json::Value = serde_json::from_slice(&payload)?;
        let exp = claims["exp"].as_u64().ok_or_else(|| {
            error!("No exp claim in token");
            AuthError::InvalidKeyFormat("No exp claim in token".to_string())
        })?;

        let expires_at = SystemTime::UNIX_EPOCH + Duration::from_secs(exp);

        if let Ok(duration) = expires_at.duration_since(SystemTime::now()) {
            info!(
                expires_in_secs = duration.as_secs(),
                expires_at_unix = exp,
                "Successfully fetched session token"
            );
        } else {
            warn!(expires_at_unix = exp, "Token already expired");
        }

        Ok(InstanceCredentials {
            security_token: proxymux_response.token,
            session_key_pair,
            expires_at,
        })
    }

    /// Get valid credentials, refreshing at half-life
    #[instrument(skip(self))]
    async fn get_credentials(&self) -> Result<(), AuthError> {
        {
            let guard = self.credentials.read().await;
            if let Some(ref creds) = *guard {
                // Refresh at half-life: check if we're past the halfway point to expiry
                let now = SystemTime::now();
                if let Ok(time_until_expiry) = creds.expires_at.duration_since(now) {
                    // Token is still valid, check if we're in the first half of its lifetime
                    // We need to know when it was issued to calculate half-life
                    // For simplicity, assume tokens are valid for 1 hour and refresh at 30 min remaining
                    if time_until_expiry > Duration::from_secs(1800) {
                        debug!(
                            time_until_expiry_secs = time_until_expiry.as_secs(),
                            "Credentials cache hit - token still valid"
                        );
                        return Ok(());
                    } else {
                        debug!(
                            time_until_expiry_secs = time_until_expiry.as_secs(),
                            "Credentials need refresh - approaching expiry"
                        );
                    }
                } else {
                    warn!("Token expired, refreshing");
                }
            } else {
                debug!("No cached credentials, fetching new token");
            }
        }

        debug!("Fetching new session token");
        let creds = self.fetch_session_token().await?;
        *self.credentials.write().await = Some(creds);
        debug!("Credentials refreshed successfully");
        Ok(())
    }

    /// Fetch region from Instance Metadata Service
    async fn fetch_region_from_imds(&self) -> Result<String, AuthError> {
        let response = self
            .imds_client
            .get(format!("{}/instance/region", Self::IMDS_BASE_URL))
            .header("Authorization", "Bearer Oracle")
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(AuthError::MetadataError(format!(
                "Failed to get region from IMDS: {}",
                response.status()
            )));
        }

        let region = response.text().await?;
        Ok(normalize_region(region.trim()))
    }
}

#[async_trait]
impl AuthProvider for OkeWorkloadIdentityAuth {
    #[instrument(skip(self, headers), fields(method = %method, path = %path, host = %host))]
    async fn sign_request(
        &self,
        headers: &mut HeaderMap,
        method: &str,
        path: &str,
        host: &str,
    ) -> Result<(), AuthError> {
        debug!("Starting request signing");
        self.get_credentials().await?;

        let guard = self.credentials.read().await;
        let creds = guard.as_ref().ok_or(AuthError::TokenExpired)?;

        // Key ID is ST${token} (full token including ST$ prefix if present)
        let key_id = if creds.security_token.starts_with("ST$") {
            creds.security_token.clone()
        } else {
            format!("ST${}", creds.security_token)
        };

        let authorization = sign_request_with_key(
            &creds.session_key_pair,
            &key_id,
            headers,
            method,
            path,
            host,
        )?;

        headers.insert(
            "authorization",
            authorization.parse().map_err(|e| {
                AuthError::SigningError(format!("Invalid authorization header: {}", e))
            })?,
        );
        debug!("Request signed successfully");
        Ok(())
    }

    async fn get_tenancy_id(&self) -> Result<String, AuthError> {
        self.get_credentials().await?;

        let guard = self.credentials.read().await;
        let creds = guard.as_ref().ok_or(AuthError::TokenExpired)?;

        // Parse JWT to get tenancy
        let parts: Vec<&str> = creds.security_token.split('.').collect();
        if parts.len() >= 2 {
            if let Ok(payload) = BASE64.decode(parts[1]) {
                if let Ok(claims) = serde_json::from_slice::<serde_json::Value>(&payload) {
                    if let Some(tenancy) = claims["tenant"].as_str() {
                        return Ok(tenancy.to_string());
                    }
                }
            }
        }

        Err(AuthError::MetadataError(
            "Could not extract tenancy from token".to_string(),
        ))
    }

    async fn get_region(&self) -> Result<String, AuthError> {
        // 1. Explicit region config
        if let Some(ref region) = self.region {
            return Ok(region.clone());
        }

        // 2. Try to extract from token claims
        if let Ok(()) = self.get_credentials().await {
            let guard = self.credentials.read().await;
            if let Some(ref creds) = *guard {
                let parts: Vec<&str> = creds.security_token.split('.').collect();
                if parts.len() >= 2 {
                    if let Ok(payload) = BASE64.decode(parts[1]) {
                        if let Ok(claims) = serde_json::from_slice::<serde_json::Value>(&payload) {
                            if let Some(region) = claims["region"].as_str() {
                                return Ok(region.to_string());
                            }
                        }
                    }
                }
            }
        }

        // 3. Auto-detect from IMDS
        self.fetch_region_from_imds().await
    }
}

/// Builder for OkeWorkloadIdentityAuth
#[derive(Default)]
pub struct OkeWorkloadIdentityAuthBuilder {
    service_host: Option<String>,
    service_port: Option<u16>,
    region: Option<String>,
    sa_token_path: Option<String>,
    sa_cert_path: Option<String>,
}

impl OkeWorkloadIdentityAuthBuilder {
    pub fn service_host(mut self, host: String) -> Self {
        self.service_host = Some(host);
        self
    }

    pub fn service_port(mut self, port: u16) -> Self {
        self.service_port = Some(port);
        self
    }

    pub fn region(mut self, region: String) -> Self {
        self.region = Some(region);
        self
    }

    pub fn sa_token_path(mut self, path: String) -> Self {
        self.sa_token_path = Some(path);
        self
    }

    pub fn sa_cert_path(mut self, path: String) -> Self {
        self.sa_cert_path = Some(path);
        self
    }

    pub fn build(self) -> Result<OkeWorkloadIdentityAuth, AuthError> {
        let service_host = self
            .service_host
            .or_else(|| std::env::var("KUBERNETES_SERVICE_HOST").ok())
            .ok_or_else(|| {
                AuthError::ConfigError(
                    "KUBERNETES_SERVICE_HOST not set and not provided".to_string(),
                )
            })?;

        let region = self
            .region
            .or_else(|| std::env::var("OCI_RESOURCE_PRINCIPAL_REGION").ok());

        let sa_token_path = self
            .sa_token_path
            .unwrap_or_else(|| OkeWorkloadIdentityAuth::DEFAULT_SA_TOKEN_PATH.to_string());

        let sa_cert_path = self
            .sa_cert_path
            .or_else(|| std::env::var("OCI_KUBERNETES_SERVICE_ACCOUNT_CERT_PATH").ok())
            .unwrap_or_else(|| OkeWorkloadIdentityAuth::DEFAULT_SA_CERT_PATH.to_string());

        // Load CA cert for TLS verification
        let ca_cert_pem = std::fs::read(&sa_cert_path).map_err(|e| {
            AuthError::ConfigError(format!("Failed to read CA cert at {}: {}", sa_cert_path, e))
        })?;

        let ca_cert = reqwest::Certificate::from_pem(&ca_cert_pem)
            .map_err(|e| AuthError::ConfigError(format!("Failed to parse CA cert: {}", e)))?;

        let http_client = reqwest::Client::builder()
            .add_root_certificate(ca_cert)
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| AuthError::ConfigError(format!("Failed to build HTTP client: {}", e)))?;

        let imds_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| AuthError::ConfigError(format!("Failed to build IMDS client: {}", e)))?;

        Ok(OkeWorkloadIdentityAuth {
            credentials: Arc::new(RwLock::new(None)),
            region,
            service_host,
            service_port: self
                .service_port
                .unwrap_or(OkeWorkloadIdentityAuth::PROXYMUX_PORT),
            sa_token_path,
            sa_cert_path,
            http_client,
            imds_client,
        })
    }
}

// ============================================================================
// Resource Principal Authentication (Alternative name for OKE Workload Identity)
// ============================================================================

/// Alias for OKE Workload Identity - Resource Principals is another name for this mechanism
pub type ResourcePrincipalAuth = OkeWorkloadIdentityAuth;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_body() {
        let body = r#"{"test": "value"}"#;
        let encoded = encode_body(body);
        assert!(!encoded.is_empty());
        // Verify it's valid base64
        assert!(BASE64.decode(&encoded).is_ok());
    }

    #[test]
    fn test_config_file_auth_missing_file() {
        let result = ConfigFileAuth::from_file(Some("/nonexistent/path/config".to_string()), None);
        assert!(result.is_err());
    }
}
