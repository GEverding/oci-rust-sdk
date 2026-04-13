//! Authentication providers for OCI SDK
//!
//! This module provides different authentication mechanisms:
//! - `ConfigFileAuth`: API key-based authentication from ~/.oci/config
//! - `InstancePrincipalAuth`: Authentication using OCI compute instance identity
//! - `OkeWorkloadIdentityAuth`: Authentication for workloads running in OKE

use async_trait::async_trait;
use aws_lc_rs::rsa::KeySize;
use aws_lc_rs::signature::{KeyPair, RsaKeyPair, RSA_PKCS1_SHA256};
use base64::{
    engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD as BASE64_URL},
    Engine,
};
use reqwest::header::HeaderMap;
use serde::Deserialize;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use thiserror::Error;
use tokio::sync::{Mutex, RwLock};
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

    /// Invalidate cached credentials, forcing re-authentication on the next request.
    /// Default is a no-op (e.g., API key auth never expires).
    async fn invalidate_credentials(&self) {}

    /// Returns true if this auth provider issues region-scoped tokens.
    /// Region-scoped providers (instance principal, workload identity) cannot
    /// authenticate against services in a different region.
    fn is_region_scoped(&self) -> bool {
        false // default: not region-scoped (safe for API key, config file)
    }
}

/// Compute SHA256 hash of body and return base64-encoded result
pub fn encode_body(body: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body.as_bytes());
    let result = hasher.finalize();
    BASE64.encode(result)
}

/// Validates that a K8s service account token has not expired.
/// Decodes the JWT payload without signature verification, checks the exp claim.
fn validate_sa_token(token: &str) -> Result<(), AuthError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AuthError::MetadataError(
            "SA token is not a valid JWT (expected 3 parts)".into(),
        ));
    }
    let payload = BASE64_URL
        .decode(parts[1])
        .or_else(|_| BASE64.decode(parts[1]))
        .map_err(|e| {
            AuthError::MetadataError(format!("Failed to decode SA token payload: {}", e))
        })?;
    let claims: serde_json::Value = serde_json::from_slice(&payload)
        .map_err(|e| AuthError::MetadataError(format!("Failed to parse SA token claims: {}", e)))?;
    let exp = claims["exp"]
        .as_u64()
        .ok_or_else(|| AuthError::MetadataError("SA token has no 'exp' claim".into()))?;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if now >= exp {
        return Err(AuthError::MetadataError(format!(
            "K8s service account token has expired (exp: {}, now: {}). The kubelet may not be refreshing projected tokens.", exp, now
        )));
    }
    Ok(())
}

/// Parse JWT to extract both issued_at (iat) and expiry (exp) times.
fn parse_jwt_times(token: &str) -> Result<(SystemTime, SystemTime), AuthError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AuthError::MetadataError("Invalid JWT format".into()));
    }
    let payload = BASE64_URL
        .decode(parts[1])
        .or_else(|_| BASE64.decode(parts[1]))
        .map_err(|e| AuthError::MetadataError(format!("Failed to decode JWT: {}", e)))?;
    let claims: serde_json::Value = serde_json::from_slice(&payload)
        .map_err(|e| AuthError::MetadataError(format!("Failed to parse JWT: {}", e)))?;
    let exp = claims["exp"]
        .as_u64()
        .ok_or_else(|| AuthError::MetadataError("JWT missing 'exp' claim".into()))?;
    let iat = claims["iat"]
        .as_u64()
        .unwrap_or_else(|| exp.saturating_sub(3600)); // default: assume 1h token
    Ok((
        SystemTime::UNIX_EPOCH + Duration::from_secs(iat),
        SystemTime::UNIX_EPOCH + Duration::from_secs(exp),
    ))
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

/// Generates an OCI opc-request-id: <32hex>/<32hex>/<32hex>
fn generate_opc_request_id() -> String {
    use aws_lc_rs::rand::SecureRandom;
    use aws_lc_rs::rand::SystemRandom;
    use std::fmt::Write;
    let rng = SystemRandom::new();
    let mut id = String::with_capacity(98);
    for segment in 0..3 {
        if segment > 0 {
            id.push('/');
        }
        let mut bytes = [0u8; 16];
        rng.fill(&mut bytes)
            .expect("failed to generate random bytes");
        for byte in bytes {
            write!(id, "{:02x}", byte).expect("hex write failed");
        }
    }
    id
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

/// Extracts the OCI region from a service endpoint URL.
/// Returns None if the URL doesn't match known OCI endpoint patterns.
///
/// # Examples
/// - `https://objectstorage.us-ashburn-1.oraclecloud.com` → `Some("us-ashburn-1")`
/// - `https://identity.us-ashburn-1.oci.oraclecloud.com` → `Some("us-ashburn-1")`
/// - `https://cell-1.queue.messaging.us-phoenix-1.oci.oraclecloud.com` → `Some("us-phoenix-1")`
/// - `https://localhost:8080` → `None`
#[must_use]
pub fn extract_region_from_endpoint(endpoint: &str) -> Option<String> {
    // Parse the URL to get the hostname
    let url = reqwest::Url::parse(endpoint).ok()?;
    let hostname = url.host_str()?;

    // Split hostname by '.'
    let parts: Vec<&str> = hostname.split('.').collect();

    // Look for "oraclecloud" in the parts
    let oraclecloud_idx = parts.iter().position(|&p| p == "oraclecloud")?;

    // The region is the segment immediately before "oraclecloud"
    if oraclecloud_idx == 0 {
        return None; // "oraclecloud" is the first part, no region before it
    }

    let region_idx = oraclecloud_idx - 1;
    let potential_region = parts[region_idx];

    // If the segment before "oraclecloud" is "oci", the region is one more segment back
    let region = if potential_region == "oci" {
        if region_idx == 0 {
            return None; // "oci" is the first part, no region before it
        }
        parts[region_idx - 1]
    } else {
        potential_region
    };

    // Run through normalize_region for consistency
    Some(normalize_region(region))
}

/// Warns if a region-scoped auth provider is being used with a cross-region endpoint.
/// Call this from client constructors when a service_endpoint override is provided.
///
/// # Arguments
/// * `auth` - The authentication provider
/// * `auth_region` - The region from the auth provider (already resolved)
/// * `service_endpoint` - The service endpoint URL being used
pub fn warn_cross_region(auth: &dyn AuthProvider, auth_region: &str, service_endpoint: &str) {
    if !auth.is_region_scoped() {
        return;
    }
    if let Some(endpoint_region) = extract_region_from_endpoint(service_endpoint) {
        let normalized_auth = normalize_region(auth_region);
        if normalized_auth != endpoint_region {
            warn!(
                auth_region = %normalized_auth,
                endpoint_region = %endpoint_region,
                service_endpoint = %service_endpoint,
                "Cross-region request with region-scoped auth provider. \
                 Security tokens from workload identity and instance principal \
                 are region-bound and will be rejected by services in other regions."
            );
        }
    }
}

/// Resolves the service endpoint for a client.
///
/// This function implements the standard endpoint resolution pattern for all OCI SDK clients.
/// It follows a priority order to determine which endpoint to use:
///
/// 1. **`service_endpoint`** — if provided, use as-is (escape hatch for custom/private endpoints)
/// 2. **`region`** — if provided, interpolate into the URL template
/// 3. **`auth.get_region()`** — default fallback to the auth provider's region
///
/// After resolution, calls [`warn_cross_region`] if the auth provider is region-scoped and
/// the resolved endpoint is in a different region.
///
/// # Arguments
/// * `auth` - The authentication provider
/// * `url_template` - The URL template with `{region}` placeholder (e.g., `"https://objectstorage.{region}.oraclecloud.com"`)
/// * `region` - Optional region override
/// * `service_endpoint` - Optional service endpoint override (takes precedence)
///
/// # Returns
/// The resolved endpoint URL as a `String`.
///
/// # Errors
/// Returns `AuthError` if `auth.get_region()` fails and neither `region` nor `service_endpoint` are provided.
///
/// # Example
/// ```no_run
/// use oci_sdk::auth::{resolve_endpoint, ConfigFileAuth};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let auth = ConfigFileAuth::from_file(None, None)?;
/// let endpoint = resolve_endpoint(
///     &auth,
///     "https://objectstorage.{region}.oraclecloud.com",
///     None,
///     None,
/// ).await?;
/// println!("Using endpoint: {}", endpoint);
/// # Ok(())
/// # }
/// ```
#[instrument(skip(auth))]
pub async fn resolve_endpoint(
    auth: &dyn AuthProvider,
    url_template: &str,
    region: Option<&str>,
    service_endpoint: Option<&str>,
) -> Result<String, AuthError> {
    // Priority 1: explicit service_endpoint override
    if let Some(endpoint) = service_endpoint {
        // Still warn about cross-region even with explicit endpoint
        if let Ok(auth_region) = auth.get_region().await {
            warn_cross_region(auth, &auth_region, endpoint);
        }
        return Ok(endpoint.to_string());
    }

    // Priority 2: explicit region override, or fall back to auth.get_region()
    let resolved_region = match region {
        Some(r) => normalize_region(r).to_string(),
        None => auth.get_region().await?,
    };

    let endpoint = url_template.replace("{region}", &resolved_region);

    // Warn if explicit region override differs from auth region
    if region.is_some() {
        if let Ok(auth_region) = auth.get_region().await {
            warn_cross_region(auth, &auth_region, &endpoint);
        }
    }

    Ok(endpoint)
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
    issued_at: SystemTime,
    expires_at: SystemTime,
}

impl std::fmt::Debug for InstanceCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstanceCredentials")
            .field("security_token", &"[REDACTED]")
            .field("private_key", &"[REDACTED]")
            .field("issued_at", &self.issued_at)
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
    refresh_lock: Arc<Mutex<()>>, // prevents thundering herd on IMDS
}

impl InstancePrincipalAuth {
    /// Maximum number of IMDS request attempts (initial + retries)
    const IMDS_MAX_ATTEMPTS: u32 = 8;
    /// Maximum sleep between retries (30 seconds)
    const IMDS_BACKOFF_CAP_SECS: u64 = 30;

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
            refresh_lock: Arc::new(Mutex::new(())),
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

    /// Returns true for status codes that warrant a retry: 404, 429, and any 5xx.
    fn is_retryable_imds_status(status: reqwest::StatusCode) -> bool {
        status == reqwest::StatusCode::NOT_FOUND
            || status == reqwest::StatusCode::TOO_MANY_REQUESTS
            || status.is_server_error()
    }

    /// Exponential backoff with simple time-based jitter, capped at `IMDS_BACKOFF_CAP_SECS`.
    ///
    /// `attempt` is 0-indexed (0 = first retry, after the initial attempt failed).
    fn compute_imds_backoff(attempt: u32) -> Duration {
        // base = 2^attempt seconds, capped (checked_shl returns None on overflow)
        let base_secs: u64 = 1u64
            .checked_shl(attempt)
            .unwrap_or(u64::MAX)
            .min(Self::IMDS_BACKOFF_CAP_SECS);
        // Jitter: use nanos of current time modulo base_secs (avoids new deps)
        let jitter_secs = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64 % base_secs.max(1))
            .unwrap_or(0);
        Duration::from_secs(
            base_secs
                .saturating_add(jitter_secs)
                .min(Self::IMDS_BACKOFF_CAP_SECS),
        )
    }

    /// GET `{metadata_base_url}/{path}` with `Authorization: Bearer Oracle`, retrying on
    /// transient errors (transport failures, 404, 429, 5xx) up to `IMDS_MAX_ATTEMPTS` total.
    ///
    /// Non-retryable 4xx responses (anything except 404/429) fail immediately.
    async fn imds_get_with_retry(
        &self,
        path: &str,
        what: &str,
    ) -> Result<reqwest::Response, AuthError> {
        let url = format!("{}/{}", self.metadata_base_url, path);
        let client = self.get_http_client().await;
        let mut last_err: Option<AuthError> = None;

        for attempt in 0..Self::IMDS_MAX_ATTEMPTS {
            if attempt > 0 {
                let backoff = Self::compute_imds_backoff(attempt - 1);
                warn!(
                    what = %what,
                    attempt = attempt,
                    backoff_secs = backoff.as_secs(),
                    "IMDS request failed, retrying"
                );
                tokio::time::sleep(backoff).await;
            }

            let send_result = client
                .get(&url)
                .header("Authorization", "Bearer Oracle")
                .send()
                .await;

            match send_result {
                Err(e) => {
                    warn!(
                        what = %what,
                        attempt = attempt + 1,
                        max_attempts = Self::IMDS_MAX_ATTEMPTS,
                        error = %e,
                        "IMDS transport error"
                    );
                    last_err = Some(AuthError::HttpError(e));
                }
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        return Ok(resp);
                    }
                    if Self::is_retryable_imds_status(status) {
                        warn!(
                            what = %what,
                            attempt = attempt + 1,
                            max_attempts = Self::IMDS_MAX_ATTEMPTS,
                            status = %status,
                            "IMDS retryable status"
                        );
                        last_err = Some(AuthError::MetadataError(format!(
                            "IMDS {what} returned {status} (attempt {}/{})",
                            attempt + 1,
                            Self::IMDS_MAX_ATTEMPTS
                        )));
                    } else {
                        // Non-retryable 4xx — fail fast
                        return Err(AuthError::MetadataError(format!(
                            "IMDS {what} returned non-retryable status {status}"
                        )));
                    }
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            AuthError::MetadataError(format!(
                "IMDS {what} failed after {} attempts",
                Self::IMDS_MAX_ATTEMPTS
            ))
        }))
    }

    /// Fetch region from IMDS
    async fn fetch_region(&self) -> Result<String, AuthError> {
        // Fast path: check cache
        {
            let guard = self.region.read().await;
            if let Some(ref region) = *guard {
                return Ok(region.clone());
            }
        }

        // Serialize IMDS calls
        let _lock = self.refresh_lock.lock().await;

        // Double-check after acquiring lock
        {
            let guard = self.region.read().await;
            if let Some(ref region) = *guard {
                return Ok(region.clone());
            }
        }

        let response = self
            .imds_get_with_retry("instance/region", "region")
            .await?;
        let region = response.text().await?;
        let region = normalize_region(region.trim());

        *self.region.write().await = Some(region.clone());
        Ok(region)
    }

    /// Fetch the leaf certificate and private key from IMDS
    async fn fetch_certificate_and_key(&self) -> Result<(String, String, String), AuthError> {
        // Required: leaf certificate
        let cert = self
            .imds_get_with_retry("identity/cert.pem", "certificate")
            .await?
            .text()
            .await?;

        // Required: private key
        let private_key = self
            .imds_get_with_retry("identity/key.pem", "private key")
            .await?
            .text()
            .await?;

        // Optional: intermediate certificate — log and continue on failure
        let intermediate_cert = match self
            .imds_get_with_retry("identity/intermediate.pem", "intermediate certificate")
            .await
        {
            Ok(resp) => resp.text().await?,
            Err(e) => {
                warn!(error = %e, "Failed to fetch intermediate certificate after retries; continuing without it");
                String::new()
            }
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
        let session_public_pem = keypair_to_public_pem(&session_key_pair)?;

        // Sanitize PEM strings for base64 encoding
        let cert_sanitized = sanitize_pem(cert);
        let session_public_sanitized = sanitize_pem(&session_public_pem);

        // Create the X509 federation request body
        let body = serde_json::json!({
            "certificate": cert_sanitized,
            "publicKey": session_public_sanitized, // Send SESSION key's public key
            "intermediateCertificates": if intermediate_cert.is_empty() {
                Vec::<String>::new()
            } else {
                vec![sanitize_pem(intermediate_cert)]
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

        // Parse JWT to get issued_at and expiry times
        let (issued_at, expires_at) = parse_jwt_times(&security_token).unwrap_or_else(|_| {
            warn!("Could not parse JWT iat/exp claims from security token, assuming 1 hour TTL");
            let now = SystemTime::now();
            (now, now + Duration::from_secs(3600))
        });

        if let Ok(duration) = expires_at.duration_since(SystemTime::now()) {
            debug!(
                expires_in_secs = duration.as_secs(),
                "Refreshed instance principal credentials"
            );
        } else {
            warn!("Instance principal security token already expired at refresh time");
        }

        *self.credentials.write().await = Some(InstanceCredentials {
            security_token,
            session_key_pair,
            issued_at,
            expires_at,
        });

        Ok(())
    }

    /// Get valid credentials, refreshing at half-life
    async fn get_credentials(&self) -> Result<(), AuthError> {
        // Fast path: check if credentials are still valid
        {
            let guard = self.credentials.read().await;
            if let Some(ref creds) = *guard {
                let total_lifetime = creds
                    .expires_at
                    .duration_since(creds.issued_at)
                    .unwrap_or(Duration::from_secs(3600));
                let half_life = total_lifetime / 2;
                let time_until_expiry = creds
                    .expires_at
                    .duration_since(SystemTime::now())
                    .unwrap_or(Duration::ZERO);
                if time_until_expiry > half_life {
                    return Ok(()); // cache hit — still in first half of lifetime
                }
            }
        }

        // Serialize refreshes — only one task hits IMDS
        let _lock = self.refresh_lock.lock().await;

        // Double-check: another task may have refreshed while we waited
        {
            let guard = self.credentials.read().await;
            if let Some(ref creds) = *guard {
                let total_lifetime = creds
                    .expires_at
                    .duration_since(creds.issued_at)
                    .unwrap_or(Duration::from_secs(3600));
                let half_life = total_lifetime / 2;
                let time_until_expiry = creds
                    .expires_at
                    .duration_since(SystemTime::now())
                    .unwrap_or(Duration::ZERO);
                if time_until_expiry > half_life {
                    return Ok(()); // cache hit — still in first half of lifetime
                }
            }
        }

        self.refresh_credentials().await
    }

    /// Fetch tenancy ID from instance metadata
    async fn fetch_tenancy_id(&self) -> Result<String, AuthError> {
        // Fast path: check cache
        {
            let guard = self.tenancy_id.read().await;
            if let Some(ref id) = *guard {
                return Ok(id.clone());
            }
        }

        // Serialize IMDS calls
        let _lock = self.refresh_lock.lock().await;

        // Double-check after acquiring lock
        {
            let guard = self.tenancy_id.read().await;
            if let Some(ref id) = *guard {
                return Ok(id.clone());
            }
        }

        let response = self
            .imds_get_with_retry("instance/", "instance metadata")
            .await?;
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
        // Token is stored without ST$ prefix, always add it when signing
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

    async fn invalidate_credentials(&self) {
        *self.credentials.write().await = None;
    }

    fn is_region_scoped(&self) -> bool {
        true
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

/// Parse strategy result for debug logging
#[derive(Debug)]
enum ParseStrategy {
    QuotedBase64,
    RawBase64,
    DirectJson,
}

/// Parse proxymux response body, supporting multiple wire formats:
/// 1. Quoted base64: `"<base64>"` → unquote → base64-decode → parse JSON
/// 2. Raw base64: `<base64>` → base64-decode → parse JSON
/// 3. Direct JSON: `{"token": "..."}` → parse JSON directly
///
/// Returns (ProxymuxResponse, ParseStrategy) on success.
fn parse_proxymux_response(body: &str) -> Result<(ProxymuxResponse, ParseStrategy), AuthError> {
    let trimmed = body.trim();

    // Strategy 1: Quoted base64
    if trimmed.starts_with('"') && trimmed.ends_with('"') {
        let unquoted = &trimmed[1..trimmed.len() - 1];
        if let Ok(decoded) = BASE64.decode(unquoted.as_bytes()) {
            if let Ok(response) = serde_json::from_slice::<ProxymuxResponse>(&decoded) {
                return Ok((response, ParseStrategy::QuotedBase64));
            }
        }
    }

    // Strategy 2: Raw base64
    if !trimmed.starts_with('{') {
        if let Ok(decoded) = BASE64.decode(trimmed.as_bytes()) {
            if let Ok(response) = serde_json::from_slice::<ProxymuxResponse>(&decoded) {
                return Ok((response, ParseStrategy::RawBase64));
            }
        }
    }

    // Strategy 3: Direct JSON
    if trimmed.starts_with('{') {
        if let Ok(response) = serde_json::from_str::<ProxymuxResponse>(trimmed) {
            return Ok((response, ParseStrategy::DirectJson));
        }
    }

    Err(AuthError::InvalidKeyFormat(
        "Failed to parse proxymux response: tried quoted_base64, raw_base64, and direct_json strategies".to_string()
    ))
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
    const PROXYMUX_MAX_RETRIES: u32 = 5;
    const PROXYMUX_INITIAL_BACKOFF_MS: u64 = 250;
    const PROXYMUX_MAX_BACKOFF_MS: u64 = 5000;

    /// Create from environment variables
    pub fn new() -> Result<Self, AuthError> {
        Self::builder().build()
    }

    /// Builder for explicit configuration
    pub fn builder() -> OkeWorkloadIdentityAuthBuilder {
        OkeWorkloadIdentityAuthBuilder::default()
    }

    /// Generate RSA 2048 session keypair
    fn generate_session_keypair() -> Result<RsaKeyPair, AuthError> {
        RsaKeyPair::generate(KeySize::Rsa2048).map_err(|e| {
            AuthError::InvalidKeyFormat(format!("Failed to generate keypair: {:?}", e))
        })
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

        // Read and validate SA token BEFORE making the request
        let sa_token = self.read_sa_token()?;
        validate_sa_token(&sa_token)?;

        // Generate session keypair and prepare request body
        let session_key_pair = Self::generate_session_keypair()?;
        let public_key_pem = keypair_to_public_pem(&session_key_pair)?;
        let sanitized_key = sanitize_pem(&public_key_pem);

        let url = format!(
            "https://{}:{}{}",
            self.service_host,
            self.service_port,
            Self::PROXYMUX_PATH
        );

        let body = serde_json::json!({
            "podKey": sanitized_key
        });

        // Generate opc-request-id for tracing
        let opc_request_id = generate_opc_request_id();
        tracing::debug!(opc_request_id = %opc_request_id, "Requesting session token from proxymux");

        // Retry loop for proxymux requests
        let mut last_error = None;
        for attempt in 0..=Self::PROXYMUX_MAX_RETRIES {
            if attempt > 0 {
                let backoff = std::cmp::min(
                    Self::PROXYMUX_INITIAL_BACKOFF_MS * 2u64.pow(attempt - 1),
                    Self::PROXYMUX_MAX_BACKOFF_MS,
                );
                tracing::warn!(attempt, backoff_ms = backoff, error = ?last_error, "Retrying proxymux token request");
                tokio::time::sleep(Duration::from_millis(backoff)).await;
            }

            let result = self
                .http_client
                .post(&url)
                .header("Authorization", format!("Bearer {}", sa_token))
                .header("Content-Type", "application/json")
                .header("opc-request-id", &opc_request_id)
                .json(&body)
                .send()
                .await;

            match result {
                Err(e) => {
                    last_error = Some(AuthError::MetadataError(format!(
                        "Proxymux request failed: {}",
                        e
                    )));
                    continue; // connection/timeout error, retry
                }
                Ok(response) => {
                    let status = response.status();
                    if status.is_success() {
                        let response_text = response.text().await?;
                        let trimmed = response_text.trim();

                        // Log response shape without leaking token
                        let starts_with = if trimmed.starts_with('"') {
                            "quote"
                        } else if trimmed.starts_with('{') {
                            "brace"
                        } else {
                            "other"
                        };

                        debug!(
                            response_len = response_text.len(),
                            starts_with = %starts_with,
                            "Received proxymux response"
                        );

                        // Parse using multi-strategy parser
                        let (proxymux_response, strategy) =
                            parse_proxymux_response(&response_text)?;

                        debug!(
                            strategy = ?strategy,
                            "Successfully parsed proxymux response"
                        );

                        // Strip ST$ prefix if present, store without it
                        let raw_token = proxymux_response.token;
                        let token = if let Some(stripped) = raw_token.strip_prefix("ST$") {
                            stripped.to_string()
                        } else {
                            raw_token
                        };

                        // Parse JWT to get issued_at and expiry times
                        let (issued_at, expires_at) = parse_jwt_times(&token)?;

                        if let Ok(duration) = expires_at.duration_since(SystemTime::now()) {
                            info!(
                                expires_in_secs = duration.as_secs(),
                                "Successfully fetched session token"
                            );
                        } else {
                            warn!("Token already expired");
                        }

                        return Ok(InstanceCredentials {
                            security_token: token,
                            session_key_pair,
                            issued_at,
                            expires_at,
                        });
                    } else if status.as_u16() == 403 {
                        return Err(AuthError::MetadataError("Proxymux returned 403. Please ensure the cluster type is enhanced (OKE).".into()));
                    } else if status.is_client_error() {
                        let body = response.text().await.unwrap_or_default();
                        return Err(AuthError::MetadataError(format!(
                            "Proxymux request failed: {} - {}",
                            status, body
                        )));
                    } else {
                        // 5xx, retry
                        let body = response.text().await.unwrap_or_default();
                        last_error = Some(AuthError::MetadataError(format!(
                            "Proxymux request failed: {} - {}",
                            status, body
                        )));
                        continue;
                    }
                }
            }
        }
        // If we get here, all retries exhausted
        Err(last_error.unwrap_or_else(|| {
            AuthError::MetadataError("Proxymux request failed after all retries".into())
        }))
    }

    /// Get valid credentials, refreshing at half-life
    #[instrument(skip(self))]
    async fn get_credentials(&self) -> Result<(), AuthError> {
        {
            let guard = self.credentials.read().await;
            if let Some(ref creds) = *guard {
                let total_lifetime = creds
                    .expires_at
                    .duration_since(creds.issued_at)
                    .unwrap_or(Duration::from_secs(3600));
                let half_life = total_lifetime / 2;
                let time_until_expiry = creds
                    .expires_at
                    .duration_since(SystemTime::now())
                    .unwrap_or(Duration::ZERO);
                if time_until_expiry > half_life {
                    debug!(
                        time_until_expiry_secs = time_until_expiry.as_secs(),
                        half_life_secs = half_life.as_secs(),
                        "Credentials cache hit - token still in first half of lifetime"
                    );
                    return Ok(()); // cache hit — still in first half of lifetime
                } else {
                    debug!(
                        time_until_expiry_secs = time_until_expiry.as_secs(),
                        half_life_secs = half_life.as_secs(),
                        "Credentials need refresh - past half-life"
                    );
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

        // Key ID is ST${token}
        // Token is stored without ST$ prefix, always add it when signing
        let key_id = format!("ST${}", creds.security_token);

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

    async fn invalidate_credentials(&self) {
        *self.credentials.write().await = None;
    }

    fn is_region_scoped(&self) -> bool {
        true
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
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
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

    // =========================================================================
    // extract_region_from_endpoint tests
    // =========================================================================

    #[test]
    fn test_extract_region_objectstorage_returns_us_ashburn_1() {
        let result =
            extract_region_from_endpoint("https://objectstorage.us-ashburn-1.oraclecloud.com");
        assert_eq!(result, Some("us-ashburn-1".to_string()));
    }

    #[test]
    fn test_extract_region_identity_oci_subdomain_returns_us_ashburn_1() {
        let result =
            extract_region_from_endpoint("https://identity.us-ashburn-1.oci.oraclecloud.com");
        assert_eq!(result, Some("us-ashburn-1".to_string()));
    }

    #[test]
    fn test_extract_region_queue_cell_prefix_returns_us_phoenix_1() {
        let result = extract_region_from_endpoint(
            "https://cell-1.queue.messaging.us-phoenix-1.oci.oraclecloud.com",
        );
        assert_eq!(result, Some("us-phoenix-1".to_string()));
    }

    #[test]
    fn test_extract_region_secrets_vaults_returns_eu_frankfurt_1() {
        let result = extract_region_from_endpoint(
            "https://secrets.vaults.eu-frankfurt-1.oci.oraclecloud.com",
        );
        assert_eq!(result, Some("eu-frankfurt-1".to_string()));
    }

    #[test]
    fn test_extract_region_nosql_returns_ap_tokyo_1() {
        let result = extract_region_from_endpoint("https://nosql.ap-tokyo-1.oci.oraclecloud.com");
        assert_eq!(result, Some("ap-tokyo-1".to_string()));
    }

    #[test]
    fn test_extract_region_short_code_iad_normalizes_to_us_ashburn_1() {
        // Short region code "iad" should be normalized to "us-ashburn-1"
        let result = extract_region_from_endpoint("https://objectstorage.iad.oraclecloud.com");
        assert_eq!(result, Some("us-ashburn-1".to_string()));
    }

    #[test]
    fn test_extract_region_short_code_phx_normalizes_to_us_phoenix_1() {
        let result = extract_region_from_endpoint("https://objectstorage.phx.oraclecloud.com");
        assert_eq!(result, Some("us-phoenix-1".to_string()));
    }

    #[test]
    fn test_extract_region_localhost_returns_none() {
        let result = extract_region_from_endpoint("https://localhost:8080");
        assert_eq!(
            result, None,
            "localhost should not match OCI endpoint pattern"
        );
    }

    #[test]
    fn test_extract_region_custom_endpoint_returns_none() {
        let result = extract_region_from_endpoint("https://custom.endpoint.com");
        assert_eq!(result, None, "non-OCI endpoint should return None");
    }

    #[test]
    fn test_extract_region_empty_string_returns_none() {
        let result = extract_region_from_endpoint("");
        assert_eq!(
            result, None,
            "empty string should not panic and should return None"
        );
    }

    #[test]
    fn test_extract_region_garbage_input_returns_none() {
        let result = extract_region_from_endpoint("not-a-url-at-all!!!");
        assert_eq!(
            result, None,
            "garbage input should not panic and should return None"
        );
    }

    #[test]
    fn test_extract_region_plain_oraclecloud_no_region_returns_none() {
        // "oraclecloud.com" with no region segment before it
        let result = extract_region_from_endpoint("https://oraclecloud.com");
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_region_various_services() {
        let cases = [
            (
                "https://dataflow.us-ashburn-1.oci.oraclecloud.com",
                Some("us-ashburn-1"),
            ),
            (
                "https://streaming.ap-tokyo-1.oci.oraclecloud.com",
                Some("ap-tokyo-1"),
            ),
            (
                "https://objectstorage.eu-frankfurt-1.oraclecloud.com",
                Some("eu-frankfurt-1"),
            ),
            (
                "https://auth.us-phoenix-1.oraclecloud.com",
                Some("us-phoenix-1"),
            ),
        ];
        for (endpoint, expected) in cases {
            let result = extract_region_from_endpoint(endpoint);
            assert_eq!(
                result.as_deref(),
                expected,
                "Failed for endpoint: {endpoint}"
            );
        }
    }

    // =========================================================================
    // is_region_scoped tests
    // =========================================================================

    /// Minimal test AuthProvider that uses the default trait implementation.
    struct DefaultScopedAuth;

    #[async_trait::async_trait]
    impl AuthProvider for DefaultScopedAuth {
        async fn sign_request(
            &self,
            _headers: &mut reqwest::header::HeaderMap,
            _method: &str,
            _path: &str,
            _host: &str,
        ) -> Result<(), AuthError> {
            Ok(())
        }

        async fn get_tenancy_id(&self) -> Result<String, AuthError> {
            Ok("ocid1.tenancy.oc1..test".to_string())
        }

        async fn get_region(&self) -> Result<String, AuthError> {
            Ok("us-ashburn-1".to_string())
        }
    }

    /// Test AuthProvider that overrides is_region_scoped to return true.
    struct RegionScopedAuth;

    #[async_trait::async_trait]
    impl AuthProvider for RegionScopedAuth {
        async fn sign_request(
            &self,
            _headers: &mut reqwest::header::HeaderMap,
            _method: &str,
            _path: &str,
            _host: &str,
        ) -> Result<(), AuthError> {
            Ok(())
        }

        async fn get_tenancy_id(&self) -> Result<String, AuthError> {
            Ok("ocid1.tenancy.oc1..test".to_string())
        }

        async fn get_region(&self) -> Result<String, AuthError> {
            Ok("us-ashburn-1".to_string())
        }

        fn is_region_scoped(&self) -> bool {
            true
        }
    }

    #[test]
    fn test_is_region_scoped_default_returns_false() {
        let auth = DefaultScopedAuth;
        assert!(
            !auth.is_region_scoped(),
            "Default trait implementation should return false"
        );
    }

    #[test]
    fn test_is_region_scoped_override_returns_true() {
        let auth = RegionScopedAuth;
        assert!(
            auth.is_region_scoped(),
            "Overridden is_region_scoped should return true"
        );
    }

    #[test]
    fn test_is_region_scoped_instance_principal_returns_true() {
        let auth = InstancePrincipalAuth::new(Some("us-ashburn-1".to_string()));
        assert!(
            auth.is_region_scoped(),
            "InstancePrincipalAuth must be region-scoped"
        );
    }

    #[test]
    fn test_is_region_scoped_config_file_auth_returns_false() {
        // ConfigFileAuth uses the default (false) — API key auth is not region-scoped
        let auth = DefaultScopedAuth; // same semantics as ConfigFileAuth
        assert!(!auth.is_region_scoped());
    }

    // =========================================================================
    // warn_cross_region tests
    // =========================================================================

    #[test]
    fn test_warn_cross_region_non_scoped_auth_does_not_panic() {
        // Non-region-scoped auth: function should return early without panicking
        let auth = DefaultScopedAuth;
        warn_cross_region(
            &auth,
            "us-ashburn-1",
            "https://objectstorage.eu-frankfurt-1.oraclecloud.com",
        );
    }

    #[test]
    fn test_warn_cross_region_same_region_does_not_panic() {
        // Region-scoped auth, same region: no warning, no panic
        let auth = RegionScopedAuth;
        warn_cross_region(
            &auth,
            "us-ashburn-1",
            "https://objectstorage.us-ashburn-1.oraclecloud.com",
        );
    }

    #[test]
    fn test_warn_cross_region_different_region_does_not_panic() {
        // Region-scoped auth, different region: should emit warning but not panic
        let auth = RegionScopedAuth;
        warn_cross_region(
            &auth,
            "us-ashburn-1",
            "https://objectstorage.eu-frankfurt-1.oraclecloud.com",
        );
    }

    #[test]
    fn test_warn_cross_region_non_oci_endpoint_does_not_panic() {
        // Region-scoped auth, non-OCI endpoint (extract_region returns None): no warning, no panic
        let auth = RegionScopedAuth;
        warn_cross_region(&auth, "us-ashburn-1", "https://localhost:8080");
    }

    #[test]
    fn test_warn_cross_region_empty_strings_does_not_panic() {
        let auth = RegionScopedAuth;
        warn_cross_region(&auth, "", "");
    }

    #[test]
    fn test_warn_cross_region_garbage_endpoint_does_not_panic() {
        let auth = RegionScopedAuth;
        warn_cross_region(&auth, "us-ashburn-1", "not-a-url!!!");
    }

    #[test]
    fn test_warn_cross_region_short_code_auth_region_normalized() {
        // auth_region "iad" should normalize to "us-ashburn-1" and match the endpoint
        let auth = RegionScopedAuth;
        // Same region via short code — should NOT warn (no panic either way)
        warn_cross_region(
            &auth,
            "iad",
            "https://objectstorage.us-ashburn-1.oraclecloud.com",
        );
    }

    #[test]
    fn test_warn_cross_region_short_code_cross_region_does_not_panic() {
        // auth_region "iad" (us-ashburn-1) vs endpoint in us-phoenix-1 — cross-region warning
        let auth = RegionScopedAuth;
        warn_cross_region(
            &auth,
            "iad",
            "https://objectstorage.us-phoenix-1.oraclecloud.com",
        );
    }

    // =========================================================================
    // resolve_endpoint tests
    // =========================================================================

    #[tokio::test]
    async fn test_resolve_endpoint_explicit_service_endpoint_takes_precedence() {
        let auth = DefaultScopedAuth;
        let result = resolve_endpoint(
            &auth,
            "https://objectstorage.{region}.oraclecloud.com",
            Some("us-phoenix-1"),
            Some("https://custom.endpoint.com"),
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://custom.endpoint.com");
    }

    #[tokio::test]
    async fn test_resolve_endpoint_explicit_region_overrides_auth() {
        let auth = DefaultScopedAuth;
        let result = resolve_endpoint(
            &auth,
            "https://objectstorage.{region}.oraclecloud.com",
            Some("eu-frankfurt-1"),
            None,
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "https://objectstorage.eu-frankfurt-1.oraclecloud.com"
        );
    }

    #[tokio::test]
    async fn test_resolve_endpoint_falls_back_to_auth_region() {
        let auth = DefaultScopedAuth;
        let result = resolve_endpoint(
            &auth,
            "https://objectstorage.{region}.oraclecloud.com",
            None,
            None,
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "https://objectstorage.us-ashburn-1.oraclecloud.com"
        );
    }

    #[tokio::test]
    async fn test_resolve_endpoint_normalizes_short_region_code() {
        let auth = DefaultScopedAuth;
        let result = resolve_endpoint(
            &auth,
            "https://objectstorage.{region}.oraclecloud.com",
            Some("iad"),
            None,
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "https://objectstorage.us-ashburn-1.oraclecloud.com"
        );
    }

    #[tokio::test]
    async fn test_resolve_endpoint_with_different_url_template() {
        let auth = DefaultScopedAuth;
        let result = resolve_endpoint(
            &auth,
            "https://identity.{region}.oci.oraclecloud.com",
            Some("ap-tokyo-1"),
            None,
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "https://identity.ap-tokyo-1.oci.oraclecloud.com"
        );
    }

    #[tokio::test]
    async fn test_resolve_endpoint_service_endpoint_none_region_none_uses_auth() {
        let auth = DefaultScopedAuth;
        let result = resolve_endpoint(
            &auth,
            "https://queue.messaging.{region}.oci.oraclecloud.com",
            None,
            None,
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "https://queue.messaging.us-ashburn-1.oci.oraclecloud.com"
        );
    }

    // =========================================================================
    // parse_proxymux_response tests
    // =========================================================================

    #[test]
    fn test_parse_proxymux_response_quoted_base64() {
        // Simulate Go SDK behavior: quoted base64 string
        let json_payload = r#"{"token":"ST$test.token.here"}"#;
        let base64_encoded = BASE64.encode(json_payload.as_bytes());
        let quoted = format!("\"{}\"", base64_encoded);

        let result = parse_proxymux_response(&quoted);
        assert!(result.is_ok(), "Should parse quoted base64");
        let (response, strategy) = result.unwrap();
        assert_eq!(response.token, "ST$test.token.here");
        assert!(matches!(strategy, ParseStrategy::QuotedBase64));
    }

    #[test]
    fn test_parse_proxymux_response_raw_base64() {
        // Raw base64 without quotes
        let json_payload = r#"{"token":"ST$test.token.here"}"#;
        let base64_encoded = BASE64.encode(json_payload.as_bytes());

        let result = parse_proxymux_response(&base64_encoded);
        assert!(result.is_ok(), "Should parse raw base64");
        let (response, strategy) = result.unwrap();
        assert_eq!(response.token, "ST$test.token.here");
        assert!(matches!(strategy, ParseStrategy::RawBase64));
    }

    #[test]
    fn test_parse_proxymux_response_direct_json() {
        // Direct JSON object
        let json_payload = r#"{"token":"ST$test.token.here"}"#;

        let result = parse_proxymux_response(json_payload);
        assert!(result.is_ok(), "Should parse direct JSON");
        let (response, strategy) = result.unwrap();
        assert_eq!(response.token, "ST$test.token.here");
        assert!(matches!(strategy, ParseStrategy::DirectJson));
    }

    #[test]
    fn test_parse_proxymux_response_direct_json_with_whitespace() {
        // Direct JSON with leading/trailing whitespace
        let json_payload = r#"  {"token":"ST$test.token.here"}  "#;

        let result = parse_proxymux_response(json_payload);
        assert!(result.is_ok(), "Should parse direct JSON with whitespace");
        let (response, strategy) = result.unwrap();
        assert_eq!(response.token, "ST$test.token.here");
        assert!(matches!(strategy, ParseStrategy::DirectJson));
    }

    #[test]
    fn test_parse_proxymux_response_malformed_quoted() {
        // Quoted but not valid base64
        let malformed = r#""not-valid-base64!!!""#;

        let result = parse_proxymux_response(malformed);
        assert!(result.is_err(), "Should fail on malformed quoted string");
        let err = result.unwrap_err();
        assert!(matches!(err, AuthError::InvalidKeyFormat(_)));
    }

    #[test]
    fn test_parse_proxymux_response_malformed_base64() {
        // Invalid base64
        let malformed = "not-valid-base64!!!";

        let result = parse_proxymux_response(malformed);
        assert!(result.is_err(), "Should fail on malformed base64");
        let err = result.unwrap_err();
        assert!(matches!(err, AuthError::InvalidKeyFormat(_)));
    }

    #[test]
    fn test_parse_proxymux_response_malformed_json() {
        // Invalid JSON
        let malformed = r#"{"token":"missing closing brace"#;

        let result = parse_proxymux_response(malformed);
        assert!(result.is_err(), "Should fail on malformed JSON");
        let err = result.unwrap_err();
        assert!(matches!(err, AuthError::InvalidKeyFormat(_)));
    }

    #[test]
    fn test_parse_proxymux_response_empty_string() {
        let result = parse_proxymux_response("");
        assert!(result.is_err(), "Should fail on empty string");
    }

    #[test]
    fn test_parse_proxymux_response_missing_token_field() {
        // Valid JSON but missing "token" field
        let json_payload = r#"{"other":"field"}"#;

        let result = parse_proxymux_response(json_payload);
        assert!(result.is_err(), "Should fail when token field is missing");
    }
}
