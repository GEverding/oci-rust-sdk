use base64::{engine::general_purpose, Engine as _};
use reqwest::header::HeaderMap;
use sha2::{Digest, Sha256};

use crate::auth::{AuthError, AuthProvider};

pub fn encode_body(body: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    let result = hasher.finalize();
    general_purpose::STANDARD.encode(result)
}

pub async fn sign_request(
    auth_provider: &dyn AuthProvider,
    headers: &mut HeaderMap,
    method: &str,
    path: &str,
    host: &str,
) -> Result<(), AuthError> {
    auth_provider
        .sign_request(headers, method, path, host)
        .await
}
