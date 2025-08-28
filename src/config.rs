// Legacy config module for backward compatibility
// Users should migrate to the new auth module for new features

use crate::auth::{AuthError, ConfigFileAuth};

#[deprecated(since = "0.3.0", note = "Use crate::auth::ConfigFileAuth instead")]
pub struct AuthConfig {
    pub user: String,
    pub fingerprint: String,
    pub tenancy: String,
    pub region: String,
    // Remove the keypair field to avoid OpenSSL dependency
}

#[allow(deprecated)]
impl AuthConfig {
    pub fn new(
        user: String,
        _key_file: String,
        fingerprint: String,
        tenancy: String,
        region: String,
        _passphrase: String,
    ) -> AuthConfig {
        AuthConfig {
            user,
            fingerprint,
            tenancy,
            region,
        }
    }

    pub fn from_file(file_path: Option<String>, profile_name: Option<String>) -> AuthConfig {
        // For backward compatibility, we'll create a simplified version
        // Users should migrate to ConfigFileAuth for full functionality
        let config_auth = ConfigFileAuth::from_file(file_path, profile_name)
            .expect("Failed to load config file");

        AuthConfig {
            user: config_auth.user,
            fingerprint: config_auth.fingerprint,
            tenancy: config_auth.tenancy,
            region: config_auth.region,
        }
    }

    /// Convert to the new ConfigFileAuth type
    pub fn to_config_file_auth(
        &self,
        key_file: String,
        passphrase: Option<String>,
    ) -> Result<ConfigFileAuth, AuthError> {
        ConfigFileAuth::new(
            self.user.clone(),
            key_file,
            self.fingerprint.clone(),
            self.tenancy.clone(),
            self.region.clone(),
            passphrase,
        )
    }
}
