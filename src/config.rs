//! Configuration module for OCI SDK
//!
//! This module provides backward compatibility with the previous API.
//! For new code, prefer using the `auth` module directly.

pub use crate::auth::ConfigFileAuth;

/// Legacy AuthConfig type - now an alias for ConfigFileAuth
///
/// # Migration
///
/// Old code:
/// ```ignore
/// let config = AuthConfig::from_file(None, None);
/// let identity = Identity::new(config, None);
/// ```
///
/// New code:
/// ```ignore
/// use std::sync::Arc;
/// let auth = Arc::new(ConfigFileAuth::from_file(None, None)?);
/// let identity = Identity::new(auth, None).await?;
/// ```
#[deprecated(
    since = "0.4.0",
    note = "Use ConfigFileAuth from the auth module instead"
)]
pub type AuthConfig = ConfigFileAuth;
