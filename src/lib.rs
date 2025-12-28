//! Oracle Cloud Infrastructure SDK for Rust
//!
//! This crate provides a Rust SDK for interacting with Oracle Cloud Infrastructure (OCI) services.
//!
//! # Authentication
//!
//! The SDK supports multiple authentication mechanisms:
//!
//! - **API Key Authentication**: Use a private key from your `~/.oci/config` file
//! - **Instance Principal**: Authenticate as an OCI compute instance
//! - **OKE Workload Identity**: Authenticate workloads running in Oracle Kubernetes Engine
//!
//! # Example
//!
//! ```no_run
//! use oci_sdk::auth::{ConfigFileAuth, AuthProvider};
//! use oci_sdk::identity::Identity;
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Load authentication from config file
//!     let auth = Arc::new(ConfigFileAuth::from_file(None, None)?);
//!
//!     // Create Identity client
//!     let identity = Identity::new(auth, None).await?;
//!
//!     // Use the client
//!     let user = identity.get_current_user().await?;
//!     println!("Current user: {:?}", user);
//!
//!     Ok(())
//! }
//! ```

pub mod auth;
pub mod config;
pub mod identity;
pub mod nosql;
pub mod queue;
pub mod secrets;

// Re-export commonly used types
pub use auth::{AuthError, AuthProvider, ConfigFileAuth, InstancePrincipalAuth, OkeWorkloadIdentityAuth};
