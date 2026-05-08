//! Example demonstrating environment-variable-based OCI authentication
//!
//! This shows how to authenticate without mounting config files — useful
//! in Docker containers, CI/CD pipelines, and cloud-native environments
//! where injecting secrets as environment variables is standard practice.
//!
//! # Required environment variables
//! ```bash
//! export OCI_CLI_USER="ocid1.user.oc1..example"
//! export OCI_CLI_FINGERPRINT="20:3b:97:13:55:1c:5b:0d:d3:37:d8:50:4e:c5:3a:34"
//! export OCI_CLI_TENANCY="ocid1.tenancy.oc1..example"
//! export OCI_CLI_REGION="us-ashburn-1"
//!
//! # Option A: pass the PEM key content directly (no file needed)
//! export OCI_CLI_KEY_CONTENT="$(cat ~/.oci/oci_api_key.pem)"
//!
//! # Option B: still point at a file (same as before, just via env var)
//! export OCI_CLI_KEY_FILE="~/.oci/oci_api_key.pem"
//! ```
//!
//! # Running
//! ```bash
//! cargo run --example env_config_example
//! ```

use oci_sdk::auth::ConfigFileAuth;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Option 1: read everything from env vars
    let auth = ConfigFileAuth::from_env()?;
    println!("Authenticated as tenancy: {}", auth.tenancy);
    println!("User:   {}", auth.user);
    println!("Region: {}", auth.region);

    // Option 2: pass strings directly (e.g. retrieved from a secrets manager)
    let _auth2 = ConfigFileAuth::from_key_content(
        std::env::var("OCI_CLI_USER")?,
        std::env::var("OCI_CLI_KEY_CONTENT")?,
        std::env::var("OCI_CLI_FINGERPRINT")?,
        std::env::var("OCI_CLI_TENANCY")?,
        std::env::var("OCI_CLI_REGION")?,
        None, // passphrase
    )?;

    println!("Both auth methods succeeded.");
    Ok(())
}
