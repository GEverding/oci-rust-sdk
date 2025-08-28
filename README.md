# OCI Rust SDK

[![Crates.io](https://img.shields.io/crates/v/oci-sdk.svg)](https://crates.io/crates/oci-sdk)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/digital-divas/oci-rust-sdk/blob/master/LICENSE)
[![Rust](https://github.com/digital-divas/oci-rust-sdk/actions/workflows/rust.yml/badge.svg)](https://github.com/digital-divas/oci-rust-sdk/actions/workflows/rust.yml)
[![codecov](https://codecov.io/gh/digital-divas/oci-rust-sdk/branch/master/graph/badge.svg?token=XJJXHENTK4)](https://codecov.io/gh/digital-divas/oci-rust-sdk)

A modern, cloud-native Oracle Cloud Infrastructure (OCI) SDK for Rust with support for Instance Principals, Queue messaging, and more.

## Features

- ✅ **Modern Cryptography**: Uses `aws-lc-rs` instead of OpenSSL for better performance and FIPS compliance
- ✅ **Instance Principal Authentication**: Cloud-native authentication without config files
- ✅ **Automatic Token Refresh**: Background token refresh for long-running services
- ✅ **OCI Queue Support**: Full support for OCI Queue service message publishing
- ✅ **Async/Await**: Fully asynchronous API using Tokio
- ✅ **Builder Pattern**: Easy client configuration with builder pattern
- ✅ **Backward Compatibility**: Maintains compatibility with existing config file authentication

## Quick Start

### Using Instance Principals (Recommended for Cloud Deployments)

```rust
use oci_sdk::auth::{InstancePrincipalAuth, start_token_refresh_task};
use oci_sdk::identity::Identity;
use oci_sdk::queue::{QueueClient, QueueMessage};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create Instance Principal auth provider
    let auth_provider = Arc::new(InstancePrincipalAuth::new(None));
    
    // Start background token refresh for long-running services
    let auth_for_refresh = auth_provider.clone();
    tokio::spawn(async move {
        start_token_refresh_task(auth_for_refresh).await;
    });

    // Create Identity client
    let identity = Identity::new(auth_provider.clone(), None).await?;
    let response = identity.get_current_user().await?;
    let user_info = response.text().await?;
    println!("Current user: {}", user_info);

    // Create Queue client and publish messages
    let queue_client = QueueClient::builder()
        .auth_provider(auth_provider)
        .queue_id("ocid1.queue.oc1.region.example")
        .build()
        .await?;

    let messages = vec![QueueMessage {
        content: "Hello from OCI Rust SDK!".to_string(),
        metadata: Some(serde_json::json!({"source": "rust-sdk"})),
    }];

    let result = queue_client.put_messages(messages).await?;
    println!("Published messages: {:?}", result);

    Ok(())
}
```

### Using Config File Authentication (For Local Development)

```rust
use oci_sdk::auth::ConfigFileAuth;
use oci_sdk::identity::Identity;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load config from ~/.oci/config
    let auth_provider = Arc::new(ConfigFileAuth::from_file(None, None)?);
    
    // Create service client
    let identity = Identity::new(auth_provider, None).await?;
    
    // Get current user information
    let response = identity.get_current_user().await?;
    let body = response.text().await?;
    println!("{}", body);

    Ok(())
}
```

## Migration Guide

### From Version 0.2.x to 0.3.x

The SDK has been significantly modernized with breaking changes for better cloud-native support:

#### Authentication Changes

**Old (Deprecated):**
```rust
use oci_sdk::config::AuthConfig;
use oci_sdk::identity::Identity;

let auth_config = AuthConfig::from_file(None, None);
let identity = Identity::new(auth_config, None);
```

**New:**
```rust
use oci_sdk::auth::ConfigFileAuth;
use oci_sdk::identity::Identity;
use std::sync::Arc;

let auth_provider = Arc::new(ConfigFileAuth::from_file(None, None)?);
let identity = Identity::new(auth_provider, None).await?;
```

#### Key Changes

1. **Authentication**: Use `ConfigFileAuth` or `InstancePrincipalAuth` instead of `AuthConfig`
2. **Async Constructors**: Client constructors are now async (`.await?` required)
3. **Shared Ownership**: Wrap auth providers in `Arc<>` for sharing between clients
4. **Error Handling**: Constructors now return `Result<>` types

### Instance Principal Setup

To use Instance Principals, your OCI compute instance needs:

1. **Dynamic Group**: Create a dynamic group that includes your compute instances
2. **IAM Policy**: Grant necessary permissions to the dynamic group

Example policy:
```
allow dynamic-group my-compute-instances to use queues in compartment my-compartment
allow dynamic-group my-compute-instances to read users in tenancy
```

## Examples

### Complete Examples

- [`comprehensive_example.rs`](./examples/comprehensive_example.rs) - Shows all features including both authentication methods and queue operations
- [`instance_principal_example.rs`](./examples/instance_principal_example.rs) - Focused example for cloud deployments

Run examples:
```bash
# Comprehensive example (works with config file auth)
cargo run --example comprehensive_example

# Instance principal example (requires OCI compute instance)
cargo run --example instance_principal_example
```

You can also look at the [test folder](./tests/) for more examples.

## Development

### OCI-Emulator

We recommend you to use [oci-emulator](https://github.com/cameritelabs/oci-emulator) to develop new features and testing.

To do so, just run:

```bash
docker run -d --name oci-emulator -p 12000:12000 cameritelabs/oci-emulator:latest
```

You can then use the `service_endpoint` parameter available on every client to use it. For example:

```rust
use oci_sdk::auth::ConfigFileAuth;
use oci_sdk::nosql::Nosql;
use std::sync::Arc;

let auth_provider = Arc::new(ConfigFileAuth::from_file(None, None)?);
let nosql = Nosql::new(auth_provider, Some("http://localhost:12000".to_string())).await?;
```

### Running Tests

We're using [tarpaulin](https://github.com/xd009642/tarpaulin) to generate code coverage.
To use it, you'll need to install it using cargo:

```bash
cargo install tarpaulin
```

After installing it, you can build/test and generate the coverage simply using:

```bash
cargo tarpaulin --out Lcov
```

We're using Lcov format to upload the coverage to `codecov`.
You can view the coverage on VSCode using [Coverage Gutters](https://marketplace.visualstudio.com/items?itemName=ryanluker.vscode-coverage-gutters).

If you don't want to generate coverage you can simply use:

```bash
cargo test
```

## Supported Services

### Current Services

- **Identity and Access Management (IAM)**: User management, authentication
- **NoSQL Database**: Table management, querying
- **Queue**: Message publishing, queue management *(New in v0.3.0)*

### Queue Service Example

```rust
use oci_sdk::auth::InstancePrincipalAuth;
use oci_sdk::queue::{QueueClient, QueueMessage};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth_provider = Arc::new(InstancePrincipalAuth::new(None));
    
    let queue_client = QueueClient::builder()
        .auth_provider(auth_provider)
        .queue_id("ocid1.queue.oc1.us-ashburn-1.example")
        .build()
        .await?;

    // Publish messages
    let messages = vec![
        QueueMessage {
            content: "Message 1".to_string(),
            metadata: Some(serde_json::json!({"priority": "high"})),
        },
        QueueMessage {
            content: "Message 2".to_string(),
            metadata: None,
        },
    ];

    let result = queue_client.put_messages(messages).await?;
    println!("Published {} messages", result.entries.len());

    // Get queue statistics
    let stats = queue_client.get_stats().await?;
    println!("Queue stats: {}", stats.text().await?);

    Ok(())
}
```

## What's New in v0.3.0

- 🚀 **Replaced OpenSSL with aws-lc-rs** for better performance and FIPS compliance
- 🔐 **Instance Principal Authentication** for cloud-native deployments
- 🔄 **Automatic Token Refresh** for long-running services
- 📨 **OCI Queue Service Support** with full message publishing capabilities
- 🏗️ **Builder Pattern** for easy client configuration
- ⚡ **Improved Error Handling** with comprehensive error types
- 🔧 **Backward Compatibility** maintained for existing applications

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
