# oci-rust-sdk

[![Crates.io](https://img.shields.io/crates/v/oci-sdk.svg)](https://crates.io/crates/oci-sdk)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/digital-divas/oci-rust-sdk/blob/master/LICENSE)
[![Rust](https://github.com/digital-divas/oci-rust-sdk/actions/workflows/rust.yml/badge.svg)](https://github.com/digital-divas/oci-rust-sdk/actions/workflows/rust.yml)
[![codecov](https://codecov.io/gh/digital-divas/oci-rust-sdk/branch/master/graph/badge.svg?token=XJJXHENTK4)](https://codecov.io/gh/digital-divas/oci-rust-sdk)

## About

Async Rust SDK for Oracle Cloud Infrastructure. Supports API key, Instance Principal, and OKE Workload Identity authentication. Built on `tokio` + `reqwest` with connection pooling tuned for high-throughput workloads.

## Supported Services

| Service | Client | Operations |
|---------|--------|------------|
| Object Storage | `ObjectStorageClient` | `list_objects`, `head_object`, `get_object` (streaming), `put_object`, `restore_objects` |
| DataFlow | `DataFlowClient` | Spark job/run management |
| Identity | `Identity` | User management |
| NoSQL | `Nosql` | Table operations |
| Queue | `Queue` | Message queue operations |
| Secrets | `Secrets` | Secret retrieval |

## Authentication

All clients accept any type implementing `AuthProvider`. Three implementations are included:

### Config File (API Key)

Reads from `~/.oci/config` by default. Supports `DEFAULT` profile or a named profile.

```rust
use oci_sdk::auth::ConfigFileAuth;

// Default: ~/.oci/config, [DEFAULT] profile
let auth = ConfigFileAuth::from_file(None, None)?;

// Custom path and profile
let auth = ConfigFileAuth::from_file(
    Some("/path/to/config".to_string()),
    Some("MY_PROFILE".to_string()),
)?;
```

Config file format:
```ini
[DEFAULT]
user=ocid1.user.oc1...<unique_ID>
fingerprint=20:3b:97:13:55:1c:...
tenancy=ocid1.tenancy.oc1...<unique_ID>
region=us-ashburn-1
key_file=~/.oci/oci_api_key.pem
```

### Instance Principal

For workloads running on OCI Compute instances. Credentials are fetched automatically from the Instance Metadata Service (IMDS) and refreshed before expiry.

```rust
use oci_sdk::auth::InstancePrincipalAuth;
use std::sync::Arc;

// Region auto-detected from IMDS
let auth = Arc::new(InstancePrincipalAuth::new(None));

// Or pin to a specific region
let auth = Arc::new(InstancePrincipalAuth::new(Some("us-ashburn-1".to_string())));
```

### OKE Workload Identity

For workloads running in Oracle Kubernetes Engine. Exchanges the pod's K8s service account token for an OCI resource principal session token via the in-cluster proxymux service.

**Prerequisites:** OKE cluster with Workload Identity enabled, `KUBERNETES_SERVICE_HOST` set, service account token mounted at the standard path.

```rust
use oci_sdk::auth::OkeWorkloadIdentityAuth;

// Auto-configure from environment
let auth = OkeWorkloadIdentityAuth::new()?;

// Or use the builder for explicit config
let auth = OkeWorkloadIdentityAuth::builder()
    .region("us-ashburn-1".to_string())
    .sa_token_path("/var/run/secrets/kubernetes.io/serviceaccount/token".to_string())
    .build()?;
```

## Quick Start — Object Storage

```rust
use oci_sdk::objectstorage::{ObjectStorageClient, ListObjectsRequest, RestoreObjectsDetails};
use oci_sdk::auth::ConfigFileAuth;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth = ConfigFileAuth::from_file(None, None)?;
    let client = ObjectStorageClient::new(auth, "my-namespace", None).await?;

    // List objects with prefix
    let request = ListObjectsRequest {
        prefix: Some("archive/2024/"),
        fields: Some("name,size,storageTier,archivalState"),
        limit: Some(100),
        ..Default::default()
    };
    let resp = client.list_objects("my-bucket", &request).await?;
    for obj in &resp.objects {
        println!("{} ({:?})", obj.name, obj.storage_tier);
    }

    // Pagination
    if let Some(next) = &resp.next_start_with {
        let next_page = ListObjectsRequest {
            prefix: Some("archive/2024/"),
            start: Some(next),
            ..Default::default()
        };
        let _page2 = client.list_objects("my-bucket", &next_page).await?;
    }

    // Restore from archive (1–240 hours)
    let details = RestoreObjectsDetails::new("archive/2024/data.tar.gz")
        .hours(48);
    client.restore_objects("my-bucket", &details).await?;

    // Check restore status
    let meta = client.head_object("my-bucket", "archive/2024/data.tar.gz").await?;
    println!("Archival state: {:?}", meta.archival_state);

    // Streaming download
    use futures_util::StreamExt;
    use tokio::io::AsyncWriteExt;
    let resp = client.get_object("my-bucket", "archive/2024/data.tar.gz").await?;
    let mut file = tokio::fs::File::create("data.tar.gz").await?;
    let mut stream = resp.stream;
    while let Some(chunk) = stream.next().await {
        file.write_all(&chunk?).await?;
    }

    // Upload
    let data = tokio::fs::read("local-file.bin").await?;
    client.put_object("my-bucket", "path/to/object", data.into(), None).await?;

    Ok(())
}
```

## Error Handling

```rust
use oci_sdk::objectstorage::ObjectStorageError;

match client.list_objects("bucket", &request).await {
    Ok(resp) => { /* handle */ }
    Err(ObjectStorageError::RateLimited { retry_after_secs, .. }) => {
        eprintln!("Rate limited, retry after {:?}s", retry_after_secs);
    }
    Err(ObjectStorageError::Api { status, code, message, .. }) => {
        eprintln!("API error {}: {} - {}", status, code, message);
    }
    Err(e) => return Err(e.into()),
}
```

`ObjectStorageError` variants:
- `RateLimited { opc_request_id, retry_after_secs }` — HTTP 429
- `Api { status, code, message, opc_request_id }` — any other non-2xx
- `Auth(AuthError)` — signing or credential failure
- `Http(reqwest::Error)` — transport-level error
- `Serialization(serde_json::Error)` — JSON parse failure

## CLI Tools

Build with the `cli` feature:

```bash
cargo build --release --features cli
```

### Object Storage CLI

```bash
# List objects
oci-objectstorage -n <namespace> -b <bucket> list-objects --prefix some/path/ --limit 100

# JSON output
oci-objectstorage -n <namespace> -b <bucket> list-objects --json

# Head object (metadata + archival state)
oci-objectstorage -n <namespace> -b <bucket> head-object --name path/to/object

# Restore from archive
oci-objectstorage -n <namespace> -b <bucket> restore-object --name path/to/object --hours 48

# Download (streaming)
oci-objectstorage -n <namespace> -b <bucket> get-object --name path/to/object --output ./local-file

# Upload
oci-objectstorage -n <namespace> -b <bucket> put-object --name path/to/object --file ./local-file

# Cross-region
oci-objectstorage -n <namespace> -b <bucket> -r us-phoenix-1 list-objects

# Instance Principal auth
oci-objectstorage -a instance-principal -n <namespace> -b <bucket> list-objects
```

### DataFlow CLI

```bash
# List runs in a compartment
oci-dataflow -r us-ashburn-1 list-runs -c <compartment-id>

# Get run details
oci-dataflow -r us-ashburn-1 get-run <run-id>
```

## High-Throughput Usage

The default client is tuned for high throughput:
- `pool_max_idle_per_host`: 64
- `pool_idle_timeout`: 90s
- `tcp_keepalive`: 60s

For custom tuning, use `with_client`:

```rust
use std::time::Duration;

let http_client = reqwest::Client::builder()
    .pool_max_idle_per_host(128)
    .pool_idle_timeout(Duration::from_secs(120))
    .tcp_keepalive(Duration::from_secs(60))
    .build()?;

let client = ObjectStorageClient::with_client(auth, "namespace", None, http_client).await?;
```

> **Note:** `put_object` requires the full object body in memory to compute the `x-content-sha256` header required by OCI. For objects larger than ~100MB, multipart upload is recommended (not yet implemented).

## Development

### OCI Emulator

Use [oci-emulator](https://github.com/cameritelabs/oci-emulator) for local development and testing:

```bash
docker run -d --name oci-emulator -p 12000:12000 cameritelabs/oci-emulator:latest
```

Pass the emulator URL as the `service_endpoint` (the `region` parameter is ignored when using a custom endpoint — construct the client and override the endpoint directly, or use the emulator-aware constructors if your client supports them).

### Running Tests

```bash
cargo test
```

For coverage with [tarpaulin](https://github.com/xd009642/tarpaulin):

```bash
cargo install tarpaulin
cargo tarpaulin --out Lcov
```

Coverage is uploaded to `codecov`. View locally in VSCode with [Coverage Gutters](https://marketplace.visualstudio.com/items?itemName=ryanluker.vscode-coverage-gutters).

## License

MIT
