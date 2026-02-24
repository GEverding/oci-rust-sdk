use clap::{Parser, Subcommand, ValueEnum};
use futures_util::StreamExt;
use oci_sdk::{
    auth::{AuthProvider, ConfigFileAuth, InstancePrincipalAuth, OkeWorkloadIdentityAuth},
    objectstorage::{
        ListObjectsRequest, ObjectStorageClient, ObjectStorageError, RestoreObjectsDetails,
    },
};
use tokio::io::AsyncWriteExt;

#[derive(Debug, Clone, ValueEnum)]
enum AuthMode {
    /// Use ~/.oci/config file
    Config,
    /// Use instance principal (for OCI VMs)
    InstancePrincipal,
    /// Use OKE workload identity (for Kubernetes)
    WorkloadIdentity,
}

#[derive(Parser)]
#[command(name = "oci-objectstorage")]
#[command(about = "OCI Object Storage CLI for managing objects")]
struct Cli {
    /// OCI config profile name (only used with --auth=config)
    #[arg(short, long, default_value = "DEFAULT")]
    profile: String,

    /// Authentication mode
    #[arg(short, long, value_enum, default_value = "config")]
    auth: AuthMode,

    /// Object Storage namespace
    #[arg(short, long)]
    namespace: String,

    /// Bucket name
    #[arg(short, long)]
    bucket: String,

    /// OCI region override (e.g. us-phoenix-1). If omitted, uses region from auth config.
    #[arg(short, long)]
    region: Option<String>,

    /// Output as JSON (for scripting/parsing)
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List objects in a bucket
    ListObjects {
        /// Filter by prefix
        #[arg(long, global = true)]
        prefix: Option<String>,

        /// Delimiter for hierarchical listing
        #[arg(long, global = true)]
        delimiter: Option<String>,

        /// Maximum number of objects to return
        #[arg(long, global = true)]
        limit: Option<u32>,

        /// Comma-separated fields to include (e.g. name,size,storageTier,archivalState)
        #[arg(long, global = true)]
        fields: Option<String>,

        /// Start listing after this object name
        #[arg(long, global = true)]
        start: Option<String>,
    },

    /// Get object metadata (HEAD request)
    HeadObject {
        /// Object name/path
        #[arg(short, long)]
        name: String,
    },

    /// Restore an archived object
    RestoreObject {
        /// Object name/path
        #[arg(short, long)]
        name: String,

        /// Hours to keep the object restored (1–240, default 24)
        #[arg(long, global = true)]
        hours: Option<u32>,
    },

    /// Download an object to a file (streaming)
    GetObject {
        /// Object name/path
        #[arg(short, long)]
        name: String,

        /// Output file path
        #[arg(short, long)]
        output: String,
    },

    /// Upload a file as an object
    PutObject {
        /// Object name/path
        #[arg(short, long)]
        name: String,

        /// Local file to upload
        #[arg(short, long)]
        file: String,

        /// Content-Type header (default: application/octet-stream)
        #[arg(long, global = true)]
        content_type: Option<String>,
    },
}

async fn run_command<A: AuthProvider>(
    client: ObjectStorageClient<A>,
    bucket: &str,
    json: bool,
    command: Commands,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Commands::ListObjects {
            prefix,
            delimiter,
            limit,
            fields,
            start,
        } => {
            let request = ListObjectsRequest {
                prefix: prefix.as_deref(),
                delimiter: delimiter.as_deref(),
                limit,
                fields: fields
                    .as_deref()
                    .or(Some("name,size,storageTier,archivalState,timeCreated")),
                start: start.as_deref(),
                ..Default::default()
            };
            let resp = client.list_objects(&bucket, &request).await?;

            if json {
                println!("{}", serde_json::to_string_pretty(&resp)?);
            } else {
                println!(
                    "{:<60} {:>12}  {:<20}  {:<10}",
                    "NAME", "SIZE", "STORAGE TIER", "ARCHIVAL STATE"
                );
                println!("{}", "-".repeat(110));

                for obj in &resp.objects {
                    let size = obj
                        .size
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "-".to_string());
                    let tier = obj
                        .storage_tier
                        .as_ref()
                        .map(|t| format!("{:?}", t))
                        .unwrap_or_else(|| "-".to_string());
                    let archival = obj
                        .archival_state
                        .as_ref()
                        .map(|a| format!("{:?}", a))
                        .unwrap_or_else(|| "-".to_string());
                    println!(
                        "{:<60} {:>12}  {:<20}  {:<10}",
                        obj.name, size, tier, archival
                    );
                }

                if !resp.prefixes.is_empty() {
                    println!("\nCommon prefixes:");
                    for p in &resp.prefixes {
                        println!("  {}", p);
                    }
                }

                if let Some(next) = resp.next_start_with {
                    eprintln!(
                        "\nMore results available. Use --start '{}' to continue.",
                        next
                    );
                }
            }
        }

        Commands::HeadObject { name } => {
            let meta = client.head_object(&bucket, &name).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&meta)?);
            } else {
                println!("Storage Tier:   {:?}", meta.storage_tier);
                println!("Archival State: {:?}", meta.archival_state);
                println!(
                    "Content Length: {}",
                    meta.content_length
                        .map(|n| format!("{} bytes", n))
                        .unwrap_or_else(|| "-".to_string())
                );
                println!("ETag:           {}", meta.etag.as_deref().unwrap_or("-"));
                if let Some(req_id) = &meta.opc_request_id {
                    println!("Request ID:     {}", req_id);
                }
            }
        }

        Commands::RestoreObject { name, hours } => {
            let mut details = RestoreObjectsDetails::new(&name);
            if let Some(h) = hours {
                details = details.hours(h);
            }
            let resp = client.restore_objects(&bucket, &details).await?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "status": "accepted",
                        "opcRequestId": resp.opc_request_id,
                    }))?
                );
            } else {
                println!("Restore request accepted.");
                if let Some(req_id) = resp.opc_request_id {
                    println!("Request ID: {}", req_id);
                }
            }
        }

        Commands::GetObject { name, output } => {
            let resp = client.get_object(&bucket, &name).await?;

            if let Some(len) = resp.content_length {
                eprintln!("Content-Length: {} bytes", len);
            }

            let opc_request_id = resp.opc_request_id.clone();
            let content_length = resp.content_length;
            let etag = resp.etag.clone();

            let mut file = tokio::fs::File::create(&output).await?;
            let mut total: u64 = 0;
            let mut stream = resp.stream;

            while let Some(chunk) = stream.next().await {
                let chunk = chunk?;
                file.write_all(&chunk).await?;
                total += chunk.len() as u64;
            }
            file.flush().await?;

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "bytesDownloaded": total,
                        "output": output,
                        "opcRequestId": opc_request_id,
                        "contentLength": content_length,
                        "etag": etag,
                    }))?
                );
            } else {
                println!("Downloaded {} bytes → {}", total, output);
            }
        }

        Commands::PutObject {
            name,
            file,
            content_type,
        } => {
            let data = tokio::fs::read(&file).await?;
            let size = data.len();
            let opc = client
                .put_object(
                    &bucket,
                    &name,
                    bytes::Bytes::from(data),
                    content_type.as_deref(),
                )
                .await?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "bytesUploaded": size,
                        "opcRequestId": opc,
                    }))?
                );
            } else {
                println!("Uploaded {} bytes.", size);
                if let Some(req_id) = opc {
                    println!("Request ID: {}", req_id);
                }
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let result = match cli.auth {
        AuthMode::Config => {
            let auth = ConfigFileAuth::from_file(None, Some(cli.profile))?;
            let client =
                ObjectStorageClient::new(auth, cli.namespace, cli.region.as_deref()).await?;
            run_command(client, &cli.bucket, cli.json, cli.command).await
        }
        AuthMode::InstancePrincipal => {
            let auth = InstancePrincipalAuth::new(None);
            let client =
                ObjectStorageClient::new(auth, cli.namespace, cli.region.as_deref()).await?;
            run_command(client, &cli.bucket, cli.json, cli.command).await
        }
        AuthMode::WorkloadIdentity => {
            let auth = OkeWorkloadIdentityAuth::new()?;
            let client =
                ObjectStorageClient::new(auth, cli.namespace, cli.region.as_deref()).await?;
            run_command(client, &cli.bucket, cli.json, cli.command).await
        }
    };

    if let Err(e) = &result {
        if let Some(ObjectStorageError::RateLimited {
            retry_after_secs,
            opc_request_id,
        }) = e.downcast_ref::<ObjectStorageError>()
        {
            eprintln!("Rate limited by OCI.");
            if let Some(secs) = retry_after_secs {
                eprintln!("Retry after: {}s", secs);
            }
            if let Some(req_id) = opc_request_id {
                eprintln!("Request ID: {}", req_id);
            }
            std::process::exit(1);
        }
    }

    result
}
