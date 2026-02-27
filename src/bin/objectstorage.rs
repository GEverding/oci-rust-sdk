use std::sync::Arc;

use clap::{Parser, Subcommand, ValueEnum};
use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use oci_sdk::{
    auth::{AuthProvider, ConfigFileAuth, InstancePrincipalAuth, OkeWorkloadIdentityAuth},
    objectstorage::{
        BucketListingAction, CreatePreauthenticatedRequestDetails, ListObjectsRequest,
        MultipartUploadConfig, ObjectStorageClient, ObjectStorageError, PreauthAccessType,
        ProgressEvent, RestoreObjectsDetails,
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

#[derive(Debug, Clone, ValueEnum)]
enum CliAccessType {
    ObjectRead,
    ObjectWrite,
    ObjectReadWrite,
    AnyObjectRead,
    AnyObjectWrite,
    AnyObjectReadWrite,
}

impl From<CliAccessType> for PreauthAccessType {
    fn from(ct: CliAccessType) -> Self {
        match ct {
            CliAccessType::ObjectRead => PreauthAccessType::ObjectRead,
            CliAccessType::ObjectWrite => PreauthAccessType::ObjectWrite,
            CliAccessType::ObjectReadWrite => PreauthAccessType::ObjectReadWrite,
            CliAccessType::AnyObjectRead => PreauthAccessType::AnyObjectRead,
            CliAccessType::AnyObjectWrite => PreauthAccessType::AnyObjectWrite,
            CliAccessType::AnyObjectReadWrite => PreauthAccessType::AnyObjectReadWrite,
        }
    }
}

fn progress_bar(total: u64) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})",
            )
            .unwrap()
            .progress_chars("█▉▊▋▌▍▎▏  "),
    );
    pb
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

    /// Download an object to a file (streaming, with progress bar)
    GetObject {
        /// Object name/path
        #[arg(short, long)]
        name: String,

        /// Output file path
        #[arg(short, long)]
        output: String,
    },

    /// Delete an object
    DeleteObject {
        /// Object name/path
        #[arg(short, long)]
        name: String,
    },

    /// Upload a file (auto-selects single or multipart based on size)
    Upload {
        /// Object name/path
        #[arg(short, long)]
        name: String,

        /// Local file to upload
        #[arg(short, long)]
        file: String,

        /// Content-Type header (default: application/octet-stream)
        #[arg(long)]
        content_type: Option<String>,

        /// Part size in MiB for multipart upload (default: 128)
        #[arg(long, default_value = "128")]
        part_size_mib: usize,

        /// Concurrency for multipart upload (default: 8)
        #[arg(long, default_value = "8")]
        concurrency: usize,
    },

    /// Create a pre-authenticated request (PAR)
    CreatePar {
        /// Human-readable name for the PAR
        #[arg(long)]
        name: String,

        /// Access type
        #[arg(long, value_enum)]
        access_type: CliAccessType,

        /// Expiration time (RFC 3339, e.g. 2025-12-31T23:59:59Z)
        #[arg(long)]
        expires: String,

        /// Object name (required for Object* access types)
        #[arg(long)]
        object_name: Option<String>,

        /// Allow listing objects (only for AnyObject* types)
        #[arg(long)]
        allow_listing: bool,
    },

    /// Get details of a pre-authenticated request
    GetPar {
        /// PAR ID
        #[arg(long)]
        par_id: String,
    },

    /// List pre-authenticated requests
    ListPars,

    /// Delete a pre-authenticated request
    DeletePar {
        /// PAR ID
        #[arg(long)]
        par_id: String,
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
            let resp = client.list_objects(bucket, &request).await?;

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
            let meta = client.head_object(bucket, &name).await?;
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
            let resp = client.restore_objects(bucket, &details).await?;
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
            let resp = client.get_object(bucket, &name).await?;

            let pb = progress_bar(resp.content_length.unwrap_or(0));
            if resp.content_length.is_none() {
                pb.set_length(0);
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
                pb.set_position(total);
            }
            file.flush().await?;
            pb.finish_with_message("done");

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

        Commands::DeleteObject { name } => {
            let opc = client.delete_object(bucket, &name).await?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "status": "deleted",
                        "objectName": name,
                        "opcRequestId": opc,
                    }))?
                );
            } else {
                println!("Deleted object: {}", name);
                if let Some(req_id) = opc {
                    println!("Request ID: {}", req_id);
                }
            }
        }

        Commands::Upload {
            name,
            file,
            content_type,
            part_size_mib,
            concurrency,
        } => {
            let metadata = tokio::fs::metadata(&file).await?;
            let file_size = metadata.len();
            let part_size = part_size_mib * 1024 * 1024;

            if file_size <= part_size as u64 {
                // Single put_object
                let data = tokio::fs::read(&file).await?;
                let pb = progress_bar(file_size);
                pb.set_position(file_size); // single shot — data already in memory
                let opc = client
                    .put_object(
                        bucket,
                        &name,
                        bytes::Bytes::from(data),
                        content_type.as_deref(),
                    )
                    .await?;
                pb.finish_with_message("done");
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "bytesUploaded": file_size,
                            "opcRequestId": opc,
                            "multipart": false,
                        }))?
                    );
                } else {
                    println!("Uploaded {} bytes (single request)", file_size);
                    if let Some(req_id) = opc {
                        println!("Request ID: {}", req_id);
                    }
                }
            } else {
                // Multipart upload
                let pb = progress_bar(file_size);
                let pb_clone = pb.clone();
                let config = MultipartUploadConfig {
                    part_size,
                    concurrency,
                    progress: Some(Arc::new(move |event: ProgressEvent| {
                        pb_clone.set_position(event.bytes_transferred);
                    })),
                };

                let f = tokio::fs::File::open(&file).await?;
                let resp = client
                    .upload_file(bucket, &name, f, Some(file_size), Some(config))
                    .await?;
                pb.finish_with_message("done");

                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "bytesUploaded": resp.total_bytes,
                            "partsUploaded": resp.parts_uploaded,
                            "opcRequestId": resp.opc_request_id,
                            "etag": resp.etag,
                            "multipart": true,
                        }))?
                    );
                } else {
                    println!(
                        "Uploaded {} bytes ({} parts)",
                        resp.total_bytes, resp.parts_uploaded
                    );
                    if let Some(req_id) = resp.opc_request_id {
                        println!("Request ID: {}", req_id);
                    }
                }
            }
        }

        Commands::CreatePar {
            name,
            access_type,
            expires,
            object_name,
            allow_listing,
        } => {
            let details = CreatePreauthenticatedRequestDetails {
                name,
                access_type: access_type.into(),
                time_expires: expires,
                object_name,
                bucket_listing_action: if allow_listing {
                    Some(BucketListingAction::ListObjects)
                } else {
                    None
                },
            };
            let par = client
                .create_preauthenticated_request(bucket, &details)
                .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&par)?);
            } else {
                println!("PAR Created:");
                println!("  ID:         {}", par.id);
                println!("  Name:       {}", par.name);
                println!("  Access:     {:?}", par.access_type);
                println!("  Expires:    {}", par.time_expires);
                if let Some(url) = &par.full_url {
                    println!("  URL:        {}", url);
                }
                eprintln!("\n⚠ Save the URL now — it cannot be retrieved later.");
            }
        }

        Commands::GetPar { par_id } => {
            let par = client.get_preauthenticated_request(bucket, &par_id).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&par)?);
            } else {
                println!("ID:        {}", par.id);
                println!("Name:      {}", par.name);
                println!("Access:    {:?}", par.access_type);
                println!("Object:    {}", par.object_name.as_deref().unwrap_or("-"));
                println!("Expires:   {}", par.time_expires);
                println!("Created:   {}", par.time_created.as_deref().unwrap_or("-"));
            }
        }

        Commands::ListPars => {
            let pars = client.list_preauthenticated_requests(bucket).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&pars)?);
            } else {
                println!(
                    "{:<40} {:<30} {:<20} {:<30}",
                    "ID", "NAME", "ACCESS", "EXPIRES"
                );
                println!("{}", "-".repeat(120));
                for par in &pars {
                    println!(
                        "{:<40} {:<30} {:<20} {:<30}",
                        par.id,
                        par.name,
                        format!("{:?}", par.access_type),
                        par.time_expires
                    );
                }
            }
        }

        Commands::DeletePar { par_id } => {
            client
                .delete_preauthenticated_request(bucket, &par_id)
                .await?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "status": "deleted",
                        "parId": par_id,
                    }))?
                );
            } else {
                println!("Deleted PAR: {}", par_id);
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
