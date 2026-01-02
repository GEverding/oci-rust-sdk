//! Example demonstrating OCI Data Flow client usage
//!
//! This example shows how to:
//! - Create a client with ConfigFileAuth
//! - Trigger a Spark job run
//! - Poll for completion
//! - Fetch run logs
//!
//! # Prerequisites
//! - OCI config file at ~/.oci/config
//! - Valid OCI credentials configured
//! - A Data Flow application already created
//!
//! # Running
//! ```bash
//! export OCI_DATAFLOW_APP_ID="ocid1.dataflowapplication.oc1..example"
//! export OCI_COMPARTMENT_ID="ocid1.compartment.oc1..example"
//! cargo run --example dataflow_example
//! ```

use oci_sdk::auth::ConfigFileAuth;
use oci_sdk::dataflow::{CreateRunDetails, DataFlowClient, RunLifecycleState};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get IDs from environment
    let application_id =
        std::env::var("OCI_DATAFLOW_APP_ID").expect("Set OCI_DATAFLOW_APP_ID environment variable");
    let compartment_id =
        std::env::var("OCI_COMPARTMENT_ID").expect("Set OCI_COMPARTMENT_ID environment variable");

    // Load auth from ~/.oci/config
    let auth = ConfigFileAuth::from_file(None, None)?;
    let region = "us-ashburn-1";

    println!("Creating DataFlow client with ConfigFileAuth...");
    let client = DataFlowClient::new(auth, region);

    // Create a run
    let run_details =
        CreateRunDetails::new(&application_id, &compartment_id).display_name("example-run");

    println!("Creating run...");
    let mut run = client.create_run(run_details).await?;
    println!("Run created: {} ({:?})", run.id, run.lifecycle_state);

    // Poll for completion
    println!("\nPolling for completion...");
    loop {
        run = client.get_run(&run.id).await?;
        println!("Status: {:?}", run.lifecycle_state);

        match run.lifecycle_state {
            RunLifecycleState::Succeeded => {
                println!("Run completed successfully!");
                break;
            }
            RunLifecycleState::Failed => {
                println!("Run failed: {:?}", run.lifecycle_details);
                break;
            }
            RunLifecycleState::Canceled => {
                println!("Run was canceled");
                break;
            }
            _ => {
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        }
    }

    // Fetch logs
    println!("\nFetching logs...");
    let logs = client.list_run_logs(&run.id, None, None).await?;
    println!("Found {} log files", logs.len());

    for log in logs {
        println!(
            "Log: {} ({} bytes, type: {})",
            log.name, log.size_in_bytes, log.log_type
        );

        // Download and print log content
        match client.get_run_log_text(&run.id, &log.name).await {
            Ok(content) => {
                println!("--- {} ---", log.name);
                println!("{}", content);
            }
            Err(e) => {
                eprintln!("Failed to fetch log {}: {}", log.name, e);
            }
        }
    }

    Ok(())
}
