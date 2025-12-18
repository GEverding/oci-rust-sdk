//! Example: Using Instance Principal authentication with OCI Queue
//!
//! This example shows how to use Instance Principal authentication
//! to send messages to an OCI Queue from within an OCI compute instance.
//!
//! # Prerequisites
//! - Running on an OCI compute instance
//! - Instance must be in a dynamic group
//! - Dynamic group must have a policy allowing queue operations
//!
//! # Running
//! ```bash
//! export OCI_QUEUE_ID="ocid1.queue.oc1..example"
//! cargo run --example instance_principal_example
//! ```

use oci_sdk::auth::InstancePrincipalAuth;
use oci_sdk::queue::QueueClient;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get queue ID from environment
    let queue_id = std::env::var("OCI_QUEUE_ID")
        .expect("Set OCI_QUEUE_ID environment variable");

    // Create Instance Principal authenticator
    // Region can be auto-detected from IMDS, or specified explicitly
    let auth = Arc::new(InstancePrincipalAuth::new(None));

    println!("Creating Queue client with Instance Principal auth...");

    // Create Queue client
    let queue = QueueClient::new(auth.clone(), &queue_id, None).await?;

    // Send a test message
    println!("Sending test message...");
    let response = queue
        .put_message(
            "Hello from Instance Principal!".to_string(),
            Some(serde_json::json!({
                "source": "instance_principal_example",
                "timestamp": chrono::Utc::now().to_rfc3339()
            })),
        )
        .await?;

    println!("Message sent successfully!");
    println!("Response: {:?}", response);

    // Get queue stats
    println!("\nQueue stats:");
    let stats = queue.get_stats().await?;
    println!("  Visible messages: {}", stats.visible_messages);
    println!("  In-flight messages: {}", stats.in_flight_messages);
    println!("  Size in bytes: {}", stats.size_in_bytes);

    Ok(())
}
