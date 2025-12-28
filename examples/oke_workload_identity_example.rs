//! Example: Using OKE Workload Identity authentication with OCI Queue
//!
//! This example shows how to use OKE Workload Identity authentication
//! to send messages to an OCI Queue from a Kubernetes pod in OKE.
//!
//! # Prerequisites
//! - Running in an OKE cluster with Workload Identity enabled
//! - Service account must be mapped to an OCI IAM principal
//! - IAM policy must allow queue operations
//!
//! # Kubernetes Deployment Example
//! ```yaml
//! apiVersion: v1
//! kind: ServiceAccount
//! metadata:
//!   name: queue-sender
//!   namespace: default
//!   annotations:
//!     oci.oraclecloud.com/audience: sts.oraclecloud.com
//! ---
//! apiVersion: apps/v1
//! kind: Deployment
//! metadata:
//!   name: queue-sender
//! spec:
//!   template:
//!     spec:
//!       serviceAccountName: queue-sender
//!       containers:
//!       - name: app
//!         image: your-image
//!         env:
//!         - name: OCI_QUEUE_ID
//!           value: "ocid1.queue.oc1..example"
//!         - name: OCI_REGION
//!           value: "us-ashburn-1"
//! ```

use oci_sdk::auth::OkeWorkloadIdentityAuth;
use oci_sdk::queue::QueueClient;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get configuration from environment
    let queue_id = std::env::var("OCI_QUEUE_ID").expect("Set OCI_QUEUE_ID environment variable");
    let region = std::env::var("OCI_REGION").expect("Set OCI_REGION environment variable");

    // Create OKE Workload Identity authenticator
    // Token path defaults to /var/run/secrets/kubernetes.io/serviceaccount/token
    // or /var/run/secrets/oci/token if using OCI-specific token
    let auth = Arc::new(OkeWorkloadIdentityAuth::new(region, None));

    println!("Creating Queue client with OKE Workload Identity auth...");

    // Create Queue client
    let queue = QueueClient::new(auth.clone(), &queue_id, None).await?;

    // Send a test message
    println!("Sending test message from Kubernetes pod...");
    let response = queue
        .put_message(
            "Hello from OKE Workload Identity!".to_string(),
            Some(serde_json::json!({
                "source": "oke_workload_identity_example",
                "pod_name": std::env::var("HOSTNAME").unwrap_or_default(),
                "timestamp": chrono::Utc::now().to_rfc3339()
            })),
        )
        .await?;

    println!("Message sent successfully!");
    println!("Response: {:?}", response);

    // Receive messages (consumer example)
    println!("\nReceiving messages...");
    let messages = queue.get_messages(Some(10), Some(30), Some(5)).await?;

    for msg in &messages.messages {
        println!("Received message: {} (id: {})", msg.content, msg.id);

        // Process the message...

        // Delete after processing
        queue.delete_message(&msg.receipt).await?;
        println!("  Deleted message {}", msg.id);
    }

    println!("\nProcessed {} messages", messages.messages.len());

    Ok(())
}
