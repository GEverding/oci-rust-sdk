// Simple example demonstrating Instance Principal authentication
// This example shows how to use the SDK in a cloud-native way without config files

use oci_sdk::auth::{InstancePrincipalAuth, start_token_refresh_task};
use oci_sdk::identity::Identity;
use oci_sdk::queue::{QueueClient, QueueMessage};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("OCI Rust SDK - Instance Principal Example");
    println!("=========================================");

    // Create Instance Principal auth provider
    // This will automatically detect the region from instance metadata
    let auth_provider = Arc::new(InstancePrincipalAuth::new(None));
    
    // Start the background token refresh task
    // This ensures tokens are refreshed automatically for long-running services
    let auth_for_refresh = auth_provider.clone();
    let _refresh_handle = tokio::spawn(async move {
        start_token_refresh_task(auth_for_refresh).await;
    });

    println!("✓ Instance Principal authentication configured");
    println!("✓ Automatic token refresh task started");

    // Create an Identity client to test authentication
    match Identity::new(auth_provider.clone(), None).await {
        Ok(identity_client) => {
            println!("✓ Identity client created successfully");
            
            // Test the authentication by getting current user info
            match identity_client.get_current_user().await {
                Ok(response) => {
                    if response.status().is_success() {
                        let user_info = response.text().await?;
                        println!("✓ Authentication successful!");
                        println!("Current user info: {}", user_info);
                    } else {
                        println!("⚠ Authentication failed: {}", response.status());
                        let error_body = response.text().await.unwrap_or_default();
                        println!("Error details: {}", error_body);
                    }
                }
                Err(e) => {
                    println!("⚠ Error calling Identity API: {}", e);
                }
            }
        }
        Err(e) => {
            println!("⚠ Failed to create Identity client: {}", e);
            println!("  Make sure this is running on an OCI compute instance with proper IAM policies");
            return Ok(());
        }
    }

    // Example: Create a Queue client for publishing messages
    // Replace with your actual queue OCID
    let queue_id = std::env::var("OCI_QUEUE_ID")
        .unwrap_or_else(|_| "ocid1.queue.oc1.region.example".to_string());

    match QueueClient::builder()
        .auth_provider(auth_provider)
        .queue_id(&queue_id)
        .build()
        .await
    {
        Ok(queue_client) => {
            println!("✓ Queue client created successfully");

            // Publish a test message
            let message = QueueMessage {
                content: format!("Test message from Instance Principal at {}", chrono::Utc::now()),
                metadata: Some(serde_json::json!({
                    "source": "instance_principal_example",
                    "hostname": gethostname::gethostname().to_string_lossy()
                })),
            };

            match queue_client.put_messages(vec![message]).await {
                Ok(response) => {
                    println!("✓ Message published successfully!");
                    for (i, entry) in response.entries.iter().enumerate() {
                        if let Some(error) = &entry.error {
                            println!("  ⚠ Message {}: Error - {}", i, error);
                        } else {
                            println!("  ✓ Message {}: Published with ID {}", i, entry.id);
                        }
                    }
                }
                Err(e) => {
                    println!("⚠ Failed to publish message: {}", e);
                }
            }

            // Get queue statistics
            match queue_client.get_stats().await {
                Ok(response) => {
                    if response.status().is_success() {
                        let stats = response.text().await?;
                        println!("✓ Queue statistics: {}", stats);
                    } else {
                        println!("⚠ Failed to get queue stats: {}", response.status());
                    }
                }
                Err(e) => {
                    println!("⚠ Error getting queue stats: {}", e);
                }
            }
        }
        Err(e) => {
            println!("⚠ Failed to create Queue client: {}", e);
        }
    }

    println!("\nInstance Principal Example completed!");
    println!("\nKey Benefits:");
    println!("  • No credential files to manage");
    println!("  • Automatic token refresh for long-running services");
    println!("  • Cloud-native security model");
    println!("  • Works seamlessly with OCI IAM policies");

    // Keep the program running for a bit to demonstrate token refresh
    println!("\nKeeping program alive for 30 seconds to demonstrate token refresh...");
    tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
    println!("✓ Token refresh working in background");

    Ok(())
}
