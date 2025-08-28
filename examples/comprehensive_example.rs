// Comprehensive example showing all new features:
// 1. Using aws-lc-rs instead of OpenSSL
// 2. Instance Principal authentication with automatic token refresh
// 3. Config file authentication
// 4. OCI Queue message publishing

use oci_sdk::auth::{ConfigFileAuth, InstancePrincipalAuth, start_token_refresh_task};
use oci_sdk::identity::Identity;
use oci_sdk::queue::{QueueClient, QueueMessage};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("OCI Rust SDK - Comprehensive Example");
    println!("====================================");

    // Example 1: Using Config File Authentication (traditional method)
    println!("\n1. Config File Authentication Example:");
    if let Ok(config_auth) = ConfigFileAuth::from_file(None, None) {
        let auth_provider = Arc::new(config_auth);
        
        // Create Identity client
        if let Ok(identity_client) = Identity::new(auth_provider.clone(), None).await {
            println!("✓ Identity client created with config file auth");
            
            // Test getting current user
            match identity_client.get_current_user().await {
                Ok(response) => {
                    if response.status().is_success() {
                        println!("✓ Successfully retrieved current user info");
                    } else {
                        println!("⚠ API call failed: {}", response.status());
                    }
                }
                Err(e) => println!("⚠ Error getting current user: {}", e),
            }
        }

        // Create Queue client for message publishing
        if let Ok(queue_client) = QueueClient::builder()
            .auth_provider(auth_provider.clone())
            .queue_id("ocid1.queue.oc1.region.example-queue-id") // Replace with actual queue OCID
            .build()
            .await
        {
            println!("✓ Queue client created with config file auth");
            
            // Example: Publishing a message
            let messages = vec![
                QueueMessage {
                    content: "Hello from OCI Rust SDK with aws-lc-rs!".to_string(),
                    metadata: Some(serde_json::json!({"source": "rust-sdk", "timestamp": chrono::Utc::now()})),
                },
                QueueMessage {
                    content: "Second message".to_string(),
                    metadata: None,
                },
            ];

            match queue_client.put_messages(messages).await {
                Ok(response) => {
                    println!("✓ Successfully published messages to queue");
                    for (i, entry) in response.entries.iter().enumerate() {
                        if let Some(error) = &entry.error {
                            println!("  ⚠ Message {}: Error - {}", i, error);
                        } else {
                            println!("  ✓ Message {}: Published with ID {}", i, entry.id);
                        }
                    }
                }
                Err(e) => println!("⚠ Error publishing messages: {}", e),
            }

            // Example: Publishing a single message
            match queue_client
                .put_message(
                    "Single message example".to_string(),
                    Some(serde_json::json!({"type": "single"})),
                )
                .await
            {
                Ok(_) => println!("✓ Successfully published single message"),
                Err(e) => println!("⚠ Error publishing single message: {}", e),
            }
        }
    } else {
        println!("⚠ Config file authentication not available (missing ~/.oci/config)");
    }

    // Example 2: Using Instance Principal Authentication (cloud native method)
    println!("\n2. Instance Principal Authentication Example:");
    
    // Create Instance Principal auth provider
    let instance_auth = Arc::new(InstancePrincipalAuth::new(Some("us-ashburn-1".to_string())));
    
    // Start the automatic token refresh task in the background
    let auth_for_refresh = instance_auth.clone();
    tokio::spawn(async move {
        start_token_refresh_task(auth_for_refresh).await;
    });

    // Try to create clients with instance principal authentication
    // Note: This will only work when running on an OCI compute instance with proper IAM policies
    match Identity::new(instance_auth.clone(), None).await {
        Ok(identity_client) => {
            println!("✓ Identity client created with instance principal auth");
            
            match identity_client.get_current_user().await {
                Ok(response) => {
                    if response.status().is_success() {
                        println!("✓ Successfully retrieved current user info via instance principal");
                    } else {
                        println!("⚠ API call failed: {}", response.status());
                    }
                }
                Err(e) => println!("⚠ Error getting current user via instance principal: {}", e),
            }
        }
        Err(e) => {
            println!("⚠ Instance principal authentication not available: {}", e);
            println!("  (This is expected when not running on an OCI compute instance)");
        }
    }

    // Create Queue client with instance principal
    match QueueClient::builder()
        .auth_provider(instance_auth)
        .queue_id("ocid1.queue.oc1.region.example-queue-id") // Replace with actual queue OCID
        .build()
        .await
    {
        Ok(queue_client) => {
            println!("✓ Queue client created with instance principal auth");
            
            // Demonstrate queue operations
            match queue_client.get_stats().await {
                Ok(response) => {
                    if response.status().is_success() {
                        println!("✓ Successfully retrieved queue statistics");
                    } else {
                        println!("⚠ Failed to get queue stats: {}", response.status());
                    }
                }
                Err(e) => println!("⚠ Error getting queue stats: {}", e),
            }
        }
        Err(e) => {
            println!("⚠ Could not create queue client with instance principal: {}", e);
        }
    }

    println!("\n3. Key Improvements in this version:");
    println!("   ✓ Replaced OpenSSL with aws-lc-rs for better performance and FIPS compliance");
    println!("   ✓ Added Instance Principal support for cloud-native authentication");
    println!("   ✓ Automatic token refresh for long-running services");
    println!("   ✓ Asynchronous authentication operations");
    println!("   ✓ New OCI Queue service support for message publishing");
    println!("   ✓ Builder pattern for easy client configuration");
    println!("   ✓ Comprehensive error handling");
    println!("   ✓ Backward compatibility with existing config file authentication");

    println!("\n4. Migration Guide:");
    println!("   • Replace `AuthConfig::from_file()` with `ConfigFileAuth::from_file()`");
    println!("   • Use `Identity::new(auth_provider, endpoint).await` instead of `Identity::new(config, endpoint)`");
    println!("   • Wrap auth providers in `Arc<>` for sharing between clients");
    println!("   • For cloud deployments, use `InstancePrincipalAuth::new()` instead of config files");
    println!("   • Use `QueueClient::builder()` to create queue clients for message publishing");

    println!("\nExample completed!");
    Ok(())
}
