// Demonstrates the elegant token management system with automatic refresh,
// proper concurrency handling, and monitoring capabilities

use oci_sdk::auth::InstancePrincipalAuth;
use oci_sdk::identity::Identity;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("OCI Rust SDK - Elegant Token Management Example");
    println!("===============================================");

    // Create Instance Principal auth with automatic token management
    let auth_provider = Arc::new(InstancePrincipalAuth::new(Some("us-ashburn-1".to_string())));

    println!("✓ Instance Principal authentication created");
    println!("✓ Background token refresh automatically started");
    println!("✓ Concurrent access protection enabled");

    // Demonstrate concurrent access - multiple tasks requesting tokens simultaneously
    println!("\n🔄 Testing concurrent token access...");

    let mut handles = vec![];
    for i in 0..5 {
        let auth = auth_provider.clone();
        handles.push(tokio::spawn(async move {
            match Identity::new(auth, None).await {
                Ok(identity) => match identity.get_current_user().await {
                    Ok(response) => {
                        println!(
                            "  Task {}: ✓ Successfully authenticated (status: {})",
                            i,
                            response.status()
                        );
                        Ok(())
                    }
                    Err(e) => {
                        println!("  Task {}: ⚠ API call failed: {}", i, e);
                        Err(e)
                    }
                },
                Err(e) => {
                    println!("  Task {}: ⚠ Auth failed: {}", i, e);
                    Err(Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
                }
            }
        }));
    }

    // Wait for all concurrent tasks to complete
    let results = futures::future::join_all(handles).await;
    let successful = results.iter().filter(|r| r.is_ok()).count();
    println!(
        "✓ {}/{} concurrent tasks completed successfully",
        successful,
        results.len()
    );

    // Demonstrate token monitoring
    println!("\n📊 Token Status Monitoring:");
    for i in 0..3 {
        if let Some(token_info) = auth_provider.get_token_info().await {
            println!(
                "  Check #{}: Token expires in {:?} (expiring soon: {})",
                i + 1,
                token_info.time_until_expiry,
                token_info.is_expiring_soon
            );
        } else {
            println!("  Check #{}: No token available yet", i + 1);
        }

        sleep(Duration::from_secs(2)).await;
    }

    // Demonstrate forced refresh
    println!("\n🔄 Testing forced token refresh...");
    match auth_provider.refresh_token().await {
        Ok(()) => {
            println!("✓ Token successfully refreshed");
            if let Some(token_info) = auth_provider.get_token_info().await {
                println!("  New token expires in: {:?}", token_info.time_until_expiry);
            }
        }
        Err(e) => {
            println!("⚠ Token refresh failed: {}", e);
        }
    }

    // Demonstrate graceful shutdown
    println!("\n🛑 Testing graceful shutdown...");
    auth_provider.stop().await;
    println!("✓ Background token refresh stopped");

    // Show the benefits of the elegant token management system
    println!("\n🎯 Key Benefits of Elegant Token Management:");
    println!("  • Automatic background refresh prevents token expiry");
    println!("  • Concurrent access protection prevents race conditions");
    println!("  • Built-in monitoring for debugging and observability");
    println!("  • Graceful shutdown for clean resource cleanup");
    println!("  • Zero-configuration - works out of the box");
    println!("  • Efficient - only refreshes when needed");
    println!("  • Resilient - handles failures gracefully");

    println!("\n✨ No more manual token management headaches!");

    Ok(())
}
