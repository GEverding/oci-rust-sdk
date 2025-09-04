# Troubleshooting OCI Rust SDK

## Common Issues and Solutions

### 1. Instance Principal Authentication Errors

#### Error: `405 Method Not Allowed` on metadata token endpoint

**Symptoms:**
```
2025-09-04T20:54:49.966540Z  WARN send_user_event_oci: mercury_core::user_events::oci: failed to send oci queue message error=Authentication error: Failed to get instance metadata: Metadata service error: Failed to get metadata token: 405 Method Not Allowed
```

**Cause:** 
The OCI metadata service endpoint might not support the HTTP method being used, or the endpoint structure has changed.

**Solution:**
The SDK now implements multiple fallback strategies:

1. **Primary**: Try `/opc/v2/identity/security-token` endpoint directly
2. **Fallback 1**: Try `/opc/v2/identity/token` endpoint directly  
3. **Fallback 2**: Use two-step process (metadata token → security token)

**Code Example:**
```rust
use oci_sdk::auth::InstancePrincipalAuth;
use std::sync::Arc;

// The SDK automatically handles endpoint detection and fallbacks
let auth = Arc::new(InstancePrincipalAuth::new(None));

// Check token status for debugging
if let Some(token_info) = auth.get_token_info().await {
    println!("Token expires in: {:?}", token_info.time_until_expiry);
}
```

#### Error: `404 Not Found` or `403 Forbidden`

**Symptoms:**
- `404 Not Found`: Instance metadata service endpoint not found
- `403 Forbidden`: Insufficient permissions to access metadata service

**Possible Causes:**
1. **IMDS Version Mismatch**: Instance configured for IMDSv2 only, but requests missing required headers
2. **IAM Policy Issues**: Instance lacks permissions to access metadata service
3. **Network Configuration**: Security groups or firewall blocking metadata service access

**Solutions:**

1. **Check IMDS Version:**
   ```bash
   # Test IMDSv2 access from the instance
   curl -H "Authorization: Bearer Oracle" http://169.254.169.254/opc/v2/instance/
   ```

2. **Verify IAM Policies:**
   - Ensure the instance has appropriate dynamic group membership
   - Check that dynamic group policies include metadata service access

3. **Network Connectivity:**
   ```bash
   # Test basic connectivity
   curl http://169.254.169.254/opc/v2/instance/
   ```

#### Error: Clock Skew Issues

**Symptoms:**
- Intermittent authentication failures
- Tokens appearing to expire immediately

**Solution:**
Ensure your instance's clock is synchronized:
```bash
# On Oracle Linux/CentOS
sudo yum install -y ntp
sudo systemctl enable ntpd
sudo systemctl start ntpd

# On Ubuntu/Debian  
sudo apt-get install -y ntp
sudo systemctl enable ntp
sudo systemctl start ntp
```

### 2. Token Management Issues

#### Token Refresh Failures

**Symptoms:**
- Periodic authentication failures in long-running applications
- Warnings about token refresh failures

**Solution:**
The SDK includes automatic token refresh with multiple retry strategies:

```rust
use oci_sdk::auth::InstancePrincipalAuth;

let auth = Arc::new(InstancePrincipalAuth::new(None));

// Token refresh happens automatically, but you can monitor it
if let Some(info) = auth.get_token_info().await {
    if info.is_expiring_soon {
        println!("Token will expire soon, refresh should happen automatically");
    }
}

// Force refresh if needed (usually not necessary)
if let Err(e) = auth.refresh_token().await {
    eprintln!("Manual refresh failed: {}", e);
}
```

#### Concurrent Access Issues

**Symptoms:**
- Race conditions when multiple threads access tokens
- Inconsistent authentication states

**Solution:**
The SDK uses proper concurrency protection:

```rust
// Safe to use the same auth provider across multiple threads/clients
let auth = Arc::new(InstancePrincipalAuth::new(None));

// Multiple clients can safely share the same auth provider
let identity1 = Identity::new(auth.clone(), None).await?;
let identity2 = Identity::new(auth.clone(), None).await?;
let queue = QueueClient::builder().auth_provider(auth.clone()).build().await?;
```

### 3. Connection and Performance Issues

#### HTTP Connection Issues

**Symptoms:**
- Slow API responses
- Connection timeouts
- Excessive connection overhead

**Solution:**
The SDK uses connection pooling and optimized HTTP settings:

- **Connection Pooling**: Reuses HTTP connections efficiently
- **Timeouts**: 10-second timeout for metadata service, 30-second for API calls
- **Keep-Alive**: TCP keep-alive enabled for persistent connections
- **HTTP/2**: Uses HTTP/2 when available for better performance

### 4. Debugging and Monitoring

#### Enable Debug Logging

Add to your application:
```rust
// The SDK includes built-in error logging for debugging
// Errors are automatically logged to stderr with detailed information
```

#### Monitor Token Status

```rust
use oci_sdk::auth::InstancePrincipalAuth;

let auth = Arc::new(InstancePrincipalAuth::new(None));

// Check token status periodically
tokio::spawn(async move {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    loop {
        interval.tick().await;
        if let Some(info) = auth.get_token_info().await {
            println!("Token status: expires in {:?}, expiring soon: {}", 
                     info.time_until_expiry, info.is_expiring_soon);
        }
    }
});
```

### 5. Migration from Older Versions

#### Updating from Manual Token Management

**Old Code:**
```rust
// Old manual approach
let auth = InstancePrincipalAuth::new(None)?;
tokio::spawn(async move {
    start_token_refresh_task(auth).await;
});
```

**New Code:**
```rust
// New automatic approach
let auth = Arc::new(InstancePrincipalAuth::new(None));
// That's it! Token management is automatic
```

#### Benefits of New Approach

- **No Manual Management**: Token refresh happens automatically
- **Concurrency Safe**: Multiple threads can safely access tokens
- **Better Error Handling**: Comprehensive error reporting and fallbacks
- **Performance**: Connection pooling and efficient caching
- **Monitoring**: Built-in token status monitoring

### 6. Best Practices

1. **Use Arc for Sharing**: Always wrap auth providers in `Arc<>` when sharing between clients
2. **Monitor Token Status**: Use `get_token_info()` for debugging and monitoring
3. **Handle Errors Gracefully**: The SDK provides detailed error information
4. **Clean Shutdown**: Call `auth.stop().await` for graceful cleanup (optional)
5. **Test in Development**: Use config file auth for local development, instance principals for production

### 7. Getting Help

If you continue to experience issues:

1. **Check the logs**: The SDK provides detailed error messages
2. **Test connectivity**: Ensure the instance can reach OCI metadata service
3. **Verify IAM policies**: Check dynamic group and policy configurations
4. **Update the SDK**: Ensure you're using the latest version
5. **File an issue**: Include error messages and environment details
