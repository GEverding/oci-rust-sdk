use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use thiserror::Error;
use tokio::sync::{Mutex, Notify, RwLock};

#[derive(Error, Debug)]
pub enum TokenError {
    #[error("Token expired")]
    Expired,
    #[error("Token refresh failed: {0}")]
    RefreshFailed(String),
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),
    #[error("JSON parsing error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Metadata service error: {0}")]
    MetadataError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    #[serde(skip, default = "SystemTime::now")]
    pub issued_at: SystemTime,
}

impl Token {
    pub fn expires_at(&self) -> SystemTime {
        self.issued_at + Duration::from_secs(self.expires_in)
    }

    pub fn is_expired(&self) -> bool {
        SystemTime::now() >= self.expires_at()
    }

    pub fn is_expiring_soon(&self, buffer_seconds: u64) -> bool {
        let buffer_time = self.expires_at() - Duration::from_secs(buffer_seconds);
        SystemTime::now() >= buffer_time
    }

    pub fn time_until_expiry(&self) -> Duration {
        self.expires_at()
            .duration_since(SystemTime::now())
            .unwrap_or(Duration::ZERO)
    }
}

/// Elegant token manager with automatic refresh, proper concurrency, and lifecycle management
pub struct TokenManager {
    /// Current token
    token: Arc<RwLock<Option<Token>>>,
    /// Refresh function
    refresh_fn: Arc<dyn Fn() -> tokio::task::JoinHandle<Result<Token, TokenError>> + Send + Sync>,
    /// Refresh mutex to prevent concurrent refreshes
    refresh_mutex: Arc<Mutex<()>>,
    /// Notify for waking up waiters when token is refreshed
    refresh_notify: Arc<Notify>,
    /// Background refresh task handle
    refresh_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    /// Configuration
    config: TokenManagerConfig,
}

#[derive(Debug, Clone)]
pub struct TokenManagerConfig {
    /// Buffer time before expiry to trigger refresh (default: 5 minutes)
    pub refresh_buffer: Duration,
    /// How often to check for token expiry in background (default: 1 minute)
    pub check_interval: Duration,
    /// Maximum number of concurrent waiters for token refresh
    pub max_waiters: usize,
    /// Whether to start background refresh automatically
    pub auto_refresh: bool,
}

impl Default for TokenManagerConfig {
    fn default() -> Self {
        Self {
            refresh_buffer: Duration::from_secs(300), // 5 minutes
            check_interval: Duration::from_secs(60),  // 1 minute
            max_waiters: 100,
            auto_refresh: true,
        }
    }
}

impl TokenManager {
    /// Create a new token manager with a refresh function
    pub fn new<F, Fut>(refresh_fn: F, config: Option<TokenManagerConfig>) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<Token, TokenError>> + Send + 'static,
    {
        let config = config.unwrap_or_default();
        
        // Wrap the async function to return a JoinHandle
        let refresh_fn = Arc::new(move || tokio::spawn(refresh_fn()));
        
        let manager = Self {
            token: Arc::new(RwLock::new(None)),
            refresh_fn,
            refresh_mutex: Arc::new(Mutex::new(())),
            refresh_notify: Arc::new(Notify::new()),
            refresh_task: Arc::new(Mutex::new(None)),
            config,
        };

        if manager.config.auto_refresh {
            manager.start_background_refresh();
        }

        manager
    }

    /// Get a valid token, refreshing if necessary
    pub async fn get_token(&self) -> Result<String, TokenError> {
        // Fast path: check if current token is still valid
        {
            let token_guard = self.token.read().await;
            if let Some(ref token) = *token_guard {
                if !token.is_expiring_soon(self.config.refresh_buffer.as_secs()) {
                    return Ok(token.access_token.clone());
                }
            }
        }

        // Slow path: need to refresh token
        self.refresh_token_if_needed().await
    }

    /// Force refresh the token
    pub async fn refresh_token(&self) -> Result<String, TokenError> {
        let _guard = self.refresh_mutex.lock().await;
        
        let handle = (self.refresh_fn)();
        let new_token = handle.await
            .map_err(|e| TokenError::RefreshFailed(format!("Task join error: {}", e)))?
            .map_err(|e| TokenError::RefreshFailed(e.to_string()))?;

        let access_token = new_token.access_token.clone();
        *self.token.write().await = Some(new_token);
        
        // Notify all waiters that token has been refreshed
        self.refresh_notify.notify_waiters();
        
        Ok(access_token)
    }

    async fn refresh_token_if_needed(&self) -> Result<String, TokenError> {
        // Try to acquire refresh mutex without blocking
        if let Ok(_guard) = self.refresh_mutex.try_lock() {
            // We got the mutex, so we're responsible for refreshing
            let handle = (self.refresh_fn)();
            let new_token = handle.await
                .map_err(|e| TokenError::RefreshFailed(format!("Task join error: {}", e)))?
                .map_err(|e| TokenError::RefreshFailed(e.to_string()))?;

            let access_token = new_token.access_token.clone();
            *self.token.write().await = Some(new_token);
            
            // Notify all waiters
            self.refresh_notify.notify_waiters();
            
            Ok(access_token)
        } else {
            // Another task is refreshing, wait for it to complete
            self.refresh_notify.notified().await;
            
            // Check if we now have a valid token
            let token_guard = self.token.read().await;
            token_guard
                .as_ref()
                .map(|t| t.access_token.clone())
                .ok_or(TokenError::Expired)
        }
    }

    /// Start background refresh task
    pub fn start_background_refresh(&self) {
        let token = Arc::clone(&self.token);
        let refresh_fn = Arc::clone(&self.refresh_fn);
        let refresh_mutex = Arc::clone(&self.refresh_mutex);
        let refresh_notify = Arc::clone(&self.refresh_notify);
        let config = self.config.clone();

        let task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(config.check_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            loop {
                interval.tick().await;

                // Check if token needs refresh
                let needs_refresh = {
                    let token_guard = token.read().await;
                    if let Some(ref current_token) = *token_guard {
                        current_token.is_expiring_soon(config.refresh_buffer.as_secs())
                    } else {
                        true // No token, need to get one
                    }
                };

                if needs_refresh {
                    if let Ok(_guard) = refresh_mutex.try_lock() {
                        match (refresh_fn)().await {
                            Ok(Ok(new_token)) => {
                                *token.write().await = Some(new_token);
                                refresh_notify.notify_waiters();
                            }
                            Ok(Err(e)) => {
                                eprintln!("Background token refresh failed: {}", e);
                            }
                            Err(e) => {
                                eprintln!("Background token refresh task failed: {}", e);
                            }
                        }
                    }
                    // If we can't get the mutex, another refresh is in progress
                }
            }
        });

        // Store the task handle
        if let Ok(mut task_guard) = self.refresh_task.try_lock() {
            *task_guard = Some(task);
        }
    }

    /// Stop background refresh task
    pub async fn stop_background_refresh(&self) {
        let mut task_guard = self.refresh_task.lock().await;
        if let Some(task) = task_guard.take() {
            task.abort();
        }
    }

    /// Get token info without refreshing
    pub async fn get_token_info(&self) -> Option<TokenInfo> {
        let token_guard = self.token.read().await;
        token_guard.as_ref().map(|token| TokenInfo {
            expires_at: token.expires_at(),
            is_expired: token.is_expired(),
            is_expiring_soon: token.is_expiring_soon(self.config.refresh_buffer.as_secs()),
            time_until_expiry: token.time_until_expiry(),
        })
    }

    /// Check if manager has a token
    pub async fn has_token(&self) -> bool {
        let token_guard = self.token.read().await;
        token_guard.is_some()
    }
}

impl Drop for TokenManager {
    fn drop(&mut self) {
        // Attempt to stop background task on drop
        if let Ok(mut task_guard) = self.refresh_task.try_lock() {
            if let Some(task) = task_guard.take() {
                task.abort();
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct TokenInfo {
    pub expires_at: SystemTime,
    pub is_expired: bool,
    pub is_expiring_soon: bool,
    pub time_until_expiry: Duration,
}

/// Instance Principal Token Manager - specialized for OCI metadata service
pub struct InstancePrincipalTokenManager {
    token_manager: TokenManager,
    metadata_base_url: String,
    client: reqwest::Client,
}

impl InstancePrincipalTokenManager {
    pub fn new(_region: Option<String>, config: Option<TokenManagerConfig>) -> Self {
        let metadata_base_url = "http://169.254.169.254/opc/v2".to_string();
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("Failed to create HTTP client");

        let metadata_url = metadata_base_url.clone();
        let http_client = client.clone();

        let refresh_fn = move || {
            let url = metadata_url.clone();
            let client = http_client.clone();
            async move {
                Self::fetch_token_from_metadata(&url, &client).await
            }
        };

        let token_manager = TokenManager::new(refresh_fn, config);

        Self {
            token_manager,
            metadata_base_url,
            client,
        }
    }

    async fn fetch_token_from_metadata(
        metadata_base_url: &str,
        client: &reqwest::Client,
    ) -> Result<Token, TokenError> {
        // Step 1: Get metadata token
        let metadata_token = Self::get_metadata_token(metadata_base_url, client).await?;

        // Step 2: Get instance principal token
        let response = client
            .get(&format!("{}/identity/token", metadata_base_url))
            .header("Metadata-Flavor", "Oracle")
            .header("Authorization", &format!("Bearer {}", metadata_token))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(TokenError::MetadataError(format!(
                "Failed to get instance principal token: {}",
                response.status()
            )));
        }

        let mut token: Token = response.json().await?;
        token.issued_at = SystemTime::now();

        Ok(token)
    }

    async fn get_metadata_token(
        metadata_base_url: &str,
        client: &reqwest::Client,
    ) -> Result<String, TokenError> {
        let response = client
            .put(&format!("{}/identity/token", metadata_base_url))
            .header("Metadata-Flavor", "Oracle")
            .header("Authorization", "Bearer Oracle")
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(TokenError::MetadataError(format!(
                "Failed to get metadata token: {}",
                response.status()
            )));
        }

        Ok(response.text().await?)
    }

    /// Get a valid token
    pub async fn get_token(&self) -> Result<String, TokenError> {
        self.token_manager.get_token().await
    }

    /// Force refresh the token
    pub async fn refresh_token(&self) -> Result<String, TokenError> {
        self.token_manager.refresh_token().await
    }

    /// Get token information
    pub async fn get_token_info(&self) -> Option<TokenInfo> {
        self.token_manager.get_token_info().await
    }

    /// Check if manager has a token
    pub async fn has_token(&self) -> bool {
        self.token_manager.has_token().await
    }

    /// Stop background refresh
    pub async fn stop(&self) {
        self.token_manager.stop_background_refresh().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[tokio::test]
    async fn test_token_manager_basic() {
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let refresh_fn = move || {
            let counter = counter_clone.clone();
            async move {
                let count = counter.fetch_add(1, Ordering::SeqCst);
                Ok(Token {
                    access_token: format!("token-{}", count),
                    token_type: "Bearer".to_string(),
                    expires_in: 3600,
                    issued_at: SystemTime::now(),
                })
            }
        };

        let config = TokenManagerConfig {
            auto_refresh: false,
            ..Default::default()
        };

        let manager = TokenManager::new(refresh_fn, Some(config));

        // First call should trigger refresh
        let token1 = manager.get_token().await.unwrap();
        assert_eq!(token1, "token-0");

        // Second call should return cached token
        let token2 = manager.get_token().await.unwrap();
        assert_eq!(token2, "token-0");

        // Counter should only be 1 (called once)
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_concurrent_refresh() {
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let refresh_fn = move || {
            let counter = counter_clone.clone();
            async move {
                // Simulate slow refresh
                tokio::time::sleep(Duration::from_millis(100)).await;
                let count = counter.fetch_add(1, Ordering::SeqCst);
                Ok(Token {
                    access_token: format!("token-{}", count),
                    token_type: "Bearer".to_string(),
                    expires_in: 1, // Very short expiry to force refresh
                    issued_at: SystemTime::now(),
                })
            }
        };

        let config = TokenManagerConfig {
            refresh_buffer: Duration::from_secs(0),
            auto_refresh: false,
            ..Default::default()
        };

        let manager = Arc::new(TokenManager::new(refresh_fn, Some(config)));

        // Launch multiple concurrent requests
        let mut handles = vec![];
        for _ in 0..10 {
            let manager_clone = manager.clone();
            handles.push(tokio::spawn(async move {
                manager_clone.get_token().await
            }));
        }

        // Wait for all to complete
        let results: Vec<_> = futures::future::join_all(handles).await;
        
        // All should succeed and get the same token
        let tokens: Vec<String> = results.into_iter().map(|r| r.unwrap().unwrap()).collect();
        assert!(tokens.iter().all(|t| t == &tokens[0]));

        // Should only refresh once despite concurrent requests
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }
}
