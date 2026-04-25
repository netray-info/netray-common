//! Backend HTTP client with semaphore-based concurrency limiting and optional caching.
//!
//! [`BackendClient`] wraps `reqwest::Client` with per-backend concurrency protection
//! (via `tokio::sync::Semaphore`), an optional `moka` TTL cache for GET responses,
//! `X-Request-Id` propagation, and Prometheus metrics.

use std::sync::Arc;
use std::time::Duration;

/// Configuration for a single backend service.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct BackendConfig {
    /// Base URL of the backend service. `None` disables this backend.
    pub url: Option<String>,
    /// Per-call timeout in milliseconds (permit acquisition + request). Default: 2000.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Max concurrent in-flight requests. Default: 20.
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: u32,
    /// Cache TTL in seconds. 0 = disabled (default).
    #[serde(default)]
    pub cache_ttl_secs: u64,
    /// Cache capacity in entries. Default: 1024.
    #[serde(default = "default_cache_capacity")]
    pub cache_capacity: u64,
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self {
            url: None,
            timeout_ms: default_timeout_ms(),
            max_concurrent: default_max_concurrent(),
            cache_ttl_secs: 0,
            cache_capacity: default_cache_capacity(),
        }
    }
}

fn default_timeout_ms() -> u64 {
    2000
}
fn default_max_concurrent() -> u32 {
    20
}
fn default_cache_capacity() -> u64 {
    1024
}

/// A cached HTTP response (status + body).
#[derive(Debug, Clone)]
pub struct CachedResponse {
    pub status: u16,
    pub body: bytes::Bytes,
}

/// Errors returned by [`BackendClient`] operations.
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("semaphore closed")]
    SemaphoreClosed,
    #[error("timeout acquiring semaphore or awaiting response")]
    Timeout,
    #[error("HTTP error: {0}")]
    Http(reqwest::StatusCode),
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),
}

/// HTTP client for internal service-to-service calls with concurrency limiting,
/// optional caching, request-ID propagation, and Prometheus metrics.
pub struct BackendClient {
    http: reqwest::Client,
    base_url: String,
    timeout: Duration,
    semaphore: Arc<tokio::sync::Semaphore>,
    cache: Option<moka::future::Cache<String, CachedResponse>>,
    service: &'static str,
    caller: &'static str,
}

impl BackendClient {
    /// Construct from config. Returns `None` if `config.url` is `None` (backend disabled).
    pub fn new(
        config: &BackendConfig,
        service: &'static str,
        caller: &'static str,
    ) -> Option<Self> {
        let base_url = config.url.as_ref()?;
        let timeout_ms = config.timeout_ms.min(25_000);
        let timeout = Duration::from_millis(timeout_ms);

        let http = reqwest::Client::builder()
            .timeout(timeout)
            .pool_max_idle_per_host(5)
            .pool_idle_timeout(Duration::from_secs(90))
            .build()
            .expect("failed to build backend HTTP client");

        let cache = if config.cache_ttl_secs > 0 {
            Some(
                moka::future::Cache::builder()
                    .max_capacity(config.cache_capacity)
                    .time_to_live(Duration::from_secs(config.cache_ttl_secs))
                    .build(),
            )
        } else {
            None
        };

        Some(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_owned(),
            timeout,
            semaphore: Arc::new(tokio::sync::Semaphore::new(config.max_concurrent as usize)),
            cache,
            service,
            caller,
        })
    }

    /// Returns the base URL of the backend service.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// GET request. Acquires semaphore, checks cache, sends request, records metrics.
    ///
    /// Cache key is `path` (full path + query string as provided).
    /// Only caches responses with 2xx status.
    pub async fn get(
        &self,
        path: &str,
        request_id: Option<&str>,
    ) -> Result<(reqwest::StatusCode, bytes::Bytes), BackendError> {
        // Check cache first (before acquiring semaphore)
        if let Some(ref cache) = self.cache {
            if let Some(cached) = cache.get(path).await {
                metrics::counter!(
                    "backend_cache_hits_total",
                    "service" => self.service,
                    "caller" => self.caller,
                )
                .increment(1);
                return Ok((
                    reqwest::StatusCode::from_u16(cached.status).unwrap_or(reqwest::StatusCode::OK),
                    cached.body,
                ));
            }
            metrics::counter!(
                "backend_cache_misses_total",
                "service" => self.service,
                "caller" => self.caller,
            )
            .increment(1);
        }

        // Acquire semaphore permit with timeout
        let permit = tokio::time::timeout(self.timeout, self.semaphore.acquire())
            .await
            .map_err(|_| BackendError::Timeout)?
            .map_err(|_| BackendError::SemaphoreClosed)?;

        // Track if we had to queue
        if self.semaphore.available_permits() == 0 {
            metrics::counter!(
                "backend_semaphore_queued_total",
                "service" => self.service,
                "caller" => self.caller,
            )
            .increment(1);
        }

        metrics::counter!(
            "backend_requests_total",
            "service" => self.service,
            "caller" => self.caller,
        )
        .increment(1);

        let url = format!("{}{}", self.base_url, path);
        let mut req = self.http.get(&url);
        if let Some(rid) = request_id {
            req = req.header("X-Request-Id", rid);
        }

        let start = std::time::Instant::now();
        let result = tokio::time::timeout(self.timeout, req.send()).await;
        let elapsed = start.elapsed().as_secs_f64();

        metrics::histogram!(
            "backend_request_duration_seconds",
            "service" => self.service,
            "caller" => self.caller,
        )
        .record(elapsed);

        drop(permit);

        let resp = match result {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => {
                metrics::counter!(
                    "backend_errors_total",
                    "service" => self.service,
                    "caller" => self.caller,
                )
                .increment(1);
                return Err(BackendError::Network(e));
            }
            Err(_) => {
                metrics::counter!(
                    "backend_errors_total",
                    "service" => self.service,
                    "caller" => self.caller,
                )
                .increment(1);
                return Err(BackendError::Timeout);
            }
        };

        let status = resp.status();
        let body = resp.bytes().await.map_err(BackendError::Network)?;

        // Cache only 2xx responses
        if status.is_success() {
            if let Some(ref cache) = self.cache {
                cache
                    .insert(
                        path.to_owned(),
                        CachedResponse {
                            status: status.as_u16(),
                            body: body.clone(),
                        },
                    )
                    .await;
            }
        }

        if status.is_success() || status.is_redirection() {
            Ok((status, body))
        } else {
            metrics::counter!(
                "backend_errors_total",
                "service" => self.service,
                "caller" => self.caller,
            )
            .increment(1);
            Err(BackendError::Http(status))
        }
    }

    /// HEAD request for readiness probes. No semaphore, no cache.
    pub async fn head(&self, path: &str) -> Result<reqwest::StatusCode, BackendError> {
        let url = format!("{}{}", self.base_url, path);
        let resp = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .map_err(BackendError::Network)?
            .head(&url)
            .send()
            .await
            .map_err(BackendError::Network)?;
        Ok(resp.status())
    }
}

impl std::fmt::Debug for BackendClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackendClient")
            .field("base_url", &self.base_url)
            .field("service", &self.service)
            .field("caller", &self.caller)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Start a mock HTTP server on a random port, returning its base URL.
    async fn mock_server(router: axum::Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(listener, router).await.ok();
        });
        (format!("http://{addr}"), handle)
    }

    fn config_with_url(url: &str, max_concurrent: u32, cache_ttl_secs: u64) -> BackendConfig {
        BackendConfig {
            url: Some(url.to_owned()),
            timeout_ms: 5000,
            max_concurrent,
            cache_ttl_secs,
            cache_capacity: 64,
        }
    }

    #[test]
    fn new_returns_none_when_url_is_none() {
        let cfg = BackendConfig::default();
        assert!(cfg.url.is_none());
        assert!(BackendClient::new(&cfg, "test", "test").is_none());
    }

    #[test]
    fn new_returns_some_when_url_is_set() {
        let cfg = BackendConfig {
            url: Some("http://localhost:9999".to_owned()),
            ..Default::default()
        };
        assert!(BackendClient::new(&cfg, "test", "test").is_some());
    }

    #[test]
    fn defaults_are_correct() {
        let cfg = BackendConfig::default();
        assert_eq!(cfg.timeout_ms, 2000);
        assert_eq!(cfg.max_concurrent, 20);
        assert_eq!(cfg.cache_ttl_secs, 0);
        assert_eq!(cfg.cache_capacity, 1024);
    }

    // T1: Semaphore caps concurrency
    #[tokio::test]
    async fn semaphore_caps_concurrency() {
        let hit_counter = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));
        let counter = hit_counter.clone();
        let max = max_seen.clone();

        let app = axum::Router::new().route(
            "/slow",
            axum::routing::get(move || {
                let counter = counter.clone();
                let max = max.clone();
                async move {
                    let current = counter.fetch_add(1, Ordering::SeqCst) + 1;
                    // Update max if current is higher
                    max.fetch_max(current, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    counter.fetch_sub(1, Ordering::SeqCst);
                    "ok"
                }
            }),
        );

        let (url, _handle) = mock_server(app).await;
        let cfg = config_with_url(&url, 2, 0);
        let client = BackendClient::new(&cfg, "test", "test").unwrap();

        // Fire 5 concurrent requests
        let mut handles = Vec::new();
        for _ in 0..5 {
            let c = &client;
            handles.push(async move { c.get("/slow", None).await });
        }
        let results: Vec<_> = futures::future::join_all(handles).await;
        for r in &results {
            assert!(r.is_ok(), "all requests should succeed: {r:?}");
        }

        // At most 2 should have been in-flight simultaneously
        assert!(
            max_seen.load(Ordering::SeqCst) <= 2,
            "max concurrent was {}, expected <= 2",
            max_seen.load(Ordering::SeqCst)
        );
    }

    // T2: Semaphore acquisition timeout — second request times out waiting for permit
    #[tokio::test]
    async fn semaphore_timeout_when_saturated() {
        let app = axum::Router::new().route(
            "/hold",
            axum::routing::get(|| async {
                // Hold the connection open for a long time
                tokio::time::sleep(Duration::from_secs(30)).await;
                "ok"
            }),
        );

        let (url, _handle) = mock_server(app).await;
        // Long timeout so the first request holds the permit, short enough that
        // the second request's semaphore wait times out.
        let cfg = BackendConfig {
            url: Some(url),
            timeout_ms: 200,
            max_concurrent: 1,
            cache_ttl_secs: 0,
            cache_capacity: 64,
        };
        let client = BackendClient::new(&cfg, "test", "test").unwrap();

        // Fire two requests concurrently on the same client (same semaphore)
        let (r1, r2) = tokio::join!(client.get("/hold", None), client.get("/hold", None));

        // Both should timeout (first from reqwest timeout, second from semaphore wait)
        let timeouts = [r1, r2]
            .iter()
            .filter(|r| matches!(r, Err(BackendError::Timeout)))
            .count();
        assert!(
            timeouts >= 1,
            "at least one request should timeout (got {timeouts} timeouts)"
        );
    }

    // T3: Cache hit reduces backend calls
    #[tokio::test]
    async fn cache_hit_reduces_backend_calls() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let counter = call_count.clone();

        let app = axum::Router::new().route(
            "/cached",
            axum::routing::get(move || {
                let counter = counter.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    "hello"
                }
            }),
        );

        let (url, _handle) = mock_server(app).await;
        let cfg = config_with_url(&url, 20, 60); // 60s cache TTL
        let client = BackendClient::new(&cfg, "test", "test").unwrap();

        let r1 = client.get("/cached", None).await;
        assert!(r1.is_ok());
        let (_, body1) = r1.unwrap();

        let r2 = client.get("/cached", None).await;
        assert!(r2.is_ok());
        let (_, body2) = r2.unwrap();

        assert_eq!(body1, body2, "both calls should return the same body");
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "backend should only be called once (second is a cache hit)"
        );
    }

    // T4: Non-2xx responses are not cached
    #[tokio::test]
    async fn non_2xx_not_cached() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let counter = call_count.clone();

        let app = axum::Router::new().route(
            "/not-found",
            axum::routing::get(move || {
                let counter = counter.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    (axum::http::StatusCode::NOT_FOUND, "nope")
                }
            }),
        );

        let (url, _handle) = mock_server(app).await;
        let cfg = config_with_url(&url, 20, 60);
        let client = BackendClient::new(&cfg, "test", "test").unwrap();

        let r1 = client.get("/not-found", None).await;
        assert!(matches!(r1, Err(BackendError::Http(_))));

        let r2 = client.get("/not-found", None).await;
        assert!(matches!(r2, Err(BackendError::Http(_))));

        assert_eq!(
            call_count.load(Ordering::SeqCst),
            2,
            "backend should be called twice (404 is not cached)"
        );
    }

    // T5 (partial): X-Request-Id propagation
    #[tokio::test]
    async fn propagates_request_id() {
        let received_id = Arc::new(tokio::sync::Mutex::new(String::new()));
        let id_ref = received_id.clone();

        let app = axum::Router::new().route(
            "/echo-rid",
            axum::routing::get(move |headers: axum::http::HeaderMap| {
                let id_ref = id_ref.clone();
                async move {
                    if let Some(rid) = headers.get("x-request-id") {
                        *id_ref.lock().await = rid.to_str().unwrap().to_owned();
                    }
                    "ok"
                }
            }),
        );

        let (url, _handle) = mock_server(app).await;
        let cfg = config_with_url(&url, 20, 0);
        let client = BackendClient::new(&cfg, "test", "test").unwrap();

        let _ = client.get("/echo-rid", Some("test-req-42")).await;

        let captured = received_id.lock().await;
        assert_eq!(*captured, "test-req-42");
    }

    // HEAD bypasses semaphore
    #[tokio::test]
    async fn head_bypasses_semaphore() {
        let app = axum::Router::new().route("/health", axum::routing::head(|| async { "" }));

        let (url, _handle) = mock_server(app).await;
        // max_concurrent = 0 means no permits available for get()
        // but head() should still work since it bypasses the semaphore
        let cfg = BackendConfig {
            url: Some(url),
            timeout_ms: 2000,
            max_concurrent: 0,
            cache_ttl_secs: 0,
            cache_capacity: 64,
        };
        // BackendClient::new creates a Semaphore(0), which would block all get() calls
        // but head() doesn't use the semaphore
        let client = BackendClient::new(&cfg, "test", "test").unwrap();
        let result = client.head("/health").await;
        assert!(result.is_ok(), "head should bypass semaphore: {result:?}");
    }
}
