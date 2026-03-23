//! Per-IP rate limiter for the Cathode REST API.
//!
//! Uses a sliding fixed-window (token bucket) algorithm backed by `DashMap`
//! for lock-free concurrent access. Default policy: 100 requests per 60-second
//! window per IP address.
//!
//! Security fix — Signed-off-by: Claude Opus 4.6
//! - CRITICAL: X-Forwarded-For header is no longer trusted for rate-limit keying.
//!   The real TCP peer address (ConnectInfo<SocketAddr>) is always used instead,
//!   preventing trivial rate-limit bypass via header spoofing.
//! - HIGH: The DashMap that backs the rate limiter is now bounded by a periodic
//!   background cleanup task spawned inside `RateLimiter::new`.  Previously the
//!   map grew without limit — one entry per unique source IP — which allowed an
//!   attacker with a large IP pool to exhaust heap memory by sending a single
//!   request from each address and never triggering a window reset.

use axum::{
    extract::{ConnectInfo, State},
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::interval;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the rate limiter.
#[derive(Debug, Clone)]
pub struct RateLimiterConfig {
    /// Maximum number of requests allowed within the window.
    pub max_requests: u64,
    /// Duration of the sliding window.
    pub window: Duration,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            max_requests: 100,
            window: Duration::from_secs(60),
        }
    }
}

// ---------------------------------------------------------------------------
// RateLimiter
// ---------------------------------------------------------------------------

/// Tracks request state for a single IP address.
#[derive(Debug, Clone)]
struct IpBucket {
    /// Number of tokens (requests) remaining in the current window.
    tokens: u64,
    /// When the current window started.
    window_start: Instant,
}

/// A concurrent, per-IP rate limiter that can be shared via `Arc`.
///
/// Each IP address gets its own token bucket. When all tokens are consumed
/// the IP is rate-limited until the window resets.
/// Inner state shared across clones.
#[derive(Debug)]
struct RateLimiterInner {
    config: RateLimiterConfig,
    buckets: DashMap<String, IpBucket>,
}

/// A concurrent, per-IP rate limiter. Cloneable (internally Arc'd) so it
/// can be used directly as axum `State`.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    inner: Arc<RateLimiterInner>,
}

impl RateLimiter {
    /// Create a new rate limiter **without** the background cleanup task.
    ///
    /// Use this in non-async contexts (tests, CLI). Call [`cleanup`] manually
    /// to evict expired entries.
    pub fn new_without_cleanup(config: RateLimiterConfig) -> Self {
        let inner = Arc::new(RateLimiterInner {
            config,
            buckets: DashMap::new(),
        });
        Self { inner }
    }

    /// Create a new rate limiter with the given configuration.
    ///
    /// Spawns a background Tokio task that calls [`cleanup`] once per window
    /// to evict expired entries from the DashMap.  This bounds memory growth
    /// to at most O(unique IPs seen within one window) rather than O(all IPs
    /// ever seen).
    ///
    /// The task holds only a weak reference via the inner `Arc`; when the
    /// last `RateLimiter` clone is dropped the task exits on the next tick.
    // Security fix — Signed-off-by: Claude Opus 4.6
    pub fn new(config: RateLimiterConfig) -> Self {
        let limiter = Self::new_without_cleanup(config);

        // Spawn periodic cleanup to bound DashMap memory growth.
        let cleanup_inner = Arc::clone(&limiter.inner);
        let cleanup_interval = limiter.inner.config.window;
        tokio::spawn(async move {
            let mut ticker = interval(cleanup_interval);
            ticker.tick().await; // consume immediate first tick
            loop {
                ticker.tick().await;
                if Arc::strong_count(&cleanup_inner) == 1 {
                    break;
                }
                let now = Instant::now();
                cleanup_inner
                    .buckets
                    .retain(|_ip, bucket| now.duration_since(bucket.window_start) < cleanup_inner.config.window);
            }
        });

        limiter
    }

    /// Create a rate limiter with default settings (100 req / 60 s).
    pub fn default_shared() -> Arc<Self> {
        Arc::new(Self::new(RateLimiterConfig::default()))
    }

    /// Return the current configuration.
    pub fn config(&self) -> &RateLimiterConfig {
        &self.inner.config
    }

    /// How many requests remain for the given IP in the current window.
    pub fn remaining(&self, ip: &str) -> u64 {
        let now = Instant::now();
        match self.inner.buckets.get(ip) {
            Some(entry) => {
                if now.duration_since(entry.window_start) >= self.inner.config.window {
                    self.inner.config.max_requests
                } else {
                    entry.tokens
                }
            }
            None => self.inner.config.max_requests,
        }
    }

    /// Remove stale entries whose windows have expired.
    pub fn cleanup(&self) {
        let now = Instant::now();
        self.inner
            .buckets
            .retain(|_ip, bucket| now.duration_since(bucket.window_start) < self.inner.config.window);
    }
}

// ---------------------------------------------------------------------------
// Public check function
// ---------------------------------------------------------------------------

/// Check whether a request from `ip` is allowed under the rate limit.
///
/// Returns `true` if the request is permitted, `false` if it should be
/// rejected (HTTP 429).
pub fn check_rate_limit(limiter: &RateLimiter, ip: &str) -> bool {
    let now = Instant::now();

    let mut entry = limiter
        .inner
        .buckets
        .entry(ip.to_string())
        .or_insert_with(|| IpBucket {
            tokens: limiter.inner.config.max_requests,
            window_start: now,
        });

    let bucket = entry.value_mut();

    // If the window has elapsed, reset the bucket.
    if now.duration_since(bucket.window_start) >= limiter.inner.config.window {
        bucket.tokens = limiter.inner.config.max_requests;
        bucket.window_start = now;
    }

    if bucket.tokens > 0 {
        bucket.tokens -= 1;
        true
    } else {
        false
    }
}

// ---------------------------------------------------------------------------
// Axum middleware
// ---------------------------------------------------------------------------

/// Axum middleware that enforces per-IP rate limiting.
///
/// # Security
/// The client IP is extracted **exclusively** from the real TCP socket address
/// via `ConnectInfo<SocketAddr>`, which is injected by axum when the server is
/// started with `into_make_service_with_connect_info`. The `X-Forwarded-For`
/// and `X-Real-IP` headers are deliberately ignored because they are trivially
/// spoofed by any client, allowing an attacker to bypass per-IP rate limits
/// entirely by cycling header values.
///
/// Returns `429 Too Many Requests` when the rate limit is exceeded.
pub async fn rate_limit_middleware(
    State(limiter): State<RateLimiter>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    // Use the real peer IP from the TCP connection. Never trust forwarded headers.
    let ip = peer.ip().to_string();

    if check_rate_limit(&limiter, &ip) {
        next.run(request).await
    } else {
        (
            StatusCode::TOO_MANY_REQUESTS,
            "Rate limit exceeded. Try again later.",
        )
            .into_response()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    /// Helper: build a limiter with custom limits (no tokio runtime needed).
    fn test_limiter(max_requests: u64, window: Duration) -> RateLimiter {
        RateLimiter::new_without_cleanup(RateLimiterConfig {
            max_requests,
            window,
        })
    }

    // 1. Single request allowed
    #[test]
    fn single_request_allowed() {
        let limiter = test_limiter(100, Duration::from_secs(60));
        assert!(check_rate_limit(&limiter, "192.168.1.1"));
        assert_eq!(limiter.remaining("192.168.1.1"), 99);
    }

    // 2. Burst within limit allowed
    #[test]
    fn burst_within_limit_allowed() {
        let limiter = test_limiter(10, Duration::from_secs(60));
        for i in 0..10 {
            assert!(
                check_rate_limit(&limiter, "10.0.0.1"),
                "request {} should be allowed",
                i + 1
            );
        }
        assert_eq!(limiter.remaining("10.0.0.1"), 0);
    }

    // 3. Exceeding limit rejected
    #[test]
    fn exceeding_limit_rejected() {
        let limiter = test_limiter(5, Duration::from_secs(60));
        for _ in 0..5 {
            assert!(check_rate_limit(&limiter, "10.0.0.2"));
        }
        // 6th and 7th requests must be rejected.
        assert!(!check_rate_limit(&limiter, "10.0.0.2"));
        assert!(!check_rate_limit(&limiter, "10.0.0.2"));
        assert_eq!(limiter.remaining("10.0.0.2"), 0);
    }

    // 4. Different IPs tracked independently
    #[test]
    fn different_ips_tracked_independently() {
        let limiter = test_limiter(2, Duration::from_secs(60));

        // Exhaust IP-A.
        assert!(check_rate_limit(&limiter, "ip-a"));
        assert!(check_rate_limit(&limiter, "ip-a"));
        assert!(!check_rate_limit(&limiter, "ip-a"));

        // IP-B must still have its full quota.
        assert!(check_rate_limit(&limiter, "ip-b"));
        assert!(check_rate_limit(&limiter, "ip-b"));
        assert!(!check_rate_limit(&limiter, "ip-b"));
    }

    // 5. Window reset after time passes
    #[test]
    fn window_reset_after_time_passes() {
        let limiter = test_limiter(2, Duration::from_millis(200));

        assert!(check_rate_limit(&limiter, "10.0.0.3"));
        assert!(check_rate_limit(&limiter, "10.0.0.3"));
        assert!(!check_rate_limit(&limiter, "10.0.0.3"));

        // Wait for the window to expire.
        thread::sleep(Duration::from_millis(250));

        // Tokens should be fully replenished.
        assert!(check_rate_limit(&limiter, "10.0.0.3"));
        assert!(check_rate_limit(&limiter, "10.0.0.3"));
        assert!(!check_rate_limit(&limiter, "10.0.0.3"));
    }

    // 6. Cleanup removes stale entries
    #[test]
    fn cleanup_removes_stale_entries() {
        let limiter = test_limiter(5, Duration::from_millis(100));

        check_rate_limit(&limiter, "stale-ip");
        assert_eq!(limiter.inner.buckets.len(), 1);

        thread::sleep(Duration::from_millis(150));
        limiter.cleanup();
        assert_eq!(limiter.inner.buckets.len(), 0);
    }

    // 7. Clone sharing works across threads
    #[test]
    fn shared_clone_works() {
        let limiter = RateLimiter::new_without_cleanup(RateLimiterConfig {
            max_requests: 3,
            window: Duration::from_secs(60),
        });

        let l1 = limiter.clone();
        let l2 = limiter.clone();

        let h1 = thread::spawn(move || check_rate_limit(&l1, "shared-ip"));
        let h2 = thread::spawn(move || check_rate_limit(&l2, "shared-ip"));

        assert!(h1.join().unwrap());
        assert!(h2.join().unwrap());
    }

    // 8. Default config values
    #[test]
    fn default_config_values() {
        let config = RateLimiterConfig::default();
        assert_eq!(config.max_requests, 100);
        assert_eq!(config.window, Duration::from_secs(60));
    }
}
