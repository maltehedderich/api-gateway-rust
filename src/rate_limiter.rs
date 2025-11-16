use crate::config::{RateLimitPolicy, RateLimitingConfig};
use crate::error::GatewayError;
use axum::http::HeaderMap;
use redis::aio::ConnectionManager;
use redis::RedisError;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, error, warn};

/// Rate limiter that enforces request rate limits
#[derive(Clone)]
pub struct RateLimiter {
    redis: ConnectionManager,
    config: Arc<RateLimitingConfig>,
}

/// Result of a rate limit check
#[derive(Debug, Clone)]
pub struct RateLimitDecision {
    /// Whether the request is allowed
    pub allowed: bool,

    /// Current count of requests in the window
    pub current_count: u64,

    /// Maximum allowed requests
    pub limit: u64,

    /// Unix timestamp when the rate limit resets
    pub reset_at: u64,

    /// Remaining requests in the window
    pub remaining: u64,

    /// Seconds until the client can retry (only relevant when denied)
    pub retry_after_secs: u64,
}

/// Key type for rate limiting
#[derive(Debug, Clone, PartialEq)]
pub enum KeyType {
    Ip,
    User,
    Endpoint,
    UserEndpoint,
    IpEndpoint,
}

impl KeyType {
    pub fn from_string(s: &str) -> Result<Self, GatewayError> {
        match s {
            "ip" => Ok(KeyType::Ip),
            "user" => Ok(KeyType::User),
            "endpoint" => Ok(KeyType::Endpoint),
            "user_endpoint" => Ok(KeyType::UserEndpoint),
            "ip_endpoint" => Ok(KeyType::IpEndpoint),
            _ => Err(GatewayError::RateLimiting(format!(
                "Invalid key type: {}",
                s
            ))),
        }
    }
}

/// Context for rate limiting decisions
#[derive(Debug, Clone)]
pub struct RateLimitContext {
    /// Client IP address
    pub client_ip: String,

    /// Authenticated user ID (if available)
    pub user_id: Option<String>,

    /// Route identifier
    pub route_id: String,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub async fn new(config: RateLimitingConfig) -> Result<Self, GatewayError> {
        let client = redis::Client::open(config.redis_url.as_str()).map_err(|e| {
            GatewayError::RateLimiting(format!("Failed to create Redis client: {}", e))
        })?;

        let redis = ConnectionManager::new(client).await.map_err(|e| {
            GatewayError::RateLimiting(format!("Failed to connect to Redis: {}", e))
        })?;

        debug!("Rate limiter initialized with Redis connection");

        Ok(Self {
            redis,
            config: Arc::new(config),
        })
    }

    /// Check if a request is allowed based on rate limiting policy
    pub async fn check_limit(
        &self,
        context: &RateLimitContext,
        policy: &RateLimitPolicy,
    ) -> Result<RateLimitDecision, GatewayError> {
        let key = self.construct_key(context, policy)?;

        let result = match policy.algorithm.as_str() {
            "token_bucket" => {
                self.check_token_bucket(&key, policy).await
            }
            "sliding_window" => {
                self.check_sliding_window(&key, policy).await
            }
            _ => {
                return Err(GatewayError::RateLimiting(format!(
                    "Unsupported algorithm: {}",
                    policy.algorithm
                )));
            }
        };

        match result {
            Ok(decision) => {
                if decision.allowed {
                    debug!(
                        "Rate limit check passed for key: {} (remaining: {})",
                        key, decision.remaining
                    );
                } else {
                    warn!(
                        "Rate limit exceeded for key: {} (retry after: {}s)",
                        key, decision.retry_after_secs
                    );
                }
                Ok(decision)
            }
            Err(e) => {
                error!("Rate limit check failed for key: {} - {}", key, e);

                // Handle failure mode
                if self.config.failure_mode == "fail_open" {
                    warn!("Rate limiter failing open, allowing request");
                    Ok(RateLimitDecision {
                        allowed: true,
                        current_count: 0,
                        limit: policy.limit,
                        reset_at: self.current_timestamp() + policy.window_secs,
                        remaining: policy.limit,
                        retry_after_secs: 0,
                    })
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Construct a rate limiting key based on context and policy
    fn construct_key(
        &self,
        context: &RateLimitContext,
        policy: &RateLimitPolicy,
    ) -> Result<String, GatewayError> {
        let key_type = KeyType::from_string(&policy.key_type)?;

        let key = match key_type {
            KeyType::Ip => {
                format!("ratelimit:ip:{}", context.client_ip)
            }
            KeyType::User => {
                let user_id = context.user_id.as_ref().ok_or_else(|| {
                    GatewayError::RateLimiting(
                        "User ID not available for user-based rate limiting".to_string(),
                    )
                })?;
                format!("ratelimit:user:{}", user_id)
            }
            KeyType::Endpoint => {
                format!("ratelimit:endpoint:{}", context.route_id)
            }
            KeyType::UserEndpoint => {
                let user_id = context.user_id.as_ref().ok_or_else(|| {
                    GatewayError::RateLimiting(
                        "User ID not available for user-endpoint rate limiting".to_string(),
                    )
                })?;
                format!("ratelimit:user:{}:endpoint:{}", user_id, context.route_id)
            }
            KeyType::IpEndpoint => {
                format!(
                    "ratelimit:ip:{}:endpoint:{}",
                    context.client_ip, context.route_id
                )
            }
        };

        Ok(key)
    }

    /// Check rate limit using token bucket algorithm
    async fn check_token_bucket(
        &self,
        key: &str,
        policy: &RateLimitPolicy,
    ) -> Result<RateLimitDecision, GatewayError> {
        let capacity = policy.burst_capacity.unwrap_or(policy.limit);
        let refill_rate = policy.limit as f64 / policy.window_secs as f64;
        let now = self.current_timestamp();

        // Redis Lua script for atomic token bucket check
        // This script:
        // 1. Gets current tokens and last refill time
        // 2. Calculates tokens to add based on elapsed time
        // 3. Consumes one token if available
        // 4. Returns: allowed (1/0), current_tokens, reset_time
        let script = redis::Script::new(
            r"
            local key = KEYS[1]
            local capacity = tonumber(ARGV[1])
            local refill_rate = tonumber(ARGV[2])
            local now = tonumber(ARGV[3])
            local window_secs = tonumber(ARGV[4])

            -- Get current state
            local tokens = tonumber(redis.call('HGET', key, 'tokens')) or capacity
            local last_refill = tonumber(redis.call('HGET', key, 'last_refill')) or now

            -- Calculate tokens to add based on elapsed time
            local elapsed = now - last_refill
            local tokens_to_add = elapsed * refill_rate
            tokens = math.min(capacity, tokens + tokens_to_add)

            -- Try to consume one token
            local allowed = 0
            if tokens >= 1 then
                tokens = tokens - 1
                allowed = 1
            end

            -- Update state
            redis.call('HSET', key, 'tokens', tokens)
            redis.call('HSET', key, 'last_refill', now)
            redis.call('EXPIRE', key, window_secs * 2)

            -- Calculate reset time (when bucket will be full again)
            local reset_time = now + math.ceil((capacity - tokens) / refill_rate)

            return {allowed, math.floor(tokens), reset_time}
            ",
        );

        let mut conn = self.redis.clone();
        let result: Vec<u64> = script
            .key(key)
            .arg(capacity)
            .arg(refill_rate)
            .arg(now)
            .arg(policy.window_secs)
            .invoke_async(&mut conn)
            .await
            .map_err(|e: RedisError| {
                GatewayError::RateLimiting(format!("Redis script execution failed: {}", e))
            })?;

        let allowed = result[0] == 1;
        let current_tokens = result[1];
        let reset_at = result[2];

        let retry_after_secs = if allowed {
            0
        } else {
            // Calculate how long until at least one token is available
            ((1.0 / refill_rate).ceil() as u64).max(1)
        };

        Ok(RateLimitDecision {
            allowed,
            current_count: capacity.saturating_sub(current_tokens),
            limit: policy.limit,
            reset_at,
            remaining: current_tokens,
            retry_after_secs,
        })
    }

    /// Check rate limit using sliding window counter algorithm
    async fn check_sliding_window(
        &self,
        key: &str,
        policy: &RateLimitPolicy,
    ) -> Result<RateLimitDecision, GatewayError> {
        let now = self.current_timestamp();
        let window_start = now - policy.window_secs;

        // Redis Lua script for atomic sliding window check
        // This script:
        // 1. Removes old entries outside the window
        // 2. Counts requests in the current window
        // 3. Adds new request if under limit
        // 4. Returns: allowed (1/0), count, reset_time
        let script = redis::Script::new(
            r"
            local key = KEYS[1]
            local limit = tonumber(ARGV[1])
            local window_start = tonumber(ARGV[2])
            local now = tonumber(ARGV[3])
            local window_secs = tonumber(ARGV[4])

            -- Remove old entries
            redis.call('ZREMRANGEBYSCORE', key, 0, window_start)

            -- Count current requests
            local count = redis.call('ZCARD', key)

            -- Check if under limit
            local allowed = 0
            if count < limit then
                -- Add new request
                redis.call('ZADD', key, now, now)
                redis.call('EXPIRE', key, window_secs)
                count = count + 1
                allowed = 1
            end

            -- Reset time is when the window rolls over
            local reset_time = now + window_secs

            return {allowed, count, reset_time}
            ",
        );

        let mut conn = self.redis.clone();
        let result: Vec<u64> = script
            .key(key)
            .arg(policy.limit)
            .arg(window_start)
            .arg(now)
            .arg(policy.window_secs)
            .invoke_async(&mut conn)
            .await
            .map_err(|e: RedisError| {
                GatewayError::RateLimiting(format!("Redis script execution failed: {}", e))
            })?;

        let allowed = result[0] == 1;
        let count = result[1];
        let reset_at = result[2];

        let retry_after_secs = if allowed {
            0
        } else {
            // Estimate retry time based on window
            policy.window_secs / policy.limit.max(1)
        };

        Ok(RateLimitDecision {
            allowed,
            current_count: count,
            limit: policy.limit,
            reset_at,
            remaining: policy.limit.saturating_sub(count),
            retry_after_secs,
        })
    }

    /// Get current Unix timestamp in seconds
    fn current_timestamp(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

/// Add rate limit headers to response
pub fn add_rate_limit_headers(headers: &mut HeaderMap, decision: &RateLimitDecision) {
    headers.insert(
        "X-RateLimit-Limit",
        decision.limit.to_string().parse().unwrap(),
    );
    headers.insert(
        "X-RateLimit-Remaining",
        decision.remaining.to_string().parse().unwrap(),
    );
    headers.insert(
        "X-RateLimit-Reset",
        decision.reset_at.to_string().parse().unwrap(),
    );

    if !decision.allowed {
        headers.insert(
            "Retry-After",
            decision.retry_after_secs.to_string().parse().unwrap(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_type_from_string() {
        assert_eq!(
            KeyType::from_string("ip").unwrap(),
            KeyType::Ip
        );
        assert_eq!(
            KeyType::from_string("user").unwrap(),
            KeyType::User
        );
        assert_eq!(
            KeyType::from_string("endpoint").unwrap(),
            KeyType::Endpoint
        );
        assert_eq!(
            KeyType::from_string("user_endpoint").unwrap(),
            KeyType::UserEndpoint
        );
        assert_eq!(
            KeyType::from_string("ip_endpoint").unwrap(),
            KeyType::IpEndpoint
        );
        assert!(KeyType::from_string("invalid").is_err());
    }
}
