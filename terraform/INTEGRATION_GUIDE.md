# DynamoDB Integration Guide

This guide explains how to adapt the API Gateway Rust code to use **DynamoDB** instead of **Redis** for rate limiting and session storage.

## Background

The current implementation uses Redis for:
1. **Rate Limiting State**: Storing request counts per key (IP, user, endpoint)
2. **Session Storage**: Storing session data for opaque token authentication

For a fully serverless AWS deployment, we need to replace Redis with DynamoDB.

## Architecture Changes

### Before (Redis)
```
Lambda → Redis (rate limits & sessions)
```

### After (DynamoDB)
```
Lambda → DynamoDB Tables:
           ├─ rate-limits table
           └─ sessions table
```

## DynamoDB Tables

Terraform creates two DynamoDB tables:

### 1. Rate Limits Table

**Table Name**: `{prefix}-rate-limits`

**Schema**:
- **Partition Key**: `limiter_key` (String) - e.g., `"ip:192.168.1.1"` or `"user:user123:endpoint:orders"`
- **Sort Key**: `window_start` (Number) - Unix timestamp of rate limit window start
- **TTL Attribute**: `expires_at` (Number) - Auto-delete old records

**Attributes**:
```rust
{
  "limiter_key": "ip:192.168.1.1",
  "window_start": 1704067200,  // Unix timestamp
  "request_count": 42,
  "last_updated": 1704067242,
  "expires_at": 1704070800     // TTL for auto-cleanup
}
```

### 2. Sessions Table

**Table Name**: `{prefix}-sessions`

**Schema**:
- **Partition Key**: `session_id` (String) - Session token value
- **GSI**: `UserIdIndex` on `user_id` for lookups by user
- **TTL Attribute**: `expires_at` (Number) - Auto-delete expired sessions

**Attributes**:
```rust
{
  "session_id": "abc123xyz789",
  "user_id": "user123",
  "username": "john_doe",
  "roles": ["user", "admin"],
  "permissions": ["orders:create", "users:read"],
  "created_at": 1704067200,
  "expires_at": 1704153600
}
```

## Code Changes Required

### 1. Add DynamoDB SDK Dependency

Update `Cargo.toml`:

```toml
[dependencies]
# Existing dependencies...

# AWS SDK for DynamoDB
aws-config = "1.1"
aws-sdk-dynamodb = "1.13"
```

### 2. Create DynamoDB Client Module

Create `src/dynamodb_client.rs`:

```rust
use aws_config::BehaviorVersion;
use aws_sdk_dynamodb::Client;
use std::sync::Arc;
use tokio::sync::OnceCell;

static DYNAMODB_CLIENT: OnceCell<Arc<Client>> = OnceCell::const_new();

pub async fn get_client() -> Arc<Client> {
    DYNAMODB_CLIENT
        .get_or_init(|| async {
            let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
            Arc::new(Client::new(&config))
        })
        .await
        .clone()
}
```

### 3. Update Rate Limiter

Modify `src/rate_limiter.rs`:

#### Current Redis Implementation:
```rust
// Uses redis::Client and redis::aio::ConnectionManager
pub async fn check_rate_limit(&self, key: &str) -> Result<bool, RateLimitError> {
    let mut conn = self.redis_pool.get().await?;
    let count: u64 = conn.incr(key, 1).await?;
    // ...
}
```

#### New DynamoDB Implementation:

```rust
use aws_sdk_dynamodb::types::AttributeValue;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct RateLimiter {
    dynamodb_client: Arc<Client>,
    table_name: String,
    // ... existing fields
}

impl RateLimiter {
    pub async fn check_rate_limit(&self, key: &str, limit: u64, window_secs: u64) -> Result<bool, RateLimitError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let window_start = (now / window_secs) * window_secs;
        let expires_at = window_start + (window_secs * 2); // Keep for 2 windows

        // Try to increment counter atomically
        let response = self.dynamodb_client
            .update_item()
            .table_name(&self.table_name)
            .key("limiter_key", AttributeValue::S(key.to_string()))
            .key("window_start", AttributeValue::N(window_start.to_string()))
            .update_expression("ADD request_count :inc SET last_updated = :now, expires_at = :expires")
            .expression_attribute_values(":inc", AttributeValue::N("1".to_string()))
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .expression_attribute_values(":expires", AttributeValue::N(expires_at.to_string()))
            .expression_attribute_values(":limit", AttributeValue::N(limit.to_string()))
            .condition_expression("attribute_not_exists(request_count) OR request_count < :limit")
            .return_values(aws_sdk_dynamodb::types::ReturnValue::AllNew)
            .send()
            .await;

        match response {
            Ok(output) => {
                // Rate limit not exceeded
                if let Some(attrs) = output.attributes {
                    let count = attrs.get("request_count")
                        .and_then(|v| v.as_n().ok())
                        .and_then(|n| n.parse::<u64>().ok())
                        .unwrap_or(0);

                    tracing::info!(
                        limiter_key = %key,
                        request_count = count,
                        limit = limit,
                        "Rate limit check passed"
                    );
                }
                Ok(true)
            }
            Err(e) => {
                // ConditionalCheckFailedException means limit exceeded
                if e.to_string().contains("ConditionalCheckFailedException") {
                    tracing::warn!(
                        limiter_key = %key,
                        limit = limit,
                        "Rate limit exceeded"
                    );
                    Ok(false)
                } else {
                    Err(RateLimitError::StorageError(e.to_string()))
                }
            }
        }
    }

    pub async fn get_current_count(&self, key: &str, window_secs: u64) -> Result<u64, RateLimitError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let window_start = (now / window_secs) * window_secs;

        let response = self.dynamodb_client
            .get_item()
            .table_name(&self.table_name)
            .key("limiter_key", AttributeValue::S(key.to_string()))
            .key("window_start", AttributeValue::N(window_start.to_string()))
            .send()
            .await
            .map_err(|e| RateLimitError::StorageError(e.to_string()))?;

        let count = response.item
            .and_then(|item| item.get("request_count").cloned())
            .and_then(|v| v.as_n().ok())
            .and_then(|n| n.parse::<u64>().ok())
            .unwrap_or(0);

        Ok(count)
    }
}
```

### 4. Update Session Storage

Modify `src/auth.rs`:

#### Current Redis Implementation:
```rust
pub async fn get_session(&self, token: &str) -> Result<Option<SessionData>, AuthError> {
    let mut conn = self.redis_pool.get().await?;
    let data: Option<String> = conn.get(format!("session:{}", token)).await?;
    // ...
}
```

#### New DynamoDB Implementation:

```rust
use aws_sdk_dynamodb::types::AttributeValue;
use std::collections::HashMap;

pub struct SessionStore {
    dynamodb_client: Arc<Client>,
    table_name: String,
}

impl SessionStore {
    pub async fn get_session(&self, token: &str) -> Result<Option<SessionData>, AuthError> {
        let response = self.dynamodb_client
            .get_item()
            .table_name(&self.table_name)
            .key("session_id", AttributeValue::S(token.to_string()))
            .send()
            .await
            .map_err(|e| AuthError::StorageError(e.to_string()))?;

        if let Some(item) = response.item {
            let session = SessionData {
                user_id: item.get("user_id")
                    .and_then(|v| v.as_s().ok())
                    .cloned()
                    .ok_or(AuthError::InvalidSession)?,
                username: item.get("username")
                    .and_then(|v| v.as_s().ok())
                    .cloned(),
                roles: item.get("roles")
                    .and_then(|v| v.as_l().ok())
                    .map(|list| {
                        list.iter()
                            .filter_map(|v| v.as_s().ok())
                            .cloned()
                            .collect()
                    })
                    .unwrap_or_default(),
                permissions: item.get("permissions")
                    .and_then(|v| v.as_l().ok())
                    .map(|list| {
                        list.iter()
                            .filter_map(|v| v.as_s().ok())
                            .cloned()
                            .collect()
                    })
                    .unwrap_or_default(),
                created_at: item.get("created_at")
                    .and_then(|v| v.as_n().ok())
                    .and_then(|n| n.parse::<u64>().ok())
                    .unwrap_or(0),
                expires_at: item.get("expires_at")
                    .and_then(|v| v.as_n().ok())
                    .and_then(|n| n.parse::<u64>().ok())
                    .unwrap_or(0),
            };

            // Check expiration
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            if session.expires_at < now {
                return Ok(None);
            }

            Ok(Some(session))
        } else {
            Ok(None)
        }
    }

    pub async fn put_session(&self, token: &str, session: &SessionData) -> Result<(), AuthError> {
        let mut item = HashMap::new();
        item.insert("session_id".to_string(), AttributeValue::S(token.to_string()));
        item.insert("user_id".to_string(), AttributeValue::S(session.user_id.clone()));

        if let Some(ref username) = session.username {
            item.insert("username".to_string(), AttributeValue::S(username.clone()));
        }

        item.insert(
            "roles".to_string(),
            AttributeValue::L(
                session.roles.iter()
                    .map(|r| AttributeValue::S(r.clone()))
                    .collect()
            )
        );

        item.insert(
            "permissions".to_string(),
            AttributeValue::L(
                session.permissions.iter()
                    .map(|p| AttributeValue::S(p.clone()))
                    .collect()
            )
        );

        item.insert("created_at".to_string(), AttributeValue::N(session.created_at.to_string()));
        item.insert("expires_at".to_string(), AttributeValue::N(session.expires_at.to_string()));

        self.dynamodb_client
            .put_item()
            .table_name(&self.table_name)
            .set_item(Some(item))
            .send()
            .await
            .map_err(|e| AuthError::StorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn delete_session(&self, token: &str) -> Result<(), AuthError> {
        self.dynamodb_client
            .delete_item()
            .table_name(&self.table_name)
            .key("session_id", AttributeValue::S(token.to_string()))
            .send()
            .await
            .map_err(|e| AuthError::StorageError(e.to_string()))?;

        Ok(())
    }
}
```

### 5. Update Configuration

Modify `src/config.rs` to accept DynamoDB table names:

```rust
pub struct RateLimitingConfig {
    // Remove: pub redis_url: String,
    // Add:
    pub dynamodb_table_name: String,
    pub aws_region: String,
    // ... existing fields
}

pub struct SessionStoreConfig {
    // Remove: pub redis_url: String,
    // Add:
    pub dynamodb_table_name: String,
    pub aws_region: String,
    // ... existing fields
}
```

### 6. Initialize Clients in Main

Update `src/main.rs`:

```rust
use crate::dynamodb_client;

#[tokio::main]
async fn main() {
    // ... existing initialization

    // Initialize DynamoDB client
    let dynamodb_client = dynamodb_client::get_client().await;

    // Pass to rate limiter and session store
    let rate_limiter = RateLimiter::new(
        dynamodb_client.clone(),
        std::env::var("DYNAMODB_RATE_LIMIT_TABLE").expect("DYNAMODB_RATE_LIMIT_TABLE must be set"),
    );

    let session_store = SessionStore::new(
        dynamodb_client.clone(),
        std::env::var("DYNAMODB_SESSION_TABLE").expect("DYNAMODB_SESSION_TABLE must be set"),
    );

    // ... rest of initialization
}
```

## Environment Variables

The Terraform configuration sets these environment variables automatically:

- `DYNAMODB_RATE_LIMIT_TABLE`: Name of the rate limits table
- `DYNAMODB_SESSION_TABLE`: Name of the sessions table
- `AWS_REGION_NAME`: AWS region for DynamoDB client

## Testing DynamoDB Integration

### 1. Test Locally with DynamoDB Local

```bash
# Run DynamoDB Local
docker run -p 8000:8000 amazon/dynamodb-local

# Create tables
aws dynamodb create-table \
  --table-name test-rate-limits \
  --attribute-definitions AttributeName=limiter_key,AttributeType=S AttributeName=window_start,AttributeType=N \
  --key-schema AttributeName=limiter_key,KeyType=HASH AttributeName=window_start,KeyType=RANGE \
  --billing-mode PAY_PER_REQUEST \
  --endpoint-url http://localhost:8000

# Set environment variables
export DYNAMODB_RATE_LIMIT_TABLE=test-rate-limits
export DYNAMODB_SESSION_TABLE=test-sessions
export AWS_ENDPOINT_URL=http://localhost:8000

# Run your application
cargo run
```

### 2. Test with AWS DynamoDB

```bash
# Deploy Terraform first
cd terraform
terraform apply

# Get table names
export DYNAMODB_RATE_LIMIT_TABLE=$(terraform output -raw rate_limit_table_name)
export DYNAMODB_SESSION_TABLE=$(terraform output -raw session_table_name)
export AWS_REGION=$(terraform output -raw aws_region)

# Run locally (will use AWS credentials)
cargo run
```

### 3. Unit Tests

Add unit tests with mocked DynamoDB client:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiter_allows_within_limit() {
        // Mock DynamoDB client
        // Test rate limiting logic
    }

    #[tokio::test]
    async fn test_rate_limiter_denies_over_limit() {
        // Test limit enforcement
    }
}
```

## Performance Considerations

### DynamoDB vs Redis

| Aspect | Redis | DynamoDB |
|--------|-------|----------|
| Latency | <1ms | 1-5ms |
| Cost (low traffic) | Always-on (~$20/month min) | Pay-per-request (~$0-$2/month) |
| Scaling | Manual/cluster | Automatic on-demand |
| Serverless | No (needs ElastiCache) | Yes |

### Optimization Tips

1. **Use Batch Operations**: For multiple reads/writes, use `batch_get_item` and `batch_write_item`
2. **Enable DAX** (optional): DynamoDB Accelerator for microsecond latency (adds cost)
3. **Use Consistent Reads sparingly**: Eventually consistent reads are half the cost
4. **Leverage TTL**: Automatically delete expired records (already configured)
5. **Monitor Performance**: Use CloudWatch metrics to track latency and throttling

## Migration Strategy

If you have existing Redis data:

1. **Dual-Write Period**: Write to both Redis and DynamoDB
2. **Backfill**: Export Redis data and import to DynamoDB
3. **Switch Reads**: Start reading from DynamoDB
4. **Decommission Redis**: Remove Redis dependency

For new deployments, skip Redis entirely and use DynamoDB from the start.

## Alternative: Keep Redis with ElastiCache Serverless

If code changes are not feasible, you can add ElastiCache Serverless Redis:

**Pros**:
- No code changes required
- Lower latency (~1ms)
- Compatible with existing implementation

**Cons**:
- Adds cost (~$0.125/hour = ~$90/month minimum)
- Not truly serverless (always-on)

**Terraform Addition**:
```hcl
resource "aws_elasticache_serverless_cache" "redis" {
  engine = "redis"
  name   = "${var.prefix}-redis"

  cache_usage_limits {
    data_storage {
      maximum = 1  # GB
      unit    = "GB"
    }
    ecpu_per_second {
      maximum = 5000
    }
  }
}
```

## Conclusion

Migrating from Redis to DynamoDB requires code changes but provides a truly serverless, cost-optimized solution. The changes are localized to `rate_limiter.rs` and `auth.rs`, making the migration straightforward.

For production deployments, DynamoDB is recommended for its serverless nature and pay-per-use pricing model.
