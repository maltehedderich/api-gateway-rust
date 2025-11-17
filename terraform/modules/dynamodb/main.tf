# DynamoDB Tables for Rate Limiting and Session Storage

# Rate Limiting Table
resource "aws_dynamodb_table" "rate_limits" {
  name           = var.rate_limit_table_name
  billing_mode   = var.billing_mode
  hash_key       = "limiter_key"
  range_key      = "window_start"

  # On-demand or provisioned capacity
  read_capacity  = var.billing_mode == "PROVISIONED" ? var.rate_limit_read_capacity : null
  write_capacity = var.billing_mode == "PROVISIONED" ? var.rate_limit_write_capacity : null

  # Primary key
  attribute {
    name = "limiter_key"
    type = "S"  # String: e.g., "ip:192.168.1.1" or "user:user123:endpoint:orders"
  }

  attribute {
    name = "window_start"
    type = "N"  # Number: Unix timestamp of window start
  }

  # TTL for automatic cleanup of old rate limit records
  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  # Point-in-time recovery for production
  point_in_time_recovery {
    enabled = var.enable_point_in_time_recovery
  }

  # Server-side encryption
  server_side_encryption {
    enabled = true
  }

  tags = merge(
    var.tags,
    {
      Name        = var.rate_limit_table_name
      Purpose     = "Rate limiting state storage"
      TableType   = "rate-limits"
    }
  )
}

# Session Storage Table (for opaque tokens)
resource "aws_dynamodb_table" "sessions" {
  name           = var.session_table_name
  billing_mode   = var.billing_mode
  hash_key       = "session_id"

  # On-demand or provisioned capacity
  read_capacity  = var.billing_mode == "PROVISIONED" ? var.session_read_capacity : null
  write_capacity = var.billing_mode == "PROVISIONED" ? var.session_write_capacity : null

  # Primary key
  attribute {
    name = "session_id"
    type = "S"  # String: Session token value
  }

  # GSI for user ID lookups (optional)
  attribute {
    name = "user_id"
    type = "S"
  }

  global_secondary_index {
    name            = "UserIdIndex"
    hash_key        = "user_id"
    projection_type = "ALL"
    read_capacity   = var.billing_mode == "PROVISIONED" ? var.session_read_capacity : null
    write_capacity  = var.billing_mode == "PROVISIONED" ? var.session_write_capacity : null
  }

  # TTL for automatic cleanup of expired sessions
  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  # Point-in-time recovery for production
  point_in_time_recovery {
    enabled = var.enable_point_in_time_recovery
  }

  # Server-side encryption
  server_side_encryption {
    enabled = true
  }

  tags = merge(
    var.tags,
    {
      Name        = var.session_table_name
      Purpose     = "Session storage for authentication"
      TableType   = "sessions"
    }
  )
}
