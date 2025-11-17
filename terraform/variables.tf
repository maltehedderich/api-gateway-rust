# Variables for API Gateway Rust Serverless Deployment

# ========================================
# General Configuration
# ========================================

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "cost_center" {
  description = "Cost center tag for billing"
  type        = string
  default     = "engineering"
}

# ========================================
# Lambda Configuration
# ========================================

variable "lambda_memory_mb" {
  description = "Lambda function memory in MB (128-10240)"
  type        = number
  default     = 512  # Start small for cost optimization

  validation {
    condition     = var.lambda_memory_mb >= 128 && var.lambda_memory_mb <= 10240
    error_message = "Lambda memory must be between 128 and 10240 MB."
  }
}

variable "lambda_timeout_secs" {
  description = "Lambda function timeout in seconds (max 900)"
  type        = number
  default     = 30

  validation {
    condition     = var.lambda_timeout_secs >= 1 && var.lambda_timeout_secs <= 900
    error_message = "Lambda timeout must be between 1 and 900 seconds."
  }
}

variable "lambda_reserved_concurrent_executions" {
  description = "Reserved concurrent executions for Lambda (null = no limit)"
  type        = number
  default     = null  # No limit for cost optimization
}

variable "lambda_image_tag" {
  description = "Docker image tag for Lambda function"
  type        = string
  default     = "latest"
}

# ========================================
# API Gateway Configuration
# ========================================

variable "api_throttle_burst_limit" {
  description = "API Gateway throttle burst limit (requests)"
  type        = number
  default     = 5000
}

variable "api_throttle_rate_limit" {
  description = "API Gateway throttle rate limit (requests per second)"
  type        = number
  default     = 2000
}

variable "enable_cors" {
  description = "Enable CORS on API Gateway"
  type        = bool
  default     = true
}

variable "cors_allow_origins" {
  description = "CORS allowed origins"
  type        = list(string)
  default     = ["*"]
}

variable "cors_allow_methods" {
  description = "CORS allowed HTTP methods"
  type        = list(string)
  default     = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
}

variable "cors_allow_headers" {
  description = "CORS allowed headers"
  type        = list(string)
  default     = ["Content-Type", "Authorization", "X-Amz-Date", "X-Api-Key", "X-Correlation-ID"]
}

# ========================================
# DynamoDB Configuration
# ========================================

variable "dynamodb_on_demand" {
  description = "Use DynamoDB on-demand billing (true = PAY_PER_REQUEST, false = PROVISIONED)"
  type        = bool
  default     = true  # Cost-optimized for low/variable traffic
}

variable "rate_limit_read_capacity" {
  description = "DynamoDB rate limit table read capacity units (ignored if on-demand)"
  type        = number
  default     = 5
}

variable "rate_limit_write_capacity" {
  description = "DynamoDB rate limit table write capacity units (ignored if on-demand)"
  type        = number
  default     = 5
}

variable "session_read_capacity" {
  description = "DynamoDB session table read capacity units (ignored if on-demand)"
  type        = number
  default     = 5
}

variable "session_write_capacity" {
  description = "DynamoDB session table write capacity units (ignored if on-demand)"
  type        = number
  default     = 5
}

# ========================================
# Logging Configuration
# ========================================

variable "log_retention_days" {
  description = "CloudWatch Logs retention in days"
  type        = number
  default     = 7  # Cost-optimized, increase for prod

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.log_retention_days)
    error_message = "Log retention must be a valid CloudWatch Logs retention period."
  }
}

variable "rust_log_level" {
  description = "Rust log level (error, warn, info, debug, trace)"
  type        = string
  default     = "info"
}

# ========================================
# Gateway Application Configuration
# ========================================

variable "gateway_request_timeout_secs" {
  description = "Gateway request timeout in seconds"
  type        = number
  default     = 30
}

# JWT Authentication
variable "jwt_algorithm" {
  description = "JWT algorithm (HS256, RS256, ES256)"
  type        = string
  default     = "HS256"

  validation {
    condition     = contains(["HS256", "RS256", "ES256"], var.jwt_algorithm)
    error_message = "JWT algorithm must be HS256, RS256, or ES256."
  }
}

variable "jwt_secret" {
  description = "JWT secret key for HS256 (WARNING: Use AWS Secrets Manager in production)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "jwt_issuer" {
  description = "JWT issuer claim for validation"
  type        = string
  default     = ""
}

variable "jwt_audience" {
  description = "JWT audience claim for validation"
  type        = string
  default     = "api-gateway"
}

variable "jwt_cookie_name" {
  description = "Cookie name for session token"
  type        = string
  default     = "session_token"
}

# Upstream Services
variable "upstream_user_service_url" {
  description = "URL for user service (Lambda URL or external API)"
  type        = string
  default     = "https://example.com/users"  # Replace with actual service
}

variable "upstream_product_service_url" {
  description = "URL for product service (Lambda URL or external API)"
  type        = string
  default     = "https://example.com/products"  # Replace with actual service
}

variable "upstream_order_service_url" {
  description = "URL for order service (Lambda URL or external API)"
  type        = string
  default     = "https://example.com/orders"  # Replace with actual service
}

# ========================================
# Custom Domain (Optional)
# ========================================

variable "enable_custom_domain" {
  description = "Enable custom domain with ACM certificate"
  type        = bool
  default     = false
}

variable "custom_domain_name" {
  description = "Custom domain name (e.g., api.example.com)"
  type        = string
  default     = ""
}

variable "acm_certificate_arn" {
  description = "ARN of ACM certificate for custom domain (must be in us-east-1 for API Gateway)"
  type        = string
  default     = ""
}

variable "route53_hosted_zone_id" {
  description = "Route53 hosted zone ID for DNS record creation"
  type        = string
  default     = ""
}
