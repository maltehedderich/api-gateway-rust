# API Gateway Rust - Serverless AWS Deployment
# Root Terraform Configuration

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Configure backend for state management
  # For production, use S3 backend:
  # backend "s3" {
  #   bucket         = "your-terraform-state-bucket"
  #   key            = "api-gateway/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "terraform-state-locks"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "api-gateway-rust"
      Environment = var.environment
      ManagedBy   = "Terraform"
      CostCenter  = var.cost_center
    }
  }
}

# Local variables
locals {
  app_name = "api-gateway-rust"
  prefix   = "${local.app_name}-${var.environment}"

  common_tags = {
    Application = local.app_name
    Environment = var.environment
  }
}

# DynamoDB tables for rate limiting and session storage
module "dynamodb" {
  source = "./modules/dynamodb"

  environment = var.environment
  prefix      = local.prefix

  # Rate limiting table configuration
  rate_limit_table_name = "${local.prefix}-rate-limits"
  rate_limit_read_capacity  = var.dynamodb_on_demand ? null : var.rate_limit_read_capacity
  rate_limit_write_capacity = var.dynamodb_on_demand ? null : var.rate_limit_write_capacity

  # Session storage table configuration
  session_table_name       = "${local.prefix}-sessions"
  session_read_capacity    = var.dynamodb_on_demand ? null : var.session_read_capacity
  session_write_capacity   = var.dynamodb_on_demand ? null : var.session_write_capacity

  # Use on-demand billing for cost optimization
  billing_mode = var.dynamodb_on_demand ? "PAY_PER_REQUEST" : "PROVISIONED"

  # Enable Point-in-Time Recovery for production
  enable_point_in_time_recovery = var.environment == "prod"

  tags = local.common_tags
}

# CloudWatch Log Groups
module "cloudwatch" {
  source = "./modules/cloudwatch"

  environment         = var.environment
  prefix              = local.prefix
  log_retention_days  = var.log_retention_days

  tags = local.common_tags
}

# Lambda function for API Gateway
module "lambda" {
  source = "./modules/lambda"

  environment         = var.environment
  prefix              = local.prefix
  app_name            = local.app_name

  # Lambda configuration
  lambda_memory_mb    = var.lambda_memory_mb
  lambda_timeout_secs = var.lambda_timeout_secs
  lambda_reserved_concurrent_executions = var.lambda_reserved_concurrent_executions

  # Container image configuration
  ecr_repository_name = "${local.prefix}-gateway"
  image_tag           = var.lambda_image_tag

  # Environment variables for the Rust gateway
  environment_variables = {
    RUST_LOG                = var.rust_log_level
    GATEWAY_PORT            = "8080"  # Lambda expects port 8080
    GATEWAY_BIND_ADDRESS    = "0.0.0.0"
    GATEWAY_REQUEST_TIMEOUT_SECS = tostring(var.gateway_request_timeout_secs)

    # JWT configuration (load from AWS Secrets Manager in production)
    GATEWAY_JWT_ALGORITHM   = var.jwt_algorithm
    GATEWAY_JWT_SECRET      = var.jwt_secret  # WARNING: Use Secrets Manager in production
    GATEWAY_JWT_ISSUER      = var.jwt_issuer
    GATEWAY_JWT_AUDIENCE    = var.jwt_audience
    GATEWAY_COOKIE_NAME     = var.jwt_cookie_name

    # DynamoDB table names (replaces Redis)
    # Note: You'll need to adapt the Rust code to use DynamoDB
    DYNAMODB_RATE_LIMIT_TABLE = module.dynamodb.rate_limit_table_name
    DYNAMODB_SESSION_TABLE    = module.dynamodb.session_table_name
    AWS_REGION_NAME           = var.aws_region

    # Upstream service URLs (other Lambda function URLs or external APIs)
    UPSTREAM_USER_SERVICE_URL    = var.upstream_user_service_url
    UPSTREAM_PRODUCT_SERVICE_URL = var.upstream_product_service_url
    UPSTREAM_ORDER_SERVICE_URL   = var.upstream_order_service_url
  }

  # DynamoDB table ARNs for IAM permissions
  dynamodb_table_arns = [
    module.dynamodb.rate_limit_table_arn,
    module.dynamodb.session_table_arn
  ]

  # CloudWatch log group
  log_group_name = module.cloudwatch.lambda_log_group_name

  tags = local.common_tags
}

# API Gateway HTTP API
module "api_gateway" {
  source = "./modules/api-gateway"

  environment = var.environment
  prefix      = local.prefix
  app_name    = local.app_name

  # Lambda integration
  lambda_function_arn         = module.lambda.lambda_function_arn
  lambda_function_invoke_arn  = module.lambda.lambda_function_invoke_arn
  lambda_function_name        = module.lambda.lambda_function_name

  # API Gateway configuration
  api_description             = "Serverless API Gateway for ${local.app_name}"
  throttle_burst_limit        = var.api_throttle_burst_limit
  throttle_rate_limit         = var.api_throttle_rate_limit

  # CORS configuration
  enable_cors                 = var.enable_cors
  cors_allow_origins          = var.cors_allow_origins
  cors_allow_methods          = var.cors_allow_methods
  cors_allow_headers          = var.cors_allow_headers

  # CloudWatch logging
  log_group_arn               = module.cloudwatch.api_gateway_log_group_arn

  tags = local.common_tags
}

# Optional: Custom domain with ACM certificate
module "custom_domain" {
  count  = var.enable_custom_domain ? 1 : 0
  source = "./modules/custom-domain"

  environment         = var.environment
  prefix              = local.prefix

  # Domain configuration
  domain_name         = var.custom_domain_name
  certificate_arn     = var.acm_certificate_arn
  hosted_zone_id      = var.route53_hosted_zone_id

  # API Gateway details for mapping
  api_gateway_id      = module.api_gateway.api_gateway_id
  api_gateway_stage   = module.api_gateway.stage_name

  tags = local.common_tags
}
