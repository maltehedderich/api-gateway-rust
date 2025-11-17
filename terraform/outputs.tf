# Outputs for API Gateway Rust Serverless Deployment

# ========================================
# API Gateway Outputs
# ========================================

output "api_gateway_url" {
  description = "API Gateway HTTP API endpoint URL"
  value       = module.api_gateway.api_gateway_url
}

output "api_gateway_id" {
  description = "API Gateway HTTP API ID"
  value       = module.api_gateway.api_gateway_id
}

output "api_gateway_arn" {
  description = "API Gateway HTTP API ARN"
  value       = module.api_gateway.api_gateway_arn
}

output "api_gateway_stage" {
  description = "API Gateway stage name"
  value       = module.api_gateway.stage_name
}

# ========================================
# Lambda Outputs
# ========================================

output "lambda_function_name" {
  description = "Lambda function name"
  value       = module.lambda.lambda_function_name
}

output "lambda_function_arn" {
  description = "Lambda function ARN"
  value       = module.lambda.lambda_function_arn
}

output "lambda_role_arn" {
  description = "Lambda execution role ARN"
  value       = module.lambda.lambda_role_arn
}

output "ecr_repository_url" {
  description = "ECR repository URL for Lambda container image"
  value       = module.lambda.ecr_repository_url
}

output "ecr_repository_name" {
  description = "ECR repository name"
  value       = module.lambda.ecr_repository_name
}

# ========================================
# DynamoDB Outputs
# ========================================

output "rate_limit_table_name" {
  description = "DynamoDB rate limit table name"
  value       = module.dynamodb.rate_limit_table_name
}

output "rate_limit_table_arn" {
  description = "DynamoDB rate limit table ARN"
  value       = module.dynamodb.rate_limit_table_arn
}

output "session_table_name" {
  description = "DynamoDB session table name"
  value       = module.dynamodb.session_table_name
}

output "session_table_arn" {
  description = "DynamoDB session table ARN"
  value       = module.dynamodb.session_table_arn
}

# ========================================
# CloudWatch Outputs
# ========================================

output "lambda_log_group_name" {
  description = "Lambda CloudWatch log group name"
  value       = module.cloudwatch.lambda_log_group_name
}

output "api_gateway_log_group_name" {
  description = "API Gateway CloudWatch log group name"
  value       = module.cloudwatch.api_gateway_log_group_name
}

# ========================================
# Custom Domain Outputs (if enabled)
# ========================================

output "custom_domain_name" {
  description = "Custom domain name (if enabled)"
  value       = var.enable_custom_domain ? module.custom_domain[0].domain_name : null
}

output "custom_domain_regional_endpoint" {
  description = "Custom domain regional endpoint (if enabled)"
  value       = var.enable_custom_domain ? module.custom_domain[0].regional_domain_name : null
}

# ========================================
# Deployment Instructions
# ========================================

output "deployment_instructions" {
  description = "Next steps for deployment"
  value = <<-EOT

    ========================================
    API Gateway Deployment Complete!
    ========================================

    API Endpoint: ${module.api_gateway.api_gateway_url}

    Next Steps:

    1. Build and push Docker image to ECR:

       aws ecr get-login-password --region ${var.aws_region} | docker login --username AWS --password-stdin ${module.lambda.ecr_repository_url}

       docker build -t ${module.lambda.ecr_repository_name}:${var.lambda_image_tag} -f terraform/Dockerfile .

       docker tag ${module.lambda.ecr_repository_name}:${var.lambda_image_tag} ${module.lambda.ecr_repository_url}:${var.lambda_image_tag}

       docker push ${module.lambda.ecr_repository_url}:${var.lambda_image_tag}

    2. Update Lambda function with new image:

       aws lambda update-function-code \
         --function-name ${module.lambda.lambda_function_name} \
         --image-uri ${module.lambda.ecr_repository_url}:${var.lambda_image_tag} \
         --region ${var.aws_region}

    3. Test the API:

       curl ${module.api_gateway.api_gateway_url}/health/live

    4. Configure upstream services:
       - Update variables for upstream_user_service_url, upstream_product_service_url, upstream_order_service_url
       - Or create separate Lambda functions for these services

    5. Configure JWT authentication:
       - Set jwt_secret via AWS Secrets Manager (recommended)
       - Or set via terraform variable (not recommended for production)

    6. IMPORTANT - DynamoDB Integration:
       - The Rust code currently uses Redis for rate limiting and sessions
       - You need to adapt src/rate_limiter.rs and src/auth.rs to use DynamoDB
       - See terraform/INTEGRATION_GUIDE.md for implementation details

    DynamoDB Tables Created:
    - Rate Limits: ${module.dynamodb.rate_limit_table_name}
    - Sessions: ${module.dynamodb.session_table_name}

    CloudWatch Logs:
    - Lambda: ${module.cloudwatch.lambda_log_group_name}
    - API Gateway: ${module.cloudwatch.api_gateway_log_group_name}

    ========================================
  EOT
}
