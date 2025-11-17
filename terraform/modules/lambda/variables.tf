variable "environment" {
  description = "Environment name"
  type        = string
}

variable "prefix" {
  description = "Resource name prefix"
  type        = string
}

variable "app_name" {
  description = "Application name"
  type        = string
}

variable "ecr_repository_name" {
  description = "Name of the ECR repository"
  type        = string
}

variable "image_tag" {
  description = "Docker image tag for Lambda"
  type        = string
  default     = "latest"
}

variable "lambda_memory_mb" {
  description = "Lambda function memory in MB"
  type        = number
  default     = 512
}

variable "lambda_timeout_secs" {
  description = "Lambda function timeout in seconds"
  type        = number
  default     = 30
}

variable "lambda_reserved_concurrent_executions" {
  description = "Reserved concurrent executions for Lambda"
  type        = number
  default     = null
}

variable "environment_variables" {
  description = "Environment variables for Lambda function"
  type        = map(string)
  default     = {}
}

variable "dynamodb_table_arns" {
  description = "ARNs of DynamoDB tables for IAM permissions"
  type        = list(string)
  default     = []
}

variable "log_group_name" {
  description = "CloudWatch log group name for Lambda"
  type        = string
}

variable "enable_function_url" {
  description = "Enable Lambda Function URL (alternative to API Gateway)"
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}
