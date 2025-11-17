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

variable "api_description" {
  description = "API Gateway description"
  type        = string
  default     = "API Gateway HTTP API"
}

variable "lambda_function_name" {
  description = "Name of the Lambda function to integrate"
  type        = string
}

variable "lambda_function_arn" {
  description = "ARN of the Lambda function"
  type        = string
}

variable "lambda_function_invoke_arn" {
  description = "Invoke ARN of the Lambda function"
  type        = string
}

variable "throttle_burst_limit" {
  description = "API Gateway throttle burst limit"
  type        = number
  default     = 5000
}

variable "throttle_rate_limit" {
  description = "API Gateway throttle rate limit (requests per second)"
  type        = number
  default     = 2000
}

variable "enable_cors" {
  description = "Enable CORS configuration"
  type        = bool
  default     = true
}

variable "cors_allow_origins" {
  description = "CORS allowed origins"
  type        = list(string)
  default     = ["*"]
}

variable "cors_allow_methods" {
  description = "CORS allowed methods"
  type        = list(string)
  default     = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
}

variable "cors_allow_headers" {
  description = "CORS allowed headers"
  type        = list(string)
  default     = ["Content-Type", "Authorization"]
}

variable "log_group_arn" {
  description = "ARN of CloudWatch log group for access logs"
  type        = string
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}
