variable "environment" {
  description = "Environment name"
  type        = string
}

variable "prefix" {
  description = "Resource name prefix"
  type        = string
}

variable "domain_name" {
  description = "Custom domain name (e.g., api.example.com)"
  type        = string
}

variable "certificate_arn" {
  description = "ARN of ACM certificate (must be in us-east-1 for API Gateway)"
  type        = string
}

variable "hosted_zone_id" {
  description = "Route53 hosted zone ID for DNS record creation"
  type        = string
  default     = ""
}

variable "api_gateway_id" {
  description = "API Gateway ID to map to custom domain"
  type        = string
}

variable "api_gateway_stage" {
  description = "API Gateway stage name"
  type        = string
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}
