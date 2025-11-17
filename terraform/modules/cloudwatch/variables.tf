variable "environment" {
  description = "Environment name"
  type        = string
}

variable "prefix" {
  description = "Resource name prefix"
  type        = string
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention in days"
  type        = number
  default     = 7
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}
