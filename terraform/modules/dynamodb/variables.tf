variable "environment" {
  description = "Environment name"
  type        = string
}

variable "prefix" {
  description = "Resource name prefix"
  type        = string
}

variable "rate_limit_table_name" {
  description = "Name of the rate limit DynamoDB table"
  type        = string
}

variable "session_table_name" {
  description = "Name of the session DynamoDB table"
  type        = string
}

variable "billing_mode" {
  description = "DynamoDB billing mode (PROVISIONED or PAY_PER_REQUEST)"
  type        = string
  default     = "PAY_PER_REQUEST"

  validation {
    condition     = contains(["PROVISIONED", "PAY_PER_REQUEST"], var.billing_mode)
    error_message = "Billing mode must be PROVISIONED or PAY_PER_REQUEST."
  }
}

variable "rate_limit_read_capacity" {
  description = "Read capacity units for rate limit table (PROVISIONED mode only)"
  type        = number
  default     = null
}

variable "rate_limit_write_capacity" {
  description = "Write capacity units for rate limit table (PROVISIONED mode only)"
  type        = number
  default     = null
}

variable "session_read_capacity" {
  description = "Read capacity units for session table (PROVISIONED mode only)"
  type        = number
  default     = null
}

variable "session_write_capacity" {
  description = "Write capacity units for session table (PROVISIONED mode only)"
  type        = number
  default     = null
}

variable "enable_point_in_time_recovery" {
  description = "Enable point-in-time recovery for tables"
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}
