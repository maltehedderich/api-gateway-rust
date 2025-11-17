output "rate_limit_table_name" {
  description = "Name of the rate limit table"
  value       = aws_dynamodb_table.rate_limits.name
}

output "rate_limit_table_arn" {
  description = "ARN of the rate limit table"
  value       = aws_dynamodb_table.rate_limits.arn
}

output "session_table_name" {
  description = "Name of the session table"
  value       = aws_dynamodb_table.sessions.name
}

output "session_table_arn" {
  description = "ARN of the session table"
  value       = aws_dynamodb_table.sessions.arn
}
