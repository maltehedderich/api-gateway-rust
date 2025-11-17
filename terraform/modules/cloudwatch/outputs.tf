output "lambda_log_group_name" {
  description = "Name of the Lambda log group"
  value       = aws_cloudwatch_log_group.lambda.name
}

output "lambda_log_group_arn" {
  description = "ARN of the Lambda log group"
  value       = aws_cloudwatch_log_group.lambda.arn
}

output "api_gateway_log_group_name" {
  description = "Name of the API Gateway log group"
  value       = aws_cloudwatch_log_group.api_gateway.name
}

output "api_gateway_log_group_arn" {
  description = "ARN of the API Gateway log group"
  value       = aws_cloudwatch_log_group.api_gateway.arn
}
