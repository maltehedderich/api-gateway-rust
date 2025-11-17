# CloudWatch Log Groups for Lambda and API Gateway

# Lambda Function Log Group
resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${var.prefix}-gateway"
  retention_in_days = var.log_retention_days

  tags = merge(
    var.tags,
    {
      Name    = "${var.prefix}-lambda-logs"
      Purpose = "Lambda function logs"
    }
  )
}

# API Gateway Access Log Group
resource "aws_cloudwatch_log_group" "api_gateway" {
  name              = "/aws/apigateway/${var.prefix}-api"
  retention_in_days = var.log_retention_days

  tags = merge(
    var.tags,
    {
      Name    = "${var.prefix}-api-gateway-logs"
      Purpose = "API Gateway access logs"
    }
  )
}
