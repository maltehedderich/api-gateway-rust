# Lambda Function with Container Image for API Gateway

# ECR Repository for Lambda Container Image
resource "aws_ecr_repository" "lambda" {
  name                 = var.ecr_repository_name
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = merge(
    var.tags,
    {
      Name    = var.ecr_repository_name
      Purpose = "Lambda container image storage"
    }
  )
}

# ECR Lifecycle Policy to keep only recent images
resource "aws_ecr_lifecycle_policy" "lambda" {
  repository = aws_ecr_repository.lambda.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last 10 images"
        selection = {
          tagStatus     = "any"
          countType     = "imageCountMoreThan"
          countNumber   = 10
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}

# IAM Role for Lambda Execution
resource "aws_iam_role" "lambda" {
  name = "${var.prefix}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(
    var.tags,
    {
      Name = "${var.prefix}-lambda-role"
    }
  )
}

# Attach AWS Lambda basic execution policy
resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# IAM Policy for DynamoDB Access
resource "aws_iam_role_policy" "dynamodb_access" {
  name = "${var.prefix}-dynamodb-access"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem",
          "dynamodb:Query",
          "dynamodb:Scan",
          "dynamodb:BatchGetItem",
          "dynamodb:BatchWriteItem"
        ]
        Resource = concat(
          var.dynamodb_table_arns,
          [for arn in var.dynamodb_table_arns : "${arn}/index/*"]
        )
      }
    ]
  })
}

# Lambda Function
resource "aws_lambda_function" "gateway" {
  function_name = "${var.prefix}-gateway"
  role          = aws_iam_role.lambda.arn

  # Container image configuration
  package_type = "Image"
  image_uri    = "${aws_ecr_repository.lambda.repository_url}:${var.image_tag}"

  # Resource configuration
  memory_size                    = var.lambda_memory_mb
  timeout                        = var.lambda_timeout_secs
  reserved_concurrent_executions = var.lambda_reserved_concurrent_executions

  # Environment variables
  environment {
    variables = var.environment_variables
  }

  # CloudWatch Logs configuration
  logging_config {
    log_format = "JSON"
    log_group  = var.log_group_name
  }

  # Ensure image is pushed before function creation
  lifecycle {
    ignore_changes = [image_uri]  # Allow manual image updates
  }

  tags = merge(
    var.tags,
    {
      Name = "${var.prefix}-gateway"
    }
  )
}

# Lambda Function URL (alternative to API Gateway for simple use cases)
resource "aws_lambda_function_url" "gateway" {
  count              = var.enable_function_url ? 1 : 0
  function_name      = aws_lambda_function.gateway.function_name
  authorization_type = "NONE"  # Public access; add auth if needed

  cors {
    allow_credentials = true
    allow_origins     = ["*"]
    allow_methods     = ["*"]
    allow_headers     = ["*"]
    max_age           = 86400
  }
}
