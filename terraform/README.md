# API Gateway Rust - Serverless AWS Deployment

This directory contains Terraform configuration for deploying the API Gateway Rust application as a serverless, cost-optimized AWS stack.

## Architecture Overview

```
Client
  │
  ├─► AWS API Gateway HTTP API (Entry point, TLS termination)
  │     │
  │     └─► AWS Lambda (Container with Rust gateway)
  │           │
  │           ├─► DynamoDB (Rate limits & sessions)
  │           ├─► CloudWatch Logs (Structured logging)
  │           └─► Upstream Services (Lambda Functions or external APIs)
```

### Components

- **API Gateway HTTP API**: Pay-per-request entry point (~$1/million requests)
- **Lambda Function (Container Image)**: Runs the Rust gateway with custom runtime adapter
- **DynamoDB Tables**: On-demand capacity for rate limiting and session storage
- **ECR Repository**: Stores the Lambda container image
- **CloudWatch Logs**: Centralized logging with configurable retention
- **IAM Roles**: Least-privilege permissions for Lambda execution

### Cost Optimization

- **No idle costs**: API Gateway HTTP API, Lambda, and DynamoDB on-demand are all pay-per-use
- **No VPC**: Keeps Lambda public to avoid NAT gateway costs (~$32/month)
- **Short log retention**: Default 7 days (configurable)
- **Minimal memory**: Lambda starts at 512MB (tunable)
- **No reserved capacity**: All resources scale to zero

**Estimated Monthly Cost (for low traffic):**
- 100,000 requests/month: **~$0.50 - $2.00**
- 1,000,000 requests/month: **~$3.00 - $10.00**

(Actual costs depend on Lambda execution time, DynamoDB usage, and data transfer)

## Prerequisites

### Required Tools

1. **Terraform** >= 1.5.0
   ```bash
   brew install terraform  # macOS
   # or download from https://www.terraform.io/downloads
   ```

2. **AWS CLI** >= 2.0
   ```bash
   brew install awscli  # macOS
   # or download from https://aws.amazon.com/cli/
   ```

3. **Docker** (for building Lambda container image)
   ```bash
   # Install Docker Desktop from https://www.docker.com/products/docker-desktop
   ```

### AWS Account Setup

1. **Configure AWS credentials**:
   ```bash
   aws configure
   # Enter your Access Key ID, Secret Access Key, and default region
   ```

2. **Verify AWS credentials**:
   ```bash
   aws sts get-caller-identity
   ```

3. **Ensure you have permissions** to create:
   - API Gateway
   - Lambda functions
   - DynamoDB tables
   - ECR repositories
   - IAM roles and policies
   - CloudWatch Logs

## Quick Start

### 1. Configure Variables

Create a `terraform.tfvars` file:

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars` and set required values:

```hcl
# Required
aws_region  = "us-east-1"
environment = "dev"

# JWT configuration (use AWS Secrets Manager in production!)
jwt_secret = "your-secret-key-here-min-256-bits"

# Upstream services (replace with actual Lambda URLs or APIs)
upstream_user_service_url    = "https://example.com/users"
upstream_product_service_url = "https://example.com/products"
upstream_order_service_url   = "https://example.com/orders"

# Optional: Tune resource sizes
lambda_memory_mb    = 512
lambda_timeout_secs = 30
log_retention_days  = 7
```

### 2. Initialize Terraform

```bash
cd terraform
terraform init
```

### 3. Review the Plan

```bash
terraform plan
```

This will show you all resources that will be created.

### 4. Apply the Configuration

```bash
terraform apply
```

Type `yes` when prompted to create resources.

**Note**: The Lambda function will fail to deploy initially because no container image exists yet. This is expected. We'll build and push the image in the next step.

### 5. Build and Push Docker Image

After Terraform creates the ECR repository:

```bash
# Get ECR login credentials
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin $(terraform output -raw ecr_repository_url)

# Build the Docker image (from repository root)
cd ..
docker build -t api-gateway-rust:latest -f terraform/Dockerfile .

# Tag the image
docker tag api-gateway-rust:latest $(cd terraform && terraform output -raw ecr_repository_url):latest

# Push to ECR
docker push $(cd terraform && terraform output -raw ecr_repository_url):latest

# Update Lambda function with the new image
cd terraform
aws lambda update-function-code \
  --function-name $(terraform output -raw lambda_function_name) \
  --image-uri $(terraform output -raw ecr_repository_url):latest \
  --region us-east-1
```

### 6. Test the Deployment

Get the API Gateway URL:

```bash
terraform output api_gateway_url
```

Test the health endpoint:

```bash
curl $(terraform output -raw api_gateway_url)/health/live
```

You should see:
```json
{"status": "ok"}
```

## Configuration Reference

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `aws_region` | AWS region for deployment | `us-east-1` |
| `environment` | Environment name | `dev`, `staging`, `prod` |
| `jwt_secret` | JWT secret for HS256 | Use AWS Secrets Manager in prod |

### Optional Variables

See `variables.tf` for a complete list. Key optional variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `lambda_memory_mb` | 512 | Lambda memory in MB (128-10240) |
| `lambda_timeout_secs` | 30 | Lambda timeout in seconds |
| `log_retention_days` | 7 | CloudWatch Logs retention |
| `dynamodb_on_demand` | true | Use on-demand billing for DynamoDB |
| `enable_custom_domain` | false | Enable custom domain with ACM |

### Custom Domain (Optional)

To use a custom domain like `api.example.com`:

1. **Create an ACM certificate** in `us-east-1` (required for API Gateway):
   ```bash
   aws acm request-certificate \
     --domain-name api.example.com \
     --validation-method DNS \
     --region us-east-1
   ```

2. **Validate the certificate** via DNS (follow AWS Console instructions)

3. **Enable custom domain in `terraform.tfvars`**:
   ```hcl
   enable_custom_domain     = true
   custom_domain_name       = "api.example.com"
   acm_certificate_arn      = "arn:aws:acm:us-east-1:..."
   route53_hosted_zone_id   = "Z1234567890ABC"  # Your Route53 zone ID
   ```

4. **Apply Terraform**:
   ```bash
   terraform apply
   ```

## Important Notes

### ⚠️ DynamoDB Integration Required

The current Rust code uses **Redis** for rate limiting and session storage. To fully utilize this serverless deployment, you need to:

1. **Adapt the code** to use DynamoDB instead of Redis
2. **Or** add ElastiCache Serverless Redis (adds ~$0.125/hour minimum cost)
3. **Or** deploy without rate limiting initially

**Code changes needed**:
- `src/rate_limiter.rs`: Replace Redis calls with DynamoDB SDK
- `src/auth.rs`: Replace session store Redis calls with DynamoDB SDK

See `INTEGRATION_GUIDE.md` for detailed implementation instructions.

### Upstream Services

The Rust gateway expects three upstream services:
- User Service
- Product Service
- Order Service

You can:
1. **Deploy separate Lambda functions** for each service
2. **Point to external APIs** by setting the `upstream_*_service_url` variables
3. **Modify the code** to remove these dependencies

Example Lambda function deployment for upstream services is in `examples/upstream-lambda/`.

### Security Best Practices

1. **JWT Secrets**: Use AWS Secrets Manager instead of hardcoding in `terraform.tfvars`:
   ```bash
   aws secretsmanager create-secret \
     --name api-gateway-jwt-secret \
     --secret-string "your-secret-key"
   ```

   Then reference it in Lambda environment variables using Terraform data source.

2. **IAM Permissions**: The Lambda role has least-privilege access to only required DynamoDB tables.

3. **API Gateway Throttling**: Configured with burst limit (5000) and rate limit (2000 req/sec).

4. **CloudWatch Logs**: Enable log retention to manage costs and compliance.

## Module Structure

```
terraform/
├── main.tf                      # Root module
├── variables.tf                 # Input variables
├── outputs.tf                   # Outputs
├── terraform.tfvars.example     # Example configuration
├── Dockerfile                   # Lambda container image
├── README.md                    # This file
├── INTEGRATION_GUIDE.md         # DynamoDB integration guide
└── modules/
    ├── api-gateway/             # API Gateway HTTP API
    ├── lambda/                  # Lambda function with ECR
    ├── dynamodb/                # DynamoDB tables
    ├── cloudwatch/              # CloudWatch Logs
    └── custom-domain/           # Custom domain (optional)
```

## Terraform Commands

### Initialize
```bash
terraform init
```

### Plan (Preview Changes)
```bash
terraform plan
```

### Apply (Create Resources)
```bash
terraform apply
```

### Destroy (Delete All Resources)
```bash
terraform destroy
```

### Output Values
```bash
terraform output                    # Show all outputs
terraform output api_gateway_url    # Show specific output
```

### Format Code
```bash
terraform fmt -recursive
```

### Validate Configuration
```bash
terraform validate
```

## Terraform State Management

By default, Terraform stores state locally. For production deployments, configure remote state:

### S3 Backend (Recommended)

1. **Create S3 bucket and DynamoDB table**:
   ```bash
   aws s3 mb s3://your-terraform-state-bucket --region us-east-1

   aws dynamodb create-table \
     --table-name terraform-state-locks \
     --attribute-definitions AttributeName=LockID,AttributeType=S \
     --key-schema AttributeName=LockID,KeyType=HASH \
     --provisioned-throughput ReadCapacityUnits=1,WriteCapacityUnits=1 \
     --region us-east-1
   ```

2. **Uncomment backend configuration in `main.tf`**:
   ```hcl
   backend "s3" {
     bucket         = "your-terraform-state-bucket"
     key            = "api-gateway/terraform.tfstate"
     region         = "us-east-1"
     dynamodb_table = "terraform-state-locks"
     encrypt        = true
   }
   ```

3. **Migrate state**:
   ```bash
   terraform init -migrate-state
   ```

## Troubleshooting

### Lambda Function Not Working

1. **Check Lambda logs**:
   ```bash
   aws logs tail /aws/lambda/$(terraform output -raw lambda_function_name) --follow
   ```

2. **Verify image was pushed**:
   ```bash
   aws ecr describe-images \
     --repository-name $(terraform output -raw ecr_repository_name) \
     --region us-east-1
   ```

3. **Test Lambda locally**:
   ```bash
   docker run -p 9000:8080 $(terraform output -raw ecr_repository_url):latest
   curl http://localhost:9000/health/live
   ```

### API Gateway Errors

1. **Check API Gateway logs**:
   ```bash
   aws logs tail /aws/apigateway/$(terraform output -raw lambda_function_name | sed 's/-gateway//') --follow
   ```

2. **Verify Lambda permissions**:
   ```bash
   aws lambda get-policy \
     --function-name $(terraform output -raw lambda_function_name) \
     --region us-east-1
   ```

### DynamoDB Throttling

If you see throttling errors, you may need to:
1. Switch to provisioned capacity with higher RCU/WCU
2. Or optimize query patterns to reduce DynamoDB calls

### Cost Overruns

Monitor costs:
```bash
aws ce get-cost-and-usage \
  --time-period Start=2024-01-01,End=2024-01-31 \
  --granularity MONTHLY \
  --metrics BlendedCost \
  --group-by Type=SERVICE
```

## Multi-Environment Deployments

To deploy multiple environments (dev, staging, prod):

### Option 1: Workspaces (Simple)

```bash
# Create workspace
terraform workspace new staging

# Switch workspace
terraform workspace select staging

# Apply with different tfvars
terraform apply -var-file=staging.tfvars
```

### Option 2: Separate Directories (Recommended)

```
terraform/
├── environments/
│   ├── dev/
│   │   ├── main.tf
│   │   └── terraform.tfvars
│   ├── staging/
│   │   ├── main.tf
│   │   └── terraform.tfvars
│   └── prod/
│       ├── main.tf
│       └── terraform.tfvars
└── modules/
    └── ... (shared modules)
```

## Additional Resources

- [AWS Lambda Container Images](https://docs.aws.amazon.com/lambda/latest/dg/images-create.html)
- [API Gateway HTTP API](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api.html)
- [DynamoDB On-Demand](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.ReadWriteCapacityMode.html)
- [Terraform AWS Provider](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)

## Support

For issues related to:
- **Terraform configuration**: Open an issue in this repository
- **Rust application**: See main README.md and API_GATEWAY_DESIGN.md
- **AWS services**: Refer to AWS documentation

## License

See the main repository LICENSE file.
