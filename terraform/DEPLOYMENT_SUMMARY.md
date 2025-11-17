# Serverless AWS Deployment - Summary

## Architecture Overview

This Terraform configuration deploys the API Gateway Rust application as a fully serverless, cost-optimized AWS stack.

### Target Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                           End Users / Clients                        │
└───────────────────────────────┬─────────────────────────────────────┘
                                │ HTTPS
                                ▼
        ┌───────────────────────────────────────────┐
        │     AWS API Gateway HTTP API              │
        │  • Pay-per-request ($1/million)           │
        │  • Managed TLS termination                │
        │  • Built-in throttling & CORS             │
        └──────────────────┬────────────────────────┘
                           │ AWS_PROXY integration
                           ▼
        ┌───────────────────────────────────────────┐
        │     AWS Lambda (Container Image)          │
        │  • Runs Rust API Gateway binary           │
        │  • 512MB RAM, 30s timeout (configurable)  │
        │  • Lambda Runtime Adapter                 │
        │  • Pay only for execution time            │
        └──────┬────────────────────┬────────────────┘
               │                    │
               │                    │ Read/Write
               │                    ▼
               │    ┌───────────────────────────────┐
               │    │    DynamoDB Tables            │
               │    │  • rate-limits (on-demand)    │
               │    │  • sessions (on-demand)       │
               │    │  • Auto-scaling, TTL enabled  │
               │    └───────────────────────────────┘
               │
               │ Forward requests
               ▼
        ┌───────────────────────────────────────────┐
        │     Upstream Services                     │
        │  • Lambda Functions (user, product,       │
        │    order services)                        │
        │  • Or external APIs                       │
        └───────────────────────────────────────────┘
```

### Observability Stack

```
All components ──► CloudWatch Logs ──► CloudWatch Insights
                                    ──► Third-party logging (optional)
                                    ──► Metrics & Alarms
```

## Components Deployed

### Core Infrastructure

1. **API Gateway HTTP API**
   - Serverless HTTP entry point
   - Regional endpoint
   - Automatic stage deployment
   - JSON access logging
   - Throttling: 5000 burst, 2000 req/sec

2. **Lambda Function (Container)**
   - ECR repository for image storage
   - Container-based deployment
   - IAM role with DynamoDB permissions
   - Structured JSON logging
   - Automatic log group creation

3. **DynamoDB Tables**
   - `rate-limits`: Hash key = limiter_key, Range key = window_start
   - `sessions`: Hash key = session_id, GSI on user_id
   - On-demand capacity (zero idle cost)
   - TTL enabled for automatic cleanup
   - Server-side encryption enabled
   - Point-in-time recovery (optional, for prod)

4. **CloudWatch Logs**
   - Lambda function logs: `/aws/lambda/{prefix}-gateway`
   - API Gateway logs: `/aws/apigateway/{prefix}-api`
   - Configurable retention (default: 7 days)

### Optional Components

5. **Custom Domain (Optional)**
   - API Gateway custom domain name
   - ACM certificate integration (must be in us-east-1)
   - Route53 DNS record (A record with alias)

## Cost Optimization Features

### Pay-Per-Use Pricing Model

| Component | Pricing Model | Free Tier | Estimated Cost (100K req/month) |
|-----------|---------------|-----------|----------------------------------|
| API Gateway HTTP API | $1/million requests | 1M requests/month (12 months) | $0.10 |
| Lambda (512MB, 500ms avg) | $0.20/1M requests + $0.0000166667/GB-sec | 1M requests, 400K GB-sec/month | $1.20 |
| DynamoDB (on-demand) | $1.25/million writes, $0.25/million reads | 25GB storage, 25 WCU, 25 RCU | $0.30 |
| CloudWatch Logs | $0.50/GB ingested, $0.03/GB stored | 5GB ingestion, 5GB storage | $0.20 |
| ECR | $0.10/GB-month | 500MB storage (12 months) | $0.05 |
| **Total** | | | **~$1.85/month** |

For 1M requests/month: **~$8-12/month**

### No Always-On Costs

- **No VPC**: Avoids NAT gateway (~$32/month)
- **No ALB/NLB**: No load balancer costs
- **No EC2/ECS**: No compute instances
- **No RDS**: No database instances
- **No ElastiCache**: No Redis instances (if using DynamoDB)

### Scalability

- **Lambda**: Automatically scales to 1000 concurrent executions (default limit)
- **API Gateway**: Handles 10,000 req/sec default (can request increase)
- **DynamoDB**: Automatically scales on-demand (no throttling)
- All components scale to zero when idle

## Directory Structure

```
terraform/
├── main.tf                      # Root configuration
├── variables.tf                 # Input variables
├── outputs.tf                   # Stack outputs
├── terraform.tfvars.example     # Example configuration
├── Dockerfile                   # Lambda container image
├── README.md                    # Setup instructions
├── INTEGRATION_GUIDE.md         # DynamoDB integration guide
├── DEPLOYMENT_SUMMARY.md        # This file
└── modules/
    ├── api-gateway/             # HTTP API module
    │   ├── main.tf
    │   ├── variables.tf
    │   └── outputs.tf
    ├── lambda/                  # Lambda function module
    │   ├── main.tf              # ECR + Lambda + IAM
    │   ├── variables.tf
    │   └── outputs.tf
    ├── dynamodb/                # DynamoDB tables module
    │   ├── main.tf              # Rate limits + sessions
    │   ├── variables.tf
    │   └── outputs.tf
    ├── cloudwatch/              # CloudWatch Logs module
    │   ├── main.tf
    │   ├── variables.tf
    │   └── outputs.tf
    └── custom-domain/           # Custom domain module (optional)
        ├── main.tf              # Domain + ACM + Route53
        ├── variables.tf
        └── outputs.tf
```

## Key Terraform Files

### Root Module (`main.tf`)

- Provider configuration (AWS)
- Module orchestration
- Local variables
- Default tags

**Key Features**:
- Parameterized environment (dev/staging/prod)
- Reusable module structure
- Tagged resources for cost tracking

### Variables (`variables.tf`)

**Required Variables**:
- `aws_region`: AWS region
- `environment`: Environment name
- `jwt_secret`: JWT secret key (use Secrets Manager in prod!)

**Optional Variables** (with sensible defaults):
- Lambda configuration: memory, timeout
- API Gateway: throttling limits, CORS
- DynamoDB: on-demand vs provisioned
- Logging: retention, log level
- Custom domain: domain name, certificate ARN

### Outputs (`outputs.tf`)

**Exported Values**:
- `api_gateway_url`: Public API endpoint
- `ecr_repository_url`: Docker registry URL
- `lambda_function_name`: Lambda function name
- `dynamodb_table_names`: Table names for rate limits and sessions
- `deployment_instructions`: Step-by-step deployment guide

## Deployment Workflow

### Step 1: Prerequisites

```bash
# Install tools
brew install terraform awscli docker

# Configure AWS credentials
aws configure

# Verify access
aws sts get-caller-identity
```

### Step 2: Terraform Configuration

```bash
cd terraform

# Create configuration file
cp terraform.tfvars.example terraform.tfvars

# Edit terraform.tfvars with your values
vim terraform.tfvars
```

### Step 3: Terraform Deployment

```bash
# Initialize Terraform
terraform init

# Review plan
terraform plan

# Deploy infrastructure
terraform apply
```

**Note**: Lambda will initially fail (no image). This is expected.

### Step 4: Build and Deploy Container

```bash
# Get ECR repository URL
ECR_URL=$(terraform output -raw ecr_repository_url)

# Authenticate Docker to ECR
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin $ECR_URL

# Build Docker image (from repo root)
cd ..
docker build -t api-gateway-rust:latest -f terraform/Dockerfile .

# Tag and push to ECR
docker tag api-gateway-rust:latest $ECR_URL:latest
docker push $ECR_URL:latest

# Update Lambda function
cd terraform
aws lambda update-function-code \
  --function-name $(terraform output -raw lambda_function_name) \
  --image-uri $ECR_URL:latest \
  --region us-east-1
```

### Step 5: Test Deployment

```bash
# Get API Gateway URL
API_URL=$(terraform output -raw api_gateway_url)

# Test health endpoint
curl $API_URL/health/live

# Expected response:
# {"status": "ok"}

# View Lambda logs
aws logs tail /aws/lambda/$(terraform output -raw lambda_function_name) --follow
```

## Required Code Adaptations

### ⚠️ DynamoDB Integration

The Rust code currently uses **Redis** for:
- Rate limiting state storage
- Session storage (opaque tokens)

**To fully utilize this serverless deployment**, you must:

1. **Replace Redis with DynamoDB** (recommended)
   - See `INTEGRATION_GUIDE.md` for detailed instructions
   - Modify `src/rate_limiter.rs` and `src/auth.rs`
   - Add `aws-sdk-dynamodb` dependency

2. **Or use ElastiCache Serverless Redis** (adds ~$90/month)
   - Requires additional Terraform resources
   - No code changes needed
   - Less cost-optimized

3. **Or disable rate limiting** (testing only)
   - Remove rate limiting dependency
   - Not recommended for production

### Upstream Services

Configure upstream service URLs in `terraform.tfvars`:

```hcl
upstream_user_service_url    = "https://your-lambda-url.amazonaws.com"
upstream_product_service_url = "https://your-lambda-url.amazonaws.com"
upstream_order_service_url   = "https://your-lambda-url.amazonaws.com"
```

Options:
1. Deploy separate Lambda functions for each service
2. Point to existing external APIs
3. Modify code to remove these dependencies

## Multi-Environment Setup

### Using Terraform Workspaces

```bash
# Create workspaces
terraform workspace new dev
terraform workspace new staging
terraform workspace new prod

# Switch workspace
terraform workspace select prod

# Deploy with environment-specific vars
terraform apply -var-file=prod.tfvars
```

### Using Separate Directories (Recommended)

```
terraform/
├── environments/
│   ├── dev/
│   │   ├── main.tf → ../../main.tf (symlink)
│   │   └── terraform.tfvars
│   ├── staging/
│   │   ├── main.tf → ../../main.tf (symlink)
│   │   └── terraform.tfvars
│   └── prod/
│       ├── main.tf → ../../main.tf (symlink)
│       └── terraform.tfvars
└── modules/ (shared)
```

## Security Best Practices

1. **JWT Secrets**: Use AWS Secrets Manager
   ```bash
   aws secretsmanager create-secret \
     --name /api-gateway/prod/jwt-secret \
     --secret-string "your-secret-key"
   ```

2. **IAM Permissions**: Least privilege (already configured)

3. **TLS**: API Gateway handles TLS termination automatically

4. **VPC** (optional): For enhanced security, place Lambda in VPC
   - Requires NAT gateway (adds cost)
   - Increases cold start time

5. **Logging**: Enable CloudWatch Logs with retention

6. **API Throttling**: Configure based on expected traffic

## Monitoring and Observability

### CloudWatch Metrics

Monitor these key metrics:

- **API Gateway**: Request count, latency, 4XX/5XX errors
- **Lambda**: Invocations, duration, errors, throttles, concurrent executions
- **DynamoDB**: Consumed read/write capacity, throttled requests, latency

### CloudWatch Alarms (Recommended)

```hcl
# Example alarm for Lambda errors
resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  alarm_name          = "${var.prefix}-lambda-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 10
  alarm_description   = "Lambda function errors"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    FunctionName = module.lambda.lambda_function_name
  }
}
```

### Logs Insights Queries

```sql
-- Find slow requests
fields @timestamp, @message
| filter @message like /latency_ms/
| parse @message /"latency_ms":(?<latency>\d+)/
| filter latency > 1000
| sort @timestamp desc

-- Find errors
fields @timestamp, @message
| filter @message like /ERROR/
| sort @timestamp desc
```

## Cost Management

### Monitoring Costs

```bash
# Get cost by service
aws ce get-cost-and-usage \
  --time-period Start=2024-01-01,End=2024-01-31 \
  --granularity MONTHLY \
  --metrics BlendedCost \
  --group-by Type=SERVICE
```

### Cost Optimization Tips

1. **Right-size Lambda**: Start at 512MB, monitor, and adjust
2. **Tune log retention**: 7 days for dev, 30-90 days for prod
3. **Use DynamoDB on-demand**: Better for variable/low traffic
4. **Enable DynamoDB TTL**: Auto-delete old records
5. **Optimize Lambda cold starts**: Use container image layers
6. **Monitor unused resources**: Clean up test deployments

### Budget Alerts

```hcl
resource "aws_budgets_budget" "monthly" {
  name              = "${var.prefix}-monthly-budget"
  budget_type       = "COST"
  limit_amount      = "50"
  limit_unit        = "USD"
  time_period_start = "2024-01-01_00:00"
  time_unit         = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = ["alerts@example.com"]
  }
}
```

## Troubleshooting

See `README.md` for detailed troubleshooting steps.

**Common Issues**:
- Lambda container image not found → Build and push image first
- DynamoDB throttling → Switch to provisioned capacity or increase on-demand limits
- Cold starts → Increase Lambda memory or use provisioned concurrency (adds cost)
- High costs → Review CloudWatch metrics to identify expensive resources

## Next Steps

1. **Adapt code for DynamoDB**: See `INTEGRATION_GUIDE.md`
2. **Configure JWT secrets**: Use AWS Secrets Manager
3. **Set up CI/CD**: Automate Docker image builds and Lambda updates
4. **Enable monitoring**: CloudWatch alarms and dashboards
5. **Load testing**: Validate performance under expected traffic
6. **Production hardening**: Custom domain, WAF, backup policies

## References

- **Terraform Modules**: `terraform/modules/`
- **Setup Guide**: `terraform/README.md`
- **DynamoDB Guide**: `terraform/INTEGRATION_GUIDE.md`
- **API Gateway Design**: `API_GATEWAY_DESIGN.md`
- **Rust README**: `README.md`

---

**Deployed Stack:**
- Region: Configurable (default: us-east-1)
- Cost: ~$2-10/month for typical low-traffic workloads
- Scalability: Automatic, up to AWS account limits
- Availability: Multi-AZ by default (API Gateway, Lambda, DynamoDB)
