# Custom Domain for API Gateway with ACM Certificate

# API Gateway Custom Domain
resource "aws_apigatewayv2_domain_name" "main" {
  domain_name = var.domain_name

  domain_name_configuration {
    certificate_arn = var.certificate_arn
    endpoint_type   = "REGIONAL"
    security_policy = "TLS_1_2"
  }

  tags = merge(
    var.tags,
    {
      Name = var.domain_name
    }
  )
}

# API Gateway Domain Name Mapping
resource "aws_apigatewayv2_api_mapping" "main" {
  api_id      = var.api_gateway_id
  domain_name = aws_apigatewayv2_domain_name.main.id
  stage       = var.api_gateway_stage
}

# Route53 DNS Record (A record with alias)
resource "aws_route53_record" "main" {
  count   = var.hosted_zone_id != "" ? 1 : 0
  zone_id = var.hosted_zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = aws_apigatewayv2_domain_name.main.domain_name_configuration[0].target_domain_name
    zone_id                = aws_apigatewayv2_domain_name.main.domain_name_configuration[0].hosted_zone_id
    evaluate_target_health = false
  }
}
