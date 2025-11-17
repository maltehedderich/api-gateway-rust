output "domain_name" {
  description = "Custom domain name"
  value       = aws_apigatewayv2_domain_name.main.domain_name
}

output "regional_domain_name" {
  description = "Regional domain name for Route53 alias"
  value       = aws_apigatewayv2_domain_name.main.domain_name_configuration[0].target_domain_name
}

output "regional_hosted_zone_id" {
  description = "Regional hosted zone ID for Route53 alias"
  value       = aws_apigatewayv2_domain_name.main.domain_name_configuration[0].hosted_zone_id
}
