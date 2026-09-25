output "flow_log_group" {
  description = "Log group recording accepted and rejected traffic across the VPC"
  value       = aws_cloudwatch_log_group.flow.name
}

output "dashboard_name" {
  description = "CloudWatch dashboard gathering the layers on one screen"
  value       = aws_cloudwatch_dashboard.this.dashboard_name
}
