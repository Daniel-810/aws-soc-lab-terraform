output "instance_id" {
  description = "ID of the application instance. Used to open a session and to verify the deployment."
  value       = aws_instance.app.id
}

# The instance has no public address (SR-03), so this is the only way to reach
# it. Phase 7 points the WAF tier at this address as its proxy target.
output "private_ip" {
  description = "Private address of the application instance"
  value       = aws_instance.app.private_ip
}

output "log_group_name" {
  description = "Log group the application writes to. The instance role is scoped to this group alone (SR-06)."
  value       = aws_cloudwatch_log_group.this.name
}
