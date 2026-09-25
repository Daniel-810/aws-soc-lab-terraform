output "instance_id" {
  description = "ID of the inspection instance. Used to open a session and to read its logs."
  value       = aws_instance.this.id
}

output "eni_id" {
  description = "Network interface the waf and nat subnets route through when inspection is enabled"
  value       = aws_instance.this.primary_network_interface_id
}

output "public_ip" {
  description = "Address the instance's own calls out leave from. Not a service address: clients reach the WAF."
  value       = aws_instance.this.public_ip
}

output "log_group" {
  description = "Log group reserved for the engine's events. Shipping to it starts in Phase 10."
  value       = aws_cloudwatch_log_group.this.name
}
