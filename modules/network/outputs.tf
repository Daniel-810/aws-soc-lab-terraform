output "vpc_id" {
  description = "ID of the VPC this moudle creates"
  value       = aws_vpc.this.id
}

output "subnet_ids" {
  description = "Subnet IDs keyed by <type>-<availability zone>."
  value       = { for k, v in aws_subnet.this : k => v.id }
}

output "route_table_ids" {
  description = "Route table IDs keyed by subnet type."
  value       = { for k, v in aws_route_table.this : k => v.id }
}

output "security_group_ids" {
  description = "Security group IDs keyed by tier: waf, app, suricata."
  value = {
    waf      = aws_security_group.waf.id
    app      = aws_security_group.app.id
    suricata = aws_security_group.suricata.id
  }
}
