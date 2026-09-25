locals {
  endpoints = {
    for s in tolist(aws_networkfirewall_firewall.this.firewall_status[0].sync_states) :
    s.availability_zone => tolist(s.attachment)[0].endpoint_id
  }
}

output "endpoint_ids" {
  description = "Firewall endpoint id per availability zone. Routes must target the endpoint in their own zone: sending traffic across zones breaks path symmetry and adds transfer cost."
  value       = local.endpoints
}

output "alert_log_group" {
  description = "Log group the firewall writes rule matches to. Phase 10 reads it for the unified view."
  value       = aws_cloudwatch_log_group.alert.name
}

output "flow_log_group" {
  description = "Log group recording connections that passed inspection (F12)."
  value       = aws_cloudwatch_log_group.flow.name
}
