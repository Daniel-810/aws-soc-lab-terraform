output "vpc_id" {
  value = module.network.vpc_id
}

output "subnet_ids" {
  value = module.network.subnet_ids
}

output "instance_id" {
  description = "ID of the application instance. Used to open a session and to verify the deployment."
  value       = module.web.instance_id
}

output "waf_instance_id" {
  description = "ID of the WAF instance"
  value       = module.waf.instance_id
}

output "waf_public_ip" {
  description = "Public address the WAF answers on"
  value       = module.waf.public_ip
}

output "firewall_endpoint_ids" {
  description = "Managed firewall endpoint id per availability zone (approach A), null otherwise"
  value       = one(module.firewall_managed[*].endpoint_ids)
}

output "suricata_instance_id" {
  description = "Inspection instance id (approach B), null otherwise. Used to read its logs."
  value       = one(module.firewall_oss[*].instance_id)
}
