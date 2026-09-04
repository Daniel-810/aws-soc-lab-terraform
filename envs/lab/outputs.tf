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
