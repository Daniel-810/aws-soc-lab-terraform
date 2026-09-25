# Which inspection approach to deploy. Routing through it is a separate
# switch below, applied only after the chosen layer is up (ADR-024, ADR-026).
variable "firewall_mode" {
  description = "Inspection approach to deploy: managed (approach A) or oss (approach B, Suricata on EC2)"
  type        = string
  default     = "managed"

  validation {
    condition     = contains(["managed", "oss"], var.firewall_mode)
    error_message = "firewall_mode must be managed or oss."
  }
}

# Off for the first apply: bring the firewall up, confirm Session Manager and
# the WAF still answer, then turn this on (ADR-015). Applying the firewall and
# the route change together would leave no way to tell a policy fault from a
# routing fault, and a fault in either can cut off management access.
variable "route_through_firewall" {
  description = "Route the waf and nat subnets through the deployed inspection layer"
  type        = bool
  default     = false
}
