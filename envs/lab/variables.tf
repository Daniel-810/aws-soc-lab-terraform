# Off for the first apply: bring the firewall up, confirm Session Manager and
# the WAF still answer, then turn this on (ADR-015). Applying the firewall and
# the route change together would leave no way to tell a policy fault from a
# routing fault, and a fault in either can cut off management access.
variable "route_through_firewall" {
  description = "Route the waf and nat subnets through the managed firewall endpoint"
  type        = bool
  default     = false
}
