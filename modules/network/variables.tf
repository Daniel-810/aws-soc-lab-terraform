variable "project" {
  description = "Name prefix applied to all resources and tags"
  type        = string
  default     = "soc-lab"
}

# Must not overlap with peering or VPN targets, and cannot be changed
# after creation. See ADR-010.
variable "vpc_cidr" {
  description = "CIDR block for the VPC. Each availability zone takes a /20 from it."
  type        = string
  default     = "10.20.0.0/16"
}

# Default of 1 follows NFR-05: availability redundancy is not required,
# but the code must scale by changing this value alone.
variable "az_count" {
  description = "Number of availability zones to deploy into"
  type        = number
  default     = 1

  validation {
    condition     = var.az_count >= 1 && var.az_count <= 3
    error_message = "az_count must be between 1 and 3."
  }
}

# The target behind the WAF is deliberately vulnerable, so the boundary is
# opened to named sources only rather than the whole internet (ADR-019).
# No default: the caller has to decide who may reach it.
variable "waf_ingress_cidrs" {
  description = "IPv4 CIDRs allowed to reach the WAF on 80 and 443"
  type        = list(string)

  validation {
    condition     = length(var.waf_ingress_cidrs) > 0 && alltrue([for c in var.waf_ingress_cidrs : can(cidrhost(c, 0))])
    error_message = "waf_ingress_cidrs must hold at least one valid IPv4 CIDR."
  }
}
