variable "project" {
  description = "Name prefix applied to all resources and tags"
  type        = string
  default     = "soc-lab"
}

# The inspection subnet for approach B. Its route to the internet gateway
# carries both the traffic this instance forwards and its own calls out.
variable "subnet_id" {
  description = "Subnet the inspection instance is placed in"
  type        = string
}

variable "security_group_id" {
  description = "Security group attached to the inspection instance's interface"
  type        = string
}

# Suricata holds its rules and flow table in memory from startup; 1 GiB
# leaves little room beside the OS and the agent (ADR-027).
variable "instance_type" {
  description = "EC2 instance type for the inspection host"
  type        = string
  default     = "t3.small"
}

# Same value the managed rule group receives, set here through the engine's
# configuration instead of a rule group variable.
variable "home_net" {
  description = "Address range the rules treat as internal"
  type        = string

  validation {
    condition     = can(cidrnetmask(var.home_net))
    error_message = "home_net must be a CIDR block, not a single address."
  }
}

# The shared rule file, passed in by the root so both approaches load the
# same source (ADR-022).
variable "rules" {
  description = "Suricata rules the engine enforces, in the shared file's readable form"
  type        = string
}

# NFR-06 caps retention at 14 days. CloudWatch accepts only a fixed set of
# values and rejects anything else at apply time, so the set is checked here
# to fail during plan instead.
variable "log_retention_days" {
  description = "Days CloudWatch Logs keeps the inspection log group"
  type        = number
  default     = 14

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90], var.log_retention_days)
    error_message = "log_retention_days must be one of the retention periods CloudWatch accepts."
  }
}

# Same image as the WAF: Suricata comes from the Ubuntu archive (ADR-006),
# and the release date is pinned for the same reasons (SR-25, NFR-03).
variable "ami_name_pattern" {
  description = "Name filter selecting the base AMI. Must resolve to an amd64 image to match the instance type."
  type        = string
  default     = "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-20260904"
}
