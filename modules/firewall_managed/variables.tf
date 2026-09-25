variable "project" {
  description = "Name prefix applied to all resources and tags"
  type        = string
  default     = "soc-lab"
}

variable "vpc_id" {
  description = "VPC the firewall endpoints are created in"
  type        = string
}

# Inspection subnets, one per availability zone. They hold only firewall
# endpoints: no other workload is placed there, and their route table sends
# traffic on to the internet gateway once inspection is done.
variable "subnet_ids" {
  description = "Subnets the firewall places an endpoint in, one per availability zone"
  type        = list(string)
}

# Injected into the rule group rather than written into the rules, so the same
# rule file can also be loaded by the self-managed engine in Phase 9 (ADR-022).
variable "home_net" {
  description = "Address range the rules treat as internal"
  type        = string

  validation {
    condition     = can(cidrnetmask(var.home_net))
    error_message = "home_net must be a CIDR block, not a single address."
  }
}

# Capacity cannot be changed after creation: raising it means replacing the
# rule group and pointing the policy at the new one. The rule file currently
# holds 15 rules, so this leaves room to add without a replacement.
variable "rule_capacity" {
  description = "Rule group capacity reserved at creation"
  type        = number
  default     = 100
}

# NFR-06 caps retention at 14 days. CloudWatch accepts only a fixed set of
# values and rejects anything else at apply time, so the set is checked here
# to fail during plan instead.
variable "log_retention_days" {
  description = "Days CloudWatch Logs keeps the firewall log groups"
  type        = number
  default     = 14

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90], var.log_retention_days)
    error_message = "log_retention_days must be one of the retention periods CloudWatch accepts."
  }
}
