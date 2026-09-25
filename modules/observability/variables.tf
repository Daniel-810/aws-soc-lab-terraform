variable "project" {
  description = "Name prefix applied to all resources and tags"
  type        = string
  default     = "soc-lab"
}

variable "vpc_id" {
  description = "VPC whose traffic the flow log records"
  type        = string
}

# One entry per deployed approach: the managed firewall's alert group or
# the Suricata group. Queries read them together, so switching approach
# does not change the dashboard.
variable "ips_alert_log_groups" {
  description = "Log groups holding IPS alerts, for whichever approach is deployed"
  type        = list(string)
}

variable "waf_log_group" {
  description = "Log group holding the WAF's ModSecurity audit entries"
  type        = string
}

# NFR-06 caps retention at 14 days. CloudWatch accepts only a fixed set of
# values and rejects anything else at apply time, so the set is checked here
# to fail during plan instead.
variable "log_retention_days" {
  description = "Days CloudWatch Logs keeps the flow log group"
  type        = number
  default     = 14

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90], var.log_retention_days)
    error_message = "log_retention_days must be one of the retention periods CloudWatch accepts."
  }
}
