variable "project" {
  description = "Name prefix applied to all resources and tags"
  type        = string
  default     = "soc-lab"
}

# The WAF is the only tier reached from the internet, so this is a public
# subnet and the instance gets an Elastic IP.
variable "subnet_id" {
  description = "Public subnet the WAF instance is placed in"
  type        = string
}

# Allows 80 and 443 from the internet and 443 out to the app tier only.
variable "security_group_id" {
  description = "Security group attached to the WAF instance"
  type        = string
}

# Proxy target. Not a secret: it is unreachable from outside the VPC, so it
# is passed as a plain value rather than through the secret.
variable "app_private_ip" {
  description = "Private address of the application instance the WAF proxies to"
  type        = string

  validation {
    condition     = can(cidrhost("${var.app_private_ip}/32", 0))
    error_message = "app_private_ip must be a single IPv4 address."
  }
}

# The app publishes its CA certificate here and the WAF reads it into its
# trust store. The role gets read access to this secret only (SR-06).
variable "ca_secret_arn" {
  description = "ARN of the secret the WAF reads the internal CA certificate from"
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type for the WAF host"
  type        = string
}

# NFR-06 caps retention at 14 days. CloudWatch accepts only a fixed set of
# values and rejects anything else at apply time, so the set is checked here
# to fail during plan instead.
variable "log_retention_days" {
  description = "Days CloudWatch Logs keeps the WAF log group"
  type        = number
  default     = 14

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90], var.log_retention_days)
    error_message = "log_retention_days must be one of the retention periods CloudWatch accepts."
  }
}

# Ubuntu rather than the app's Amazon Linux: the ModSecurity packages exist
# only in the Ubuntu archive (ADR-006). The release date is pinned in the name
# for the same reason as the app image: an image that changes without a code
# change breaks the supply chain requirement and repeatable verification
# (SR-25, NFR-03). Updating means editing this string (SR-26).
variable "ami_name_pattern" {
  description = "Name filter selecting the base AMI. Must resolve to an amd64 image to match the instance type."
  type        = string
  default     = "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-20260904"
}

# The shared installer in scripts/, passed in by the root as the rule file
# is, so both boot scripts run the same verified install (ADR-028).
variable "cwagent_install" {
  description = "Shell fragment that installs the CloudWatch agent after verifying its signature"
  type        = string
}

# Shared by every instance, passed in by the root as the agent installer is:
# keeps chrony on the link-local Amazon Time Sync Service only (ADR-031).
variable "time_sync" {
  description = "Shell fragment that points chrony at the Amazon Time Sync Service only"
  type        = string
}
