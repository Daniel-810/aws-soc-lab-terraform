variable "project" {
  description = "Name prefix applied to all resources and tags"
  type        = string
  default     = "soc-lab"
}

# The instance carries no public IP (SR-03), so this has to be a private
# subnet whose default route points at the NAT gateway.
variable "subnet_id" {
  description = "Private subnet the application instance is placed in"
  type        = string
}

# Its only inbound rule allows the WAF tier, so nothing reaches the
# application without passing the boundary layer first (SR-03, SR-04).
variable "security_group_id" {
  description = "Security group attached to the application instance"
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type for the application host"
  type        = string
}

# Pin the tag instead of tracking a moving one. An image that changes
# underneath the lab would alter detection results without any code change,
# which breaks both the supply chain requirement and repeatable verification
# (SR-25, NFR-03).
variable "app_image" {
  description = "Container image for the target application, including an explicit tag"
  type        = string
}

# NFR-06 caps retention at 14 days. CloudWatch accepts only a fixed set of
# values and rejects anything else at apply time, so the set is checked here
# to fail during plan instead.
variable "log_retention_days" {
  description = "Days CloudWatch Logs keeps the application log group"
  type        = number
  default     = 14

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90], var.log_retention_days)
    error_message = "log_retention_days must be one of the retention periods CloudWatch accepts."
  }
}

# The version is pinned inside the pattern rather than matching the newest
# 2023.x build: Amazon publishes a new image roughly every two weeks, and an
# image that changes without a code change breaks both the supply chain
# requirement and repeatable verification (SR-25, NFR-03). Moving to a newer
# image is done by editing this string, which records the change in history
# (SR-26). Matching by name rather than image ID keeps the module portable
# across regions, where the same image carries a different ID.
variable "ami_name_pattern" {
  description = "Name filter selecting the base AMI. Must resolve to an x86_64 image to match the instance type."
  type        = string
  default     = "al2023-ami-2023.12.20260831.0-kernel-6.1-x86_64"
}
