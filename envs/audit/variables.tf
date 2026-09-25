# Compliance-mode retention cannot be shortened once an object is written.
# Raising it is safe; lowering it applies only to objects written after.
variable "retention_days" {
  description = "Days each audit object is locked against deletion"
  type        = number
  default     = 1

  validation {
    condition     = var.retention_days >= 1
    error_message = "retention_days must be at least 1."
  }
}
