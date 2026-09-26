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

# Personal addresses do not belong in a public repository (SR-10). They come
# from terraform.tfvars, which is git ignored.
variable "budget_alert_emails" {
  description = "Addresses that receive the monthly budget alerts"
  type        = list(string)

  validation {
    condition     = length(var.budget_alert_emails) > 0
    error_message = "At least one address must receive budget alerts."
  }
}

# NFR-04: 50,000 KRW a month, held in dollars because that is the billing
# currency.
variable "monthly_budget_usd" {
  description = "Monthly cost limit the alerts are measured against, in USD"
  type        = number
  default     = 36
}
