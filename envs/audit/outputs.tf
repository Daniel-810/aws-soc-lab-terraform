output "audit_bucket" {
  description = "Object Lock bucket holding the audit trail"
  value       = aws_s3_bucket.audit.id
}

output "trail_arn" {
  description = "ARN of the trail, for aws cloudtrail validate-logs"
  value       = aws_cloudtrail.audit.arn
}
