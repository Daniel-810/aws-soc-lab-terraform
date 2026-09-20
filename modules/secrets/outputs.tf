output "ca_cert_secret_arn" {
  description = "ARN of the secret holding the internal CA certificate. Passed to roles that write or read it"
  value       = aws_secretsmanager_secret.this.arn
}
