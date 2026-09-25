locals {
  common_tags = {
    Project   = var.project
    ManagedBy = "terraform"
  }
}

# Accepted: the secret holds a public CA certificate only, never a key
# (ADR-017), so a customer managed key would protect nothing secret.
#trivy:ignore:AWS-0098
resource "aws_secretsmanager_secret" "this" {
  # Holds only the public CA certificate. No value is written here, so the
  # private key never reaches state (ADR-017).
  name = "${var.project}/internal-ca-cert"

  # Delete immediately so the next apply can reuse the name. Lab only:
  # in production this makes a deleted secret unrecoverable.
  recovery_window_in_days = 0

  tags = merge(local.common_tags, {
    Name = "${var.project}-internal-ca-cert"
  })
}
