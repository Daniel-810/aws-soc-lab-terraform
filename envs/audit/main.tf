# Audit trail and its store. Persistent: created once and kept while the lab
# in envs/lab is brought up and torn down, so the calls that build and
# destroy the lab are themselves recorded (ADR-032). Kept out of bootstrap,
# which stays limited to the state bucket (ADR-014).

terraform {
  required_version = ">=1.10"

  # Same state bucket as envs/lab, under its own key. The key is set here
  # rather than in backend.hcl so this environment can never be initialised
  # onto the lab's state by copying the wrong file.
  backend "s3" {
    key = "envs/audit/terraform.tfstate"
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = "ap-northeast-2"
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  project    = "soc-lab"
  account_id = data.aws_caller_identity.current.account_id
  trail_name = "${local.project}-audit"
  trail_arn  = "arn:aws:cloudtrail:${data.aws_region.current.region}:${local.account_id}:trail/${local.trail_name}"

  common_tags = {
    Project   = local.project
    ManagedBy = "terraform"
  }
}

# --- write-once store (SR-17) ------------------------------------------------

# Object Lock can only be switched on when the bucket is created. In
# compliance mode no one, the root user included, can delete or overwrite a
# locked version before its retention ends (ADR-032).
# Accepted: access to this bucket is itself recorded by the trail it
# holds; object access logs would need another bucket (ADR-032).
#trivy:ignore:AWS-0089
resource "aws_s3_bucket" "audit" {
  bucket              = "${local.project}-audit-${local.account_id}"
  object_lock_enabled = true

  tags = merge(local.common_tags, { Name = "${local.project}-audit" })

  # Locked objects make the bucket undeletable until they expire; a destroy
  # would fail halfway. Removing this guard is a deliberate decision.
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "audit" {
  bucket = aws_s3_bucket.audit.id
  versioning_configuration {
    status = "Enabled"
  }
}

# One day: long enough to show that deletion is refused, short enough that
# the lab's audit records cost nothing to keep.
resource "aws_s3_bucket_object_lock_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.audit]
}

# Accepted: AWS-managed key, as for the state bucket (ADR-014, ADR-032).
#trivy:ignore:AWS-0132
resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "audit" {
  bucket                  = aws_s3_bucket.audit.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Versions leave once their lock has run out. Object Lock refuses any
# earlier removal, so these rules cannot shorten the retention.
resource "aws_s3_bucket_lifecycle_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id

  rule {
    id     = "expire-after-retention"
    status = "Enabled"
    filter {}

    expiration {
      days = var.retention_days + 1
    }
    noncurrent_version_expiration {
      noncurrent_days = 1
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }

  rule {
    id     = "remove-expired-delete-markers"
    status = "Enabled"
    filter {}

    expiration {
      expired_object_delete_marker = true
    }
  }

  depends_on = [aws_s3_bucket_versioning.audit]
}

data "aws_iam_policy_document" "audit" {
  # CloudTrail writes here only on behalf of this trail in this account
  # (confused deputy).
  statement {
    sid       = "CloudTrailAclCheck"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.audit.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "CloudTrailWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.audit.arn}/cloudtrail/AWSLogs/${local.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.audit.arn, "${aws_s3_bucket.audit.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "audit" {
  bucket = aws_s3_bucket.audit.id
  policy = data.aws_iam_policy_document.audit.json

  depends_on = [aws_s3_bucket_public_access_block.audit]
}

# --- API audit (SR-23) ---------------------------------------------------------

# Management events in every region, including global services such as IAM.
# The first copy of management events is free; this is the account's only
# trail. Log file validation writes signed digests, so a removed or altered
# log file can be detected (validate-logs).
# Accepted: AWS-managed key (ADR-032), and delivery to S3 with Object Lock
# only; a CloudWatch copy would add ingestion cost and no protection.
#trivy:ignore:AWS-0015
#trivy:ignore:AWS-0162
resource "aws_cloudtrail" "audit" {
  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.audit.id
  s3_key_prefix                 = "cloudtrail"
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true

  tags = merge(local.common_tags, { Name = local.trail_name })

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [aws_s3_bucket_policy.audit]
}

# --- account baseline (Phase 11, Prowler) --------------------------------------

# Settings that apply to the whole account rather than to the lab, so they
# live with the other persistent controls. Each closes a finding from the
# Prowler audit at no cost (ADR-034). The EBS, metadata and Access Analyzer
# settings are regional; this account works in Seoul only.

# New volumes are encrypted even when a resource does not ask for it. The lab
# instances already set it explicitly (ADR-033); this covers anything else.
resource "aws_ebs_encryption_by_default" "this" {
  enabled = true
}

# New instances require IMDSv2 unless they say otherwise, closing the gap the
# original environment left open (F6) for resources created outside this code.
resource "aws_ec2_instance_metadata_defaults" "this" {
  http_tokens = "required"
}

# No bucket in this account is meant to be public. Blocking at the account
# level holds even if a bucket's own block is removed.
resource "aws_s3_account_public_access_block" "this" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Reports resources shared outside the account. The external access
# analyzer carries no charge.
resource "aws_accessanalyzer_analyzer" "this" {
  analyzer_name = "${local.project}-account"
  type          = "ACCOUNT"

  tags = local.common_tags
}

# Length and variety, and no reuse. No expiry: NIST SP 800-63B advises
# against periodic changes, which push users towards predictable passwords;
# a change is forced on evidence of compromise instead. Prowler's 90-day
# expiry check therefore stays open by decision (ADR-034).
resource "aws_iam_account_password_policy" "this" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  password_reuse_prevention      = 24
}
