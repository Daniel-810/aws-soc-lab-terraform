locals {
  common_tags = {
    Project   = var.project
    ManagedBy = "terraform"
  }
}

# No log group here. The app is not a security layer, so it runs no log
# agent and ships nothing (SR-16); the WAF in front of it records every
# flagged request. A group and a write permission were created in Phase 6
# and never used, until review removed them (2026-09-26).

data "aws_iam_policy_document" "assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
    # EC2 may assume this role only for this account's instances (confused
    # deputy, Prowler iam_role_cross_service_confused_deputy_prevention).
    # Whether EC2 supplies this key when it delivers instance credentials is
    # verified by deployment (ADR-036).
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

data "aws_caller_identity" "current" {}

resource "aws_iam_role" "app" {
  name               = "${var.project}-app-role"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json

  tags = merge(local.common_tags, {
    Name = "${var.project}-app-role"
  })
}

data "aws_iam_policy_document" "app" {
  # These actions do not support resource-level permissions, so the scope
  # cannot be narrowed (SR-06).
  statement {
    effect = "Allow"
    actions = [
      "ssm:UpdateInstanceInformation",
      "ssmmessages:CreateControlChannel",
      "ssmmessages:CreateDataChannel",
      "ssmmessages:OpenControlChannel",
      "ssmmessages:OpenDataChannel",
    ]
    resources = ["*"]
  }

  # Write only. Reading belongs to the WAF role, so the trust anchor can be
  # replaced by this instance alone (ADR-017).
  statement {
    effect    = "Allow"
    actions   = ["secretsmanager:PutSecretValue"]
    resources = [var.ca_secret_arn]
  }
}

resource "aws_iam_role_policy" "app" {
  name   = "${var.project}-app-policy"
  role   = aws_iam_role.app.id
  policy = data.aws_iam_policy_document.app.json
}

resource "aws_iam_instance_profile" "app" {
  name = "${var.project}-app-profile"
  role = aws_iam_role.app.name

  tags = merge(local.common_tags, {
    Name = "${var.project}-app-profile"
  })
}

data "aws_ami" "app" {
  owners      = ["amazon"]
  most_recent = true

  filter {
    name   = "name"
    values = [var.ami_name_pattern]
  }
}

data "aws_region" "current" {}

resource "aws_instance" "app" {
  ami           = data.aws_ami.app.id
  instance_type = var.instance_type

  subnet_id              = var.subnet_id
  vpc_security_group_ids = [var.security_group_id]
  iam_instance_profile   = aws_iam_instance_profile.app.name

  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    app_image     = var.app_image
    ca_secret_arn = var.ca_secret_arn
    region        = data.aws_region.current.region
    time_sync     = var.time_sync
  })
  user_data_replace_on_change = true

  # Encrypted at rest with the AWS-managed EBS key: no cost, and the disk
  # holds the app's data and its TLS key. Left out until Trivy flagged it (AWS-0131).
  root_block_device {
    encrypted = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  tags = merge(local.common_tags, {
    Name = "${var.project}-app"
  })
}
