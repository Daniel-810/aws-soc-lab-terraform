locals {
  common_tags = {
    Project   = var.project
    ManagedBy = "terraform"
  }
}

# Accepted: AWS-managed encryption. A customer managed key adds a monthly
# charge and a key policy to run for a lab brought up on demand (ADR-014).
#trivy:ignore:AWS-0017
resource "aws_cloudwatch_log_group" "this" {
  name              = "/${var.project}/waf"
  retention_in_days = var.log_retention_days
  tags = merge(local.common_tags, {
    Name = "${var.project}-waf-logs"
  })
}

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

resource "aws_iam_role" "waf" {
  name               = "${var.project}-waf-role"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json

  tags = merge(local.common_tags, {
    Name = "${var.project}-waf-role"
  })
}

data "aws_iam_policy_document" "waf" {
  statement {
    effect  = "Allow"
    actions = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = [
      aws_cloudwatch_log_group.this.arn,
      "${aws_cloudwatch_log_group.this.arn}:*",
    ]
  }

  # These actions do not support resource-level permissions, so the scope
  # cannot be narrowed. The log permissions above are limited to this
  # module's log group (SR-06).
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

  # Read only. Writing belongs to the app role (ADR-017)
  statement {
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [var.ca_secret_arn]
  }
}

resource "aws_iam_role_policy" "waf" {
  name   = "${var.project}-waf-policy"
  role   = aws_iam_role.waf.id
  policy = data.aws_iam_policy_document.waf.json
}

resource "aws_iam_instance_profile" "waf" {
  name = "${var.project}-waf-profile"
  role = aws_iam_role.waf.name

  tags = merge(local.common_tags, {
    Name = "${var.project}-waf-profile"
  })
}

data "aws_ami" "waf" {
  owners      = ["099720109477"] # Canonical
  most_recent = true

  filter {
    name   = "name"
    values = [var.ami_name_pattern]
  }
}

data "aws_region" "current" {}

resource "aws_instance" "waf" {
  ami           = data.aws_ami.waf.id
  instance_type = var.instance_type

  subnet_id              = var.subnet_id
  vpc_security_group_ids = [var.security_group_id]
  iam_instance_profile   = aws_iam_instance_profile.waf.name

  # Compressed for the same reason as the Suricata instance: with the agent
  # installer and time source added it came within 2.3 KiB of the 16 KiB
  # limit. cloud-init detects gzip and unpacks it.
  user_data_base64 = base64gzip(templatefile("${path.module}/user_data.sh.tftpl", {
    app_private_ip  = var.app_private_ip
    ca_secret_arn   = var.ca_secret_arn
    region          = data.aws_region.current.region
    log_group       = aws_cloudwatch_log_group.this.name
    cwagent_install = var.cwagent_install
    time_sync       = var.time_sync
  }))
  user_data_replace_on_change = true

  # Encrypted at rest with the AWS-managed EBS key: no cost, and the disk
  # holds logs and TLS keys. Left out until Trivy flagged it (AWS-0131).
  root_block_device {
    encrypted = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  tags = merge(local.common_tags, {
    Name = "${var.project}-waf"
  })
}

resource "aws_eip" "waf" {
  domain   = "vpc"
  instance = aws_instance.waf.id

  tags = merge(local.common_tags, {
    Name = "${var.project}-waf-eip"
  })
}
