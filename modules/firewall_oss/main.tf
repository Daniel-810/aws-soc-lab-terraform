locals {
  common_tags = {
    Project   = var.project
    ManagedBy = "terraform"
  }
}

# The agent ships the engine's alerts here (Phase 10).
# Accepted: AWS-managed encryption. A customer managed key adds a monthly
# charge and a key policy to run for a lab brought up on demand (ADR-014).
#trivy:ignore:AWS-0017
resource "aws_cloudwatch_log_group" "this" {
  name              = "/${var.project}/suricata"
  retention_in_days = var.log_retention_days
  tags = merge(local.common_tags, {
    Name = "${var.project}-suricata-logs"
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

# Not shared with any other tier (SR-07).
resource "aws_iam_role" "this" {
  name               = "${var.project}-suricata-role"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json

  tags = merge(local.common_tags, {
    Name = "${var.project}-suricata-role"
  })
}

data "aws_iam_policy_document" "this" {
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
}

resource "aws_iam_role_policy" "this" {
  name   = "${var.project}-suricata-policy"
  role   = aws_iam_role.this.id
  policy = data.aws_iam_policy_document.this.json
}

resource "aws_iam_instance_profile" "this" {
  name = "${var.project}-suricata-profile"
  role = aws_iam_role.this.name

  tags = merge(local.common_tags, {
    Name = "${var.project}-suricata-profile"
  })
}

data "aws_region" "current" {}

data "aws_ami" "this" {
  owners      = ["099720109477"] # Canonical
  most_recent = true

  filter {
    name   = "name"
    values = [var.ami_name_pattern]
  }
}

resource "aws_instance" "this" {
  ami           = data.aws_ami.this.id
  instance_type = var.instance_type

  subnet_id              = var.subnet_id
  vpc_security_group_ids = [var.security_group_id]
  iam_instance_profile   = aws_iam_instance_profile.this.name

  # AWS drops packets at the interface unless it is addressed to or from
  # the instance itself. Forwarding other hosts' traffic needs this off (F13).
  source_dest_check = false

  # For the instance's own calls out (package archive, Session Manager). NAT
  # cannot serve them: its default route leads back to this instance. No
  # Elastic IP, since nothing needs to reach this address (ADR-027).
  associate_public_ip_address = true

  # Compressed: the script carries the whole rule file and the agent
  # installer, and uncompressed it sits within 1 KiB of the 16 KiB user data
  # limit. cloud-init detects gzip and unpacks it (ADR-027).
  user_data_base64 = base64gzip(templatefile("${path.module}/user_data.sh.tftpl", {
    home_net        = var.home_net
    rules           = var.rules
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
    Name = "${var.project}-suricata"
  })
}
