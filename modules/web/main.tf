locals {
  common_tags = {
    Project   = var.project
    ManagedBy = "terraform"
  }
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/${var.project}/app"
  retention_in_days = var.log_retention_days
  tags = merge(local.common_tags, {
    Name = "${var.project}-app-logs"
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
  }
}

resource "aws_iam_role" "app" {
  name               = "${var.project}-app-role"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json

  tags = merge(local.common_tags, {
    Name = "${var.project}-app-role"
  })
}

data "aws_iam_policy_document" "app" {
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

resource "aws_instance" "app" {
  ami           = data.aws_ami.app.id
  instance_type = var.instance_type

  subnet_id              = var.subnet_id
  vpc_security_group_ids = [var.security_group_id]
  iam_instance_profile   = aws_iam_instance_profile.app.name

  user_data                   = templatefile("${path.module}/user_data.sh.tftpl", { app_image = var.app_image })
  user_data_replace_on_change = true

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  tags = merge(local.common_tags, {
    Name = "${var.project}-app"
  })
}
