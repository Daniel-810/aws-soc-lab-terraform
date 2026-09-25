locals {
  common_tags = {
    Project   = var.project
    ManagedBy = "terraform"
  }
}

resource "aws_networkfirewall_rule_group" "this" {
  name     = "${var.project}-attacks"
  type     = "STATEFUL"
  capacity = var.rule_capacity

  rule_group {
    rule_variables {
      ip_sets {
        key = "HOME_NET"
        ip_set {
          definition = [var.home_net]
        }
      }
    }

    rules_source {
      # The managed firewall reads one rule per line and rejects Suricata's
      # backslash continuation, which the self-managed engine accepts. The file
      # keeps the readable form both engines share (ADR-022); lines are joined
      # only on the way to this API.
      rules_string = replace(var.rules, "/\\\\\\n\\s*/", " ")
    }
  }

  tags = merge(local.common_tags, { Name = "${var.project}-nfw-rule-group" })
}

resource "aws_networkfirewall_firewall_policy" "this" {
  name = "${var.project}-policy"
  firewall_policy {
    stateless_default_actions          = ["aws:forward_to_sfe"]
    stateless_fragment_default_actions = ["aws:forward_to_sfe"]


    stateful_rule_group_reference {
      resource_arn = aws_networkfirewall_rule_group.this.arn
    }
  }

  tags = merge(local.common_tags, { Name = "${var.project}-nfw-policy" })
}

resource "aws_networkfirewall_firewall" "this" {
  name                = "${var.project}-nfw"
  firewall_policy_arn = aws_networkfirewall_firewall_policy.this.arn
  vpc_id              = var.vpc_id
  # Off on purpose: this environment is created and destroyed each session.
  # Production keeps these on so a firewall cannot be removed by accident.
  delete_protection                 = false
  firewall_policy_change_protection = false
  subnet_change_protection          = false

  dynamic "subnet_mapping" {
    for_each = var.subnet_ids
    content {
      subnet_id = subnet_mapping.value
    }
  }

  tags = merge(local.common_tags, { Name = "${var.project}-nfw" })

  timeouts {
    create = "40m"
    update = "50m"
    delete = "1h"
  }
}

# Accepted: AWS-managed encryption. A customer managed key adds a monthly
# charge and a key policy to run for a lab brought up on demand (ADR-014).
#trivy:ignore:AWS-0017
resource "aws_cloudwatch_log_group" "alert" {
  name              = "/${var.project}/firewall/alert"
  retention_in_days = var.log_retention_days
  tags = merge(local.common_tags, {
    Name = "${var.project}-fw-alert-logs"
  })
}

# Accepted: AWS-managed encryption. A customer managed key adds a monthly
# charge and a key policy to run for a lab brought up on demand (ADR-014).
#trivy:ignore:AWS-0017
resource "aws_cloudwatch_log_group" "flow" {
  name              = "/${var.project}/firewall/flow"
  retention_in_days = var.log_retention_days
  tags = merge(local.common_tags, {
    Name = "${var.project}-fw-flow-logs"
  })
}

resource "aws_networkfirewall_logging_configuration" "this" {
  firewall_arn = aws_networkfirewall_firewall.this.arn
  logging_configuration {
    log_destination_config {
      log_destination = {
        logGroup = aws_cloudwatch_log_group.alert.name
      }
      log_destination_type = "CloudWatchLogs"
      log_type             = "ALERT"
    }

    log_destination_config {
      log_destination = {
        logGroup = aws_cloudwatch_log_group.flow.name
      }
      log_destination_type = "CloudWatchLogs"
      log_type             = "FLOW"
    }
  }
}
