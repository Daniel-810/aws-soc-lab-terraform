locals {
  common_tags = {
    Project   = var.project
    ManagedBy = "terraform"
  }

  # The two approaches log the same engine's records, one wrapped in an
  # "event" object (managed) and one flat (Suricata). coalesce() reads
  # whichever is present, so one query serves both (ADR-030).
  network_fields = <<-EOT
    fields @timestamp,
      coalesce(event.alert.signature_id, alert.signature_id) as sid,
      coalesce(event.alert.signature, alert.signature) as signature,
      coalesce(event.alert.action, alert.action) as action,
      coalesce(event.src_ip, src_ip) as src,
      coalesce(event.dest_ip, dest_ip) as dst,
      coalesce(event.dest_port, dest_port) as port,
      coalesce(event.http.url, http.url) as url
  EOT

  queries = {
    network-alerts = {
      groups = var.network_alert_log_groups
      query  = <<-EOT
        ${trimspace(local.network_fields)}
        | filter ispresent(sid)
        | sort @timestamp desc
        | limit 200
      EOT
    }

    network-top-sources = {
      groups = var.network_alert_log_groups
      query  = <<-EOT
        ${trimspace(local.network_fields)}
        | filter ispresent(sid)
        | stats count(*) as alerts, count_distinct(sid) as signatures by src
        | sort alerts desc
        | limit 20
      EOT
    }

    # 949110 is the rule CRS records when the anomaly score crosses the
    # threshold, which is what the engine acts on. A match on any other rule
    # is a scored finding, not a verdict (see tools/probe).
    waf-blocked = {
      groups = [var.waf_log_group]
      query  = <<-EOT
        fields @timestamp, transaction.client_ip as src,
          transaction.request.method as method, transaction.request.uri as uri
        | filter @message like /949110/
        | sort @timestamp desc
        | limit 200
      EOT
    }

    # One request across every layer. Replace PROBE_ID with an id the probe
    # printed; the id travels in the query string, which each layer logs.
    trace-probe = {
      groups = concat(var.network_alert_log_groups, [var.waf_log_group])
      query  = <<-EOT
        fields @timestamp, @log, @message
        | filter @message like /PROBE_ID/
        | sort @timestamp asc
      EOT
    }

    flow-rejects = {
      groups = [aws_cloudwatch_log_group.flow.name]
      query  = <<-EOT
        fields @timestamp, srcAddr, dstAddr, dstPort, action
        | filter action = "REJECT"
        | stats count(*) as rejected by srcAddr, dstPort
        | sort rejected desc
        | limit 20
      EOT
    }
  }
}

# --- VPC flow log (SR-15) ---------------------------------------------------

# Accepted and rejected traffic both, at every interface in the VPC: what
# passed is the part a rule-only log never shows (F10, T-06).
resource "aws_cloudwatch_log_group" "flow" {
  name              = "/${var.project}/vpc/flow"
  retention_in_days = var.log_retention_days
  tags = merge(local.common_tags, {
    Name = "${var.project}-vpc-flow-logs"
  })
}

data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "flow_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
    # The service acts for this account only (confused deputy).
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_iam_role" "flow" {
  name               = "${var.project}-vpc-flow-role"
  assume_role_policy = data.aws_iam_policy_document.flow_assume.json

  tags = merge(local.common_tags, {
    Name = "${var.project}-vpc-flow-role"
  })
}

data "aws_iam_policy_document" "flow" {
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
    ]
    resources = [
      aws_cloudwatch_log_group.flow.arn,
      "${aws_cloudwatch_log_group.flow.arn}:*",
    ]
  }
}

resource "aws_iam_role_policy" "flow" {
  name   = "${var.project}-vpc-flow-policy"
  role   = aws_iam_role.flow.id
  policy = data.aws_iam_policy_document.flow.json
}

resource "aws_flow_log" "this" {
  vpc_id                   = var.vpc_id
  traffic_type             = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.flow.arn
  iam_role_arn             = aws_iam_role.flow.arn
  max_aggregation_interval = 60

  tags = merge(local.common_tags, {
    Name = "${var.project}-vpc-flow"
  })
}

# --- saved queries and dashboard (FR-06) ------------------------------------

resource "aws_cloudwatch_query_definition" "this" {
  for_each = local.queries

  name            = "${var.project}/${each.key}"
  log_group_names = each.value.groups
  query_string    = trimspace(each.value.query)
}

data "aws_region" "current" {}

resource "aws_cloudwatch_dashboard" "this" {
  dashboard_name = "${var.project}-soc"

  dashboard_body = jsonencode({
    widgets = [
      for i, name in ["network-top-sources", "waf-blocked", "network-alerts", "flow-rejects"] : {
        type   = "log"
        x      = (i % 2) * 12
        y      = floor(i / 2) * 8
        width  = 12
        height = 8
        properties = {
          title  = name
          region = data.aws_region.current.region
          view   = "table"
          query = join(" | ", concat(
            [for g in local.queries[name].groups : "SOURCE '${g}'"],
            [trimspace(local.queries[name].query)],
          ))
        }
      }
    ]
  })
}
