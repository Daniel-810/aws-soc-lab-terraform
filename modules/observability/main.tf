locals {
  common_tags = {
    Project   = var.project
    ManagedBy = "terraform"
  }

  # The two approaches log the same engine's records, one wrapped in an
  # "event" object (managed) and one flat (Suricata). coalesce() reads
  # whichever is present, so one query serves both (ADR-030).
  #
  # No filter on the alert fields: both groups hold alerts only by
  # construction (the managed alert log, and the agent's include filter on
  # Suricata). Filters were tried and gave wrong counts in Logs Insights:
  # ispresent() on the coalesced alias matched nothing, and ispresent(a) or
  # ispresent(b), with b absent from the records, returned 9 of 20.
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
        | sort @timestamp desc
        | limit 200
      EOT
    }

    network-top-sources = {
      groups = var.network_alert_log_groups
      query  = <<-EOT
        ${trimspace(local.network_fields)}
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

# --- logs to metrics (FR-06) ------------------------------------------------

# Counting blocks as metrics gives one number per layer whatever the log
# shape, and a metric can carry an alarm, which a log query cannot (ADR-031).
locals {
  namespace = "SocLab"

  # One entity keeps one colour in every widget (dataviz slots 1 to 3,
  # validated for colour-vision deficiency in the reference palette).
  colours = {
    waf     = "#2a78d6"
    network = "#eb6834"
    flow    = "#1baf7a"
  }
}

# Same metric for either approach: the managed record wraps the alert in
# "event", Suricata's does not. The pattern accepts both, so the dashboard
# does not change when the approach does.
resource "aws_cloudwatch_log_metric_filter" "network_blocked" {
  for_each = toset(var.network_alert_log_groups)

  name           = "${var.project}-network-blocked-${replace(trimprefix(each.value, "/"), "/", "-")}"
  log_group_name = each.value
  pattern        = "{ ($.event.alert.action = \"blocked\") || ($.alert.action = \"blocked\") }"

  metric_transformation {
    name      = "NetworkBlocked"
    namespace = local.namespace
    value     = "1"
    unit      = "Count"
  }
}

# 949110 is recorded when the CRS anomaly score crosses the threshold, the
# point at which the engine blocks.
resource "aws_cloudwatch_log_metric_filter" "waf_blocked" {
  name           = "${var.project}-waf-blocked"
  log_group_name = var.waf_log_group
  pattern        = "\"949110\""

  metric_transformation {
    name      = "WafBlocked"
    namespace = local.namespace
    value     = "1"
    unit      = "Count"
  }
}

resource "aws_cloudwatch_log_metric_filter" "flow_rejected" {
  name           = "${var.project}-flow-rejected"
  log_group_name = aws_cloudwatch_log_group.flow.name
  pattern        = "[version, account, eni, source, destination, srcport, destport, protocol, packets, bytes, windowstart, windowend, action=\"REJECT\", flowlogstatus]"

  metric_transformation {
    name      = "FlowRejected"
    namespace = local.namespace
    value     = "1"
    unit      = "Count"
  }
}

# A burst of blocks in one minute. No action is attached: the alarm marks
# the moment on the dashboard, and acting on it is FR-07, which is optional
# and not built (ADR-031).
resource "aws_cloudwatch_metric_alarm" "burst" {
  for_each = {
    network = "NetworkBlocked"
    waf     = "WafBlocked"
  }

  alarm_name          = "${var.project}-${each.key}-blocked-burst"
  alarm_description   = "Ten or more ${each.key} layer blocks within one minute"
  namespace           = local.namespace
  metric_name         = each.value
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 10
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  tags = local.common_tags

  depends_on = [
    aws_cloudwatch_log_metric_filter.network_blocked,
    aws_cloudwatch_log_metric_filter.waf_blocked,
  ]
}

# --- dashboard ----------------------------------------------------------------

locals {
  region = data.aws_region.current.region

  # Logs Insights charts need a stats query; these reuse the network fields
  # so they read either approach.
  charts = {
    network-by-category = {
      groups = var.network_alert_log_groups
      query  = <<-EOT
        fields coalesce(event.alert.metadata.probe_category.0, alert.metadata.probe_category.0) as category
        | stats count(*) as alerts by category
        | sort alerts desc
      EOT
    }
    network-by-rule = {
      groups = var.network_alert_log_groups
      query  = <<-EOT
        fields coalesce(event.alert.signature, alert.signature) as rule
        | stats count(*) as alerts by rule
        | sort alerts desc
        | limit 10
      EOT
    }
    # Ports the internet probes and the security groups turn away: blocked
    # attempts never reach an alert log, so this is the only view of them.
    flow-rejected-ports = {
      groups = [aws_cloudwatch_log_group.flow.name]
      query  = <<-EOT
        filter action = "REJECT"
        | stats count(*) as rejected by dstPort
        | sort rejected desc
        | limit 10
      EOT
    }
  }

  log_query = { for k, v in merge(local.queries, local.charts) : k => join(" | ", concat(
    [for g in v.groups : "SOURCE '${g}'"],
    [trimspace(v.query)],
  )) }

  metric = {
    waf     = [local.namespace, "WafBlocked", { label = "WAF", color = local.colours.waf }]
    network = [local.namespace, "NetworkBlocked", { label = "Network layer", color = local.colours.network }]
    flow    = [local.namespace, "FlowRejected", { label = "Flow rejected", color = local.colours.flow }]
  }

  log_widget = { for k, v in {
    # name                  = [x, y, w, h, view]
    network-by-category = [0, 10, 8, 6, "bar"]
    network-by-rule     = [8, 10, 8, 6, "bar"]
    flow-rejected-ports = [16, 10, 8, 6, "bar"]
    network-top-sources = [0, 16, 8, 6, "table"]
    waf-blocked         = [8, 16, 16, 6, "table"]
    network-alerts      = [0, 22, 24, 7, "table"]
    } : k => {
    type = "log", x = v[0], y = v[1], width = v[2], height = v[3]
    properties = {
      title  = k
      region = local.region
      view   = v[4]
      query  = local.log_query[k]
    }
  } }
}

resource "aws_cloudwatch_dashboard" "this" {
  dashboard_name = "${var.project}-soc"

  dashboard_body = jsonencode({
    widgets = concat(
      [
        # Headline: one number per layer over the dashboard's time range.
        {
          type = "metric", x = 0, y = 0, width = 24, height = 4
          properties = {
            title                = "Blocked or rejected in the selected range"
            region               = local.region
            view                 = "singleValue"
            stat                 = "Sum"
            period               = 60
            setPeriodToTimeRange = true
            metrics              = [local.metric.waf, local.metric.network, local.metric.flow]
          }
        },
        # The two blocking layers over time, on one axis: same unit, same
        # scale. Flow rejections stay out of it; their volume is driven by
        # internet scanning and would flatten the other two lines.
        {
          type = "metric", x = 0, y = 4, width = 16, height = 6
          properties = {
            title   = "Blocks per minute by layer"
            region  = local.region
            view    = "timeSeries"
            stat    = "Sum"
            period  = 60
            metrics = [local.metric.waf, local.metric.network]
            yAxis   = { left = { min = 0, label = "Count", showUnits = false } }
          }
        },
        {
          type = "alarm", x = 16, y = 4, width = 8, height = 6
          properties = {
            title  = "Block bursts (ten or more in a minute)"
            alarms = [for a in aws_cloudwatch_metric_alarm.burst : a.arn]
          }
        },
      ],
      values(local.log_widget),
    )
  })
}
