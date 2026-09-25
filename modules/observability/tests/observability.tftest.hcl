# Mocked AWS provider: no credentials, no resources, no cost.
# Only values the code sets can be asserted: the mock fills anything left
# unset (a key pair name, a public address flag) with random data.

# Policy documents are rendered by the provider; the mock returns a random
# string, which the role resource rejects. A valid empty policy stands in.
mock_provider "aws" {
  # The flow log checks the ARNs it is given; mocked ones must look real.
  mock_resource "aws_cloudwatch_log_group" {
    defaults = {
      arn = "arn:aws:logs:ap-northeast-2:000000000000:log-group:/soc-lab/vpc/flow"
    }
  }
  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::000000000000:role/soc-lab-vpc-flow-role"
    }
  }
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
}

variables {
  vpc_id               = "vpc-0123456789abcdef0"
  ips_alert_log_groups = ["/soc-lab/suricata"]
  waf_log_group        = "/soc-lab/waf"
}

run "flow_log_records_everything_for_fourteen_days" {
  assert {
    condition     = aws_flow_log.this.traffic_type == "ALL"
    error_message = "Accepted and rejected traffic must both be recorded (SR-15, F10)."
  }
  assert {
    condition     = aws_cloudwatch_log_group.flow.retention_in_days == 14
    error_message = "Log retention must be 14 days (NFR-06, F7)."
  }
}

# Alarms mark bursts on the dashboard; acting on them is FR-07, which is
# optional and not built (ADR-031). An action appearing here is a scope
# change and should come with its own decision.
run "alarms_take_no_action" {
  assert {
    condition     = alltrue([for a in aws_cloudwatch_metric_alarm.burst : try(length(a.alarm_actions), 0) == 0])
    error_message = "Burst alarms must have no actions attached (ADR-031)."
  }
}

run "one_ips_filter_per_alert_group" {
  variables {
    ips_alert_log_groups = ["/soc-lab/firewall/alert", "/soc-lab/suricata"]
  }
  assert {
    condition     = length(aws_cloudwatch_log_metric_filter.ips_blocked) == 2
    error_message = "Every IPS alert group needs its own metric filter feeding IpsBlocked."
  }
}
