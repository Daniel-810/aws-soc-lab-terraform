# Runs against a mocked AWS provider: no credentials, no resources, no cost.
# Only values the code sets can be asserted: the mock fills anything left
# unset (a key pair name, a public address flag) with random data.
# Each run applies the module to the mock and checks what the code decided,
# so a change that quietly reverses a routing or exposure decision fails CI.

mock_provider "aws" {
  mock_data "aws_availability_zones" {
    defaults = {
      names = ["ap-northeast-2a", "ap-northeast-2b", "ap-northeast-2c"]
    }
  }
}

variables {
  waf_ingress_cidrs = ["203.0.113.10/32"]
}

run "inspection_off_routes_to_the_internet_gateway" {
  assert {
    condition     = length(aws_route_table.igw) == 0 && length(aws_route.igw_to_inspection) == 0
    error_message = "With inspection off there must be no edge route table (ADR-024)."
  }
  assert {
    condition     = aws_route.waf_default.gateway_id != null && aws_route.waf_default.vpc_endpoint_id == null
    error_message = "With inspection off the WAF subnet must route to the internet gateway."
  }
}

run "managed_endpoint_takes_both_directions" {
  variables {
    inspection_enabled     = true
    inspection_endpoint_id = "vpce-0123456789abcdef0"
  }
  assert {
    condition     = aws_route.waf_default.vpc_endpoint_id == "vpce-0123456789abcdef0" && aws_route.waf_default.gateway_id == null
    error_message = "Outbound from the WAF subnet must go to the endpoint, not the gateway."
  }
  assert {
    condition     = aws_route.nat_default.vpc_endpoint_id == "vpce-0123456789abcdef0"
    error_message = "Outbound after NAT must go to the endpoint (FR-10)."
  }
  # Return traffic must meet the same endpoint, or stateful inspection sees
  # half a connection.
  assert {
    condition     = length(aws_route_table_association.igw_edge) == 1 && toset(keys(aws_route.igw_to_inspection)) == toset(["waf-ap-northeast-2a", "nat-ap-northeast-2a"])
    error_message = "Inbound to the WAF and NAT subnets must be routed through the endpoint at the gateway edge."
  }
}

run "suricata_interface_is_the_target" {
  variables {
    inspection_enabled = true
    inspection_eni_id  = "eni-0123456789abcdef0"
  }
  assert {
    condition     = aws_route.waf_default.network_interface_id == "eni-0123456789abcdef0" && aws_route.waf_default.vpc_endpoint_id == null
    error_message = "Approach B must route to the instance's interface (ADR-026)."
  }
}

run "inspection_without_a_target_is_refused" {
  command = plan
  variables {
    inspection_enabled = true
  }
  expect_failures = [var.inspection_eni_id]
}

run "two_targets_are_refused" {
  command = plan
  variables {
    inspection_enabled     = true
    inspection_endpoint_id = "vpce-0123456789abcdef0"
    inspection_eni_id      = "eni-0123456789abcdef0"
  }
  expect_failures = [var.inspection_eni_id]
}

run "app_subnet_has_no_route_from_the_internet" {
  assert {
    condition     = aws_route.app_default.nat_gateway_id != null && aws_route.app_default.gateway_id == null
    error_message = "The app subnet must leave through NAT and never route to the gateway directly (SR-03)."
  }
}

run "boundary_is_limited_to_named_sources" {
  assert {
    condition     = toset(keys(aws_vpc_security_group_ingress_rule.waf_in_https)) == toset(["203.0.113.10/32"])
    error_message = "WAF HTTPS must be open to the listed sources only (ADR-019)."
  }
  assert {
    condition     = toset(keys(aws_vpc_security_group_ingress_rule.suricata_in_http)) == toset(["203.0.113.10/32"])
    error_message = "The inspection instance must accept forwarded HTTP from the WAF's sources only (ADR-027)."
  }
  # The app accepts one thing: the WAF's security group, never an address.
  assert {
    condition     = aws_vpc_security_group_ingress_rule.app_in_waf.cidr_ipv4 == null && aws_vpc_security_group_ingress_rule.app_in_waf.from_port == 443
    error_message = "The app must be reachable only from the WAF security group on 443 (SR-04, F2)."
  }
}

run "subnets_stay_apart_when_zones_are_added" {
  command = plan
  variables {
    az_count = 2
  }
  assert {
    condition     = length(local.subnets) == 10 && length(distinct([for s in local.subnets : s.cidr])) == 10
    error_message = "Adding a zone must add subnets without overlapping ranges (NFR-05)."
  }
}
