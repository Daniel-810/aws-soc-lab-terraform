data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  common_tags = {
    Project   = var.project
    ManagedBy = "terraform"
  }
  azs = slice(data.aws_availability_zones.available.names, 0, var.az_count)
  subnet_type = {
    waf         = { index = 0, public = true }
    inspect_mgd = { index = 1, public = false }
    inspect_oss = { index = 2, public = false }
    nat         = { index = 3, public = true }
    app         = { index = 8, public = false }
  }

  subnets = {
    for s in flatten([
      for az_idx, az in local.azs : [
        for name, def in local.subnet_type : {
          key    = "${name}-${az}"
          type   = name
          az     = az
          cidr   = cidrsubnet(cidrsubnet(var.vpc_cidr, 4, az_idx), 4, def.index)
          public = def.public
        }
      ]
    ]) : s.key => s
  }

  route_tables_for = {
    waf         = "waf"
    inspect_mgd = "inspect"
    inspect_oss = "inspect"
    nat         = "nat"
    app         = "app"
  }

}

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(local.common_tags, {
    Name = "${var.project}-vpc"
  })
}

resource "aws_subnet" "this" {
  for_each = local.subnets

  vpc_id            = aws_vpc.this.id
  cidr_block        = each.value.cidr
  availability_zone = each.value.az

  tags = merge(local.common_tags, {
    Name = "${var.project}-${each.value.key}"
  })
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = merge(local.common_tags, {
    Name = "${var.project}-igw"
  })
}

resource "aws_eip" "nat" {
  domain = "vpc"
  tags = merge(local.common_tags, {
    Name = "${var.project}-nat-eip"
  })
}

resource "aws_nat_gateway" "this" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.this["nat-${local.azs[0]}"].id

  tags = merge(local.common_tags, {
    Name = "${var.project}-nat"
  })
  depends_on = [aws_internet_gateway.this]
}

resource "aws_route_table" "this" {
  for_each = toset(["waf", "inspect", "nat", "app"])

  vpc_id = aws_vpc.this.id

  tags = merge(local.common_tags, {
    Name = "${var.project}-${each.key}-rt"
  })
}

resource "aws_route_table_association" "this" {
  for_each = local.subnets

  subnet_id      = aws_subnet.this[each.key].id
  route_table_id = aws_route_table.this[local.route_tables_for[each.value.type]].id
}

# Phase 8/9에서 검사 계층 타깃으로 교체된다.
# 검사 계층이 없는 동안 Phase 6·7의 아웃바운드를 위한 임시 경로.
resource "aws_route" "waf_default" {
  route_table_id         = aws_route_table.this["waf"].id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route" "inspect_default" {
  route_table_id         = aws_route_table.this["inspect"].id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

# Phase 8/9에서 검사 계층 타깃으로 교체된다.
# 검사 계층이 없는 동안 Phase 6·7의 아웃바운드를 위한 임시 경로.
resource "aws_route" "nat_default" {
  route_table_id         = aws_route_table.this["nat"].id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route" "app_default" {
  route_table_id         = aws_route_table.this["app"].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.this.id
}

resource "aws_security_group" "waf" {
  name        = "${var.project}-waf-sg"
  description = "WAF Security Group"
  vpc_id      = aws_vpc.this.id

  tags = merge(local.common_tags, {
    Name = "${var.project}-waf-sg"
  })
}

resource "aws_security_group" "app" {
  name        = "${var.project}-app-sg"
  description = "App Security Group"
  vpc_id      = aws_vpc.this.id

  tags = merge(local.common_tags, {
    Name = "${var.project}-app-sg"
  })
}

resource "aws_security_group" "suricata" {
  name        = "${var.project}-suricata-sg"
  description = "Suricata Security Group"
  vpc_id      = aws_vpc.this.id

  tags = merge(local.common_tags, {
    Name = "${var.project}-suricata-sg"
  })
}

# ---------------------------------------------------------------------------
# Security group rules
#
# Rules live in separate resources rather than inline blocks for two reasons:
# waf-sg and app-sg reference each other, which an inline definition turns into
# a dependency cycle; and Terraform forbids mixing inline rules with standalone
# rule resources on the same group.
#
# Naming: <group>_<direction>_<peer>. The Name tag mirrors the resource name so
# a rule seen in the console can be traced straight back to the code.
# ---------------------------------------------------------------------------

resource "aws_vpc_security_group_ingress_rule" "waf_in_https" {
  security_group_id = aws_security_group.waf.id
  description       = "Public HTTPS to the boundary layer (FR-01)"

  cidr_ipv4   = "0.0.0.0/0"
  ip_protocol = "tcp"
  from_port   = 443
  to_port     = 443

  tags = merge(local.common_tags, {
    Name = "${var.project}-waf-in-https"
  })
}

# T-11: the plaintext path is kept on purpose so that per-layer detection
# coverage can be demonstrated. Registered as an accepted risk in the threat
# model (section 12). Not to be carried into a production environment.
resource "aws_vpc_security_group_ingress_rule" "waf_in_http" {
  security_group_id = aws_security_group.waf.id
  description       = "Public HTTP kept open on purpose to compare detection layers (T-11)"

  cidr_ipv4   = "0.0.0.0/0"
  ip_protocol = "tcp"
  from_port   = 80
  to_port     = 80

  tags = merge(local.common_tags, {
    Name = "${var.project}-waf-in-http"
  })
}

resource "aws_vpc_security_group_egress_rule" "waf_out_app" {
  security_group_id = aws_security_group.waf.id
  description       = "Outbound HTTPS to the app tier over the internal TLS leg (SR-08)"

  referenced_security_group_id = aws_security_group.app.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443

  tags = merge(local.common_tags, {
    Name = "${var.project}-waf-out-app"
  })
}

resource "aws_vpc_security_group_egress_rule" "waf_out_internet" {
  security_group_id = aws_security_group.waf.id
  description       = "Outbound HTTPS for session manager endpoints and patching"

  cidr_ipv4   = "0.0.0.0/0"
  ip_protocol = "tcp"
  from_port   = 443
  to_port     = 443

  tags = merge(local.common_tags, {
    Name = "${var.project}-waf-out-internet"
  })
}

# The app tier has exactly one inbound rule. Nothing reaches the application
# without passing the boundary layer first, which is what closes F2 (security
# groups left wide open in the original build).
resource "aws_vpc_security_group_ingress_rule" "app_in_waf" {
  security_group_id = aws_security_group.app.id
  description       = "HTTPS from the WAF security group only (SR-03, SR-04)"

  referenced_security_group_id = aws_security_group.waf.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443

  tags = merge(local.common_tags, {
    Name = "${var.project}-app-in-waf"
  })
}

resource "aws_vpc_security_group_egress_rule" "app_out_https" {
  security_group_id = aws_security_group.app.id
  description       = "Outbound HTTPS for session manager endpoints and packages"

  cidr_ipv4   = "0.0.0.0/0"
  ip_protocol = "tcp"
  from_port   = 443
  to_port     = 443

  tags = merge(local.common_tags, {
    Name = "${var.project}-app-out-https"
  })
}

# Known compromise, recorded in architecture section 5.2: distribution package
# repositories still serve over plaintext HTTP. Narrowing this to the mirrors
# actually in use is possible but the address ranges are not stable.
resource "aws_vpc_security_group_egress_rule" "app_out_http" {
  security_group_id = aws_security_group.app.id
  description       = "Outbound HTTP for distribution package repositories (accepted compromise)"

  cidr_ipv4   = "0.0.0.0/0"
  ip_protocol = "tcp"
  from_port   = 80
  to_port     = 80

  tags = merge(local.common_tags, {
    Name = "${var.project}-app-out-http"
  })
}

resource "aws_vpc_security_group_ingress_rule" "suricata_in_http" {
  security_group_id = aws_security_group.suricata.id
  description       = "Inbound HTTP being routed through inspection"

  cidr_ipv4   = "0.0.0.0/0"
  ip_protocol = "tcp"
  from_port   = 80
  to_port     = 80

  tags = merge(local.common_tags, {
    Name = "${var.project}-suricata-in-http"
  })
}

resource "aws_vpc_security_group_ingress_rule" "suricata_in_https" {
  security_group_id = aws_security_group.suricata.id
  description       = "Inbound HTTPS being routed through inspection"

  cidr_ipv4   = "0.0.0.0/0"
  ip_protocol = "tcp"
  from_port   = 443
  to_port     = 443

  tags = merge(local.common_tags, {
    Name = "${var.project}-suricata-in-https"
  })
}

# Outbound traffic from the app tier arrives here after the NAT gateway.
# The destination and protocol are unknown in advance, so the port cannot
# be narrowed.
resource "aws_vpc_security_group_ingress_rule" "suricata_in_nat" {
  security_group_id = aws_security_group.suricata.id
  description       = "Egress traffic from the app tier arriving via NAT"

  cidr_ipv4   = local.subnets["nat-${local.azs[0]}"].cidr
  ip_protocol = "-1"

  tags = merge(local.common_tags, {
    Name = "${var.project}-suricata-in-nat"
  })
}

# A transit instance forwards packets to arbitrary destinations, so egress
# cannot be narrowed. Managed firewall endpoints have no security group at
# all, which is why approach B carries more T-30 (lateral movement) risk than
# approach A. See architecture section 3.3.
resource "aws_vpc_security_group_egress_rule" "suricata_out_all" {
  security_group_id = aws_security_group.suricata.id
  description       = "Forwarding to arbitrary destinations; cannot be narrowed"

  cidr_ipv4   = "0.0.0.0/0"
  ip_protocol = "-1"

  tags = merge(local.common_tags, {
    Name = "${var.project}-suricata-out-all"
  })
}
