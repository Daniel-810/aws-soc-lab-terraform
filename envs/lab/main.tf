terraform {
  required_version = ">=1.10"

  backend "s3" {}

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    http = {
      source  = "hashicorp/http"
      version = "~> 3.0"
    }
  }
}

provider "aws" {
  region = "ap-northeast-2"
}

# The operator's public address, looked up at plan time so it never has to
# be written into the repository (SR-10). The lab is run and tested from the
# same machine, so this is also the only source that needs to reach the WAF.
data "http" "operator_ip" {
  url = "https://checkip.amazonaws.com"

  lifecycle {
    postcondition {
      condition     = self.status_code == 200 && can(cidrhost("${chomp(self.response_body)}/32", 0))
      error_message = "Could not determine the operator's public IPv4 address."
    }
  }
}

module "network" {
  source = "../../modules/network"

  project           = "soc-lab"
  vpc_cidr          = "10.20.0.0/16"
  az_count          = 1
  waf_ingress_cidrs = ["${chomp(data.http.operator_ip.response_body)}/32"]

  # The firewall is created in the network's subnets and the network routes
  # through the firewall. Terraform resolves this per resource, so the
  # modules can feed each other without a cycle (ADR-024). Only the deployed
  # approach yields a target; one() turns the other's empty list into null.
  inspection_enabled     = var.route_through_firewall
  inspection_endpoint_id = one([for m in module.firewall_managed : m.endpoint_ids[local.az]])
  inspection_eni_id      = one(module.firewall_oss[*].eni_id)
}

module "secrets" {
  source = "../../modules/secrets"

  project = "soc-lab"
}

module "web" {
  source = "../../modules/web"

  project           = "soc-lab"
  subnet_id         = module.network.subnet_ids["app-ap-northeast-2a"]
  security_group_id = module.network.security_group_ids["app"]
  instance_type     = "t3.micro"
  app_image         = "bkimminich/juice-shop:v18.0.0"
  ca_secret_arn     = module.secrets.ca_cert_secret_arn
  time_sync         = local.time_sync
}

module "waf" {
  source = "../../modules/waf"

  project           = "soc-lab"
  subnet_id         = module.network.subnet_ids["waf-ap-northeast-2a"]
  security_group_id = module.network.security_group_ids["waf"]
  instance_type     = "t3.micro"
  app_private_ip    = module.web.private_ip
  ca_secret_arn     = module.secrets.ca_cert_secret_arn
  cwagent_install   = local.cwagent_install
  time_sync         = local.time_sync
}

# Both approaches load one rule file with one notion of internal, so a
# difference between them comes from how they are run (ADR-022).
locals {
  az       = module.network.availability_zones[0]
  rules    = file("${path.module}/../../rules/attacks.rules")
  home_net = "10.20.0.0/16"

  # One verified installer for every instance that ships logs (ADR-028).
  cwagent_install = file("${path.module}/../../scripts/install-cloudwatch-agent.sh")

  # Every instance syncs to the link-local time service only (ADR-031).
  time_sync = file("${path.module}/../../scripts/use-amazon-time-sync.sh")
}

# Approach A. Only the approach selected by firewall_mode is created: the two
# are never compared at the same time, and the managed endpoint bills by the
# hour whether or not traffic is routed to it (ADR-026).
module "firewall_managed" {
  source = "../../modules/firewall_managed"
  count  = var.firewall_mode == "managed" ? 1 : 0

  project    = "soc-lab"
  vpc_id     = module.network.vpc_id
  subnet_ids = [module.network.subnet_ids["inspect_mgd-${local.az}"]]
  home_net   = local.home_net
  rules      = local.rules
}

# Approach B.
module "firewall_oss" {
  source = "../../modules/firewall_oss"
  count  = var.firewall_mode == "oss" ? 1 : 0

  project           = "soc-lab"
  subnet_id         = module.network.subnet_ids["inspect_oss-${local.az}"]
  security_group_id = module.network.security_group_ids["suricata"]
  home_net          = local.home_net
  rules             = local.rules
  cwagent_install   = local.cwagent_install
  time_sync         = local.time_sync
}

# Every layer's log in one place and on one screen (FR-05, FR-06). The
# IPS alert group follows whichever approach is deployed.
module "observability" {
  source = "../../modules/observability"

  project = "soc-lab"
  vpc_id  = module.network.vpc_id
  ips_alert_log_groups = concat(
    [for m in module.firewall_managed : m.alert_log_group],
    [for m in module.firewall_oss : m.log_group],
  )
  waf_log_group = module.waf.log_group
}
