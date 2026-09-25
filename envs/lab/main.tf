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
  # through the firewall's endpoint. Terraform resolves this per resource, so
  # the two modules can feed each other without a cycle.
  inspection_enabled     = var.route_through_firewall
  inspection_endpoint_id = module.firewall.endpoint_ids[module.network.availability_zones[0]]
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
}

module "waf" {
  source = "../../modules/waf"

  project           = "soc-lab"
  subnet_id         = module.network.subnet_ids["waf-ap-northeast-2a"]
  security_group_id = module.network.security_group_ids["waf"]
  instance_type     = "t3.micro"
  app_private_ip    = module.web.private_ip
  ca_secret_arn     = module.secrets.ca_cert_secret_arn
}

module "firewall" {
  source = "../../modules/firewall_managed"

  project    = "soc-lab"
  vpc_id     = module.network.vpc_id
  subnet_ids = [module.network.subnet_ids["inspect_mgd-${module.network.availability_zones[0]}"]]
  home_net   = "10.20.0.0/16"
}
