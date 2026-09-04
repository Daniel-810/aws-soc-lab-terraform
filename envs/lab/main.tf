terraform {
  required_version = ">=1.10"

  backend "s3" {}

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = "ap-northeast-2"
}

module "network" {
  source = "../../modules/network"

  project  = "soc-lab"
  vpc_cidr = "10.20.0.0/16"
  az_count = 1
}

module "web" {
  source = "../../modules/web"

  project           = "soc-lab"
  subnet_id         = module.network.subnet_ids["app-ap-northeast-2a"]
  security_group_id = module.network.security_group_ids["app"]
  instance_type     = "t3.micro"
  app_image         = "bkimminich/juice-shop:v18.0.0"
}
