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
