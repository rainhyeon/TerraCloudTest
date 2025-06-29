// Filename: variables.tf
variable "region" {
  description = "region"
  default     = "ap-northeast-2"
}

// Filename: terraform.tf
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

// Filename: vpc.tf
resource "aws_vpc" "this" {
  cidr_block           = "10.30.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "hat_vpc"
  }
}
