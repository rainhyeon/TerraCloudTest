// Filename: terraform.tf
terraform {
  required_version = ">= 1.0"
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

// Filename: variables.tf
variable "region" {
  description = "region"
  type        = string
  default     = "ap-northeast-2"
}


// Filename: vpc.tf
resource "aws_vpc" "cafe_vpc" {
  cidr_block           = "10.20.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "cafe_vpc"
  }
}