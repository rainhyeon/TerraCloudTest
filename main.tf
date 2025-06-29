variable "region" {
  description = "region"
  default     = "ap-northeast-2"
}

variable "db_name" {
  description = "DB name"
  default     = "cafe_db"
}

variable "db_username" {
  description = "master user"
  default     = "admin"
}

variable "db_password" {
  description = "master password"
  sensitive   = true
  default     = "password"
}

variable "domain_name" {
  description = "Domain name"
  default     = "rainhyeon.store"
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
