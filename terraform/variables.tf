# =============================================================================
# Demo App Variables
# =============================================================================

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "dev"
}

variable "organization_name" {
  description = "Organization name for resource naming"
  type        = string
  default     = "nrlabs"
}

variable "vpc_id" {
  description = "VPC ID to deploy the demo app into"
  type        = string
  default     = "vpc-0f8962c2c286036ae"
}

variable "subnet_id" {
  description = "Subnet ID for the EC2 instance"
  type        = string
  default     = "subnet-09e33a889352da68a"
}

variable "ami_id" {
  description = "Amazon Linux 2023 AMI ID (us-east-1)"
  type        = string
  default     = "ami-0f3caa1cf4417e51b"
}
