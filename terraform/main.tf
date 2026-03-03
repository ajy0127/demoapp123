# =============================================================================
# Demo App - ECS Fargate Deployment
# =============================================================================
# Purpose: Deploy the demo Flask web app to ECS Fargate for DAST scanning.
#          This is a separate Terraform config from the main pipeline.
#
# Author:  AJ Yawn, GRC Engineering Lead
# =============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "GRC-Demo-App"
      ManagedBy   = "Terraform"
      Owner       = "NR-Labs-GRC-Engineering"
      Environment = var.environment
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# -----------------------------------------------------------------------------
# ECR Repository (kept for CI/CD image push)
# -----------------------------------------------------------------------------
resource "aws_ecr_repository" "demo_app" {
  name                 = "${var.organization_name}-grc-demo-app"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Purpose = "GRC demo app container images"
  }
}

# -----------------------------------------------------------------------------
# Security Group — EC2 t2.micro (free tier)
# -----------------------------------------------------------------------------
resource "aws_security_group" "demo_app" {
  name        = "${var.organization_name}-grc-demo-app-sg"
  description = "Security group for GRC demo app EC2"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 5000
    to_port     = 5000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Flask app"
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound"
  }

  tags = {
    Purpose = "GRC demo app security group"
  }
}

# -----------------------------------------------------------------------------
# IAM Instance Profile — allows EC2 to pull from ECR
# -----------------------------------------------------------------------------
resource "aws_iam_role" "ec2_instance" {
  name = "${var.organization_name}-grc-demo-ec2"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = {
    Purpose = "GRC demo app EC2 instance role"
  }
}

resource "aws_iam_role_policy_attachment" "ecr_read" {
  role       = aws_iam_role.ec2_instance.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

resource "aws_iam_instance_profile" "demo_app" {
  name = "${var.organization_name}-grc-demo-ec2-profile"
  role = aws_iam_role.ec2_instance.name
}

# -----------------------------------------------------------------------------
# EC2 t2.micro — free tier (750 hrs/month for 12 months)
# -----------------------------------------------------------------------------
resource "aws_instance" "demo_app" {
  ami                    = var.ami_id
  instance_type          = "t2.micro"
  vpc_security_group_ids = [aws_security_group.demo_app.id]
  subnet_id              = var.subnet_id
  iam_instance_profile   = aws_iam_instance_profile.demo_app.name

  associate_public_ip_address = true

  user_data = base64encode(<<-EOF
    #!/bin/bash
    set -e

    # Install Docker
    dnf update -y
    dnf install -y docker
    systemctl enable docker
    systemctl start docker

    # Authenticate ECR and start app
    AWS_REGION="${data.aws_region.current.name}"
    ACCOUNT_ID="${data.aws_caller_identity.current.account_id}"
    ECR_REPO="${aws_ecr_repository.demo_app.repository_url}"

    aws ecr get-login-password --region "$AWS_REGION" | \
      docker login --username AWS --password-stdin "$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"

    # Pull and run (will retry on CI/CD pushes via cron)
    docker pull "$ECR_REPO:latest" 2>/dev/null || true
    docker run -d --restart=always -p 5000:5000 \
      -e ENVIRONMENT=${var.environment} \
      --name grc-demo-app \
      "$ECR_REPO:latest" 2>/dev/null || true

    # Cron job to auto-pull latest image on redeploy
    echo "*/5 * * * * root docker pull $ECR_REPO:latest && docker stop grc-demo-app; docker rm grc-demo-app; docker run -d --restart=always -p 5000:5000 -e ENVIRONMENT=${var.environment} --name grc-demo-app $ECR_REPO:latest" \
      > /etc/cron.d/grc-demo-redeploy
  EOF
  )

  tags = {
    Name    = "${var.organization_name}-grc-demo-app"
    Purpose = "GRC demo app host - free tier t2.micro"
  }
}

# -----------------------------------------------------------------------------
# Elastic IP — stable URL for DAST scanning
# -----------------------------------------------------------------------------
resource "aws_eip" "demo_app" {
  instance = aws_instance.demo_app.id
  domain   = "vpc"

  tags = {
    Purpose = "GRC demo app stable public IP"
  }
}
