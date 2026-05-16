# Guardian Pi — Terraform Infrastructure (AWS)
# Production deployment on ECS Fargate with RDS and ElastiCache

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
  backend "s3" {
    bucket = "guardian-pi-terraform-state"
    key    = "prod/terraform.tfstate"
    region = "us-east-1"
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  default = "us-east-1"
}
variable "environment" {
  default = "production"
}

# ── VPC ────────────────────────────────────────────────────────
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  tags = { Name = "guardian-pi-vpc", Environment = var.environment }
}

resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "${var.aws_region}a"
  tags = { Name = "guardian-private-a" }
}

resource "aws_subnet" "private_b" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "${var.aws_region}b"
  tags = { Name = "guardian-private-b" }
}

resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.10.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true
  tags = { Name = "guardian-public-a" }
}

# ── RDS PostgreSQL ─────────────────────────────────────────────
resource "aws_db_instance" "guardian_db" {
  identifier             = "guardian-pi-db"
  engine                 = "postgres"
  engine_version         = "16"
  instance_class         = "db.t3.medium"
  allocated_storage      = 50
  storage_encrypted      = true
  db_name                = "guardianpi"
  username               = "guardian_admin"
  password               = var.db_password
  vpc_security_group_ids = [aws_security_group.db.id]
  db_subnet_group_name   = aws_db_subnet_group.main.name
  multi_az               = true
  backup_retention_period = 30
  deletion_protection    = true
  skip_final_snapshot    = false
  tags = { Name = "guardian-pi-rds", Environment = var.environment }
}

variable "db_password" {
  sensitive = true
}

resource "aws_db_subnet_group" "main" {
  name       = "guardian-db-subnet"
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_b.id]
}

resource "aws_security_group" "db" {
  name   = "guardian-db-sg"
  vpc_id = aws_vpc.main.id
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.api.id]
  }
}

# ── ElastiCache Redis ──────────────────────────────────────────
resource "aws_elasticache_cluster" "guardian_redis" {
  cluster_id           = "guardian-pi-redis"
  engine               = "redis"
  engine_version       = "7.0"
  node_type            = "cache.t3.micro"
  num_cache_nodes      = 1
  port                 = 6379
  security_group_ids   = [aws_security_group.redis.id]
  subnet_group_name    = aws_elasticache_subnet_group.main.name
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  tags = { Name = "guardian-pi-redis" }
}

resource "aws_elasticache_subnet_group" "main" {
  name       = "guardian-redis-subnet"
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_b.id]
}

resource "aws_security_group" "redis" {
  name   = "guardian-redis-sg"
  vpc_id = aws_vpc.main.id
  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.api.id]
  }
}

# ── ECS Fargate ────────────────────────────────────────────────
resource "aws_security_group" "api" {
  name   = "guardian-api-sg"
  vpc_id = aws_vpc.main.id
  ingress {
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_ecs_cluster" "guardian" {
  name = "guardian-pi-cluster"
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

# ── GuardDuty ──────────────────────────────────────────────────
resource "aws_guardduty_detector" "main" {
  enable = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

# ── Security Hub ───────────────────────────────────────────────
resource "aws_securityhub_account" "main" {}

# ── CloudTrail ─────────────────────────────────────────────────
resource "aws_cloudtrail" "guardian" {
  name                          = "guardian-pi-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
}

resource "aws_s3_bucket" "cloudtrail" {
  bucket        = "guardian-pi-cloudtrail-logs"
  force_destroy = false
}

# ── WAF ────────────────────────────────────────────────────────
resource "aws_wafv2_web_acl" "guardian" {
  name        = "guardian-pi-waf"
  scope       = "REGIONAL"
  default_action { allow {} }
  rule {
    name     = "rate-limit"
    priority = 1
    action { block {} }
    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "guardian-rate-limit"
    }
  }
  visibility_config {
    sampled_requests_enabled   = true
    cloudwatch_metrics_enabled = true
    metric_name                = "guardian-waf"
  }
}

output "vpc_id" { value = aws_vpc.main.id }
output "guardduty_detector_id" { value = aws_guardduty_detector.main.id }
