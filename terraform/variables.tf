# ─────────────────────────────────────────────────────────────
# [TF-VAR] Variables de entrada para el entorno de prueba
# ─────────────────────────────────────────────────────────────

variable "aws_region" {
  description = "AWS region where test resources will be deployed"
  type        = string
  default     = "us-east-1"
}

variable "aws_profile" {
  description = "AWS CLI profile to use for deployment"
  type        = string
  default     = "audit-role"
}

variable "prefix" {
  description = "Prefix for all test resources — used for easy identification and cleanup"
  type        = string
  default     = "audit-test"
}

variable "tags" {
  description = "Common tags applied to all resources"
  type        = map(string)
  default = {
    Project     = "aws-security-audit"
    Environment = "test"
    ManagedBy   = "terraform"
    Purpose     = "security-audit-validation"
  }
}

variable "deploy_rds" {
  description = "Set to true to deploy RDS test instances (adds ~$0.034/hr cost)"
  type        = bool
  default     = true
}

variable "deploy_ec2" {
  description = "Set to true to deploy EC2 test instances (adds ~$0.02/hr cost)"
  type        = bool
  default     = true
}

variable "rds_password" {
  description = "Master password for RDS test instances"
  type        = string
  sensitive   = true
  default     = "AuditTest2024!"
}

variable "allowed_cidr" {
  description = "CIDR block allowed for SSH access to test instances (your IP)"
  type        = string
  default     = "0.0.0.0/0" # Overridden intentionally to test open SG detection
}
