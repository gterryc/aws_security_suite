# ─────────────────────────────────────────────────────────────
# [TF-OUT] Outputs del entorno de prueba
# Útiles para verificar los recursos desplegados
# ─────────────────────────────────────────────────────────────

output "account_id" {
  description = "AWS Account ID"
  value       = data.aws_caller_identity.current.account_id
}

output "region" {
  description = "AWS Region"
  value       = data.aws_region.current.id
}

# ── VPC ───────────────────────────────────────────────────────
output "vpc_secure_id" {
  description = "Secure VPC ID (with flow logs) — expects PASS"
  value       = module.vpc.vpc_secure_id
}

output "vpc_insecure_id" {
  description = "Insecure VPC ID (no flow logs) — expects CIS-VPC-3.9 FAIL"
  value       = module.vpc.vpc_insecure_id
}

# ── IAM ───────────────────────────────────────────────────────
output "iam_insecure_user_no_mfa" {
  description = "User without MFA — expects CIS-IAM-1.10 FAIL"
  value       = module.iam.insecure_user_no_mfa_arn
}

output "iam_insecure_star_star_policy" {
  description = "Policy with *:* — expects CIS-IAM-1.16 FAIL"
  value       = module.iam.insecure_policy_star_star
}

output "iam_access_analyzer_arn" {
  description = "IAM Access Analyzer — expects CIS-IAM-1.20 PASS"
  value       = module.iam.access_analyzer_arn
}

# ── S3 ────────────────────────────────────────────────────────
output "s3_insecure_no_encryption" {
  description = "Bucket without SSE — expects CIS-S3-2.1.1-ENC FAIL"
  value       = module.s3.insecure_bucket_no_encryption
}

output "s3_insecure_no_public_block" {
  description = "Bucket without public block — expects CIS-S3-2.1.1 FAIL"
  value       = module.s3.insecure_bucket_no_block
}

output "s3_secure_bucket" {
  description = "Fully configured bucket — expects all PASS"
  value       = module.s3.secure_bucket
}

# ── EC2 ───────────────────────────────────────────────────────
output "ec2_insecure_instance_id" {
  description = "Instance without IMDSv2 — expects CIS-EC2-5.6 FAIL"
  value       = var.deploy_ec2 ? module.ec2[0].insecure_instance_id : "not deployed"
}

output "ec2_secure_instance_id" {
  description = "Secure instance with SSM — expects all PASS"
  value       = var.deploy_ec2 ? module.ec2[0].secure_instance_id : "not deployed"
}

output "ec2_insecure_sg_id" {
  description = "Security group with open SSH/RDP — expects CIS-EC2-5.2 FAIL"
  value       = var.deploy_ec2 ? module.ec2[0].insecure_sg_id : "not deployed"
}

# ── RDS ───────────────────────────────────────────────────────
output "rds_insecure_db_id" {
  description = "Public RDS instance — expects CIS-RDS-2.3.2 FAIL"
  value       = var.deploy_rds ? module.rds[0].insecure_db_id : "not deployed"
}

output "rds_secure_db_id" {
  description = "Private encrypted RDS instance — expects all PASS"
  value       = var.deploy_rds ? module.rds[0].secure_db_id : "not deployed"
}

# ── GuardDuty ─────────────────────────────────────────────────
output "guardduty_detector_id" {
  description = "GuardDuty detector — expects CIS-GD-3.1 PASS, WAF-GD-EXP-01 FAIL"
  value       = module.guardduty.detector_id
}

# ── Resumen para validación ───────────────────────────────────
output "expected_fails" {
  description = "Controls expected to FAIL after deployment"
  value = [
    "CIS-VPC-3.9   — insecure VPC has no flow logs",
    "WAF-EC2-SUB-01 — insecure subnet auto-assigns public IPs",
    "CIS-EC2-5.1   — insecure NACL allows port 22/3389 from 0.0.0.0/0",
    "CIS-IAM-1.8   — password min length < 14",
    "CIS-IAM-1.13  — password max age > 90 days",
    "CIS-IAM-1.14  — password reuse prevention < 24",
    "CIS-IAM-1.10  — user without MFA",
    "CIS-IAM-1.15  — user with directly attached policy",
    "CIS-IAM-1.16  — policy with *:* permissions",
    "WAF-IAM-G01   — empty IAM group",
    "CIS-S3-2.1.1-ENC — bucket without SSE",
    "CIS-S3-2.1.1  — bucket without block public access",
    "CIS-S3-2.6    — bucket without access logging",
    "WAF-S3-VER-01 — bucket without versioning",
    "CIS-EC2-5.2   — security group open SSH/RDP to world",
    "CIS-EC2-5.6   — instance without IMDSv2",
    "CIS-EC2-2.2.1-VOL — unencrypted EBS volume",
    "CIS-EC2-2.2.2 — public EBS snapshot",
    "CIS-RDS-2.3.2 — publicly accessible RDS instance",
    "CIS-RDS-2.3.1 — unencrypted RDS instance",
    "CIS-RDS-2.3.1-BCK — RDS backup retention = 0",
    "WAF-RDS-DEL-01 — RDS without deletion protection",
    "CIS-RDS-2.3.3 — public RDS snapshot",
    "WAF-GD-EXP-01 — GuardDuty without findings export",
    "WAF-GD-PPL-01 — GuardDuty protection plans disabled",
  ]
}

