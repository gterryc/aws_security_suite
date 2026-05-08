# ─────────────────────────────────────────────────────────────
# [TF-MAIN] AWS Security Audit — Test Infrastructure
# Despliega recursos seguros e inseguros para validar la suite
# ─────────────────────────────────────────────────────────────

# ── Data sources ──────────────────────────────────────────────
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ── Módulos ───────────────────────────────────────────────────

module "vpc" {
  source = "./modules/vpc"
  prefix = var.prefix
  tags   = var.tags
}

module "iam" {
  source     = "./modules/iam"
  prefix     = var.prefix
  account_id = data.aws_caller_identity.current.account_id
  tags       = var.tags
}

module "s3" {
  source     = "./modules/s3"
  prefix     = var.prefix
  account_id = data.aws_caller_identity.current.account_id
  tags       = var.tags
}

module "ec2" {
  count  = var.deploy_ec2 ? 1 : 0
  source = "./modules/ec2"
  prefix = var.prefix

  vpc_id             = module.vpc.vpc_secure_id
  insecure_vpc_id    = module.vpc.vpc_insecure_id
  public_subnet_id   = module.vpc.public_subnet_id
  private_subnet_id  = module.vpc.private_subnet_id
  region             = var.aws_region
  aws_profile        = var.aws_profile

  tags = var.tags
}

module "rds" {
  count  = var.deploy_rds ? 1 : 0
  source = "./modules/rds"
  prefix = var.prefix

  vpc_id              = module.vpc.vpc_secure_id
  insecure_vpc_id     = module.vpc.vpc_insecure_id
  private_subnet_ids  = module.vpc.private_subnet_ids
  public_subnet_ids   = module.vpc.public_subnet_ids
  insecure_subnet_ids = module.vpc.insecure_subnet_ids

  db_password  = var.rds_password
  region       = var.aws_region
  aws_profile  = var.aws_profile
  tags         = var.tags
}

module "guardduty" {
  source = "./modules/guardduty"
  prefix = var.prefix
  tags   = var.tags
}
