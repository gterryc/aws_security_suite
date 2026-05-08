# ─────────────────────────────────────────────────────────────
# [TF-RDS] Módulo RDS — instancias seguras e inseguras
#
# Inseguros (FAIL):
#   - DB pública (publicly_accessible = true)
#   - DB sin encriptación
#   - DB sin backup retention
#   - DB sin deletion protection
#
# Seguros (PASS):
#   - DB privada, encriptada, con backup y deletion protection
# ─────────────────────────────────────────────────────────────

variable "prefix"              { type = string }
variable "vpc_id"              { type = string }
variable "insecure_vpc_id"     { 
  type = string 
  default = "" 
}
variable "private_subnet_ids"  { type = list(string) }
variable "public_subnet_ids"   { type = list(string) }
variable "insecure_subnet_ids" { 
  type = list(string)
  default = [] 
}
variable "db_password"         { 
  type = string
  sensitive = true 
}
variable "tags"                { type = map(string) }
variable "region"              { 
  type = string
  default = "us-east-1" 
}
variable "aws_profile"         { 
  type = string
  default = "terraform-deploy" 
}

# ── Subnet groups ─────────────────────────────────────────────
resource "aws_db_subnet_group" "private" {
  name       = "${var.prefix}-private-db-subnet"
  subnet_ids = var.private_subnet_ids
  tags       = merge(var.tags, { Purpose = "secure-db-subnet-group" })
}

resource "aws_db_subnet_group" "public" {
  name       = "${var.prefix}-public-db-subnet"
  subnet_ids = length(var.insecure_subnet_ids) > 0 ? var.insecure_subnet_ids : var.public_subnet_ids
  tags       = merge(var.tags, { Purpose = "insecure-db-subnet-group" })
}

# ── Security groups para RDS ──────────────────────────────────
resource "aws_security_group" "db_secure" {
  name        = "${var.prefix}-db-secure-sg"
  description = "SECURE: Private DB access only"
  vpc_id      = var.vpc_id
  tags        = merge(var.tags, { Purpose = "secure-db-sg" })

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}

resource "aws_security_group" "db_insecure" {
  name        = "${var.prefix}-db-insecure-sg"
  description = "INSECURE: Open DB access"
  vpc_id      = var.insecure_vpc_id != "" ? var.insecure_vpc_id : var.vpc_id
  tags        = merge(var.tags, { Purpose = "insecure-db-sg" })

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]   # INSECURE
  }
}

# ── DB INSEGURA — pública, sin backup, sin encriptación ───────
# Genera: CIS-RDS-2.3.2 FAIL, CIS-RDS-2.3.1 FAIL
#         CIS-RDS-2.3.1-BCK FAIL, WAF-RDS-DEL-01 FAIL
resource "aws_db_instance" "insecure" {
  identifier              = "${var.prefix}-insecure-db"
  engine                  = "mysql"
  engine_version          = "8.0"
  instance_class          = "db.t3.micro"
  allocated_storage       = 5
  db_name                 = "auditdb"
  username                = "admin"
  password                = var.db_password
  db_subnet_group_name    = aws_db_subnet_group.public.name
  vpc_security_group_ids  = [aws_security_group.db_insecure.id]

  publicly_accessible     = true    # INSECURE: acceso público
  storage_encrypted       = false   # INSECURE: sin encriptación
  backup_retention_period = 0       # INSECURE: sin backups
  deletion_protection     = false   # INSECURE: sin protección
  multi_az                = false   # INSECURE: sin alta disponibilidad
  skip_final_snapshot     = true

  tags = merge(var.tags, { Purpose = "insecure-test-db" })
}

# ── DB SEGURA — privada, encriptada, con backup y protección ──
# Genera: CIS-RDS-2.3.2 PASS, CIS-RDS-2.3.1 PASS
#         CIS-RDS-2.3.1-BCK PASS, WAF-RDS-DEL-01 PASS
resource "aws_db_instance" "secure" {
  identifier              = "${var.prefix}-secure-db"
  engine                  = "mysql"
  engine_version          = "8.0"
  instance_class          = "db.t3.micro"
  allocated_storage       = 5
  db_name                 = "auditdb"
  username                = "admin"
  password                = var.db_password
  db_subnet_group_name    = aws_db_subnet_group.private.name
  vpc_security_group_ids  = [aws_security_group.db_secure.id]

  publicly_accessible          = false   # SECURE
  storage_encrypted            = true    # SECURE
  backup_retention_period      = 7       # SECURE
  deletion_protection          = true    # SECURE
  multi_az                     = true    # SECURE
  auto_minor_version_upgrade   = true    # SECURE
  performance_insights_enabled = false   # db.t3.micro no soporta PI
  skip_final_snapshot          = true

  enabled_cloudwatch_logs_exports = ["audit", "error", "general", "slowquery"]  # SECURE

  tags = merge(var.tags, { Purpose = "secure-test-db" })
}

# ── Snapshot RDS público ──────────────────────────────────────
# Genera CIS-RDS-2.3.3 FAIL
resource "aws_db_snapshot" "public_snap" {
  db_instance_identifier = aws_db_instance.insecure.identifier
  db_snapshot_identifier = "${var.prefix}-public-snapshot"
  tags                   = merge(var.tags, { Purpose = "insecure-test-public-snapshot" })
}

# Hacer el snapshot público via AWS CLI después del apply
# usando null_resource + local-exec
resource "null_resource" "make_snapshot_public" {
  depends_on = [aws_db_snapshot.public_snap]

  provisioner "local-exec" {
    command = <<-EOT
      aws rds modify-db-snapshot-attribute \
        --db-snapshot-identifier ${aws_db_snapshot.public_snap.db_snapshot_identifier} \
        --attribute-name restore \
        --values-to-add '["all"]' \
        --region ${var.region} \
        --profile ${var.aws_profile} || true
    EOT
  }
}
