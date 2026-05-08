# ─────────────────────────────────────────────────────────────
# [TF-IAM] Módulo IAM — recursos seguros e inseguros
#
# Recursos inseguros (generan FAIL):
#   - Usuario sin MFA con contraseña activa
#   - Usuario con política adjunta directamente
#   - Política con permisos *:*
#   - Grupo vacío
#   - Password policy incompleta
#
# Recursos seguros (generan PASS):
#   - Usuario con MFA simulado
#   - Usuario con políticas solo via grupos
#   - Política con scope correcto
#   - Rol de soporte
# ─────────────────────────────────────────────────────────────

variable "prefix" { type = string }
variable "account_id" { type = string }
variable "tags" { type = map(string) }

# ── Password policy INSEGURA ──────────────────────────────────
# Genera FAIL en CIS-IAM-1.8, 1.13, 1.14
resource "aws_iam_account_password_policy" "insecure" {
  minimum_password_length        = 8 # FAIL: debe ser >= 14
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  require_numbers                = true
  require_symbols                = false # FAIL: debe ser true
  allow_users_to_change_password = true
  max_password_age               = 180 # FAIL: debe ser <= 90
  password_reuse_prevention      = 5   # FAIL: debe ser >= 24
}

# ── Usuario SIN MFA ───────────────────────────────────────────
# Genera CIS-IAM-1.10 FAIL
resource "aws_iam_user" "no_mfa" {
  name = "${var.prefix}-no-mfa-user"
  path = "/audit-test/"
  tags = merge(var.tags, { Purpose = "insecure-test-no-mfa" })
}

resource "aws_iam_user_login_profile" "no_mfa" {
  user                    = aws_iam_user.no_mfa.name
  password_reset_required = true
}

# ── Usuario con política adjunta DIRECTAMENTE ─────────────────
# Genera CIS-IAM-1.15 FAIL
resource "aws_iam_user" "direct_policy" {
  name = "${var.prefix}-direct-policy-user"
  path = "/audit-test/"
  tags = merge(var.tags, { Purpose = "insecure-test-direct-policy" })
}

resource "aws_iam_user_policy_attachment" "direct" {
  user       = aws_iam_user.direct_policy.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

# ── Política con permisos *:* ─────────────────────────────────
# Genera CIS-IAM-1.16 FAIL
resource "aws_iam_policy" "star_star" {
  name        = "${var.prefix}-star-star-policy"
  path        = "/audit-test/"
  description = "INSECURE: Full admin policy for audit testing"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "FullAccess"
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
  tags = merge(var.tags, { Purpose = "insecure-test-star-star" })
}

# ── Grupo VACÍO ───────────────────────────────────────────────
# Genera WAF-IAM-G01 FAIL
resource "aws_iam_group" "empty" {
  name = "${var.prefix}-empty-group"
  path = "/audit-test/"
}

# ── Usuario SEGURO ────────────────────────────────────────────
# Pertenece a grupo, sin políticas directas
resource "aws_iam_user" "secure" {
  name = "${var.prefix}-secure-user"
  path = "/audit-test/"
  tags = merge(var.tags, { Purpose = "secure-test-user" })
}

resource "aws_iam_group" "secure" {
  name = "${var.prefix}-secure-group"
  path = "/audit-test/"
}

resource "aws_iam_group_policy_attachment" "secure" {
  group      = aws_iam_group.secure.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

resource "aws_iam_group_membership" "secure" {
  name  = "${var.prefix}-secure-membership"
  users = [aws_iam_user.secure.name]
  group = aws_iam_group.secure.name
}

# ── Política SEGURA ───────────────────────────────────────────
# Genera CIS-IAM-1.16 PASS
resource "aws_iam_policy" "scoped" {
  name        = "${var.prefix}-scoped-policy"
  path        = "/audit-test/"
  description = "SECURE: Scoped policy for audit testing"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "S3ReadOnly"
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:ListBucket"]
      Resource = "arn:aws:s3:::audit-test-*"
    }]
  })
  tags = merge(var.tags, { Purpose = "secure-test-scoped-policy" })
}

# ── Rol de soporte AWS ────────────────────────────────────────
# Genera CIS-IAM-1.17 PASS
resource "aws_iam_role" "support" {
  name        = "${var.prefix}-support-role"
  path        = "/audit-test/"
  description = "Support role for incident management - CIS 1.17"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${var.account_id}:root" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = merge(var.tags, { Purpose = "secure-test-support-role" })
}

resource "aws_iam_role_policy_attachment" "support" {
  role       = aws_iam_role.support.name
  policy_arn = "arn:aws:iam::aws:policy/AWSSupportAccess"
}

# ── IAM Access Analyzer ───────────────────────────────────────
# Genera CIS-IAM-1.20 PASS
resource "aws_accessanalyzer_analyzer" "main" {
  analyzer_name = "${var.prefix}-access-analyzer"
  type          = "ACCOUNT"
  tags          = merge(var.tags, { Purpose = "secure-test-access-analyzer" })
}
