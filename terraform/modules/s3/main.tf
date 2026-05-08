# ─────────────────────────────────────────────────────────────
# [TF-S3] Módulo S3 — buckets seguros e inseguros
#
# Inseguros (FAIL):
#   - Sin encriptación SSE
#   - Sin block public access
#   - Sin access logging
#   - Sin versionado
#   - Sin SSL policy
#
# Seguros (PASS):
#   - Totalmente configurado con todas las mejores prácticas
# ─────────────────────────────────────────────────────────────

variable "prefix" { type = string }
variable "account_id" { type = string }
variable "tags" { type = map(string) }

resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  suffix = random_id.suffix.hex
}

# ── Bucket de logs (necesario para logging de otros buckets) ──
resource "aws_s3_bucket" "logs" {
  bucket        = "${var.prefix}-logs-${local.suffix}"
  force_destroy = true
  tags          = merge(var.tags, { Purpose = "audit-test-log-bucket" })
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# ── Bucket INSEGURO 1 — sin encriptación ──────────────────────
# Genera CIS-S3-2.1.1-ENC FAIL
resource "aws_s3_bucket" "no_encryption" {
  bucket        = "${var.prefix}-no-enc-${local.suffix}"
  force_destroy = true
  tags          = merge(var.tags, { Purpose = "insecure-test-no-encryption" })
}

resource "aws_s3_bucket_public_access_block" "no_encryption" {
  bucket                  = aws_s3_bucket.no_encryption.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}
# Deliberadamente sin aws_s3_bucket_server_side_encryption_configuration

# ── Bucket INSEGURO 2 — sin block public access ───────────────
# Genera CIS-S3-2.1.1 FAIL
resource "aws_s3_bucket" "no_public_block" {
  bucket        = "${var.prefix}-no-block-${local.suffix}"
  force_destroy = true
  tags          = merge(var.tags, { Purpose = "insecure-test-no-public-block" })
}

resource "aws_s3_bucket_public_access_block" "no_public_block" {
  bucket                  = aws_s3_bucket.no_public_block.id
  block_public_acls       = false # INSECURE
  ignore_public_acls      = false # INSECURE
  block_public_policy     = false # INSECURE
  restrict_public_buckets = false # INSECURE
}

# ── Bucket INSEGURO 3 — sin logging ──────────────────────────
# Genera CIS-S3-2.6 FAIL
resource "aws_s3_bucket" "no_logging" {
  bucket        = "${var.prefix}-no-log-${local.suffix}"
  force_destroy = true
  tags          = merge(var.tags, { Purpose = "insecure-test-no-logging" })
}

resource "aws_s3_bucket_public_access_block" "no_logging" {
  bucket                  = aws_s3_bucket.no_logging.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "no_logging" {
  bucket = aws_s3_bucket.no_logging.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}
# Deliberadamente sin aws_s3_bucket_logging

# ── Bucket INSEGURO 4 — sin versionado ───────────────────────
# Genera WAF-S3-VER-01 FAIL
resource "aws_s3_bucket" "no_versioning" {
  bucket        = "${var.prefix}-no-ver-${local.suffix}"
  force_destroy = true
  tags          = merge(var.tags, { Purpose = "insecure-test-no-versioning" })
}

resource "aws_s3_bucket_public_access_block" "no_versioning" {
  bucket                  = aws_s3_bucket.no_versioning.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "no_versioning" {
  bucket = aws_s3_bucket.no_versioning.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}
# Deliberadamente sin aws_s3_bucket_versioning

# ── Bucket SEGURO — totalmente configurado ────────────────────
# Genera PASS en todos los controles S3
resource "aws_s3_bucket" "secure" {
  bucket        = "${var.prefix}-secure-${local.suffix}"
  force_destroy = true
  tags          = merge(var.tags, { Purpose = "secure-test-full-config" })
}

resource "aws_s3_bucket_ownership_controls" "secure" {
  bucket = aws_s3_bucket.secure.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_public_access_block" "secure" {
  bucket                  = aws_s3_bucket.secure.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure" {
  bucket = aws_s3_bucket.secure.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_versioning" "secure" {
  bucket = aws_s3_bucket.secure.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_logging" "secure" {
  bucket        = aws_s3_bucket.secure.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "secure-bucket-logs/"
}

resource "aws_s3_bucket_lifecycle_configuration" "secure" {
  bucket = aws_s3_bucket.secure.id
  rule {
    id     = "expire-old-versions"
    status = "Enabled"
    noncurrent_version_expiration { noncurrent_days = 90 }
    filter { prefix = "" }
  }
}

resource "aws_s3_bucket_policy" "secure_ssl" {
  bucket = aws_s3_bucket.secure.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyNonSSL"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        aws_s3_bucket.secure.arn,
        "${aws_s3_bucket.secure.arn}/*",
      ]
      Condition = {
        Bool = { "aws:SecureTransport" = "false" }
      }
    }]
  })
}
