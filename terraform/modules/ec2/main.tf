# ─────────────────────────────────────────────────────────────
# [TF-EC2] Módulo EC2 — recursos seguros e inseguros
#
# Inseguros (FAIL):
#   - Security group con SSH/RDP abierto a 0.0.0.0/0
#   - Instancia sin IMDSv2
#   - Instancia con IP pública directa
#   - Volumen EBS sin encriptar
#   - Snapshot público
#
# Seguros (PASS):
#   - Security group restrictivo
#   - Instancia con IMDSv2 requerido
#   - Instancia sin IP pública
# ─────────────────────────────────────────────────────────────

variable "prefix" { type = string }
variable "vpc_id" { type = string }
variable "insecure_vpc_id" { type = string }
variable "public_subnet_id" { type = string }
variable "private_subnet_id" { type = string }
variable "tags" { type = map(string) }
variable "region" {
  type    = string
  default = "us-east-1"
}
variable "aws_profile" {
  type    = string
  default = "terraform-deploy"
}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# ── IAM Role para instancias seguras (SSM) ────────────────────
resource "aws_iam_instance_profile" "ssm" {
  name = "${var.prefix}-ssm-profile"
  role = aws_iam_role.ssm.name
}

resource "aws_iam_role" "ssm" {
  name = "${var.prefix}-ssm-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.ssm.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# ── Security group INSEGURO — SSH y RDP abiertos ──────────────
# Genera CIS-EC2-5.2 FAIL
resource "aws_security_group" "open_ssh_rdp" {
  name        = "${var.prefix}-open-ssh-rdp"
  description = "INSECURE: Open SSH and RDP - audit test"
  vpc_id      = var.vpc_id
  tags        = merge(var.tags, { Purpose = "insecure-test-open-ports" })

  ingress {
    description = "SSH open to world - INSECURE"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "RDP open to world - INSECURE"
    from_port   = 3389
    to_port     = 3389
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

# ── Security group SEGURO ─────────────────────────────────────
# Genera CIS-EC2-5.2 PASS
resource "aws_security_group" "secure" {
  name        = "${var.prefix}-secure-sg"
  description = "SECURE: No open admin ports - audit test"
  vpc_id      = var.vpc_id
  tags        = merge(var.tags, { Purpose = "secure-test-sg" })

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ── Instancia INSEGURA — sin IMDSv2, con IP pública ──────────
# Genera CIS-EC2-5.6 FAIL + WAF-EC2-PIP-01 FAIL
resource "aws_instance" "insecure_no_imdsv2" {
  ami                         = data.aws_ami.amazon_linux.id
  instance_type               = "t3.micro"
  subnet_id                   = var.public_subnet_id
  vpc_security_group_ids      = [aws_security_group.open_ssh_rdp.id]
  associate_public_ip_address = true # INSECURE: IP pública directa

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional" # INSECURE: IMDSv2 no requerido
  }

  root_block_device {
    encrypted = false # INSECURE: volumen sin encriptar
  }

  tags = merge(var.tags, {
    Name    = "${var.prefix}-insecure-no-imdsv2"
    Purpose = "insecure-test-no-imdsv2"
  })
}

# ── Instancia SEGURA — IMDSv2, sin IP pública, SSM ──────────
# Genera CIS-EC2-5.6 PASS + WAF-EC2-SSM-01 PASS
resource "aws_instance" "secure" {
  ami                         = data.aws_ami.amazon_linux.id
  instance_type               = "t3.micro"
  subnet_id                   = var.private_subnet_id
  vpc_security_group_ids      = [aws_security_group.secure.id]
  iam_instance_profile        = aws_iam_instance_profile.ssm.name
  associate_public_ip_address = false # SECURE

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required" # SECURE: IMDSv2 requerido
  }

  root_block_device {
    encrypted = true # SECURE
  }

  monitoring = true # SECURE: detailed monitoring

  tags = merge(var.tags, {
    Name    = "${var.prefix}-secure-instance"
    Purpose = "secure-test-full-config"
  })
}

# ── Volumen EBS sin encriptar ─────────────────────────────────
# Genera CIS-EC2-2.2.1-VOL FAIL
data "aws_availability_zones" "ec2_azs" {
  state = "available"
}

resource "aws_ebs_volume" "unencrypted" {
  availability_zone = data.aws_availability_zones.ec2_azs.names[0]
  size              = 1
  encrypted         = false # INSECURE
  tags = merge(var.tags, {
    Name    = "${var.prefix}-unencrypted-vol"
    Purpose = "insecure-test-unencrypted-ebs"
  })
}

# ── Snapshot público ──────────────────────────────────────────
# Genera CIS-EC2-2.2.2 FAIL
resource "aws_ebs_snapshot" "public_snap" {
  volume_id   = aws_ebs_volume.unencrypted.id
  description = "INSECURE: Public snapshot for audit testing"
  tags = merge(var.tags, {
    Name    = "${var.prefix}-public-snapshot"
    Purpose = "insecure-test-public-snapshot"
  })
}

# Hacer el snapshot público via AWS CLI
# account_id = "all" no es válido en el resource — se usa CLI directamente
resource "null_resource" "make_snapshot_public" {
  depends_on = [aws_ebs_snapshot.public_snap]

  provisioner "local-exec" {
    command = <<-EOT
      aws ec2 modify-snapshot-attribute \
        --snapshot-id ${aws_ebs_snapshot.public_snap.id} \
        --attribute createVolumePermission \
        --operation-type add \
        --group-names all \
        --region ${var.region} \
        --profile ${var.aws_profile} || true
    EOT
  }
}
