# ─────────────────────────────────────────────────────────────
# [TF-VPC] Módulo VPC — recursos seguros e inseguros
#
# Recursos inseguros (generan FAIL):
#   - VPC sin flow logs
#   - Subnet con auto-assign public IP
#   - NACL con puerto 22 abierto a 0.0.0.0/0
#
# Recursos seguros (generan PASS):
#   - VPC con flow logs habilitados (ALL traffic)
#   - Subnets privadas sin auto-assign IP
#   - NACL restrictivo
# ─────────────────────────────────────────────────────────────

variable "prefix" { type = string }
variable "tags" { type = map(string) }

data "aws_availability_zones" "available" {
  state = "available"
}

# ── CloudWatch Log Group para flow logs ───────────────────────
resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc/${var.prefix}-flow-logs"
  retention_in_days = 30
  tags              = var.tags
}

resource "aws_iam_role" "flow_logs" {
  name = "${var.prefix}-flow-logs-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "${var.prefix}-flow-logs-policy"
  role = aws_iam_role.flow_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
      ]
      Resource = "*"
    }]
  })
}

# ── VPC SEGURA — con flow logs ────────────────────────────────
resource "aws_vpc" "secure" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = merge(var.tags, { Name = "${var.prefix}-secure-vpc" })
}

resource "aws_flow_log" "secure" {
  vpc_id          = aws_vpc.secure.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.flow_logs.arn
  log_destination = aws_cloudwatch_log_group.flow_logs.arn
  tags            = merge(var.tags, { Name = "${var.prefix}-flow-log" })
}

# Subnets privadas (sin auto-assign public IP)
resource "aws_subnet" "private_a" {
  vpc_id                  = aws_vpc.secure.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false
  tags                    = merge(var.tags, { Name = "${var.prefix}-private-subnet-a" })
}

resource "aws_subnet" "private_b" {
  vpc_id                  = aws_vpc.secure.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = data.aws_availability_zones.available.names[1]
  map_public_ip_on_launch = false
  tags                    = merge(var.tags, { Name = "${var.prefix}-private-subnet-b" })
}

# Subnet pública para NAT Gateway
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.secure.id
  cidr_block              = "10.0.10.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false
  tags                    = merge(var.tags, { Name = "${var.prefix}-public-subnet" })
}

resource "aws_internet_gateway" "secure" {
  vpc_id = aws_vpc.secure.id
  tags   = merge(var.tags, { Name = "${var.prefix}-igw" })
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.secure.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.secure.id
  }
  tags = merge(var.tags, { Name = "${var.prefix}-public-rt" })
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# NACL seguro — sin reglas permisivas en puertos admin
resource "aws_network_acl" "secure" {
  vpc_id     = aws_vpc.secure.id
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_b.id]

  ingress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "10.0.0.0/8"
    from_port  = 443
    to_port    = 443
  }
  egress {
    rule_no    = 100
    protocol   = "-1"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }
  tags = merge(var.tags, { Name = "${var.prefix}-secure-nacl" })
}

# ── VPC INSEGURA — sin flow logs ──────────────────────────────
resource "aws_vpc" "insecure" {
  cidr_block           = "10.1.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = merge(var.tags, { Name = "${var.prefix}-insecure-vpc" })
  # Deliberadamente sin flow logs — genera CIS-VPC-3.9 FAIL
}

# Subnet con auto-assign public IP — genera WAF-EC2-SUB-01 FAIL
resource "aws_subnet" "insecure_public" {
  vpc_id                  = aws_vpc.insecure.id
  cidr_block              = "10.1.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true # INSECURE: auto-asigna IPs públicas
  tags                    = merge(var.tags, { Name = "${var.prefix}-insecure-subnet" })
}

resource "aws_internet_gateway" "insecure" {
  vpc_id = aws_vpc.insecure.id
  tags   = merge(var.tags, { Name = "${var.prefix}-insecure-igw" })
}

# NACL inseguro — puerto 22 y 3389 abiertos a 0.0.0.0/0
# Genera CIS-EC2-5.1 FAIL
resource "aws_network_acl" "insecure" {
  vpc_id     = aws_vpc.insecure.id
  subnet_ids = [aws_subnet.insecure_public.id]

  ingress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 22
    to_port    = 22
  }
  ingress {
    rule_no    = 110
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 3389
    to_port    = 3389
  }
  egress {
    rule_no    = 100
    protocol   = "-1"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }
  tags = merge(var.tags, { Name = "${var.prefix}-insecure-nacl" })
}
# Segunda subnet pública insegura en AZ diferente (requerida por RDS)
resource "aws_subnet" "insecure_public_b" {
  vpc_id                  = aws_vpc.insecure.id
  cidr_block              = "10.1.2.0/24"
  availability_zone       = data.aws_availability_zones.available.names[1]
  map_public_ip_on_launch = true # INSECURE: auto-asigna IPs públicas
  tags                    = merge(var.tags, { Name = "${var.prefix}-insecure-subnet-b" })
}
