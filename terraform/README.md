# Terraform — Entorno de Prueba para AWS Security Audit Suite

Despliega recursos AWS seguros e inseguros para validar que la suite
detecta correctamente los hallazgos esperados.

---

## Prerequisitos

```bash
# Instalar Terraform en WSL
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install terraform

# Verificar
terraform --version
```

---

## Uso

### 1. Configurar variables

```bash
cd ~/aws_audit_suite/terraform

# Opción A: usar valores por defecto (editar variables.tf)
# Opción B: crear terraform.tfvars
cat > terraform.tfvars << 'EOF2'
aws_region   = "us-east-1"
aws_profile  = "audit-role"
prefix       = "audit-test"
deploy_rds   = true
deploy_ec2   = true
rds_password = "MySecurePass2024!"
EOF2
```

### 2. Inicializar y desplegar

```bash
terraform init
terraform plan    # Revisar qué se va a crear
terraform apply   # Desplegar (confirmar con 'yes')
```

### 3. Ejecutar la auditoría

```bash
cd ~/aws_audit_suite
./orchestrator/run_audit.sh \
  --profile audit-role \
  --region us-east-1 \
  --auditor "Test Run"
```

### 4. Validar resultados

Verifica que el reporte contiene los findings esperados:

```bash
# Ver findings FAIL en el JSON
cat outputs/json/report_*.json | python3 -m json.tool | \
  python3 -c "
import json, sys
report = json.load(sys.stdin)
fails = [f for f in report['findings'] if f['status'] == 'FAIL']
for f in sorted(fails, key=lambda x: x['control_id']):
    print(f\"{f['control_id']:30} {f['severity']:10} {f['resource_id'][-40:]}\")
"
```

### 5. Destruir recursos

```bash
# MUY IMPORTANTE: destruir al terminar para evitar costos
terraform destroy   # Confirmar con 'yes'
```

---

## Costo estimado

| Recurso | Tipo | $/hora |
|---------|------|--------|
| EC2 insecure | t3.micro | $0.0104 |
| EC2 secure | t3.micro | $0.0104 |
| RDS insecure | db.t3.micro | $0.017 |
| RDS secure | db.t3.micro Multi-AZ | $0.034 |
| GuardDuty | Detector | ~$0.002 |
| **Total** | | **~$0.07/hora** |

> Destruir todo con `terraform destroy` después de validar.
> Costo total de una sesión de prueba de 2 horas: ~$0.15

---

## Findings esperados post-deploy

| Control | Servicio | Tipo |
|---------|---------|------|
| CIS-VPC-3.9 | VPC | FAIL — VPC insegura sin flow logs |
| WAF-EC2-SUB-01 | EC2 | FAIL — subnet con auto-assign IP |
| CIS-EC2-5.1 | EC2 | FAIL — NACL con puerto 22/3389 abierto |
| CIS-IAM-1.8 | IAM | FAIL — password min length < 14 |
| CIS-IAM-1.10 | IAM | FAIL — usuario sin MFA |
| CIS-IAM-1.15 | IAM | FAIL — política adjunta directamente |
| CIS-IAM-1.16 | IAM | FAIL — política con *:* |
| CIS-S3-2.1.1-ENC | S3 | FAIL — bucket sin SSE |
| CIS-S3-2.1.1 | S3 | FAIL — bucket sin block public access |
| CIS-S3-2.6 | S3 | FAIL — bucket sin logging |
| CIS-EC2-5.2 | EC2 | FAIL — SG con SSH/RDP abierto |
| CIS-EC2-5.6 | EC2 | FAIL — instancia sin IMDSv2 |
| CIS-EC2-2.2.2 | EC2 | FAIL — snapshot público |
| CIS-RDS-2.3.2 | RDS | FAIL — DB pública |
| CIS-RDS-2.3.1 | RDS | FAIL — DB sin encriptación |
| CIS-RDS-2.3.3 | RDS | FAIL — snapshot RDS público |
| WAF-GD-EXP-01 | GuardDuty | FAIL — sin export config |
| WAF-GD-PPL-01 | GuardDuty | FAIL — protection plans deshabilitados |
