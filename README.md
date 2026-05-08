# AWS Security Audit Suite

Suite modular de auditoría de seguridad para cuentas AWS basada en:
- **CIS AWS Foundations Benchmark v1.4**
- **AWS Well-Architected Framework — Security Pillar**

---

## Índice

1. [Arquitectura](#arquitectura)
2. [Requisitos](#requisitos)
3. [Instalación](#instalación)
4. [Configuración AWS](#configuración-aws)
5. [Uso](#uso)
6. [Servicios auditados](#servicios-auditados)
7. [Entregables](#entregables)
8. [Estructura del proyecto](#estructura-del-proyecto)
9. [Referencia de tags](#referencia-de-tags)
10. [Troubleshooting](#troubleshooting)

---

## Arquitectura

```
collectors/   → Recopilan datos via boto3 (un módulo por servicio)
     ↓
analyzers/    → Evalúan controles CIS/WAF sobre los datos recopilados
     ↓
reporter/     → Genera PDF, HTML y Markdown a partir del Report
     ↓
outputs/      → Archivos generados (json/, reports/, dashboard/)
```

El orchestrator (`main.py` + `orchestrator/run_audit.sh`) coordina
las 4 fases: recolección → análisis → construcción del report → generación.

---

## Requisitos

### Sistema
- Python 3.10+
- WSL Ubuntu 20.04 (o cualquier Linux/macOS)
- AWS CLI v2

### Python
```
boto3>=1.34.0
pydantic>=2.0.0
jinja2>=3.1.0
weasyprint>=60.0
PyYAML>=6.0
python-dotenv>=1.0.0
rich>=13.0.0
click>=8.1.0
```

### AWS
- Acceso a la cuenta objetivo con un rol de auditoría de solo lectura
- Políticas requeridas en el rol:
  - `SecurityAudit`
  - `ReadOnlyAccess`
  - `AmazonGuardDutyReadOnlyAccess`
  - `CloudWatchReadOnlyAccess`

---

## Instalación

### 1. Clonar o copiar el proyecto

```bash
# Crear directorio del proyecto
mkdir -p ~/aws_audit_suite
cd ~/aws_audit_suite
```

### 2. Crear entorno virtual

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Instalar dependencias

```bash
pip install -r requirements.txt
```

> **Nota WeasyPrint:** Si la instalación falla en WSL, instalar dependencias del sistema primero:
> ```bash
> sudo apt-get install -y python3-cffi python3-brotli libpango-1.0-0 \
>   libpangoft2-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 \
>   libffi-dev shared-mime-info
> ```

### 4. Configurar variables de entorno

```bash
cp .env.example .env
# Editar .env con tu configuración
nano .env
```

Contenido de `.env`:
```
AWS_PROFILE=audit-role
AWS_REGION=us-east-1
AWS_ACCOUNT_ID=123456789012
```

---

## Configuración AWS

### Crear el rol de auditoría

```bash
# 1. Crear el rol IAM con las políticas necesarias
aws iam create-role \
  --role-name AuditRole \
  --assume-role-policy-document file://trust-policy.json

# 2. Adjuntar políticas de solo lectura
aws iam attach-role-policy \
  --role-name AuditRole \
  --policy-arn arn:aws:iam::aws:policy/SecurityAudit

aws iam attach-role-policy \
  --role-name AuditRole \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess

aws iam attach-role-policy \
  --role-name AuditRole \
  --policy-arn arn:aws:iam::aws:policy/AmazonGuardDutyReadOnlyAccess

aws iam attach-role-policy \
  --role-name AuditRole \
  --policy-arn arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess
```

### Configurar el perfil AWS en WSL

```bash
aws configure --profile audit-role
# AWS Access Key ID: <tu-key>
# AWS Secret Access Key: <tu-secret>
# Default region name: us-east-1
# Default output format: json
```

### Verificar acceso

```bash
aws sts get-caller-identity --profile audit-role
```

---

## Uso

### Ejecución básica (todos los servicios)

```bash
cd ~/aws_audit_suite
source .venv/bin/activate
./orchestrator/run_audit.sh --profile audit-role --region us-east-1
```

### Opciones disponibles

```bash
./orchestrator/run_audit.sh [OPTIONS]

Opciones:
  --profile     AWS profile name (default: credenciales de entorno)
  --region      Región AWS a auditar (default: us-east-1)
  --services    Servicios específicos separados por coma
  --output-dir  Directorio de salida (default: outputs/)
  --auditor     Nombre del auditor para el reporte
  --formats     Formatos a generar: pdf,html,markdown (default: todos)
  --skip-report Solo recolectar y analizar, sin generar reportes
  --verbose     Logging detallado
```

### Ejemplos de uso

```bash
# Auditar solo IAM y S3
./orchestrator/run_audit.sh \
  --profile audit-role \
  --region us-east-1 \
  --services iam,s3

# Generar solo HTML y Markdown (sin PDF)
./orchestrator/run_audit.sh \
  --profile audit-role \
  --region us-east-1 \
  --formats html,markdown

# Auditoría completa con nombre de auditor
./orchestrator/run_audit.sh \
  --profile audit-role \
  --region us-east-1 \
  --auditor "John Smith" \
  --output-dir ./outputs/client-xyz

# Solo recolección (sin reportes) para inspección de datos
./orchestrator/run_audit.sh \
  --profile audit-role \
  --region us-east-1 \
  --skip-report
```

### Ejecución directa con Python

```bash
python3 main.py --profile audit-role --region us-east-1
python3 main.py --help
```

### Exit codes

| Código | Significado |
|--------|-------------|
| `0` | Auditoría completada sin findings CRITICAL |
| `1` | Error fatal — la auditoría no pudo completarse |
| `2` | Auditoría completada pero existen findings CRITICAL |

---

## Servicios auditados

| Tag | Servicio | Controles CIS | Controles WAF |
|-----|----------|--------------|---------------|
| `[COL-01/ANZ-01]` | IAM | 1.4, 1.5, 1.6, 1.8–1.17, 1.20 | Grupos vacíos |
| `[COL-02/ANZ-02]` | S3 | 2.1.1–2.1.4, 2.6 | Versioning, SSL, lifecycle |
| `[COL-03/ANZ-03]` | EC2 | 2.2.1, 2.2.2, 3.9, 5.1–5.6 | SSM, ELB exposure, endpoints |
| `[COL-04/ANZ-04]` | RDS | 2.3.1–2.3.3 | Multi-AZ, deletion protection, SSL |
| `[COL-05/ANZ-05]` | GuardDuty | 3.1 | Protection plans, findings activos |
| `[COL-06/ANZ-06]` | CloudWatch | 3.1–3.7, 4.1–4.15 | Log groups, alarmas |
| `[COL-07/ANZ-07]` | VPC | 3.9, 5.3 | Flow logs, peering, endpoints |

---

## Entregables

Todos los archivos se generan en `outputs/` con el formato:
```
aws_audit_{account_id}_{timestamp}.{extension}
```

### `outputs/reports/`
| Archivo | Descripción |
|---------|-------------|
| `*.pdf` | Reporte profesional para entrega al cliente |
| `*.html` | Reporte interactivo con dashboard, charts y tabs por servicio |
| `*.md` | Reporte en Markdown para documentación técnica |

### `outputs/json/`
| Archivo | Descripción |
|---------|-------------|
| `{service}_{timestamp}.json` | Raw data recopilado por cada collector |
| `report_{timestamp}.json` | Report completo con todos los findings |

### `outputs/`
| Archivo | Descripción |
|---------|-------------|
| `audit.log` | Log completo de la ejecución |

---

## Estructura del proyecto

```
aws_audit_suite/
│
├── collectors/                  # [COL-00..07] Recopilación de datos
│   ├── __init__.py              # Registro de collectors
│   ├── iam_collector.py         # [COL-01]
│   ├── s3_collector.py          # [COL-02]
│   ├── ec2_collector.py         # [COL-03]
│   ├── rds_collector.py         # [COL-04]
│   ├── guardduty_collector.py   # [COL-05]
│   ├── cloudwatch_collector.py  # [COL-06]
│   └── vpc_collector.py         # [COL-07]
│
├── analyzers/                   # [ANZ-00..07] Evaluación de controles
│   ├── __init__.py              # Registro de analyzers
│   ├── iam_analyzer.py          # [ANZ-01]
│   ├── s3_analyzer.py           # [ANZ-02]
│   ├── ec2_analyzer.py          # [ANZ-03]
│   ├── rds_analyzer.py          # [ANZ-04]
│   ├── guardduty_analyzer.py    # [ANZ-05]
│   ├── cloudwatch_analyzer.py   # [ANZ-06]
│   └── vpc_analyzer.py          # [ANZ-07]
│
├── schemas/                     # [SCH-01..03] Modelos de datos
│   ├── finding.py               # [SCH-01] Unidad mínima de hallazgo
│   ├── collector_output.py      # [SCH-02] Output de cada collector
│   └── report.py                # [SCH-03] Reporte consolidado
│
├── utils/                       # [UTL-01..03] Utilidades comunes
│   ├── aws_session.py           # [UTL-01] Sesión boto3
│   ├── logger.py                # [UTL-02] Logger centralizado
│   └── helpers.py               # [UTL-03] IO y utilidades
│
├── reporter/                    # [REP-01] Generación de entregables
│   ├── __init__.py              # Función build_reports()
│   ├── base_reporter.py         # Interfaz común
│   ├── md_reporter.py           # Formato Markdown
│   ├── html_reporter.py         # Formato HTML con dashboard
│   └── pdf_reporter.py          # Formato PDF via WeasyPrint
│
├── orchestrator/                # [ORC-01] Coordinación
│   └── run_audit.sh             # Wrapper Bash con pre-flight checks
│
├── tests/                       # Pruebas unitarias (próxima iteración)
│   ├── test_collectors.py
│   └── test_analyzers.py
│
├── outputs/                     # Generado automáticamente
│   ├── json/
│   ├── reports/
│   └── dashboard/
│
├── main.py                      # [ORC-01] Entry point Python
├── config.yaml                  # Configuración central
├── requirements.txt             # Dependencias Python
├── .env.example                 # Template de variables de entorno
└── README.md                    # Este archivo
```

---

## Referencia de tags

| Tag | Módulo | Archivo(s) |
|-----|--------|-----------|
| `[SCH-01]` | Schema | `schemas/finding.py` |
| `[SCH-02]` | Schema | `schemas/collector_output.py` |
| `[SCH-03]` | Schema | `schemas/report.py` |
| `[UTL-01]` | Utils | `utils/aws_session.py` |
| `[UTL-02]` | Utils | `utils/logger.py` |
| `[UTL-03]` | Utils | `utils/helpers.py` |
| `[COL-00]` | Collector | `collectors/__init__.py` |
| `[COL-01]` | Collector | `collectors/iam_collector.py` |
| `[COL-02]` | Collector | `collectors/s3_collector.py` |
| `[COL-03]` | Collector | `collectors/ec2_collector.py` |
| `[COL-04]` | Collector | `collectors/rds_collector.py` |
| `[COL-05]` | Collector | `collectors/guardduty_collector.py` |
| `[COL-06]` | Collector | `collectors/cloudwatch_collector.py` |
| `[COL-07]` | Collector | `collectors/vpc_collector.py` |
| `[ANZ-00]` | Analyzer | `analyzers/__init__.py` |
| `[ANZ-01]` | Analyzer | `analyzers/iam_analyzer.py` |
| `[ANZ-02]` | Analyzer | `analyzers/s3_analyzer.py` |
| `[ANZ-03]` | Analyzer | `analyzers/ec2_analyzer.py` |
| `[ANZ-04]` | Analyzer | `analyzers/rds_analyzer.py` |
| `[ANZ-05]` | Analyzer | `analyzers/guardduty_analyzer.py` |
| `[ANZ-06]` | Analyzer | `analyzers/cloudwatch_analyzer.py` |
| `[ANZ-07]` | Analyzer | `analyzers/vpc_analyzer.py` |
| `[ORC-01]` | Orchestrator | `main.py` + `orchestrator/run_audit.sh` |
| `[REP-01]` | Reporter | `reporter/` |

---

## Troubleshooting

### Error: `No module named 'pydantic'`
```bash
pip install -r requirements.txt
```

### Error: `botocore.exceptions.NoCredentialsError`
```bash
# Verificar configuración del perfil
aws configure list --profile audit-role
aws sts get-caller-identity --profile audit-role
```

### Error: `AccessDenied` en algún servicio
El rol de auditoría puede no tener permisos para ese servicio.
Los errores no fatales se registran en `outputs/audit.log` y
en `collector_output.errors` — la auditoría continúa con los
demás servicios.

### WeasyPrint falla en WSL
```bash
# Instalar dependencias del sistema
sudo apt-get update
sudo apt-get install -y \
  python3-cffi python3-brotli libpango-1.0-0 \
  libpangoft2-1.0-0 libpangocairo-1.0-0 \
  libgdk-pixbuf2.0-0 libffi-dev shared-mime-info

pip install weasyprint
```

### Re-ejecutar un solo servicio
```bash
./orchestrator/run_audit.sh \
  --profile audit-role \
  --region us-east-1 \
  --services iam \
  --skip-report
```

### Ver raw data de un collector
```bash
cat outputs/json/iam_*.json | python3 -m json.tool | less
```

---

*AWS Security Audit Suite — CIS AWS Foundations Benchmark 1.4 +
AWS Well-Architected Framework Security Pillar*