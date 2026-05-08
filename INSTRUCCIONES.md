# AWS Security Audit Suite — Guía Completa de Uso

## Índice

1. [Requisitos previos](#1-requisitos-previos)
2. [Instalación](#2-instalación)
3. [Configuración de AWS](#3-configuración-de-aws)
4. [Configuración del cliente](#4-configuración-del-cliente)
5. [Ejecutar la auditoría](#5-ejecutar-la-auditoría)
6. [Entregables generados](#6-entregables-generados)
7. [Comparar auditorías (diff)](#7-comparar-auditorías-diff)
8. [Estructura del proyecto](#8-estructura-del-proyecto)
9. [Troubleshooting](#9-troubleshooting)
10. [Referencia rápida de comandos](#10-referencia-rápida-de-comandos)

---

## 1. Requisitos previos

### Sistema operativo
- WSL Ubuntu 20.04+ sobre Windows 11 (o cualquier Linux/macOS)

### Software necesario

| Software    | Versión mínima | Para qué se usa                    |
|-------------|----------------|------------------------------------|
| Python      | 3.10+          | Core de la suite                   |
| pip         | 22+            | Gestor de paquetes Python          |
| AWS CLI     | v2             | Validación de credenciales         |
| Node.js     | 18+            | Generación de PPTX (opcional)      |
| npm         | 8+             | Dependencias de Node.js (opcional) |

### Verificar requisitos

```bash
python3 --version    # Debe ser 3.10+
pip3 --version       # Disponible
aws --version        # AWS CLI v2
node --version       # 18+ (opcional, para PPTX)
```

---

## 2. Instalación

### 2.1 Clonar/copiar el proyecto

```bash
cd ~
# Si usas git:
git clone <url-del-repo> aws_audit_suite
# O copiar la carpeta directamente
cd aws_audit_suite
```

### 2.2 Ejecutar setup automático

```bash
chmod +x setup.sh
./setup.sh
```

El script `setup.sh` hace todo automáticamente:
- Crea el virtualenv Python (`.venv/`)
- Instala todas las dependencias pip
- Instala `pptxgenjs` para reportes PPTX
- Verifica credenciales AWS
- Valida la estructura del proyecto

### 2.3 Instalación manual (si prefieres hacerlo paso a paso)

```bash
# Crear virtualenv
python3 -m venv .venv
source .venv/bin/activate

# Instalar dependencias Python
pip install -r requirements.txt

# Instalar dependencias Node.js (para PPTX)
cd reporter
npm init -y
npm install pptxgenjs
cd ..

# Para generación de PDF (WeasyPrint necesita estas libs del sistema):
sudo apt-get install -y python3-cffi libpango-1.0-0 \
  libpangocairo-1.0-0 libgdk-pixbuf2.0-0 shared-mime-info
```

### 2.4 Verificar instalación

```bash
./setup.sh --check
```

---

## 3. Configuración de AWS

### 3.1 Crear el rol de auditoría en la cuenta del cliente

El cliente (o tú con acceso admin) debe crear un rol IAM con permisos de solo lectura. El rol necesita 4 políticas managed de AWS:

```bash
# Crear perfil en tu máquina para la cuenta del cliente
aws configure --profile audit-cliente
# AWS Access Key ID:     <access-key-del-rol>
# AWS Secret Access Key: <secret-key-del-rol>
# Default region name:   us-east-1
# Default output format: json
```

**Políticas necesarias en el rol IAM:**

| Política AWS Managed              | Qué cubre                                    |
|-----------------------------------|----------------------------------------------|
| `SecurityAudit`                   | IAM, CloudTrail, Config, VPC, Security Groups|
| `ReadOnlyAccess`                  | S3, EC2, RDS y servicios generales           |
| `AmazonGuardDutyReadOnlyAccess`   | GuardDuty detectors y findings               |
| `CloudWatchReadOnlyAccess`        | CloudWatch alarms, logs, metrics             |

### 3.2 Verificar acceso

```bash
aws sts get-caller-identity --profile audit-cliente
```

Deberías ver algo como:
```json
{
    "UserId": "AROA...:audit-session",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:role/AuditRole"
}
```

### 3.3 Verificar permisos mínimos

```bash
# IAM
aws iam get-account-authorization-details --max-items 1 --profile audit-cliente

# S3
aws s3api list-buckets --profile audit-cliente

# EC2
aws ec2 describe-instances --max-items 1 --profile audit-cliente

# RDS
aws rds describe-db-instances --max-items 1 --profile audit-cliente

# GuardDuty
aws guardduty list-detectors --profile audit-cliente

# CloudWatch
aws cloudwatch describe-alarms --max-items 1 --profile audit-cliente
```

Si alguno falla con `AccessDenied`, falta la política correspondiente en el rol.

---

## 4. Configuración del cliente

### 4.1 Archivo `.env`

Copia y edita el archivo de variables de entorno:

```bash
cp .env.example .env
nano .env
```

Contenido de `.env`:
```bash
# ── Credenciales AWS ─────────────────────────────────────
AWS_PROFILE=audit-cliente
AWS_REGION=us-east-1

# ── Datos del reporte ────────────────────────────────────
AUDITOR_NAME=George
```

### 4.2 Archivo `config.yaml`

El archivo `config.yaml` controla qué se audita y en qué formatos se genera:

```yaml
aws:
  region: us-east-1
  profile: audit-cliente

audit:
  frameworks:
    - CIS_AWS_1.4
    - AWS_WAF_SECURITY
  services:
    - iam
    - s3
    - ec2
    - rds
    - guardduty
    - cloudwatch

output:
  formats:
    - pdf
    - html
    - markdown
    - docx
    - pptx
    - csv
  directory: outputs/reports
  json_directory: outputs/json
  dashboard_directory: outputs/dashboard
```

### 4.3 Qué cambiar por cada cliente

Para cada nuevo cliente, solo necesitas modificar:

| Qué cambiar           | Dónde                  | Ejemplo                         |
|------------------------|------------------------|---------------------------------|
| Perfil AWS             | `.env` → `AWS_PROFILE` | `audit-cliente-xyz`             |
| Región                 | `.env` → `AWS_REGION`  | `eu-west-1`                     |
| Nombre del auditor     | CLI `--auditor`        | `"George — Security Analyst"`   |
| Directorio de output   | CLI `--output-dir`     | `outputs/cliente-xyz-mayo2026`  |

---

## 5. Ejecutar la auditoría

### 5.1 Activar el entorno

```bash
cd ~/aws_audit_suite
source .venv/bin/activate
```

### 5.2 Ejecución completa (recomendado)

```bash
./orchestrator/run_audit.sh \
  --profile audit-cliente \
  --region us-east-1 \
  --auditor "George — Security Analyst" \
  --formats pdf,html,markdown,docx,pptx,csv
```

### 5.3 Opciones disponibles

```
./orchestrator/run_audit.sh [OPCIONES]

Opciones:
  --profile NAME       Perfil AWS a usar (default: credenciales de entorno)
  --region REGION      Región AWS a auditar (default: us-east-1)
  --services s1,s2     Solo auditar servicios específicos
  --output-dir PATH    Directorio de salida (default: outputs/)
  --auditor NAME       Nombre del auditor para el reporte
  --formats f1,f2      Formatos a generar (default: pdf,html,markdown,docx,pptx,csv)
  --skip-report        Solo recolectar y analizar, sin generar reportes
  --verbose            Logging detallado
```

### 5.4 Ejemplos de uso

```bash
# Solo auditar IAM y S3
./orchestrator/run_audit.sh \
  --profile audit-cliente \
  --region us-east-1 \
  --services iam,s3

# Solo generar DOCX y PPTX (para la reunión)
./orchestrator/run_audit.sh \
  --profile audit-cliente \
  --region us-east-1 \
  --formats docx,pptx

# Auditoría en otra región
./orchestrator/run_audit.sh \
  --profile audit-cliente \
  --region eu-west-1 \
  --output-dir outputs/cliente-xyz-eu

# Solo recolección (sin reportes) para inspección de datos
./orchestrator/run_audit.sh \
  --profile audit-cliente \
  --region us-east-1 \
  --skip-report
```

### 5.5 Ejecución directa con Python (alternativa)

```bash
source .venv/bin/activate
python main.py \
  --profile audit-cliente \
  --region us-east-1 \
  --auditor "George" \
  --formats pdf,html,markdown,docx,pptx,csv
```

### 5.6 Exit codes

| Código | Significado                                      |
|--------|--------------------------------------------------|
| `0`    | Auditoría completada sin hallazgos críticos      |
| `2`    | Auditoría completada CON hallazgos CRITICAL      |
| `1`    | Error fatal (credenciales, dependencias, etc.)   |

---

## 6. Entregables generados

Después de ejecutar la auditoría, encontrarás los archivos en el directorio de output:

```
outputs/<run-name>/
├── json/
│   ├── report_<account>_<timestamp>.json          ← Datos crudos (fuente de verdad)
│   ├── collector_iam_<timestamp>.json
│   ├── collector_s3_<timestamp>.json
│   └── ...
├── reports/
│   ├── aws_audit_<account>_<timestamp>.md          ← Markdown
│   ├── aws_audit_<account>_<timestamp>.html        ← HTML interactivo
│   ├── aws_audit_<account>_<timestamp>.pdf         ← PDF para impresión
│   ├── aws_audit_<account>_<timestamp>_en.docx     ← Word (inglés)
│   ├── aws_audit_<account>_<timestamp>_es.docx     ← Word (español)
│   ├── aws_audit_<account>_<timestamp>_en.pptx     ← PowerPoint (inglés)
│   ├── aws_audit_<account>_<timestamp>_es.pptx     ← PowerPoint (español)
│   ├── aws_audit_<account>_<timestamp>.csv         ← CSV para importar a Jira
│   └── aws_audit_<account>_<timestamp>.xlsx        ← Excel con formato
└── dashboard/
    └── dashboard_<account>_<timestamp>.html        ← Dashboard interactivo
```

### Cuándo usar cada formato

| Formato | Para qué                                                         |
|---------|------------------------------------------------------------------|
| **DOCX** | Entregable formal al cliente (reporte técnico completo)         |
| **PPTX** | Reunión de presentación de resultados                           |
| **PDF**  | Versión imprimible del reporte                                  |
| **HTML** | Revisión interactiva en navegador                               |
| **CSV**  | Importar findings a Jira, ServiceNow, o cualquier ticket tracker|
| **XLSX** | Findings en Excel con filtros y colores para el equipo de TI    |
| **MD**   | Documentación interna, integración con wikis/repos              |
| **JSON** | Fuente de verdad, input para diff y procesamiento programático  |
| **Dashboard** | Visualización ejecutiva interactiva en navegador           |

---

## 7. Comparar auditorías (diff)

Cuando el cliente remedie y re-ejecutes la auditoría, usa `audit_diff.py` para generar un reporte de comparación:

```bash
python3 audit_diff.py \
  outputs/run-anterior/json/report_*.json \
  outputs/run-nuevo/json/report_*.json \
  --output outputs/comparacion.md
```

El diff muestra:
- Delta de score global y por servicio
- Controles remediados (FAIL → PASS)
- Regresiones (PASS → FAIL)
- Nuevos fallos
- Controles que siguen fallando

---

## 8. Estructura del proyecto

```
aws_audit_suite/
├── main.py                          ← Entry point principal
├── setup.sh                         ← Instalación y verificación
├── audit_diff.py                    ← Comparar dos auditorías
├── config.yaml                      ← Configuración central
├── requirements.txt                 ← Dependencias Python
├── .env.example                     ← Template de variables de entorno
│
├── collectors/                      ← Recolección de datos via boto3
│   ├── iam_collector.py
│   ├── s3_collector.py
│   ├── ec2_collector.py
│   ├── rds_collector.py
│   ├── guardduty_collector.py
│   └── cloudwatch_collector.py
│
├── analyzers/                       ← Evaluación de controles CIS/WAF
│   ├── iam_analyzer.py
│   ├── s3_analyzer.py
│   ├── ec2_analyzer.py
│   ├── rds_analyzer.py
│   ├── guardduty_analyzer.py
│   └── cloudwatch_analyzer.py
│
├── reporter/                        ← Generación de reportes
│   ├── base_reporter.py             ← Interfaz común
│   ├── md_reporter.py               ← Markdown
│   ├── html_reporter.py             ← HTML
│   ├── pdf_reporter.py              ← PDF (via WeasyPrint)
│   ├── docx_reporter.py             ← Word (EN + ES)
│   ├── pptx_reporter.py             ← PowerPoint (EN + ES)
│   ├── pptx_builder.js              ← Motor PPTX (pptxgenjs)
│   ├── csv_reporter.py              ← CSV + Excel
│   └── node_modules/                ← Dependencias Node.js
│
├── schemas/                         ← Modelos de datos
│   ├── finding.py                   ← Finding individual
│   ├── report.py                    ← Reporte completo
│   ├── collector_output.py          ← Output de collectors
│   └── controls_catalog.py          ← Catálogo de controles (nombres EN/ES)
│
├── dashboard/                       ← Dashboard HTML interactivo
│   └── dashboard_builder.py
│
├── utils/                           ← Utilidades compartidas
│   ├── aws_session.py               ← Manejo de sesiones boto3
│   ├── logger.py                    ← Logging centralizado
│   └── helpers.py                   ← Funciones auxiliares
│
├── orchestrator/                    ← Scripts de ejecución
│   └── run_audit.sh                 ← Wrapper Bash
│
└── outputs/                         ← Resultados (generado automáticamente)
    ├── json/
    ├── reports/
    └── dashboard/
```

---

## 9. Troubleshooting

### "Cannot find module 'pptxgenjs'"

```bash
cd ~/aws_audit_suite/reporter
npm init -y
npm install pptxgenjs
```

### "No module named 'openpyxl'" (o cualquier módulo Python)

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

### "WeasyPrint: cannot load library 'libpango'"

```bash
sudo apt-get install -y python3-cffi libpango-1.0-0 \
  libpangocairo-1.0-0 libgdk-pixbuf2.0-0 shared-mime-info
```

### "AWS credentials not valid"

```bash
# Verificar perfil configurado
aws sts get-caller-identity --profile audit-cliente

# Si expiraron las credenciales temporales, renovar:
aws sts assume-role \
  --role-arn arn:aws:iam::ACCOUNT_ID:role/AuditRole \
  --role-session-name audit-session \
  --profile base-profile
```

### "Permission denied" en run_audit.sh

```bash
chmod +x orchestrator/run_audit.sh
chmod +x setup.sh
```

### Los reportes DOCX/PPTX se generan pero los demás no

Revisa que el error no sea en el `__init__.py` del reporter. Un import fallido (como `openpyxl` faltante) hace que todos los formatos fallen. Ejecuta `./setup.sh --check` para verificar todas las dependencias.

### El diff no encuentra diferencias

Asegúrate de usar los archivos `report_*.json` (no los `collector_*.json`). El diff compara reportes completos, no datos de collectors individuales.

---

## 10. Referencia rápida de comandos

```bash
# ── Setup ──────────────────────────────────────────────────
./setup.sh                          # Instalar todo
./setup.sh --check                  # Solo verificar
./setup.sh --profile audit-cliente  # Verificar con perfil AWS

# ── Auditoría ──────────────────────────────────────────────
./orchestrator/run_audit.sh \
  --profile audit-cliente \
  --region us-east-1 \
  --auditor "George" \
  --formats pdf,html,markdown,docx,pptx,csv

# ── Comparar auditorías ───────────────────────────────────
python3 audit_diff.py \
  outputs/run-01/json/report_*.json \
  outputs/run-02/json/report_*.json \
  --output comparacion.md

# ── Verificaciones ─────────────────────────────────────────
aws sts get-caller-identity --profile audit-cliente
python3 -c "import boto3; print('OK')"
node -e "require('pptxgenjs'); console.log('OK')"
```