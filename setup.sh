#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# [TOOL-02] setup.sh — Instalación y verificación del entorno
#
# Uso:
#   chmod +x setup.sh
#   ./setup.sh
#   ./setup.sh --check        # Solo verificar, no instalar
#   ./setup.sh --profile NAME # Verificar con un perfil AWS específico
# ══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

# ── Colores ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

ok()    { echo -e "  ${GREEN}✓${NC} $*"; }
fail()  { echo -e "  ${RED}✗${NC} $*"; }
warn()  { echo -e "  ${YELLOW}!${NC} $*"; }
info()  { echo -e "  ${BLUE}→${NC} $*"; }
header(){ echo -e "\n${BOLD}$*${NC}"; }

ERRORS=0
CHECK_ONLY=false
AWS_PROFILE_ARG=""

# ── Parse args ────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --check)   CHECK_ONLY=true; shift ;;
        --profile) AWS_PROFILE_ARG="$2"; shift 2 ;;
        -h|--help)
            echo "Uso: ./setup.sh [--check] [--profile AWS_PROFILE]"
            echo "  --check    Solo verificar dependencias, no instalar"
            echo "  --profile  Perfil AWS para verificar credenciales"
            exit 0 ;;
        *) echo "Opción desconocida: $1"; exit 1 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo -e "${BOLD}══════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  AWS Security Audit Suite — Setup${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════════════════${NC}"

# ══════════════════════════════════════════════════════════════════════════════
# 1. SISTEMA
# ══════════════════════════════════════════════════════════════════════════════
header "1. Verificando requisitos del sistema..."

# Python 3.10+
if command -v python3 &>/dev/null; then
    PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
    PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
    if [[ "$PY_MAJOR" -ge 3 && "$PY_MINOR" -ge 10 ]]; then
        ok "Python $PY_VER"
    else
        fail "Python $PY_VER (requiere 3.10+)"
        ((ERRORS++))
    fi
else
    fail "Python3 no encontrado"
    info "Instalar: sudo apt install python3 python3-pip python3-venv"
    ((ERRORS++))
fi

# pip
if command -v pip3 &>/dev/null || python3 -m pip --version &>/dev/null 2>&1; then
    ok "pip3 disponible"
else
    fail "pip3 no encontrado"
    info "Instalar: sudo apt install python3-pip"
    ((ERRORS++))
fi

# Node.js (para PPTX)
if command -v node &>/dev/null; then
    NODE_VER=$(node --version)
    ok "Node.js $NODE_VER"
else
    warn "Node.js no encontrado (necesario para reportes PPTX)"
    info "Instalar: sudo apt install nodejs npm"
fi

# AWS CLI
if command -v aws &>/dev/null; then
    AWS_VER=$(aws --version 2>&1 | head -1)
    ok "AWS CLI: $AWS_VER"
else
    fail "AWS CLI no encontrado"
    info "Instalar: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
    ((ERRORS++))
fi

# ══════════════════════════════════════════════════════════════════════════════
# 2. ENTORNO VIRTUAL PYTHON
# ══════════════════════════════════════════════════════════════════════════════
header "2. Entorno virtual Python..."

if [[ -d ".venv" ]]; then
    ok "Virtualenv .venv existe"
    source .venv/bin/activate
    ok "Virtualenv activado"
elif [[ "$CHECK_ONLY" == "false" ]]; then
    info "Creando virtualenv .venv..."
    python3 -m venv .venv
    source .venv/bin/activate
    ok "Virtualenv creado y activado"
else
    warn "Virtualenv .venv no existe (ejecutar sin --check para crear)"
fi

# ══════════════════════════════════════════════════════════════════════════════
# 3. DEPENDENCIAS PYTHON
# ══════════════════════════════════════════════════════════════════════════════
header "3. Dependencias Python..."

PYTHON_DEPS=(
    "boto3"
    "botocore"
    "pydantic"
    "jinja2"
    "click"
    "rich"
    "pyyaml"
    "python-dotenv"
    "python-docx"
    "openpyxl"
)

OPTIONAL_DEPS=(
    "weasyprint"
)

MISSING_REQUIRED=()
MISSING_OPTIONAL=()

for dep in "${PYTHON_DEPS[@]}"; do
    # Normalizar nombre de paquete para import
    import_name="${dep//-/_}"
    # Casos especiales
    [[ "$dep" == "pyyaml" ]] && import_name="yaml"
    [[ "$dep" == "python-docx" ]] && import_name="docx"
    [[ "$dep" == "python-dotenv" ]] && import_name="dotenv"

    if python3 -c "import $import_name" &>/dev/null 2>&1; then
        ok "$dep"
    else
        fail "$dep no instalado"
        MISSING_REQUIRED+=("$dep")
    fi
done

for dep in "${OPTIONAL_DEPS[@]}"; do
    if python3 -c "import $dep" &>/dev/null 2>&1; then
        ok "$dep (opcional)"
    else
        warn "$dep no instalado (opcional — necesario para PDF)"
        MISSING_OPTIONAL+=("$dep")
    fi
done

# Instalar faltantes
if [[ ${#MISSING_REQUIRED[@]} -gt 0 && "$CHECK_ONLY" == "false" ]]; then
    info "Instalando dependencias faltantes..."
    pip install -r requirements.txt -q
    ok "Dependencias instaladas"
elif [[ ${#MISSING_REQUIRED[@]} -gt 0 ]]; then
    fail "${#MISSING_REQUIRED[@]} dependencias faltantes"
    info "Ejecutar: pip install -r requirements.txt"
    ((ERRORS++))
fi

# ══════════════════════════════════════════════════════════════════════════════
# 4. DEPENDENCIAS NODE.JS (para PPTX)
# ══════════════════════════════════════════════════════════════════════════════
header "4. Dependencias Node.js (PPTX)..."

if [[ -d "reporter/node_modules/pptxgenjs" ]]; then
    ok "pptxgenjs instalado en reporter/node_modules/"
elif command -v node &>/dev/null; then
    if [[ "$CHECK_ONLY" == "false" ]]; then
        info "Instalando pptxgenjs..."
        cd reporter
        [[ ! -f "package.json" ]] && npm init -y --silent 2>/dev/null
        npm install pptxgenjs --silent 2>/dev/null
        cd ..
        ok "pptxgenjs instalado"
    else
        warn "pptxgenjs no instalado en reporter/"
        info "Ejecutar: cd reporter && npm init -y && npm install pptxgenjs"
    fi
else
    warn "Node.js no disponible — reportes PPTX no se generarán"
fi

# ══════════════════════════════════════════════════════════════════════════════
# 5. DEPENDENCIAS DEL SISTEMA (para WeasyPrint/PDF)
# ══════════════════════════════════════════════════════════════════════════════
header "5. Dependencias del sistema (PDF)..."

SYS_DEPS=("libpango-1.0-0" "libpangocairo-1.0-0" "libgdk-pixbuf2.0-0")
SYS_MISSING=0

for dep in "${SYS_DEPS[@]}"; do
    if dpkg -s "$dep" &>/dev/null 2>&1; then
        ok "$dep"
    else
        warn "$dep no instalado (necesario para PDF)"
        ((SYS_MISSING++))
    fi
done

if [[ $SYS_MISSING -gt 0 ]]; then
    info "Para instalar: sudo apt-get install -y python3-cffi libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 shared-mime-info"
fi

# ══════════════════════════════════════════════════════════════════════════════
# 6. CREDENCIALES AWS
# ══════════════════════════════════════════════════════════════════════════════
header "6. Verificando credenciales AWS..."

if [[ -n "$AWS_PROFILE_ARG" ]]; then
    export AWS_PROFILE="$AWS_PROFILE_ARG"
    info "Usando perfil: $AWS_PROFILE_ARG"
fi

if aws sts get-caller-identity --output text &>/dev/null 2>&1; then
    ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null)
    CALLER_ARN=$(aws sts get-caller-identity --query Arn --output text 2>/dev/null)
    ok "Autenticado en cuenta: $ACCOUNT_ID"
    ok "Identidad: $CALLER_ARN"

    # Verificar políticas mínimas
    info "Verificando acceso a servicios..."
    if aws iam get-account-authorization-details --max-items 1 --output text &>/dev/null 2>&1; then
        ok "IAM: acceso de lectura"
    else
        warn "IAM: acceso limitado (puede afectar algunos controles)"
    fi

    if aws s3api list-buckets --max-items 1 --output text &>/dev/null 2>&1; then
        ok "S3: acceso de lectura"
    else
        warn "S3: sin acceso"
    fi

    if aws guardduty list-detectors --max-results 1 --output text &>/dev/null 2>&1; then
        ok "GuardDuty: acceso de lectura"
    else
        warn "GuardDuty: sin acceso"
    fi
else
    warn "Credenciales AWS no configuradas o inválidas"
    info "Configurar: aws configure --profile audit-role"
    info "O usar: export AWS_PROFILE=audit-role"
fi

# ══════════════════════════════════════════════════════════════════════════════
# 7. ESTRUCTURA DE DIRECTORIOS
# ══════════════════════════════════════════════════════════════════════════════
header "7. Verificando estructura del proyecto..."

REQUIRED_DIRS=("collectors" "analyzers" "reporter" "schemas" "utils" "orchestrator")
for d in "${REQUIRED_DIRS[@]}"; do
    if [[ -d "$d" ]]; then
        ok "$d/"
    else
        fail "$d/ no existe"
        ((ERRORS++))
    fi
done

REQUIRED_FILES=("main.py" "requirements.txt" "config.yaml")
for f in "${REQUIRED_FILES[@]}"; do
    if [[ -f "$f" ]]; then
        ok "$f"
    else
        fail "$f no existe"
        ((ERRORS++))
    fi
done

# ══════════════════════════════════════════════════════════════════════════════
# RESUMEN
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}══════════════════════════════════════════════════════════════${NC}"
if [[ $ERRORS -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}  ✓ Entorno listo. Puedes ejecutar la auditoría.${NC}"
    echo ""
    echo -e "  Uso rápido:"
    echo -e "    ${BLUE}source .venv/bin/activate${NC}"
    echo -e "    ${BLUE}./orchestrator/run_audit.sh --profile audit-role --region us-east-1${NC}"
else
    echo -e "${RED}${BOLD}  ✗ $ERRORS problemas encontrados. Revisa los errores arriba.${NC}"
fi
echo -e "${BOLD}══════════════════════════════════════════════════════════════${NC}"
echo ""

exit $ERRORS