#!/usr/bin/env bash
# [ORC-01] AWS Security Audit Suite — Bash wrapper
# Uso: ./orchestrator/run_audit.sh [--profile PROFILE] [--region REGION] [--services s1,s2]

set -euo pipefail

# ── Colores ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

log()     { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# ── Defaults ──────────────────────────────────────────────────────────────────
PROFILE=""
REGION="us-east-1"
SERVICES=""
OUTPUT_DIR="outputs"
AUDITOR=""
FORMATS="pdf,html,markdown"
SKIP_REPORT=false
VERBOSE=false

# ── Parse args ────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --profile)    PROFILE="$2";     shift 2 ;;
        --region)     REGION="$2";      shift 2 ;;
        --services)   SERVICES="$2";    shift 2 ;;
        --output-dir) OUTPUT_DIR="$2";  shift 2 ;;
        --auditor)    AUDITOR="$2";     shift 2 ;;
        --formats)    FORMATS="$2";     shift 2 ;;
        --skip-report) SKIP_REPORT=true; shift ;;
        --verbose)    VERBOSE=true;     shift ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --profile     AWS profile name"
            echo "  --region      AWS region (default: us-east-1)"
            echo "  --services    Comma-separated services (default: all)"
            echo "  --output-dir  Output directory (default: outputs)"
            echo "  --auditor     Auditor name for report"
            echo "  --formats     Report formats: pdf,html,markdown (default: all)"
            echo "  --skip-report Skip report generation"
            echo "  --verbose     Verbose output"
            exit 0
            ;;
        *) error "Unknown option: $1"; exit 1 ;;
    esac
done

# ── Pre-flight checks ─────────────────────────────────────────────────────────
log "AWS Security Audit Suite"
log "Project dir : $PROJECT_DIR"

cd "$PROJECT_DIR"

# Verificar Python
if ! command -v python3 &>/dev/null; then
    error "python3 not found. Install Python 3.10+."
    exit 1
fi

PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
log "Python      : $PYTHON_VERSION"

# Verificar virtualenv o instalar dependencias
if [[ -d ".venv" ]]; then
    log "Activating virtualenv..."
    source .venv/bin/activate
elif [[ -f "requirements.txt" ]]; then
    warn "No virtualenv found. Installing dependencies globally..."
    pip3 install -r requirements.txt -q
fi

# Verificar boto3
if ! python3 -c "import boto3" &>/dev/null; then
    error "boto3 not found. Run: pip install -r requirements.txt"
    exit 1
fi

# Verificar credenciales AWS
log "Verifying AWS credentials..."
if [[ -n "$PROFILE" ]]; then
    export AWS_PROFILE="$PROFILE"
fi

if ! aws sts get-caller-identity --region "$REGION" --output text &>/dev/null; then
    error "AWS credentials not valid or not configured."
    error "Configure via: aws configure --profile $PROFILE"
    exit 1
fi

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null)
success "Authenticated as account: $ACCOUNT_ID"

# ── Crear directorios de salida ───────────────────────────────────────────────
mkdir -p "$OUTPUT_DIR"/{json,reports,dashboard}
log "Output dir  : $OUTPUT_DIR"

# ── Construir comando Python ──────────────────────────────────────────────────
CMD="python3 main.py"
CMD+=" --region $REGION"
CMD+=" --output-dir $OUTPUT_DIR"
CMD+=" --formats $FORMATS"

[[ -n "$PROFILE" ]]  && CMD+=" --profile $PROFILE"
[[ -n "$SERVICES" ]] && CMD+=" --services $SERVICES"
[[ -n "$AUDITOR" ]]  && CMD+=" --auditor \"$AUDITOR\""
[[ "$SKIP_REPORT" == "true" ]] && CMD+=" --skip-report"
[[ "$VERBOSE" == "true" ]]     && CMD+=" --verbose"

# ── Ejecutar ──────────────────────────────────────────────────────────────────
log "Starting audit..."
echo ""

START_TS=$(date +%s)

if eval "$CMD"; then
    END_TS=$(date +%s)
    ELAPSED=$((END_TS - START_TS))
    echo ""
    success "Audit completed in ${ELAPSED}s"
    success "Reports saved to: $OUTPUT_DIR/reports/"
    exit 0
elif [[ $? -eq 2 ]]; then
    END_TS=$(date +%s)
    ELAPSED=$((END_TS - START_TS))
    echo ""
    warn "Audit completed in ${ELAPSED}s with CRITICAL findings"
    warn "Review reports in: $OUTPUT_DIR/reports/"
    exit 2
else
    error "Audit failed with unexpected error"
    exit 1
fi