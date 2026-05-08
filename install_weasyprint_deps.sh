#!/usr/bin/env bash
# Instala dependencias del sistema para WeasyPrint en WSL Ubuntu 20.04
set -e

echo "Detectando versión de Ubuntu..."
UBUNTU_VERSION=$(lsb_release -rs 2>/dev/null || echo "unknown")
echo "Ubuntu: $UBUNTU_VERSION"

echo "Actualizando lista de paquetes..."
sudo apt-get update -qq

echo "Instalando dependencias del sistema..."
sudo apt-get install -y \
  libglib2.0-0 \
  libpango-1.0-0 \
  libpangocairo-1.0-0 \
  libpangoft2-1.0-0 \
  libcairo2 \
  libgdk-pixbuf2.0-0 \
  libffi-dev \
  shared-mime-info \
  libxml2 \
  libxslt1.1 \
  fontconfig \
  fonts-liberation

echo "Reinstalando WeasyPrint..."
pip install --force-reinstall weasyprint --break-system-packages 2>/dev/null || \
pip install --force-reinstall weasyprint

echo "Verificando instalación..."
python3 -c "
from weasyprint import HTML
import tempfile, os
with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as f:
    tmp = f.name
HTML(string='<h1>WeasyPrint OK</h1>').write_pdf(tmp)
os.unlink(tmp)
print('WeasyPrint instalado correctamente ✅')
"