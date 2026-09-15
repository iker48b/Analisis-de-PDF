#!/bin/bash
# Instalador de dependencias para el script de análisis de PDFs (analisis.sh)
#
# Uso:
#   sudo ./instalar_dependencias.sh
#
# Qué hace:
#   1. Instala las dependencias OBLIGATORIAS (exiftool, pdfid, poppler-utils, binutils...)
#   2. Instala las dependencias OPCIONALES (qpdf, zbar-tools) para detección de QR y descifrado
#   3. Descarga pdf-parser.py (no está en los repos de apt) para análisis de JavaScript embebido
#   4. Verifica al final que todo quedó correctamente instalado
#
# Solución de conflictos de dependencias:
#   Si tu sistema lleva tiempo sin actualizarse, apt puede rechazar instalar
#   paquetes nuevos con un error del tipo:
#     "libyaml-libyaml-perl : Breaks: lintian (< X.X.X) but Y.Y.Y is to be installed"
#   Esto NO lo soluciona este script automáticamente (a propósito, para no
#   tocar todo el sistema sin tu consentimiento). Si te aparece, actualiza
#   el sistema completo por tu cuenta ANTES de reejecutar este instalador:
#     sudo apt update && sudo apt full-upgrade
#   Revisa qué se va a actualizar antes de confirmar, ya que un full-upgrade
#   afecta a todos los paquetes del equipo, no solo a los de este script.
#
# Pensado para Debian, Parrot OS, Kali y derivados basados en apt.

set -uo pipefail

# ---------- Comprobación de permisos ----------
if [[ "${EUID}" -ne 0 ]]; then
  echo "❌ Este script necesita permisos de administrador."
  echo "   Ejecútalo con: sudo $0"
  exit 1
fi

echo "=========================================="
echo " Instalador de dependencias — analisis.sh"
echo "=========================================="
echo

# ---------- 1. Actualizar índices de paquetes ----------
echo "--- Actualizando índices de apt ---"
apt update

# ---------- 1b. Aviso sobre paquetes desactualizados ----------
# Muchos de los conflictos de dependencias (p.ej. libyaml-libyaml-perl vs
# lintian) aparecen porque hay paquetes desactualizados que chocan entre sí
# con los que se intentan instalar nuevos. Este script NO ejecuta
# 'apt full-upgrade' automáticamente (es una decisión que debe tomar el
# usuario, ya que puede afectar a todo el sistema) — solo avisa si detecta
# esta situación. Ver la nota al principio del archivo sobre cómo resolverlo
# manualmente si aparecen errores de dependencias rotas más abajo.
UPGRADABLE_COUNT="$(apt list --upgradable 2>/dev/null | grep -c '\[upgradable')"
if [[ "${UPGRADABLE_COUNT}" -gt 0 ]]; then
  echo
  echo "⚠️ Hay ${UPGRADABLE_COUNT} paquetes desactualizados en tu sistema."
  echo "   Esto puede causar errores de dependencias rotas (como 'Breaks: lintian') al instalar algo nuevo."
  echo "   Si algún paso de abajo falla por eso, considera ejecutar 'sudo apt full-upgrade' por tu cuenta"
  echo "   (revisa antes qué se va a actualizar, ya que afecta a todo el sistema)."
  echo
fi

# ---------- 2. Dependencias obligatorias ----------
echo
echo "--- Instalando dependencias OBLIGATORIAS ---"

# El paquete de exiftool se llama distinto según la distro/versión.
# Probamos primero el nombre corto y, si no existe, el nombre real de Debian.
if apt-cache show exiftool >/dev/null 2>&1; then
  EXIFTOOL_PKG="exiftool"
else
  EXIFTOOL_PKG="libimage-exiftool-perl"
fi

REQUIRED_PKGS=(
  "${EXIFTOOL_PKG}"
  pdfid
  poppler-utils
  binutils
  coreutils
  util-linux
  file
  grep
)

apt install -y "${REQUIRED_PKGS[@]}"
REQUIRED_STATUS=$?

# ---------- 3. Dependencias opcionales ----------
echo
echo "--- Instalando dependencias OPCIONALES (QR + descifrado) ---"
OPTIONAL_PKGS=(qpdf zbar-tools)

if ! apt install -y "${OPTIONAL_PKGS[@]}"; then
  echo "⚠️ No se pudo instalar alguna dependencia opcional (probablemente por paquetes desactualizados en tu sistema)."
  echo "   El script principal seguirá funcionando, simplemente omitirá esas secciones (QR / descifrado automático)."
  echo "   Consulta la sección 'Solución de conflictos de dependencias' en la documentación si quieres resolverlo."
fi

# ---------- 4. pdf-parser.py (no está en apt) ----------
echo
echo "--- Instalando pdf-parser.py (análisis de JavaScript embebido) ---"
PDF_PARSER_PATH="/usr/local/bin/pdf-parser.py"
PDF_PARSER_URL="https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/pdf-parser.py"

if command -v wget >/dev/null 2>&1; then
  if wget -q -O "${PDF_PARSER_PATH}" "${PDF_PARSER_URL}"; then
    chmod +x "${PDF_PARSER_PATH}"
    echo "✅ pdf-parser.py instalado en ${PDF_PARSER_PATH}"
  else
    echo "⚠️ No se pudo descargar pdf-parser.py (¿sin conexión a GitHub?). Puedes reintentarlo más tarde con:"
    echo "   sudo wget -O ${PDF_PARSER_PATH} ${PDF_PARSER_URL} && sudo chmod +x ${PDF_PARSER_PATH}"
  fi
else
  echo "⚠️ 'wget' no está disponible, instalando..."
  apt install -y wget
  if wget -q -O "${PDF_PARSER_PATH}" "${PDF_PARSER_URL}"; then
    chmod +x "${PDF_PARSER_PATH}"
    echo "✅ pdf-parser.py instalado en ${PDF_PARSER_PATH}"
  else
    echo "⚠️ No se pudo descargar pdf-parser.py."
  fi
fi

# ---------- 5. Verificación final ----------
echo
echo "=========================================="
echo " Verificación de instalación"
echo "=========================================="

check_tool () {
  local name="$1"
  local required="$2"  # "obligatoria" u "opcional"
  if command -v "$name" >/dev/null 2>&1; then
    echo "✅ $name — instalado"
  else
    if [[ "$required" == "obligatoria" ]]; then
      echo "❌ $name — FALTA (obligatoria, el script principal no funcionará)"
    else
      echo "⚠️  $name — falta (opcional, esa sección se omitirá)"
    fi
  fi
}

check_tool exiftool obligatoria
check_tool pdfid obligatoria
check_tool pdftohtml obligatoria
check_tool strings obligatoria
check_tool md5sum obligatoria
check_tool sha256sum obligatoria
check_tool stat obligatoria
check_tool file obligatoria
check_tool mktemp obligatoria
check_tool grep obligatoria
check_tool qpdf opcional
check_tool pdftoppm opcional
check_tool zbarimg opcional
check_tool pdf-parser.py opcional

echo
echo "=========================================="
echo " Instalación finalizada."
echo " Recuerda dar permisos de ejecución a tu script principal:"
echo "   chmod +x analisis.sh"
echo "=========================================="