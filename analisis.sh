#!/bin/bash
# Analizador de PDFs con extracción de hipervínculos
# Uso:
#   phishing <prefijo> [-p contraseña] [archivo_salida]
# Ejemplo:
#   phishing Michael evidencias.txt
#   phishing Factura   # salida por defecto evidencias_Factura.txt
#   phishing ATT2023876304419.pdf -p "contraseña_del_pdf"

set -uo pipefail
# Nota: se ha quitado la 'e' de set -euo pipefail a propósito.
# Con -e, un solo PDF corrupto que haga fallar exiftool/pdfid detendría
# todo el análisis del lote. Ahora cada comando gestiona su propio error.

# ---------- Parseo de argumentos ----------
# Se separa el flag -p (contraseña) del resto, ya que puede aparecer en
# cualquier posición: "phishing Factura -p 1234" o "phishing -p 1234 Factura".
PASSWORD=""
POSITIONAL=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -p)
      if [[ -z "${2:-}" ]]; then
        echo "❌ Error: -p requiere una contraseña a continuación."
        exit 1
      fi
      PASSWORD="$2"
      shift 2
      ;;
    -p=*)
      PASSWORD="${1#-p=}"
      shift
      ;;
    *)
      POSITIONAL+=("$1")
      shift
      ;;
  esac
done
set -- "${POSITIONAL[@]:-}"

# ---------- Validación de argumentos ----------
if [[ $# -lt 1 || -z "${1:-}" ]]; then
  echo "❌ Error: Debes proporcionar un prefijo para buscar PDFs."
  echo "Uso: $0 <prefijo> [-p contraseña] [archivo_salida]"
  exit 1
fi

PREFIJO="$1"
# Si el usuario ha pasado el nombre completo con extensión (.pdf, .PDF, .Pdf...),
# la quitamos para que el patrón de búsqueda de abajo funcione igual con o sin ella.
PREFIJO="${PREFIJO%.[Pp][Dd][Ff]}"
SALIDA="${2:-evidencias_${PREFIJO}.txt}"

# ---------- Comprobación de dependencias ----------
need_cmd () {
  command -v "$1" >/dev/null 2>&1 || {
    echo "❌ Falta la dependencia: $1"
    MISSING=1
  }
}

# Dependencias obligatorias
MISSING=0
need_cmd exiftool
need_cmd pdfid
need_cmd pdftohtml
need_cmd md5sum
need_cmd sha256sum
need_cmd stat
need_cmd file
need_cmd grep
need_cmd mktemp
need_cmd strings

if [[ "${MISSING}" -eq 1 ]]; then
  echo
  echo "💡 Instala las dependencias faltantes. En Debian/Parrot:"
  echo "   sudo apt update && sudo apt install exiftool pdfid poppler-utils binutils"
  echo "   (pdftohtml viene en poppler-utils; strings viene en binutils)"
  exit 1
fi

# Dependencias opcionales (mejoras 4 y 5) — si faltan, se avisa una vez y se
# omiten esas secciones sin detener el script.
HAS_PDF_PARSER=1
command -v pdf-parser.py >/dev/null 2>&1 || HAS_PDF_PARSER=0

HAS_QR_TOOLS=1
command -v pdftoppm >/dev/null 2>&1 || HAS_QR_TOOLS=0
command -v zbarimg   >/dev/null 2>&1 || HAS_QR_TOOLS=0

HAS_QPDF=1
command -v qpdf >/dev/null 2>&1 || HAS_QPDF=0

if [[ "${HAS_PDF_PARSER}" -eq 0 ]]; then
  echo "ℹ️  Opcional no instalado: pdf-parser.py (contenido de JavaScript embebido se omitirá)"
fi
if [[ "${HAS_QR_TOOLS}" -eq 0 ]]; then
  echo "ℹ️  Opcional no instalado: pdftoppm/zbarimg (detección de QR se omitirá)"
  echo "    Instalación: sudo apt install poppler-utils zbar-tools"
fi
if [[ "${HAS_QPDF}" -eq 0 ]]; then
  echo "ℹ️  Opcional no instalado: qpdf (intento automático de descifrado se omitirá)"
  echo "    Instalación: sudo apt install qpdf"
fi

# ---------- Preparación de salida ----------
: > "$SALIDA"

# Habilita nullglob para que un patrón sin coincidencias no pase el literal
shopt -s nullglob

# Recoge la lista de PDFs que coinciden
PDFS=( "${PREFIJO}"*.pdf )

if [[ ${#PDFS[@]} -eq 0 ]]; then
  echo "⚠️ No se encontraron PDFs que empiecen por '${PREFIJO}'."
  echo "⚠️ No se encontraron PDFs con el prefijo '${PREFIJO}'" >> "$SALIDA"
  echo "✅ Análisis completado. Revisa el archivo: $SALIDA"
  exit 0
fi

# ---------- Función: extraer enlaces con pdftohtml ----------
extract_links_with_pdftohtml () {
  local pdf="$1"
  local TMP_BASE
  TMP_BASE="$(mktemp -u)"
  if ! pdftohtml -s -i "$pdf" "$TMP_BASE" > /dev/null 2>&1; then
    echo "⚠️ pdftohtml falló al procesar '$pdf'"
    return 2
  fi

  local HTML_FILE="${TMP_BASE}-html.html"
  if [[ ! -f "$HTML_FILE" ]]; then
    HTML_FILE_CANDIDATE=$(ls "${TMP_BASE}"*.html 2>/dev/null | head -n 1 || true)
    if [[ -n "${HTML_FILE_CANDIDATE:-}" ]]; then
      HTML_FILE="$HTML_FILE_CANDIDATE"
    else
      echo "⚠️ No se generó HTML para '$pdf'"
      return 3
    fi
  fi

  grep -Eo '(http|https)://[^"'\''<> ]+' "$HTML_FILE" \
    | grep -v '^http://www\.w3\.org/1999/xhtml$' \
    | sort -u

  rm -f "${TMP_BASE}"*.html "${TMP_BASE}"*.xml 2>/dev/null || true
}

# ---------- Función: extraer URIs embebidas directamente del binario ----------
# Complementa a pdftohtml, que solo captura enlaces "renderizados". Muchos
# PDFs maliciosos ocultan URIs en objetos internos que no se muestran.
extract_uris_from_binary () {
  local pdf="$1"
  strings "$pdf" \
    | grep -Eo '/URI\s*\(([^)]*)\)' \
    | sed -E 's#/URI\s*\(##; s#\)$##' \
    | sort -u
}

# ---------- Bucle principal ----------
for file in "${PDFS[@]}"; do
  {
    echo "========================================"
    echo "EVIDENCIAS PARA: $file"
    echo "========================================"

    # 1. Metadatos
    echo -e "\n--- METADATOS (exiftool) ---"
    exiftool "$file" || echo "⚠️ exiftool falló al procesar este archivo"

    # 2. Estructura interna (pdfid)
    echo -e "\n--- ANÁLISIS ESTRUCTURA (pdfid) ---"
    PDFID_OUT="$(pdfid "$file" 2>&1)" || echo "⚠️ pdfid falló al procesar este archivo"
    echo "${PDFID_OUT}"

    # 2b. Alerta explícita sobre auto-ejecución (/OpenAction, /AA)
    echo -e "\n--- ALERTAS DE AUTO-EJECUCIÓN ---"
    OPENACTION_COUNT="$(echo "${PDFID_OUT}" | grep -E '^\s*/OpenAction' | awk '{print $2}')"
    AA_COUNT="$(echo "${PDFID_OUT}" | grep -E '^\s*/AA' | awk '{print $2}')"
    JS_COUNT="$(echo "${PDFID_OUT}" | grep -E '^\s*/JS\b' | awk '{print $2}')"
    URI_COUNT="$(echo "${PDFID_OUT}" | grep -E '^\s*/URI\b' | awk '{print $2}')"

    if [[ "${OPENACTION_COUNT:-0}" != "0" && -n "${OPENACTION_COUNT:-}" ]]; then
      echo "⚠️ ALERTA: /OpenAction presente (${OPENACTION_COUNT}) — el PDF ejecuta una acción al abrirse"
    fi
    if [[ "${AA_COUNT:-0}" != "0" && -n "${AA_COUNT:-}" ]]; then
      echo "⚠️ ALERTA: /AA (Additional Actions) presente (${AA_COUNT}) — acciones automáticas ante eventos (abrir/cerrar/etc.)"
    fi
    if [[ "${JS_COUNT:-0}" != "0" && -n "${JS_COUNT:-}" ]] && [[ "${URI_COUNT:-0}" != "0" && -n "${URI_COUNT:-}" ]]; then
      echo "🚨 ALERTA ALTA: JavaScript + URI detectados juntos — patrón típico de redirección/phishing automatizado"
    fi
    if [[ "${OPENACTION_COUNT:-0}" == "0" || -z "${OPENACTION_COUNT:-}" ]] && [[ "${AA_COUNT:-0}" == "0" || -z "${AA_COUNT:-}" ]]; then
      echo "OK: No se detectó /OpenAction ni /AA"
    fi

    # 2c. Detección de cifrado (/Encrypt) — condiciona el resto del análisis
    ENCRYPT_COUNT="$(echo "${PDFID_OUT}" | grep -E '^\s*/Encrypt\b' | awk '{print $2}')"
    IS_ENCRYPTED=0
    DECRYPT_TMP=""
    WORK_FILE="$file"
    if [[ "${ENCRYPT_COUNT:-0}" != "0" && -n "${ENCRYPT_COUNT:-}" ]]; then
      IS_ENCRYPTED=1
      echo "🚨 ALERTA: PDF cifrado (/Encrypt) — técnica común para evadir gateways de correo/antivirus automáticos"
      echo "   Nota: al estar cifrado, las secciones de enlaces y QR de abajo probablemente no puedan procesar el contenido."

      # 2d. Intento automático de descifrado.
      # Primero sin contraseña (por si el cifrado es solo de permisos).
      # Si falla y el usuario pasó -p, se reintenta con la contraseña dada.
      echo -e "\n--- INTENTO DE DESCIFRADO (qpdf) ---"
      if [[ "${HAS_QPDF}" -eq 1 ]]; then
        DECRYPT_TMP="$(mktemp --suffix=.pdf)"
        if qpdf --decrypt "$file" "$DECRYPT_TMP" > /dev/null 2>&1; then
          echo "✅ Descifrado sin contraseña: el PDF solo tenía restricciones de permisos, no contraseña de apertura."
          echo "   Se usará la versión descifrada para las secciones de enlaces y QR."
          WORK_FILE="$DECRYPT_TMP"
        elif [[ -n "${PASSWORD}" ]]; then
          if qpdf --password="${PASSWORD}" --decrypt "$file" "$DECRYPT_TMP" > /dev/null 2>&1; then
            echo "✅ Descifrado correctamente con la contraseña proporcionada (-p)."
            echo "   Se usará la versión descifrada para las secciones de enlaces y QR."
            WORK_FILE="$DECRYPT_TMP"
          else
            echo "⚠️ La contraseña proporcionada (-p) no es válida para este archivo."
            rm -f "$DECRYPT_TMP"
            DECRYPT_TMP=""
          fi
        else
          echo "⚠️ No se pudo descifrar sin contraseña: probablemente requiere contraseña de apertura (user password)."
          echo "   Esto en sí mismo es una señal de riesgo si el PDF viene de un remitente no verificado."
          echo "   Si conoces la contraseña, reejecuta con: $0 ${PREFIJO} -p \"la_contraseña\""
          rm -f "$DECRYPT_TMP"
          DECRYPT_TMP=""
        fi
      else
        echo "Omitido: qpdf no está instalado"
      fi
    fi

    # 3. Enlaces (HTML con hipervínculos)
    echo -e "\n--- ENLACES DETECTADOS (pdftohtml) ---"
    if [[ "${IS_ENCRYPTED}" -eq 1 && -z "${DECRYPT_TMP}" ]]; then
      echo "⚠️ No se pudo extraer: el PDF sigue cifrado (descifrado automático falló o no disponible)"
    else
      LINKS="$(extract_links_with_pdftohtml "$WORK_FILE" || true)"
      if [[ -n "${LINKS}" ]]; then
        echo "${LINKS}"
      else
        echo "Sin enlaces detectados"
      fi
    fi

    # 3b. URIs embebidas en el binario (complemento a pdftohtml)
    echo -e "\n--- URIs EMBEBIDAS EN EL BINARIO (strings) ---"
    BIN_URIS="$(extract_uris_from_binary "$WORK_FILE" || true)"
    if [[ -n "${BIN_URIS}" ]]; then
      echo "${BIN_URIS}"
    else
      echo "Sin URIs adicionales detectadas en el binario"
    fi

    # 4. Contenido de JavaScript embebido (si hay pdf-parser.py disponible)
    echo -e "\n--- CONTENIDO JAVASCRIPT EMBEBIDO ---"
    if [[ "${HAS_PDF_PARSER}" -eq 1 ]]; then
      JS_CONTENT="$(pdf-parser.py --search /JavaScript "$WORK_FILE" 2>/dev/null || true)"
      if [[ -n "${JS_CONTENT}" ]]; then
        echo "${JS_CONTENT}"
      else
        echo "Sin contenido JavaScript extraíble o no se encontró el objeto"
      fi
    else
      echo "Omitido: pdf-parser.py no está instalado"
    fi

    # 5. Detección de códigos QR ("quishing")
    echo -e "\n--- DETECCIÓN DE CÓDIGOS QR (quishing) ---"
    if [[ "${HAS_QR_TOOLS}" -eq 1 ]]; then
      QR_TMP="$(mktemp -d)"
      if pdftoppm -png -r 150 "$WORK_FILE" "${QR_TMP}/page" > /dev/null 2>&1; then
        QR_RESULTS="$(zbarimg --quiet "${QR_TMP}"/page*.png 2>/dev/null | grep -i 'QR-Code' || true)"
        if [[ -n "${QR_RESULTS}" ]]; then
          echo "🚨 ALERTA: Código(s) QR detectado(s):"
          echo "${QR_RESULTS}"
        else
          echo "Sin códigos QR detectados"
        fi
      else
        if [[ "${IS_ENCRYPTED}" -eq 1 && -z "${DECRYPT_TMP}" ]]; then
          echo "⚠️ No se pudo renderizar: el PDF sigue cifrado (descifrado automático falló o no disponible)"
        else
          echo "⚠️ No se pudieron renderizar páginas para buscar QR"
        fi
      fi
      rm -rf "${QR_TMP}"
    else
      echo "Omitido: pdftoppm/zbarimg no están instalados"
    fi

    # 6. Permisos del archivo
    echo -e "\n--- PERMISOS DEL ARCHIVO ---"
    perms=$(stat -c "%A" "$file" 2>/dev/null || echo "desconocido")
    echo "Permisos: $perms"
    if [[ "$perms" == *"x"* ]]; then
      echo "⚠️ ALERTA: El archivo tiene permisos de ejecución (sospechoso)"
    else
      echo "OK: No tiene permisos de ejecución"
    fi

    # 7. Tipo real del archivo
    echo -e "\n--- TIPO REAL DEL ARCHIVO ---"
    tipo=$(file "$file" 2>/dev/null || echo "desconocido")
    echo "$tipo"
    if [[ "$tipo" != *"PDF"* ]]; then
      echo "⚠️ ALERTA: El archivo NO es un PDF real (posible ejecutable disfrazado)"
    else
      echo "OK: El archivo es un PDF válido"
    fi

    # 8. Hashes para reputación (consulta manual a VirusTotal por ahora)
    echo -e "\n--- HASHES DEL ARCHIVO ---"
    md5=$(md5sum "$file" | awk '{print $1}')
    sha256=$(sha256sum "$file" | awk '{print $1}')
    echo "MD5: $md5"
    echo "SHA256: $sha256"
    echo "Puedes subir estos hashes a VirusTotal para verificar reputación:"
    echo "https://www.virustotal.com/gui/file/${sha256}"
    # TODO: cuando tengas API key de VirusTotal, automatizar esta consulta
    # con curl contra https://www.virustotal.com/api/v3/files/<sha256>

    echo -e "\n----------------------------------------\n"

    # Limpieza del archivo temporal descifrado, si se creó
    if [[ -n "${DECRYPT_TMP}" && -f "${DECRYPT_TMP}" ]]; then
      rm -f "${DECRYPT_TMP}"
    fi
  } >> "$SALIDA"
done

echo "✅ Análisis completado. Revisa el archivo: $SALIDA"