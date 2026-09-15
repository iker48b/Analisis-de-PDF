#!/bin/bash
# Analizador de PDFs con extracción de hipervínculos
# Uso:
#   phishing <prefijo> [-p contraseña] [archivo_salida]
# Ejemplo:
#   phishing Michael evidencias.html
#   phishing Factura   # salida por defecto evidencias_Factura.html
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
SALIDA="${2:-evidencias_${PREFIJO}.html}"

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

# ---------- Escapado HTML ----------
# TODO el contenido que provenga del propio PDF (metadatos, JS, URIs, enlaces...)
# se considera NO CONFIABLE y se escapa antes de insertarlo en el informe HTML.
# Sin esto, un PDF malicioso podría inyectar <script> en el propio informe
# que abrirás luego en un navegador.
esc() {
  sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e "s/'/\&#39;/g" -e 's/"/\&quot;/g'
}
esc1() {
  printf '%s' "$1" | esc
}

# Habilita nullglob para que un patrón sin coincidencias no pase el literal
shopt -s nullglob

# Recoge la lista de PDFs que coinciden
PDFS=( "${PREFIJO}"*.pdf )

# ---------- Cabecera / pie del informe HTML ----------
html_header() {
  cat <<'HTMLHEAD'
<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Informe de análisis de PDFs</title>
<style>
  :root {
    --bg: #0f1115; --panel: #171a21; --border: #2a2e37;
    --text: #e6e6e6; --muted: #9aa0aa;
    --ok: #2fbf71; --ok-bg: #12261c;
    --warn: #e8a13a; --warn-bg: #2b2214;
    --danger: #e5484d; --danger-bg: #2b1516;
    --accent: #5b8cff;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 24px; background: var(--bg); color: var(--text);
    font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
    line-height: 1.5;
  }
  h1 { font-size: 1.6rem; margin-bottom: 4px; }
  .subtitle { color: var(--muted); margin-bottom: 24px; font-size: .9rem; }
  .toc {
    background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
    padding: 16px 20px; margin-bottom: 28px;
  }
  .toc h2 { margin-top: 0; font-size: 1.05rem; }
  .toc ul { list-style: none; margin: 0; padding: 0; }
  .toc li { padding: 6px 0; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; gap: 12px; align-items: center; }
  .toc li:last-child { border-bottom: none; }
  .toc a { color: var(--accent); text-decoration: none; word-break: break-all; }
  .toc a:hover { text-decoration: underline; }
  section.report {
    background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
    padding: 20px 24px; margin-bottom: 24px;
  }
  section.report > h2 { margin-top: 0; word-break: break-all; font-size: 1.2rem; }
  .card {
    background: #12141a; border: 1px solid var(--border); border-radius: 8px;
    padding: 12px 16px; margin: 12px 0;
  }
  .card h3 { margin: 0 0 8px 0; font-size: .95rem; color: var(--muted); text-transform: uppercase; letter-spacing: .03em; }
  pre {
    white-space: pre-wrap; word-break: break-word; margin: 0;
    font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: .85rem;
    max-height: 400px; overflow-y: auto;
  }
  .alert { border-radius: 8px; padding: 10px 14px; margin: 8px 0; font-size: .9rem; }
  .alert.ok { background: var(--ok-bg); color: var(--ok); border: 1px solid var(--ok); }
  .alert.warn { background: var(--warn-bg); color: var(--warn); border: 1px solid var(--warn); }
  .alert.danger { background: var(--danger-bg); color: var(--danger); border: 1px solid var(--danger); }
  .badge { display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: .75rem; font-weight: 600; white-space: nowrap; }
  .badge.ok { background: var(--ok-bg); color: var(--ok); }
  .badge.warn { background: var(--warn-bg); color: var(--warn); }
  .badge.danger { background: var(--danger-bg); color: var(--danger); }
  table.hashes { border-collapse: collapse; width: 100%; font-size: .85rem; }
  table.hashes td { padding: 4px 8px; vertical-align: top; }
  table.hashes td:first-child { color: var(--muted); white-space: nowrap; }
  table.hashes a { color: var(--accent); word-break: break-all; }
  footer { color: var(--muted); font-size: .8rem; margin-top: 32px; text-align: center; }
</style>
</head>
<body>
HTMLHEAD
}

html_footer() {
  cat <<HTMLFOOT
<footer>Generado el $(date '+%Y-%m-%d %H:%M:%S') · $0</footer>
</body>
</html>
HTMLFOOT
}

badge_html() {
  # $1 = nivel: ok | warn | danger
  case "$1" in
    danger) echo '<span class="badge danger">RIESGO ALTO</span>' ;;
    warn)   echo '<span class="badge warn">RIESGO MEDIO</span>' ;;
    *)      echo '<span class="badge ok">SIN ALERTAS</span>' ;;
  esac
}

if [[ ${#PDFS[@]} -eq 0 ]]; then
  echo "⚠️ No se encontraron PDFs que empiecen por '${PREFIJO}'."
  {
    html_header
    echo "<h1>Informe de análisis de PDFs</h1>"
    echo "<p class=\"subtitle\">Prefijo buscado: $(esc1 "$PREFIJO")</p>"
    echo "<div class=\"alert warn\">No se encontraron PDFs con el prefijo '$(esc1 "$PREFIJO")'.</div>"
    html_footer
  } > "$SALIDA"
  echo "✅ Análisis completado. Revisa el archivo: $SALIDA"
  exit 0
fi

# ---------- Función: extraer enlaces con pdftohtml ----------
extract_links_with_pdftohtml () {
  local pdf="$1"
  local TMP_BASE
  TMP_BASE="$(mktemp -u)"
  if ! pdftohtml -s -i "$pdf" "$TMP_BASE" > /dev/null 2>&1; then
    return 2
  fi

  local HTML_FILE="${TMP_BASE}-html.html"
  if [[ ! -f "$HTML_FILE" ]]; then
    HTML_FILE_CANDIDATE=$(ls "${TMP_BASE}"*.html 2>/dev/null | head -n 1 || true)
    if [[ -n "${HTML_FILE_CANDIDATE:-}" ]]; then
      HTML_FILE="$HTML_FILE_CANDIDATE"
    else
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

TOC_HTML=""
BODY_HTML=""
INDEX=0

# ---------- Bucle principal ----------
for file in "${PDFS[@]}"; do
  INDEX=$((INDEX+1))
  ANCHOR="pdf-${INDEX}"
  RISK="ok"   # ok < warn < danger
  ALERTS_HTML=""

  add_alert () {
    # $1 = ok|warn|danger  $2 = mensaje (texto plano, se escapa)
    ALERTS_HTML+="<div class=\"alert $1\">$(esc1 "$2")</div>"$'\n'
    if [[ "$1" == "danger" ]]; then RISK="danger"
    elif [[ "$1" == "warn" && "$RISK" != "danger" ]]; then RISK="warn"
    fi
  }

  SECTION_HEAD="<section class=\"report\" id=\"${ANCHOR}\">"$'\n'
  SECTION_HEAD+="<h2>📄 $(esc1 "$file")</h2>"$'\n'
  SECTION=""

  # 1. Metadatos
  META_OUT="$(exiftool "$file" 2>&1)" || true
  SECTION+="<div class=\"card\"><h3>Metadatos (exiftool)</h3><pre>$(printf '%s' "$META_OUT" | esc)</pre></div>"$'\n'

  # 2. Estructura interna (pdfid)
  PDFID_OUT="$(pdfid "$file" 2>&1)" || true
  SECTION+="<div class=\"card\"><h3>Análisis de estructura (pdfid)</h3><pre>$(printf '%s' "$PDFID_OUT" | esc)</pre></div>"$'\n'

  # 2b. Alerta explícita sobre auto-ejecución (/OpenAction, /AA)
  OPENACTION_COUNT="$(echo "${PDFID_OUT}" | grep -E '^\s*/OpenAction' | awk '{print $2}')"
  AA_COUNT="$(echo "${PDFID_OUT}" | grep -E '^\s*/AA' | awk '{print $2}')"
  JS_COUNT="$(echo "${PDFID_OUT}" | grep -E '^\s*/JS\b' | awk '{print $2}')"
  URI_COUNT="$(echo "${PDFID_OUT}" | grep -E '^\s*/URI\b' | awk '{print $2}')"

  if [[ "${OPENACTION_COUNT:-0}" != "0" && -n "${OPENACTION_COUNT:-}" ]]; then
    add_alert warn "/OpenAction presente (${OPENACTION_COUNT}) — el PDF ejecuta una acción al abrirse"
  fi
  if [[ "${AA_COUNT:-0}" != "0" && -n "${AA_COUNT:-}" ]]; then
    add_alert warn "/AA (Additional Actions) presente (${AA_COUNT}) — acciones automáticas ante eventos (abrir/cerrar/etc.)"
  fi
  if [[ "${JS_COUNT:-0}" != "0" && -n "${JS_COUNT:-}" ]] && [[ "${URI_COUNT:-0}" != "0" && -n "${URI_COUNT:-}" ]]; then
    add_alert danger "JavaScript + URI detectados juntos — patrón típico de redirección/phishing automatizado"
  fi
  if [[ "${OPENACTION_COUNT:-0}" == "0" || -z "${OPENACTION_COUNT:-}" ]] && [[ "${AA_COUNT:-0}" == "0" || -z "${AA_COUNT:-}" ]]; then
    add_alert ok "No se detectó /OpenAction ni /AA"
  fi

  # 2c. Detección de cifrado (/Encrypt) — condiciona el resto del análisis
  ENCRYPT_COUNT="$(echo "${PDFID_OUT}" | grep -E '^\s*/Encrypt\b' | awk '{print $2}')"
  IS_ENCRYPTED=0
  DECRYPT_TMP=""
  WORK_FILE="$file"
  if [[ "${ENCRYPT_COUNT:-0}" != "0" && -n "${ENCRYPT_COUNT:-}" ]]; then
    IS_ENCRYPTED=1
    add_alert danger "PDF cifrado (/Encrypt) — técnica común para evadir gateways de correo/antivirus automáticos. Las secciones de enlaces y QR podrían no poder procesar el contenido."

    if [[ "${HAS_QPDF}" -eq 1 ]]; then
      DECRYPT_TMP="$(mktemp --suffix=.pdf)"
      if qpdf --decrypt "$file" "$DECRYPT_TMP" > /dev/null 2>&1; then
        add_alert ok "Descifrado sin contraseña: el PDF solo tenía restricciones de permisos, no contraseña de apertura. Se usará la versión descifrada."
        WORK_FILE="$DECRYPT_TMP"
      elif [[ -n "${PASSWORD}" ]]; then
        if qpdf --password="${PASSWORD}" --decrypt "$file" "$DECRYPT_TMP" > /dev/null 2>&1; then
          add_alert ok "Descifrado correctamente con la contraseña proporcionada (-p). Se usará la versión descifrada."
          WORK_FILE="$DECRYPT_TMP"
        else
          add_alert warn "La contraseña proporcionada (-p) no es válida para este archivo."
          rm -f "$DECRYPT_TMP"
          DECRYPT_TMP=""
        fi
      else
        add_alert warn "No se pudo descifrar sin contraseña: probablemente requiere contraseña de apertura. Esto en sí mismo es una señal de riesgo si el PDF viene de un remitente no verificado. Reejecuta con: $0 ${PREFIJO} -p \"la_contraseña\""
        rm -f "$DECRYPT_TMP"
        DECRYPT_TMP=""
      fi
    else
      add_alert warn "Omitido: qpdf no está instalado (no se intentó descifrado automático)"
    fi
  fi

  # 3. Enlaces (HTML con hipervínculos)
  if [[ "${IS_ENCRYPTED}" -eq 1 && -z "${DECRYPT_TMP}" ]]; then
    LINKS_BLOCK="⚠️ No se pudo extraer: el PDF sigue cifrado"
  else
    LINKS="$(extract_links_with_pdftohtml "$WORK_FILE" || true)"
    if [[ -n "${LINKS}" ]]; then
      LINKS_BLOCK="$LINKS"
      add_alert warn "Se detectaron enlaces embebidos en el PDF — revísalos antes de hacer clic"
    else
      LINKS_BLOCK="Sin enlaces detectados"
    fi
  fi
  SECTION+="<div class=\"card\"><h3>Enlaces detectados (pdftohtml)</h3><pre>$(printf '%s' "$LINKS_BLOCK" | esc)</pre></div>"$'\n'

  # 3b. URIs embebidas en el binario (complemento a pdftohtml)
  BIN_URIS="$(extract_uris_from_binary "$WORK_FILE" || true)"
  if [[ -n "${BIN_URIS}" ]]; then
    BIN_URIS_BLOCK="$BIN_URIS"
  else
    BIN_URIS_BLOCK="Sin URIs adicionales detectadas en el binario"
  fi
  SECTION+="<div class=\"card\"><h3>URIs embebidas en el binario (strings)</h3><pre>$(printf '%s' "$BIN_URIS_BLOCK" | esc)</pre></div>"$'\n'

  # 4. Contenido de JavaScript embebido (si hay pdf-parser.py disponible)
  if [[ "${HAS_PDF_PARSER}" -eq 1 ]]; then
    JS_CONTENT="$(pdf-parser.py --search /JavaScript "$WORK_FILE" 2>/dev/null || true)"
    if [[ -n "${JS_CONTENT}" ]]; then
      JS_BLOCK="$JS_CONTENT"
      add_alert danger "Se encontró contenido JavaScript embebido en el PDF"
    else
      JS_BLOCK="Sin contenido JavaScript extraíble o no se encontró el objeto"
    fi
  else
    JS_BLOCK="Omitido: pdf-parser.py no está instalado"
  fi
  SECTION+="<div class=\"card\"><h3>Contenido JavaScript embebido</h3><pre>$(printf '%s' "$JS_BLOCK" | esc)</pre></div>"$'\n'

  # 5. Detección de códigos QR ("quishing")
  if [[ "${HAS_QR_TOOLS}" -eq 1 ]]; then
    QR_TMP="$(mktemp -d)"
    if pdftoppm -png -r 150 "$WORK_FILE" "${QR_TMP}/page" > /dev/null 2>&1; then
      QR_RESULTS="$(zbarimg --quiet "${QR_TMP}"/page*.png 2>/dev/null | grep -i 'QR-Code' || true)"
      if [[ -n "${QR_RESULTS}" ]]; then
        QR_BLOCK="$QR_RESULTS"
        add_alert danger "Código(s) QR detectado(s) en el PDF"
      else
        QR_BLOCK="Sin códigos QR detectados"
      fi
    else
      if [[ "${IS_ENCRYPTED}" -eq 1 && -z "${DECRYPT_TMP}" ]]; then
        QR_BLOCK="⚠️ No se pudo renderizar: el PDF sigue cifrado"
      else
        QR_BLOCK="⚠️ No se pudieron renderizar páginas para buscar QR"
      fi
    fi
    rm -rf "${QR_TMP}"
  else
    QR_BLOCK="Omitido: pdftoppm/zbarimg no están instalados"
  fi
  SECTION+="<div class=\"card\"><h3>Detección de códigos QR (quishing)</h3><pre>$(printf '%s' "$QR_BLOCK" | esc)</pre></div>"$'\n'

  # 6. Permisos del archivo
  perms=$(stat -c "%A" "$file" 2>/dev/null || echo "desconocido")
  if [[ "$perms" == *"x"* ]]; then
    add_alert warn "El archivo tiene permisos de ejecución ($perms) — sospechoso"
  fi

  # 7. Tipo real del archivo
  tipo=$(file "$file" 2>/dev/null || echo "desconocido")
  if [[ "$tipo" != *"PDF"* ]]; then
    add_alert danger "El archivo NO es un PDF real (posible ejecutable disfrazado): $tipo"
  fi

  # 8. Hashes para reputación
  md5=$(md5sum "$file" | awk '{print $1}')
  sha256=$(sha256sum "$file" | awk '{print $1}')
  SECTION+="<div class=\"card\"><h3>Permisos, tipo y hashes</h3>"$'\n'
  SECTION+="<table class=\"hashes\">"$'\n'
  SECTION+="<tr><td>Permisos</td><td>$(esc1 "$perms")</td></tr>"$'\n'
  SECTION+="<tr><td>Tipo real</td><td>$(esc1 "$tipo")</td></tr>"$'\n'
  SECTION+="<tr><td>MD5</td><td>$(esc1 "$md5")</td></tr>"$'\n'
  SECTION+="<tr><td>SHA256</td><td>$(esc1 "$sha256")</td></tr>"$'\n'
  SECTION+="<tr><td>VirusTotal</td><td><a href=\"https://www.virustotal.com/gui/file/${sha256}\" target=\"_blank\" rel=\"noopener noreferrer\">Consultar reputación</a></td></tr>"$'\n'
  SECTION+="</table></div>"$'\n'
  # TODO: cuando tengas API key de VirusTotal, automatizar esta consulta
  # con curl contra https://www.virustotal.com/api/v3/files/<sha256>

  SUMMARY="<div class=\"summary\">$(badge_html "$RISK")"$'\n'"$ALERTS_HTML"$'\n'"</div>"$'\n'

  BODY_HTML+="${SECTION_HEAD}${SUMMARY}${SECTION}</section>"$'\n'

  TOC_HTML+="<li><a href=\"#${ANCHOR}\">$(esc1 "$file")</a> $(badge_html "$RISK")</li>"$'\n'

  # Limpieza del archivo temporal descifrado, si se creó
  if [[ -n "${DECRYPT_TMP}" && -f "${DECRYPT_TMP}" ]]; then
    rm -f "${DECRYPT_TMP}"
  fi
done

{
  html_header
  echo "<h1>Informe de análisis de PDFs</h1>"
  echo "<p class=\"subtitle\">Prefijo: $(esc1 "$PREFIJO") · ${#PDFS[@]} archivo(s) analizado(s)</p>"
  echo "<div class=\"toc\"><h2>Resumen</h2><ul>"
  echo "$TOC_HTML"
  echo "</ul></div>"
  echo "$BODY_HTML"
  html_footer
} > "$SALIDA"

echo "✅ Análisis completado. Revisa el archivo: $SALIDA"
