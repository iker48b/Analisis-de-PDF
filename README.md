# Analizador de PDFs sospechosos (phishing)

Script en Bash para analizar PDFs recibidos por correo y detectar posibles indicios de phishing/malware: enlaces ocultos, JavaScript embebido, auto-ejecución, códigos QR ("quishing"), cifrado sospechoso y más.

## ¿Qué hace?

Para cada PDF que coincida con el prefijo indicado, genera un informe con:

- **Metadatos** (`exiftool`)
- **Estructura interna** (`pdfid`): detecta `/OpenAction`, `/AA`, `/JS`, `/URI`, `/Encrypt`
- **Alertas de auto-ejecución** y combinaciones sospechosas (JS + URI)
- **Intento automático de descifrado** si el PDF está cifrado (`qpdf`, con o sin contraseña)
- **Enlaces detectados** vía render HTML (`pdftohtml`)
- **URIs embebidas** directamente en el binario (`strings`), como complemento
- **Contenido JavaScript embebido** (`pdf-parser.py`, opcional)
- **Detección de códigos QR** (`pdftoppm` + `zbarimg`, opcional)
- **Permisos y tipo real del archivo** (detecta ejecutables disfrazados de PDF)
- **Hashes MD5/SHA256** con enlace directo a VirusTotal

El resultado se guarda en un **informe HTML** (`evidencias_<prefijo>.html` por defecto) con:

- Un índice al inicio con enlace directo a cada PDF y un badge de riesgo (`SIN ALERTAS` / `RIESGO MEDIO` / `RIESGO ALTO`)
- Alertas resaltadas por color (verde/ámbar/rojo) para cada hallazgo
- Secciones organizadas en tarjetas por tipo de análisis
- Enlace directo a VirusTotal por cada hash

Todo el contenido extraído del propio PDF (metadatos, JavaScript, URIs, enlaces) se **escapa** antes de insertarse en el HTML, para evitar que un PDF malicioso pueda inyectar código en el propio informe al abrirlo en el navegador.

## Requisitos

Dependencias obligatorias:

```bash
sudo apt update && sudo apt install exiftool pdfid poppler-utils binutils
```

(`pdftohtml` viene en `poppler-utils`; `strings` viene en `binutils`)

Dependencias opcionales (si faltan, esas secciones se omiten sin detener el análisis):

- `pdf-parser.py` — extracción de JavaScript embebido
- `pdftoppm` + `zbarimg` (`poppler-utils` + `zbar-tools`) — detección de códigos QR
- `qpdf` — intento automático de descifrado

## Uso

```bash
chmod +x analisis.sh

./analisis.sh <prefijo> [-p contraseña] [archivo_salida]
```

### Ejemplos

```bash
./analisis.sh Michael evidencias.html
./analisis.sh Factura                      # salida por defecto: evidencias_Factura.html
./analisis.sh ATT2023876304419.pdf -p "contraseña_del_pdf"
```

El script busca todos los archivos `<prefijo>*.pdf` en el directorio actual.

## ⚠️ Advertencia de seguridad

- Este script está pensado para analizar archivos **potencialmente maliciosos**. Ejecútalo en un entorno aislado (VM, sandbox) si sospechas que el PDF puede explotar vulnerabilidades del propio sistema.
- Si usas la opción `-p` para pasar una contraseña, ten en cuenta que quedará visible en el historial de tu shell y en la lista de procesos (`ps aux`) mientras el script corre. Evita usarla con contraseñas sensibles en sistemas compartidos.
- El script **no sube nada a VirusTotal automáticamente**; solo genera el enlace para que la consulta se haga manualmente.
- El informe HTML generado puede contener enlaces/URIs extraídos del PDF analizado. No hagas clic directamente desde el informe; cópialos a un entorno seguro (ej. [urlscan.io](https://urlscan.io)) si necesitas visitarlos.

## Licencia

Uso libre para fines de análisis y respuesta ante incidentes.
