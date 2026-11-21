#!/usr/bin/env bash
# Corre OWASP ZAP autenticado contra staging. Devuelve el código de salida de ZAP:
#   0 sin alertas · 1 alertas de riesgo alto (o error) · 2 alertas de riesgo medio
set -uo pipefail
target="$1" reportes="$2"
plan="$(mktemp --suffix=.yaml)"
trap 'rm -f "$plan"' EXIT   # el plan final lleva la cookie: no se guarda

# Usuario de prueba de los datos semilla (públicos en el repo, solo laboratorio).
cookie="$(./ci/sesion-zap.sh "$target" ana ana123)" || exit 1

# El job «replacer» de ZAP no expande variables de entorno (las URLs sí). Por eso el
# plan se arma aquí con todas las variables ya reemplazadas.
TARGET="$target" REPORT_DIR="$reportes" SESSION_COOKIE="$cookie" \
python3 -c 'import os, sys; print(os.path.expandvars(open(sys.argv[1]).read()))' \
    security/zap.yaml > "$plan"

# -port 8090: el proxy de ZAP usa 8080 por defecto, que es el de Jenkins.
zap.sh -cmd -port 8090 -autorun "$plan" 2>&1 | tee "$reportes/zap-consola.log"
exit "${PIPESTATUS[0]}"
