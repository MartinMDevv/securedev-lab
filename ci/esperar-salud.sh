#!/usr/bin/env bash
# Espera hasta 30 s a que la app responda 200 en /health. Si no, muestra el log y falla.
set -euo pipefail
url="$1"
for _ in $(seq 1 30); do
    if curl -fsS -o /dev/null "$url" 2>/dev/null; then
        echo "App arriba: $url"
        exit 0
    fi
    sleep 1
done
echo "La app no respondió en $url" >&2
exit 1
