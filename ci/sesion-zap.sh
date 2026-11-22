#!/usr/bin/env bash
# Inicia sesión en la app y escribe en stdout el valor de la cookie «session».
# ZAP la inyecta en cada petición (job «replacer» de security/zap.yaml), así puede
# escanear las páginas que piden login.
#
# Si el formulario trae token CSRF (después de corregir la app), lo envía también;
# así el mismo script sirve antes y después de las correcciones.
set -euo pipefail
base="$1" usuario="$2" clave="$3"
jar="$(mktemp)"
trap 'rm -f "$jar"' EXIT

pagina="$(curl -fsS -c "$jar" -b "$jar" "$base/login")"
csrf="$(printf '%s' "$pagina" | sed -n 's/.*name="csrf_token"[^>]*value="\([^"]*\)".*/\1/p' | head -1)"

datos=(--data-urlencode "username=$usuario" --data-urlencode "password=$clave")
[ -n "$csrf" ] && datos+=(--data-urlencode "csrf_token=$csrf")

codigo="$(curl -sS -o /dev/null -w '%{http_code}' -c "$jar" -b "$jar" "${datos[@]}" "$base/login")"
if [ "$codigo" != "302" ]; then
    echo "Login de $usuario falló (HTTP $codigo)" >&2
    exit 1
fi

# Visitar una página con sesión hace que la app guarde el token CSRF dentro de la cookie.
# Así ZAP usa una sesión que ya trae su token y puede enviar formularios válidos; si no,
# todos sus POST rebotarían con 400 y el escaneo no probaría nada detrás de ellos.
curl -fsS -o /dev/null -c "$jar" -b "$jar" "$base/"

cookie="$(awk '$6 == "session" { print $7 }' "$jar" | tail -1)"
[ -n "$cookie" ] || { echo "No llegó la cookie de sesión" >&2; exit 1; }
printf '%s' "$cookie"
