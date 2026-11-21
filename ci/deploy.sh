#!/usr/bin/env bash
# «Producción» del laboratorio: gunicorn dentro del contenedor de Jenkins, puerto 8000.
# Prometheus la alcanza por la red Docker «securedev» como jenkins-p3:8000.
#
# Cada build queda en su propia carpeta (releases/<n°>) y «actual» apunta a la vigente:
# volver atrás es apuntar «actual» a la release anterior y reiniciar.
set -euo pipefail
: "${PROD_DIR:?}" "${PROD_PORT:?}" "${BUILD_NUMBER:?}"

mkdir -p "$PROD_DIR/releases" "$PROD_DIR/data" "$PROD_DIR/logs"
rel="$PROD_DIR/releases/$BUILD_NUMBER"

# El secreto de sesión se genera una vez en el servidor y nunca pasa por git.
if [ ! -s "$PROD_DIR/secret_key" ]; then
    (umask 077; python3 -c 'import secrets; print(secrets.token_hex(32))' > "$PROD_DIR/secret_key")
fi

rm -rf "$rel" && mkdir -p "$rel"
cp -r app.py templates requirements.txt "$rel/"
python3 -m venv "$rel/.venv"
"$rel/.venv/bin/pip" install --quiet -r "$rel/requirements.txt"

# Detener la versión anterior, si hay una corriendo.
if [ -s "$PROD_DIR/gunicorn.pid" ]; then
    kill "$(cat "$PROD_DIR/gunicorn.pid")" 2>/dev/null || true
    sleep 2
fi

ln -sfn "$rel" "$PROD_DIR/actual"
cd "$PROD_DIR/actual"
# Un solo worker: las métricas de prometheus_client viven en memoria del proceso;
# con varios workers cada uno contaría por separado. Los hilos dan la concurrencia.
SECRET_KEY="$(cat "$PROD_DIR/secret_key")" \
DATABASE_PATH="$PROD_DIR/data/securedev.db" \
.venv/bin/gunicorn --daemon --pid "$PROD_DIR/gunicorn.pid" \
    --workers 1 --threads 4 \
    --bind "0.0.0.0:$PROD_PORT" \
    --access-logfile "$PROD_DIR/logs/access.log" \
    --error-logfile "$PROD_DIR/logs/error.log" \
    'app:create_app()'

"$WORKSPACE/ci/esperar-salud.sh" "http://127.0.0.1:$PROD_PORT/health"
echo "Desplegada la build $BUILD_NUMBER en $rel"

# Guardar solo las 5 releases más recientes.
ls -1dt "$PROD_DIR"/releases/*/ | tail -n +6 | xargs -r rm -rf
