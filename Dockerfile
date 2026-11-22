FROM python:3.15-slim-bookworm

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Usuario sin privilegios: si alguien compromete la app, no es root dentro del contenedor.
RUN useradd --system --uid 10001 --no-create-home app \
 && mkdir -p /data && chown app /data

COPY app.py ./
COPY templates ./templates
COPY static ./static

ENV PYTHONUNBUFFERED=1 DATABASE_PATH=/data/securedev.db
USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"
# gunicorn en vez del servidor de desarrollo de Flask. Un worker: las métricas de
# Prometheus y el límite de intentos viven en la memoria del proceso.
CMD ["gunicorn", "--workers", "1", "--threads", "4", "--bind", "0.0.0.0:8000", "app:create_app()"]
