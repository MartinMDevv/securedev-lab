"""Aplicación deliberadamente vulnerable para la evaluación OCY1102 EV3.

Solo debe ejecutarse en el laboratorio local. El alumnado debe revisar y corregir
los defectos; estos comentarios no enumeran las respuestas de la evaluación.
"""

import os
import sqlite3
import time
from pathlib import Path

from flask import Flask, abort, g, redirect, render_template, request, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from werkzeug.security import check_password_hash, generate_password_hash


HTTP_REQUESTS = Counter(
    "securedev_http_requests_total",
    "Solicitudes HTTP de la aplicación",
    ["endpoint", "method", "status"],
)
HTTP_DURATION = Histogram(
    "securedev_http_request_duration_seconds",
    "Duración de solicitudes HTTP",
    ["endpoint"],
)
LOGIN_FAILURES = Counter(
    "securedev_login_failures_total",
    "Intentos de acceso fallidos",
)


def create_app(database_path=None):
    app = Flask(__name__)
    # Sin valor por defecto: con una clave conocida cualquiera puede firmar su propia
    # cookie de sesión (ej. user_id=2) y entrar como otro usuario.
    secret_key = os.getenv("SECRET_KEY", "")
    if len(secret_key) < 32:
        raise RuntimeError(
            "Falta SECRET_KEY o es demasiado corta (mínimo 32 caracteres). "
            "Generar una con: python3 -c 'import secrets; print(secrets.token_hex(32))'"
        )
    app.config["SECRET_KEY"] = secret_key
    # Cookie de sesión: no legible desde JavaScript y no enviada en peticiones de otros sitios.
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    # Secure exige HTTPS; el laboratorio corre en HTTP, así que se activa por variable.
    app.config["SESSION_COOKIE_SECURE"] = os.getenv("SESSION_COOKIE_SECURE") == "1"
    app.config["DATABASE_PATH"] = str(
        database_path or os.getenv("DATABASE_PATH", str(Path(__file__).with_name("securedev.db")))
    )

    # Token CSRF obligatorio en todo POST: sin él la petición se rechaza con 400.
    CSRFProtect(app)

    # Límite de intentos por IP (contador en memoria del proceso: por eso producción
    # corre con un solo worker de gunicorn).
    limiter = Limiter(get_remote_address, app=app, storage_uri="memory://")

    def db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE_PATH"])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(_error):
        connection = g.pop("db", None)
        if connection is not None:
            connection.close()

    @app.before_request
    def start_request_timer():
        g.request_started_at = time.perf_counter()

    @app.after_request
    def security_headers(response):
        # Solo recursos del propio sitio, sin plugins, sin ser embebida en iframes.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; object-src 'none'; base-uri 'self'; "
            "form-action 'self'; frame-ancestors 'none'"
        )
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin"
        return response

    @app.after_request
    def record_request(response):
        if request.endpoint != "metrics":
            endpoint = request.endpoint or "unknown"
            HTTP_REQUESTS.labels(endpoint, request.method, str(response.status_code)).inc()
            # Si otra validación cortó la petición antes de iniciar el cronómetro (ej. CSRF),
            # igual se cuenta: esos rechazos son justo los que interesa ver en Grafana.
            started = g.get("request_started_at", time.perf_counter())
            HTTP_DURATION.labels(endpoint).observe(time.perf_counter() - started)
        return response

    with app.app_context():
        Path(app.config["DATABASE_PATH"]).parent.mkdir(parents=True, exist_ok=True)
        connection = db()
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tickets (
                id INTEGER PRIMARY KEY,
                owner_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                body TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY,
                ticket_id INTEGER NOT NULL,
                author_id INTEGER NOT NULL,
                body TEXT NOT NULL
            );
            """
        )
        if connection.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            connection.executemany(
                "INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
                [
                    (1, "ana", generate_password_hash("ana123")),
                    (2, "bruno", generate_password_hash("bruno123")),
                ],
            )
            connection.executemany(
                "INSERT INTO tickets (id, owner_id, title, body) VALUES (?, ?, ?, ?)",
                [
                    (1, 1, "Revisión de despliegue", "Preparar evidencias de CI/CD."),
                    (2, 2, "Acceso al panel", "Revisar registros de acceso."),
                ],
            )
        connection.commit()

    def current_user():
        return session.get("user_id")

    def ticket_del_usuario(ticket_id):
        """Devuelve el ticket solo si pertenece al usuario actual; si no, 404.

        Se responde 404 y no 403 para no confirmar que el ticket existe.
        """
        item = db().execute(
            "SELECT id, owner_id, title, body FROM tickets WHERE id = ? AND owner_id = ?",
            (ticket_id, current_user()),
        ).fetchone()
        if item is None:
            abort(404)
        return item

    @app.route("/")
    def index():
        if not current_user():
            return redirect(url_for("login"))
        tickets = db().execute(
            "SELECT id, title FROM tickets WHERE owner_id = ? ORDER BY id", (current_user(),)
        ).fetchall()
        return render_template("index.html", tickets=tickets)

    @app.route("/login", methods=["GET", "POST"])
    # Fuerza bruta: más de 5 intentos por minuto desde la misma IP reciben 429.
    @limiter.limit("5 per minute", methods=["POST"])
    def login():
        error = None
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            user = db().execute(
                "SELECT id, username, password_hash FROM users WHERE username = ?", (username,)
            ).fetchone()
            if user and check_password_hash(user["password_hash"], password):
                session.clear()
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                return redirect(url_for("index"))
            LOGIN_FAILURES.inc()
            # Registro para auditoría: quién intentó y desde dónde (%r evita inyectar saltos de línea).
            app.logger.warning("Login fallido usuario=%r ip=%s", username, request.remote_addr)
            error = "Credenciales inválidas"
        return render_template("login.html", error=error)

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.get("/tickets/<int:ticket_id>")
    def ticket(ticket_id):
        if not current_user():
            return redirect(url_for("login"))
        item = ticket_del_usuario(ticket_id)
        comments = db().execute(
            "SELECT body FROM comments WHERE ticket_id = ? ORDER BY id", (ticket_id,)
        ).fetchall()
        return render_template("ticket.html", ticket=item, comments=comments)

    @app.post("/tickets/<int:ticket_id>/comments")
    def add_comment(ticket_id):
        if not current_user():
            return redirect(url_for("login"))
        ticket_del_usuario(ticket_id)
        body = request.form.get("body", "")
        db().execute(
            "INSERT INTO comments (ticket_id, author_id, body) VALUES (?, ?, ?)",
            (ticket_id, current_user(), body),
        )
        db().commit()
        return redirect(url_for("ticket", ticket_id=ticket_id))

    @app.get("/search")
    def search():
        if not current_user():
            return redirect(url_for("login"))
        query = request.args.get("q", "")
        # Consulta parametrizada: el texto del usuario viaja como DATO, nunca como parte del SQL.
        # Y solo se busca entre los tickets del usuario que inició sesión.
        tickets = db().execute(
            "SELECT id, title FROM tickets WHERE owner_id = ? AND title LIKE ? ORDER BY id",
            (current_user(), f"%{query}%"),
        ).fetchall()
        return render_template("search.html", tickets=tickets, query=query)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/metrics")
    def metrics():
        return app.response_class(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

    return app


if __name__ == "__main__":
    # Solo para desarrollo local. Staging y producción usan gunicorn (ver Dockerfile y ci/).
    create_app().run(host="127.0.0.1", port=8000)
