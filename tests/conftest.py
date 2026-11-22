"""Piezas compartidas por todas las pruebas."""

import re

import pytest

from app import create_app


@pytest.fixture
def app(tmp_path, monkeypatch):
    # La app exige SECRET_KEY por variable de entorno (vulnerabilidad #7).
    monkeypatch.setenv("SECRET_KEY", "clave-solo-para-pruebas-" + "x" * 32)
    aplicacion = create_app(tmp_path / "test.db")
    aplicacion.config["TESTING"] = True
    return aplicacion


@pytest.fixture
def client(app):
    return app.test_client()


def token_csrf(client, ruta):
    """Saca el token CSRF del formulario de una página (None si la página no trae)."""
    html = client.get(ruta).get_data(as_text=True)
    encontrado = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
    return encontrado.group(1) if encontrado else None


def login(client, usuario, clave):
    datos = {"username": usuario, "password": clave}
    token = token_csrf(client, "/login")
    if token:
        datos["csrf_token"] = token
    return client.post("/login", data=datos)


def comentar(client, ticket_id, texto):
    datos = {"body": texto}
    token = token_csrf(client, "/")
    if token:
        datos["csrf_token"] = token
    return client.post(f"/tickets/{ticket_id}/comments", data=datos)
