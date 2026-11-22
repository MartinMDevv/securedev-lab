"""Una prueba (o más) por cada vulnerabilidad corregida.

Los números (#1, #2…) son los de la tabla de vulnerabilidades del informe. Cada prueba
falla sobre el código original (tag v0-vulnerable) y pasa después de su corrección.
"""

import pytest

from app import create_app
from conftest import comentar, login, token_csrf

TICKET_DE_ANA = 1
TICKET_DE_BRUNO = 2


# 1 · Inyección SQL en /search ------------------------------------------------------

def test_1_sqli_comilla_no_rompe_la_consulta(client):
    login(client, "ana", "ana123")
    assert client.get("/search", query_string={"q": "'"}).status_code == 200


def test_1_sqli_payload_no_devuelve_tickets_ajenos(client):
    login(client, "ana", "ana123")
    html = client.get("/search", query_string={"q": "' OR '1'='1"}).get_data(as_text=True)
    assert "Acceso al panel" not in html


# 2 · La búsqueda mostraba tickets de otros usuarios ---------------------------------

def test_2_busqueda_solo_devuelve_mis_tickets(client):
    login(client, "ana", "ana123")
    html = client.get("/search", query_string={"q": ""}).get_data(as_text=True)
    assert "Revisión de despliegue" in html
    assert "Acceso al panel" not in html


# 3 · XSS almacenado en comentarios --------------------------------------------------

def test_3_comentario_con_script_sale_escapado(client):
    login(client, "ana", "ana123")
    comentar(client, TICKET_DE_ANA, "<script>alert(1)</script>")
    html = client.get(f"/tickets/{TICKET_DE_ANA}").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


# 4 · IDOR al ver tickets ------------------------------------------------------------

def test_4_no_puedo_ver_ticket_ajeno(client):
    login(client, "ana", "ana123")
    assert client.get(f"/tickets/{TICKET_DE_BRUNO}").status_code == 404


# 5 · IDOR al comentar ---------------------------------------------------------------

def test_5_no_puedo_comentar_ticket_ajeno(client):
    login(client, "ana", "ana123")
    assert comentar(client, TICKET_DE_BRUNO, "comentario intruso").status_code == 404

    client.post("/logout", data={"csrf_token": token_csrf(client, "/") or ""})
    login(client, "bruno", "bruno123")
    assert "comentario intruso" not in client.get(f"/tickets/{TICKET_DE_BRUNO}").get_data(as_text=True)


# 6 · CSRF ---------------------------------------------------------------------------

def test_6_login_sin_token_csrf_es_rechazado(client):
    respuesta = client.post("/login", data={"username": "ana", "password": "ana123"})
    assert respuesta.status_code == 400


def test_6_comentario_sin_token_csrf_es_rechazado(client):
    login(client, "ana", "ana123")
    respuesta = client.post(f"/tickets/{TICKET_DE_ANA}/comments", data={"body": "sin token"})
    assert respuesta.status_code == 400


def test_6_formularios_traen_token_csrf(client):
    assert token_csrf(client, "/login") is not None
    login(client, "ana", "ana123")
    assert token_csrf(client, f"/tickets/{TICKET_DE_ANA}") is not None


# 7 · SECRET_KEY por defecto ---------------------------------------------------------

def test_7_sin_secret_key_la_app_no_arranca(tmp_path, monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError):
        create_app(tmp_path / "test.db")


def test_7_secret_key_corta_es_rechazada(tmp_path, monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "corta")
    with pytest.raises(RuntimeError):
        create_app(tmp_path / "test.db")


# 8 · Fuerza bruta en el login -------------------------------------------------------

def test_8_login_bloquea_tras_cinco_intentos_por_minuto(client):
    codigos = [login(client, "ana", f"mala-{i}").status_code for i in range(6)]
    assert codigos[:5] == [200] * 5
    assert codigos[5] == 429


# 9 · Configuración insegura ---------------------------------------------------------

def test_9_cabeceras_de_seguridad(client):
    cabeceras = client.get("/login").headers
    assert "default-src 'self'" in cabeceras["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in cabeceras["Content-Security-Policy"]
    assert cabeceras["X-Frame-Options"] == "DENY"
    assert cabeceras["X-Content-Type-Options"] == "nosniff"
    assert cabeceras["Referrer-Policy"] == "same-origin"


def test_9_cookie_de_sesion_httponly_y_samesite(client):
    cookie = login(client, "ana", "ana123").headers["Set-Cookie"]
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie
