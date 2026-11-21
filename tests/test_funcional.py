"""Pruebas funcionales: lo que la app TIENE que seguir haciendo después de corregirla.

Las pruebas de seguridad (una por vulnerabilidad) se agregan en test_seguridad.py,
junto con cada corrección.
"""

import pytest

from app import create_app


@pytest.fixture
def client(tmp_path):
    app = create_app(tmp_path / "test.db")
    app.config["TESTING"] = True
    return app.test_client()


def login(client, usuario, clave):
    return client.post("/login", data={"username": usuario, "password": clave})


def test_health_responde_ok(client):
    respuesta = client.get("/health")
    assert respuesta.status_code == 200
    assert respuesta.get_json() == {"status": "ok"}


def test_sin_sesion_redirige_al_login(client):
    respuesta = client.get("/")
    assert respuesta.status_code == 302
    assert "/login" in respuesta.headers["Location"]


def test_login_correcto_entra(client):
    respuesta = login(client, "ana", "ana123")
    assert respuesta.status_code == 302
    assert client.get("/").status_code == 200


def test_login_incorrecto_muestra_error(client):
    respuesta = login(client, "ana", "clave-mala")
    assert respuesta.status_code == 200
    assert "Credenciales inválidas" in respuesta.get_data(as_text=True)


def test_portada_muestra_solo_mis_tickets(client):
    login(client, "ana", "ana123")
    html = client.get("/").get_data(as_text=True)
    assert "Revisión de despliegue" in html
    assert "Acceso al panel" not in html


def test_se_puede_comentar_mi_ticket(client):
    login(client, "ana", "ana123")
    respuesta = client.post("/tickets/1/comments", data={"body": "Listo el CI"})
    assert respuesta.status_code == 302
    assert "Listo el CI" in client.get("/tickets/1").get_data(as_text=True)


def test_metricas_exponen_logins_fallidos(client):
    login(client, "ana", "clave-mala")
    texto = client.get("/metrics").get_data(as_text=True)
    assert "securedev_login_failures_total" in texto
