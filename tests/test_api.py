import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient

import api.main as api_main

cliente = TestClient(api_main.app)


# ── Entrada valida ───────────────────────────────────────────

def test_extrae_iocs_de_texto_valido():
    r = cliente.post("/iocs/extract",
                     json={"texto": "C2 en 198[.]51[.]100[.]42 explotando CVE-2024-1234"})
    assert r.status_code == 200
    assert "198.51.100.42" in r.json()["iocs"]["ip"]
    assert "CVE-2024-1234" in r.json()["iocs"]["cve"]


# ── Entrada invalida -> 422, nunca 500 ───────────────────────

def test_texto_no_string_devuelve_422_y_no_500():
    r = cliente.post("/iocs/extract", json={"texto": 123})
    assert r.status_code == 422


def test_texto_vacio_o_ausente_devuelve_422():
    assert cliente.post("/iocs/extract", json={"texto": ""}).status_code == 422
    assert cliente.post("/iocs/extract", json={}).status_code == 422


def test_campo_desconocido_devuelve_422():
    r = cliente.post("/iocs/extract", json={"texto": "hola", "extra": 1})
    assert r.status_code == 422


def test_texto_demasiado_largo_devuelve_422():
    texto = "a" * (api_main.MAX_CARACTERES_TEXTO + 1)
    r = cliente.post("/iocs/extract", json={"texto": texto})
    assert r.status_code == 422


# ── Limite de cuerpo antes de parsear ────────────────────────

def test_cuerpo_gigante_se_rechaza_con_413():
    cuerpo = b'{"texto": "' + b"a" * (api_main.MAX_BYTES_CUERPO + 1) + b'"}'
    r = cliente.post("/iocs/extract", content=cuerpo,
                     headers={"Content-Type": "application/json"})
    assert r.status_code == 413


def test_get_no_exige_content_length():
    # El limite solo aplica a metodos con cuerpo; los GET siguen funcionando.
    assert cliente.get("/").status_code == 200


# ── /stats ───────────────────────────────────────────────────

def test_stats_no_cuenta_el_ruido_como_campana():
    bundles = {
        "cluster_0":  {"objects": [{"type": "campaign"}, {"type": "indicator"}]},
        "cluster_1":  {"objects": [{"type": "campaign"}]},
        "cluster_-1": {"objects": [{"type": "indicator"}]},
    }
    with patch.object(api_main, "cargar_bundles", return_value=bundles):
        r = cliente.get("/stats")
    assert r.status_code == 200
    assert r.json()["campanas_detectadas"] == 2
    assert r.json()["indicadores"] == 2