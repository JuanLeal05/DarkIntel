"""
Tests del NER con Transformer SIN descargar el modelo: se simula la salida
del pipeline de HuggingFace con el mismo formato que devuelve
aggregation_strategy="first". La validación con el modelo real se hace con:

    python src/darkintel/ner/transformer.py
"""
import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import darkintel.ner.transformer as tr
import darkintel.ner.hibrido as hibrido


def _pred(grupo, palabra, score, inicio=0):
    return {"entity_group": grupo, "word": palabra, "score": score,
            "start": inicio, "end": inicio + len(palabra)}


def _con_modelo_falso(predicciones):
    """Reemplaza el modelo real por uno que devuelve `predicciones`."""
    return patch.object(tr, "_cargar_pipeline", lambda: (lambda texto: predicciones))


TEXTO = "LockBit 3.0 affiliates use Cobalt Strike; attributed to FIN7 via spear-phishing"


# ── Mapeo de etiquetas ───────────────────────────────────────

def test_mapea_etiquetas_aptner_a_categorias():
    preds = [
        _pred("MAL", " LockBit 3.0", 0.97),
        _pred("TOOL", " Cobalt Strike", 0.95),
        _pred("APT", " FIN7", 0.99),
        _pred("ACT", " spear-phishing", 0.90),
    ]
    with _con_modelo_falso(preds):
        r = tr.extraer_entidades(TEXTO)
    assert r == {
        "malware": ["LockBit 3.0"],
        "actor": ["FIN7"],
        "herramienta": ["Cobalt Strike"],
        "tecnica": ["spear-phishing"],
    }


def test_acepta_etiquetas_con_prefijo_bio():
    # Por si un modelo alternativo devuelve "B-MAL" sin agregar.
    with _con_modelo_falso([_pred("B-MAL", "Emotet", 0.9)]):
        assert tr.extraer_entidades("x")["malware"] == ["Emotet"]


def test_ignora_etiquetas_atomicas_que_cubre_la_regex():
    preds = [
        _pred("IP", "198.51.100.23", 0.99),
        _pred("DOM", "evil.onion", 0.99),
        _pred("MD5", "5d41402abc4b2a76b9719d911017c592", 0.99),
        _pred("PROT", "HTTPS", 0.99),   # el modelo trae PROT sin prefijo B-/I-
    ]
    with _con_modelo_falso(preds):
        r = tr.extraer_entidades("x")
    assert all(v == [] for v in r.values())


# ── Filtrado y normalización ─────────────────────────────────

def test_descarta_predicciones_bajo_el_umbral():
    preds = [_pred("MAL", "Emotet", 0.95), _pred("MAL", "Netflix", 0.40)]
    with _con_modelo_falso(preds):
        assert tr.extraer_entidades("x", umbral=0.8)["malware"] == ["Emotet"]


def test_deduplica_sin_distinguir_mayusculas():
    preds = [_pred("MAL", "LockBit", 0.9), _pred("MAL", " lockbit", 0.9),
             _pred("MAL", "LOCKBIT.", 0.9)]
    with _con_modelo_falso(preds):
        assert tr.extraer_entidades("x")["malware"] == ["LockBit"]


def test_limpia_espacios_y_puntuacion_de_bordes():
    with _con_modelo_falso([_pred("TOOL", '  "Cobalt   Strike", ', 0.9)]):
        assert tr.extraer_entidades("x")["herramienta"] == ["Cobalt Strike"]


def test_descarta_fragmentos_sin_sentido():
    preds = [_pred("MAL", "3", 0.99), _pred("MAL", "x", 0.99),
             _pred("MAL", "...", 0.99), _pred("APT", "2024", 0.99)]
    with _con_modelo_falso(preds):
        r = tr.extraer_entidades("x")
    assert r["malware"] == [] and r["actor"] == []


def test_texto_vacio_no_llama_al_modelo():
    def no_debe_llamarse():
        raise AssertionError("no debe cargar el modelo para texto vacío")
    with patch.object(tr, "_cargar_pipeline", no_debe_llamarse):
        assert all(v == [] for v in tr.extraer_entidades("   ").values())


def test_recorta_textos_enormes_antes_del_modelo():
    recibido = {}

    def modelo(texto):
        recibido["largo"] = len(texto)
        return []
    with patch.object(tr, "_cargar_pipeline", lambda: modelo):
        tr.extraer_entidades("a" * (tr.MAX_CARACTERES + 5000))
    assert recibido["largo"] == tr.MAX_CARACTERES


# ── NER híbrido ──────────────────────────────────────────────

def test_hibrido_combina_regex_y_transformer(monkeypatch):
    monkeypatch.setenv("DARKINTEL_NER_TRANSFORMER", "1")
    texto = "LockBit C2 en 198[.]51[.]100[.]23 explotando CVE-2024-9001"
    with _con_modelo_falso([_pred("MAL", "LockBit", 0.96)]):
        r = hibrido.extraer(texto)
    assert "198.51.100.23" in r["iocs"]["ip"]          # de la regex
    assert "CVE-2024-9001" in r["iocs"]["cve"]          # de la regex
    assert r["entidades"]["malware"] == ["LockBit"]     # del transformer


def test_hibrido_con_transformer_desactivado_no_carga_el_modelo(monkeypatch):
    monkeypatch.setenv("DARKINTEL_NER_TRANSFORMER", "0")

    def no_debe_llamarse():
        raise AssertionError("no debe cargar el modelo si está desactivado")
    with patch.object(tr, "_cargar_pipeline", no_debe_llamarse):
        r = hibrido.extraer("C2 en 198.51.100.23")
    assert "198.51.100.23" in r["iocs"]["ip"]
    assert all(v == [] for v in r["entidades"].values())


def test_hibrido_falla_ruidosamente_si_el_modelo_no_carga(monkeypatch):
    # Activado + modelo roto => error, NUNCA un "solo regex" silencioso.
    monkeypatch.setenv("DARKINTEL_NER_TRANSFORMER", "1")

    def modelo_roto():
        raise OSError("modelo no encontrado en la caché")
    with patch.object(tr, "_cargar_pipeline", modelo_roto):
        try:
            hibrido.extraer("LockBit")
            assert False, "debía propagar el error"
        except OSError:
            pass