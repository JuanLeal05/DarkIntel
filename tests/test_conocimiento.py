import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from darkintel.ner import conocimiento as kb
import darkintel.ner.hibrido as hibrido
import darkintel.ner.transformer as tr
from darkintel import evaluacion as ev


# ── Limpieza y alias ─────────────────────────────────────────

@pytest.mark.parametrize("entrada,esperado", [
    ("Cobalt Strike beacons", "Cobalt Strike"),     # sufijo genérico (prueba real)
    ("the Cobalt Strike beacon", "Cobalt Strike"),
    ("LockBit 3.0", "LockBit"),                      # versión (prueba real)
    ("LockBit 3.0 ransomware builder", "LockBit"),
    ("RedLine v2", "RedLine"),
    ("RedLine stealer", "RedLine"),
    ("grupo FIN7", "FIN7"),                          # prueba real en español
    ("FIN7,", "FIN7"),
    ("Lazarus Group", "Lazarus"),
    ("APT29", "APT29"),                              # el número es parte del nombre
    ("mimi", "Mimikatz"),                            # alias
    ("QBot", "QakBot"),
    ("ALPHV", "BlackCat"),
    ("Spear Phishing", "spear-phishing"),
    ("mimikatz", "Mimikatz"),                        # mayúsculas canónicas
    ("UnknownLoader 2.1", "UnknownLoader"),          # desconocido: solo se limpia
])
def test_canonicalizar(entrada, esperado):
    assert kb.canonicalizar(entrada) == esperado


# ── Corrección de tipos ──────────────────────────────────────

def test_corrige_los_tipos_que_confundio_el_modelo():
    # Salida REAL de SecureBERT-NER en la prueba del 22/10
    del_modelo = {"malware": ["Cobalt Strike beacons", "Mimikatz"],
                  "actor": ["FIN7"], "herramienta": [], "tecnica": ["spear-phishing"]}
    r = kb.corregir(del_modelo)
    assert r["herramienta"] == ["Cobalt Strike", "Mimikatz"]
    assert r["malware"] == []
    assert r["actor"] == ["FIN7"]
    assert r["tecnica"] == ["spear-phishing"]


def test_nombre_ambiguo_respeta_el_tipo_del_modelo():
    # LockBit puede ser malware o actor: si el modelo dijo actor, se respeta
    assert kb.corregir({"actor": ["LockBit"]})["actor"] == ["LockBit"]
    assert kb.corregir({"malware": ["LockBit"]})["malware"] == ["LockBit"]
    # ...pero nunca herramienta
    assert kb.corregir({"herramienta": ["LockBit"]})["malware"] == ["LockBit"]


def test_nombre_desconocido_conserva_el_tipo_del_modelo():
    r = kb.corregir({"malware": ["NewLocker beacon"], "herramienta": []})
    assert r["malware"] == ["NewLocker"]


def test_corregir_deduplica_tras_canonicalizar():
    r = kb.corregir({"herramienta": ["Mimikatz", "mimi", "MIMIKATZ"]})
    assert r["herramienta"] == ["Mimikatz"]


def test_descarta_terminos_genericos_que_el_modelo_etiqueta():
    # Visto en run_ner.py con el modelo real: "C2" salió como herramienta
    r = kb.corregir({"herramienta": ["C2", "Cobalt Strike"], "malware": ["ransomware", "RAT"],
                     "tecnica": ["hacking"]})
    assert r["herramienta"] == ["Cobalt Strike"]
    assert r["malware"] == [] and r["tecnica"] == []


# ── Detección por diccionario ────────────────────────────────

def test_detecta_alias_que_el_modelo_no_conoce():
    r = kb.detectar_en_texto("dump creds with mimi then move laterally")
    assert r["herramienta"] == ["Mimikatz"]


def test_contexto_decide_malware_o_actor():
    r = kb.detectar_en_texto("LockBit encrypted the DC. LockBit affiliates get 80%.")
    assert r["malware"] == ["LockBit"]
    assert r["actor"] == ["LockBit"]
    r = kb.detectar_en_texto("LockBit 3.0 operators are recruiting")
    assert r["actor"] == ["LockBit"] and r["malware"] == []


def test_no_cuenta_phishing_dentro_de_spear_phishing():
    r = kb.detectar_en_texto("initial access via spear-phishing")
    assert r["tecnica"] == ["spear-phishing"]


def test_alias_ambiguos_no_se_detectan_sueltos():
    # "CS" puede ser Counter-Strike: no se busca suelto en el texto
    r = kb.detectar_en_texto("selling CS skins and computer science notes")
    assert all(v == [] for v in r.values())


def test_no_detecta_partes_de_otras_palabras():
    r = kb.detectar_en_texto("the hydraulic pump and the nmapper tool")
    assert r["herramienta"] == []


def test_texto_sin_entidades():
    assert all(v == [] for v in kb.detectar_en_texto("Read the rules before posting.").values())


# ── Fusión e integración en el híbrido ───────────────────────

def test_fusionar_el_modelo_manda_y_el_diccionario_agrega():
    r = kb.fusionar({"actor": ["LockBit"], "herramienta": []},
                    {"malware": ["LockBit"], "herramienta": ["Mimikatz"]})
    assert r["actor"] == ["LockBit"]            # tipo del modelo (contexto)
    assert r.get("malware", []) == []           # no se duplica
    assert r["herramienta"] == ["Mimikatz"]     # lo que el modelo no vio


def _modelo_falso(predicciones):
    return patch.object(tr, "_cargar_pipeline", lambda: (lambda texto: predicciones))


def test_hibrido_completo_sobre_la_frase_de_la_prueba_real(monkeypatch):
    monkeypatch.setenv("DARKINTEL_NER_TRANSFORMER", "1")
    monkeypatch.setenv("DARKINTEL_NER_KB", "1")
    texto = ("LockBit 3.0 affiliates are using Cobalt Strike beacons and Mimikatz to "
             "dump credentials. The intrusion was attributed to FIN7, who gained "
             "initial access via spear-phishing.")
    # Lo que devolvió SecureBERT-NER realmente (umbral ya aplicado aparte)
    preds = [
        {"entity_group": "APT", "word": " LockBit", "score": 0.905},
        {"entity_group": "MAL", "word": " Cobalt Strike beacons", "score": 0.85},
        {"entity_group": "MAL", "word": " Mimikatz", "score": 0.916},
        {"entity_group": "APT", "word": " FIN7,", "score": 0.926},
        {"entity_group": "ACT", "word": " spear-phishing.", "score": 0.922},
    ]
    with _modelo_falso(preds):
        r = hibrido.extraer(texto)["entidades"]
    assert r["actor"] == ["LockBit", "FIN7"]          # "affiliates" => grupo
    assert r["herramienta"] == ["Cobalt Strike", "Mimikatz"]
    assert r["malware"] == []
    assert r["tecnica"] == ["spear-phishing"]


def test_hibrido_sin_kb_deja_la_salida_cruda_del_modelo(monkeypatch):
    monkeypatch.setenv("DARKINTEL_NER_TRANSFORMER", "1")
    monkeypatch.setenv("DARKINTEL_NER_KB", "0")
    with _modelo_falso([{"entity_group": "MAL", "word": "Mimikatz", "score": 0.9}]):
        r = hibrido.extraer("Mimikatz")["entidades"]
    assert r["malware"] == ["Mimikatz"]               # sin corregir


def test_kb_sin_transformer_no_carga_el_modelo(monkeypatch):
    monkeypatch.setenv("DARKINTEL_NER_TRANSFORMER", "0")
    monkeypatch.setenv("DARKINTEL_NER_KB", "1")

    def no_debe_llamarse():
        raise AssertionError("no debe cargar el modelo")
    with patch.object(tr, "_cargar_pipeline", no_debe_llamarse):
        r = hibrido.extraer("dump creds with mimi")["entidades"]
    assert r["herramienta"] == ["Mimikatz"]


# ── El evaluador usa la misma canonicalización ───────────────

def test_evaluador_trata_alias_y_canonico_como_iguales():
    vacio = {t: [] for t in ev.TIPOS_IOC}
    ref = {"p01": {"iocs": vacio, "entidades": {"malware": [], "herramienta": ["mimi"],
                                                 "actor": [], "tecnica": []}}}
    pred = {"p01": {"iocs": vacio, "entidades": {"malware": [], "herramienta": ["Mimikatz"],
                                                  "actor": [], "tecnica": []}}}
    assert ev.comparar(ref, pred, ["p01"])["entidades.herramienta"]["f1"] == 1.0