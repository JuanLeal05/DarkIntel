import json
import os
import subprocess
import sys

import pytest

RAIZ = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(RAIZ, "src"))

from darkintel import evaluacion as ev

EJEMPLO = os.path.join(RAIZ, "docs", "ejemplo_dataset")


def _anotacion(pid, **valores):
    a = {"post_id": pid,
         "iocs": {t: [] for t in ev.TIPOS_IOC},
         "entidades": {t: [] for t in ev.TIPOS_ENTIDAD}}
    for clave, lista in valores.items():
        grupo = "iocs" if clave in ev.TIPOS_IOC else "entidades"
        a[grupo][clave] = lista
    return a


@pytest.fixture
def dataset(tmp_path):
    posts = [{"post_id": "p01", "split": "dev", "title": "t", "text": "x"},
             {"post_id": "p02", "split": "test", "title": "t", "text": "y"}]
    (tmp_path / "posts.jsonl").write_text("\n".join(json.dumps(p) for p in posts))
    return tmp_path


def _escribir_anotaciones(carpeta, nombre, filas):
    ruta = carpeta / nombre
    ruta.write_text("\n".join(json.dumps(f) for f in filas))
    return str(ruta)


def _errores(carpeta, filas):
    _, _, posts = ev.validar_posts(str(carpeta / "posts.jsonl"))
    ruta = _escribir_anotaciones(carpeta, "anotaciones_X.jsonl", filas)
    return ev.validar_anotaciones(ruta, posts)[0]


# ── Validación ───────────────────────────────────────────────

def test_el_dataset_de_ejemplo_es_valido():
    errores, _, posts = ev.validar_posts(os.path.join(EJEMPLO, "posts.jsonl"))
    assert errores == []
    assert ev.validar_campanas(os.path.join(EJEMPLO, "campanas.json"), posts) == []
    errores, _ = ev.validar_anotaciones(os.path.join(EJEMPLO, "anotaciones_final.jsonl"), posts)
    assert errores == []


def test_anotacion_correcta_no_da_errores(dataset):
    filas = [_anotacion("p01", ip=["198.51.100.23"], malware=["LockBit"]),
             _anotacion("p02")]
    assert _errores(dataset, filas) == []


def test_json_roto_reporta_la_linea(dataset):
    _, _, posts = ev.validar_posts(str(dataset / "posts.jsonl"))
    ruta = dataset / "anotaciones_X.jsonl"
    ruta.write_text(json.dumps(_anotacion("p01")) + '\n{"post_id": "p02", "iocs": ')
    errores, _ = ev.validar_anotaciones(str(ruta), posts)
    assert len(errores) == 1 and ":2:" in errores[0]


@pytest.mark.parametrize("tipo,valor,fragmento", [
    ("ip", "192.168.1.10", "privada"),
    ("ip", "198[.]51[.]100[.]23", "no es una dirección IP"),
    ("ip", "2001:db8::1", "va en 'ipv6'"),
    ("md5", "5D41402ABC4B2A76B9719D911017C592", "minúsculas"),
    ("md5", "d41d8cd98f00b204e9800998ecf8427e", "archivo vacío"),
    ("sha256", "abc123", "64 caracteres"),
    ("cve", "cve-2023-4966", "MAYÚSCULAS"),
    ("dominio", "evil[.]com", "ofuscación"),
    ("dominio", "http://evil.com/gate", "sin http"),
    ("dominio", "Evil.com", "minúsculas"),
    ("tecnica", "Phishing", "minúsculas"),
    ("malware", "LockBit.", "puntuación"),
])
def test_detecta_errores_de_normalizacion(dataset, tipo, valor, fragmento):
    errores = _errores(dataset, [_anotacion("p01", **{tipo: [valor]}), _anotacion("p02")])
    assert any(fragmento in e for e in errores), errores


def test_ips_de_documentacion_son_validas(dataset):
    filas = [_anotacion("p01", ip=["192.0.2.44", "203.0.113.9"], ipv6=["2001:db8::1"]),
             _anotacion("p02")]
    assert _errores(dataset, filas) == []


def test_falta_una_clave_o_un_post(dataset):
    incompleta = _anotacion("p01")
    del incompleta["entidades"]["tecnica"]
    errores = _errores(dataset, [incompleta])
    assert any("entidades.tecnica" in e for e in errores)
    assert any("falta anotar p02" in e for e in errores)


def test_valores_repetidos(dataset):
    errores = _errores(dataset, [_anotacion("p01", malware=["LockBit", "lockbit"]),
                                 _anotacion("p02")])
    assert any("repetidos" in e for e in errores)


def test_campanas_detecta_post_sin_asignar_y_duplicado(dataset):
    _, _, posts = ev.validar_posts(str(dataset / "posts.jsonl"))
    ruta = dataset / "campanas.json"
    ruta.write_text(json.dumps({"c1": ["p01"], "c2": ["p01"]}))
    errores = ev.validar_campanas(str(ruta), posts)
    assert any("p01 está en" in e for e in errores)
    assert any("p02 no está asignado" in e for e in errores)


# ── Métricas ─────────────────────────────────────────────────

def test_comparar_calcula_precision_y_recall():
    ref = {"p01": _anotacion("p01", ip=["1.1.1.1", "2.2.2.2"], malware=["LockBit"])}
    pred = {"p01": _anotacion("p01", ip=["1.1.1.1", "9.9.9.9"], malware=["lockbit"])}
    m = ev.comparar(ref, pred, ["p01"])
    assert m["iocs.ip"] == {"tp": 1, "fp": 1, "fn": 1,
                            "precision": 0.5, "recall": 0.5, "f1": 0.5}
    assert m["entidades.malware"]["f1"] == 1.0        # sin distinguir mayúsculas
    assert m["global"]["tp"] == 2 and m["global"]["fp"] == 1 and m["global"]["fn"] == 1


def test_deteccion_ignora_el_tipo_pero_clasificacion_no():
    # El modelo encontró Mimikatz pero lo llamó malware (caso real de SecureBERT-NER)
    ref = {"p01": _anotacion("p01", herramienta=["Mimikatz"])}
    pred = {"p01": _anotacion("p01", malware=["Mimikatz"])}
    m = ev.comparar(ref, pred, ["p01"])
    assert m["entidades_deteccion"]["f1"] == 1.0      # sí lo encontró
    assert m["entidades_total"]["f1"] == 0.0          # pero con el tipo mal


def test_falsos_positivos_en_post_vacio():
    ref = {"p03": _anotacion("p03")}
    pred = {"p03": _anotacion("p03", ip=["115.0.2.1"])}   # versión tomada como IP
    m = ev.comparar(ref, pred, ["p03"])
    assert m["global"]["fp"] == 1 and m["global"]["precision"] == 0.0


# ── Scripts de línea de comandos ─────────────────────────────

def _correr(*args):
    entorno = dict(os.environ, DARKINTEL_NER_TRANSFORMER="0", PYTHONIOENCODING="utf-8")
    return subprocess.run([sys.executable, *args], cwd=RAIZ, env=entorno,
                          capture_output=True, text=True, encoding="utf-8")


def test_cli_validar_ejemplo():
    r = _correr("pipeline/validar_anotaciones.py", "--dir", EJEMPLO)
    assert r.returncode == 0, r.stdout + r.stderr


def test_cli_evaluar_regex_en_dev():
    r = _correr("pipeline/evaluar.py", "--dir", EJEMPLO, "--modo", "regex")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "iocs_total" in r.stdout


def test_cli_test_exige_final():
    r = _correr("pipeline/evaluar.py", "--dir", EJEMPLO, "--split", "test", "--modo", "regex")
    assert r.returncode == 1
    assert "--final" in r.stdout


def test_cli_sin_dataset_da_mensaje_claro_y_no_traceback(tmp_path):
    r = _correr("pipeline/evaluar.py", "--dir", str(tmp_path),
                "--acuerdo", "anotaciones_A.jsonl", "anotaciones_B.jsonl")
    assert r.returncode == 1
    assert "Traceback" not in r.stderr
    assert "docs/ejemplo_dataset" in r.stdout


def test_cli_acuerdo_con_archivo_faltante(tmp_path):
    import shutil
    for nombre in ("posts.jsonl", "anotaciones_final.jsonl"):
        shutil.copy(os.path.join(EJEMPLO, nombre), tmp_path / nombre)
    r = _correr("pipeline/evaluar.py", "--dir", str(tmp_path),
                "--acuerdo", "anotaciones_final.jsonl", "anotaciones_B.jsonl")
    assert r.returncode == 1
    assert "Traceback" not in r.stderr
    assert "lo crea el anotador" in r.stdout
