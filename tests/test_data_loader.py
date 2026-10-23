import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import darkintel.data_loader as dl


@pytest.fixture
def raw(tmp_path, monkeypatch):
    """Carpeta data/raw temporaria: los tests nunca tocan la real."""
    monkeypatch.setattr(dl, "RUTA_RAW", str(tmp_path))
    return tmp_path


def _escribir(carpeta, nombre, contenido):
    ruta = carpeta / nombre
    if isinstance(contenido, (dict, list)):
        contenido = json.dumps(contenido)
    ruta.write_text(contenido, encoding="utf-8")
    return ruta


# ── Comportamiento normal ────────────────────────────────────

def test_post_valido_del_scraper_se_carga(raw):
    _escribir(raw, "resultado_1.json", {
        "source": "scraper_tor", "url": "http://x.onion/p1",
        "titulo": "t", "text": "C2 en 198.51.100.23",
    })
    posts, es_sintetico = dl.cargar_posts()
    assert es_sintetico is False
    assert len(posts) == 1
    assert posts[0]["text"] == "C2 en 198.51.100.23"
    assert posts[0]["post_id"] == "resultado_1"


def test_sin_archivos_raw_usa_el_sintetico(raw):
    posts, es_sintetico = dl.cargar_posts()
    assert es_sintetico is True
    assert all(p["labels_manual"] is not None for p in posts)


# ── Contenido hostil o corrupto ──────────────────────────────

def test_texto_que_no_es_string_se_descarta(raw):
    _escribir(raw, "malo.json", {"text": {"payload": 1}})
    _escribir(raw, "bueno.json", {"text": "hola"})
    posts, _ = dl.cargar_posts()
    assert [p["post_id"] for p in posts] == ["bueno"]


def test_json_invalido_no_tumba_el_pipeline(raw):
    _escribir(raw, "roto.json", "{esto no es json")
    _escribir(raw, "bueno.json", {"text": "hola"})
    posts, _ = dl.cargar_posts()
    assert len(posts) == 1


def test_archivo_gigante_se_descarta_sin_leerlo(raw, monkeypatch):
    monkeypatch.setattr(dl, "MAX_BYTES_ARCHIVO", 100)
    _escribir(raw, "enorme.json", {"text": "a" * 500})
    posts, _ = dl.cargar_posts()
    assert posts == []


def test_demasiados_posts_en_un_archivo_se_descarta(raw, monkeypatch):
    monkeypatch.setattr(dl, "MAX_POSTS_POR_ARCHIVO", 3)
    _escribir(raw, "lista.json", [{"text": f"p{i}"} for i in range(4)])
    posts, _ = dl.cargar_posts()
    assert posts == []


def test_labels_manual_inyectado_se_ignora(raw):
    # Un scraper comprometido no debe poder falsear el "ground truth".
    _escribir(raw, "trampa.json", {
        "text": "hola",
        "labels_manual": {"ips": ["1.2.3.4"], "hashes": [], "cves": [], "dominios": []},
    })
    posts, es_sintetico = dl.cargar_posts()
    assert es_sintetico is False
    assert posts[0]["labels_manual"] is None


def test_campos_desconocidos_no_se_copian(raw):
    _escribir(raw, "extra.json", {"text": "hola", "__class__": "x", "cmd": "rm -rf /"})
    posts, _ = dl.cargar_posts()
    assert set(posts[0]) == {"post_id", "text", "url", "titulo", "source", "labels_manual"}


def test_post_id_con_ruta_se_reemplaza(raw):
    _escribir(raw, "resultado_9.json", {"text": "hola", "post_id": "../../etc/passwd"})
    posts, _ = dl.cargar_posts()
    assert posts[0]["post_id"] == "resultado_9"


def test_post_ids_repetidos_se_desambiguan(raw):
    _escribir(raw, "a.json", {"text": "uno", "post_id": "p1"})
    _escribir(raw, "b.json", {"text": "dos", "post_id": "p1"})
    posts, _ = dl.cargar_posts()
    assert len({p["post_id"] for p in posts}) == 2


def test_si_todo_es_invalido_no_cae_al_sintetico(raw):
    _escribir(raw, "malo.json", {"text": 123})
    posts, es_sintetico = dl.cargar_posts()
    assert posts == []
    assert es_sintetico is False   # nunca presentar datos de prueba como reales


def test_enlace_simbolico_se_ignora(raw, tmp_path_factory):
    secreto = tmp_path_factory.mktemp("fuera") / "environ.json"
    secreto.write_text(json.dumps({"text": "DATABASE_URL=postgresql://..."}))
    try:
        os.symlink(secreto, raw / "trampa.json")
    except (OSError, NotImplementedError):
        pytest.skip("Este sistema no permite crear symlinks (Windows sin modo desarrollador)")
    posts, _ = dl.cargar_posts()
    assert posts == []