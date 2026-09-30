"""
Punto único de carga de posts para el pipeline (run_ner / run_clustering /
run_stix). Antes, cada script tenía hardcodeado data/synthetic_darkweb_dump.json
y el contenido real de data/raw/ (lo que trae el scraper) se ignoraba por
completo. Este módulo resuelve eso: si hay posts reales en data/raw/, los usa;
si no, cae de vuelta al dataset sintético — así el pipeline sigue corriendo
igual para la demo aunque no hayas scrapeado nada todavía.
"""
import glob
import json
import os

RUTA_RAW = os.path.join(os.path.dirname(__file__), "..", "..", "data", "raw")
RUTA_SINTETICO = os.path.join(
    os.path.dirname(__file__), "..", "..", "data", "synthetic_darkweb_dump.json"
)


def _normalizar_post(datos: dict, origen_archivo: str) -> dict:
    """
    Un post real (guardado por fetcher.py) no trae post_id ni labels_manual
    — eso solo existe en el dataset sintético etiquetado a mano. Se completan
    con valores por defecto para que el resto del pipeline no tenga que saber
    la diferencia.
    """
    post = dict(datos)
    post.setdefault("post_id", os.path.basename(origen_archivo).replace(".json", ""))
    post.setdefault("text", post.get("texto", ""))  # storage.py usa 'texto' en algunos casos
    post.setdefault("labels_manual", None)  # None = "no hay ground truth, no es sintético"
    return post


def cargar_posts() -> tuple[list[dict], bool]:
    """
    Devuelve (posts, es_sintetico).

    es_sintetico=True  -> viene de synthetic_darkweb_dump.json, TIENE
                           labels_manual, se le pueden calcular métricas
                           precision/recall/F1 (run_ner.py).
    es_sintetico=False -> viene de data/raw/ (scraper real), NO tiene
                           ground truth, no se le deben calcular métricas
                           de precisión — solo se reportan los IoCs
                           detectados.
    """
    archivos_raw = sorted(glob.glob(os.path.join(RUTA_RAW, "*.json")))

    if archivos_raw:
        posts = []
        for ruta in archivos_raw:
            with open(ruta, encoding="utf-8") as f:
                datos = json.load(f)
            # Cada archivo puede ser un post único o una lista de posts.
            items = datos if isinstance(datos, list) else [datos]
            posts.extend(_normalizar_post(item, ruta) for item in items)
        return posts, False

    with open(RUTA_SINTETICO, encoding="utf-8") as f:
        return json.load(f), True
