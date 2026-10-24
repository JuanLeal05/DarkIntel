"""
Punto único de carga de posts para el pipeline (pipeline/run_pipeline.py y
run_ner.py). Si hay posts reales en data/raw/, los usa; si no, cae de vuelta al
dataset sintético — así el pipeline sigue corriendo igual para la demo aunque
no hayas scrapeado nada todavía.

FRONTERA DE CONFIANZA
---------------------
data/raw/ lo escribe el scraper, que es el único contenedor expuesto a
contenido .onion hostil. Si ese contenedor quedara comprometido, el volumen
raw_data sería su única vía para atacar al backend. Por eso NADA de lo que
viene de data/raw/ se usa sin validar:

  - Se ignoran enlaces simbólicos (un symlink a /proc/self/environ haría que
    el processor leyera SUS PROPIAS variables de entorno, incluido
    DATABASE_URL, y las metiera al pipeline como si fueran un post).
  - Se mide el tamaño ANTES de leer: un archivo de varios GB no se carga.
  - Se limita la cantidad de archivos y de posts por archivo.
  - Cada post se valida con un esquema estricto (tipos y longitudes).
  - Solo se copian los campos conocidos. En particular labels_manual se
    fuerza a None: si no, un scraper comprometido podría inyectar "ground
    truth" falso y manipular las métricas de precisión.
  - post_id se sanea: solo caracteres seguros, sin rutas tipo "../".

Lo inválido se descarta con un aviso; nunca tumba el pipeline.
"""
import glob
from datetime import datetime, timezone
import json
import os
import re
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationError

RUTA_RAW = os.path.join(os.path.dirname(__file__), "..", "..", "data", "raw")
RUTA_SINTETICO = os.path.join(
    os.path.dirname(__file__), "..", "..", "data", "synthetic_darkweb_dump.json"
)

# ── Límites ─────────────────────────────────────────────────
# El fetcher corta respuestas a 5 MB de HTML; el texto extraído es menor,
# así que 6 MB por archivo JSON deja margen sin abrir la puerta a archivos
# gigantes.
MAX_BYTES_ARCHIVO = 6 * 1024 * 1024
MAX_ARCHIVOS = 10_000
MAX_POSTS_POR_ARCHIVO = 1_000
MAX_CARACTERES_TEXTO = 1_000_000

_POST_ID_SEGURO = re.compile(r"^[A-Za-z0-9_.\-]{1,100}$")


class PostCrudo(BaseModel):
    """
    Esquema de un post escrito por el scraper. Cualquier otro campo se
    ignora (extra="ignore") y NUNCA se copia al post normalizado.
    """
    model_config = ConfigDict(extra="ignore", strict=True)

    text: Optional[str] = Field(default=None, max_length=MAX_CARACTERES_TEXTO)
    texto: Optional[str] = Field(default=None, max_length=MAX_CARACTERES_TEXTO)
    post_id: Optional[str] = Field(default=None, max_length=200)
    url: Optional[str] = Field(default=None, max_length=2048)
    titulo: Optional[str] = Field(default=None, max_length=1000)
    source: Optional[str] = Field(default=None, max_length=100)
    timestamp: Optional[str] = Field(default=None, max_length=40)


def _avisar(ruta: str, motivo: str) -> None:
    print(f"⚠️  Descartado {os.path.basename(ruta)}: {motivo}")


def _timestamp_seguro(propuesto: Optional[str], ruta: str) -> str:
    """
    Fecha del post en ISO 8601 UTC. Si el scraper no la trae o es inválida
    (dato no confiable), se usa la fecha de modificación del archivo.
    """
    if propuesto:
        try:
            dt = datetime.fromisoformat(propuesto.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat(timespec="seconds")
        except ValueError:
            pass
    return datetime.fromtimestamp(os.path.getmtime(ruta), tz=timezone.utc).isoformat(timespec="seconds")


def _post_id_seguro(propuesto: Optional[str], respaldo: str) -> str:
    if propuesto and _POST_ID_SEGURO.match(propuesto) and ".." not in propuesto:
        return propuesto
    return respaldo


def _normalizar_post(datos: dict, origen_archivo: str, indice: int) -> Optional[dict]:
    """
    Valida un post crudo y devuelve SOLO los campos que el pipeline usa.
    Devuelve None si el post no es válido.
    """
    try:
        crudo = PostCrudo.model_validate(datos)
    except ValidationError as error:
        campos = ", ".join(str(e["loc"][0]) for e in error.errors() if e["loc"])
        _avisar(origen_archivo, f"post #{indice} no cumple el esquema ({campos})")
        return None

    texto = crudo.text if crudo.text is not None else crudo.texto
    if not texto or not texto.strip():
        _avisar(origen_archivo, f"post #{indice} sin texto")
        return None

    base = os.path.splitext(os.path.basename(origen_archivo))[0]
    respaldo = base if indice == 0 else f"{base}_{indice}"
    return {
        "post_id": _post_id_seguro(crudo.post_id, respaldo),
        "text": texto,
        "url": crudo.url,
        "titulo": crudo.titulo,
        "source": crudo.source,
        "timestamp": _timestamp_seguro(crudo.timestamp, origen_archivo),
        "labels_manual": None,   # datos reales: nunca hay ground truth
    }


def _cargar_archivo_raw(ruta: str) -> list[dict]:
    if os.path.islink(ruta):
        _avisar(ruta, "es un enlace simbólico")
        return []
    if not os.path.isfile(ruta):
        _avisar(ruta, "no es un archivo regular")
        return []
    tamano = os.path.getsize(ruta)
    if tamano > MAX_BYTES_ARCHIVO:
        _avisar(ruta, f"{tamano} bytes supera el límite de {MAX_BYTES_ARCHIVO}")
        return []

    try:
        with open(ruta, encoding="utf-8") as f:
            datos = json.load(f)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        _avisar(ruta, f"JSON inválido ({type(error).__name__})")
        return []

    if isinstance(datos, dict):
        items = [datos]
    elif isinstance(datos, list):
        if len(datos) > MAX_POSTS_POR_ARCHIVO:
            _avisar(ruta, f"{len(datos)} posts supera el límite de {MAX_POSTS_POR_ARCHIVO}")
            return []
        items = datos
    else:
        _avisar(ruta, "la raíz del JSON no es un objeto ni una lista")
        return []

    posts = []
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            _avisar(ruta, f"post #{i} no es un objeto")
            continue
        post = _normalizar_post(item, ruta, i)
        if post is not None:
            posts.append(post)
    return posts


def _ids_unicos(posts: list[dict]) -> list[dict]:
    """Dos archivos podrían proponer el mismo post_id: se desambiguan."""
    vistos = {}
    for post in posts:
        pid = post["post_id"]
        if pid in vistos:
            vistos[pid] += 1
            post["post_id"] = f"{pid}_{vistos[pid]}"
        else:
            vistos[pid] = 0
    return posts


def cargar_posts() -> tuple[list[dict], bool]:
    """
    Devuelve (posts, es_sintetico).

    es_sintetico=True  -> viene de synthetic_darkweb_dump.json, TIENE
                           labels_manual, se le pueden calcular métricas
                           precision/recall/F1 sobre los IoCs.
    es_sintetico=False -> viene de data/raw/ (scraper real), validado y sin
                           ground truth. Si había archivos pero todos eran
                           inválidos, devuelve una lista vacía: NO cae al
                           sintético, para no presentar datos de prueba como
                           si fueran lo que trajo el scraper.
    """
    archivos_raw = sorted(glob.glob(os.path.join(RUTA_RAW, "*.json")))

    if archivos_raw:
        if len(archivos_raw) > MAX_ARCHIVOS:
            print(f"⚠️  {len(archivos_raw)} archivos en data/raw; "
                  f"solo se procesan los primeros {MAX_ARCHIVOS}.")
            archivos_raw = archivos_raw[:MAX_ARCHIVOS]

        posts = []
        for ruta in archivos_raw:
            posts.extend(_cargar_archivo_raw(ruta))

        if not posts:
            print("⚠️  Había archivos en data/raw pero ninguno pasó la validación.")
        return _ids_unicos(posts), False

    with open(RUTA_SINTETICO, encoding="utf-8") as f:
        return json.load(f), True
