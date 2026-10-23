import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from darkintel.ner.extractor import extraer_iocs

# ── Limites de entrada ──────────────────────────────────────
# El texto de un post real rara vez pasa de unos KB; 100.000 caracteres da
# margen de sobra y mantiene acotado el costo de las regex del extractor.
MAX_CARACTERES_TEXTO = 100_000
# Limite del cuerpo HTTP completo. Un caracter UTF-8 ocupa hasta 4 bytes y
# el JSON agrega comillas y escapes, por eso 4x el limite de caracteres.
MAX_BYTES_CUERPO = 4 * MAX_CARACTERES_TEXTO


class SolicitudExtraccion(BaseModel):
    """
    Body de POST /iocs/extract. Pydantic valida antes de llegar al codigo:
    'texto' ausente, vacio, de otro tipo o demasiado largo -> 422.
    """
    model_config = ConfigDict(extra="forbid")   # campos desconocidos -> 422
    texto: str = Field(min_length=1, max_length=MAX_CARACTERES_TEXTO)


app = FastAPI(
    title="DarkIntel API",
    description="Endpoint de inteligencia de amenazas en formato STIX 2.1",
    version="1.0.0"
)


@app.middleware("http")
async def limitar_tamano_cuerpo(request: Request, call_next):
    """
    Rechaza cuerpos grandes ANTES de leerlos: el max_length de Pydantic solo
    actua cuando el JSON entero ya esta en memoria.
    """
    if request.method in ("POST", "PUT", "PATCH"):
        longitud = request.headers.get("content-length")
        if longitud is None:
            # Sin Content-Length (envio chunked) no se puede acotar de antemano.
            return JSONResponse(status_code=411,
                                content={"detail": "Se requiere Content-Length"})
        if not longitud.isdigit() or int(longitud) > MAX_BYTES_CUERPO:
            return JSONResponse(status_code=413,
                                content={"detail": f"Cuerpo mayor a {MAX_BYTES_CUERPO} bytes"})
    return await call_next(request)


RUTA_BUNDLES = os.path.join(
    os.path.dirname(__file__), "..", "data", "output", "stix_bundles.json"
)

# Clave que run_stix.py usa para los posts que HDBSCAN marca como ruido.
CLAVE_RUIDO = "cluster_-1"


def cargar_bundles() -> dict:
    """Carga los bundles STIX generados por el pipeline."""
    if not os.path.exists(RUTA_BUNDLES):
        raise HTTPException(
            status_code=404,
            detail="No hay bundles generados. Ejecuta pipeline/run_stix.py primero."
        )
    with open(RUTA_BUNDLES, encoding="utf-8") as f:
        return json.load(f)


@app.get("/")
def raiz():
    """Información general de la API."""
    return {
        "servicio": "DarkIntel API",
        "version": "1.0.0",
        "endpoints": [
            "/stix/bundles",
            "/stix/bundles/{cluster_id}",
            "/iocs/extract",
            "/stats"
        ]
    }


@app.get("/stix/bundles")
def obtener_todos_los_bundles():
    """Devuelve todos los bundles STIX agrupados por campaña."""
    return cargar_bundles()


@app.get("/stix/bundles/{cluster_id}")
def obtener_bundle(cluster_id: int):
    """Devuelve el bundle STIX de una campaña específica."""
    bundles = cargar_bundles()
    clave = f"cluster_{cluster_id}"

    if clave not in bundles:
        raise HTTPException(
            status_code=404,
            detail=f"No existe el cluster {cluster_id}"
        )

    return bundles[clave]


@app.post("/iocs/extract")
def extraer_de_texto(solicitud: SolicitudExtraccion):
    """
    Extrae IoCs de un texto enviado en vivo.
    Body esperado: {"texto": "..."} (de 1 a 100.000 caracteres).
    """
    iocs = extraer_iocs(solicitud.texto)
    return {
        "iocs": {k: v for k, v in iocs.items() if v},
        "total": sum(len(v) for v in iocs.values())
    }


@app.get("/stats")
def estadisticas():
    """Resumen de la inteligencia disponible."""
    bundles = cargar_bundles()

    total_objetos = 0
    total_indicadores = 0
    total_campanas = 0
    total_vulnerabilidades = 0

    for bundle in bundles.values():
        objetos = bundle.get("objects", [])
        total_objetos += len(objetos)
        for obj in objetos:
            tipo = obj.get("type")
            if tipo == "indicator":
                total_indicadores += 1
            elif tipo == "campaign":
                total_campanas += 1
            elif tipo == "vulnerability":
                total_vulnerabilidades += 1

    return {
        # El ruido de HDBSCAN no es una campaña: no se cuenta.
        "campanas_detectadas": sum(1 for clave in bundles if clave != CLAVE_RUIDO),
        "total_objetos_stix": total_objetos,
        "indicadores": total_indicadores,
        "campanas": total_campanas,
        "vulnerabilidades": total_vulnerabilidades
    }