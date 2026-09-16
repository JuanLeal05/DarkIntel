import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from fastapi import FastAPI, HTTPException
from darkintel.ner.extractor import extraer_iocs

app = FastAPI(
    title="DarkIntel API",
    description="Endpoint de inteligencia de amenazas en formato STIX 2.1",
    version="1.0.0"
)

RUTA_BUNDLES = os.path.join(
    os.path.dirname(__file__), "..", "data", "output", "stix_bundles.json"
)


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
def extraer_de_texto(payload: dict):
    """
    Extrae IoCs de un texto enviado en vivo.
    Body esperado: {"texto": "..."}
    """
    texto = payload.get("texto", "")

    if not texto:
        raise HTTPException(
            status_code=400,
            detail="Falta el campo 'texto' en el body"
        )

    iocs = extraer_iocs(texto)
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
        "campanas_detectadas": len(bundles),
        "total_objetos_stix": total_objetos,
        "indicadores": total_indicadores,
        "campanas": total_campanas,
        "vulnerabilidades": total_vulnerabilidades
    }