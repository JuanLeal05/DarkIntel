import json
import os
from datetime import datetime, timezone


def guardar_json(datos: dict, carpeta: str = "data/raw", nombre_archivo: str | None = None) -> str:
    """
    Guarda un diccionario como archivo JSON en la carpeta indicada.
    Si no se especifica nombre_archivo, genera uno único con timestamp.
    Devuelve la ruta completa del archivo guardado.
    """
    os.makedirs(carpeta, exist_ok=True)

    if nombre_archivo is None:
        marca_tiempo = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        nombre_archivo = f"scrape_{marca_tiempo}.json"

    ruta_completa = os.path.join(carpeta, nombre_archivo)

    with open(ruta_completa, "w", encoding="utf-8") as archivo:
        json.dump(datos, archivo, ensure_ascii=False, indent=2)

    return ruta_completa