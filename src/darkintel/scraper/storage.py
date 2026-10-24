import json
import os
from datetime import datetime, timezone


def guardar_json(datos: dict, carpeta: str = "data/raw",
                 nombre_archivo: str = None) -> str:
    """
    Guarda un diccionario como JSON en disco con timestamp automático.
    """
    os.makedirs(carpeta, exist_ok=True)

    if nombre_archivo is None:
        marca = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        nombre_archivo = f"resultado_{marca}.json"

    ruta = os.path.join(carpeta, nombre_archivo)

    with open(ruta, "w", encoding="utf-8") as f:
        json.dump(datos, f, ensure_ascii=False, indent=2)

    return ruta
