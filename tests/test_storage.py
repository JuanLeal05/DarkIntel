import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from darkintel.scraper.storage import guardar_json


def test_guardar_json_crea_archivo_valido():
    datos_prueba = {
        "title": "Prueba",
        "url": "https://ejemplo.com",
        "content": "Contenido de prueba con ñ y áéíóú",
        "links": ["https://ejemplo.com/1", "https://ejemplo.com/2"],
    }

    ruta = guardar_json(datos_prueba, carpeta="data/raw", nombre_archivo="test_storage.json")

    # Verificamos que el archivo exista físicamente
    assert os.path.exists(ruta)

    # Verificamos que se pueda volver a leer y que los datos coincidan
    with open(ruta, "r", encoding="utf-8") as archivo:
        datos_leidos = json.load(archivo)

    assert datos_leidos == datos_prueba

    print(f"✅ Prueba superada. Archivo JSON creado y verificado en: {ruta}")


if __name__ == "__main__":
    test_guardar_json_crea_archivo_valido()