from darkintel.scraper.fetcher import obtener_html
from darkintel.scraper.parser import (
    crear_soup,
    extraer_titulo,
    extraer_enlaces,
    extraer_contenido,
)
from darkintel.scraper.storage import guardar_json
from darkintel.ioc_detector.detector import detectar_iocs
from darkintel.stix_builder.builder import construir_bundle
import json
def scrapear_pagina(url: str) -> dict:
    html = obtener_html(url)
    soup = crear_soup(html)

    contenido = extraer_contenido(soup)
    iocs = detectar_iocs(contenido)
    bundle = construir_bundle(iocs)

    resultado = {
        "title": extraer_titulo(soup),
        "url": url,
        "content": contenido,
        "links": extraer_enlaces(soup, url),
        "iocs": iocs,
        "stix_bundle": json.loads(str(bundle)),
    }

    return resultado

if __name__ == "__main__":
    url = "https://books.toscrape.com"
    resultado = scrapear_pagina(url)

    print("Título:", resultado["title"])
    print("URL:", resultado["url"])
    print("Longitud del contenido:", len(resultado["content"]))
    print("Cantidad de enlaces:", len(resultado["links"]))
    print("IoCs encontrados:", resultado["iocs"])

    ruta_guardada = guardar_json(resultado)
    print("Resultado guardado en:", ruta_guardada)