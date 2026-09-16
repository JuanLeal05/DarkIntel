from darkintel.scraper.fetcher import obtener_html
from darkintel.scraper.parser import (
    crear_soup,
    extraer_titulo,
    extraer_enlaces,
    extraer_contenido,
)
from darkintel.scraper.storage import guardar_json
from darkintel.ioc_detector.detector import detectar_iocs


def scrapear_pagina(url: str) -> dict:
    """
    Orquesta el proceso completo: descarga, parseo,
    extracción de datos estructurados y detección de IoCs.
    """
    html = obtener_html(url)
    soup = crear_soup(html)

    contenido = extraer_contenido(soup)

    resultado = {
        "title": extraer_titulo(soup),
        "url": url,
        "content": contenido,
        "links": extraer_enlaces(soup, url),
        "iocs": detectar_iocs(contenido),
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