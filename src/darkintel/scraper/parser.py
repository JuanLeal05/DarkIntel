from bs4 import BeautifulSoup
from urllib.parse import urljoin


def extraer_libros(soup: BeautifulSoup, url_base: str) -> list[dict]:
    """
    Extrae título y enlace absoluto de cada libro listado en la página.
    Devuelve una lista de diccionarios: [{"titulo": ..., "url": ...}, ...]
    """
    libros = []
    articulos = soup.find_all("article", class_="product_pod")

    for articulo in articulos:
        tag_enlace = articulo.find("h3").find("a")

        titulo = tag_enlace.get("title", "").strip()
        href_relativo = tag_enlace.get("href", "")
        url_absoluta = urljoin(url_base, href_relativo)

        libros.append({
            "titulo": titulo,
            "url": url_absoluta
        })

    return libros

def crear_soup(html: str) -> BeautifulSoup:
    """
    Convierte un string de HTML en un objeto BeautifulSoup navegable.
    """
    return BeautifulSoup(html, "lxml")

def extraer_titulo(soup: BeautifulSoup) -> str:
    """
    Extrae el texto del elemento <title> de la página.
    """
    tag_titulo = soup.find("title")
    if tag_titulo is None:
        return ""
    return tag_titulo.get_text(strip=True)

def extraer_enlaces(soup: BeautifulSoup, url_base: str) -> list[str]:
    """
    Extrae todos los enlaces (<a href="...">) de la página,
    los convierte en URLs absolutas y descarta enlaces no útiles.
    Devuelve una lista de URLs únicas.
    """
    enlaces_validos = set()

    for tag_a in soup.find_all("a"):
        href = tag_a.get("href")

        if not href:
            continue  # no tiene atributo href

        href = href.strip()

        if href.startswith("#") or href.startswith("javascript:") or href.startswith("mailto:"):
            continue  # enlace no navegable / no útil

        url_absoluta = urljoin(url_base, href)
        enlaces_validos.add(url_absoluta)

    return sorted(enlaces_validos)

def extraer_contenido(soup: BeautifulSoup) -> str:
    """
    Extrae el texto visible del cuerpo de la página,
    eliminando scripts, estilos y espacios/saltos de línea redundantes.
    """
    # Eliminamos etiquetas que no son texto "legible" para un humano
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()

    texto = soup.get_text(separator=" ")

    # Normalizamos espacios: varias líneas/espacios seguidos -> uno solo
    lineas = [linea.strip() for linea in texto.splitlines()]
    lineas_no_vacias = [linea for linea in lineas if linea]
    texto_limpio = " ".join(lineas_no_vacias)

    return texto_limpio

if __name__ == "__main__":
    from darkintel.scraper.fetcher import obtener_html

    url = "https://books.toscrape.com"
    html = obtener_html(url)
    soup = crear_soup(html)

    titulo_pagina = extraer_titulo(soup)
    libros = extraer_libros(soup, url)
    enlaces = extraer_enlaces(soup, url)

    print("Título de la página:", titulo_pagina)
    print(f"Se encontraron {len(libros)} libros.")
    print(f"Se encontraron {len(enlaces)} enlaces únicos.")
    print("Primeros 5 enlaces:")
    for enlace in enlaces[:5]:
        print(" -", enlace)

