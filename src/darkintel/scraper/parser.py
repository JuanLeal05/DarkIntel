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


if __name__ == "__main__":
    from darkintel.scraper.fetcher import obtener_html

    url = "https://books.toscrape.com"
    html = obtener_html(url)
    soup = crear_soup(html)

    titulo_pagina = extraer_titulo(soup)
    libros = extraer_libros(soup, url)

    print("Título de la página:", titulo_pagina)
    print(f"Se encontraron {len(libros)} libros.")
    print("Primeros 3 libros:")
    for libro in libros[:3]:
        print(libro)