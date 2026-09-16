from bs4 import BeautifulSoup
from urllib.parse import urljoin


def extraer_texto_pagina(soup: BeautifulSoup) -> str:
    """
    Extrae el texto visible de una página eliminando scripts y estilos.
    Esta es la entrada que consumirá el módulo NER.
    """
    for tag in soup(["script", "style"]):
        tag.decompose()
    return soup.get_text(separator=" ", strip=True)


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

    print("Título:", extraer_titulo(soup))
    print("Texto extraído (primeros 300 chars):")
    print(extraer_texto_pagina(soup)[:300])