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
