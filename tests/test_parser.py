import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from darkintel.scraper.fetcher import obtener_html
from darkintel.scraper.parser import crear_soup, extraer_titulo
from darkintel.scraper.parser import extraer_libros

def test_extraer_libros():
    html = obtener_html("https://books.toscrape.com")
    soup = crear_soup(html)
    libros = extraer_libros(soup, "https://books.toscrape.com")

    assert len(libros) == 20
    assert all("titulo" in libro and "url" in libro for libro in libros)
    assert libros[0]["url"].startswith("https://books.toscrape.com/")
    print(f"✅ Prueba superada. Se extrajeron {len(libros)} libros correctamente.")


def test_extraer_titulo():
    html = obtener_html("https://books.toscrape.com")
    soup = crear_soup(html)
    titulo = extraer_titulo(soup)

    assert titulo != ""
    assert "Books" in titulo
    print("✅ Prueba superada. Título extraído:", titulo)

from darkintel.scraper.parser import extraer_enlaces

def test_extraer_enlaces():
    html = obtener_html("https://books.toscrape.com")
    soup = crear_soup(html)
    enlaces = extraer_enlaces(soup, "https://books.toscrape.com")

    assert len(enlaces) > 0
    assert all(enlace.startswith("http") for enlace in enlaces)
    assert len(enlaces) == len(set(enlaces))  # confirma que no hay duplicados
    print(f"✅ Prueba superada. Se extrajeron {len(enlaces)} enlaces únicos.")

if __name__ == "__main__":
    test_extraer_titulo()
    test_extraer_libros()
    test_extraer_enlaces()