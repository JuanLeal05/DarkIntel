import sys
import os

# Permite importar desde src/ sin instalar el paquete
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from darkintel.scraper.fetcher import obtener_html

def test_obtener_html_devuelve_contenido():
    html = obtener_html("https://books.toscrape.com")
    assert "<!DOCTYPE html>" in html or "<!doctype html>" in html.lower()
    assert len(html) > 100
    print("✅ Prueba superada: se descargó HTML válido.")

if __name__ == "__main__":
    test_obtener_html_devuelve_contenido()