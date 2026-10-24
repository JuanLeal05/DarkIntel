import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from darkintel.scraper.parser import crear_soup, extraer_titulo, extraer_texto_pagina


def test_extraer_titulo():
    html = "<html><head><title>Foro Underground</title></head><body></body></html>"
    soup = crear_soup(html)
    titulo = extraer_titulo(soup)
    assert titulo == "Foro Underground"
    print("✅ test_extraer_titulo superado:", titulo)


def test_extraer_texto_pagina():
    html = """
    <html><body>
        <script>alert('ignorar')</script>
        <style>body { color: red; }</style>
        <p>IP sospechosa: 198.51.100.42</p>
        <p>Hash: e3b0c44298fc1c149afbf4c8996fb924</p>
    </body></html>
    """
    soup = crear_soup(html)
    texto = extraer_texto_pagina(soup)
    assert "198.51.100.42" in texto
    assert "e3b0c44298fc1c149afbf4c8996fb924" in texto
    assert "alert" not in texto
    assert "color: red" not in texto
    print("✅ test_extraer_texto_pagina superado")


if __name__ == "__main__":
    test_extraer_titulo()
    test_extraer_texto_pagina()