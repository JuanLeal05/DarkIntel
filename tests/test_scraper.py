import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from darkintel.scraper.scraper import scrapear_pagina


def test_scrapear_pagina_estructura_correcta():
    resultado = scrapear_pagina("https://books.toscrape.com")

    # Verificamos que existan todas las claves esperadas
    claves_esperadas = {"title", "url", "content", "links"}
    assert claves_esperadas.issubset(resultado.keys())

    # Verificamos tipos de datos
    assert isinstance(resultado["title"], str)
    assert isinstance(resultado["url"], str)
    assert isinstance(resultado["content"], str)
    assert isinstance(resultado["links"], list)

    # Verificamos contenido mínimo razonable
    assert len(resultado["title"]) > 0
    assert len(resultado["content"]) > 100
    assert len(resultado["links"]) > 0

    print("✅ Prueba superada. Estructura del resultado es correcta.")
    print(f"   - title: {resultado['title']}")
    print(f"   - content: {len(resultado['content'])} caracteres")
    print(f"   - links: {len(resultado['links'])} enlaces")


def test_scrapear_pagina_incluye_iocs():
    resultado = scrapear_pagina("https://books.toscrape.com")

    assert "iocs" in resultado
    claves_ioc_esperadas = {"ips", "dominios", "emails", "cves", "md5", "sha1", "sha256"}
    assert claves_ioc_esperadas.issubset(resultado["iocs"].keys())

    print("✅ Prueba superada: el resultado del scraper incluye la estructura de IoCs.")
    print(f"   IoCs encontrados: {resultado['iocs']}")


from darkintel.ioc_detector.detector import detectar_iocs

def test_deteccion_iocs_con_texto_simulado():
    """
    No depende de una URL externa: simula directamente el paso
    'contenido -> IoCs' con datos que sabemos que contienen indicadores.
    """
    texto_simulado = "Servidor C2 en 8.8.8.8, contacto: hacker@evil.com, CVE-2023-12345"
    iocs = detectar_iocs(texto_simulado)

    assert "8.8.8.8" in iocs["ips"]
    assert "hacker@evil.com" in iocs["emails"]
    assert "CVE-2023-12345" in iocs["cves"]

    print("✅ Prueba superada: detección de IoCs confirmada con datos simulados.")


if __name__ == "__main__":
    test_scrapear_pagina_estructura_correcta()
    test_scrapear_pagina_incluye_iocs()
    test_deteccion_iocs_con_texto_simulado()