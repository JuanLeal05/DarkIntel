import sys
import os
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from darkintel.scraper.fetcher import obtener_html


def test_obtener_html_devuelve_contenido():
    mock_resp = MagicMock()
    mock_resp.text = "<html><title>Mock</title><body>contenido simulado</body></html>"
    mock_resp.raise_for_status = lambda: None

    with patch("darkintel.scraper.fetcher.requests.get", return_value=mock_resp):
        html = obtener_html("http://fake-forum.onion")
        assert len(html) > 0
        assert "contenido simulado" in html
        print("✅ test_obtener_html_devuelve_contenido superado")


def test_obtener_html_lanza_error_en_fallo():
    mock_resp = MagicMock()
    mock_resp.raise_for_status.side_effect = Exception("404 Not Found")

    with patch("darkintel.scraper.fetcher.requests.get", return_value=mock_resp):
        try:
            obtener_html("http://fake-forum.onion")
            assert False, "Debería haber lanzado excepción"
        except Exception as e:
            print("✅ test_obtener_html_lanza_error_en_fallo superado:", e)


if __name__ == "__main__":
    test_obtener_html_devuelve_contenido()
    test_obtener_html_lanza_error_en_fallo()