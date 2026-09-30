import sys
import os
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from darkintel.scraper.fetcher import obtener_html, _proxies


def _mock_respuesta(chunks, encoding="utf-8"):
    mock_resp = MagicMock()
    mock_resp.raise_for_status = lambda: None
    mock_resp.encoding = encoding
    mock_resp.iter_content = lambda chunk_size: iter(chunks)
    return mock_resp


def test_obtener_html_devuelve_contenido():
    contenido = b"<html><title>Mock</title><body>contenido simulado</body></html>"
    mock_resp = _mock_respuesta([contenido])

    with patch("darkintel.scraper.fetcher.requests.get", return_value=mock_resp):
        # usar_tor=False: prueba unitaria pura, sin depender de que
        # TOR_SOCKS_PROXY esté configurado en el entorno de test.
        html = obtener_html("http://fake-forum.onion", usar_tor=False)
        assert len(html) > 0
        assert "contenido simulado" in html
        print("✅ test_obtener_html_devuelve_contenido superado")


def test_obtener_html_lanza_error_en_fallo():
    mock_resp = MagicMock()
    mock_resp.raise_for_status.side_effect = Exception("404 Not Found")

    with patch("darkintel.scraper.fetcher.requests.get", return_value=mock_resp):
        try:
            obtener_html("http://fake-forum.onion", usar_tor=False)
            assert False, "Debería haber lanzado excepción"
        except Exception as e:
            print("✅ test_obtener_html_lanza_error_en_fallo superado:", e)


def test_obtener_html_corta_respuesta_demasiado_grande():
    # Un solo chunk mayor al límite (bajamos el límite localmente para no
    # tener que generar 5MB reales en el test).
    import darkintel.scraper.fetcher as fetcher_mod
    limite_original = fetcher_mod.MAX_BYTES_RESPUESTA
    fetcher_mod.MAX_BYTES_RESPUESTA = 10  # bytes

    mock_resp = _mock_respuesta([b"0123456789ABCDEF"])  # 16 bytes > 10

    try:
        with patch("darkintel.scraper.fetcher.requests.get", return_value=mock_resp):
            try:
                obtener_html("http://fake-forum.onion", usar_tor=False)
                assert False, "Debería haber lanzado ValueError por tamaño"
            except ValueError as e:
                print("✅ test_obtener_html_corta_respuesta_demasiado_grande superado:", e)
    finally:
        fetcher_mod.MAX_BYTES_RESPUESTA = limite_original


def test_proxies_exige_socks5h():
    import darkintel.scraper.fetcher as fetcher_mod
    original = fetcher_mod.TOR_SOCKS_PROXY

    try:
        fetcher_mod.TOR_SOCKS_PROXY = "socks5://tor-proxy:9050"  # sin 'h', inválido
        try:
            _proxies()
            assert False, "Debería rechazar socks5:// sin 'h'"
        except RuntimeError as e:
            print("✅ test_proxies_exige_socks5h superado:", e)
    finally:
        fetcher_mod.TOR_SOCKS_PROXY = original


if __name__ == "__main__":
    test_obtener_html_devuelve_contenido()
    test_obtener_html_lanza_error_en_fallo()
    test_obtener_html_corta_respuesta_demasiado_grande()
    test_proxies_exige_socks5h()
