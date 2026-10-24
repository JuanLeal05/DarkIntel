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


# ── Tiempo total y redirecciones ─────────────────────────────

def _mock_redireccion(location, codigo=302):
    mock_resp = MagicMock()
    mock_resp.status_code = codigo
    mock_resp.headers = {"Location": location}
    return mock_resp


def _con_proxy_tor():
    """Context manager: simula TOR_SOCKS_PROXY configurado (sin red real)."""
    import darkintel.scraper.fetcher as fetcher_mod
    return patch.object(fetcher_mod, "TOR_SOCKS_PROXY", "socks5h://tor-proxy:9050")


def test_corta_servidor_lento_por_tiempo_total():
    import time

    def goteo():
        # Simula un servidor que manda poquito, despacio y sin parar.
        for _ in range(50):
            time.sleep(0.05)
            yield b"x"

    mock_resp = _mock_respuesta([])
    mock_resp.iter_content = lambda chunk_size: goteo()

    with patch("darkintel.scraper.fetcher.requests.get", return_value=mock_resp):
        inicio = time.monotonic()
        try:
            obtener_html("http://lento.onion", usar_tor=False, tiempo_total=0.2)
            assert False, "Deberia haber lanzado TimeoutError"
        except TimeoutError:
            pass
        assert time.monotonic() - inicio < 1.5   # corto mucho antes de los 2.5 s


def test_bloquea_redireccion_onion_a_clearnet():
    redir = _mock_redireccion("http://evil-tracker.com/beacon")
    with _con_proxy_tor(), patch(
        "darkintel.scraper.fetcher.requests.get", return_value=redir
    ) as mock_get:
        try:
            obtener_html("http://foro.onion/post", usar_tor=True)
            assert False, "Deberia bloquear la redireccion a clearnet"
        except ValueError as e:
            assert "fuera de .onion" in str(e)
        assert mock_get.call_count == 1   # nunca se pidio evil-tracker.com


def test_sigue_redireccion_onion_a_onion():
    redir = _mock_redireccion("/post?page=2")   # relativa: mismo .onion
    final = _mock_respuesta([b"<html>pagina 2</html>"])
    final.status_code = 200
    with _con_proxy_tor(), patch(
        "darkintel.scraper.fetcher.requests.get", side_effect=[redir, final]
    ) as mock_get:
        html = obtener_html("http://foro.onion/post", usar_tor=True)
        assert "pagina 2" in html
        assert mock_get.call_args_list[1].args[0] == "http://foro.onion/post?page=2"
        # Nunca se delega en requests el seguir redirecciones:
        assert mock_get.call_args_list[0].kwargs["allow_redirects"] is False


def test_limita_cantidad_de_redirecciones():
    with _con_proxy_tor(), patch(
        "darkintel.scraper.fetcher.requests.get",
        side_effect=lambda *a, **k: _mock_redireccion("http://foro.onion/loop"),
    ) as mock_get:
        try:
            obtener_html("http://foro.onion/loop", usar_tor=True)
            assert False, "Deberia cortar el bucle de redirecciones"
        except ValueError as e:
            assert "redirecciones" in str(e)
        assert mock_get.call_count == 4   # 1 original + 3 redirecciones


def test_bloquea_esquema_no_http():
    redir = _mock_redireccion("file:///etc/passwd")
    with _con_proxy_tor(), patch(
        "darkintel.scraper.fetcher.requests.get", return_value=redir
    ):
        try:
            obtener_html("http://foro.onion/x", usar_tor=True)
            assert False
        except ValueError as e:
            assert "esquema" in str(e)


# ── Rotacion de circuitos (aislamiento por credencial SOCKS) ─

def test_proxies_lleva_credencial_de_aislamiento():
    from urllib.parse import urlparse
    with _con_proxy_tor():
        proxies = _proxies()
    url = urlparse(proxies["https"])
    assert proxies["http"] == proxies["https"]
    assert url.scheme == "socks5h"
    assert (url.hostname, url.port) == ("tor-proxy", 9050)
    assert url.username and len(url.username) == 32   # 128 bits aleatorios


def test_renovar_circuito_cambia_la_credencial():
    import darkintel.scraper.fetcher as fetcher_mod
    with _con_proxy_tor():
        antes = _proxies()["https"]
        assert fetcher_mod.renovar_circuito() is True
        despues = _proxies()["https"]
        assert fetcher_mod.renovar_circuito() is True
        otra = _proxies()["https"]
    assert len({antes, despues, otra}) == 3   # circuito distinto cada vez


def test_redirecciones_comparten_circuito():
    redir = _mock_redireccion("/post?page=2")
    final = _mock_respuesta([b"<html>ok</html>"])
    final.status_code = 200
    with _con_proxy_tor(), patch(
        "darkintel.scraper.fetcher.requests.get", side_effect=[redir, final]
    ) as mock_get:
        obtener_html("http://foro.onion/post", usar_tor=True)
    p1 = mock_get.call_args_list[0].kwargs["proxies"]
    p2 = mock_get.call_args_list[1].kwargs["proxies"]
    assert p1 == p2


def test_proxies_rechaza_credenciales_en_la_variable():
    import darkintel.scraper.fetcher as fetcher_mod
    with patch.object(fetcher_mod, "TOR_SOCKS_PROXY", "socks5h://u:p@tor-proxy:9050"):
        try:
            _proxies()
            assert False, "Deberia rechazar usuario/contraseña en TOR_SOCKS_PROXY"
        except RuntimeError as e:
            assert "aislamiento" in str(e)


def test_no_quedan_rastros_del_controlport():
    import darkintel.scraper.fetcher as fetcher_mod
    for nombre in ("TOR_CONTROL_PASSWORD", "TOR_CONTROL_HOST", "Controller"):
        assert not hasattr(fetcher_mod, nombre), nombre


# ── Reintentos ante fallos de red ────────────────────────────

def test_reintenta_error_de_red_y_luego_tiene_exito():
    import requests
    import darkintel.scraper.fetcher as fetcher_mod

    fallos = [requests.exceptions.ConnectTimeout("circuito no se armo"),
              requests.exceptions.ConnectionError("0x06 TTL expired")]

    def obtener_falso(url, usar_tor=True):
        if fallos:
            raise fallos.pop(0)
        return "<html>ok</html>"

    esperas = []
    with patch.object(fetcher_mod, "obtener_html", side_effect=obtener_falso), \
         patch.object(fetcher_mod, "renovar_circuito", return_value=True) as renovar, \
         patch("darkintel.scraper.fetcher.time.sleep", side_effect=esperas.append):
        html = fetcher_mod.obtener_html_con_reintentos("http://x.onion/p")

    assert html == "<html>ok</html>"
    assert esperas == [5, 10]          # backoff exponencial
    assert renovar.call_count == 2     # circuito nuevo antes de cada reintento


def test_agota_reintentos_y_propaga_el_error():
    import requests
    import darkintel.scraper.fetcher as fetcher_mod

    with patch.object(fetcher_mod, "obtener_html",
                      side_effect=requests.exceptions.ConnectTimeout("caido")) as obtener, \
         patch.object(fetcher_mod, "renovar_circuito", return_value=True), \
         patch("darkintel.scraper.fetcher.time.sleep"):
        try:
            fetcher_mod.obtener_html_con_reintentos("http://x.onion/p")
            assert False, "Deberia propagar el error tras agotar reintentos"
        except requests.exceptions.ConnectTimeout:
            pass
    assert obtener.call_count == 3     # 1 intento + 2 reintentos


def test_no_reintenta_errores_de_politica():
    import darkintel.scraper.fetcher as fetcher_mod

    for error in (ValueError("redireccion bloqueada"), TimeoutError("slowloris")):
        with patch.object(fetcher_mod, "obtener_html", side_effect=error) as obtener, \
             patch("darkintel.scraper.fetcher.time.sleep"):
            try:
                fetcher_mod.obtener_html_con_reintentos("http://x.onion/p")
                assert False
            except type(error):
                pass
        assert obtener.call_count == 1  # sin reintentos


if __name__ == "__main__":
    test_obtener_html_devuelve_contenido()
    test_obtener_html_lanza_error_en_fallo()
    test_obtener_html_corta_respuesta_demasiado_grande()
    test_proxies_exige_socks5h()