import os
import requests

try:
    from stem import Signal
    from stem.control import Controller
    _STEM_DISPONIBLE = True
except ImportError:
    _STEM_DISPONIBLE = False


# ── Configuración vía entorno (inyectada por docker-compose) ───────────
TOR_SOCKS_PROXY = os.environ.get("TOR_SOCKS_PROXY", "")          # socks5h://tor-proxy:9050
TOR_CONTROL_HOST = os.environ.get("TOR_CONTROL_HOST", "tor-proxy")
TOR_CONTROL_PORT = int(os.environ.get("TOR_CONTROL_PORT", "9051"))
TOR_CONTROL_PASSWORD = os.environ.get("TOR_CONTROL_PASSWORD", "")

# Los .onion son lentos: nada de timeout=10 aquí.
TIMEOUT_TOR = 90

# Límite defensivo de tamaño de respuesta (bytes). Contenido .onion no es
# confiable: evita que una respuesta gigante o una zip-bomb agote memoria/disco.
MAX_BYTES_RESPUESTA = 5 * 1024 * 1024  # 5 MB

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/128.0"


def _proxies() -> dict:
    """
    Arma el diccionario de proxies para requests. Usa socks5h (con 'h') y NO
    socks5: la 'h' hace que la resolución DNS ocurra DENTRO del proxy Tor,
    que es justo lo que permite resolver .onion y evita fugas de DNS locales.
    """
    if not TOR_SOCKS_PROXY:
        raise RuntimeError(
            "TOR_SOCKS_PROXY no está definido. No se debe hacer ninguna "
            "petición .onion sin pasar por Tor."
        )
    if not TOR_SOCKS_PROXY.startswith("socks5h://"):
        raise RuntimeError(
            f"TOR_SOCKS_PROXY debe usar el esquema socks5h:// (recibido: "
            f"{TOR_SOCKS_PROXY!r}). socks5:// simple resuelve DNS en local "
            f"y filtra qué dominios .onion estás visitando."
        )
    return {"http": TOR_SOCKS_PROXY, "https": TOR_SOCKS_PROXY}


def renovar_circuito() -> bool:
    """
    Pide a Tor un circuito nuevo (NEWNYM) vía el ControlPort usando stem.
    Requiere ControlPort + HashedControlPassword configurados en torrc.
    Devuelve False silenciosamente si stem o la contraseña no están
    disponibles, para que el scraper siga funcionando sin rotación si hace
    falta (mejor degradar que caerse).
    """
    if not _STEM_DISPONIBLE:
        return False
    if not TOR_CONTROL_PASSWORD:
        return False
    try:
        with Controller.from_port(address=TOR_CONTROL_HOST, port=TOR_CONTROL_PORT) as controlador:
            controlador.authenticate(password=TOR_CONTROL_PASSWORD)
            controlador.signal(Signal.NEWNYM)
        return True
    except Exception as error:
        print(f"⚠️  No se pudo renovar el circuito Tor: {error}")
        return False


def obtener_html(url: str, usar_tor: bool = True, timeout: int = None) -> str:
    """
    Descarga el HTML crudo de una URL.

    usar_tor=True (default): enruta SIEMPRE por el proxy SOCKS5 de Tor.
    Es el modo esperado para cualquier objetivo .onion o dark web.

    usar_tor=False existe solo para pruebas locales controladas (ver
    SAFE_TESTING.md) contra objetivos que deliberadamente no requieren Tor.
    Nunca debe usarse contra un dominio .onion: un .onion no resuelve fuera
    de la red Tor, así que esa combinación simplemente fallará por diseño.

    Lanza una excepción si la petición falla o si la respuesta excede
    MAX_BYTES_RESPUESTA.
    """
    timeout = timeout or (TIMEOUT_TOR if usar_tor else 10)
    kwargs = {
        "timeout": timeout,
        "headers": {"User-Agent": USER_AGENT},
        "stream": True,   # necesario para poder cortar por tamaño
    }
    if usar_tor:
        kwargs["proxies"] = _proxies()

    respuesta = requests.get(url, **kwargs)
    respuesta.raise_for_status()

    contenido = bytearray()
    for chunk in respuesta.iter_content(chunk_size=8192):
        contenido.extend(chunk)
        if len(contenido) > MAX_BYTES_RESPUESTA:
            respuesta.close()
            raise ValueError(
                f"Respuesta de {url} supera el límite de "
                f"{MAX_BYTES_RESPUESTA} bytes; descartada por seguridad."
            )

    return contenido.decode(respuesta.encoding or "utf-8", errors="replace")


if __name__ == "__main__":
    # Objetivo controlado por entorno: ver SAFE_TESTING.md para el orden de
    # etapas (servicio local propio -> onion legítimo conocido -> objetivo real).
    url = os.environ.get("SCRAPER_TARGET_URL", "")
    if not url:
        raise SystemExit(
            "Define SCRAPER_TARGET_URL antes de correr el scraper "
            "(ver SAFE_TESTING.md)."
        )

    print(f"🎯 Objetivo: {url}")
    print(f"🧦 Proxy Tor: {TOR_SOCKS_PROXY or '(no configurado)'}")

    if renovar_circuito():
        print("🔄 Circuito Tor renovado (NEWNYM)")

    html = obtener_html(url, usar_tor=True)
    print("Longitud del HTML descargado:", len(html))
    print("Primeros 300 caracteres:")
    print(html[:300])
