import os
import socket
import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests

try:
    from stem import Signal
    from stem.control import Controller
    _STEM_DISPONIBLE = True
except ImportError:
    _STEM_DISPONIBLE = False

from darkintel.scraper.parser import crear_soup, extraer_texto_pagina, extraer_titulo
from darkintel.scraper.storage import guardar_json


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

# Tiempo MAXIMO total por descarga (conexion + redirecciones + cuerpo).
# TIMEOUT_TOR es por operacion de red y se reinicia con cada byte recibido:
# un servidor hostil que manda 1 byte cada 80 s nunca lo dispararia
# (slowloris). Este limite si corta.
TIEMPO_TOTAL_MAX = 120

# Redirecciones: se siguen a mano, como maximo estas, y solo hacia .onion
# cuando se usa Tor (ver _validar_redireccion).
MAX_REDIRECCIONES = 3
CODIGOS_REDIRECCION = (301, 302, 303, 307, 308)

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


# Tor ignora (aplaza) un NEWNYM si llega antes de 10 s desde el anterior.
INTERVALO_NEWNYM = 10
_ultimo_newnym = float("-inf")   # instante (monotonic) del ultimo NEWNYM enviado


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
        # stem exige una IP literal: Controller.from_port falla con
        # "Invalid IP address: tor-proxy" si se le pasa el nombre DNS del
        # servicio Docker. Hay que resolverlo antes.
        direccion = socket.gethostbyname(TOR_CONTROL_HOST)
        with Controller.from_port(address=direccion, port=TOR_CONTROL_PORT) as controlador:
            controlador.authenticate(password=TOR_CONTROL_PASSWORD)
            # Tor solo respeta un NEWNYM cada 10 s. OJO: stem tiene
            # get_newnym_wait(), pero solo recuerda los NEWNYM enviados por
            # ESE objeto Controller, y aqui se abre uno nuevo en cada llamada,
            # asi que siempre devolveria 0. Por eso el registro es global.
            global _ultimo_newnym
            espera = INTERVALO_NEWNYM - (time.monotonic() - _ultimo_newnym)
            if espera > 0:
                time.sleep(espera)
            controlador.signal(Signal.NEWNYM)
            _ultimo_newnym = time.monotonic()
        return True
    except Exception as error:
        print(f"⚠️  No se pudo renovar el circuito Tor: {error}")
        return False


def _es_onion(url: str) -> bool:
    return (urlparse(url).hostname or "").lower().endswith(".onion")


def _validar_redireccion(origen: str, destino: str, usar_tor: bool) -> None:
    """
    Lanza ValueError si la redireccion no es aceptable.

    Un .onion hostil puede responder 302 hacia un dominio de clearnet que
    controla: aunque el trafico siga yendo por Tor, le confirma que lo
    visitamos y nos saca del entorno .onion. Por eso, con Tor solo se
    aceptan destinos .onion; sin Tor (pruebas locales), solo el mismo host.
    """
    esquema = urlparse(destino).scheme
    if esquema not in ("http", "https"):
        raise ValueError(f"Redireccion con esquema no permitido: {destino!r}")
    if usar_tor and not _es_onion(destino):
        raise ValueError(f"Redireccion fuera de .onion bloqueada: {origen} -> {destino}")
    if not usar_tor and urlparse(destino).hostname != urlparse(origen).hostname:
        raise ValueError(f"Redireccion a otro host bloqueada: {origen} -> {destino}")


def obtener_html(url: str, usar_tor: bool = True, timeout: int = None,
                 tiempo_total: float = None) -> str:
    """
    Descarga el HTML crudo de una URL.

    usar_tor=True (default): enruta SIEMPRE por el proxy SOCKS5 de Tor.
    Es el modo esperado para cualquier objetivo .onion o dark web.

    usar_tor=False existe solo para pruebas locales controladas (ver
    SAFE_TESTING.md) contra objetivos que deliberadamente no requieren Tor.

    Defensas frente a un servidor hostil:
      - limite de tamano (MAX_BYTES_RESPUESTA)
      - limite de tiempo total (TIEMPO_TOTAL_MAX), no solo por operacion
      - redirecciones seguidas a mano: maximo MAX_REDIRECCIONES y solo
        hacia .onion cuando se usa Tor

    Lanza ValueError (tamano, redireccion) o TimeoutError (tiempo total).
    """
    timeout = timeout or (TIMEOUT_TOR if usar_tor else 10)
    limite = time.monotonic() + (tiempo_total or TIEMPO_TOTAL_MAX)

    kwargs = {
        "timeout": timeout,
        "headers": {"User-Agent": USER_AGENT},
        "stream": True,            # necesario para poder cortar por tamano/tiempo
        "allow_redirects": False,  # las redirecciones se validan a mano abajo
    }
    if usar_tor:
        kwargs["proxies"] = _proxies()

    actual = url
    for _ in range(MAX_REDIRECCIONES + 1):
        respuesta = requests.get(actual, **kwargs)
        if respuesta.status_code not in CODIGOS_REDIRECCION:
            break
        destino = urljoin(actual, respuesta.headers.get("Location", ""))
        respuesta.close()
        _validar_redireccion(actual, destino, usar_tor)
        if time.monotonic() > limite:
            raise TimeoutError(f"{url}: tiempo total agotado durante redirecciones")
        actual = destino
    else:
        raise ValueError(f"{url}: mas de {MAX_REDIRECCIONES} redirecciones")

    respuesta.raise_for_status()

    contenido = bytearray()
    for chunk in respuesta.iter_content(chunk_size=8192):
        contenido.extend(chunk)
        if len(contenido) > MAX_BYTES_RESPUESTA:
            respuesta.close()
            raise ValueError(
                f"Respuesta de {url} supera el limite de "
                f"{MAX_BYTES_RESPUESTA} bytes; descartada por seguridad."
            )
        if time.monotonic() > limite:
            respuesta.close()
            raise TimeoutError(
                f"{url}: se supero el tiempo total de descarga; "
                f"posible servidor lento a proposito (slowloris)."
            )

    return contenido.decode(respuesta.encoding or "utf-8", errors="replace")


# Reintentos solo para fallos de RED transitorios (circuito .onion que no
# se arma, timeout de conexion). Nunca para fallos de POLITICA: tamano,
# tiempo total, redireccion bloqueada o un HTTP 4xx/5xx del servidor.
REINTENTOS_RED = 2
ESPERA_BASE_REINTENTO = 5   # segundos; se duplica en cada reintento


def obtener_html_con_reintentos(url: str, reintentos: int = REINTENTOS_RED) -> str:
    """
    Envuelve obtener_html(usar_tor=True) con reintentos ante errores de red.

    Los servicios .onion fallan a menudo de forma transitoria: armar el
    circuito de rendezvous puede no completarse a tiempo. Antes de cada
    reintento se pide un circuito nuevo y se espera con backoff exponencial.
    """
    for intento in range(reintentos + 1):
        try:
            return obtener_html(url, usar_tor=True)
        except (requests.exceptions.ConnectionError,
                requests.exceptions.Timeout) as error:
            if intento == reintentos:
                raise
            espera = ESPERA_BASE_REINTENTO * (2 ** intento)
            print(f"   ↻ Error de red ({type(error).__name__}); reintento "
                  f"{intento + 1}/{reintentos} en {espera}s con circuito nuevo")
            time.sleep(espera)
            renovar_circuito()


if __name__ == "__main__":
    # Objetivo controlado por entorno: ver SAFE_TESTING.md para el orden de
    # etapas (servicio local propio -> onion legítimo conocido -> objetivo real).
    # SCRAPER_TARGET_URL acepta varias URLs separadas por coma. El pipeline
    # necesita al menos 4 posts para que UMAP/HDBSCAN funcionen, así que una
    # sola página no alcanza para la demo completa.
    crudo = os.environ.get("SCRAPER_TARGET_URL", "")
    urls = [u.strip() for u in crudo.split(",") if u.strip()]
    if not urls:
        raise SystemExit(
            "Define SCRAPER_TARGET_URL antes de correr el scraper "
            "(ver SAFE_TESTING.md)."
        )

    print(f"🧦 Proxy Tor: {TOR_SOCKS_PROXY or '(no configurado)'}")
    print(f"🎯 {len(urls)} objetivo(s)\n")

    fallidas = 0
    for url in urls:
        print(f"── {url}")

        # Circuito nuevo por cada objetivo: evita que todas las peticiones
        # salgan por la misma ruta.
        if renovar_circuito():
            print("   🔄 Circuito Tor renovado (NEWNYM)")

        try:
            html = obtener_html_con_reintentos(url)
        except Exception as error:
            # Un objetivo caído no debe tumbar el resto del rastreo.
            print(f"   ❌ Falló: {type(error).__name__}: {error}")
            fallidas += 1
            continue

        soup = crear_soup(html)
        texto = extraer_texto_pagina(soup)
        titulo = extraer_titulo(soup)

        print(f"   Título: {titulo or '(sin título)'} — {len(html)} bytes")

        # El post va al volumen raw_data: el único canal hacia el backend.
        # El processor lo valida antes de usarlo (data_loader.py).
        post = {
            "source": "scraper_tor",
            "url": url,
            # Hora de recolección: alimenta first_seen/valid_from en STIX
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "titulo": titulo,
            "text": texto,
        }
        ruta_guardada = guardar_json(post, carpeta="data/raw")
        print(f"   ✅ Guardado en: {ruta_guardada}")

    print(f"\n{len(urls) - fallidas}/{len(urls)} objetivos recolectados.")
    if fallidas:
        raise SystemExit(1)
