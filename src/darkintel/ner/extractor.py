import re
from datetime import datetime

# ── Listas de filtrado ──────────────────────────────────────

RANGOS_EXCLUIDOS = [
    "127.", "0.", "255.", "169.254.",
    "192.168.", "10.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
]

DOMINIOS_BENIGNOS = {
    "google.com", "microsoft.com", "github.com", "youtube.com",
    "amazon.com", "cloudflare.com", "wikipedia.org", "apache.org",
    "exploit-db.com", "virustotal.com", "shodan.io", "protonmail.com",
}

# Hashes conocidos sin valor de inteligencia
HASHES_VACIOS = {
    "d41d8cd98f00b204e9800998ecf8427e",       # MD5 vacío
    "aad3b435b51404eeaad3b435b51404ee",       # NTLM vacío
    "31d6cfe0d16ae931b73c59d7e0c089c0",       # NTLM vacío alt
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA256 vacío
}

TLDS_CTI = (
    "onion|com|net|ru|to|cc|xyz|io|su|me|pw|"
    "top|club|site|online|store|info|biz|"
    "monster|stream|ws|tk|ml|ga|cf"
)

ANO_ACTUAL = datetime.now().year

# ── Patrones ────────────────────────────────────────────────

PATTERNS = {
    "ip":     r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "ipv6":   r"\b(?:[a-fA-F0-9]{1,4}:){3,7}[a-fA-F0-9]{0,4}\b",
    "sha256": r"\b[a-fA-F0-9]{64}\b",
    "md5":    r"\b[a-fA-F0-9]{32}\b",
    "cve":    r"\bCVE-\d{4}-\d{4,8}\b",
    "dominio":rf"\b(?:[a-z0-9\-]+\.)+(?:{TLDS_CTI})\b",
}

# ── Pre-procesamiento ───────────────────────────────────────

def normalizar_texto(texto: str) -> str:
    """
    Normaliza técnicas de ofuscación comunes en foros dark web
    antes de aplicar los patrones regex.
    """
    # Defanging: 198[.]51[.]100[.]42 → 198.51.100.42
    texto = re.sub(r"\[\.?\]", ".", texto)

    # Defanging con espacios: 198 . 51 . 100 . 42 → 198.51.100.42
    texto = re.sub(r"(\d)\s+\.\s+(\d)", r"\1.\2", texto)

    # hxxp/hxxps → http/https
    texto = re.sub(r"hxxps?", "http", texto, flags=re.IGNORECASE)

    # SHA256 partido en dos líneas: unir líneas que terminen en hex
    texto = re.sub(
        r"([a-fA-F0-9]{16,})\n([a-fA-F0-9]{16,})",
        r"\1\2",
        texto
    )

    # Eliminar zero-width characters (ofuscación invisible)
    texto = re.sub(r"[\u200b\u200c\u200d\ufeff]", "", texto)

    return texto

# ── Validaciones ────────────────────────────────────────────

def es_ip_valida(ip: str) -> bool:
    try:
        partes = ip.split(".")
        return len(partes) == 4 and all(0 <= int(p) <= 255 for p in partes)
    except ValueError:
        return False


def es_ipv6_valida(ip: str) -> bool:
    """Descarta loopback y link-local."""
    excluidos = ["::1", "fe80"]
    return not any(ip.lower().startswith(e) for e in excluidos)


def es_dominio_valido(dominio: str, texto_original: str) -> bool:
    if dominio.lower() in DOMINIOS_BENIGNOS:
        return False
    # Parte de un email
    idx = texto_original.lower().find(dominio.lower())
    if idx > 0 and texto_original[idx - 1] == "@":
        return False
    # Versión tipo "2.0.net"
    if dominio.split(".")[0].isdigit():
        return False
    return True


def es_cve_valido(cve: str) -> bool:
    try:
        ano = int(cve.upper().split("-")[1])
        return 1999 <= ano <= ANO_ACTUAL
    except (IndexError, ValueError):
        return False

# ── Extractor principal ─────────────────────────────────────

def extraer_iocs(texto: str) -> dict:
    """
    Extrae IoCs del texto con normalización previa de ofuscación.
    Cubre casos específicos de foros dark web y CTI.
    """
    texto_normalizado = normalizar_texto(texto)
    resultado = {}

    for tipo, patron in PATTERNS.items():
        coincidencias = re.findall(patron, texto_normalizado, re.IGNORECASE)
        resultado[tipo] = list(set(coincidencias))

    # Validar IPs
    resultado["ip"] = [
        ip for ip in resultado["ip"]
        if es_ip_valida(ip)
        and not any(ip.startswith(r) for r in RANGOS_EXCLUIDOS)
    ]

    # Validar IPv6
    resultado["ipv6"] = [
        ip for ip in resultado["ipv6"]
        if es_ipv6_valida(ip)
    ]

    # Normalizar y filtrar hashes
    resultado["sha256"] = [
        h.lower() for h in resultado["sha256"]
        if h.lower() not in HASHES_VACIOS
    ]
    resultado["md5"] = [
        h.lower() for h in resultado["md5"]
        if h.lower() not in HASHES_VACIOS
    ]

    # Normalizar y filtrar CVEs
    resultado["cve"] = [
        cve.upper() for cve in resultado["cve"]
        if es_cve_valido(cve)
    ]

    # Validar dominios con contexto
    resultado["dominio"] = [
        d for d in resultado["dominio"]
        if es_dominio_valido(d, texto_normalizado)
    ]

    return resultado