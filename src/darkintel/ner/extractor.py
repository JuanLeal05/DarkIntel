"""
Extracción de IoCs atómicos con expresiones regulares.

IPs, hashes, CVEs y dominios tienen una forma fija: para ellos la regex es
precisa y explicable. Las entidades semánticas (malware, actores...) las
extrae el Transformer (ner/transformer.py); ver ner/hibrido.py.

Flujo: normalizar_texto() quita la ofuscación -> cada patrón busca
candidatos -> validaciones descartan falsos positivos.
"""
import ipaddress
import re
from datetime import datetime

# ── Listas de filtrado ──────────────────────────────────────

# Servicios legítimos que se mencionan en foros sin ser infraestructura del
# atacante. Se descartan también sus subdominios (www.google.com,
# drive.google.com...).
DOMINIOS_BENIGNOS = {
    "google.com", "microsoft.com", "github.com", "youtube.com",
    "amazon.com", "cloudflare.com", "wikipedia.org", "apache.org",
    "exploit-db.com", "virustotal.com", "shodan.io", "protonmail.com",
    "proton.me", "torproject.org", "mozilla.org", "telegram.org",
    "discord.com", "twitter.com", "x.com", "reddit.com", "pastebin.com",
    "mega.nz", "dropbox.com", "gmail.com", "outlook.com", "yahoo.com",
    "linkedin.com", "facebook.com", "apple.com", "python.org", "pypi.org",
    "npmjs.com", "docker.com", "ubuntu.com", "debian.org", "mitre.org",
    "nist.gov", "cve.org",
}

# Hashes conocidos sin valor de inteligencia (archivos vacíos)
HASHES_VACIOS = {
    "d41d8cd98f00b204e9800998ecf8427e",                                    # MD5 vacío
    "aad3b435b51404eeaad3b435b51404ee",                                    # NTLM vacío
    "31d6cfe0d16ae931b73c59d7e0c089c0",                                    # NTLM vacío alt
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",                            # SHA-1 vacío
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",    # SHA-256 vacío
}

# TLDs aceptados. Lista explícita (no "cualquier cosa tras un punto") para
# no confundir nombres de archivo (loader.exe, dump.zip) con dominios.
TLDS = (
    # genéricos y comunes en CTI
    "onion", "com", "net", "org", "info", "biz", "xyz", "top", "club", "site",
    "online", "store", "shop", "live", "app", "dev", "cloud", "link", "click",
    "work", "support", "tech", "space", "website", "fun", "icu", "monster",
    "stream", "vip", "pro", "name", "mobi", "edu", "gov",
    # ccTLDs frecuentes en infraestructura maliciosa o en foros
    "ru", "su", "ua", "by", "kz", "cn", "hk", "tw", "kr", "kp", "jp", "ir",
    "in", "id", "vn", "th", "sg", "my", "ph", "tr", "de", "uk", "fr", "nl",
    "be", "it", "es", "pt", "eu", "ch", "at", "se", "no", "fi", "dk", "cz",
    "ro", "bg", "hu", "lt", "lv", "ee", "br", "ar", "mx", "cl", "co", "pe",
    "ve", "us", "ca", "au", "nz", "za", "ng", "ke", "eg",
    "to", "cc", "io", "me", "pw", "ws", "tk", "ml", "ga", "cf", "gq", "la",
    "ly", "li", "am", "bz", "nu", "tv", "fm", "ac", "sh", "is", "lol", "gg",
)
# Ordenados de más largo a más corto: en una alternancia regex, "co" no debe
# ganarle a "com".
TLDS_CTI = "|".join(sorted(TLDS, key=len, reverse=True))

# Extensiones de archivo que coinciden con un TLD real (.sh, .zip, .md...):
# "setup.sh" o "readme.md" casi siempre son archivos, no dominios.
_EXTENSIONES_AMBIGUAS = {"sh", "zip", "md", "py", "pl", "rs", "mov", "exe", "bat"}
# Nombres típicos de archivo: "readme.info" o "setup.me" son archivos.
_NOMBRES_DE_ARCHIVO = {
    "readme", "setup", "install", "installer", "config", "update", "updater",
    "loader", "payload", "index", "main", "run", "build", "test", "license",
    "changelog", "notes", "dump", "logs", "output", "file", "document",
}

ANO_ACTUAL = datetime.now().year

# Redes de documentación (RFC 5737 / RFC 3849). Son las que usan el dataset
# de la demo y las páginas de prueba, así que se aceptan como IoCs aunque
# ipaddress las marque como privadas.
_REDES_DOCUMENTACION = [ipaddress.ip_network(r) for r in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]

# ── Patrones ────────────────────────────────────────────────

PATTERNS = {
    "ip":     r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    # Candidato amplio (admite '::' comprimido); la validación real la hace
    # ipaddress. Así se descartan MACs (00:1a:2b:3c:4d:5e) y horas (12:30:45).
    "ipv6":   r"(?<![0-9A-Fa-f:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:.])",
    "sha256": r"\b[a-fA-F0-9]{64}\b",
    "sha1":   r"\b[a-fA-F0-9]{40}\b",
    "md5":    r"\b[a-fA-F0-9]{32}\b",
    "cve":    r"\bCVE-\d{4}-\d{4,8}\b",
    "dominio": rf"(?<![a-z0-9.\-])(?:[a-z0-9](?:[a-z0-9\-]{{0,61}}[a-z0-9])?\.){{1,10}}(?:{TLDS_CTI})(?![a-z0-9\-])",
}

# ── Pre-procesamiento ───────────────────────────────────────

# Un SHA256 partido en dos líneas: primera parte de 16-63 hex, segunda de 1-48.
# Los \b evitan cortar un hash más largo; \r? cubre textos con fin de línea Windows.
_HEX_PARTIDO = re.compile(
    r"\b([a-fA-F0-9]{16,63})[ \t]*\r?\n[ \t]*([a-fA-F0-9]{1,48})\b"
)
_PALABRA_SHA256 = re.compile(r"sha[-_ ]?256", re.IGNORECASE)


def _unir_hash_partido(m: re.Match) -> str:
    """
    Decide si dos líneas hex consecutivas son UN SHA256 partido o dos
    hashes distintos.

    - Si no suman 64 caracteres, no pueden ser un SHA256: se dejan igual.
    - 32 + 32 es ambiguo: puede ser un SHA256 cortado a la mitad o dos MD5
      seguidos (muy común en listas de foros). Solo se unen si el contexto
      previo menciona "sha256"; si no, se asume que son dos MD5.
    - Cualquier otro corte que sume 64 (p. ej. 40 + 24) no puede ser un par
      de MD5, así que se une.
    """
    a, b = m.group(1), m.group(2)
    if len(a) + len(b) != 64:
        return m.group(0)
    if len(a) == 32 and len(b) == 32:
        contexto = m.string[max(0, m.start() - 40):m.start()]
        if not _PALABRA_SHA256.search(contexto):
            return m.group(0)
    return a + b


# Variantes de punto ofuscado: [.]  (.)  {.}  [dot]  (dot)  {dot}
_PUNTO_OFUSCADO = re.compile(r"[\[\(\{]\s*(?:\.|dot)\s*[\]\)\}]", re.IGNORECASE)
# Dos puntos ofuscados en URLs: hxxps[:]//
_DOS_PUNTOS_OFUSCADOS = re.compile(r"\[\s*:\s*\]")


def normalizar_texto(texto: str) -> str:
    """
    Normaliza técnicas de ofuscación comunes en foros dark web
    antes de aplicar los patrones regex.
    """
    # Defanging: 198[.]51[.]100[.]42, evil(dot)com, x{.}onion → con punto real
    texto = _PUNTO_OFUSCADO.sub(".", texto)
    texto = _DOS_PUNTOS_OFUSCADOS.sub(":", texto)

    # Defanging con espacios: 198 . 51 . 100 . 42 → 198.51.100.42
    texto = re.sub(r"(\d)\s+\.\s+(\d)", r"\1.\2", texto)

    # hxxp/hxxps → http/https
    texto = re.sub(r"hxxp(s?)", r"http\1", texto, flags=re.IGNORECASE)

    # SHA256 partido en dos líneas (ver _unir_hash_partido)
    texto = _HEX_PARTIDO.sub(_unir_hash_partido, texto)

    # Eliminar zero-width characters (ofuscación invisible)
    texto = re.sub(r"[​‌‍﻿]", "", texto)

    return texto


# ── Validaciones ────────────────────────────────────────────

def _es_documentacion(ip) -> bool:
    return any(ip in red for red in _REDES_DOCUMENTACION if red.version == ip.version)


def es_ip_publica(texto_ip: str) -> bool:
    """
    True si es una IP (v4 o v6) válida y enrutable en internet.
    Descarta privadas, loopback, link-local, multicast, CGNAT (100.64/10),
    benchmarking (198.18/15) y reservadas. Acepta las de documentación.
    """
    try:
        ip = ipaddress.ip_address(texto_ip)
    except ValueError:
        return False
    if _es_documentacion(ip):
        return True
    # is_global por sí solo deja pasar multicast (224.0.0.0/4): se excluye aparte
    return ip.is_global and not (ip.is_multicast or ip.is_reserved or ip.is_unspecified
                                 or ip.is_loopback or ip.is_link_local)


def es_ip_valida(ip: str) -> bool:
    """Compatibilidad: forma de IPv4 con octetos 0-255."""
    try:
        return isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address)
    except ValueError:
        return False


# Palabras que, justo antes de un número con forma de IP, indican que es una
# versión de software ("Firefox 115.0.2.1", "build 2.4.1.7").
_CONTEXTO_VERSION = re.compile(
    r"(?:versi[oó]n|ver\.?|\bv|build|release|update|firmware|patch|"
    r"chrome|firefox|edge|safari|windows|android|ios|kernel|linux|apache|"
    r"nginx|openssl|openssh|php|python|java|node|jdk|wordpress|vmware)\s*$",
    re.IGNORECASE,
)


def _contexto_sugiere_version(texto: str, inicio_match: int) -> bool:
    """
    True si justo antes del número hay una palabra como 'version', 'build' o
    el nombre de un producto. Un número de versión de 4 partes tiene la
    misma forma que una IP: solo el contexto los distingue.
    """
    ventana = texto[max(0, inicio_match - 25):inicio_match]
    return bool(_CONTEXTO_VERSION.search(ventana))


def _es_benigno(dominio: str) -> bool:
    d = dominio.lower()
    return any(d == b or d.endswith("." + b) for b in DOMINIOS_BENIGNOS)


def _parece_archivo(dominio: str) -> bool:
    etiquetas = dominio.lower().split(".")
    if len(etiquetas) != 2:
        return False
    nombre, extension = etiquetas
    return extension in _EXTENSIONES_AMBIGUAS or nombre in _NOMBRES_DE_ARCHIVO


def es_dominio_valido(dominio: str, texto: str, inicio: int) -> bool:
    """`inicio` es la posición de ESTA aparición (no de la primera)."""
    if _es_benigno(dominio):
        return False
    if inicio > 0 and texto[inicio - 1] == "@":       # parte de un email
        return False
    if dominio.split(".")[0].isdigit():                # "2.0.net"
        return False
    if _parece_archivo(dominio):                       # "setup.sh", "readme.info"
        return False
    return True


def es_cve_valido(cve: str) -> bool:
    try:
        ano = int(cve.upper().split("-")[1])
        return 1999 <= ano <= ANO_ACTUAL
    except (IndexError, ValueError):
        return False


# ── Extractor principal ─────────────────────────────────────

def _unicos(valores):
    """Deduplica conservando el orden de aparición."""
    return list(dict.fromkeys(valores))


def extraer_iocs(texto: str) -> dict:
    """
    Extrae IoCs del texto con normalización previa de ofuscación.
    Devuelve siempre las claves: ip, ipv6, sha256, sha1, md5, cve, dominio.
    """
    t = normalizar_texto(texto)
    resultado = {}

    # IPv4: se mira el contexto de cada aparición para descartar versiones
    resultado["ip"] = _unicos(
        m.group() for m in re.finditer(PATTERNS["ip"], t)
        if es_ip_valida(m.group())
        and es_ip_publica(m.group())
        and not _contexto_sugiere_version(t, m.start())
    )

    # IPv6: validada y normalizada a su forma comprimida en minúsculas
    ipv6 = []
    for m in re.finditer(PATTERNS["ipv6"], t):
        try:
            ip = ipaddress.IPv6Address(m.group())
        except ValueError:
            continue
        if es_ip_publica(str(ip)):
            ipv6.append(ip.compressed)
    resultado["ipv6"] = _unicos(ipv6)

    for tipo in ("sha256", "sha1", "md5"):
        resultado[tipo] = _unicos(
            h.lower() for h in re.findall(PATTERNS[tipo], t)
            if h.lower() not in HASHES_VACIOS
        )

    resultado["cve"] = _unicos(
        c.upper() for c in re.findall(PATTERNS["cve"], t, re.IGNORECASE)
        if es_cve_valido(c)
    )

    # Dominios: cada aparición se valida en SU posición (emails, archivos)
    resultado["dominio"] = _unicos(
        m.group().lower() for m in re.finditer(PATTERNS["dominio"], t, re.IGNORECASE)
        if es_dominio_valido(m.group(), t, m.start())
    )

    return resultado
