"""
Base de conocimiento para el NER híbrido: "el modelo detecta, el
conocimiento experto clasifica".

Resuelve tres problemas que se vieron al probar SecureBERT-NER:

  1. TIPO equivocado: el modelo encuentra "Mimikatz" pero lo llama malware.
     -> Si el nombre está en la tabla, el tipo lo decide la tabla.
  2. NOMBRES sucios: "Cobalt Strike beacons", "LockBit 3.0".
     -> Se quitan versiones y palabras genéricas pegadas al nombre.
  3. ALIAS que el modelo no conoce: "mimi", "QBot", "ALPHV".
     -> Se mapean al nombre canónico y, si son inequívocos, se detectan
        directamente en el texto.

Solo usa la librería estándar: el validador y el evaluador la importan sin
necesitar PyTorch.

Las decisiones de tipo siguen docs/guia_anotacion.md (sección 4.2): software
diseñado para atacar -> malware; legítimo o de doble uso -> herramienta.
"""
import re
from typing import Optional

# ── Tabla de entidades conocidas ────────────────────────────
# nombre canónico -> tipos permitidos (el primero es el tipo por defecto)
#
# Los nombres que son a la vez una familia de malware y el grupo que la
# opera (ransomware como servicio) admiten "malware" y "actor": el tipo
# concreto lo decide el contexto de la frase (regla 4.2.2 de la guía).

_MALWARE = (
    "RedLine", "Raccoon", "Vidar", "Lumma", "StealC", "Emotet", "QakBot",
    "IcedID", "TrickBot", "Dridex", "AsyncRAT", "Remcos", "njRAT",
    "AgentTesla", "Formbook", "SmokeLoader", "Bumblebee", "Ryuk",
)
_MALWARE_Y_ACTOR = (
    "LockBit", "BlackCat", "Conti", "REvil", "Clop", "Akira",
    "Black Basta", "Royal", "Hive",
)
_HERRAMIENTAS = (
    "Cobalt Strike", "Mimikatz", "PsExec", "AnyDesk", "Rclone", "Metasploit",
    "Nmap", "sqlmap", "BloodHound", "Sliver", "Impacket", "Rubeus", "ngrok",
    "Masscan", "Hydra", "WinSCP", "Brute Ratel", "Advanced IP Scanner",
)
_ACTORES = (
    "FIN7", "FIN8", "APT28", "APT29", "Lazarus", "Scattered Spider",
    "Wizard Spider", "TA505", "Evil Corp", "Sandworm", "Kimsuky",
)

TABLA: dict[str, tuple[str, ...]] = {}
for _n in _MALWARE:
    TABLA[_n] = ("malware",)
for _n in _MALWARE_Y_ACTOR:
    TABLA[_n] = ("malware", "actor")
for _n in _HERRAMIENTAS:
    TABLA[_n] = ("herramienta",)
for _n in _ACTORES:
    TABLA[_n] = ("actor",)

# Técnicas: nombre canónico en minúsculas (como pide la guía).
TECNICAS = (
    "spear-phishing", "phishing", "credential stuffing", "brute force",
    "password spraying", "sql injection", "kerberoasting", "dll sideloading",
    "pass-the-hash", "sim swapping", "typosquatting", "watering hole",
)

# ── Alias ───────────────────────────────────────────────────
# alias (minúsculas) -> nombre canónico
ALIAS = {
    "mimi": "Mimikatz",
    "cobaltstrike": "Cobalt Strike",
    "cobalt-strike": "Cobalt Strike",
    "cs": "Cobalt Strike",
    "msf": "Metasploit",
    "qbot": "QakBot",
    "quakbot": "QakBot",
    "alphv": "BlackCat",
    "lockbit black": "LockBit",
    "lummac2": "Lumma",
    "lazarus group": "Lazarus",
    "agent tesla": "AgentTesla",
    "spearphishing": "spear-phishing",
    "spear phishing": "spear-phishing",
    "brute-force": "brute force",
    "bruteforce": "brute force",
    "sqli": "sql injection",
    "dll side-loading": "dll sideloading",
    "pass the hash": "pass-the-hash",
}
# Alias demasiado ambiguos para buscarlos sueltos en el texto ("CS" también
# es Counter-Strike o Computer Science). Se canonicalizan si el modelo los
# devuelve, pero NO se detectan por diccionario.
_ALIAS_NO_DETECTABLES = {"cs", "msf"}

# ── Limpieza de nombres ─────────────────────────────────────
# Palabras genéricas que a veces quedan pegadas al FINAL del nombre.
_SUFIJOS_GENERICOS = {
    "beacon", "beacons", "payload", "payloads", "builder", "panel", "loader",
    "dump", "dumps", "stager", "implant", "logs", "log", "build", "builds",
    "sample", "samples", "ransomware", "stealer", "malware", "rat", "botnet",
    "affiliate", "affiliates", "operators", "operator", "gang", "group",
    "crew", "team", "members", "framework", "tool", "binary",
}
_PREFIJOS_GENERICOS = {"the", "a", "an", "grupo", "el", "la"}
_VERSION_FINAL = re.compile(r"\s+v?\d+(?:\.\d+)*[a-z]?$", re.IGNORECASE)
# Palabras que, justo después de un nombre ambiguo, indican que se habla del
# GRUPO y no del software (regla 4.2.2 de la guía).
_INDICA_GRUPO = re.compile(
    r"^\W{0,3}(?:\d+(?:\.\d+)*\s+)?(?:affiliates?|operators?|gang|group|crew|"
    r"members|team|admins?|devs?|developers)\b", re.IGNORECASE)

# Términos genéricos que el modelo a veces etiqueta como entidad pero que NO
# nombran ningún software, grupo ni técnica concreta (regla 4.2.6 de la guía).
# Visto en la práctica: SecureBERT-NER etiqueta "C2" como TOOL.
NO_SON_ENTIDADES = {
    "c2", "c&c", "cnc", "command and control", "botnet", "bot", "bots",
    "ransomware", "stealer", "infostealer", "loader", "rat", "trojan",
    "malware", "virus", "worm", "backdoor", "exploit", "exploits", "0day",
    "zero-day", "payload", "panel", "builder", "crypter", "vpn", "rdp", "ssh",
    "tor", "proxy", "socks", "bitcoin", "btc", "monero", "xmr", "logs",
    "combo", "combolist", "database", "db", "shell", "webshell", "hacking",
    "attack", "hack", "access", "credentials", "creds",
}

_CANONICOS_POR_CLAVE = {n.lower(): n for n in TABLA}
_CANONICOS_POR_CLAVE.update({t: t for t in TECNICAS})


def normalizar_nombre(nombre: str) -> str:
    """'the Cobalt Strike beacons' -> 'Cobalt Strike'; 'LockBit 3.0' -> 'LockBit'."""
    nombre = re.sub(r"\s+", " ", nombre).strip(" .,;:!?\"'()[]{}<>")
    palabras = nombre.split(" ")
    while len(palabras) > 1 and palabras[0].lower() in _PREFIJOS_GENERICOS:
        palabras.pop(0)
    nombre = " ".join(palabras)
    for _ in range(3):   # "LockBit 3.0 ransomware builder" necesita varias pasadas
        anterior = nombre
        nombre = _VERSION_FINAL.sub("", nombre)
        palabras = nombre.split(" ")
        if len(palabras) > 1 and palabras[-1].lower() in _SUFIJOS_GENERICOS:
            nombre = " ".join(palabras[:-1])
        if nombre == anterior:
            break
    return nombre.strip()


def canonicalizar(nombre: str) -> str:
    """Nombre limpio y, si se conoce, en su forma canónica ('mimi' -> 'Mimikatz')."""
    limpio = normalizar_nombre(nombre)
    clave = limpio.lower()
    if clave in ALIAS:
        return ALIAS[clave]
    return _CANONICOS_POR_CLAVE.get(clave, limpio)


def tipos_permitidos(nombre_canonico: str) -> Optional[tuple[str, ...]]:
    if nombre_canonico in TABLA:
        return TABLA[nombre_canonico]
    if nombre_canonico in TECNICAS:
        return ("tecnica",)
    return None


def corregir(entidades: dict[str, list[str]]) -> dict[str, list[str]]:
    """
    Aplica la base de conocimiento a la salida del modelo:
    canonicaliza nombres y, si el nombre es conocido y el modelo le puso un
    tipo no permitido, lo mueve a su tipo por defecto. Los nombres
    desconocidos se conservan con el tipo que eligió el modelo.
    """
    salida = {tipo: [] for tipo in entidades}
    vistos = set()
    for tipo, nombres in entidades.items():
        for nombre in nombres:
            canonico = canonicalizar(nombre)
            if len(canonico) < 2 or canonico.lower() in NO_SON_ENTIDADES:
                continue
            if tipo == "tecnica":
                canonico = canonico.lower()
            permitidos = tipos_permitidos(canonico)
            destino = tipo if permitidos is None or tipo in permitidos else permitidos[0]
            clave = (destino, canonico.lower())
            if clave not in vistos:
                vistos.add(clave)
                salida.setdefault(destino, []).append(canonico)
    return salida


# ── Detección directa en el texto ───────────────────────────

def _patron(nombre: str) -> re.Pattern:
    # Bordes que no parten nombres con guiones o dígitos (APT28, spear-phishing)
    # Espacio o guion entre palabras: "Cobalt Strike" == "Cobalt-Strike"
    cuerpo = r"[\s-]+".join(re.escape(p) for p in nombre.split())
    return re.compile(r"(?<![\w-])" + cuerpo + r"(?![\w-])", re.IGNORECASE)


_DETECTABLES: list[tuple[re.Pattern, str]] = sorted(
    [(_patron(n), n) for n in TABLA]
    + [(_patron(t), t) for t in TECNICAS]
    + [(_patron(a), c) for a, c in ALIAS.items() if a not in _ALIAS_NO_DETECTABLES],
    key=lambda par: -len(par[0].pattern),   # primero los más largos
)


def detectar_en_texto(texto: str) -> dict[str, list[str]]:
    """
    Busca en el texto los nombres y alias inequívocos de la tabla.
    Los más largos primero, y lo encontrado se tapa para que "phishing" no
    se cuente otra vez dentro de "spear-phishing".
    """
    resultado = {"malware": [], "herramienta": [], "actor": [], "tecnica": []}
    vistos = set()
    restante = texto
    for patron, canonico in _DETECTABLES:
        for m in patron.finditer(restante):
            permitidos = tipos_permitidos(canonico)
            tipo = permitidos[0]
            if "actor" in permitidos and _INDICA_GRUPO.match(restante[m.end():m.end() + 30]):
                tipo = "actor"
            if (tipo, canonico) not in vistos:
                vistos.add((tipo, canonico))
                resultado[tipo].append(canonico)
        restante = patron.sub(lambda m: " " * len(m.group()), restante)
    return resultado


def fusionar(del_modelo: dict[str, list[str]], del_diccionario: dict[str, list[str]]) -> dict[str, list[str]]:
    """
    Une la salida del modelo (ya corregida) con lo detectado por diccionario.
    Si el modelo ya encontró un nombre, manda el tipo del modelo (tiene en
    cuenta el contexto); el diccionario solo AGREGA lo que el modelo no vio.
    """
    salida = {tipo: list(nombres) for tipo, nombres in del_modelo.items()}
    ya = {n.lower() for nombres in del_modelo.values() for n in nombres}
    for tipo, nombres in del_diccionario.items():
        for nombre in nombres:
            if nombre.lower() not in ya:
                ya.add(nombre.lower())
                salida.setdefault(tipo, []).append(nombre)
    return salida