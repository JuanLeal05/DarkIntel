"""
Evaluación de DarkIntel contra el dataset anotado de la demo.

Formato de los archivos: ver docs/guia_anotacion.md (secciones 3.4, 3.6 y 5).

Este módulo tiene la lógica; los scripts de línea de comandos están en
pipeline/validar_anotaciones.py y pipeline/evaluar.py.
"""
import ipaddress
import json
import re

# ── Esquema ─────────────────────────────────────────────────

TIPOS_IOC = ("ip", "ipv6", "md5", "sha1", "sha256", "cve", "dominio")
TIPOS_ENTIDAD = ("malware", "herramienta", "actor", "tecnica")

_POST_ID = re.compile(r"^p\d{2,3}$")
_HEX = {"md5": 32, "sha1": 40, "sha256": 64}
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_DOMINIO = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,}$")
_HASHES_VACIOS = {
    "d41d8cd98f00b204e9800998ecf8427e",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}
# Rangos de documentación (RFC 5737 / RFC 3849): el dataset de la demo los
# usa a propósito, así que SÍ son IoCs válidos aunque ipaddress los marque
# como privados.
_REDES_DOC = [ipaddress.ip_network(r) for r in
              ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]


class ErrorFormato(Exception):
    pass


# ── Lectura ─────────────────────────────────────────────────

def leer_jsonl(ruta: str) -> list[tuple[int, dict]]:
    """Devuelve [(numero_de_linea, objeto)]. Ignora líneas vacías."""
    filas = []
    with open(ruta, encoding="utf-8") as f:
        for n, linea in enumerate(f, start=1):
            if not linea.strip():
                continue
            try:
                obj = json.loads(linea)
            except json.JSONDecodeError as e:
                raise ErrorFormato(f"{ruta}:{n}: JSON inválido ({e.msg}, columna {e.colno})")
            if not isinstance(obj, dict):
                raise ErrorFormato(f"{ruta}:{n}: cada línea debe ser un objeto {{...}}")
            filas.append((n, obj))
    return filas


# ── Validación de posts ─────────────────────────────────────

def validar_posts(ruta: str) -> tuple[list[str], list[str], dict]:
    """Devuelve (errores, avisos, posts_por_id)."""
    errores, avisos, posts = [], [], {}
    try:
        filas = leer_jsonl(ruta)
    except FileNotFoundError:
        return [f"No existe {ruta}"], [], {}
    except ErrorFormato as e:
        return [str(e)], [], {}

    for n, p in filas:
        donde = f"{ruta}:{n}"
        pid = p.get("post_id")
        if not isinstance(pid, str) or not _POST_ID.match(pid):
            errores.append(f"{donde}: post_id inválido {pid!r} (formato p01, p02, ...)")
            continue
        if pid in posts:
            errores.append(f"{donde}: post_id repetido {pid}")
            continue
        if p.get("split") not in ("dev", "test"):
            errores.append(f"{donde} [{pid}]: split debe ser 'dev' o 'test'")
        if not isinstance(p.get("text"), str) or not p["text"].strip():
            errores.append(f"{donde} [{pid}]: falta 'text' o está vacío")
        if not isinstance(p.get("title", ""), str):
            errores.append(f"{donde} [{pid}]: 'title' debe ser texto")
        posts[pid] = p

    n_dev = sum(1 for p in posts.values() if p.get("split") == "dev")
    n_test = sum(1 for p in posts.values() if p.get("split") == "test")
    if len(posts) != 45:
        avisos.append(f"Hay {len(posts)} posts; la guía pide 45")
    if (n_dev, n_test) != (16, 29):
        avisos.append(f"División dev/test = {n_dev}/{n_test}; la guía pide 16/29")
    return errores, avisos, posts


def validar_campanas(ruta: str, posts: dict) -> list[str]:
    errores = []
    try:
        with open(ruta, encoding="utf-8") as f:
            campanas = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        return [f"{ruta}: no se pudo leer ({e})"]
    if not isinstance(campanas, dict):
        return [f"{ruta}: debe ser un objeto {{\"campana_1\": [...], ...}}"]

    vistos = {}
    for nombre, ids in campanas.items():
        if not isinstance(ids, list):
            errores.append(f"{ruta}: '{nombre}' debe ser una lista de post_id")
            continue
        for pid in ids:
            if pid not in posts:
                errores.append(f"{ruta}: '{nombre}' contiene {pid!r}, que no está en posts")
            elif pid in vistos:
                errores.append(f"{ruta}: {pid} está en '{vistos[pid]}' y en '{nombre}'")
            else:
                vistos[pid] = nombre
    for pid in sorted(set(posts) - set(vistos)):
        errores.append(f"{ruta}: {pid} no está asignado a ninguna campaña ni a 'ruido'")
    return errores


# ── Validación de anotaciones ───────────────────────────────

def _es_doc(ip) -> bool:
    return any(ip in red for red in _REDES_DOC if red.version == ip.version)


def _errores_valor(tipo: str, v: str) -> list[str]:
    """Reglas de normalización de la guía (sección 4.1 y 4.2)."""
    if v != v.strip() or not v:
        return ["espacios sobrantes o vacío"]
    if tipo in _HEX:
        if len(v) != _HEX[tipo] or not re.fullmatch(r"[0-9a-fA-F]+", v):
            return [f"un {tipo} tiene {_HEX[tipo]} caracteres hexadecimales"]
        if v != v.lower():
            return ["los hashes van en minúsculas"]
        if v in _HASHES_VACIOS:
            return ["es el hash de un archivo vacío (no se anota)"]
    elif tipo == "cve":
        if not _CVE.match(v):
            return ["formato CVE-AAAA-NNNN en MAYÚSCULAS"]
    elif tipo in ("ip", "ipv6"):
        try:
            ip = ipaddress.ip_address(v)
        except ValueError:
            return ["no es una dirección IP válida"]
        if (tipo == "ip") != (ip.version == 4):
            return [f"va en '{'ip' if ip.version == 4 else 'ipv6'}'"]
        if not _es_doc(ip) and not ip.is_global:
            return ["IP privada/reservada/loopback (no se anota)"]
    elif tipo == "dominio":
        if v != v.lower():
            return ["los dominios van en minúsculas"]
        if "[" in v or "]" in v or "(" in v:
            return ["quitar la ofuscación ([.], (dot))"]
        if "://" in v or "/" in v or ":" in v:
            return ["sin http://, sin ruta y sin puerto"]
        if not _DOMINIO.match(v):
            return ["no parece un dominio válido"]
    elif tipo == "tecnica":
        if v != v.lower():
            return ["las técnicas van en minúsculas"]
    if tipo in TIPOS_ENTIDAD and re.search(r"[.,;:!?\"']$", v):
        return ["sin puntuación al final"]
    return []


def validar_anotaciones(ruta: str, posts: dict) -> tuple[list[str], dict]:
    """Devuelve (errores, anotaciones_por_id)."""
    errores, anotaciones = [], {}
    try:
        filas = leer_jsonl(ruta)
    except FileNotFoundError:
        return [f"No existe {ruta}"], {}
    except ErrorFormato as e:
        return [str(e)], {}

    for n, a in filas:
        pid = a.get("post_id")
        donde = f"{ruta}:{n} [{pid}]"
        if pid not in posts:
            errores.append(f"{donde}: post_id no existe en posts.jsonl")
            continue
        if pid in anotaciones:
            errores.append(f"{donde}: post anotado dos veces")
            continue

        for grupo, tipos in (("iocs", TIPOS_IOC), ("entidades", TIPOS_ENTIDAD)):
            bloque = a.get(grupo)
            if not isinstance(bloque, dict):
                errores.append(f"{donde}: falta el objeto '{grupo}'")
                continue
            for extra in sorted(set(bloque) - set(tipos)):
                errores.append(f"{donde}: clave desconocida '{grupo}.{extra}'")
            for tipo in tipos:
                if tipo not in bloque:
                    errores.append(f"{donde}: falta '{grupo}.{tipo}' (aunque esté vacía: [])")
                    continue
                valores = bloque[tipo]
                if not isinstance(valores, list) or not all(isinstance(v, str) for v in valores):
                    errores.append(f"{donde}: '{grupo}.{tipo}' debe ser una lista de textos")
                    continue
                if len({v.lower() for v in valores}) != len(valores):
                    errores.append(f"{donde}: '{grupo}.{tipo}' tiene valores repetidos")
                for v in valores:
                    for problema in _errores_valor(tipo, v):
                        errores.append(f"{donde}: {grupo}.{tipo} {v!r}: {problema}")
        anotaciones[pid] = a

    for pid in sorted(set(posts) - set(anotaciones)):
        errores.append(f"{ruta}: falta anotar {pid} (los posts sin nada también se anotan)")
    return errores, anotaciones


# ── Métricas ────────────────────────────────────────────────

def _conjunto(valores) -> set:
    return {v.strip().lower() for v in valores if v and v.strip()}


def prf(tp: int, fp: int, fn: int) -> dict:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return {"tp": tp, "fp": fp, "fn": fn,
            "precision": round(p, 4), "recall": round(r, 4), "f1": round(f, 4)}


def comparar(referencia: dict, prediccion: dict, post_ids) -> dict:
    """
    Compara dos conjuntos de anotaciones {post_id: {"iocs": {...}, "entidades": {...}}}.

    Niveles:
      - por tipo de IoC y de entidad
      - iocs_total / entidades_total: micro-promedio (tipo + valor deben coincidir)
      - entidades_deteccion: la entidad se encontró, SIN importar el tipo
        (separa "no la vio" de "la vio pero la clasificó mal")
      - global: IoCs + entidades, la cifra del paper
    """
    cont = {}

    def sumar(clave, ref, pred):
        c = cont.setdefault(clave, [0, 0, 0])
        c[0] += len(ref & pred)
        c[1] += len(pred - ref)
        c[2] += len(ref - pred)

    for pid in post_ids:
        ref, pred = referencia[pid], prediccion.get(pid, {"iocs": {}, "entidades": {}})
        det_ref, det_pred = set(), set()
        for grupo, tipos, total in (("iocs", TIPOS_IOC, "iocs_total"),
                                    ("entidades", TIPOS_ENTIDAD, "entidades_total")):
            for tipo in tipos:
                r = _conjunto(ref[grupo].get(tipo, []))
                p = _conjunto(pred.get(grupo, {}).get(tipo, []))
                sumar(f"{grupo}.{tipo}", r, p)
                sumar(total, {(tipo, v) for v in r}, {(tipo, v) for v in p})
                sumar("global", {(tipo, v) for v in r}, {(tipo, v) for v in p})
                if grupo == "entidades":
                    det_ref |= r
                    det_pred |= p
        sumar("entidades_deteccion", det_ref, det_pred)

    return {clave: prf(*valores) for clave, valores in cont.items()}
