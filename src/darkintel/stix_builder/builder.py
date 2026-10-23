"""
Construcción de bundles STIX 2.1 a partir de lo que extrae el pipeline.

Grafo por campaña (clúster de HDBSCAN):

    Indicator ──indicates──► Campaign ──uses──────────► Malware
    (IP, dominio, hash)         │      ──uses──────────► Tool
                                │      ──uses──────────► Attack-Pattern
                                │      ──targets───────► Vulnerability (CVE)
                                └───── ──attributed-to─► Threat-Actor

Decisiones de diseño:

- IDs DETERMINISTAS (UUIDv5 sobre el contenido): la misma IP, el mismo
  malware o la misma relación generan siempre el mismo ID. Volver a correr
  el pipeline no duplica objetos, y "LockBit" es UN solo objeto aunque
  aparezca en varias campañas. (STIX 2.1 recomienda UUIDv4 para SDO; se
  elige v5 a propósito por la deduplicación.)
- Fechas REALES: valid_from / first_seen / last_seen salen de la fecha de
  los posts, no de una constante. created/modified usan la misma fecha para
  que el bundle sea reproducible.
- Autor (Identity "DarkIntel") en created_by_ref y marca TLP:AMBER: la
  inteligencia sale de fuentes sensibles y no debe redistribuirse libremente.
- El clúster -1 (ruido de HDBSCAN) no genera Campaign ni relaciones: sus
  objetos se publican sueltos.
"""
import uuid
from datetime import datetime, timezone
from typing import Optional

from stix2 import (TLP_AMBER, AttackPattern, Bundle, Campaign, Identity, Indicator,
                   Malware, Relationship, ThreatActor, Tool, Vulnerability)

# Espacio de nombres propio para los UUIDv5 de DarkIntel.
NAMESPACE_DARKINTEL = uuid.uuid5(uuid.NAMESPACE_URL, "https://darkintel.local/stix/v1")

MARCA = TLP_AMBER
FECHA_POR_DEFECTO = "2025-01-01T00:00:00Z"


def _id(tipo: str, *partes: str) -> str:
    clave = "|".join([tipo, *[p.lower() for p in partes]])
    return f"{tipo}--{uuid.uuid5(NAMESPACE_DARKINTEL, clave)}"


AUTOR = Identity(
    id=_id("identity", "darkintel"),
    name="DarkIntel",
    identity_class="system",
    description="Pipeline automatizado de recolección de IoCs en la Dark Web (proyecto académico).",
    created=FECHA_POR_DEFECTO,
    modified=FECHA_POR_DEFECTO,
)


def _comunes(fecha: str) -> dict:
    """Propiedades que llevan todos los objetos que crea DarkIntel."""
    return {
        "created_by_ref": AUTOR.id,
        "object_marking_refs": [MARCA.id],
        "created": fecha,
        "modified": fecha,
    }


# ── Indicadores (IoCs atómicos) ─────────────────────────────

_PATRONES = {
    "ip":      ("ipv4-addr:value", "IP sospechosa"),
    "ipv6":    ("ipv6-addr:value", "IPv6 sospechosa"),
    "dominio": ("domain-name:value", "Dominio sospechoso"),
    "sha256":  ("file:hashes.'SHA-256'", "Archivo sospechoso (SHA-256)"),
    "sha1":    ("file:hashes.'SHA-1'", "Archivo sospechoso (SHA-1)"),
    "md5":     ("file:hashes.MD5", "Archivo sospechoso (MD5)"),
}


def crear_indicador(tipo: str, valor: str, fecha: str) -> Indicator:
    """
    Los valores vienen del extractor regex (solo dígitos, hex, letras,
    puntos y guiones), así que no pueden romper el patrón STIX con comillas.
    """
    ruta, etiqueta = _PATRONES[tipo]
    patron = f"[{ruta} = '{valor}']"
    return Indicator(
        id=_id("indicator", patron),
        name=f"{etiqueta}: {valor}",
        indicator_types=["malicious-activity"],
        pattern=patron,
        pattern_type="stix",
        valid_from=fecha,
        **_comunes(fecha),
    )


def crear_vulnerabilidad_cve(cve_id: str, fecha: str = FECHA_POR_DEFECTO) -> Vulnerability:
    return Vulnerability(
        id=_id("vulnerability", cve_id),
        name=cve_id,
        external_references=[{"source_name": "cve", "external_id": cve_id}],
        **_comunes(fecha),
    )


# ── Entidades (Transformer + base de conocimiento) ──────────

def crear_malware(nombre: str, fecha: str) -> Malware:
    return Malware(id=_id("malware", nombre), name=nombre, is_family=True, **_comunes(fecha))


def crear_herramienta(nombre: str, fecha: str) -> Tool:
    return Tool(id=_id("tool", nombre), name=nombre, **_comunes(fecha))


def crear_actor(nombre: str, fecha: str) -> ThreatActor:
    return ThreatActor(id=_id("threat-actor", nombre), name=nombre, **_comunes(fecha))


def crear_tecnica(nombre: str, fecha: str) -> AttackPattern:
    return AttackPattern(id=_id("attack-pattern", nombre), name=nombre, **_comunes(fecha))


_ENTIDADES = {
    # categoría -> (constructor, relación desde la campaña)
    "malware":     (crear_malware, "uses"),
    "herramienta": (crear_herramienta, "uses"),
    "tecnica":     (crear_tecnica, "uses"),
    "actor":       (crear_actor, "attributed-to"),
}


# ── Campaña y relaciones ────────────────────────────────────

def crear_campana(cluster_id: int, descripcion: str, primera_vista: str,
                  ultima_vista: str, firma: str) -> Campaign:
    return Campaign(
        id=_id("campaign", firma),
        name=f"Campaña cluster-{cluster_id}",
        description=descripcion,
        first_seen=primera_vista,
        last_seen=ultima_vista,
        **_comunes(primera_vista),
    )


def _relacion(origen, tipo: str, destino, fecha: str) -> Relationship:
    return Relationship(
        id=_id("relationship", origen.id, tipo, destino.id),
        relationship_type=tipo,
        source_ref=origen.id,
        target_ref=destino.id,
        **_comunes(fecha),
    )


def _fecha_stix(fecha: Optional[str]) -> str:
    """Acepta ISO 8601 (con o sin Z) y devuelve el formato STIX con Z."""
    if not fecha:
        return FECHA_POR_DEFECTO
    dt = datetime.fromisoformat(fecha.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── API pública ─────────────────────────────────────────────

def construir_objetos_stix(iocs: dict, entidades: Optional[dict] = None,
                           fecha: str = FECHA_POR_DEFECTO) -> dict:
    """
    Devuelve {"indicadores": [...], "vulnerabilidades": [...],
              "entidades": [(objeto, relacion_desde_campana), ...]}.
    """
    indicadores = [
        crear_indicador(tipo, valor, fecha)
        for tipo in _PATRONES
        for valor in sorted(set(iocs.get(tipo, [])))
    ]
    vulnerabilidades = [crear_vulnerabilidad_cve(c, fecha) for c in sorted(set(iocs.get("cve", [])))]

    objetos_entidad, vistos = [], set()
    for categoria, (constructor, relacion) in _ENTIDADES.items():
        for nombre in (entidades or {}).get(categoria, []):
            obj = constructor(nombre, fecha)
            if obj.id not in vistos:
                vistos.add(obj.id)
                objetos_entidad.append((obj, relacion))

    return {"indicadores": indicadores, "vulnerabilidades": vulnerabilidades,
            "entidades": objetos_entidad}


def construir_bundle(iocs: dict, cluster_id: int = None, entidades: Optional[dict] = None,
                     primera_vista: Optional[str] = None,
                     ultima_vista: Optional[str] = None) -> Bundle:
    """
    Bundle STIX 2.1 de un clúster.

    iocs:       {"ip": [...], "ipv6": [...], "dominio": [...], "sha256": [...],
                 "sha1": [...], "md5": [...], "cve": [...]}
    entidades:  {"malware": [...], "herramienta": [...], "actor": [...], "tecnica": [...]}
    fechas:     ISO 8601 del primer y último post del clúster.
    """
    primera = _fecha_stix(primera_vista)
    ultima = _fecha_stix(ultima_vista or primera_vista)

    partes = construir_objetos_stix(iocs, entidades, primera)
    indicadores, vulnerabilidades = partes["indicadores"], partes["vulnerabilidades"]
    entidades_stix = partes["entidades"]

    objetos = indicadores + vulnerabilidades + [obj for obj, _ in entidades_stix]
    if not objetos:
        return Bundle()

    if cluster_id is not None and cluster_id >= 0:
        # Firma de la campaña: su contenido. Mismo contenido -> mismo ID.
        firma = "|".join(sorted(o.id for o in objetos))
        resumen = ", ".join(
            f"{len(lista)} {nombre}" for nombre, lista in (
                ("indicadores", indicadores), ("vulnerabilidades", vulnerabilidades),
                ("entidades", entidades_stix)) if lista
        )
        campana = crear_campana(cluster_id, f"Agrupada automáticamente por DarkIntel: {resumen}.",
                                primera, ultima, firma)
        relaciones = (
            [_relacion(ind, "indicates", campana, primera) for ind in indicadores]
            + [_relacion(campana, "targets", vul, primera) for vul in vulnerabilidades]
            + [_relacion(campana, rel, obj, primera) for obj, rel in entidades_stix]
        )
        objetos = objetos + [campana] + relaciones

    return Bundle(objects=[AUTOR, MARCA] + objetos)
