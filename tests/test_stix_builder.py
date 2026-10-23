import json
import os
import sys

import stix2

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from darkintel.stix_builder.builder import AUTOR, MARCA, construir_bundle

IOCS = {
    "ip": ["198.51.100.23", "198.51.100.24"], "ipv6": ["2001:db8::1"],
    "dominio": ["ransom-pay-test.onion"],
    "sha256": ["a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"],
    "md5": [], "cve": ["CVE-2023-4966"],
}
ENTIDADES = {"malware": ["LockBit"], "herramienta": ["Cobalt Strike", "Mimikatz"],
             "actor": ["FIN7"], "tecnica": ["spear-phishing"]}
PRIMERA, ULTIMA = "2025-11-15T03:42:00Z", "2025-11-16T10:00:00+00:00"


def _objetos(bundle) -> list[dict]:
    return json.loads(bundle.serialize())["objects"]


def _por_tipo(objetos, tipo):
    return [o for o in objetos if o["type"] == tipo]


def _bundle():
    return construir_bundle(IOCS, 0, ENTIDADES, PRIMERA, ULTIMA)


# ── Validez ──────────────────────────────────────────────────

def test_bundle_es_stix_21_valido():
    # stix2.parse valida tipos, propiedades obligatorias y formatos.
    # allow_custom=False: cualquier propiedad inventada haría fallar.
    stix2.parse(_bundle().serialize(), allow_custom=False)


def test_relaciones_son_las_del_estandar():
    validas = {
        ("indicator", "indicates", "campaign"),
        ("campaign", "uses", "malware"),
        ("campaign", "uses", "tool"),
        ("campaign", "uses", "attack-pattern"),
        ("campaign", "targets", "vulnerability"),
        ("campaign", "attributed-to", "threat-actor"),
    }
    for rel in _por_tipo(_objetos(_bundle()), "relationship"):
        triple = (rel["source_ref"].split("--")[0], rel["relationship_type"],
                  rel["target_ref"].split("--")[0])
        assert triple in validas, triple


# ── Contenido ────────────────────────────────────────────────

def test_crea_un_objeto_por_entidad_con_su_tipo():
    objs = _objetos(_bundle())
    assert [o["name"] for o in _por_tipo(objs, "malware")] == ["LockBit"]
    assert sorted(o["name"] for o in _por_tipo(objs, "tool")) == ["Cobalt Strike", "Mimikatz"]
    assert [o["name"] for o in _por_tipo(objs, "threat-actor")] == ["FIN7"]
    assert [o["name"] for o in _por_tipo(objs, "attack-pattern")] == ["spear-phishing"]
    assert _por_tipo(objs, "malware")[0]["is_family"] is True


def test_incluye_ipv6_y_todos_los_indicadores():
    patrones = {o["pattern"] for o in _por_tipo(_objetos(_bundle()), "indicator")}
    assert "[ipv6-addr:value = '2001:db8::1']" in patrones
    assert "[ipv4-addr:value = '198.51.100.23']" in patrones
    assert "[domain-name:value = 'ransom-pay-test.onion']" in patrones
    assert len(patrones) == 5


def test_cada_entidad_tiene_su_relacion_con_la_campana():
    objs = _objetos(_bundle())
    campana = _por_tipo(objs, "campaign")[0]
    relaciones = _por_tipo(objs, "relationship")
    destinos = {r["target_ref"] for r in relaciones if r["source_ref"] == campana["id"]}
    for tipo in ("malware", "tool", "threat-actor", "attack-pattern", "vulnerability"):
        for o in _por_tipo(objs, tipo):
            assert o["id"] in destinos, o["name"]
    origenes = {r["source_ref"] for r in relaciones if r["target_ref"] == campana["id"]}
    assert {o["id"] for o in _por_tipo(objs, "indicator")} == origenes


# ── Fechas reales ────────────────────────────────────────────

def test_usa_las_fechas_de_los_posts():
    objs = _objetos(_bundle())
    campana = _por_tipo(objs, "campaign")[0]
    assert campana["first_seen"] == "2025-11-15T03:42:00Z"
    assert campana["last_seen"] == "2025-11-16T10:00:00Z"
    for ind in _por_tipo(objs, "indicator"):
        assert ind["valid_from"] == "2025-11-15T03:42:00Z"


# ── IDs deterministas ────────────────────────────────────────

def test_dos_ejecuciones_producen_los_mismos_objetos():
    # Antes cada ejecución generaba IDs y fechas nuevas: duplicados infinitos
    assert _objetos(_bundle()) == _objetos(_bundle())


def test_el_mismo_malware_en_dos_campanas_es_un_solo_objeto():
    b1 = construir_bundle({"ip": ["198.51.100.1"]}, 0, {"malware": ["LockBit"]}, PRIMERA)
    b2 = construir_bundle({"ip": ["203.0.113.9"]}, 1, {"malware": ["LockBit"]}, PRIMERA)
    id1 = _por_tipo(_objetos(b1), "malware")[0]["id"]
    id2 = _por_tipo(_objetos(b2), "malware")[0]["id"]
    assert id1 == id2
    # ...pero son campañas distintas
    assert _por_tipo(_objetos(b1), "campaign")[0]["id"] != _por_tipo(_objetos(b2), "campaign")[0]["id"]


# ── Autoría y marcado ────────────────────────────────────────

def test_todos_los_objetos_tienen_autor_y_tlp():
    objs = _objetos(_bundle())
    assert AUTOR.id in {o["id"] for o in objs}
    assert MARCA.id in {o["id"] for o in objs}
    for o in objs:
        if o["type"] in ("identity", "marking-definition"):
            continue
        assert o["created_by_ref"] == AUTOR.id, o["type"]
        assert o["object_marking_refs"] == [MARCA.id], o["type"]


# ── Casos borde ──────────────────────────────────────────────

def test_cluster_de_ruido_no_crea_campana_ni_relaciones():
    objs = _objetos(construir_bundle(IOCS, -1, ENTIDADES, PRIMERA))
    assert _por_tipo(objs, "campaign") == []
    assert _por_tipo(objs, "relationship") == []
    assert len(_por_tipo(objs, "indicator")) == 5


def test_sin_nada_devuelve_bundle_vacio():
    assert json.loads(construir_bundle({}, 0, {}).serialize()).get("objects", []) == []


def test_sin_entidades_sigue_funcionando_como_antes():
    objs = _objetos(construir_bundle({"ip": ["198.51.100.23"]}, 0))
    assert len(_por_tipo(objs, "indicator")) == 1
    assert len(_por_tipo(objs, "campaign")) == 1
