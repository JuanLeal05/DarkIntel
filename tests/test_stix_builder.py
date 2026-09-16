import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from darkintel.stix_builder.builder import (
    crear_indicador_ip,
    crear_vulnerabilidad_cve,
    construir_objetos_stix_desde_iocs,
    construir_bundle,
)


def test_crear_indicador_ip_estructura_valida():
    indicador = crear_indicador_ip("8.8.8.8")

    assert indicador["type"] == "indicator"
    assert indicador["spec_version"] == "2.1"
    assert indicador["pattern"] == "[ipv4-addr:value = '8.8.8.8']"
    assert indicador["pattern_type"] == "stix"
    assert indicador["id"].startswith("indicator--")

    print("✅ Prueba superada: Indicator STIX generado correctamente.")
    print(json.dumps(json.loads(str(indicador)), indent=2))


def test_construir_objetos_desde_iocs():
    iocs = {
        "ips": ["8.8.8.8"],
        "dominios": ["evil.com"],
        "emails": ["x@evil.com"],
        "cves": ["CVE-2023-12345"],
        "md5": ["5d41402abc4b2a76b9719d911017c592"],
        "sha1": [],
        "sha256": [],
    }

    objetos = construir_objetos_stix_desde_iocs(iocs)

    # 1 ip + 1 dominio + 1 email + 1 md5 + 1 cve = 5
    assert len(objetos) == 5

    tipos = [obj["type"] for obj in objetos]
    assert tipos.count("indicator") == 4
    assert tipos.count("vulnerability") == 1

    print(f"✅ Prueba superada: {len(objetos)} objetos STIX (4 indicator + 1 vulnerability).")


def test_construir_bundle_estructura_valida():
    iocs = {"ips": ["1.1.1.1"], "dominios": [], "emails": [], "cves": [], "md5": [], "sha1": [], "sha256": []}
    bundle = construir_bundle(iocs)

    assert bundle["type"] == "bundle"
    assert len(bundle.objects) == 1
    assert bundle["id"].startswith("bundle--")

    print("✅ Prueba superada: Bundle STIX generado correctamente.")


def test_crear_vulnerabilidad_cve():
    vuln = crear_vulnerabilidad_cve("CVE-2023-12345")

    assert vuln["type"] == "vulnerability"
    assert vuln["name"] == "CVE-2023-12345"
    assert vuln["external_references"][0]["source_name"] == "cve"
    assert vuln["external_references"][0]["external_id"] == "CVE-2023-12345"

    print("✅ Prueba superada: Vulnerability STIX generada correctamente.")


def test_construir_objetos_incluye_vulnerabilidad():
    iocs = {
        "ips": [],
        "dominios": [],
        "emails": [],
        "cves": ["CVE-2023-12345", "CVE-2021-9999"],
        "md5": [],
        "sha1": [],
        "sha256": [],
    }

    objetos = construir_objetos_stix_desde_iocs(iocs)

    assert len(objetos) == 2
    assert all(obj["type"] == "vulnerability" for obj in objetos)

    print(f"✅ Prueba superada: {len(objetos)} vulnerabilidades generadas desde CVEs.")


def test_bundle_mezcla_indicator_y_vulnerability():
    """
    Prueba específica contra el bug que acabamos de corregir:
    confirma que el Bundle realmente combina ambos tipos de objeto,
    no solo uno de ellos.
    """
    iocs = {
        "ips": ["8.8.8.8"],
        "dominios": [],
        "emails": [],
        "cves": ["CVE-2023-12345"],
        "md5": [],
        "sha1": [],
        "sha256": [],
    }

    bundle = construir_bundle(iocs)
    bundle_dict = json.loads(str(bundle))

    tipos = [obj["type"] for obj in bundle_dict["objects"]]
    assert "indicator" in tipos
    assert "vulnerability" in tipos

    print("✅ Prueba superada: el Bundle mezcla correctamente Indicator y Vulnerability.")


if __name__ == "__main__":
    test_crear_indicador_ip_estructura_valida()
    test_construir_objetos_desde_iocs()
    test_construir_bundle_estructura_valida()
    test_crear_vulnerabilidad_cve()
    test_construir_objetos_incluye_vulnerabilidad()
    test_bundle_mezcla_indicator_y_vulnerability()