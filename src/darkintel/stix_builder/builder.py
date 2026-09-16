from stix2 import Indicator, Bundle, Vulnerability


def crear_indicador_ip(ip: str) -> Indicator:
    """
    Crea un objeto STIX Indicator a partir de una dirección IP.
    """
    patron = f"[ipv4-addr:value = '{ip}']"
    return Indicator(
        pattern=patron,
        pattern_type="stix",
        name=f"IP sospechosa: {ip}",
    )


def crear_indicador_dominio(dominio: str) -> Indicator:
    patron = f"[domain-name:value = '{dominio}']"
    return Indicator(pattern=patron, pattern_type="stix", name=f"Dominio sospechoso: {dominio}")


def crear_indicador_email(email: str) -> Indicator:
    patron = f"[email-addr:value = '{email}']"
    return Indicator(pattern=patron, pattern_type="stix", name=f"Email sospechoso: {email}")


def crear_indicador_hash(valor_hash: str, algoritmo_stix: str) -> Indicator:
    """
    algoritmo_stix debe ser el nombre EXACTO que espera STIX: 'MD5', 'SHA-1' o 'SHA-256'.
    Los nombres con guion (como SHA-1 y SHA-256) requieren comillas simples
    dentro del patrón STIX, según la especificación del lenguaje de patrones.
    """
    patron = f"[file:hashes.'{algoritmo_stix}' = '{valor_hash}']"
    return Indicator(
        pattern=patron,
        pattern_type="stix",
        name=f"Archivo sospechoso ({algoritmo_stix}): {valor_hash}",
    )


def crear_vulnerabilidad_cve(cve_id: str) -> Vulnerability:
    """
    Crea un objeto STIX Vulnerability a partir de un identificador CVE,
    usando external_references para apuntar al catálogo oficial de MITRE.
    """
    return Vulnerability(
        name=cve_id,
        external_references=[
            {
                "source_name": "cve",
                "external_id": cve_id,
            }
        ],
    )


def construir_objetos_stix_desde_iocs(iocs: dict) -> list:
    """
    Recibe el diccionario de IoCs (tal como lo produce detector.py)
    y devuelve una lista de objetos STIX, mezclando Indicator
    (para IoCs observables) y Vulnerability (para CVEs).
    """
    objetos = []

    for ip in iocs.get("ips", []):
        objetos.append(crear_indicador_ip(ip))

    for dominio in iocs.get("dominios", []):
        objetos.append(crear_indicador_dominio(dominio))

    for email in iocs.get("emails", []):
        objetos.append(crear_indicador_email(email))

    for md5 in iocs.get("md5", []):
        objetos.append(crear_indicador_hash(md5, "MD5"))

    for sha1 in iocs.get("sha1", []):
        objetos.append(crear_indicador_hash(sha1, "SHA-1"))

    for sha256 in iocs.get("sha256", []):
        objetos.append(crear_indicador_hash(sha256, "SHA-256"))

    for cve in iocs.get("cves", []):
        objetos.append(crear_vulnerabilidad_cve(cve))

    return objetos


def construir_bundle(iocs: dict) -> Bundle:
    """
    Construye un Bundle STIX completo a partir del diccionario de IoCs,
    incluyendo tanto Indicator (IoCs observables) como Vulnerability (CVEs).
    """
    objetos = construir_objetos_stix_desde_iocs(iocs)
    return Bundle(objects=objetos)


if __name__ == "__main__":
    iocs_prueba = {
        "ips": ["8.8.8.8"],
        "dominios": ["malicious-site.com"],
        "emails": ["atacante@evil.com"],
        "cves": ["CVE-2023-12345"],
        "md5": ["5d41402abc4b2a76b9719d911017c592"],
        "sha1": [],
        "sha256": [],
    }

    bundle = construir_bundle(iocs_prueba)

    print(f"Cantidad de objetos en el bundle: {len(bundle.objects)}")
    print(bundle)