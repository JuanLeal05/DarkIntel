from stix2 import Indicator, Bundle, Vulnerability, Campaign, Relationship


def crear_indicador_ip(ip: str) -> Indicator:
    patron = f"[ipv4-addr:value = '{ip}']"
    return Indicator(
        pattern=patron,
        pattern_type="stix",
        name=f"IP sospechosa: {ip}",
        valid_from="2025-01-01T00:00:00Z"
    )


def crear_indicador_dominio(dominio: str) -> Indicator:
    patron = f"[domain-name:value = '{dominio}']"
    return Indicator(
        pattern=patron,
        pattern_type="stix",
        name=f"Dominio sospechoso: {dominio}",
        valid_from="2025-01-01T00:00:00Z"
    )


def crear_indicador_hash(valor_hash: str, algoritmo: str) -> Indicator:
    patron = f"[file:hashes.'{algoritmo}' = '{valor_hash}']"
    return Indicator(
        pattern=patron,
        pattern_type="stix",
        name=f"Archivo sospechoso ({algoritmo}): {valor_hash}",
        valid_from="2025-01-01T00:00:00Z"
    )


def crear_vulnerabilidad_cve(cve_id: str) -> Vulnerability:
    return Vulnerability(
        name=cve_id,
        external_references=[{
            "source_name": "cve",
            "external_id": cve_id,
        }]
    )


def crear_campana(cluster_id: int, descripcion: str) -> Campaign:
    return Campaign(
        name=f"Campaña cluster-{cluster_id}",
        description=descripcion
    )


def construir_objetos_stix(iocs: dict) -> list:
    objetos = []

    for ip in iocs.get("ip", []):
        objetos.append(crear_indicador_ip(ip))

    for dominio in iocs.get("dominio", []):
        objetos.append(crear_indicador_dominio(dominio))

    for h in iocs.get("sha256", []):
        objetos.append(crear_indicador_hash(h, "SHA-256"))

    for h in iocs.get("md5", []):
        objetos.append(crear_indicador_hash(h, "MD5"))

    for cve in iocs.get("cve", []):
        objetos.append(crear_vulnerabilidad_cve(cve))

    return objetos


def construir_bundle(iocs: dict, cluster_id: int = None) -> Bundle:
    objetos = construir_objetos_stix(iocs)

    if not objetos:
        return Bundle()

    if cluster_id is not None and cluster_id >= 0:
        iocs_str = ", ".join(
            ioc for tipo in iocs.values() for ioc in tipo
        )
        campana = crear_campana(cluster_id, f"IoCs: {iocs_str}")

        # Construir relaciones ANTES de modificar la lista
        relaciones = [
            Relationship(
                relationship_type="indicates",
                source_ref=obj.id,
                target_ref=campana.id
            )
            for obj in objetos
            if obj.get("type") == "indicator"
        ]

        objetos.append(campana)
        objetos.extend(relaciones)

    return Bundle(objects=objetos)