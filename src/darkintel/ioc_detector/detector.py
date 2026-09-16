import re


PATRON_IP = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
PATRON_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
PATRON_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
PATRON_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
PATRON_EMAIL = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
PATRON_DOMINIO = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|ru|cn|onion|info|biz|gov|edu|co)\b"
)
PATRON_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
def extraer_emails(texto: str) -> list[str]:
    return list(dict.fromkeys(PATRON_EMAIL.findall(texto)))


def extraer_dominios(texto: str) -> list[str]:
    return list(dict.fromkeys(PATRON_DOMINIO.findall(texto)))


def extraer_cves(texto: str) -> list[str]:
    # Normalizamos a mayúsculas, porque "CVE" siempre se reporta así por convención
    encontrados = PATRON_CVE.findall(texto)
    normalizados = [cve.upper() for cve in encontrados]
    return list(dict.fromkeys(normalizados))
def extraer_hashes(texto: str) -> dict[str, list[str]]:
    """
    Busca hashes MD5, SHA1 y SHA256 en un texto.
    Devuelve un diccionario separado por tipo, sin duplicados.
    """
    md5 = list(dict.fromkeys(PATRON_MD5.findall(texto)))
    sha1 = list(dict.fromkeys(PATRON_SHA1.findall(texto)))
    sha256 = list(dict.fromkeys(PATRON_SHA256.findall(texto)))

    return {
        "md5": md5,
        "sha1": sha1,
        "sha256": sha256,
    }

def extraer_ips(texto: str) -> list[str]:
    """
    Busca todas las direcciones IPv4 dentro de un texto.
    Devuelve una lista de IPs únicas, en el orden en que aparecen.
    """
    coincidencias = PATRON_IP.findall(texto)
    # Usamos dict.fromkeys() en vez de set() para eliminar duplicados
    # PERO conservando el orden de aparición (los sets no garantizan orden)
    return list(dict.fromkeys(coincidencias))

def detectar_iocs(texto: str) -> dict:
    """
    Ejecuta todos los detectores sobre un texto y devuelve
    un único diccionario con todos los tipos de IoCs encontrados.
    """
    hashes = extraer_hashes(texto)

    return {
        "ips": extraer_ips(texto),
        "dominios": extraer_dominios(texto),
        "emails": extraer_emails(texto),
        "cves": extraer_cves(texto),
        "md5": hashes["md5"],
        "sha1": hashes["sha1"],
        "sha256": hashes["sha256"],
    }
if __name__ == "__main__":
    texto_prueba = """
    El atacante se conectó desde la IP 192.168.1.10 y también desde 8.8.8.8.

    Se identificó el archivo malicioso con hash MD5: 5d41402abc4b2a76b9719d911017c592
    y SHA256: 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae

    El correo del atacante fue reportado como contacto@malicious-site.com
    El dominio malicious-site.com también fue visto en logs de red,
    junto con panel-c2.ru y una dirección .onion como ejemplo: darkforum.onion

    La vulnerabilidad explotada corresponde a CVE-2023-12345 y también cve-2021-9999.
    """

    resultado = detectar_iocs(texto_prueba)

    import json
    print(json.dumps(resultado, indent=2, ensure_ascii=False))