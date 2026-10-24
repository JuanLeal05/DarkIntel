import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from darkintel.ioc_detector.detector import extraer_ips


def test_extraer_ips_detecta_ips_validas():
    texto = "Conexión desde 192.168.1.10 y también 8.8.8.8."
    ips = extraer_ips(texto)

    assert "192.168.1.10" in ips
    assert "8.8.8.8" in ips
    assert len(ips) == 2
    print("✅ Prueba superada: IPs válidas detectadas correctamente.")


def test_extraer_ips_rechaza_invalidas():
    texto = "Esto no es una IP: 999.999.999.999"
    ips = extraer_ips(texto)

    assert "999.999.999.999" not in ips
    print("✅ Prueba superada: IP inválida correctamente rechazada.")


def test_extraer_ips_elimina_duplicados():
    texto = "IP repetida: 10.0.0.5 y de nuevo 10.0.0.5"
    ips = extraer_ips(texto)

    assert ips.count("10.0.0.5") == 1
    print("✅ Prueba superada: duplicados eliminados correctamente.")


from darkintel.ioc_detector.detector import extraer_hashes


def test_extraer_hashes_por_tipo():
    texto = """
    MD5: 5d41402abc4b2a76b9719d911017c592
    SHA1: aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
    SHA256: 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
    """

    hashes = extraer_hashes(texto)

    assert "5d41402abc4b2a76b9719d911017c592" in hashes["md5"]
    assert "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d" in hashes["sha1"]
    assert "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae" in hashes["sha256"]

    # Verificamos que no haya "fugas" entre tipos (un MD5 no debe aparecer como SHA1, etc.)
    assert len(hashes["md5"]) == 1
    assert len(hashes["sha1"]) == 1
    assert len(hashes["sha256"]) == 1

    print("✅ Prueba superada: hashes clasificados correctamente por tipo.")


from darkintel.ioc_detector.detector import (
    extraer_emails,
    extraer_dominios,
    extraer_cves,
    detectar_iocs,
)


def test_extraer_emails():
    texto = "Contacto: atacante@malicious-site.com para más información."
    emails = extraer_emails(texto)
    assert "atacante@malicious-site.com" in emails
    print("✅ Prueba superada: email detectado correctamente.")


def test_extraer_cves_normaliza_mayusculas():
    texto = "Vulnerabilidad cve-2023-12345 explotada activamente."
    cves = extraer_cves(texto)
    assert "CVE-2023-12345" in cves
    print("✅ Prueba superada: CVE detectado y normalizado a mayúsculas.")


def test_detectar_iocs_estructura_completa():
    texto = "IP 8.8.8.8, dominio panel-c2.ru, CVE-2023-12345, email x@y.com"
    resultado = detectar_iocs(texto)

    claves_esperadas = {"ips", "dominios", "emails", "cves", "md5", "sha1", "sha256"}
    assert claves_esperadas.issubset(resultado.keys())
    assert "8.8.8.8" in resultado["ips"]
    assert "CVE-2023-12345" in resultado["cves"]
    print("✅ Prueba superada: detectar_iocs devuelve estructura completa.")


if __name__ == "__main__":
    test_extraer_ips_detecta_ips_validas()
    test_extraer_ips_rechaza_invalidas()
    test_extraer_ips_elimina_duplicados()
    test_extraer_hashes_por_tipo()
    test_extraer_emails()
    test_extraer_cves_normaliza_mayusculas()
    test_detectar_iocs_estructura_completa()