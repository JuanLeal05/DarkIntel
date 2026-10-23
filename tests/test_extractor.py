import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from darkintel.ner.extractor import extraer_iocs


# ── Tests originales ─────────────────────────────────────────

def test_detecta_ip():
    texto = "C2 corriendo en 198.51.100.42:4444"
    resultado = extraer_iocs(texto)
    assert "198.51.100.42" in resultado["ip"]
    print("✅ test_detecta_ip superado")


def test_detecta_sha256():
    texto = "hash SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b856"
    resultado = extraer_iocs(texto)
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b856" in resultado["sha256"]
    print("✅ test_detecta_sha256 superado")


def test_detecta_cve():
    texto = "Exploiting CVE-2024-1234 on unpatched systems"
    resultado = extraer_iocs(texto)
    assert "CVE-2024-1234" in resultado["cve"]
    print("✅ test_detecta_cve superado")


def test_detecta_dominio_onion():
    texto = "Payment via ransom.darkpay.onion for decryption"
    resultado = extraer_iocs(texto)
    assert "ransom.darkpay.onion" in resultado["dominio"]
    print("✅ test_detecta_dominio_onion superado")


def test_sin_falsos_positivos_en_texto_limpio():
    texto = "El clima hoy está soleado y tranquilo"
    resultado = extraer_iocs(texto)
    assert resultado["ip"] == []
    assert resultado["cve"] == []
    print("✅ test_sin_falsos_positivos superado")


# ── Tests de validación IP ───────────────────────────────────

def test_no_detecta_version_como_ip():
    texto = "Apache versión 2.4.51.3 tiene vulnerabilidad"
    resultado = extraer_iocs(texto)
    assert "2.4.51.3" not in resultado["ip"]
    print("✅ test_no_detecta_version_como_ip superado")


def test_no_detecta_ip_privada():
    texto = "servidor interno en 192.168.1.1 y loopback 127.0.0.1"
    resultado = extraer_iocs(texto)
    assert "192.168.1.1" not in resultado["ip"]
    assert "127.0.0.1" not in resultado["ip"]
    print("✅ test_no_detecta_ip_privada superado")


def test_no_detecta_octetos_imposibles():
    texto = "dirección inválida 999.999.999.999"
    resultado = extraer_iocs(texto)
    assert "999.999.999.999" not in resultado["ip"]
    print("✅ test_no_detecta_octetos_imposibles superado")


def test_detecta_ip_en_json():
    texto = '{"src":"198.51.100.42","dst":"203.0.113.5","port":443}'
    resultado = extraer_iocs(texto)
    assert "198.51.100.42" in resultado["ip"]
    assert "203.0.113.5" in resultado["ip"]
    print("✅ test_detecta_ip_en_json superado")


def test_detecta_ip_en_comando():
    texto = "nmap -sV 198.51.100.42 -p 1-65535"
    resultado = extraer_iocs(texto)
    assert "198.51.100.42" in resultado["ip"]
    print("✅ test_detecta_ip_en_comando superado")


def test_detecta_ip_en_markdown():
    texto = "`198.51.100.42:8080` es el panel de control"
    resultado = extraer_iocs(texto)
    assert "198.51.100.42" in resultado["ip"]
    print("✅ test_detecta_ip_en_markdown superado")


# ── Tests de defanging ───────────────────────────────────────

def test_detecta_ip_defangeada_corchetes():
    texto = "C2: 198[.]51[.]100[.]42 activa"
    resultado = extraer_iocs(texto)
    assert "198.51.100.42" in resultado["ip"]
    print("✅ test_detecta_ip_defangeada_corchetes superado")


def test_detecta_ip_defangeada_espacios():
    texto = "ip: 198 . 51 . 100 . 42 reportada"
    resultado = extraer_iocs(texto)
    assert "198.51.100.42" in resultado["ip"]
    print("✅ test_detecta_ip_defangeada_espacios superado")


def test_detecta_dominio_defangeado():
    texto = "conectar a evil-site[.]onion para el panel"
    resultado = extraer_iocs(texto)
    assert "evil-site.onion" in resultado["dominio"]
    print("✅ test_detecta_dominio_defangeado superado")


def test_detecta_url_hxxp():
    texto = "payload en hxxp://evil[.]com/payload.exe"
    resultado = extraer_iocs(texto)
    assert "evil.com" in resultado["dominio"]
    print("✅ test_detecta_url_hxxp superado")


# ── Tests de hashes ──────────────────────────────────────────

def test_sha256_en_lista():
    texto = "- a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a\n- e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b856"
    resultado = extraer_iocs(texto)
    assert "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a" in resultado["sha256"]
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b856" in resultado["sha256"]
    print("✅ test_sha256_en_lista superado")


def test_sha256_partido_en_dos_lineas():
    texto = "sha256: e3b0c44298fc1c149afbf4c8996fb924\n27ae41e4649b934ca495991b7852b856"
    resultado = extraer_iocs(texto)
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b856" in resultado["sha256"]
    print("✅ test_sha256_partido_en_dos_lineas superado")


def test_sha256_en_codigo_python():
    texto = "if sha256 == 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a':"
    resultado = extraer_iocs(texto)
    assert "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a" in resultado["sha256"]
    print("✅ test_sha256_en_codigo_python superado")


def test_sha256_normalizado_a_minusculas():
    texto = "PAYLOAD: A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A"
    resultado = extraer_iocs(texto)
    assert "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a" in resultado["sha256"]
    print("✅ test_sha256_normalizado_a_minusculas superado")


def test_no_detecta_sha256_vacio():
    texto = "sha256 vacío: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    resultado = extraer_iocs(texto)
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" not in resultado["sha256"]
    print("✅ test_no_detecta_sha256_vacio superado")


def test_no_detecta_md5_vacio():
    texto = "md5 de archivo vacío: d41d8cd98f00b204e9800998ecf8427e"
    resultado = extraer_iocs(texto)
    assert "d41d8cd98f00b204e9800998ecf8427e" not in resultado["md5"]
    print("✅ test_no_detecta_md5_vacio superado")


def test_md5_en_dump_credenciales():
    texto = "john,doe,5f4dcc3b5aa765d61d8327deb882cf99,admin@corp.com"
    resultado = extraer_iocs(texto)
    assert "5f4dcc3b5aa765d61d8327deb882cf99" in resultado["md5"]
    print("✅ test_md5_en_dump_credenciales superado")


def test_md5_con_asteriscos_foro():
    texto = "**5f4dcc3b5aa765d61d8327deb882cf99** <- loader hash confirmado"
    resultado = extraer_iocs(texto)
    assert "5f4dcc3b5aa765d61d8327deb882cf99" in resultado["md5"]
    print("✅ test_md5_con_asteriscos_foro superado")


# ── Tests de CVE ─────────────────────────────────────────────

def test_dos_md5_en_lineas_consecutivas_no_se_fusionan():
    texto = "5f4dcc3b5aa765d61d8327deb882cf99\n098f6bcd4621d373cade4e832627b4f6"
    resultado = extraer_iocs(texto)
    assert "5f4dcc3b5aa765d61d8327deb882cf99" in resultado["md5"]
    assert "098f6bcd4621d373cade4e832627b4f6" in resultado["md5"]
    assert resultado["sha256"] == []


def test_md5_consecutivos_con_fin_de_linea_windows():
    texto = "5f4dcc3b5aa765d61d8327deb882cf99\r\n098f6bcd4621d373cade4e832627b4f6"
    resultado = extraer_iocs(texto)
    assert len(resultado["md5"]) == 2
    assert resultado["sha256"] == []


def test_lista_de_tres_md5_no_se_fusiona():
    texto = ("hashes del loader:\n"
             "5f4dcc3b5aa765d61d8327deb882cf99\n"
             "098f6bcd4621d373cade4e832627b4f6\n"
             "5d41402abc4b2a76b9719d911017c592")
    resultado = extraer_iocs(texto)
    assert len(resultado["md5"]) == 3
    assert resultado["sha256"] == []


def test_sha256_partido_asimetrico_se_une_sin_palabra_clave():
    # 40 + 24 = 64: no puede ser un par de MD5, así que es un SHA256 partido
    texto = "hash: a7ffc6f8bf1ed76651c14756a061d662f580ff4d\ne43b49fa82d80a4b80f8434a"
    resultado = extraer_iocs(texto)
    assert "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a" in resultado["sha256"]

def test_cve_se_normaliza_a_mayusculas():
    texto = "vulnerabilidad cve-2024-1234 explotada activamente"
    resultado = extraer_iocs(texto)
    assert "CVE-2024-1234" in resultado["cve"]
    print("✅ test_cve_normalizado superado")


def test_multiples_cves_en_una_linea():
    texto = "chain: CVE-2024-1234,CVE-2023-9999,CVE-2022-1111"
    resultado = extraer_iocs(texto)
    assert "CVE-2024-1234" in resultado["cve"]
    assert "CVE-2023-9999" in resultado["cve"]
    assert "CVE-2022-1111" in resultado["cve"]
    print("✅ test_multiples_cves_en_una_linea superado")


def test_cve_8_digitos():
    texto = "CVE-2024-12345678 afecta millones de dispositivos"
    resultado = extraer_iocs(texto)
    assert "CVE-2024-12345678" in resultado["cve"]
    print("✅ test_cve_8_digitos superado")


def test_no_detecta_cve_año_futuro():
    texto = "CVE-2099-0001 no existe aún"
    resultado = extraer_iocs(texto)
    assert "CVE-2099-0001" not in resultado["cve"]
    print("✅ test_no_detecta_cve_año_futuro superado")


def test_cve_entre_parentesis():
    texto = "PoC for (CVE-2024-1234) published today"
    resultado = extraer_iocs(texto)
    assert "CVE-2024-1234" in resultado["cve"]
    print("✅ test_cve_entre_parentesis superado")


# ── Tests de dominios ────────────────────────────────────────

def test_no_detecta_dominio_benigno():
    texto = "descargado desde google.com y microsoft.com"
    resultado = extraer_iocs(texto)
    assert "google.com" not in resultado["dominio"]
    assert "microsoft.com" not in resultado["dominio"]
    print("✅ test_no_detecta_dominio_benigno superado")


def test_no_detecta_version_como_dominio():
    texto = "usando librería version 2.0.net instalada"
    resultado = extraer_iocs(texto)
    assert "2.0.net" not in resultado["dominio"]
    print("✅ test_no_detecta_version_como_dominio superado")


def test_no_detecta_email_como_dominio():
    texto = "contacto en hacker@protonmail.com para deals"
    resultado = extraer_iocs(texto)
    assert "protonmail.com" not in resultado["dominio"]
    print("✅ test_no_detecta_email_como_dominio superado")


def test_detecta_dominio_tld_cc():
    texto = "C2 activo en malware-host.cc respondiendo"
    resultado = extraer_iocs(texto)
    assert "malware-host.cc" in resultado["dominio"]
    print("✅ test_detecta_dominio_tld_cc superado")


def test_detecta_subdominio_onion():
    texto = "panel en forum.zqktlwi4fecvo6ri.onion activo"
    resultado = extraer_iocs(texto)
    assert "forum.zqktlwi4fecvo6ri.onion" in resultado["dominio"]
    print("✅ test_detecta_subdominio_onion superado")


def test_detecta_dominio_con_guiones():
    texto = "market en dark--market--v3.onion disponible"
    resultado = extraer_iocs(texto)
    assert "dark--market--v3.onion" in resultado["dominio"]
    print("✅ test_detecta_dominio_con_guiones superado")


# ── Tests de IPv6 ────────────────────────────────────────────

def test_detecta_ipv6_completo():
    texto = "C2 en 2001:0db8:85a3:0000:0000:8a2e:0370:7334 activo"
    resultado = extraer_iocs(texto)
    assert any("2001" in ip for ip in resultado["ipv6"])
    print("✅ test_detecta_ipv6_completo superado")


def test_no_detecta_ipv6_loopback():
    texto = "loopback ::1 no es un IoC"
    resultado = extraer_iocs(texto)
    assert "::1" not in resultado["ipv6"]
    print("✅ test_no_detecta_ipv6_loopback superado")


def test_no_redos_en_texto_largo():
    import time
    t = time.time()
    extraer_iocs("a." * 50000 + "!")
    assert time.time() - t < 2


# ── Tests de ofuscación avanzada ─────────────────────────────

def test_zero_width_characters_ignorados():
    # Hash con zero-width space invisible en medio
    texto = "hash: a7ffc6f8bf1ed76651c14756a061d662\u200bf580ff4de43b49fa82d80a4b80f8434a"
    resultado = extraer_iocs(texto)
    assert "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a" in resultado["sha256"]
    print("✅ test_zero_width_characters_ignorados superado")


if __name__ == "__main__":
    # Originales
    test_detecta_ip()
    test_detecta_sha256()
    test_detecta_cve()
    test_detecta_dominio_onion()
    test_sin_falsos_positivos_en_texto_limpio()

    # IP
    test_no_detecta_version_como_ip()
    test_no_detecta_ip_privada()
    test_no_detecta_octetos_imposibles()
    test_detecta_ip_en_json()
    test_detecta_ip_en_comando()
    test_detecta_ip_en_markdown()

    # Defanging
    test_detecta_ip_defangeada_corchetes()
    test_detecta_ip_defangeada_espacios()
    test_detecta_dominio_defangeado()
    test_detecta_url_hxxp()

    # Hashes
    test_sha256_en_lista()
    test_sha256_partido_en_dos_lineas()
    test_sha256_en_codigo_python()
    test_sha256_normalizado_a_minusculas()
    test_no_detecta_sha256_vacio()
    test_no_detecta_md5_vacio()
    test_md5_en_dump_credenciales()
    test_md5_con_asteriscos_foro()

    # CVE
    test_cve_se_normaliza_a_mayusculas()
    test_multiples_cves_en_una_linea()
    test_cve_8_digitos()
    test_no_detecta_cve_año_futuro()
    test_cve_entre_parentesis()

    # Dominios
    test_no_detecta_dominio_benigno()
    test_no_detecta_version_como_dominio()
    test_no_detecta_email_como_dominio()
    test_detecta_dominio_tld_cc()
    test_detecta_subdominio_onion()
    test_detecta_dominio_con_guiones()

    # IPv6
    test_detecta_ipv6_completo()
    test_no_detecta_ipv6_loopback()

    # Ofuscación
    test_zero_width_characters_ignorados()

    print("\n✅ Todos los tests superados")