"""
NER con Transformer: entidades SEMÁNTICAS que la regex no puede ver.

Modelo por defecto: CyberPeace-Institute/SecureBERT-NER
  - RoBERTa (SecureBERT) ajustado para NER sobre el corpus APTNER.
  - Licencia MIT, público (no requiere solicitar acceso).
  - Máximo 512 tokens por pasada: los textos largos se procesan en
    ventanas solapadas (parámetro `stride` del pipeline).

División de trabajo en el NER híbrido (ver ner/hibrido.py):
  - La REGEX (extractor.py) sigue siendo la fuente de verdad para los IoCs
    atómicos: IP, hash, CVE, dominio. Son patrones con forma fija, la regex
    los valida (rangos privados, defanging, hashes vacíos...) y es exacta.
  - El TRANSFORMER aporta solo lo que la regex no puede: malware, actores,
    herramientas y técnicas. Las etiquetas atómicas que también predice el
    modelo (IP, DOM, MD5...) se ignoran a propósito.

Para cambiar de modelo (p. ej. un DarkBERT ajustado para NER) basta con la
variable de entorno DARKINTEL_NER_MODEL, siempre que use etiquetas
compatibles con MAPEO_ETIQUETAS o se amplíe ese mapeo.
"""
import os
import re
from functools import lru_cache

# ── Configuración ───────────────────────────────────────────

MODELO_NER = os.environ.get("DARKINTEL_NER_MODEL", "CyberPeace-Institute/SecureBERT-NER")
# Commit fijo del modelo: reproducibilidad y protección de la cadena de
# suministro (si alguien cambia el modelo en HuggingFace, no nos afecta).
REVISION_NER = os.environ.get("DARKINTEL_NER_REVISION", "7f935a4f7db13697580c881e381bb2636dfa779a")

# Confianza mínima para aceptar una entidad. Se calibra con el dataset de la
# demo (frente D): subirlo gana precisión y pierde exhaustividad.
UMBRAL_CONFIANZA = float(os.environ.get("DARKINTEL_NER_UMBRAL", "0.80"))

# Tope de texto por post. El costo crece lineal con la longitud y en CPU
# cada ventana de 512 tokens toma tiempo; un post real rara vez pasa de esto.
MAX_CARACTERES = 50_000

# Solapamiento entre ventanas de 512 tokens: evita cortar una entidad justo
# en el borde de una ventana.
STRIDE_TOKENS = 128

# Etiquetas de APTNER -> categoría de DarkIntel.
# APTNER: MAL=malware, APT=grupo/actor, TOOL=herramienta, ACT=técnica/acción.
MAPEO_ETIQUETAS = {
    "MAL": "malware",
    "APT": "actor",
    "TOOL": "herramienta",
    "ACT": "tecnica",
}
CATEGORIAS = tuple(dict.fromkeys(MAPEO_ETIQUETAS.values()))

# Etiquetas que el modelo predice pero se ignoran: o las cubre la regex con
# validación (IP, DOM, URL, hashes, EMAIL, VULID) o no se usan todavía en el
# grafo STIX (TIME, LOC, OS, PROT, ENCR, FILE, IDTY, SECTEAM, VULNAME).

_SOLO_PUNTUACION = re.compile(r"^[\W_]+$")
_ESPACIOS = re.compile(r"\s+")


# ── Carga del modelo ────────────────────────────────────────

@lru_cache(maxsize=1)
def _cargar_pipeline():
    """
    Carga el modelo UNA vez por proceso. Import diferido: así el resto del
    proyecto (y los tests) no necesitan transformers/torch instalados.
    """
    from transformers import pipeline

    return pipeline(
        "token-classification",
        model=MODELO_NER,
        revision=REVISION_NER,
        # "first": une los sub-tokens de una palabra y usa la etiqueta del
        # primero. Evita fragmentos tipo "Lock" + "Bit".
        aggregation_strategy="first",
        stride=STRIDE_TOKENS,
        device=-1,  # CPU
    )


# ── Normalización ───────────────────────────────────────────

def _limpiar(palabra: str) -> str:
    """Quita espacios sobrantes y puntuación de los bordes (', ', '.', '"')."""
    palabra = _ESPACIOS.sub(" ", palabra).strip()
    return palabra.strip(" .,;:!?\"'()[]{}<>")


def _es_entidad_valida(nombre: str) -> bool:
    if len(nombre) < 2:
        return False
    if nombre.isdigit() or _SOLO_PUNTUACION.match(nombre):
        return False
    return True


def _etiqueta_base(grupo: str) -> str:
    """'B-MAL' / 'I-MAL' / 'MAL' -> 'MAL'. (El modelo trae 'PROT' sin prefijo.)"""
    return grupo.split("-", 1)[-1] if grupo[:2] in ("B-", "I-") else grupo


# ── API pública ─────────────────────────────────────────────

def entidades_crudas(texto: str) -> list[dict]:
    """
    Predicciones del modelo sin filtrar (útil para depurar y calibrar el
    umbral). Cada item: {"etiqueta", "texto", "confianza", "inicio", "fin"}.
    """
    if not texto or not texto.strip():
        return []
    texto = texto[:MAX_CARACTERES]
    predicciones = _cargar_pipeline()(texto)
    return [
        {
            "etiqueta": _etiqueta_base(p["entity_group"]),
            "texto": p["word"],
            "confianza": float(p["score"]),
            "inicio": p.get("start"),
            "fin": p.get("end"),
        }
        for p in predicciones
    ]


def extraer_entidades(texto: str, umbral: float = None) -> dict[str, list[str]]:
    """
    Extrae entidades semánticas de un texto.

    Devuelve siempre todas las categorías, p. ej.:
      {"malware": ["LockBit 3.0"], "actor": ["FIN7"],
       "herramienta": ["Cobalt Strike"], "tecnica": []}

    - Solo entidades con confianza >= umbral.
    - Deduplicadas sin distinguir mayúsculas (se conserva la primera forma).
    """
    umbral = UMBRAL_CONFIANZA if umbral is None else umbral
    resultado = {categoria: [] for categoria in CATEGORIAS}
    vistos = {categoria: set() for categoria in CATEGORIAS}

    for entidad in entidades_crudas(texto):
        categoria = MAPEO_ETIQUETAS.get(entidad["etiqueta"])
        if categoria is None or entidad["confianza"] < umbral:
            continue
        nombre = _limpiar(entidad["texto"])
        if not _es_entidad_valida(nombre):
            continue
        clave = nombre.lower()
        if clave not in vistos[categoria]:
            vistos[categoria].add(clave)
            resultado[categoria].append(nombre)

    return resultado


if __name__ == "__main__":
    # Prueba manual con el modelo real:
    #   python src/darkintel/ner/transformer.py "LockBit 3.0 affiliates use Cobalt Strike"
    import sys

    texto = " ".join(sys.argv[1:]) or (
        "LockBit 3.0 affiliates are using Cobalt Strike beacons and Mimikatz "
        "to dump credentials. The intrusion was attributed to FIN7, who "
        "gained initial access via spear-phishing."
    )
    print(f"Modelo: {MODELO_NER} @ {REVISION_NER[:8]}\nTexto: {texto}\n")
    print("── Predicciones crudas ──")
    for e in entidades_crudas(texto):
        print(f"  {e['etiqueta']:8s} {e['confianza']:.3f}  {e['texto']!r}")
    print(f"\n── Resultado (umbral {UMBRAL_CONFIANZA}) ──")
    for categoria, nombres in extraer_entidades(texto).items():
        print(f"  {categoria:12s} {nombres}")