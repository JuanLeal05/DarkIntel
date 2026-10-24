"""
NER híbrido: punto único de extracción para el pipeline.

  regex        (extractor.py)    -> IoCs atómicos: ip, ipv6, sha256, md5, cve, dominio
  transformer  (transformer.py)  -> entidades: malware, actor, herramienta, tecnica
  conocimiento (conocimiento.py) -> corrige tipos, resuelve alias, limpia nombres
                                    y detecta nombres conocidos que el modelo no vio

Cada capa se activa por separado, para poder medir cuánto aporta cada una
(pipeline/evaluar.py --modo todos):

  DARKINTEL_NER_TRANSFORMER=0|1   (por defecto 1)
  DARKINTEL_NER_KB=0|1            (por defecto 1)

Si el Transformer está ACTIVADO y el modelo no carga, se lanza el error en
vez de seguir solo con regex: un pipeline que dice usar IA y en silencio no
la usa daría resultados engañosos en la demo y en las métricas.
"""
import os

from darkintel.ner import conocimiento
from darkintel.ner.extractor import extraer_iocs

CATEGORIAS_ENTIDAD = ("malware", "herramienta", "actor", "tecnica")


def transformer_activo() -> bool:
    return os.environ.get("DARKINTEL_NER_TRANSFORMER", "1") != "0"


def conocimiento_activo() -> bool:
    return os.environ.get("DARKINTEL_NER_KB", "1") != "0"


def extraer(texto: str) -> dict:
    """
    Devuelve:
      {
        "iocs":      {"ip": [...], "ipv6": [...], "sha256": [...], "md5": [...],
                      "cve": [...], "dominio": [...]},
        "entidades": {"malware": [...], "herramienta": [...],
                      "actor": [...], "tecnica": [...]},
      }
    """
    resultado = {"iocs": extraer_iocs(texto)}
    entidades = {c: [] for c in CATEGORIAS_ENTIDAD}

    if transformer_activo():
        # Import diferido: con el Transformer desactivado no hace falta torch.
        from darkintel.ner.transformer import extraer_entidades
        for categoria, nombres in extraer_entidades(texto).items():
            entidades.setdefault(categoria, []).extend(nombres)

    if conocimiento_activo():
        entidades = conocimiento.fusionar(
            conocimiento.corregir(entidades),
            conocimiento.detectar_en_texto(texto),
        )

    resultado["entidades"] = {c: entidades.get(c, []) for c in CATEGORIAS_ENTIDAD}
    return resultado
