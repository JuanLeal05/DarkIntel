"""
NER híbrido: punto único de extracción para el pipeline.

  regex (extractor.py)        -> IoCs atómicos: ip, ipv6, sha256, md5, cve, dominio
  transformer (transformer.py)-> entidades: malware, actor, herramienta, tecnica

El Transformer se puede desactivar con DARKINTEL_NER_TRANSFORMER=0 (por
ejemplo, para comparar "solo regex" contra "híbrido" en las métricas, o para
correr el pipeline en una máquina sin el modelo descargado).

Si está ACTIVADO y el modelo no carga, se lanza el error en vez de seguir
solo con regex: un pipeline que dice usar IA y en silencio no la usa daría
resultados engañosos en la demo y en las métricas.
"""
import os

from darkintel.ner.extractor import extraer_iocs


def transformer_activo() -> bool:
    return os.environ.get("DARKINTEL_NER_TRANSFORMER", "1") != "0"


def extraer(texto: str) -> dict:
    """
    Devuelve:
      {
        "iocs":      {"ip": [...], "ipv6": [...], "sha256": [...], "md5": [...],
                      "cve": [...], "dominio": [...]},
        "entidades": {"malware": [...], "actor": [...],
                      "herramienta": [...], "tecnica": [...]},
      }
    Con el Transformer desactivado, "entidades" trae las categorías vacías.
    """
    resultado = {"iocs": extraer_iocs(texto)}

    if transformer_activo():
        # Import diferido: con el Transformer desactivado no hace falta torch.
        from darkintel.ner.transformer import extraer_entidades
        resultado["entidades"] = extraer_entidades(texto)
    else:
        from darkintel.ner.transformer import CATEGORIAS
        resultado["entidades"] = {categoria: [] for categoria in CATEGORIAS}

    return resultado