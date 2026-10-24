from functools import lru_cache

MODELO = "all-MiniLM-L6-v2"


@lru_cache(maxsize=1)
def _modelo():
    """
    Carga el modelo de embeddings UNA vez por proceso (antes se cargaba en
    cada llamada). Import diferido: los tests y el resto del proyecto no
    necesitan sentence-transformers instalado.
    """
    from sentence_transformers import SentenceTransformer
    return SentenceTransformer(MODELO)


def generar_embeddings(textos: list[str], mostrar_progreso: bool = True):
    """
    Convierte una lista de textos en vectores numéricos.
    Cada vector representa el significado semántico del texto.
    """
    return _modelo().encode(textos, show_progress_bar=mostrar_progreso)
