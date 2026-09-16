from sentence_transformers import SentenceTransformer

MODELO = "all-MiniLM-L6-v2"

def generar_embeddings(textos: list[str]) -> list:
    """
    Convierte una lista de textos en vectores numéricos.
    Cada vector representa el significado semántico del texto.
    """
    modelo = SentenceTransformer(MODELO)
    embeddings = modelo.encode(textos, show_progress_bar=True)
    return embeddings