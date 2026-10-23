"""
Agrupamiento no supervisado de posts en campañas: UMAP + HDBSCAN.

UMAP reduce los embeddings (384 dimensiones) a pocas dimensiones
conservando qué posts están cerca de cuáles; HDBSCAN busca zonas densas
sin que haya que decirle cuántas campañas hay, y marca como ruido (-1) lo
que no encaja en ninguna.

Dos regímenes, según cuántos posts haya:

  - Pocos posts (< UMBRAL_MUESTRA_GRANDE): parámetros originales del
    proyecto, ya validados con el modelo real sobre las páginas de prueba
    del .onion y el dataset sintético (agrupan las campañas correctamente).
  - Muestra grande (>= UMBRAL_MUESTRA_GRANDE, p. ej. el dataset de la demo):
    configuración recomendada en la literatura para embeddings de texto
    (5 dimensiones, min_dist=0, distancia coseno). En una simulación con
    4 campañas de 9 posts + 9 de ruido, los parámetros originales partían
    las 4 campañas en 11-17 clústeres; estos encuentran 4-5.

La proyección 2D para el gráfico es independiente del espacio donde se
agrupa: agrupar directamente en 2D pierde información.
"""
import hdbscan
import numpy as np
import umap

UMBRAL_MUESTRA_GRANDE = 15
# UMAP necesita al menos 3 muestras (con 2 falla internamente); con 3 hay que
# usar inicialización aleatoria porque la espectral falla con "k >= N".
MINIMO_POSTS = 3
SEMILLA = 42


def _n_vecinos(n: int) -> int:
    """Tamaño de vecindario de UMAP: ~raíz de n, entre 3 y n-1."""
    return max(2, min(n - 1, max(3, round(n ** 0.5))))


def _parametros(n: int) -> dict:
    # Con 3 posts la inicialización espectral falla; desde 4 se conserva la
    # original (es la que se validó con las 4 páginas del .onion de prueba).
    inicio = "spectral" if n >= 4 else "random"
    if n < UMBRAL_MUESTRA_GRANDE:
        return {"n_components": 2, "min_dist": 0.1, "n_neighbors": min(3, n - 1),
                "init": inicio, "metric": "euclidean"}
    return {"n_components": 5, "min_dist": 0.0, "n_neighbors": _n_vecinos(n),
            "init": inicio, "metric": "cosine"}


def reducir_dimensiones(embeddings, n_components: int = None) -> np.ndarray:
    """
    Reduce los embeddings para AGRUPAR. Con n_components se fuerza la
    dimensión (p. ej. 2 para el gráfico).
    """
    embeddings = np.asarray(embeddings)
    n = len(embeddings)
    if n < MINIMO_POSTS:
        raise ValueError(f"Hacen falta al menos {MINIMO_POSTS} posts para agrupar (hay {n}).")
    params = _parametros(n)
    if n_components is not None:
        params["n_components"] = n_components
    return umap.UMAP(random_state=SEMILLA, **params).fit_transform(embeddings)


def proyeccion_2d(embeddings) -> np.ndarray:
    """Proyección 2D solo para visualizar (clusters.png)."""
    embeddings = np.asarray(embeddings)
    n = len(embeddings)
    params = _parametros(n)
    params.update(n_components=2, min_dist=0.1)
    return umap.UMAP(random_state=SEMILLA, **params).fit_transform(embeddings)


def clustering(embeddings_reducidos: np.ndarray) -> np.ndarray:
    """
    Agrupa los puntos con HDBSCAN. -1 = ruido (post sin campaña).
    Con muestras grandes se exige un mínimo de 3 posts por campaña: con 2,
    cualquier par de posts parecidos se convierte en "campaña".
    """
    n = len(embeddings_reducidos)
    clusterer = hdbscan.HDBSCAN(
        min_cluster_size=2 if n < UMBRAL_MUESTRA_GRANDE else 3,
        min_samples=1,
    )
    return clusterer.fit_predict(embeddings_reducidos)
