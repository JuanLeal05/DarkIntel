import umap
import hdbscan
import numpy as np


def reducir_dimensiones(embeddings) -> np.ndarray:
    """
    Reduce embeddings de alta dimensión a 2D con UMAP.
    Preserva estructura local y global de los datos.
    """
    reducer = umap.UMAP(
        n_components=2,
        random_state=42,
        min_dist=0.1,
        n_neighbors=3
    )
    return reducer.fit_transform(embeddings)


def clustering(embeddings_2d: np.ndarray) -> np.ndarray:
    """
    Agrupa los puntos en clusters con HDBSCAN.
    -1 significa ruido (post que no pertenece a ningún cluster).
    """
    clusterer = hdbscan.HDBSCAN(
        min_cluster_size=2,
        min_samples=1
    )
    return clusterer.fit_predict(embeddings_2d)