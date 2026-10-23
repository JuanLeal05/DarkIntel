import os
import sys

import numpy as np
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

pytest.importorskip("umap")
pytest.importorskip("hdbscan")

from darkintel.clustering import cluster as cl


def _campanas(semilla=0, n_campanas=4, por_campana=9, n_ruido=9, dispersion=1.1):
    """Embeddings simulados: campañas = nubes alrededor de un centro; ruido = al azar."""
    rng = np.random.default_rng(semilla)
    centros = rng.normal(size=(n_campanas, 384))
    X, y = [], []
    for c in range(n_campanas):
        for _ in range(por_campana):
            X.append(centros[c] + rng.normal(scale=dispersion, size=384))
            y.append(c)
    for _ in range(n_ruido):
        X.append(rng.normal(size=384))
        y.append(-1)
    return np.array(X), np.array(y)


def test_pocos_posts_conserva_los_parametros_validados():
    # Son los parámetros con los que se validaron las 4 páginas del .onion
    p = cl._parametros(4)
    assert p == {"n_components": 2, "min_dist": 0.1, "n_neighbors": 3,
                 "init": "spectral", "metric": "euclidean"}


def test_muestra_grande_usa_la_configuracion_recomendada():
    p = cl._parametros(45)
    assert p["n_components"] == 5 and p["min_dist"] == 0.0 and p["metric"] == "cosine"
    assert 3 <= p["n_neighbors"] <= 10


def test_con_dos_posts_da_un_error_claro():
    with pytest.raises(ValueError, match="al menos 3"):
        cl.reducir_dimensiones(np.random.default_rng(0).normal(size=(2, 384)))


def test_con_tres_posts_ya_no_falla():
    # Antes el mínimo era 4: con 3, UMAP fallaba (inicialización espectral)
    X = np.random.default_rng(0).normal(size=(3, 384))
    etiquetas = cl.clustering(cl.reducir_dimensiones(X))
    assert len(etiquetas) == 3


def test_muestra_grande_recupera_las_campanas():
    from sklearn.metrics import adjusted_rand_score
    X, y = _campanas()
    etiquetas = cl.clustering(cl.reducir_dimensiones(X))
    n_campanas = len(set(etiquetas) - {-1})
    assert 3 <= n_campanas <= 6, n_campanas            # antes: 11-17 fragmentos
    assert adjusted_rand_score(y, etiquetas) >= 0.5


def test_proyeccion_2d_para_el_grafico():
    X, _ = _campanas()
    assert cl.proyeccion_2d(X).shape == (len(X), 2)
