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


# ── Clustering híbrido: significado + infraestructura ────────

def test_infraestructura_incluye_dominio_base_y_excluye_cve():
    s = cl.infraestructura({"ip": ["198.51.100.23"], "dominio": ["ransom.darkpay.onion"],
                            "cve": ["CVE-2024-1234"], "md5": ["5d41402abc4b2a76b9719d911017c592"]})
    assert "ip:198.51.100.23" in s
    assert "dominio:ransom.darkpay.onion" in s and "dominio:darkpay.onion" in s
    assert not any(x.startswith("cve:") for x in s)   # un CVE lo explotan muchos actores


def test_compartir_infraestructura_acerca_a_los_posts():
    X = np.random.default_rng(0).normal(size=(3, 384))
    infra = [{"ip:a"}, {"ip:a"}, {"ip:b"}]
    D = cl.matriz_distancias(X, infra, alfa=0.5)
    sin = cl.matriz_distancias(X, [set()] * 3, alfa=0.5)
    assert D[0, 1] < sin[0, 1]          # comparten C2 => más cerca
    assert D[0, 2] > sin[0, 2] - 1e-9   # no comparten => no se acercan


def test_sin_infraestructura_la_distancia_es_la_semantica():
    X = np.random.default_rng(1).normal(size=(4, 384))
    D = cl.matriz_distancias(X, [set()] * 4, alfa=0.3)
    Xn = X / np.linalg.norm(X, axis=1, keepdims=True)
    esperada = np.clip(1 - Xn @ Xn.T, 0, 1)
    np.fill_diagonal(esperada, 0)
    assert np.allclose(D, esperada)


def test_post_que_suena_distinto_pero_comparte_c2_va_a_su_campana():
    # El caso real de post_002 del dataset sintético: su texto se parecía a
    # otra campaña, pero compartía la IP de C2 con la suya.
    rng = np.random.default_rng(3)
    a, b = rng.normal(size=384), rng.normal(size=384)
    X = np.array([a + rng.normal(scale=.3, size=384) for _ in range(3)]
                 + [b + rng.normal(scale=.3, size=384) for _ in range(3)]
                 + [b + rng.normal(scale=.3, size=384)])          # "suena" a B
    infra = [{"ip:c2a"}, {"ip:c2a"}, {"ip:c2a"},
             {"ip:c2b"}, {"ip:c2b"}, {"ip:c2b"},
             {"ip:c2a"}]                                           # ...pero usa el C2 de A
    etiquetas = cl.agrupar(X, infra, modo="hibrido")
    assert etiquetas[6] == etiquetas[0] != -1
    assert etiquetas[3] == etiquetas[4] == etiquetas[5] != etiquetas[0]


def test_muestra_grande_hibrido_al_menos_tan_bueno_como_semantico():
    from sklearn.metrics import adjusted_rand_score
    X, y = _campanas()
    infra = [{f"ip:c{c}"} if c >= 0 and i % 2 == 0 else set() for i, c in enumerate(y)]
    hib = adjusted_rand_score(y, cl.agrupar(X, infra, modo="hibrido"))
    sem = adjusted_rand_score(y, cl.agrupar(X, infra, modo="semantico"))
    assert hib >= sem - 0.05


def test_modo_desconocido_da_error():
    with pytest.raises(ValueError, match="modo"):
        cl.agrupar(np.zeros((4, 8)) + np.eye(4, 8), [set()] * 4, modo="magia")


def test_infraestructura_compartida_explica_cada_campana():
    infra = [{"ip:a", "dominio:x.onion"}, {"ip:a"}, {"ip:b"}, {"ip:b"}, {"ip:z"}]
    r = cl.infraestructura_compartida(infra, [0, 0, 1, 1, -1])
    assert r == {0: ["ip:a"], 1: ["ip:b"]}
