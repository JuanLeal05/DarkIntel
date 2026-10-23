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


# ── Clustering híbrido: significado + infraestructura compartida ────────
#
# Un analista de CTI agrupa dos posts en la misma campaña porque comparten
# INFRAESTRUCTURA (el mismo C2, el mismo hash, el mismo dominio de pago),
# aunque estén escritos de forma distinta. Los embeddings solo miden cómo
# "suena" el texto. Se combinan las dos señales:
#
#     distancia = alfa * d_semantica + (1 - alfa) * d_infraestructura
#
# - d_semantica: distancia coseno entre embeddings, en [0, 1].
# - d_infraestructura: 1 - |A ∩ B| / min(|A|, |B|) sobre IPs, dominios y
#   hashes. Basta UN indicador compartido para acercar mucho dos posts.
# - Si alguno de los dos posts no tiene infraestructura, no hay evidencia:
#   se usa solo la distancia semántica.
# - Los CVE NO cuentan como infraestructura: muchos actores explotan el mismo
#   CVE; una IP de C2 o un hash de un binario, no.
#
# HDBSCAN agrupa directamente sobre esa matriz de distancias (sin UMAP).
# Simulación con 4 campañas de 9 posts + 9 de ruido (ARI, 1 = perfecto):
#   - posts que "suenan" a otra campaña:  semántico 0.46 -> híbrido 0.90
#   - sin ninguna infraestructura:        semántico 0.73 -> híbrido 0.96

TIPOS_INFRAESTRUCTURA = ("ip", "ipv6", "dominio", "md5", "sha1", "sha256")
ALFA_POR_DEFECTO = 0.5


def infraestructura(iocs: dict) -> set:
    """
    IoCs de un post que identifican infraestructura (con su tipo como prefijo).
    Los subdominios aportan también su dominio base: "ransom.darkpay.onion" y
    "pay.darkpay.onion" son la misma infraestructura ("darkpay.onion").
    """
    salida = set()
    for tipo in TIPOS_INFRAESTRUCTURA:
        for valor in iocs.get(tipo, []):
            valor = valor.lower()
            salida.add(f"{tipo}:{valor}")
            if tipo == "dominio" and valor.count(".") >= 2:
                salida.add("dominio:" + ".".join(valor.split(".")[-2:]))
    return salida


def matriz_distancias(embeddings, infra: list, alfa: float = ALFA_POR_DEFECTO) -> np.ndarray:
    X = np.asarray(embeddings, dtype=np.float64)
    X = X / np.clip(np.linalg.norm(X, axis=1, keepdims=True), 1e-12, None)
    d_sem = np.clip(1.0 - X @ X.T, 0.0, 1.0)

    d_inf = d_sem.copy()          # sin evidencia de infraestructura => neutra
    n = len(X)
    for i in range(n):
        for j in range(i + 1, n):
            if infra[i] and infra[j]:
                comunes = len(infra[i] & infra[j])
                d_inf[i, j] = d_inf[j, i] = 1.0 - comunes / min(len(infra[i]), len(infra[j]))

    D = alfa * d_sem + (1.0 - alfa) * d_inf
    np.fill_diagonal(D, 0.0)
    return D


def agrupar(embeddings, infra: list = None, modo: str = "hibrido",
            alfa: float = ALFA_POR_DEFECTO) -> np.ndarray:
    """
    Etiquetas de campaña por post (-1 = ruido).

    modo="hibrido"   : significado + infraestructura compartida (por defecto)
    modo="semantico" : solo embeddings con UMAP + HDBSCAN (método anterior,
                       se conserva para comparar en la evaluación)
    """
    embeddings = np.asarray(embeddings)
    n = len(embeddings)
    if n < MINIMO_POSTS:
        raise ValueError(f"Hacen falta al menos {MINIMO_POSTS} posts para agrupar (hay {n}).")
    if modo == "semantico":
        return clustering(reducir_dimensiones(embeddings))
    if modo != "hibrido":
        raise ValueError(f"modo de clustering desconocido: {modo!r}")

    D = matriz_distancias(embeddings, infra or [set()] * n, alfa)
    # Nota: allow_single_cluster=True NO se usa: en las pruebas fusionaba
    # campañas distintas en una sola. El precio es que, si TODOS los posts
    # son de una misma campaña, HDBSCAN los marca como ruido.
    return hdbscan.HDBSCAN(
        metric="precomputed",
        min_cluster_size=2 if n < UMBRAL_MUESTRA_GRANDE else 3,
        min_samples=1,
    ).fit_predict(D)


def infraestructura_compartida(infra: list, etiquetas) -> dict:
    """{campaña: [indicadores que aparecen en 2+ posts de esa campaña]} (explicabilidad)."""
    salida = {}
    for c in sorted(set(int(e) for e in etiquetas) - {-1}):
        cuenta = {}
        for s, e in zip(infra, etiquetas):
            if int(e) == c:
                for x in s:
                    cuenta[x] = cuenta.get(x, 0) + 1
        salida[c] = sorted(x for x, k in cuenta.items() if k >= 2)
    return salida


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
