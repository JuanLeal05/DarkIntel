import sys
import os
import matplotlib.pyplot as plt

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from darkintel.ner.extractor import extraer_iocs
from darkintel.clustering.embedder import generar_embeddings
from darkintel.clustering.cluster import reducir_dimensiones, clustering
from darkintel.data_loader import cargar_posts

# UMAP no funciona con muy pocas muestras: con 2 posts lanza "zero-size array
# to reduction operation maximum" y con 3 un TypeError de scipy.linalg.eigh.
# Medido empíricamente: 4 es el mínimo con el que corre limpio.
MINIMO_POSTS_CLUSTERING = 4


def run():
    posts, es_sintetico = cargar_posts()
    fuente = "synthetic_darkweb_dump.json" if es_sintetico else "data/raw (scraper real)"
    print(f"📂 Cargados {len(posts)} posts — fuente: {fuente}\n")

    if len(posts) < MINIMO_POSTS_CLUSTERING:
        print(f"⚠️  Hacen falta al menos {MINIMO_POSTS_CLUSTERING} posts para "
              f"agrupar y solo hay {len(posts)}.")
        print("    UMAP falla por debajo de ese umbral (con 2 posts lanza "
              "'zero-size array'; con 3, un error de scipy.linalg).")
        print("    Scrapea más páginas y vuelve a correr.")
        return

    # Extraer IoCs de cada post y combinarlos con el texto
    textos = []
    for post in posts:
        iocs = extraer_iocs(post["text"])
        iocs_str = " ".join(
            ioc
            for tipo in iocs.values()
            for ioc in tipo
        )
        textos.append(post["text"] + " " + iocs_str)

    # Generar embeddings
    print("🔢 Generando embeddings...")
    embeddings = generar_embeddings(textos)

    # Reducir dimensiones
    print("📉 Reduciendo dimensiones con UMAP...")
    embeddings_2d = reducir_dimensiones(embeddings)

    # Clustering
    print("🔍 Agrupando con HDBSCAN...")
    labels = clustering(embeddings_2d)

    # Mostrar resultados
    print("\n=== RESULTADO DEL CLUSTERING ===\n")
    clusters_encontrados = set(labels)
    for cluster_id in sorted(clusters_encontrados):
        nombre = f"Cluster {cluster_id}" if cluster_id != -1 else "Ruido"
        posts_cluster = [
            posts[i]["post_id"]
            for i, l in enumerate(labels)
            if l == cluster_id
        ]
        print(f"  {nombre}: {posts_cluster}")

    # Scatter plot
    print("\n📊 Generando scatter plot...")
    colores = ["red" if l == -1 else f"C{l}" for l in labels]
    plt.figure(figsize=(8, 6))
    plt.scatter(
        embeddings_2d[:, 0],
        embeddings_2d[:, 1],
        c=labels,
        cmap="tab10",
        s=100
    )
    for i, post in enumerate(posts):
        plt.annotate(
            post["post_id"],
            (embeddings_2d[i, 0], embeddings_2d[i, 1]),
            fontsize=8,
            ha="right"
        )
    plt.title("Clusters de campañas — DarkIntel")
    plt.savefig("clusters.png")
    print("✅ Scatter plot guardado en clusters.png")


if __name__ == "__main__":
    run()