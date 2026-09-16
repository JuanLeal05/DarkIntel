import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from darkintel.ner.extractor import extraer_iocs
from darkintel.clustering.embedder import generar_embeddings
from darkintel.clustering.cluster import reducir_dimensiones, clustering
from darkintel.stix_builder.builder import construir_bundle
from darkintel.scraper.storage import guardar_json


def cargar_dump(ruta: str) -> list[dict]:
    with open(ruta, encoding="utf-8") as f:
        return json.load(f)


def run():
    ruta_dump = os.path.join(
        os.path.dirname(__file__), "..", "data", "synthetic_darkweb_dump.json"
    )

    posts = cargar_dump(ruta_dump)
    print(f"📂 Cargados {len(posts)} posts\n")

    # 1. Extraer IoCs
    print("🔍 Extrayendo IoCs...")
    iocs_por_post = [extraer_iocs(p["text"]) for p in posts]

    # 2. Clustering
    print("🔢 Generando embeddings...")
    textos = [
        p["text"] + " " + " ".join(
            ioc for tipo in iocs.values() for ioc in tipo
        )
        for p, iocs in zip(posts, iocs_por_post)
    ]
    embeddings = generar_embeddings(textos)
    embeddings_2d = reducir_dimensiones(embeddings)
    labels = clustering(embeddings_2d)

    # 3. Agrupar IoCs por cluster
    print("📦 Construyendo bundles STIX por campaña...\n")
    iocs_por_cluster = {}
    for iocs, label in zip(iocs_por_post, labels):
        label = int(label)
        if label not in iocs_por_cluster:
            iocs_por_cluster[label] = {
                "ip": [], "ipv6": [], "sha256": [],
                "md5": [], "cve": [], "dominio": []
            }
        for tipo, valores in iocs.items():
            iocs_por_cluster[label][tipo].extend(valores)

    # Eliminar duplicados
    for label in iocs_por_cluster:
        for tipo in iocs_por_cluster[label]:
            iocs_por_cluster[label][tipo] = list(
                set(iocs_por_cluster[label][tipo])
            )

    # 4. Construir bundles STIX
    bundles = {}
    for cluster_id, iocs in sorted(iocs_por_cluster.items()):
        bundle = construir_bundle(iocs, cluster_id)
        bundle_dict = json.loads(bundle.serialize())
        bundles[f"cluster_{cluster_id}"] = bundle_dict

        n_objetos = len(bundle_dict.get("objects", []))
        nombre = f"Cluster {cluster_id}" if cluster_id >= 0 else "Ruido"
        print(f"  {nombre}: {n_objetos} objetos STIX")

    # 5. Guardar resultado
    ruta = guardar_json(bundles, carpeta="data/output",
                        nombre_archivo="stix_bundles.json")
    print(f"\n✅ Bundles STIX guardados en: {ruta}")


if __name__ == "__main__":
    run()