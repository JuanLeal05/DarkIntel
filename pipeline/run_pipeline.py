"""
Pipeline completo de DarkIntel en UN solo proceso (frente E1).

    [1/4] Carga y validación de posts (data/raw o dataset sintético)
    [2/4] NER híbrido: regex + Transformer + base de conocimiento
    [3/4] Campañas: embeddings + UMAP + HDBSCAN
    [4/4] STIX 2.1: un bundle por campaña

Antes, run_ner.py, run_clustering.py y run_stix.py se ejecutaban por
separado: el modelo NER se cargaba tres veces y los embeddings y el
clustering se calculaban dos veces (con riesgo de que el gráfico y los
bundles no coincidieran). Aquí todo se calcula una vez.

Salidas en data/output/:
    stix_bundles.json   bundles STIX 2.1 que sirve la API
    analisis.json       por post: campaña, IoCs y entidades
    clusters.png        gráfico de las campañas

Uso:
    python pipeline/run_pipeline.py
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))

from darkintel.data_loader import cargar_posts
from darkintel.ner.hibrido import (CATEGORIAS_ENTIDAD, conocimiento_activo, extraer,
                                   transformer_activo)
from darkintel.scraper.storage import guardar_json
from run_ner import calcular_metricas, evaluar_post

CARPETA_SALIDA = os.path.join("data", "output")


def _fase(numero: int, titulo: str) -> float:
    print(f"\n{'═' * 64}\n[{numero}/4] {titulo}\n{'═' * 64}")
    return time.perf_counter()


def _fin(inicio: float) -> float:
    segundos = time.perf_counter() - inicio
    print(f"   ⏱  {segundos:.2f} s")
    return segundos


def _unicos(valores):
    return list(dict.fromkeys(valores))


def _texto_para_embedding(post: dict, resultado: dict) -> str:
    """Texto + señales extraídas: posts que comparten C2 o malware quedan más cerca."""
    senales = " ".join(
        valor
        for grupo in ("iocs", "entidades")
        for valores in resultado[grupo].values()
        for valor in valores
    )
    return post["text"] + " " + senales


def _guardar_grafico(proyeccion, labels, posts, ruta: str) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.figure(figsize=(9, 7))
    for cluster_id in sorted(set(labels)):
        idx = [i for i, l in enumerate(labels) if l == cluster_id]
        etiqueta = "Ruido" if cluster_id == -1 else f"Campaña {cluster_id}"
        plt.scatter(proyeccion[idx, 0], proyeccion[idx, 1], s=110, label=etiqueta,
                    marker="x" if cluster_id == -1 else "o",
                    color="grey" if cluster_id == -1 else None)
    for i, post in enumerate(posts):
        plt.annotate(post["post_id"][-12:], (proyeccion[i, 0], proyeccion[i, 1]),
                     fontsize=7, ha="right", va="bottom")
    plt.title("DarkIntel — campañas detectadas (UMAP + HDBSCAN)")
    plt.legend(loc="best", fontsize=8)
    plt.tight_layout()
    plt.savefig(ruta, dpi=120)
    plt.close()


def run() -> int:
    tiempos = {}

    # ── 1. Carga ────────────────────────────────────────────
    t = _fase(1, "Carga de posts")
    posts, es_sintetico = cargar_posts()
    fuente = "dataset sintético" if es_sintetico else "data/raw (recolectado por el scraper vía Tor)"
    print(f"📂 {len(posts)} posts — fuente: {fuente}")
    tiempos["carga"] = _fin(t)

    from darkintel.clustering.cluster import MINIMO_POSTS
    if len(posts) < MINIMO_POSTS:
        print(f"⚠️  Hacen falta al menos {MINIMO_POSTS} posts para agrupar campañas "
              f"(hay {len(posts)}). Recolecta más páginas y vuelve a ejecutar.")
        return 1

    # ── 2. NER ──────────────────────────────────────────────
    capas = ["regex"] + (["Transformer"] if transformer_activo() else []) \
        + (["base de conocimiento"] if conocimiento_activo() else [])
    t = _fase(2, f"NER híbrido: {' + '.join(capas)}")
    resultados = [extraer(p["text"]) for p in posts]
    tp = fp = fn = 0
    for post, r in zip(posts, resultados):
        iocs = {k: v for k, v in r["iocs"].items() if v}
        entidades = {k: v for k, v in r["entidades"].items() if v}
        print(f"\n  [{post['post_id']}]")
        print(f"    IoCs:      {iocs or '—'}")
        print(f"    Entidades: {entidades or '—'}")
        if post.get("labels_manual") is not None:
            m = evaluar_post(r["iocs"], post["labels_manual"])
            tp, fp, fn = tp + m["tp"], fp + m["fp"], fn + m["fn"]
    if es_sintetico:
        m = calcular_metricas(tp, fp, fn)
        print(f"\n  IoCs vs labels_manual (sintético): P={m['precision']*100:.1f}% "
              f"R={m['recall']*100:.1f}% F1={m['f1']*100:.1f}%")
    total_iocs = sum(len(v) for r in resultados for v in r["iocs"].values())
    total_ent = sum(len(v) for r in resultados for v in r["entidades"].values())
    print(f"\n  Total: {total_iocs} IoCs y {total_ent} entidades")
    tiempos["ner"] = _fin(t)

    # ── 3. Campañas ─────────────────────────────────────────
    t = _fase(3, "Campañas: embeddings + UMAP + HDBSCAN")
    from darkintel.clustering.cluster import clustering, proyeccion_2d, reducir_dimensiones
    from darkintel.clustering.embedder import generar_embeddings

    embeddings = generar_embeddings(
        [_texto_para_embedding(p, r) for p, r in zip(posts, resultados)],
        mostrar_progreso=False)
    labels = [int(l) for l in clustering(reducir_dimensiones(embeddings))]
    for cluster_id in sorted(set(labels)):
        nombre = "Ruido" if cluster_id == -1 else f"Campaña {cluster_id}"
        miembros = [posts[i]["post_id"] for i, l in enumerate(labels) if l == cluster_id]
        print(f"  {nombre}: {miembros}")

    os.makedirs(CARPETA_SALIDA, exist_ok=True)
    ruta_png = os.path.join(CARPETA_SALIDA, "clusters.png")
    _guardar_grafico(proyeccion_2d(embeddings), labels, posts, ruta_png)
    print(f"  📊 Gráfico: {ruta_png}")
    tiempos["campanas"] = _fin(t)

    # ── 4. STIX ─────────────────────────────────────────────
    t = _fase(4, "STIX 2.1: un bundle por campaña")
    from darkintel.stix_builder.builder import construir_bundle

    por_cluster = {}
    for post, r, label in zip(posts, resultados, labels):
        c = por_cluster.setdefault(label, {"iocs": {}, "entidades": {k: [] for k in CATEGORIAS_ENTIDAD},
                                           "fechas": []})
        for tipo, valores in r["iocs"].items():
            c["iocs"][tipo] = _unicos(c["iocs"].get(tipo, []) + valores)
        for tipo, valores in r["entidades"].items():
            c["entidades"][tipo] = _unicos(c["entidades"].get(tipo, []) + valores)
        if post.get("timestamp"):
            c["fechas"].append(post["timestamp"])

    bundles = {}
    for cluster_id, c in sorted(por_cluster.items()):
        fechas = sorted(c["fechas"])
        bundle = construir_bundle(c["iocs"], cluster_id, entidades=c["entidades"],
                                  primera_vista=fechas[0] if fechas else None,
                                  ultima_vista=fechas[-1] if fechas else None)
        bundles[f"cluster_{cluster_id}"] = json.loads(bundle.serialize())
        tipos = {}
        for obj in bundles[f"cluster_{cluster_id}"].get("objects", []):
            tipos[obj["type"]] = tipos.get(obj["type"], 0) + 1
        nombre = "Ruido" if cluster_id == -1 else f"Campaña {cluster_id}"
        resumen = ", ".join(f"{n} {t}" for t, n in sorted(tipos.items())
                            if t not in ("identity", "marking-definition"))
        print(f"  {nombre}: {resumen or 'sin objetos'}")

    guardar_json(bundles, carpeta=CARPETA_SALIDA, nombre_archivo="stix_bundles.json")
    guardar_json(
        [{"post_id": p["post_id"], "url": p.get("url"), "timestamp": p.get("timestamp"),
          "campana": l, "iocs": r["iocs"], "entidades": r["entidades"]}
         for p, r, l in zip(posts, resultados, labels)],
        carpeta=CARPETA_SALIDA, nombre_archivo="analisis.json")
    print(f"  💾 {os.path.join(CARPETA_SALIDA, 'stix_bundles.json')} y analisis.json")
    tiempos["stix"] = _fin(t)

    total = sum(tiempos.values())
    print(f"\n✅ Pipeline completado en {total:.1f} s "
          f"(NER {tiempos['ner']:.1f} s · campañas {tiempos['campanas']:.1f} s · "
          f"STIX {tiempos['stix']:.1f} s)")
    return 0


if __name__ == "__main__":
    sys.exit(run())
