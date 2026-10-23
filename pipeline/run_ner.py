import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from darkintel.ner.hibrido import conocimiento_activo, extraer, transformer_activo
from darkintel.data_loader import cargar_posts


def describir_ner() -> str:
    partes = ["regex"]
    if transformer_activo():
        partes.append("Transformer")
    if conocimiento_activo():
        partes.append("base de conocimiento")
    return " + ".join(partes)


def evaluar_post(detectado: dict, esperado: dict) -> dict:
    """
    Compara lo detectado contra labels_manual.
    Une sha256 + md5 en un solo conjunto antes de comparar.
    """
    # Unir sha256 y md5 en un solo conjunto de hashes detectados
    hashes_detectados = set(
        h.lower() for h in
        detectado.get("sha256", []) + detectado.get("md5", [])
    )
    hashes_esperados = set(
        h.lower() for h in esperado.get("hashes", [])
    )

    ips_detectadas = set(d.lower() for d in detectado.get("ip", []))
    ips_esperadas  = set(e.lower() for e in esperado.get("ips", []))

    cves_detectados = set(d.lower() for d in detectado.get("cve", []))
    cves_esperados  = set(e.lower() for e in esperado.get("cves", []))

    dominios_detectados = set(d.lower() for d in detectado.get("dominio", []))
    dominios_esperados  = set(e.lower() for e in esperado.get("dominios", []))

    tp, fp, fn = 0, 0, 0
    for det, esp in [
        (hashes_detectados,  hashes_esperados),
        (ips_detectadas,     ips_esperadas),
        (cves_detectados,    cves_esperados),
        (dominios_detectados,dominios_esperados),
    ]:
        tp += len(det & esp)
        fp += len(det - esp)
        fn += len(esp - det)

    return {"tp": tp, "fp": fp, "fn": fn}


def calcular_metricas(tp: int, fp: int, fn: int) -> dict:
    """Calcula precision, recall y F1."""
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0)
    return {
        "precision": round(precision, 3),
        "recall":    round(recall, 3),
        "f1":        round(f1, 3),
    }


def run():
    posts, es_sintetico = cargar_posts()
    fuente = "synthetic_darkweb_dump.json" if es_sintetico else "data/raw (scraper real)"
    print(f"📂 Cargados {len(posts)} posts — fuente: {fuente}")
    print(f"🧠 NER: {describir_ner()}\n")

    tp_total, fp_total, fn_total = 0, 0, 0

    for post in posts:
        resultado = extraer(post["text"])
        iocs = resultado["iocs"]
        print(f"[{post['post_id']}]")
        print(f"  IoCs:      { {k: v for k, v in iocs.items() if v} }")
        print(f"  Entidades: { {k: v for k, v in resultado['entidades'].items() if v} }")

        if post.get("labels_manual") is not None:
            metricas = evaluar_post(iocs, post["labels_manual"])
            tp_total += metricas["tp"]
            fp_total += metricas["fp"]
            fn_total += metricas["fn"]
            print(f"  Esperado:  {post['labels_manual']}")
            print(f"  TP={metricas['tp']} FP={metricas['fp']} FN={metricas['fn']}")
        else:
            # Post real sin ground truth (viene del scraper, no del dataset
            # etiquetado): se reporta lo detectado, no se puede medir
            # precisión/recall porque no hay con qué comparar.
            print("  (sin labels_manual — post real, no se calculan métricas)")
        print()

    if es_sintetico:
        metricas_finales = calcular_metricas(tp_total, fp_total, fn_total)
        print("=" * 50)
        print("RESULTADO FINAL (dataset sintético)")
        print("=" * 50)
        print(f"  Precision : {metricas_finales['precision'] * 100:.1f}%")
        print(f"  Recall    : {metricas_finales['recall']    * 100:.1f}%")
        print(f"  F1-score  : {metricas_finales['f1']        * 100:.1f}%")
        print(f"  TP={tp_total} FP={fp_total} FN={fn_total}")
    else:
        print("=" * 50)
        print("Datos reales: no hay ground truth para calcular métricas.")
        print("Para medir precisión/recall, usa el dataset sintético")
        print("(borra o mueve data/raw/*.json y vuelve a correr).")
        print("=" * 50)


if __name__ == "__main__":
    run()
