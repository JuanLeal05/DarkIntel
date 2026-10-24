"""
Compara modelos NER sobre la partición de PRUEBA de CyberNER.

Mide a nivel de entidad (inicio, fin y tipo deben coincidir) en las 4
categorías de DarkIntel, en total y por fuente. Así se ve si el ajuste fino
mejoró de verdad frente al modelo original.

Uso:
    python entrenamiento/evaluar_ner.py --modelos base modelos/darkintel-ner-v1

"base" = SecureBERT-NER original (el que usa DarkIntel por defecto).
Recordatorio: test no contiene frases de APTNER (ver preparar_cyberner.py).
"""
import argparse
import json
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(__file__))
from metricas import TIPOS, evaluar  # noqa: E402

BASE = ("CyberPeace-Institute/SecureBERT-NER", "7f935a4f7db13697580c881e381bb2636dfa779a")
MAX_TOKENS = 512


def etiqueta_darkintel(etiqueta: str) -> str:
    """'B-MAL' -> 'B-MAL'; 'I-PROT' / 'PROT' / 'B-LOC' -> 'O'. Funciona con las
    40 etiquetas de SecureBERT-NER y con las 9 del modelo ajustado."""
    if "-" in etiqueta:
        prefijo, tipo = etiqueta.split("-", 1)
    else:
        prefijo, tipo = "I", etiqueta
    return f"{prefijo}-{tipo}" if tipo in TIPOS and prefijo in ("B", "I") else "O"


def predecir(nombre: str, frases: list[dict], lote: int = 16) -> list[list[str]]:
    import torch
    from transformers import AutoModelForTokenClassification, AutoTokenizer

    if nombre == "base":
        ruta, revision = BASE
    else:
        ruta, revision = nombre, None
    tokenizer = AutoTokenizer.from_pretrained(ruta, revision=revision, add_prefix_space=True)
    modelo = AutoModelForTokenClassification.from_pretrained(ruta, revision=revision)
    dispositivo = "cuda" if torch.cuda.is_available() else "cpu"
    modelo.to(dispositivo).eval()
    id2label = modelo.config.id2label

    salida = []
    for i in range(0, len(frases), lote):
        grupo = frases[i:i + lote]
        enc = tokenizer([f["tokens"] for f in grupo], is_split_into_words=True,
                        truncation=True, max_length=MAX_TOKENS, padding=True,
                        return_tensors="pt")
        with torch.no_grad():
            ids = modelo(**{k: v.to(dispositivo) for k, v in enc.items()}).logits.argmax(-1).cpu()
        for j, fr in enumerate(grupo):
            etiquetas = ["O"] * len(fr["tokens"])   # palabras truncadas => O
            anterior = None
            for pos, palabra in enumerate(enc.word_ids(j)):
                if palabra is not None and palabra != anterior:
                    etiquetas[palabra] = etiqueta_darkintel(id2label[int(ids[j, pos])])
                anterior = palabra
            salida.append(etiquetas)
    return salida


def imprimir(titulo: str, m: dict) -> None:
    print(f"\n{titulo}")
    print(f"  {'tipo':14s} {'P':>6s} {'R':>6s} {'F1':>6s}   {'TP':>5s} {'FP':>5s} {'FN':>5s}")
    for clave in ("malware", "herramienta", "actor", "tecnica", "total", "deteccion"):
        v = m[clave]
        if clave == "total":
            print("  " + "-" * 56)
        print(f"  {clave:14s} {v['precision']*100:5.1f}% {v['recall']*100:5.1f}% {v['f1']*100:5.1f}%"
              f"   {v['tp']:5d} {v['fp']:5d} {v['fn']:5d}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--modelos", nargs="+", default=["base"],
                        help="'base' y/o carpetas de modelos ajustados")
    parser.add_argument("--datos", default=os.path.join("data", "cyberner"))
    parser.add_argument("--split", choices=("dev", "test"), default="test")
    parser.add_argument("--salida", default=os.path.join("modelos", "evaluacion_cyberner.json"))
    args = parser.parse_args()

    ruta = os.path.join(args.datos, f"{args.split}.jsonl")
    if not os.path.exists(ruta):
        print(f"❌ Falta {ruta}: ejecuta antes preparar_cyberner.py")
        return 1
    with open(ruta, encoding="utf-8") as f:
        frases = [json.loads(linea) for linea in f if linea.strip()]
    print(f"📂 {len(frases)} frases de {args.split} (CyberNER sin APTNER)")

    resultados = {}
    for nombre in args.modelos:
        print(f"\n🔎 Evaluando {nombre}...")
        preds = predecir(nombre, frases)
        refs = [f["etiquetas"] for f in frases]
        total = evaluar(refs, preds)
        por_fuente = defaultdict(lambda: ([], []))
        for fr, r, p in zip(frases, refs, preds):
            por_fuente[fr["fuente"]][0].append(r)
            por_fuente[fr["fuente"]][1].append(p)
        resultados[nombre] = {
            "total": total,
            "por_fuente": {fu: evaluar(r, p) for fu, (r, p) in sorted(por_fuente.items())},
        }
        imprimir(f"Modelo: {nombre}", total)
        for fuente, m in resultados[nombre]["por_fuente"].items():
            print(f"    {fuente:9s} F1 total {m['total']['f1']*100:5.1f}%   "
                  f"detección {m['deteccion']['f1']*100:5.1f}%")

    if len(args.modelos) > 1:
        print("\nResumen (F1 a nivel de entidad)")
        print(f"  {'modelo':34s} {'total':>7s} {'detección':>10s}  " +
              " ".join(f"{t:>11s}" for t in ("malware", "herramienta", "actor", "tecnica")))
        for nombre, r in resultados.items():
            t = r["total"]
            print(f"  {nombre[-34:]:34s} {t['total']['f1']*100:6.1f}% {t['deteccion']['f1']*100:9.1f}%  " +
                  " ".join(f"{t[c]['f1']*100:10.1f}%" for c in ("malware", "herramienta", "actor", "tecnica")))

    os.makedirs(os.path.dirname(args.salida) or ".", exist_ok=True)
    with open(args.salida, "w", encoding="utf-8") as f:
        json.dump({"split": args.split, "resultados": resultados}, f, ensure_ascii=False, indent=2)
    print(f"\n💾 {args.salida}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
