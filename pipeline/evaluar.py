"""
Mide DarkIntel contra el dataset anotado de la demo (frente D del plan).

Uso típico:
    # Durante el desarrollo: SOLO el conjunto dev
    python pipeline/evaluar.py

    # Comparar solo regex vs. híbrido (regex + Transformer)
    python pipeline/evaluar.py --modo ambos

    # Acuerdo entre los dos anotadores (antes de crear anotaciones_final)
    python pipeline/evaluar.py --acuerdo anotaciones_A.jsonl anotaciones_B.jsonl

    # Métricas FINALES del paper: una sola vez, al terminar todo
    python pipeline/evaluar.py --split test --final

Reporta precisión, exhaustividad (recall) y F1 por tipo de IoC y de entidad,
la detección de entidades sin importar el tipo, y el tiempo del sistema frente
al tiempo manual registrado en tiempos.csv.
"""
import argparse
import csv
import json
import os
import sys
import time
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from darkintel.evaluacion import (TIPOS_ENTIDAD, TIPOS_IOC, comparar,
                                  validar_anotaciones, validar_posts)

ORDEN_FILAS = ([f"iocs.{t}" for t in TIPOS_IOC] + ["iocs_total"]
               + [f"entidades.{t}" for t in TIPOS_ENTIDAD]
               + ["entidades_total", "entidades_deteccion", "global"])


# ── Predicción del sistema ──────────────────────────────────

def predecir(posts: dict, post_ids: list, modo: str) -> tuple[dict, float]:
    """
    Ejecuta el NER sobre cada post. modo: 'regex' o 'hibrido'.
    Devuelve (predicciones, segundos_totales).
    """
    os.environ["DARKINTEL_NER_TRANSFORMER"] = "1" if modo == "hibrido" else "0"
    from darkintel.ner.hibrido import extraer

    if modo == "hibrido":
        extraer("warm up")   # carga el modelo fuera del cronómetro

    predicciones = {}
    inicio = time.perf_counter()
    for pid in post_ids:
        r = extraer(posts[pid]["text"])
        predicciones[pid] = {
            "iocs": {t: r["iocs"].get(t, []) for t in TIPOS_IOC},
            "entidades": {t: r["entidades"].get(t, []) for t in TIPOS_ENTIDAD},
        }
    return predicciones, time.perf_counter() - inicio


# ── Tiempo manual ───────────────────────────────────────────

def minutos_manuales(ruta: str, split: str) -> list[tuple[str, float]]:
    """[(anotador, minutos)] para el split pedido, desde tiempos.csv."""
    if not os.path.exists(ruta):
        return []
    fmt = "%Y-%m-%d %H:%M"
    salida = []
    with open(ruta, encoding="utf-8") as f:
        for fila in csv.DictReader(f):
            if fila.get("split") != split:
                continue
            try:
                inicio = datetime.strptime(fila["inicio"].strip(), fmt)
                fin = datetime.strptime(fila["fin"].strip(), fmt)
            except (KeyError, ValueError):
                print(f"⚠️  Fila de tiempos.csv ignorada (formato de fecha): {fila}")
                continue
            salida.append((fila.get("anotador", "?"), (fin - inicio).total_seconds() / 60))
    return salida


# ── Presentación ────────────────────────────────────────────

def imprimir_tabla(titulo: str, metricas: dict) -> None:
    print(f"\n{titulo}")
    print(f"  {'tipo':24s} {'P':>6s} {'R':>6s} {'F1':>6s}   {'TP':>4s} {'FP':>4s} {'FN':>4s}")
    for clave in ORDEN_FILAS:
        m = metricas.get(clave)
        if m is None:
            continue
        if clave in ("iocs_total", "entidades_total", "global"):
            print("  " + "-" * 62)
        if m["tp"] + m["fp"] + m["fn"] == 0:
            # Ni en la referencia ni en la predicción: no hay nada que medir.
            print(f"  {clave:24s} {'—':>6s} {'—':>6s} {'—':>6s}   {0:4d} {0:4d} {0:4d}")
            continue
        print(f"  {clave:24s} {m['precision']*100:5.1f}% {m['recall']*100:5.1f}% "
              f"{m['f1']*100:5.1f}%   {m['tp']:4d} {m['fp']:4d} {m['fn']:4d}")


# ── Main ────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dir", default=os.path.join("data", "demo"))
    parser.add_argument("--split", choices=("dev", "test"), default="dev")
    parser.add_argument("--final", action="store_true",
                        help="obligatorio para evaluar el split test")
    parser.add_argument("--referencia", default="anotaciones_final.jsonl")
    parser.add_argument("--modo", choices=("regex", "hibrido", "ambos"), default="ambos")
    parser.add_argument("--acuerdo", nargs=2, metavar=("A", "B"),
                        help="compara dos archivos de anotaciones entre sí")
    parser.add_argument("--salida", help="guardar resultados en este JSON")
    args = parser.parse_args()

    ruta_posts = os.path.join(args.dir, "posts.jsonl")
    if not os.path.exists(ruta_posts):
        print(f"❌ No existe {ruta_posts}.")
        print("   El dataset de la demo todavía no está creado (frente C, docs/guia_anotacion.md).")
        print("   Para probar los scripts usa el ejemplo:  --dir docs/ejemplo_dataset")
        return 1
    errores, _, posts = validar_posts(ruta_posts)
    if errores:
        print("❌ posts.jsonl tiene errores; corre pipeline/validar_anotaciones.py")
        return 1

    # Acuerdo entre anotadores: se usan todos los posts (dev + test)
    if args.acuerdo:
        cargados = []
        for nombre in args.acuerdo:
            errs, anot = validar_anotaciones(os.path.join(args.dir, nombre), posts)
            if errs and errs[0].startswith("No existe"):
                print(f"❌ {errs[0]}. Ese archivo lo crea el anotador al terminar (guía, sección 5).")
                return 1
            if errs:
                print(f"❌ {nombre} tiene errores; corre pipeline/validar_anotaciones.py")
                return 1
            cargados.append(anot)
        metricas = comparar(cargados[0], cargados[1], sorted(posts))
        imprimir_tabla(f"Acuerdo entre anotadores: {args.acuerdo[0]} vs {args.acuerdo[1]} "
                       f"(F1 = acuerdo; 100 % = idénticos)", metricas)
        print("\nRevisen juntos los tipos con F1 bajo: ahí la guía es ambigua.")
        return 0

    if args.split == "test" and not args.final:
        print("⛔ El conjunto test es para las métricas FINALES del paper y se evalúa una")
        print("   sola vez. Durante el desarrollo usa --split dev. Si de verdad es la")
        print("   evaluación final, agrega --final.")
        return 1

    errs, referencia = validar_anotaciones(os.path.join(args.dir, args.referencia), posts)
    if errs:
        print(f"❌ {args.referencia} tiene errores; corre pipeline/validar_anotaciones.py")
        return 1

    post_ids = sorted(pid for pid, p in posts.items() if p["split"] == args.split)
    print(f"📂 {len(post_ids)} posts del split '{args.split}' — referencia: {args.referencia}")

    modos = ("regex", "hibrido") if args.modo == "ambos" else (args.modo,)
    resultados = {}
    for modo in modos:
        pred, segundos = predecir(posts, post_ids, modo)
        metricas = comparar(referencia, pred, post_ids)
        resultados[modo] = {"metricas": metricas, "segundos": round(segundos, 3)}
        imprimir_tabla(f"Modo '{modo}'  ({segundos:.2f} s para {len(post_ids)} posts)", metricas)

    if len(modos) == 2:
        g_r = resultados["regex"]["metricas"]["global"]
        g_h = resultados["hibrido"]["metricas"]["global"]
        print(f"\nAporte del Transformer (global): F1 {g_r['f1']*100:.1f}% → {g_h['f1']*100:.1f}%, "
              f"precisión {g_r['precision']*100:.1f}% → {g_h['precision']*100:.1f}%")

    manuales = minutos_manuales(os.path.join(args.dir, "tiempos.csv"), args.split)
    if manuales:
        promedio = sum(m for _, m in manuales) / len(manuales)
        seg_sistema = resultados[modos[-1]]["segundos"]
        print(f"\nTiempo manual ({args.split}): " +
              ", ".join(f"{a}={m:.0f} min" for a, m in manuales) + f"  → promedio {promedio:.0f} min")
        print(f"Tiempo del sistema ({modos[-1]}): {seg_sistema:.1f} s")
        print("⚠️  Para la métrica del 70 % falta sumar el tiempo de REVISIÓN humana de la")
        print("   salida del sistema (frente D2): reducción = 1 - (sistema + revisión) / manual.")
        resultados["tiempo_manual_min"] = dict(manuales)
    elif args.split == "test":
        print("\n⚠️  No hay tiempos de 'test' en tiempos.csv: falta la línea base manual.")

    if args.salida:
        os.makedirs(os.path.dirname(args.salida) or ".", exist_ok=True)
        with open(args.salida, "w", encoding="utf-8") as f:
            json.dump({"split": args.split, "referencia": args.referencia, **resultados},
                      f, ensure_ascii=False, indent=2)
        print(f"\n💾 Resultados guardados en {args.salida}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
