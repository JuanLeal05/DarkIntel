"""
Valida el dataset de la demo antes de usarlo (docs/guia_anotacion.md).

Uso:
    python pipeline/validar_anotaciones.py                 # todo data/demo
    python pipeline/validar_anotaciones.py --dir otra/carpeta

Revisa posts.jsonl, campanas.json y cada anotaciones_*.jsonl: formato JSON,
claves obligatorias y reglas de normalización (hashes en minúsculas, CVE en
mayúsculas, dominios sin ofuscación, sin IPs privadas, etc.).
Sale con código 1 si hay errores.
"""
import argparse
import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from darkintel.evaluacion import validar_anotaciones, validar_campanas, validar_posts

MAX_ERRORES_MOSTRADOS = 40


def _reportar(titulo: str, errores: list[str]) -> bool:
    if not errores:
        print(f"✅ {titulo}")
        return True
    print(f"❌ {titulo}: {len(errores)} error(es)")
    for e in errores[:MAX_ERRORES_MOSTRADOS]:
        print(f"   - {e}")
    if len(errores) > MAX_ERRORES_MOSTRADOS:
        print(f"   ... y {len(errores) - MAX_ERRORES_MOSTRADOS} más")
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dir", default=os.path.join("data", "demo"),
                        help="carpeta del dataset (por defecto data/demo)")
    args = parser.parse_args()

    ruta_posts = os.path.join(args.dir, "posts.jsonl")
    if not os.path.exists(ruta_posts):
        print(f"❌ No existe {ruta_posts}")
        return 1

    todo_ok = True
    errores, avisos, posts = validar_posts(ruta_posts)
    todo_ok &= _reportar(f"posts.jsonl ({len(posts)} posts)", errores)
    for a in avisos:
        print(f"   ⚠️  {a}")

    ruta_campanas = os.path.join(args.dir, "campanas.json")
    if os.path.exists(ruta_campanas):
        todo_ok &= _reportar("campanas.json", validar_campanas(ruta_campanas, posts))
    else:
        print("⚠️  campanas.json todavía no existe")

    archivos = sorted(glob.glob(os.path.join(args.dir, "anotaciones_*.jsonl")))
    if not archivos:
        print("⚠️  No hay archivos anotaciones_*.jsonl todavía")
    for ruta in archivos:
        errores, anotaciones = validar_anotaciones(ruta, posts)
        todo_ok &= _reportar(f"{os.path.basename(ruta)} ({len(anotaciones)} posts)", errores)

    return 0 if todo_ok else 1


if __name__ == "__main__":
    sys.exit(main())
