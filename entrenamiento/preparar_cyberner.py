"""
Prepara el corpus CyberNER para ajustar (fine-tuning) el NER de DarkIntel.

Entrada:  el CSV del repositorio de CyberNER
          (dataset/cyberner_combined_stix.csv: Word, Tag, Sentence_ID, STIX_Tag, Source)
Salida:   data/cyberner/{train,dev,test}.jsonl + resumen.json

Decisiones:

1. Solo se conservan los 4 tipos que usa DarkIntel; el resto pasa a "O":
       Malware                      -> MAL   (malware)
       Tool                         -> TOOL  (herramienta)
       Threat-Actor, Intrusion-Set  -> APT   (actor)
       Attack-Pattern               -> ACT   (tecnica)
   Los nombres MAL/TOOL/APT/ACT son los de APTNER, los mismos que ya entiende
   src/darkintel/ner/transformer.py: el modelo ajustado se usa sin cambiar
   ese mapeo.

2. Las frases se identifican por (Source, Sentence_ID): el Sentence_ID se
   repite entre fuentes.

3. APTNER va ENTERO a entrenamiento y NUNCA a dev/test: el modelo de partida
   (SecureBERT-NER) ya se entrenó con APTNER, así que medirlo sobre esas
   frases lo favorecería injustamente. dev/test salen de CyNER, DNRTI y
   Attacker (10 % / 10 % de cada fuente, el resto a entrenamiento).

4. División reproducible: semilla fija (42).

5. Los textos largos (algunos "Sentence_ID" son documentos enteros, de hasta
   ~5.800 palabras) se parten en fragmentos de <= 128 palabras, cortando
   siempre fuera de una entidad. El modelo lee como mucho 512 sub-tokens: sin
   esto, el final de esos textos se perdería al entrenar y al medir. Todos los
   fragmentos de un mismo texto van al mismo conjunto (train, dev o test).

Uso:
    python entrenamiento/preparar_cyberner.py ruta/a/cyberner_combined_stix.csv
"""
import argparse
import csv
import json
import os
import random
from collections import Counter

MAPEO = {
    "Malware": "MAL",
    "Tool": "TOOL",
    "Threat-Actor": "APT",
    "Intrusion-Set": "APT",
    "Attack-Pattern": "ACT",
}
FUENTE_SOLO_TRAIN = "APTNER"
SEMILLA = 42
MAX_PALABRAS = 128


def mapear_etiqueta(stix_tag: str) -> str:
    if stix_tag == "O" or "-" not in stix_tag:
        return "O"
    prefijo, tipo = stix_tag.split("-", 1)
    nuevo = MAPEO.get(tipo)
    return f"{prefijo}-{nuevo}" if nuevo and prefijo in ("B", "I") else "O"


def corregir_bio(etiquetas: list[str]) -> list[str]:
    """Tras mapear, un I-X puede quedar sin B-X (p. ej. B-Software I-Tool): se repara."""
    salida, anterior = [], "O"
    for et in etiquetas:
        if et.startswith("I-") and anterior[2:] != et[2:]:
            et = "B-" + et[2:]
        salida.append(et)
        anterior = et
    return salida


def fragmentar(frase: dict, maximo: int = MAX_PALABRAS) -> list[dict]:
    """Parte una frase larga en trozos de <= maximo palabras sin cortar entidades."""
    tokens, etiquetas = frase["tokens"], frase["etiquetas"]
    if len(tokens) <= maximo:
        return [frase]
    trozos, inicio = [], 0
    while inicio < len(tokens):
        fin = min(inicio + maximo, len(tokens))
        # Retroceder si el corte cae dentro de una entidad (la siguiente es I-)
        while fin < len(tokens) and fin > inicio + 1 and etiquetas[fin].startswith("I-"):
            fin -= 1
        trozos.append({**frase, "id": f"{frase['id']}#{len(trozos)}",
                       "tokens": tokens[inicio:fin], "etiquetas": etiquetas[inicio:fin]})
        inicio = fin
    return trozos


def leer_frases(ruta_csv: str) -> list[dict]:
    frases, actual, clave_actual = [], None, None
    with open(ruta_csv, newline="", encoding="utf-8") as f:
        for fila in csv.DictReader(f):
            clave = (fila["Source"], fila["Sentence_ID"])
            if clave != clave_actual:
                if actual and actual["tokens"]:
                    frases.append(actual)
                actual = {"fuente": fila["Source"], "id": f"{fila['Source']}-{fila['Sentence_ID']}",
                          "tokens": [], "etiquetas": []}
                clave_actual = clave
            palabra = fila["Word"].strip()
            if not palabra:
                continue
            actual["tokens"].append(palabra)
            actual["etiquetas"].append(mapear_etiqueta(fila["STIX_Tag"]))
    if actual and actual["tokens"]:
        frases.append(actual)
    for fr in frases:
        fr["etiquetas"] = corregir_bio(fr["etiquetas"])
    return frases


def dividir(frases: list[dict], frac_dev: float = 0.10, frac_test: float = 0.10):
    rng = random.Random(SEMILLA)
    train, dev, test = [], [], []
    for fuente in sorted({f["fuente"] for f in frases}):
        del_origen = [f for f in frases if f["fuente"] == fuente]
        if fuente == FUENTE_SOLO_TRAIN:
            train.extend(del_origen)
            continue
        rng.shuffle(del_origen)
        n_test = round(len(del_origen) * frac_test)
        n_dev = round(len(del_origen) * frac_dev)
        test.extend(del_origen[:n_test])
        dev.extend(del_origen[n_test:n_test + n_dev])
        train.extend(del_origen[n_test + n_dev:])
    return train, dev, test


def _entidades(frases: list[dict]) -> dict:
    c = Counter(et[2:] for f in frases for et in f["etiquetas"] if et.startswith("B-"))
    return {t: c.get(t, 0) for t in ("MAL", "TOOL", "APT", "ACT")}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("csv", help="ruta a cyberner_combined_stix.csv")
    parser.add_argument("--salida", default=os.path.join("data", "cyberner"))
    args = parser.parse_args()

    if not os.path.exists(args.csv):
        print(f"❌ No existe {args.csv}")
        return 1

    frases = leer_frases(args.csv)
    ids = [f["id"] for f in frases]
    if len(ids) != len(set(ids)):
        repetidas = [k for k, v in Counter(ids).items() if v > 1][:5]
        print(f"⚠️  Hay frases con el mismo (fuente, id) no contiguas: {repetidas}...")

    train, dev, test = dividir(frases)
    # Fragmentar DESPUÉS de dividir: los trozos de un mismo texto no se reparten
    train, dev, test = ([t for f in c for t in fragmentar(f)] for c in (train, dev, test))
    os.makedirs(args.salida, exist_ok=True)
    for nombre, conjunto in (("train", train), ("dev", dev), ("test", test)):
        with open(os.path.join(args.salida, f"{nombre}.jsonl"), "w", encoding="utf-8") as f:
            for fr in conjunto:
                f.write(json.dumps(fr, ensure_ascii=False) + "\n")

    resumen = {
        "fuente_csv": os.path.basename(args.csv),
        "semilla": SEMILLA,
        "mapeo": MAPEO,
        "solo_entrenamiento": FUENTE_SOLO_TRAIN,
        "max_palabras_por_fragmento": MAX_PALABRAS,
        "conjuntos": {
            nombre: {"frases": len(c), "por_fuente": dict(Counter(f["fuente"] for f in c)),
                     "entidades": _entidades(c)}
            for nombre, c in (("train", train), ("dev", dev), ("test", test))
        },
    }
    with open(os.path.join(args.salida, "resumen.json"), "w", encoding="utf-8") as f:
        json.dump(resumen, f, ensure_ascii=False, indent=2)

    print(f"✅ {len(frases)} frases → {args.salida}")
    for nombre, info in resumen["conjuntos"].items():
        print(f"   {nombre:5s} {info['frases']:6d} frases  {info['por_fuente']}  entidades={info['entidades']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
