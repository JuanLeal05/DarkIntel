"""
Métricas de NER a nivel de ENTIDAD (spans), sin dependencias externas.

Una entidad cuenta como acierto solo si coinciden el inicio, el final y el
tipo (criterio estándar de CoNLL / seqeval). Además se reporta la
"detección": el span correcto aunque el tipo sea otro, para separar
"no la vio" de "la vio pero la clasificó mal" (igual que pipeline/evaluar.py).
"""

TIPOS = ("MAL", "TOOL", "APT", "ACT")
NOMBRES = {"MAL": "malware", "TOOL": "herramienta", "APT": "actor", "ACT": "tecnica"}


def spans(etiquetas: list[str]) -> set[tuple[int, int, str]]:
    """
    Etiquetas BIO por palabra -> {(inicio, fin_exclusivo, tipo)}.
    Tolerante: un I-X sin B-X previo (o tras otro tipo) abre una entidad nueva.
    """
    resultado, inicio, tipo = set(), None, None
    for i, et in enumerate(list(etiquetas) + ["O"]):
        prefijo, _, t = et.partition("-") if "-" in et else ("O", "", "")
        continua = prefijo == "I" and t == tipo and inicio is not None
        if not continua and inicio is not None:
            resultado.add((inicio, i, tipo))
            inicio, tipo = None, None
        if prefijo in ("B", "I") and not continua:
            inicio, tipo = i, t
    return resultado


def _prf(tp: int, fp: int, fn: int) -> dict:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f, 4),
            "tp": tp, "fp": fp, "fn": fn}


def evaluar(referencias: list[list[str]], predicciones: list[list[str]]) -> dict:
    """Métricas por tipo, micro-promedio ("total") y detección sin tipo."""
    cont = {t: [0, 0, 0] for t in TIPOS}
    det = [0, 0, 0]
    for ref, pred in zip(referencias, predicciones):
        r, p = spans(ref), spans(pred)
        for t in TIPOS:
            rt = {s for s in r if s[2] == t}
            pt = {s for s in p if s[2] == t}
            cont[t][0] += len(rt & pt)
            cont[t][1] += len(pt - rt)
            cont[t][2] += len(rt - pt)
        r_sin, p_sin = {s[:2] for s in r}, {s[:2] for s in p}
        det[0] += len(r_sin & p_sin)
        det[1] += len(p_sin - r_sin)
        det[2] += len(r_sin - p_sin)

    salida = {NOMBRES[t]: _prf(*cont[t]) for t in TIPOS}
    salida["total"] = _prf(*(sum(c[i] for c in cont.values()) for i in range(3)))
    salida["deteccion"] = _prf(*det)
    return salida
