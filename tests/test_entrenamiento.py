"""
Tests de entrenamiento/ que NO necesitan GPU ni descargar modelos:
mapeo de etiquetas, división sin contaminación, fragmentación, métricas
y alineación palabra/sub-token.
"""
import csv
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "entrenamiento"))

import metricas as me                        # noqa: E402
import preparar_cyberner as prep             # noqa: E402


# ── Mapeo de etiquetas ───────────────────────────────────────

@pytest.mark.parametrize("stix,esperada", [
    ("B-Malware", "B-MAL"), ("I-Malware", "I-MAL"),
    ("B-Tool", "B-TOOL"),
    ("B-Threat-Actor", "B-APT"), ("I-Threat-Actor", "I-APT"),   # el tipo tiene guion
    ("B-Intrusion-Set", "B-APT"),
    ("B-Attack-Pattern", "B-ACT"),
    ("B-Software", "O"), ("B-Location", "O"), ("B-IPv4-Addr", "O"), ("O", "O"),
])
def test_mapeo_a_categorias_darkintel(stix, esperada):
    assert prep.mapear_etiqueta(stix) == esperada


def test_corregir_bio_repara_i_sin_b():
    # B-Software I-Tool -> tras mapear: O I-TOOL -> debe quedar O B-TOOL
    assert prep.corregir_bio(["O", "I-TOOL", "I-TOOL", "O"]) == ["O", "B-TOOL", "I-TOOL", "O"]
    assert prep.corregir_bio(["B-MAL", "I-TOOL"]) == ["B-MAL", "B-TOOL"]


# ── Lectura, división y fragmentación ────────────────────────

def _csv(tmp_path, filas):
    ruta = tmp_path / "cyberner.csv"
    with open(ruta, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Word", "Tag", "Sentence_ID", "STIX_Tag", "Source"])
        w.writerows(filas)
    return str(ruta)


def test_mismo_sentence_id_en_fuentes_distintas_son_frases_distintas(tmp_path):
    ruta = _csv(tmp_path, [
        ["Emotet", "x", "0", "B-Malware", "CyNER"],
        ["spreads", "x", "0", "O", "CyNER"],
        ["APT28", "x", "0", "B-Threat-Actor", "DNRTI"],
    ])
    frases = prep.leer_frases(ruta)
    assert [f["id"] for f in frases] == ["CyNER-0", "DNRTI-0"]
    assert frases[1]["etiquetas"] == ["B-APT"]


def _frases(fuente, n):
    return [{"fuente": fuente, "id": f"{fuente}-{i}", "tokens": ["x"], "etiquetas": ["O"]}
            for i in range(n)]


def test_aptner_nunca_va_a_dev_ni_test():
    frases = _frases("APTNER", 50) + _frases("DNRTI", 100) + _frases("CyNER", 100)
    train, dev, test = prep.dividir(frases)
    assert all(f["fuente"] != "APTNER" for f in dev + test)
    assert sum(f["fuente"] == "APTNER" for f in train) == 50
    assert len(test) == 20 and len(dev) == 20


def test_division_reproducible_y_sin_solapamiento():
    frases = _frases("DNRTI", 200)
    a = prep.dividir(frases)
    b = prep.dividir(frases)
    assert [[f["id"] for f in c] for c in a] == [[f["id"] for f in c] for c in b]
    ids = [{f["id"] for f in c} for c in a]
    assert not (ids[0] & ids[2]) and not (ids[1] & ids[2])


def test_fragmentar_no_corta_entidades_ni_pierde_palabras():
    etiquetas = ["O"] * 9 + ["B-MAL", "I-MAL", "I-MAL"] + ["O"] * 8   # 20 palabras
    frase = {"fuente": "X", "id": "X-1", "tokens": [str(i) for i in range(20)],
             "etiquetas": etiquetas}
    trozos = prep.fragmentar(frase, maximo=10)
    assert sum(len(t["tokens"]) for t in trozos) == 20
    assert all(len(t["tokens"]) <= 10 for t in trozos)
    assert all(not t["etiquetas"][0].startswith("I-") for t in trozos)
    assert sum(e == "B-MAL" for t in trozos for e in t["etiquetas"]) == 1


# ── Métricas ─────────────────────────────────────────────────

def test_spans_bio():
    assert me.spans(["B-MAL", "I-MAL", "O", "B-APT"]) == {(0, 2, "MAL"), (3, 4, "APT")}
    assert me.spans(["O", "I-TOOL", "I-TOOL"]) == {(1, 3, "TOOL")}       # I- sin B-
    assert me.spans(["B-MAL", "I-TOOL"]) == {(0, 1, "MAL"), (1, 2, "TOOL")}


def test_metricas_exige_limites_y_tipo_exactos():
    ref = [["B-MAL", "I-MAL", "O", "B-TOOL"]]
    m = me.evaluar(ref, [["B-MAL", "I-MAL", "O", "B-TOOL"]])
    assert m["total"]["f1"] == 1.0
    m = me.evaluar(ref, [["B-MAL", "O", "O", "B-TOOL"]])          # límite mal
    assert m["malware"]["tp"] == 0 and m["herramienta"]["tp"] == 1


def test_deteccion_separa_no_vista_de_mal_clasificada():
    # El caso real: Mimikatz encontrado pero etiquetado como malware
    ref = [["B-TOOL", "O"]]
    pred = [["B-MAL", "O"]]
    m = me.evaluar(ref, pred)
    assert m["total"]["f1"] == 0.0
    assert m["deteccion"]["f1"] == 1.0


# ── Conversión de etiquetas del modelo base ──────────────────

def test_etiquetas_del_modelo_base_se_traducen():
    import evaluar_ner as ev
    assert ev.etiqueta_darkintel("B-MAL") == "B-MAL"
    assert ev.etiqueta_darkintel("I-APT") == "I-APT"
    assert ev.etiqueta_darkintel("PROT") == "O"        # el modelo base trae PROT sin prefijo
    assert ev.etiqueta_darkintel("B-LOC") == "O"
    assert ev.etiqueta_darkintel("O") == "O"


# ── Alineación palabra / sub-token (sin descargar modelos) ───

def test_alineacion_solo_primer_subtoken_lleva_etiqueta():
    tokenizers = pytest.importorskip("tokenizers")
    transformers = pytest.importorskip("transformers")
    import entrenar_ner as en

    # Tokenizador BPE diminuto, entrenado aquí mismo: fuerza que "Mimikatz"
    # se parta en varios sub-tokens, como pasaría con RoBERTa.
    bpe = tokenizers.ByteLevelBPETokenizer()
    bpe.train_from_iterator(["the actor used tools to dump creds"] * 5, vocab_size=300,
                            min_frequency=1, special_tokens=["<s>", "<pad>", "</s>", "<unk>", "<mask>"])
    tok = transformers.PreTrainedTokenizerFast(tokenizer_object=bpe._tokenizer,
                                               bos_token="<s>", eos_token="</s>",
                                               pad_token="<pad>", unk_token="<unk>")
    frase = {"tokens": ["the", "Mimikatz", "tool"], "etiquetas": ["O", "B-TOOL", "O"]}
    item = en.ConjuntoNER([frase], tok)[0]
    con_etiqueta = [l for l in item["labels"] if l != -100]
    assert [en.ID2LABEL[l] for l in con_etiqueta] == ["O", "B-TOOL", "O"]   # una por palabra
    assert item["labels"].count(-100) >= 1                                  # sub-tokens extra ignorados


def test_a_etiquetas_ignora_las_posiciones_minus_100():
    import entrenar_ner as en
    preds = [[0, 3, 4, 0]]
    labels = [[-100, 3, -100, 0]]
    refs, p = en.a_etiquetas(preds, labels)
    assert refs == [["B-TOOL", "O"]] and p == [["B-TOOL", "O"]]
