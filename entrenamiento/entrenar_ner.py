"""
Ajuste fino (fine-tuning) del NER de DarkIntel sobre CyberNER, en GPU.

Parte de SecureBERT-NER (el modelo que ya usa DarkIntel) y le enseña las 4
categorías de DarkIntel con los datos de preparar_cyberner.py. El modelo
resultante usa las mismas etiquetas (MAL, TOOL, APT, ACT), así que
src/darkintel/ner/transformer.py lo usa sin cambios: basta con
DARKINTEL_NER_MODEL=<carpeta del modelo>.

Uso (en el entorno con GPU, ver entrenamiento/README.md):
    python entrenamiento/entrenar_ner.py
    python entrenamiento/entrenar_ner.py --epocas 5 --lr 2e-5

Entrena con train, elige la mejor época con dev y NO mira test: test se usa
después, una sola vez, con evaluar_ner.py.
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(__file__))
from metricas import evaluar  # noqa: E402

ETIQUETAS = ["O", "B-MAL", "I-MAL", "B-TOOL", "I-TOOL", "B-APT", "I-APT", "B-ACT", "I-ACT"]
ID2LABEL = dict(enumerate(ETIQUETAS))
LABEL2ID = {v: k for k, v in ID2LABEL.items()}

MODELO_BASE = "CyberPeace-Institute/SecureBERT-NER"
REVISION_BASE = "7f935a4f7db13697580c881e381bb2636dfa779a"
MAX_TOKENS = 256


def leer_jsonl(ruta: str) -> list[dict]:
    with open(ruta, encoding="utf-8") as f:
        return [json.loads(linea) for linea in f if linea.strip()]


class ConjuntoNER:
    """Tokeniza por palabras y alinea etiquetas: solo el 1er sub-token de cada
    palabra lleva etiqueta; el resto se ignora en la pérdida (-100)."""

    def __init__(self, frases: list[dict], tokenizer):
        self.items = []
        for fr in frases:
            enc = tokenizer(fr["tokens"], is_split_into_words=True,
                            truncation=True, max_length=MAX_TOKENS)
            etiquetas, anterior = [], None
            for palabra in enc.word_ids():
                if palabra is None or palabra == anterior:
                    etiquetas.append(-100)
                else:
                    etiquetas.append(LABEL2ID[fr["etiquetas"][palabra]])
                anterior = palabra
            enc["labels"] = etiquetas
            self.items.append(enc)

    def __len__(self):
        return len(self.items)

    def __getitem__(self, i):
        return self.items[i]


def a_etiquetas(pred_ids, label_ids):
    """Convierte las salidas del Trainer en listas BIO por palabra (sin -100)."""
    refs, preds = [], []
    for p_fila, l_fila in zip(pred_ids, label_ids):
        r, p = [], []
        for p_id, l_id in zip(p_fila, l_fila):
            if l_id == -100:
                continue
            r.append(ID2LABEL[int(l_id)])
            p.append(ID2LABEL[int(p_id)])
        refs.append(r)
        preds.append(p)
    return refs, preds


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--datos", default=os.path.join("data", "cyberner"))
    parser.add_argument("--salida", default=os.path.join("modelos", "darkintel-ner-v1"))
    parser.add_argument("--base", default=MODELO_BASE)
    parser.add_argument("--revision", default=REVISION_BASE)
    parser.add_argument("--epocas", type=float, default=4)
    parser.add_argument("--lr", type=float, default=3e-5)
    parser.add_argument("--batch", type=int, default=16)
    parser.add_argument("--semilla", type=int, default=42)
    args = parser.parse_args()

    import numpy as np
    import torch
    from transformers import (AutoModelForTokenClassification, AutoTokenizer,
                              DataCollatorForTokenClassification, Trainer, TrainingArguments)

    if not torch.cuda.is_available():
        print("⚠️  No hay GPU CUDA: el entrenamiento en CPU será MUY lento.")
        print("   Activa el entorno .venv-gpu (ver entrenamiento/README.md).")
    else:
        print(f"🖥️  GPU: {torch.cuda.get_device_name(0)}")

    for nombre in ("train", "dev"):
        if not os.path.exists(os.path.join(args.datos, f"{nombre}.jsonl")):
            print(f"❌ Falta {args.datos}/{nombre}.jsonl: ejecuta antes preparar_cyberner.py")
            return 1

    revision = args.revision if not os.path.isdir(args.base) else None
    tokenizer = AutoTokenizer.from_pretrained(args.base, revision=revision, add_prefix_space=True)
    modelo = AutoModelForTokenClassification.from_pretrained(
        args.base, revision=revision,
        num_labels=len(ETIQUETAS), id2label=ID2LABEL, label2id=LABEL2ID,
        # La cabeza original tiene 40 etiquetas (APTNER); se reemplaza por una
        # de 9. El resto del modelo (lo que ya sabe de ciberseguridad) se conserva.
        ignore_mismatched_sizes=True,
    )

    print("📂 Tokenizando...")
    train = ConjuntoNER(leer_jsonl(os.path.join(args.datos, "train.jsonl")), tokenizer)
    dev = ConjuntoNER(leer_jsonl(os.path.join(args.datos, "dev.jsonl")), tokenizer)
    print(f"   train={len(train)} dev={len(dev)}")

    def compute_metrics(eval_pred):
        logits, labels = eval_pred
        refs, preds = a_etiquetas(np.argmax(logits, axis=-1), labels)
        m = evaluar(refs, preds)
        return {"f1": m["total"]["f1"], "precision": m["total"]["precision"],
                "recall": m["total"]["recall"], "f1_deteccion": m["deteccion"]["f1"],
                **{f"f1_{k}": v["f1"] for k, v in m.items() if k not in ("total", "deteccion")}}

    usar_bf16 = torch.cuda.is_available() and torch.cuda.is_bf16_supported()
    trabajo = os.path.join(args.salida, "_checkpoints")
    argumentos = TrainingArguments(
        output_dir=trabajo,
        num_train_epochs=args.epocas,
        learning_rate=args.lr,
        per_device_train_batch_size=args.batch,
        per_device_eval_batch_size=args.batch * 2,
        weight_decay=0.01,
        warmup_steps=0.1,              # 10 % de los pasos (transformers 5.x)
        eval_strategy="epoch",
        save_strategy="epoch",
        save_total_limit=1,
        load_best_model_at_end=True,   # la mejor época según dev
        metric_for_best_model="f1",
        greater_is_better=True,
        bf16=usar_bf16,
        logging_steps=100,
        report_to="none",
        seed=args.semilla,
        dataloader_num_workers=0,      # Windows
    )

    trainer = Trainer(
        model=modelo,
        args=argumentos,
        train_dataset=train,
        eval_dataset=dev,
        processing_class=tokenizer,
        data_collator=DataCollatorForTokenClassification(tokenizer),
        compute_metrics=compute_metrics,
    )

    inicio = time.time()
    trainer.train()
    minutos = (time.time() - inicio) / 60
    metricas_dev = trainer.evaluate()

    trainer.save_model(args.salida)
    tokenizer.save_pretrained(args.salida)
    with open(os.path.join(args.salida, "darkintel_entrenamiento.json"), "w", encoding="utf-8") as f:
        json.dump({
            "fecha": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "modelo_base": args.base, "revision_base": revision,
            "datos": os.path.join(args.datos, "resumen.json"),
            "hiperparametros": {"epocas": args.epocas, "lr": args.lr, "batch": args.batch,
                                "max_tokens": MAX_TOKENS, "semilla": args.semilla, "bf16": usar_bf16},
            "minutos_entrenamiento": round(minutos, 1),
            "metricas_dev": {k: v for k, v in metricas_dev.items() if isinstance(v, (int, float))},
            "etiquetas": ETIQUETAS,
        }, f, ensure_ascii=False, indent=2)

    print(f"\n✅ Modelo guardado en {args.salida} ({minutos:.1f} min)")
    print(f"   dev: F1={metricas_dev.get('eval_f1', 0)*100:.1f}%  "
          f"detección={metricas_dev.get('eval_f1_deteccion', 0)*100:.1f}%")
    print("   Siguiente: python entrenamiento/evaluar_ner.py --modelos base " + args.salida)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
