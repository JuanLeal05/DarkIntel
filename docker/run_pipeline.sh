#!/bin/sh
# Ejecuta el pipeline completo de DarkIntel en un solo proceso:
# carga -> NER híbrido -> campañas (UMAP + HDBSCAN) -> bundles STIX 2.1.
# El modelo NER y los embeddings se cargan y calculan una sola vez.
#
# Para depurar solo la extracción: python pipeline/run_ner.py
set -e

python pipeline/run_pipeline.py

echo "==> Salida en /app/data/output (stix_bundles.json, analisis.json, clusters.png)"
