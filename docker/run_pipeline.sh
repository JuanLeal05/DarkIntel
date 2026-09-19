#!/bin/sh
# Ejecuta el pipeline completo sobre el dataset sintetico.
# Orden: metricas NER -> clustering (scatter plot) -> bundles STIX.
set -e

echo "==> [1/3] NER: extraccion de IoCs y metricas contra labels_manual"
python pipeline/run_ner.py

echo "==> [2/3] Clustering: embeddings + UMAP + HDBSCAN"
python pipeline/run_clustering.py
# run_clustering.py guarda clusters.png en el cwd; lo movemos al volumen
# compartido para que sea visible fuera del contenedor.
[ -f clusters.png ] && mv clusters.png data/output/clusters.png

echo "==> [3/3] STIX: construccion de bundles por campana"
python pipeline/run_stix.py

echo "==> Pipeline completado. Salida en /app/data/output"
