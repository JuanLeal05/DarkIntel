# Modelos NER ajustados

Aquí se guardan los modelos que produce `entrenamiento/entrenar_ner.py`
(por defecto `modelos/darkintel-ner-v1/`). **No se versionan** (pesan ~500 MB):
este README es lo único de la carpeta que está en git, para que el
`COPY modelos/` del `Dockerfile.backend` funcione aunque esté vacía.

Para usar un modelo ajustado en Docker, define en `.env`:

```
DARKINTEL_NER_MODEL=/app/modelos/darkintel-ner-v1
```

y reconstruye el processor: `docker compose build processor`.
Instrucciones completas en `entrenamiento/README.md`.
