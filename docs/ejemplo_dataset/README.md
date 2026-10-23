# Ejemplo de dataset

Tres posts de muestra con el formato exacto de `docs/guia_anotacion.md`.
Sirve de plantilla y para probar los scripts:

```
python pipeline/validar_anotaciones.py --dir docs/ejemplo_dataset
python pipeline/evaluar.py --dir docs/ejemplo_dataset --modo regex
```

El dataset real va en `data/demo/`.
