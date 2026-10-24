# Ajuste fino (fine-tuning) del NER con CyberNER

DarkIntel usa por defecto **SecureBERT-NER**, que detecta bien las entidades
pero confunde sus tipos (por ejemplo, llama *malware* a Mimikatz, que es una
herramienta). Aquí se ajusta ese modelo con **CyberNER** (Chammakhy et al.,
2025): un corpus que unifica CyNER, DNRTI, APTNER y AttackER en etiquetas
STIX 2.1, citado en el paper del proyecto.

| Script | Qué hace | Necesita GPU |
|---|---|---|
| `preparar_cyberner.py` | Convierte el CSV de CyberNER a las 4 categorías de DarkIntel y lo divide en train/dev/test | No |
| `entrenar_ner.py` | Ajusta SecureBERT-NER con train; elige la mejor época con dev | Sí |
| `evaluar_ner.py` | Compara modelos sobre test, por tipo y por fuente | Recomendable |
| `metricas.py` | F1 a nivel de entidad (usado por los dos anteriores) | No |

## Decisiones de diseño

- **Categorías:** Malware → `MAL`, Tool → `TOOL`, Threat-Actor e
  Intrusion-Set → `APT`, Attack-Pattern → `ACT`; el resto, `O`. Son los nombres
  que ya entiende `src/darkintel/ner/transformer.py`: el modelo ajustado se
  usa sin tocar el código.
- **Sin contaminación:** SecureBERT-NER ya se entrenó con APTNER, así que las
  frases de **APTNER solo van a entrenamiento**. dev y test salen de CyNER,
  DNRTI y AttackER (10 % / 10 % de cada fuente).
- **Textos largos:** algunos "frases" del CSV son documentos enteros (hasta
  ~5.800 palabras); se parten en fragmentos de 128 palabras sin cortar
  entidades.
- **Reproducible:** semilla fija (42) en la división y en el entrenamiento.

Resultado de la preparación (23.477 frases):

| Conjunto | Frases | Malware | Herramienta | Actor | Técnica |
|---|---|---|---|---|---|
| train | 21.005 | 6.989 | 6.362 | 8.543 | 4.619 |
| dev | 1.343 | 373 | 371 | 499 | 362 |
| test | 1.343 | 345 | 324 | 511 | 348 |

## Licencia de los datos

El repositorio de CyberNER **no incluye archivo de licencia**, y los corpus de
origen tienen las suyas. Por eso los datos derivados (`data/cyberner/`) y los
modelos (`modelos/`) **no se versionan**. Para el paper: citar CyberNER y sus
fuentes, y confirmar con el docente (o los autores) el uso académico.

## Pasos (Windows / PowerShell)

### 1. Obtener CyberNER (fuera del repositorio)

```powershell
cd C:\Users\david\Documents\Universidad\CIBE
git clone https://github.com/yasirech-chammakhy/CyberNER.git
cd DarkIntel
```

### 2. Preparar los datos (cualquier entorno, no necesita GPU)

```powershell
python entrenamiento/preparar_cyberner.py ..\CyberNER\dataset\cyberner_combined_stix.csv
```

Crea `data/cyberner/{train,dev,test}.jsonl` y `resumen.json`.

### 3. Entorno de GPU

```powershell
.venv-gpu\Scripts\Activate.ps1
pip install -r entrenamiento/requirements-gpu.txt
python -c "import torch; print(torch.cuda.is_available(), torch.cuda.get_device_name(0))"
```

Debe imprimir `True NVIDIA GeForce RTX 5070`. El modelo base ya está en la
caché de HuggingFace de tu usuario (lo descargaste al probar DarkIntel), así
que no se vuelve a bajar.

### 4. Entrenar

```powershell
python entrenamiento/entrenar_ner.py
```

Por defecto: 4 épocas, learning rate 3e-5, lotes de 16, bf16. Guarda el mejor
modelo (según dev) en `modelos/darkintel-ner-v1/`, con
`darkintel_entrenamiento.json` (hiperparámetros, tiempo y métricas de dev).

Si se acaba la memoria de la GPU: `--batch 8`.

### 5. Comparar con el modelo original (una vez, al final)

```powershell
python entrenamiento/evaluar_ner.py --modelos base modelos/darkintel-ner-v1
```

Tabla de F1 por tipo y por fuente, más la **detección** (encontró la entidad
aunque el tipo esté mal). Lo esperable: detección parecida, y mejor F1 por tipo
en el ajustado. Si pruebas varios hiperparámetros, compáralos con
`--split dev`; usa `test` solo para el resultado final del paper.

### 6. Calibrar el umbral de confianza (con dev)

El umbral de 0,80 se fijó para el modelo original. El ajustado acierta el tipo
de muchas herramientas con confianza más baja (~0,5), y con 0,80 las descarta.
Se calibra en **dev**, nunca en test:

```powershell
python entrenamiento/evaluar_ner.py --split dev --modelos modelos/darkintel-ner-v1 --umbrales --salida modelos/umbrales_dev.json
```

Imprime P/R/F1 para cada umbral y el mejor. Ese valor va en
`DARKINTEL_NER_UMBRAL`.

### 7. Usarlo en DarkIntel

**Local:**

```powershell
.venv\Scripts\Activate.ps1
$env:DARKINTEL_NER_MODEL = "modelos\darkintel-ner-v1"
$env:DARKINTEL_NER_UMBRAL = "0.5"     # el que dio la calibración
python pipeline/run_pipeline.py
python pipeline/evaluar.py          # sobre el dataset de la demo (split dev)
Remove-Item Env:DARKINTEL_NER_MODEL, Env:DARKINTEL_NER_UMBRAL
```

**Docker:** en `.env`, `DARKINTEL_NER_MODEL=/app/modelos/darkintel-ner-v1` y
`DARKINTEL_NER_UMBRAL=<el calibrado>`, y
después `docker compose build processor`.

## Qué reportar en el paper

1. Tabla de `evaluar_ner.py`: F1 del modelo original frente al ajustado, en el
   test de CyberNER (sin APTNER).
2. Hiperparámetros y tiempo de entrenamiento (`darkintel_entrenamiento.json`) y
   el hardware: una GPU de consumo (RTX 5070).
3. El resultado sobre el dataset propio con `pipeline/evaluar.py`, que es la
   métrica del paper: CyberNER son informes formales y la demo son posts.
