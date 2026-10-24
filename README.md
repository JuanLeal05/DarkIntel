# DarkIntel

**Recolección y análisis automatizado de indicadores de compromiso (IoCs) en
la Dark Web por medio de IA.** Proyecto académico — Ingeniería de Sistemas.

DarkIntel automatiza el trabajo de un analista de inteligencia de amenazas:
recolecta posts de servicios `.onion` a través de Tor, extrae indicadores y
entidades con un NER híbrido (reglas + Transformer + conocimiento experto),
agrupa los posts en campañas y publica el resultado en **STIX 2.1** mediante
una API.

```
 .onion ──Tor──► scraper ──► data/raw ──► processor ─────────────────────────► API
                (aislado)   (frontera   [1] carga y validación               STIX 2.1
                             validada)  [2] NER híbrido
                                        [3] campañas (significado + infraestructura)
                                        [4] bundles STIX 2.1
```

## Cómo funciona

| Etapa | Qué hace | Dónde |
|---|---|---|
| Recolección | Descarga vía Tor (`socks5h`), con rotación de circuitos, límites de tamaño y tiempo, y redirecciones solo hacia `.onion` | `src/darkintel/scraper/` |
| Frontera de confianza | Valida todo lo que llega del scraper antes de procesarlo | `src/darkintel/data_loader.py` |
| IoCs | IPs, hashes, CVEs y dominios con regex: quita la ofuscación (`[.]`, `hxxp`) y filtra falsos positivos | `src/darkintel/ner/extractor.py` |
| Entidades | Malware, herramientas, actores y técnicas con **SecureBERT-NER** | `src/darkintel/ner/transformer.py` |
| Conocimiento experto | Corrige el tipo de las entidades, resuelve alias y descarta términos genéricos: *el modelo detecta, el conocimiento clasifica* | `src/darkintel/ner/conocimiento.py` |
| Campañas | Agrupa posts que **suenan parecido o comparten infraestructura** (mismo C2, hash o dominio) y explica qué comparte cada campaña | `src/darkintel/clustering/` |
| STIX 2.1 | Indicadores, malware, herramientas, actores, técnicas, vulnerabilidades y campañas, con IDs deterministas, fechas reales y TLP:AMBER | `src/darkintel/stix_builder/` |
| API | Sirve los bundles y extrae IoCs en vivo | `api/main.py` |

## Puesta en marcha

Todo corre en Docker con aislamiento de red en cuatro redes (el scraper no
tiene salida directa a internet: solo a través de Tor).

```bash
cp .env.example .env          # definir POSTGRES_PASSWORD y TOR_CONTROL_PASSWORD
docker compose build
docker compose up -d api      # ejecuta el pipeline sobre el dataset sintético y levanta la API
```

API en http://localhost:8000/docs. Instrucciones completas en
[README-docker.md](README-docker.md); antes de recolectar de un `.onion`,
seguir [SAFE_TESTING.md](SAFE_TESTING.md).

### Desarrollo local

```bash
python -m venv .venv
# Windows: .venv\Scripts\Activate.ps1   ·   Linux/macOS: source .venv/bin/activate
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -r requirements.txt
python -m pytest tests/ -q
python pipeline/run_pipeline.py
```

## Evaluación

El paper se compromete a dos métricas, medidas sobre la muestra de la demo:
**precisión ≥ 85 %** en la extracción frente a un etiquetado manual y
**reducción ≥ 70 %** del tiempo de catalogación manual.

| Herramienta | Uso |
|---|---|
| `docs/guia_anotacion.md` | Cómo se escriben y anotan los posts de evaluación |
| `pipeline/validar_anotaciones.py` | Valida el formato del dataset y de las anotaciones |
| `pipeline/evaluar.py` | Precisión/recall/F1 por capa (regex, +conocimiento, +Transformer, híbrido) |
| `pipeline/evaluar.py --acuerdo A B` | Acuerdo entre anotadores |
| `pipeline/evaluar.py --campanas` | Calidad de las campañas (ARI): semántico frente a híbrido |

El conjunto `test` solo se evalúa una vez, al final (`--split test --final`).

## Estructura

```
api/                    API FastAPI
docker/                 Dockerfiles, configuración de Tor, hidden service de prueba
docs/                   Guía de anotación, despliegue en GCP, dataset de ejemplo
pipeline/               run_pipeline.py (pipeline completo), run_ner.py, evaluación
src/darkintel/
  scraper/              Recolección vía Tor
  ner/                  Extractor regex, Transformer, conocimiento y NER híbrido
  clustering/           Embeddings y agrupamiento en campañas
  stix_builder/         Bundles STIX 2.1
  data_loader.py        Carga y validación de data/raw
  evaluacion.py         Métricas (P/R/F1, ARI) y validación de anotaciones
tests/                  Pruebas automatizadas (pytest)
```

## Documentación

| Documento | Contenido |
|---|---|
| [README-docker.md](README-docker.md) | Arquitectura de red, decisiones de seguridad, uso con Docker |
| [SAFE_TESTING.md](SAFE_TESTING.md) | Pruebas por etapas de riesgo creciente antes de un objetivo real |
| [docs/guia_anotacion.md](docs/guia_anotacion.md) | Escritura y anotación del dataset de evaluación |
| [docs/despliegue_gcp.md](docs/despliegue_gcp.md) | Despliegue en una VM de Google Cloud |

## Ética y OPSEC

- Solo se recolecta **texto**; nunca se descargan imágenes ni binarios.
- Las pruebas se hacen contra un hidden service propio con contenido de prueba
  (IPs de documentación, dominios inventados).
- Las salidas del pipeline (`data/raw/`, `data/output/`) **nunca se versionan**:
  con datos reales contienen inteligencia sobre objetivos y campañas.
- Antes de recolectar de objetivos reales: VM desechable, marco legal revisado
  y aprobación del docente (ver SAFE_TESTING.md, Etapa 3).

## Estado

Funcional de punta a punta. Trabajo futuro: persistencia en PostgreSQL +
pgvector, enriquecimiento (VirusTotal, AbuseIPDB, OTX, WHOIS), reportes con
RAG y descubrimiento automático de enlaces.

## Autores

Karol Estupiñan · Julian Castiblanco · Juan Leal
