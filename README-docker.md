# DarkIntel — Despliegue con Docker

Orquestación completa del pipeline (scraper Tor → NER → clustering → STIX 2.1
→ API) con aislamiento de red en cuatro redes. Antes de apuntar el scraper a
un objetivo real, sigue el orden de pruebas de [SAFE_TESTING.md](SAFE_TESTING.md).

## Arquitectura de red

```
                         INTERNET
                            │
          ┌─────────────────┴───────────────────┐
          │  tor_egress  (única red con salida) │
          │                                     │
          │   tor-proxy          test-onion*    │
          └─────┬───────────────────────┬───────┘
                │                       │
          ┌─────┴───────────────────────┴───────┐
          │  darknet  (internal: true)          │
          │                                     │
          │   scraper ── socks5h :9050 ──► tor-proxy
          │           ── control  :9051 ──►     │
          └─────┬───────────────────────────────┘
                │ escribe (rw)
                ▼
        volumen raw_data   ◄── ÚNICO punto de contacto
                │              entre la zona de riesgo y el backend
                │ lee (ro) + validación (data_loader.py)
          ┌─────┴───────────────────────────────┐
          │  backend  (internal: true)          │
          │                                     │
          │   processor ─────────► db           │
          │   NER híbrido,         (Postgres +  │
          │   campañas, STIX        pgvector)*  │
          └─────┬───────────────────────────────┘
                │ volumen output_data (ro)
          ┌─────┴───────────────────────────────┐
          │  frontend                           │
          │   api (FastAPI) ──► 127.0.0.1:8000  │
          └─────────────────────────────────────┘

  * test-onion solo existe con --profile testing
  * db: el esquema existe, pero el pipeline aún guarda en JSON (trabajo futuro)
```

## Decisiones de seguridad

| Decisión | Motivo |
|---|---|
| `scraper` solo en `darknet`, que es `internal: true` | El scraper **no tiene salida directa a internet**: su único camino hacia afuera es el SOCKS de Tor. Si un bug o un contenedor comprometido intenta salir sin Tor, no hay ruta (*fail-closed*): la IP real del host no puede filtrarse. |
| Solo `tor-proxy` y `test-onion` en `tor_egress` | Son los únicos procesos que necesitan internet: el daemon Tor para construir circuitos y el hidden service de prueba para publicar su descriptor. |
| `socks5h://` obligatorio | La "h" hace que el DNS se resuelva dentro de Tor: permite resolver `.onion` y evita fugas de DNS. `fetcher.py` rechaza cualquier otro esquema. |
| Hash del ControlPort generado al arrancar | `docker/tor-entrypoint.sh` calcula `HashedControlPassword` desde `TOR_CONTROL_PASSWORD`. No hay hashes ni contraseñas por defecto en el repositorio. |
| `scraper` sin credenciales de BD ni ruta a `backend` | Si se ve comprometido por contenido `.onion`, no alcanza la base de datos. |
| `raw_data` montado `:ro` en `processor` | Flujo unidireccional: darknet → backend, nunca al revés. |
| `data/raw` validado como frontera de confianza | `data_loader.py` ignora symlinks, mide el tamaño antes de leer, valida cada post con un esquema estricto, descarta campos desconocidos y fuerza `labels_manual = None` (un scraper comprometido no puede falsear las métricas). |
| `backend` con `internal: true` | Sin salida a internet. El modelo de embeddings se descarga en el build, no en runtime. |
| `db` sin `ports:` publicados | No alcanzable desde el host ni desde `darknet`. |
| `api` solo en `frontend`, publicada en `127.0.0.1` | Sin credenciales ni ruta a la BD mientras no la necesite; solo accesible desde el propio host. Entrada validada con Pydantic (422) y cuerpo limitado (413). |
| Usuarios sin privilegios + `no-new-privileges` | Ningún contenedor de código propio corre como root. |

## Uso

### 1. Configuración

```bash
cp .env.example .env        # Windows: copy .env.example .env
```

Edita `.env` y define **obligatoriamente**:

| Variable | Para qué |
|---|---|
| `POSTGRES_PASSWORD` | Contraseña de la base de datos |
| `TOR_CONTROL_PASSWORD` | Contraseña del ControlPort de Tor (rotación de circuitos con `stem`) |

Si alguna está vacía o falta, `docker compose` **se niega a arrancar**, a
propósito. `POSTGRES_PASSWORD` solo se aplica al crear la base: para
cambiarla después hay que recrear el volumen (`docker compose down -v`).

### 2. Build

```bash
docker compose build        # la primera vez tarda 10-20 min (torch + modelo)
```

### 3. Pipeline + API sobre el dataset sintético

```bash
docker compose up -d api               # arranca db, ejecuta processor y luego api
docker compose logs processor          # debe terminar en "Pipeline completado"
```

API en http://localhost:8000 — documentación interactiva en
http://localhost:8000/docs.

```bash
curl localhost:8000/stats              # Windows (PowerShell): curl.exe localhost:8000/stats
curl localhost:8000/stix/bundles
```

Para `POST /iocs/extract` es más cómodo usar `/docs` → *Try it out*:

```json
{"texto": "C2 en 198[.]51[.]100[.]42 explotando CVE-2024-1234"}
```

### 4. Scraping vía Tor (hidden service propio)

Ver [SAFE_TESTING.md](SAFE_TESTING.md), Etapa 1. Resumen en PowerShell:

```powershell
docker compose --profile testing up -d --build test-onion tor-proxy
$ONION = (docker compose exec -T test-onion cat /var/lib/tor/test_service/hostname).Trim()
docker compose --profile testing run --rm -e "SCRAPER_TARGET_URL=http://$ONION/post1.html,http://$ONION/post2.html,http://$ONION/post3.html,http://$ONION/post4.html" scraper
docker compose run --rm processor      # ahora procesa data/raw en vez del sintético
docker compose --profile testing down  # no dejar el hidden service corriendo
```

En bash, la segunda línea es:
`ONION=$(docker compose exec -T test-onion cat /var/lib/tor/test_service/hostname | tr -d '\r\n')`

Volver al dataset sintético (vacía el volumen `raw_data`):

```bash
docker compose run --rm --entrypoint sh scraper -c "rm -f /app/data/raw/*.json"
```

### Re-ejecutar solo el pipeline

```bash
docker compose run --rm processor
```

El processor ejecuta `pipeline/run_pipeline.py` en un solo proceso y muestra
cuatro fases numeradas con su tiempo:

| Fase | Qué hace |
|---|---|
| 1. Carga | Lee y valida `data/raw` (o el dataset sintético si está vacío) |
| 2. NER híbrido | Regex (IoCs) + SecureBERT-NER + base de conocimiento (malware, herramientas, actores, técnicas) |
| 3. Campañas | Agrupa por significado **e infraestructura compartida** y muestra qué comparte cada campaña |
| 4. STIX 2.1 | Un bundle por campaña |

Salidas en el volumen `output_data`:

| Archivo | Contenido |
|---|---|
| `stix_bundles.json` | Bundles STIX 2.1 que sirve la API |
| `analisis.json` | Por post: campaña, IoCs y entidades |
| `clusters.png` | Gráfico de las campañas |

La API lee los bundles en cada petición: no hace falta reiniciarla.

### Variables de configuración del pipeline

Opcionales; se pasan con `-e` (por ejemplo,
`docker compose run --rm -e DARKINTEL_CLUSTERING=semantico processor`).

| Variable | Por defecto | Efecto |
|---|---|---|
| `DARKINTEL_NER_TRANSFORMER` | `1` | `0` desactiva el Transformer (solo regex + conocimiento) |
| `DARKINTEL_NER_KB` | `1` | `0` desactiva la base de conocimiento |
| `DARKINTEL_NER_UMBRAL` | `0.80` | Confianza mínima de las entidades del Transformer |
| `DARKINTEL_CLUSTERING` | `hibrido` | `semantico` = solo embeddings (método anterior) |
| `DARKINTEL_CLUSTER_ALFA` | `0.5` | Peso del significado frente a la infraestructura compartida |

### Después de cambiar código

El código se copia dentro de las imágenes (no se monta), así que hay que
reconstruir la imagen afectada:

| Si cambias… | Reconstruye |
|---|---|
| `src/darkintel/ner/` | `docker compose build processor api` |
| `src/darkintel/scraper/` | `docker compose build scraper` |
| `src/darkintel/clustering/`, `stix_builder/`, `data_loader.py`, `pipeline/` | `docker compose build processor` |
| `api/` | `docker compose build api` |
| `docker/torrc`, `Dockerfile.tor`, `tor-entrypoint.sh` | `docker compose build tor-proxy` |

## Verificar el aislamiento (útil para la demo)

```bash
# 1. El scraper NO tiene internet directo (debe FALLAR):
docker compose run --rm --entrypoint python scraper -c "import requests; requests.get('https://example.com', timeout=5)"

# 2. El scraper NO alcanza la base de datos (debe FALLAR):
docker compose run --rm --entrypoint python scraper -c "import socket; socket.create_connection(('db', 5432), 3)"

# 3. Tor sí enruta (debe devolver "IsTor":true):
docker compose exec tor-proxy curl -s --socks5-hostname localhost:9050 https://check.torproject.org/api/ip

# 4. Sin contraseñas, el stack no arranca (debe FALLAR con un mensaje claro):
#    comentar TOR_CONTROL_PASSWORD en .env y ejecutar:
docker compose up -d tor-proxy
```

## Comportamiento del scraper

| Mecanismo | Detalle |
|---|---|
| Rotación de circuitos | `NEWNYM` vía `stem` antes de cada objetivo, con un mínimo real de 10 s entre señales (límite de Tor). |
| Tamaño máximo | 5 MB por respuesta; si se supera, se descarta. |
| Tiempo máximo | 90 s por operación de red y **120 s totales** por descarga (protege contra servidores que envían datos muy despacio a propósito). |
| Redirecciones | Seguidas a mano: máximo 3, solo hacia `.onion` y solo `http`/`https`. |
| Reintentos | Solo ante fallos de red transitorios: 2 reintentos con circuito nuevo y espera de 5 s y 10 s. Los fallos de política (tamaño, tiempo, redirección) no se reintentan. |

## Estado de cada servicio

| Servicio | Estado |
|---|---|
| `tor-proxy` | Funcional. SOCKS5 y ControlPort autenticado, hash generado al arrancar. |
| `scraper` | Funcional vía Tor con las protecciones de la tabla anterior. Recolecta las URLs de `SCRAPER_TARGET_URL`; todavía no descubre enlaces por sí mismo (no hay crawling). |
| `test-onion` | Hidden service propio para pruebas (perfil `testing`). |
| `processor` | Funcional: valida `data/raw`, NER híbrido (regex + SecureBERT-NER + base de conocimiento), campañas por significado e infraestructura compartida, y bundles STIX 2.1 con malware, herramientas, actores y técnicas. Usa `data/raw` si tiene posts; si no, el dataset sintético. |
| `api` | Funcional. Sirve los bundles generados y extrae IoCs en vivo (`POST /iocs/extract` usa solo la regex: la imagen de la API no incluye los modelos). |
| `db` | Arranca con el esquema de `docker/postgres/init.sql` (pgvector), pero el pipeline todavía guarda en JSON: **pendiente**. |

### Pendiente (trabajo futuro)

- Persistencia en PostgreSQL + pgvector (el esquema ya existe en `docker/postgres/init.sql`).
- Enriquecimiento (VirusTotal, AbuseIPDB, OTX, WHOIS) y reportes con RAG.
- Descubrimiento automático de enlaces (crawling); hoy se recolectan las URLs indicadas.
- Ajuste fino (fine-tuning) del modelo NER si las métricas sobre el dataset de evaluación lo requieren.

## Antes de correr el scraper contra un objetivo real

**No lo pruebes directo contra la dark web real.** Sigue el orden de
[SAFE_TESTING.md](SAFE_TESTING.md): unitarios sin red → hidden service
propio (riesgo cero) → `.onion` legítimo conocido → objetivo real, y solo
en una VM desechable, nunca en un equipo personal.

Las salidas del pipeline (`data/raw/`, `data/output/`, `clusters.png`)
**nunca se versionan**: con datos reales contienen inteligencia sobre
objetivos y campañas.
