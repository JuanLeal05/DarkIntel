# DarkIntel — Despliegue con Docker

Contenerizacion del codigo **que ya existe**, con aislamiento de red en tres
zonas. La integracion con Tor todavia **no** esta implementada: ver
[Pendiente: integracion Tor](#pendiente-integracion-tor).

## Arquitectura de red

```
        INTERNET
            |
   ┌────────┴─────────────────────────────┐
   │  darknet  (zona de riesgo)           │
   │                                      │
   │   tor-proxy  ◄── socks5 :9050 ──  scraper
   │   (Tor daemon)                       │   │
   └──────────────────────────────────────┘   │
                                              │ escribe
                              volumen raw_data │  (rw)
                        ◄─── UNICO PUNTO DE ───┘
                             CONTACTO
                                   │ lee (ro)
   ┌───────────────────────────────┼──────────┐
   │  backend  (internal: true)    ▼          │
   │                                          │
   │   processor ──────────► db (Postgres     │
   │   NER, embeddings,         + pgvector)   │
   │   clustering, STIX                       │
   └──────────────┬───────────────────────────┘
                  │ volumen output_data (ro)
   ┌──────────────┼───────────────────────────┐
   │  frontend    ▼                           │
   │            api (FastAPI)  ──► :8000 host │
   └──────────────────────────────────────────┘
```

Decisiones de seguridad detras del diseno:

| Decision | Motivo |
|---|---|
| `scraper` solo en `darknet` | No tiene ruta de red hacia `db`. Si se ve comprometido por contenido `.onion`, no alcanza la base de datos. |
| `scraper` sin credenciales de BD | No puede filtrar lo que no tiene. |
| `backend` con `internal: true` | Sin salida a internet. El modelo de embeddings se descarga en build, no en runtime. |
| `raw_data` montado `:ro` en `processor` | El flujo de datos es unidireccional: darknet -> backend, nunca al reves. |
| `db` sin `ports:` publicados | No alcanzable desde el host ni desde `darknet`. |
| Puerto SOCKS de Tor sin publicar | Solo alcanzable dentro de `darknet`. |
| Usuarios sin privilegios + `no-new-privileges` | Ningun contenedor de codigo propio corre como root. |

## Uso

```bash
cp .env.example .env     # editar POSTGRES_PASSWORD
docker compose build
docker compose up
```

`processor` es un job de un solo uso: corre el pipeline completo (NER ->
clustering -> STIX), escribe en `output_data` y termina. `api` espera a que
termine (`service_completed_successfully`) y luego sirve los bundles en
http://localhost:8000.

```bash
curl localhost:8000/stats
curl localhost:8000/stix/bundles
curl -X POST localhost:8000/iocs/extract \
     -H 'Content-Type: application/json' \
     -d '{"texto":"C2 en 198[.]51[.]100[.]42 explotando CVE-2024-1234"}'
```

Verificar el aislamiento de red (util para la demo):

```bash
# El scraper NO puede alcanzar la base de datos:
docker compose run --rm scraper python -c \
  "import socket;socket.create_connection(('db',5432),3)"   # falla

# Tor si esta enrutando:
docker compose exec tor-proxy \
  curl -s --socks5-hostname localhost:9050 https://check.torproject.org/api/ip
```

Re-ejecutar solo el pipeline: `docker compose run --rm processor`.

## Estado de cada servicio

| Servicio | Estado |
|---|---|
| `api` | Funcional. Sirve los bundles generados. |
| `processor` | Funcional sobre `data/synthetic_darkweb_dump.json` (datos sinteticos, no scrapeados). |
| `scraper` | **Placeholder.** Corre el `__main__` de `fetcher.py`: HTTP plano contra `books.toscrape.com`. No usa Tor. |
| `tor-proxy` | Daemon real y funcional, pero **ningun servicio lo usa todavia**. |
| `db` | Levanta con el esquema de `docker/postgres/init.sql`, pero el codigo sigue guardando JSON plano. |

## Pendiente: integracion Tor

Lo que habria que cambiar cuando se implemente (no hecho aun):

**`docker/requirements-scraper.txt`**
```
PySocks==1.7.1     # backend SOCKS5 para requests
stem>=1.8.2        # control de circuitos Tor via ControlPort
```
(Playwright, si se agrega, requiere ademas `playwright install --with-deps
chromium` en `Dockerfile.scraper` y sube la imagen a >1GB.)

**`src/darkintel/scraper/fetcher.py`** — hoy:
```python
respuesta = requests.get(url, timeout=10)
```
tendria que pasar por el proxy que ya se inyecta como variable de entorno
`TOR_SOCKS_PROXY` (ya definida en `docker-compose.yml`):
```python
proxies = {"http": os.environ["TOR_SOCKS_PROXY"],
           "https": os.environ["TOR_SOCKS_PROXY"]}
respuesta = requests.get(url, proxies=proxies, timeout=60)
```
El esquema debe ser `socks5h://` (no `socks5://`): la `h` hace que la
resolucion DNS ocurra **en** el proxy Tor, que es lo que permite resolver
`.onion` y evita fugas de DNS al resolver local.

**`docker/torrc`** — descomentar `ControlPort` y fijar
`HashedControlPassword` para que Stem pueda pedir circuitos nuevos
(`NEWNYM`). Sin autenticacion configurada, el ControlPort es un riesgo.

**Timeouts** — los servicios `.onion` son lentos; `timeout=10` es
insuficiente. 60-120s es lo razonable.
