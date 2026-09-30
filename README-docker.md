# DarkIntel — Despliegue con Docker

Contenerizacion del codigo **que ya existe**, con aislamiento de red en tres
zonas. La integracion con Tor ya esta implementada (`fetcher.py` enruta por
SOCKS5 y rota circuitos via ControlPort/stem); ver
[SAFE_TESTING.md](SAFE_TESTING.md) para el orden de pruebas antes de apuntar
a un objetivo real.

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
| `scraper` | Funcional: enruta por `TOR_SOCKS_PROXY` (`socks5h://`), rota circuitos con `stem`/`NEWNYM`, timeout 90s y limite de tamano de respuesta. Objetivo controlado por `SCRAPER_TARGET_URL` (ver `SAFE_TESTING.md`). |
| `tor-proxy` | Daemon real y funcional, con `ControlPort` autenticado; ahora consumido por `scraper`. |
| `test-onion` | Hidden service propio para pruebas (perfil `testing`, no se levanta en `up` normal). Ver `SAFE_TESTING.md` Etapa 1. |
| `db` | Levanta con el esquema de `docker/postgres/init.sql`, pero el codigo sigue guardando JSON plano — pendiente para una siguiente iteracion. |

## Antes de correr el scraper contra un objetivo real

**No lo pruebes directo contra dark web real.** Sigue el orden de
[SAFE_TESTING.md](SAFE_TESTING.md): unitarios sin red → hidden service
propio (riesgo cero) → `.onion` legitimo conocido → objetivo real, y solo
en una VM desechable, nunca en un equipo personal.
