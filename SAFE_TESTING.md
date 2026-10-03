# Pruebas seguras de la integración Tor

Antes de apuntar `scraper` a un `.onion` real, esta integración se valida en
tres etapas de riesgo creciente. **No te saltes etapas.** Cada una confirma
una pieza distinta (código, red Tor, objetivo real) sin mezclar variables.

No lo corras en tu equipo personal de uso diario. Usa una VM desechable o una
sesión aislada (ver "Entorno del host" al final) desde la Etapa 2 en adelante.

---

## Etapa 0 — Unitarios (sin red, sin Docker)

```bash
python3 tests/test_fetcher.py
```

Confirma que `obtener_html()`, el límite de tamaño de respuesta y la
validación de `socks5h://` funcionan en aislamiento, con `requests.get`
mockeado. Cero riesgo: no sale ni un paquete a la red. Correr esto primero
siempre que toques `fetcher.py`.

---

## Etapa 1 — Hidden service propio (riesgo cero, todo local)

Objetivo: probar el circuito completo — `scraper` → Tor real → `.onion` →
respuesta parseada — sin que un solo byte salga hacia la dark web pública.
`test-onion` es un hidden service que armamos nosotros, con contenido
inocuo que escribimos nosotros.

Precision importante: el *contenido* nunca sale de tus contenedores, pero el
trafico de protocolo Tor si toca la red real — tu hidden service publica su
descriptor en las autoridades de directorio y el scraper lo consulta de
vuelta. Es inevitable para probar contra un `.onion` de verdad y no implica
ninguna exposicion a contenido de dark web.

```bash
cp .env.example .env

docker compose --profile testing up -d --build test-onion tor-proxy

# Lee la direccion .onion que genero el hidden service (puede tardar ~1 min
# en aparecer la primera vez):
ONION=$(docker compose exec -T test-onion cat /var/lib/tor/test_service/hostname | tr -d '\r\n')
echo $ONION

# Scrapea las 4 paginas de prueba de una sola corrida (el pipeline necesita
# al menos 4 posts para que UMAP/HDBSCAN funcionen):
docker compose --profile testing run --rm \
  -e SCRAPER_TARGET_URL="http://$ONION/post1.html,http://$ONION/post2.html,http://$ONION/post3.html,http://$ONION/post4.html" \
  scraper
```

**No uses `http://test-onion:80` como objetivo.** Es un nombre DNS de Docker,
y `socks5h://` se lo entrega a Tor para que lo resuelva — Tor no sabe qué es
y falla con `0x04 Host unreachable`. El objetivo tiene que ser la direccion
`.onion` real.

Qué validar:
- El log del scraper debe mostrar `🔄 Circuito Tor renovado (NEWNYM)` —
  confirma que `stem` se autenticó contra el `ControlPort` correctamente.
- El HTML devuelto debe contener el texto de prueba de
  `docker/test-onion/index.html` (incluye un IoC de prueba,
  `CVE-2024-9999`, que **no existe** — así se distingue de inmediato de
  cualquier IoC real si aparece mezclado en algún log).
- `docker compose --profile testing down` al terminar; este servicio no
  debe quedar corriendo fuera de una sesión de prueba activa.

Si esta etapa falla, el problema está en tu código o tu configuración de
Tor — no en el objetivo. Resuélvelo aquí antes de seguir.

### Cierre del ciclo: ¿el análisis sí procesa lo scrapeado?

El scraper ya guarda el post en `data/raw/` (vía `storage.guardar_json`).
Corre el pipeline justo después, en el mismo volumen, para confirmar que
`run_ner.py` lo recoge automáticamente en vez de usar el dataset sintético:

```bash
docker compose --profile testing run --rm processor python pipeline/run_ner.py
```

Debe imprimir `fuente: data/raw (scraper real)` y detectar los IoCs de
prueba que trae `docker/test-onion/index.html` (una IP, un CVE y un hash,
todos marcados como "de prueba" para no confundirlos con datos reales).
Esto es lo que confirma el objetivo completo de la aplicación de punta a
punta — no solo que Tor conecta, sino que lo que trae se analiza.

---

## Etapa 2 — Un `.onion` público pero legítimo y documentado

Objetivo: confirmar que el circuito Tor real (saliendo a internet) funciona
igual que el local, contra un servicio que es *sabidamente seguro y
propiedad de una organización conocida*. No es dark web ilícita.

Objetivos recomendados (operados por organizaciones verificables):
- `http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion` —
  el sitio oficial del Tor Project, listado en onion.torproject.org
  (`www.torproject.org` en su versión `.onion`).

```bash
echo "SCRAPER_TARGET_URL=http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion" >> .env

docker compose up -d tor-proxy
docker compose run --rm scraper
```

Qué validar: la petición completa en menos de `TIMEOUT_TOR` (90s) y el HTML
recibido tiene contenido coherente con una página real. Si esto falla pero
la Etapa 1 funcionó, el problema es de salida a internet del contenedor
`tor-proxy` (revisa la red `darknet`, no `internal`), no de tu código.

---

## Etapa 3 — Objetivo real de la investigación

Solo después de que 1 y 2 pasen limpio. Aquí sí aplica todo lo que ya
describe el paper sobre riesgo operativo:

- **Nunca en tu dispositivo personal.** Usa una VM desechable dedicada
  (snapshot antes de empezar, revertir después) o un entorno cloud aislado
  sin datos personales ni credenciales propias.
- El aislamiento de red del `docker-compose.yml` (scraper sin ruta a
  `backend`, sin credenciales de BD) sigue siendo tu segunda capa de
  defensa, no la primera — la primera es el host.
- Define `SCRAPER_TARGET_URL` en `.env`, nunca lo pegues directo en el
  código ni en un commit.
- Sube `MaxCircuitDirtiness` o llama `renovar_circuito()` con más
  frecuencia si vas a rastrear varios posts seguidos del mismo foro.
- Respeta lo que ya dice el paper: filtrado previo por hash conocido
  (PhotoDNA u homólogo) antes de persistir cualquier contenido, y
  descarte automático de lo que no pase ese filtro. Esto se implementa en
  `parser.py`/`storage.py`, no en `fetcher.py` — `fetcher.py` solo trae
  bytes, nunca decide qué se guarda.
- Ten claro el marco legal de tu jurisdicción para la sola *observación*
  de foros clandestinos antes de esta etapa; documentarlo brevemente en el
  paper (una frase sobre alcance ético/legal) fortalece la sustentación.
- Registra qué se visitó y cuándo (`storage.py` ya timestampa) por si
  necesitas justificar el alcance de la recolección después.

Empieza con **un solo objetivo, una sola petición**, revisa el log y el
HTML resultante antes de automatizar un rastreo más amplio.

---

## Entorno del host (aplica desde la Etapa 2)

- VM desechable o sandbox — nunca el equipo con tus datos personales,
  correo, contraseñas guardadas, etc.
- Snapshot limpio antes de la sesión; revertir al terminar, se haya
  encontrado algo problemático o no.
- Sin necesidad de Tor Browser en el host: todo el tráfico ya sale desde
  el contenedor `tor-proxy`, aislado del host por Docker.
- Monitorea recursos (`docker stats`) durante la Etapa 3: un `.onion`
  hostil podría intentar mantener la conexión abierta o forzar timeouts
  largos a propósito.
