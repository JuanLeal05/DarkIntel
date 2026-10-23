# Despliegue de DarkIntel en Google Cloud (Compute Engine)

DarkIntel se despliega en **una sola VM** que ejecuta el mismo
`docker compose` que en local. Así se conservan intactos el aislamiento de
red de P0 (cuatro redes Docker, volúmenes compartidos, Tor como servicio).

```
 Tu portátil ── túnel SSH por IAP (HTTPS) ──► VM darkintel-vm (sin IP pública)
                                                  │
                                                  │ docker compose
                                                  │  tor-proxy, scraper, processor, db, api
                                                  ▼
                                    Cloud NAT ──► internet (solo salida: Tor, apt, imágenes)
```

| Decisión | Motivo |
|---|---|
| VM **sin IP pública** | Nadie puede iniciar una conexión hacia la VM desde internet |
| Acceso solo por **IAP** | SSH sin abrir el puerto 22 al mundo; el túnel viaja por HTTPS y funciona incluso en redes que bloquean Tor o SSH (útil el día de la demo) |
| **Cloud NAT** | La VM necesita salida (Tor, apt, Docker, HuggingFace) aunque no tenga IP pública |
| Red VPC **propia** | La red `default` trae reglas que abren SSH y RDP a todo internet |
| **Sin cuenta de servicio** | La VM no necesita permisos sobre el proyecto; si se compromete, no puede tocar nada de GCP |
| **Snapshots** | Implementan la "VM desechable" de `SAFE_TESTING.md`: estado limpio antes de cada sesión, revertir después |

> **Dónde ejecutar los comandos:** todo lo de este documento se ejecuta en
> **Cloud Shell** (el botón `>_` arriba a la derecha en console.cloud.google.com).
> Es una terminal **bash** con `gcloud` ya instalado y autenticado. No usar
> PowerShell para esta guía.

---

## Fase 0 — Infraestructura (antes de terminar P1)

Objetivo: dejar la VM creada, segura y con Tor funcionando, usando el código
que ya está en la rama. Tiempo estimado: 1–2 horas (la mayor parte es el
`docker compose build`).

### 0.1 Proyecto, facturación y presupuesto

```bash
# Elegir un ID único (minúsculas, números y guiones)
export PROJECT_ID=darkintel-$RANDOM
gcloud projects create $PROJECT_ID --name="DarkIntel"
gcloud config set project $PROJECT_ID
echo "Tu proyecto es: $PROJECT_ID"   # anótalo
```

Luego, en la consola web:

1. **Facturación** → vincular el proyecto a tu cuenta de facturación (o a la
   prueba gratuita).
2. **Facturación → Presupuestos y alertas** → crear un presupuesto de
   **20 USD** con alertas al 50 %, 90 % y 100 %. Es la protección contra
   olvidarse la VM encendida.

```bash
gcloud services enable compute.googleapis.com iap.googleapis.com
```

### 0.2 Variables de la sesión

Cloud Shell no recuerda variables entre sesiones. Al volver, repetir esto:

```bash
export PROJECT_ID=<el-id-que-anotaste>
export REGION=us-east1
export ZONE=us-east1-b
gcloud config set project $PROJECT_ID
gcloud config set compute/zone $ZONE
```

### 0.3 Red aislada

```bash
# Red propia, sin las reglas abiertas de la red "default"
gcloud compute networks create darkintel-net --subnet-mode=custom

gcloud compute networks subnets create darkintel-subnet \
  --network=darkintel-net --region=$REGION --range=10.10.0.0/24

# ÚNICA regla de entrada: SSH desde el rango de IAP de Google.
# Todo lo demás queda bloqueado (GCP deniega la entrada por defecto).
gcloud compute firewall-rules create darkintel-allow-iap-ssh \
  --network=darkintel-net --direction=INGRESS --action=allow \
  --rules=tcp:22 --source-ranges=35.235.240.0/20 --target-tags=darkintel

# Salida a internet sin IP pública
gcloud compute routers create darkintel-router \
  --network=darkintel-net --region=$REGION
gcloud compute routers nats create darkintel-nat \
  --router=darkintel-router --region=$REGION \
  --auto-allocate-nat-external-ips --nat-all-subnet-ip-ranges
```

### 0.4 Crear la VM

```bash
gcloud compute instances create darkintel-vm \
  --zone=$ZONE \
  --machine-type=e2-standard-4 \
  --subnet=darkintel-subnet \
  --no-address \
  --tags=darkintel \
  --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud \
  --boot-disk-size=50GB --boot-disk-type=pd-balanced \
  --no-service-account --no-scopes \
  --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring \
  --metadata=enable-oslogin=TRUE
```

| Opción | Para qué |
|---|---|
| `e2-standard-4` | 4 vCPU / 16 GB RAM: PyTorch + SecureBERT + embeddings |
| `--no-address` | Sin IP pública |
| `--no-service-account --no-scopes` | La VM no tiene ningún permiso sobre GCP |
| `--shielded-*` | Arranque verificado: detecta manipulación del sistema de arranque |
| `enable-oslogin` | El acceso SSH se controla con tu cuenta de Google, no con llaves sueltas |

### 0.5 Entrar a la VM

```bash
gcloud compute ssh darkintel-vm --zone=$ZONE --tunnel-through-iap
```

La primera vez pide crear una llave SSH: aceptar (Enter). A partir de aquí,
los comandos se ejecutan **dentro de la VM** hasta que se indique lo contrario.

### 0.6 Instalar Docker (dentro de la VM)

```bash
sudo apt-get update
sudo apt-get install -y docker.io docker-compose-v2 git
sudo usermod -aG docker $USER
exit
```

Volver a entrar (para que el grupo `docker` tenga efecto) y comprobar:

```bash
gcloud compute ssh darkintel-vm --zone=$ZONE --tunnel-through-iap
docker run --rm hello-world
docker compose version
```

### 0.7 Traer el código (dentro de la VM)

**Si el repositorio es público:**

```bash
git clone -b feat/ner-transformer https://github.com/JuanLeal05/DarkIntel.git darkintel
```

**Si es privado**, con una *deploy key* de solo lectura (la VM solo puede
leer ese repositorio, nada más de tu cuenta):

```bash
ssh-keygen -t ed25519 -f ~/.ssh/darkintel_deploy -N "" -C "darkintel-vm"
cat ~/.ssh/darkintel_deploy.pub
```

En GitHub → repositorio → *Settings → Deploy keys → Add deploy key*: pegar la
llave pública, **sin** marcar "Allow write access". Después:

```bash
cat >> ~/.ssh/config <<'EOF'
Host github.com
  IdentityFile ~/.ssh/darkintel_deploy
  IdentitiesOnly yes
EOF
git clone -b feat/ner-transformer git@github.com:JuanLeal05/DarkIntel.git darkintel
```

### 0.8 Configurar `.env` (dentro de la VM)

**Contraseñas nuevas, distintas de las de tu portátil.**

```bash
cd ~/darkintel
cp .env.example .env
chmod 600 .env
# Generar contraseñas aleatorias:
sed -i "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$(openssl rand -hex 24)/" .env
sed -i "s/^TOR_CONTROL_PASSWORD=.*/TOR_CONTROL_PASSWORD=$(openssl rand -hex 24)/" .env
grep -c "=$" .env   # cuántas variables siguen vacías (SCRAPER_TARGET_URL puede quedar vacía)
```

### 0.9 Comprobaciones de la Fase 0 (dentro de la VM)

```bash
cd ~/darkintel
docker compose build            # 10-20 min la primera vez

# 1. Tor funciona desde la red de Google
docker compose up -d tor-proxy
sleep 60
docker compose exec tor-proxy curl -s --socks5-hostname localhost:9050 \
  https://check.torproject.org/api/ip          # debe decir "IsTor":true

# 2. El scraper no tiene internet directo (debe FALLAR)
docker compose run --rm --entrypoint python scraper -c \
  "import requests; requests.get('https://example.com', timeout=5)"

# 3. Pipeline completo con el hidden service propio (Etapa 1 de SAFE_TESTING.md)
docker compose --profile testing up -d test-onion
sleep 60
ONION=$(docker compose exec -T test-onion cat /var/lib/tor/test_service/hostname | tr -d '\r\n')
docker compose --profile testing run --rm \
  -e SCRAPER_TARGET_URL="http://$ONION/post1.html,http://$ONION/post2.html,http://$ONION/post3.html,http://$ONION/post4.html" \
  scraper
docker compose up -d api        # ejecuta el processor y luego levanta la API
docker compose logs processor | tail -20
curl -s localhost:8000/stats    # debe decir "campanas_detectadas": 2
docker compose --profile testing down
```

### 0.10 Ver la API desde tu portátil

Requiere instalar **Google Cloud CLI** en Windows
(cloud.google.com/sdk/docs/install) y ejecutar `gcloud auth login` una vez.
En **PowerShell, en tu portátil**:

```powershell
gcloud compute ssh darkintel-vm --project <PROJECT_ID> --zone us-east1-b --tunnel-through-iap -- -N -L 8000:localhost:8000
```

Mientras esa ventana siga abierta, http://localhost:8000/docs en tu navegador
muestra la API que corre en GCP. La API nunca se expone a internet.

### 0.11 Snapshot limpio y apagar (de vuelta en Cloud Shell)

```bash
gcloud compute instances stop darkintel-vm --zone=$ZONE
gcloud compute disks snapshot darkintel-vm --zone=$ZONE \
  --snapshot-names=darkintel-base-$(date +%Y%m%d)
```

**Apagar siempre al terminar.** Apagada solo cuesta el disco y los snapshots.

```bash
gcloud compute instances start darkintel-vm --zone=$ZONE   # para volver a trabajar
```

---

## Fase 1 — Versión de la demo

Cuando la rama tenga la versión a presentar (dentro de la VM):

```bash
cd ~/darkintel && git pull
docker compose build processor api scraper
docker compose up -d api           # ejecuta el pipeline y levanta la API
docker compose logs processor | tail -30
```

Repetir las comprobaciones de 0.9 y, si todo está bien, crear un snapshot
"listo para la demo" desde Cloud Shell:

```bash
gcloud compute instances stop darkintel-vm --zone=$ZONE
gcloud compute disks snapshot darkintel-vm --zone=$ZONE \
  --snapshot-names=darkintel-demo-$(date +%Y%m%d)
```

El día de la presentación: arrancar la VM, levantar `tor-proxy` y
`test-onion` unos minutos antes (para que Tor tenga circuitos listos) y abrir
el túnel de 0.10 desde el portátil.

---

## Operación y OPSEC

| Regla | Motivo |
|---|---|
| Solo **cliente** Tor: nunca configurar `ORPort`, `ExitRelay` ni relays | Operar relays/nodos de salida desde la nube trae problemas de abuso y de política del proveedor |
| Snapshot limpio **antes** de cada sesión de scraping real, y revertir después | Práctica de VM desechable de `SAFE_TESTING.md` |
| Antes de la Etapa 3 (objetivos reales), revisar la política de uso aceptable de GCP y confirmarlo con el profesor | La cuenta de GCP está a tu nombre |
| No copiar el `.env` de la VM a ningún otro lugar | Son credenciales del entorno desplegado |
| Apagar la VM al terminar y mantener la alerta de presupuesto | Evita costes sorpresa |

### Restaurar desde un snapshot

```bash
gcloud compute instances stop darkintel-vm --zone=$ZONE
gcloud compute instances detach-disk darkintel-vm --disk=darkintel-vm --zone=$ZONE
gcloud compute disks delete darkintel-vm --zone=$ZONE
gcloud compute disks create darkintel-vm --zone=$ZONE \
  --source-snapshot=<nombre-del-snapshot> --type=pd-balanced
gcloud compute instances attach-disk darkintel-vm --disk=darkintel-vm --zone=$ZONE --boot
gcloud compute instances start darkintel-vm --zone=$ZONE
```

### Borrar todo al terminar el proyecto

```bash
gcloud projects delete $PROJECT_ID
```
