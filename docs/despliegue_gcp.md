# Despliegue de DarkIntel en Google Cloud (Compute Engine)

DarkIntel se despliega en **una sola VM** que ejecuta el mismo
`docker compose` que en local. Así se conservan intactos el aislamiento de
red de P0 (cuatro redes Docker, volúmenes compartidos, Tor como servicio).

```
 Tu portátil ── túnel SSH por IAP (HTTPS, OS Login + 2FA) ──► VM darkintel-vm (sin IP pública)
                                                                 │
                                                                 │ docker compose (sin capacidades,
                                                                 │  límites de memoria, firewall DOCKER-USER)
                                                                 │  tor-proxy, scraper, processor, db, api
                                                                 ▼
                                                   Cloud NAT ──► internet (solo salida: Tor, apt, imágenes)
```

| Decisión | Motivo |
|---|---|
| VM **sin IP pública** | Nadie puede iniciar una conexión hacia la VM desde internet |
| Acceso solo por **IAP** + **OS Login con 2FA** | SSH sin abrir el puerto 22 al mundo, ligado a cuentas de Google con verificación en dos pasos; no hay llaves SSH sueltas que robar |
| **Cloud NAT** con registro | La VM necesita salida (Tor, apt, Docker, HuggingFace); los registros dejan rastro de a dónde salió |
| Red VPC **propia** | La red `default` trae reglas que abren SSH y RDP a todo internet |
| **Sin cuenta de servicio** | La VM no tiene permisos sobre el proyecto; si se compromete, no puede tocar nada de GCP |
| **Firewall `DOCKER-USER`** en la VM | Ningún contenedor alcanza el servidor de metadatos de GCP, y la API no puede iniciar conexiones hacia afuera |
| Contenedores **sin capacidades**, con límites | Un `.onion` hostil no puede escalar privilegios ni agotar la VM |
| **IAM mínimo** por persona | Quien solo mira la API no puede administrar la VM ni Docker |
| **Snapshots** regionales | Implementan la "VM desechable" de `SAFE_TESTING.md`: estado limpio antes de cada sesión, revertir después |

> **Dónde ejecutar los comandos:** salvo que se indique otra cosa, todo se
> ejecuta en **Cloud Shell** (el botón `>_` arriba a la derecha en
> console.cloud.google.com). Es una terminal **bash** con `gcloud` ya
> instalado y autenticado. No usar PowerShell para esta guía.

---

## Fase 0 — Infraestructura

Objetivo: dejar la VM creada, endurecida y con Tor funcionando. Tiempo
estimado: 1–2 horas (la mayor parte es el `docker compose build`).

### 0.0 Requisito previo: verificación en dos pasos

Cada persona que vaya a entrar a la VM debe tener **activada la verificación
en dos pasos** en su cuenta de Google (myaccount.google.com → Seguridad).
La VM exige 2FA en cada conexión SSH (paso 0.4); sin ella, no se puede entrar.

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
   olvidarse la VM encendida, y también una alarma temprana si alguien
   abusara del proyecto.

Activar **solo** las APIs que se usan:

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

# ÚNICA regla de entrada: SSH desde el rango de IAP de Google, con registro
# de cada conexión. Todo lo demás queda bloqueado (GCP deniega la entrada
# por defecto).
gcloud compute firewall-rules create darkintel-allow-iap-ssh \
  --network=darkintel-net --direction=INGRESS --action=allow \
  --rules=tcp:22 --source-ranges=35.235.240.0/20 --target-tags=darkintel \
  --enable-logging

# Salida a internet sin IP pública, registrando las conexiones
gcloud compute routers create darkintel-router \
  --network=darkintel-net --region=$REGION
gcloud compute routers nats create darkintel-nat \
  --router=darkintel-router --region=$REGION \
  --auto-allocate-nat-external-ips --nat-all-subnet-ip-ranges \
  --enable-logging --log-filter=ALL
```

Comprobar que la red tiene **una sola** regla de firewall:

```bash
gcloud compute firewall-rules list --filter="network:darkintel-net" \
  --format="table(name,direction,sourceRanges.list(),allowed[].map().firewall_rule().list())"
```

✅ Debe aparecer solo `darkintel-allow-iap-ssh`.

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
  --metadata=enable-oslogin=TRUE,enable-oslogin-2fa=TRUE,block-project-ssh-keys=TRUE \
  --deletion-protection
```

| Opción | Para qué |
|---|---|
| `e2-standard-4` | 4 vCPU / 16 GB RAM: PyTorch + SecureBERT + embeddings |
| `--no-address` | Sin IP pública |
| `--no-service-account --no-scopes` | La VM no tiene ningún permiso sobre GCP |
| `--shielded-*` | Arranque verificado: detecta manipulación del sistema de arranque |
| `enable-oslogin` | El acceso SSH se controla con IAM y tu cuenta de Google, no con llaves sueltas |
| `enable-oslogin-2fa` | Cada conexión SSH pide el segundo factor |
| `block-project-ssh-keys` | Ignora llaves SSH puestas a nivel de proyecto |
| `--deletion-protection` | Evita borrar la VM por error (se quita al final, ver "Borrar todo") |

> Si después de activar 2FA no puedes entrar (por ejemplo, olvidaste el paso
> 0.0), desactívalo temporalmente desde Cloud Shell:
> `gcloud compute instances add-metadata darkintel-vm --zone=$ZONE --metadata=enable-oslogin-2fa=FALSE`,
> activa la verificación en dos pasos y vuelve a ponerlo en `TRUE`.

### 0.5 Entrar a la VM

```bash
gcloud compute ssh darkintel-vm --zone=$ZONE --tunnel-through-iap
```

La primera vez pide crear una llave SSH: aceptar (Enter). Luego pide el
segundo factor. A partir de aquí, los comandos se ejecutan **dentro de la
VM** hasta que se indique lo contrario.

### 0.6 Preparar el sistema y Docker (dentro de la VM)

```bash
sudo apt-get update && sudo apt-get -y upgrade
sudo apt-get install -y docker.io docker-compose-v2 git
# Las actualizaciones de seguridad automáticas vienen activas en Ubuntu: comprobarlo
systemctl is-active unattended-upgrades     # debe decir: active
```

Endurecer el daemon de Docker: ningún proceso de contenedor puede ganar
privilegios nuevos, y los logs rotan para que un `.onion` ruidoso no llene el
disco.

```bash
sudo tee /etc/docker/daemon.json >/dev/null <<'EOF'
{
  "no-new-privileges": true,
  "log-driver": "local",
  "log-opts": { "max-size": "10m", "max-file": "3" },
  "live-restore": true
}
EOF
sudo systemctl restart docker
sudo usermod -aG docker $USER
exit
```

> Estar en el grupo `docker` equivale a ser root en la VM. Solo las personas
> con rol de **operador** (paso 0.12) deben estarlo.

Volver a entrar (para que el grupo `docker` tenga efecto) y comprobar:

```bash
gcloud compute ssh darkintel-vm --zone=$ZONE --tunnel-through-iap
docker run --rm hello-world
docker compose version
docker info --format '{{.SecurityOptions}}'   # debe incluir no-new-privileges
```

### 0.7 Traer el código (dentro de la VM)

Usar la rama que se va a presentar (aquí `main`; cambiarla si es otra).

**Si el repositorio es público:**

```bash
git clone -b main https://github.com/JuanLeal05/DarkIntel.git darkintel
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
git clone -b main git@github.com:JuanLeal05/DarkIntel.git darkintel
```

### 0.8 Configurar `.env` (dentro de la VM)

**Contraseñas nuevas, distintas de las de tu portátil.**

```bash
cd ~/darkintel
cp .env.example .env
chmod 600 .env
# Generar la contraseña aleatoria (Tor ya no usa contraseña de control):
sed -i "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$(openssl rand -hex 24)/" .env
grep -c "=$" .env   # cuántas variables siguen vacías (SCRAPER_TARGET_URL puede quedar vacía)
```

### 0.9 Firewall de contenedores (dentro de la VM)

Docker programa sus propias reglas de red; la cadena `DOCKER-USER` es el
lugar para añadir las nuestras. Las subredes de las cuatro redes están fijas
en `docker-compose.yml` (`172.30.0.0/24` a `172.30.3.0/24`) para que estas
reglas no cambien.

```bash
sudo tee /usr/local/sbin/darkintel-fw.sh >/dev/null <<'EOF'
#!/bin/sh
# Reglas de DarkIntel en DOCKER-USER. Idempotente: se puede correr varias veces.
set -eu
add() { iptables -C DOCKER-USER "$@" 2>/dev/null || iptables -I DOCKER-USER "$@"; }

# 1. Ningún contenedor habla con el servidor de metadatos de GCP.
add -d 169.254.169.254 -j DROP
# 2. La API (red frontend) no inicia conexiones hacia afuera: solo responde.
add -s 172.30.3.0/24 -m conntrack --ctstate NEW -j DROP
EOF
sudo chmod 755 /usr/local/sbin/darkintel-fw.sh

# Aplicarlas cada vez que arranque Docker (también tras reiniciar la VM)
sudo tee /etc/systemd/system/darkintel-fw.service >/dev/null <<'EOF'
[Unit]
Description=Reglas de firewall de DarkIntel para contenedores
After=docker.service
Requires=docker.service
PartOf=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/darkintel-fw.sh
RemainAfterExit=yes

[Install]
WantedBy=docker.service
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now darkintel-fw.service
sudo iptables -S DOCKER-USER
```

✅ Deben aparecer las dos reglas (`169.254.169.254` y `172.30.3.0/24`)
antes del `-j RETURN`.

### 0.10 Comprobaciones de la Fase 0 (dentro de la VM)

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

# 3. El scraper tampoco puede resolver nombres fuera de Tor: sin fuga de DNS
#    (debe FALLAR con socket.gaierror)
docker compose run --rm --no-deps --entrypoint python scraper -c \
  "import socket; print(socket.gethostbyname('example.com'))"

# 4. Ningún contenedor llega al servidor de metadatos (debe FALLAR, código 28 o 7)
docker compose exec tor-proxy curl -s -m 5 -H "Metadata-Flavor: Google" \
  http://169.254.169.254/computeMetadata/v1/ ; echo "codigo de salida: $?"

# 4b. Tor no tiene ControlPort (debe FALLAR con ConnectionRefusedError)
docker compose run --rm --no-deps --entrypoint python scraper -c \
  "import socket; socket.create_connection(('tor-proxy', 9051), 5)"

# 5. Pipeline completo con el hidden service propio (Etapa 1 de SAFE_TESTING.md)
docker compose --profile testing up -d test-onion
sleep 60
ONION=$(docker compose exec -T test-onion cat /var/lib/tor/test_service/hostname | tr -d '\r\n')

# 5a. El scraper NO alcanza test-onion directamente, solo vía Tor (debe FALLAR)
docker compose --profile testing run --rm --no-deps --entrypoint python scraper -c \
  "import socket; socket.create_connection(('test-onion', 8080), 5)"

docker compose --profile testing run --rm \
  -e SCRAPER_TARGET_URL="http://$ONION/post1.html,http://$ONION/post2.html,http://$ONION/post3.html,http://$ONION/post4.html" \
  scraper
docker compose up -d api        # ejecuta el processor y luego levanta la API
docker compose logs processor | tail -20
curl -s localhost:8000/stats    # debe decir "campanas_detectadas": 2

# 6. La API no puede iniciar conexiones hacia afuera (debe FALLAR)
docker compose exec api python -c \
  "import urllib.request; urllib.request.urlopen('https://example.com', timeout=5)"

docker compose --profile testing down
```

Si alguna prueba marcada "debe FALLAR" **funciona**, detenerse: el
aislamiento no está activo y no se debe apuntar el scraper a nada real.

### 0.11 Ver la API desde tu portátil

Requiere instalar **Google Cloud CLI** en Windows
(cloud.google.com/sdk/docs/install) y ejecutar `gcloud auth login` una vez.
En **PowerShell, en tu portátil**:

```powershell
gcloud compute ssh darkintel-vm --project <PROJECT_ID> --zone us-east1-b --tunnel-through-iap -- -N -L 127.0.0.1:8000:localhost:8000
```

Mientras esa ventana siga abierta, http://localhost:8000/docs en tu navegador
muestra la API que corre en GCP. La API nunca se expone a internet.

> El `127.0.0.1:` del túnel es a propósito: nunca usar `-L 0.0.0.0:8000:...`
> ni `-g`, que publicarían la API a toda la red Wi-Fi donde esté el portátil.

### 0.12 Acceso del equipo (de vuelta en Cloud Shell)

Dos perfiles, cada uno con lo mínimo. **Nadie más que el dueño del proyecto
tiene `Owner` o `Editor`.**

| Perfil | Puede | Roles |
|---|---|---|
| **Operador** | Entrar con `sudo`, usar Docker, cambiar la VM | `roles/iap.tunnelResourceAccessor`, `roles/compute.osAdminLogin`, `roles/compute.viewer` |
| **Lector** | Abrir el túnel del paso 0.11 y ver la API | `roles/iap.tunnelResourceAccessor`, `roles/compute.osLogin`, `roles/compute.viewer` |

```bash
# Ejemplo: un compañero como lector
MIEMBRO=user:correo.del.companero@gmail.com
for ROL in roles/iap.tunnelResourceAccessor roles/compute.osLogin roles/compute.viewer; do
  gcloud projects add-iam-policy-binding $PROJECT_ID --member=$MIEMBRO --role=$ROL --condition=None
done

# Revisar quién tiene acceso a qué
gcloud projects get-iam-policy $PROJECT_ID \
  --flatten="bindings[].members" --format="table(bindings.role,bindings.members)"
```

Un lector entra a la VM sin `sudo` y sin el grupo `docker`, así que no puede
leer el `.env`, la base de datos ni los volúmenes con lo recolectado.

### 0.13 Snapshot limpio y apagar (en Cloud Shell)

```bash
gcloud compute instances stop darkintel-vm --zone=$ZONE
gcloud compute disks snapshot darkintel-vm --zone=$ZONE \
  --storage-location=$REGION \
  --snapshot-names=darkintel-base-$(date +%Y%m%d)
```

Los snapshots contienen el `.env`, la deploy key y, después de la Etapa 3,
lo recolectado. Se quedan en la región del proyecto (`--storage-location`)
y se borran los que ya no se usen:

```bash
gcloud compute snapshots list
gcloud compute snapshots delete <nombre>
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

Repetir **todas** las comprobaciones de 0.10 (también las que deben fallar)
y, si todo está bien, crear un snapshot "listo para la demo" desde Cloud
Shell:

```bash
gcloud compute instances stop darkintel-vm --zone=$ZONE
gcloud compute disks snapshot darkintel-vm --zone=$ZONE \
  --storage-location=$REGION \
  --snapshot-names=darkintel-demo-$(date +%Y%m%d)
```

El día de la presentación: arrancar la VM, levantar `tor-proxy` y
`test-onion` unos minutos antes (para que Tor tenga circuitos listos) y abrir
el túnel de 0.11 desde el portátil.

---

## Sesión de scraping real (Etapa 3 de `SAFE_TESTING.md`)

1. Confirmar con el profesor y revisar la política de uso aceptable de GCP.
2. **Restaurar** el snapshot `darkintel-base` o `darkintel-demo` (ver abajo).
3. Repetir las comprobaciones de 0.10.
4. Correr el scraper y el processor. Vigilar con `docker stats`.
5. Sacar de la VM **solo** la salida del pipeline, nunca `data/raw`:

   ```bash
   # dentro de la VM
   docker compose cp api:/app/data/output/stix_bundles.json ~/stix_bundles.json
   ```
   ```bash
   # en Cloud Shell
   gcloud compute scp --tunnel-through-iap --zone=$ZONE darkintel-vm:~/stix_bundles.json .
   ```

6. Apagar y **volver a restaurar** el snapshot limpio, se haya visto algo
   raro o no.

---

## Operación y OPSEC

| Regla | Motivo |
|---|---|
| Solo **cliente** Tor: nunca configurar `ORPort`, `ExitRelay` ni relays | Operar relays/nodos de salida desde la nube trae problemas de abuso y de política del proveedor |
| Snapshot limpio **antes** de cada sesión de scraping real, y revertir después | Práctica de VM desechable de `SAFE_TESTING.md` |
| Antes de la Etapa 3 (objetivos reales), revisar la política de uso aceptable de GCP y confirmarlo con el profesor | La cuenta de GCP está a tu nombre |
| No copiar el `.env` de la VM a ningún otro lugar | Son credenciales del entorno desplegado |
| No sacar `data/raw` de la VM; solo los bundles STIX | Lo crudo es contenido no confiable y puede incluir datos personales de terceros |
| Túnel de la API siempre a `127.0.0.1` | Evita publicarla en la red local del portátil |
| Revisar IAM y la alerta de presupuesto cada semana | Detecta accesos que sobran o uso anómalo |
| Apagar la VM al terminar | Evita costes sorpresa y reduce el tiempo expuesto |

### Tor sin ControlPort

Tor no permite limitar qué comandos acepta su ControlPort: con la contraseña
de control, quien comprometiera el scraper (por ejemplo, un `.onion` que
explote una falla en el parser) podría reconfigurar Tor. Por eso el
`tor-proxy` corre **sin ControlPort** (`ControlPort 0`), y la rotación de
circuitos se hace con credenciales SOCKS aleatorias por objetivo: Tor
(`IsolateSOCKSAuth`) asigna un circuito propio a cada credencial. No hay
contraseña de control en el `.env` ni en ningún contenedor. La prueba 4b de
0.10 confirma que el puerto 9051 está cerrado.

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

1. En GitHub, *Settings → Deploy keys*: borrar la llave `darkintel-vm`.
2. En Cloud Shell:

```bash
gcloud compute instances update darkintel-vm --zone=$ZONE --no-deletion-protection
gcloud projects delete $PROJECT_ID
```
