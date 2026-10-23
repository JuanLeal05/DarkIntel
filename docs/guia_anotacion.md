# Guía de escritura y anotación del dataset de la demo

Este documento define cómo se construye la muestra sobre la que DarkIntel
mide sus dos métricas del paper:

- **Precisión ≥ 85 %** en la extracción automática frente a un etiquetado manual.
- **Reducción ≥ 70 %** del tiempo de identificación y catalogación manual.

Ambas se miden *"sobre la misma muestra usada en la demo"*. Por eso esta
muestra es, a la vez, el contenido del `.onion` de la demo y el examen del
sistema. Si la muestra es fácil o está contaminada, las métricas no valen.

---

## 1. Roles y reglas de independencia

| Rol | Quién | Qué hace |
|---|---|---|
| **Escritor** | Karol | Escribe los posts y define las campañas |
| **Anotador A** | Karol | Anota todos los posts |
| **Anotador B** | Juan | Anota todos los posts, sin ver la anotación de A |
| **Desarrollador** | David | Programa el NER. **No anota** |

Reglas:

1. **Quien programa el NER no anota.** Si no, la anotación se parece
   inconscientemente a lo que el código ya detecta y la métrica sale inflada.
2. **Los anotadores trabajan por separado** y no comparan resultados hasta
   terminar. Las diferencias se resuelven al final (sección 7).
3. **Nadie ajusta el sistema mirando el conjunto de prueba.** El desarrollador
   solo usa el conjunto `dev` para calibrar umbrales o entrenar. El conjunto
   `test` se evalúa **una sola vez**, al final, para las métricas del paper.

---

## 2. Qué hay que producir

```
data/demo/
├── posts.jsonl                  # los posts (escritor)
├── campanas.json                # qué posts pertenecen a qué campaña (escritor)
├── anotaciones_A.jsonl          # anotador A
├── anotaciones_B.jsonl          # anotador B
├── anotaciones_final.jsonl      # versión acordada tras resolver diferencias
└── tiempos.csv                  # tiempo de anotación manual (métrica del 70 %)
```

`.jsonl` significa **un objeto JSON por línea**. Un post = una línea.

---

## 3. Escritura de los posts (escritor)

### 3.1 Cantidad y estructura

- **45 posts en total**, en **inglés** (el modelo NER rinde mucho peor en
  español, y los foros reales están mayoritariamente en inglés o ruso).
- **4 campañas** de 9 posts cada una (36 posts) + **9 posts de ruido**
  (no pertenecen a ninguna campaña).
- Cada post entre **40 y 200 palabras**, con estilo de foro: informal,
  abreviaturas, faltas ocasionales, emojis o separadores (`---`, `>>`).

Una **campaña** es un conjunto de posts que hablan de la misma operación y
comparten algo verificable: infraestructura (IPs, dominios), malware,
herramientas o actor. Ideas:

| Campaña | Tema | Elementos compartidos |
|---|---|---|
| 1 | Afiliados de un ransomware ofreciendo accesos y builds | Malware, 2–3 IPs de C2, un dominio `.onion` de pago |
| 2 | Venta de logs de un infostealer | Malware stealer, panel en una IP, hashes del binario |
| 3 | Venta de accesos iniciales (RDP/VPN) a empresas ficticias | Técnica (brute force, phishing), herramientas (AnyDesk, Rclone) |
| 4 | Explotación de una vulnerabilidad publicada | CVE, PoC, herramientas de escaneo, IPs de escáneres |

Dentro de una campaña los posts **no deben ser copias**: unos mencionan solo
parte de los indicadores, otros los repiten ofuscados de otra forma, otros
añaden uno nuevo. Así el clustering tiene que trabajar de verdad.

Los **posts de ruido** son conversación de foro sin relación con las
campañas: reglas del foro, presentaciones, quejas sobre un moderador, preguntas
técnicas genéricas, ofertas de servicios VPN o hosting. Al menos **4** de ellos
**sin ningún IoC ni entidad**: sirven para medir falsos positivos.

### 3.2 Casos difíciles obligatorios

Repartidos entre los posts, deben aparecer **todos** estos al menos una vez.
Una muestra sin casos difíciles da una precisión que no significa nada.

| Caso | Ejemplo |
|---|---|
| IP ofuscada con corchetes | `198[.]51[.]100[.]23` |
| IP ofuscada con espacios o `(dot)` | `203 . 0 . 113 . 9`, `192(dot)0(dot)2(dot)44` |
| URL con `hxxp` | `hxxp://payments-check[.]com/gate.php` |
| Número de versión con forma de IP | `builder v2.4.1.7`, `Chrome 120.0.6099.71` |
| IP privada (no es IoC) | `connect to 192.168.1.10 on the victim LAN` |
| Lista de MD5, uno por línea | tres hashes de 32 caracteres en líneas seguidas |
| SHA-256 partido en dos líneas | 32 + 32 caracteres, con la palabra `sha256` antes |
| SHA-1 | 40 caracteres hexadecimales |
| Dominio dentro de un email (no es IoC) | `contact me at admin@protonmail.com` |
| Dominio legítimo (no es IoC) | `upload it to github.com`, `check it on virustotal.com` |
| Nombre de archivo con forma de dominio | `run setup.exe`, `read readme.info` |
| Malware con versión | `LockBit 3.0`, `RedLine v2` |
| Herramienta seguida de palabra genérica | `Cobalt Strike beacon`, `Mimikatz dump` |
| Mismo nombre como malware y como grupo | `LockBit encrypted the DC` vs `LockBit affiliates are recruiting` |
| Alias o abreviatura | `CS beacon` (Cobalt Strike), `mimi` (Mimikatz) |
| Técnica nombrada | `spear-phishing`, `credential stuffing`, `kerberoasting` |
| CVE en minúsculas o entre paréntesis | `(cve-2023-4966)` |

### 3.3 Seguridad del contenido — obligatorio

Los posts imitan un foro criminal, pero **no pueden contener nada que funcione
de verdad ni que identifique a alguien real**.

| Elemento | Usar | No usar nunca |
|---|---|---|
| IPv4 | Solo rangos de documentación: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` | Cualquier otra IP |
| IPv6 | Solo `2001:db8::/32` | Cualquier otra |
| Dominios | Inventados y claramente falsos (`ransom-pay-test.onion`, `stealer-panel-demo.cc`) | Dominios que existan |
| Hashes | Hashes de cadenas triviales (`echo -n "post7-a" \| sha256sum`) | Hashes de malware real |
| CVEs | Reales y públicos (`CVE-2021-44228`) o inventados | — |
| Malware, herramientas, actores | Nombres reales y públicos (LockBit, Cobalt Strike, FIN7): el modelo debe reconocerlos | — |
| Víctimas | Empresas y personas **inventadas** | Empresas, personas o datos personales reales |
| Instrucciones | Descripciones vagas ("works on unpatched boxes") | Código de exploit, comandos funcionales o pasos reproducibles |

### 3.4 Formato de `posts.jsonl`

Una línea por post:

```json
{"post_id": "p01", "split": "dev", "title": "LB3 affiliate spots open", "text": "Recruiting pentesters for LockBit 3.0 ..."}
```

| Campo | Regla |
|---|---|
| `post_id` | `p01` … `p45`, sin huecos |
| `split` | `dev` o `test` (ver 3.5) |
| `title` | Título del hilo |
| `text` | Cuerpo del post. Los saltos de línea se escriben como `\n` |

### 3.5 División `dev` / `test`

- En **cada campaña**: 4 posts `dev` y 5 posts `test`.
- En el **ruido**: 4 `dev` y 5 `test`.
- Total: **16 `dev`** (calibrar y, si hace falta, entrenar) y **29 `test`**
  (métricas finales y demo en el `.onion`).
- Cada caso difícil de 3.2 debe aparecer **al menos una vez en `test`**.
- El escritor decide el `split` **antes** de que nadie anote.

### 3.6 Formato de `campanas.json`

```json
{
  "campana_1": ["p01", "p02", "p03", "p04", "p05", "p06", "p07", "p08", "p09"],
  "campana_2": ["p10", "..."],
  "ruido":     ["p37", "..."]
}
```

Sirve para evaluar el clustering: ¿agrupó el sistema lo que el escritor diseñó
como una misma campaña?

---

## 4. Qué se anota

Para cada post se anotan **IoCs** (indicadores técnicos) y **entidades**
(conceptos con nombre).

### 4.1 IoCs

| Tipo | Se anota | **No** se anota |
|---|---|---|
| `ip` | IPv4 públicas, incluidas las de documentación (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`) | IPs privadas (`10.x`, `172.16–31.x`, `192.168.x`), loopback, `0.0.0.0`, multicast, números de versión |
| `ipv6` | IPv6 globales, incluido `2001:db8::/32` | `::1`, `fe80::…`, direcciones MAC, horas tipo `12:30:45` |
| `md5` | 32 hex | Hash de archivo vacío `d41d8cd98f00b204e9800998ecf8427e` |
| `sha1` | 40 hex | Hash de archivo vacío `da39a3ee5e6b4b0d3255bfef95601890afd80709` |
| `sha256` | 64 hex. Si está partido en dos líneas, se anota **unido** | Hash de archivo vacío `e3b0c442…b855` |
| `cve` | `CVE-AAAA-NNNN…` | — |
| `dominio` | Hostnames usados como infraestructura del atacante: C2, paneles, mirrors, mercados, pago. Incluye `.onion` | Dominios de proveedores legítimos (github.com, protonmail.com, virustotal.com), la parte de dominio de un **email**, nombres de archivo |

**Normalización obligatoria** (para que A, B y el sistema escriban lo mismo):

- Quitar la ofuscación: `198[.]51[.]100[.]23` → `198.51.100.23`;
  `evil[.]com` → `evil.com`.
- Hashes en **minúsculas**; CVEs en **MAYÚSCULAS**.
- Dominios en minúsculas, **sin** `http://`, sin ruta y sin puerto:
  `hxxp://Panel-Demo[.]cc:8080/gate.php` → `panel-demo.cc`.
- Subdominios completos tal como aparecen: `forum.market-demo.onion`.
- Una URL basada en IP se anota como `ip`.
- Cada valor **una sola vez** por post, aunque aparezca varias veces.

### 4.2 Entidades

| Tipo | Qué es | Ejemplos |
|---|---|---|
| `malware` | Software diseñado con fines maliciosos: familias de ransomware, stealers, loaders, RATs, botnets | LockBit, BlackCat, RedLine, Lumma, Emotet, QakBot |
| `herramienta` | Software legítimo o de doble uso que el atacante utiliza | Cobalt Strike, Mimikatz, PsExec, AnyDesk, Rclone, Metasploit, Nmap, sqlmap |
| `actor` | Grupo u operador con nombre propio | FIN7, APT29, Lazarus, Scattered Spider, "LockBit" cuando se refiere al grupo |
| `tecnica` | Método de ataque con nombre reconocible | phishing, spear-phishing, credential stuffing, brute force, SQL injection, kerberoasting, DLL sideloading |

**Reglas para los casos ambiguos** — son las decisiones del equipo; si
aparece un caso nuevo, se añade a la tabla de la sección 9:

1. **Malware o herramienta:** si el software se creó para atacar → `malware`.
   Si es legítimo o comercial y el atacante lo reutiliza → `herramienta`.
   Cobalt Strike y Mimikatz son `herramienta`.
2. **Mismo nombre como malware y como grupo:** se decide por el **papel en la
   frase**. "LockBit encrypted the file server" → `malware`. "LockBit
   affiliates / operators / gang" → `actor`. Un mismo post puede tener las dos.
3. **Versiones:** se anota el **nombre base sin versión**:
   `LockBit 3.0` → `LockBit`; `RedLine v2` → `RedLine`.
4. **Palabras genéricas pegadas al nombre** no forman parte de él:
   `Cobalt Strike beacon` → `Cobalt Strike`; `Mimikatz dump` → `Mimikatz`.
5. **Alias y abreviaturas** se anotan **tal como aparecen**: `CS beacon` →
   `CS`; `mimi` → `mimi`. (La equivalencia `CS = Cobalt Strike` la resuelve el
   sistema, no la anotación.)
6. **Categorías genéricas no son entidades:** "ransomware", "a stealer",
   "some RAT", "malware", "exploit", "hacking" **no** se anotan.
7. **Nombres de usuario del foro** (`xX_k1ng_Xx`) **no** se anotan como actor
   en esta versión.
8. **Técnicas:** solo nombres reconocibles de un método. Verbos genéricos
   ("hack", "attack", "break in") no se anotan. Se escriben en minúsculas.
9. **Ante la duda, no se anota** y se apunta el caso en la sección 9 para
   discutirlo al final.

---

## 5. Formato de las anotaciones

`anotaciones_A.jsonl` y `anotaciones_B.jsonl`: **una línea por post**, con
**todas** las claves aunque estén vacías:

```json
{"post_id": "p01", "iocs": {"ip": ["198.51.100.23"], "ipv6": [], "md5": [], "sha1": [], "sha256": [], "cve": ["CVE-2023-4966"], "dominio": ["ransom-pay-test.onion"]}, "entidades": {"malware": ["LockBit"], "herramienta": ["Cobalt Strike"], "actor": [], "tecnica": ["spear-phishing"]}}
```

- Un post sin nada se anota igual, con todas las listas vacías (es un dato
  importante: mide falsos positivos).
- Se anotan **los 45 posts**, `dev` y `test`.
- El JSON escrito a mano se rompe fácil: antes de entregar, validar con el
  script del repositorio (se añadirá en `pipeline/validar_anotaciones.py`).

---

## 6. Medición del tiempo manual (métrica del 70 %)

La anotación del conjunto `test` **es** la línea base de tiempo: es exactamente
el trabajo que DarkIntel pretende ahorrar.

Cada anotador, al anotar los **29 posts de `test`**:

1. Lo hace en **una sola sesión**, sin interrupciones largas.
2. Usa solo un editor de texto. Sin scripts, sin regex, sin buscar en internet
   (un analista que cataloga a mano).
3. Anota hora de inicio y fin en `tiempos.csv`:

```csv
anotador,split,inicio,fin,posts,notas
A,test,2026-10-28 15:00,2026-10-28 16:20,29,
B,test,2026-10-29 10:05,2026-10-29 11:40,29,pausa de 5 min
```

El conjunto `dev` también se anota, pero **no se cronometra**: sirve de
práctica para que el tiempo de `test` refleje a un analista ya familiarizado
con la tarea.

---

## 7. Resolución de diferencias

Cuando A y B terminan:

1. Se mide el acuerdo entre los dos (script en el repositorio). Un acuerdo
   bajo indica que esta guía es ambigua y hay que aclararla.
2. Se revisan **juntos** solo los valores en los que difieren.
3. Se decide por la regla de esta guía; si la guía no lo cubre, se añade la
   decisión a la sección 9.
4. El resultado acordado va a `anotaciones_final.jsonl`, que es la referencia
   ("ground truth") contra la que se evalúa el sistema.

El nivel de acuerdo entre A y B se reporta en el paper: demuestra que la
referencia es fiable y no la opinión de una sola persona.

---

## 8. Lista de verificación antes de entregar

**Escritor**
- [ ] 45 posts en inglés, `p01`–`p45`
- [ ] 4 campañas × 9 posts + 9 de ruido; al menos 4 posts sin nada
- [ ] 16 `dev` / 29 `test`, repartidos como en 3.5
- [ ] Todos los casos difíciles de 3.2, cada uno al menos una vez en `test`
- [ ] Solo IPs/dominios/hashes seguros (3.3); sin víctimas reales ni instrucciones funcionales
- [ ] `campanas.json` completo

**Cada anotador**
- [ ] 45 líneas, todas con todas las claves
- [ ] Normalización de 4.1 aplicada
- [ ] Reglas de 4.2 aplicadas
- [ ] Validado con el script
- [ ] Tiempo de `test` registrado en `tiempos.csv`

---

## 9. Registro de decisiones

Casos nuevos que la guía no cubría y cómo se resolvieron. Ambos anotadores
aplican estas decisiones desde el momento en que se agregan.

| Fecha | Caso | Decisión |
|---|---|---|
| 2026-10-22 | `LockBit 3.0` | Nombre base sin versión: `LockBit` (regla 4.2.3) |
| 2026-10-22 | `Cobalt Strike beacons` | `Cobalt Strike`, tipo `herramienta` (reglas 4.2.1 y 4.2.4) |
| 2026-10-22 | Mimikatz | `herramienta` (regla 4.2.1) |
| | | |