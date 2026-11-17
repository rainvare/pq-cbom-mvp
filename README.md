# PQ-CBOM MVP

## Problema

Un computador cuántico suficientemente grande rompe en tiempo polinomial
(algoritmo de Shor) la criptografía asimétrica que protege hoy casi todo el
tráfico seguro de internet (RSA, ECDSA, Diffie-Hellman). No se sabe cuándo
va a existir ese computador, pero migrar la infraestructura criptográfica de
una organización — identificar qué usa qué algoritmo, dónde, con qué
prioridad — toma años. El riesgo ya es real hoy: tráfico cifrado
interceptado ahora puede guardarse y descifrarse después
("harvest now, decrypt later").

Para priorizar esa migración hace falta un inventario confiable (CBOM —
Cryptographic Bill of Materials) de qué algoritmo usa cada sistema,
clasificado correctamente como vulnerable o seguro frente a un adversario
cuántico. La necesidad no es que un modelo decida en tiempo real qué
algoritmo usar — eso agrega superficie de ataque sin necesidad. Es
clasificación determinista y auditable, con humano en el loop para la
migración real.

## Solución propuesta

Un pipeline de dos etapas que valida la parte de mayor riesgo del problema
— descubrimiento y clasificación — sin construir infraestructura (sin base
de datos, sin API, sin actualización automática):

```
sample_target/  --[collector de código: regex o semgrep]--\
host:puerto     --[collector de red: sslyze (TLS + cert)]---+--> hallazgos crudos
                --[classifier: rules/pq_rules.yaml]---------->   pq_status + rationale + reemplazo
                --[prioritizer: heurística simple]----------->   score + banda + acción recomendada
                --[cbom.json]--------------------------------->  inventario auditable con evidencia
```

**Dos collectors**, con el mismo pipeline de clasificación/priorización:

- **Código** (`scan`): escanea archivos fuente buscando uso de algoritmos
  criptográficos. Dos motores intercambiables:
  - `--engine regex` (default, sin dependencias): matchea texto por línea.
  - `--engine semgrep`: parsea el AST real por lenguaje (Python, Java, Go,
    JS/TS, YAML), así que no genera falsos positivos por texto dentro de
    comentarios o strings.
- **Red** (`scan-tls`): se conecta a un host vía [sslyze](https://github.com/nabla-c0d3/sslyze)
  y reporta qué versiones de TLS acepta el servidor y el algoritmo de la
  clave pública de su certificado.

**Clasificación determinista**: ambos collectors comparten
`rules/pq_rules.yaml`, una tabla de lookup que mapea cada algoritmo a
`vulnerable` / `at_risk` / `secure` / `unknown` según si lo rompe Shor
(asimétrico) o si Grover reduce su seguridad efectiva a la mitad
(simétrico/hash), con la razón y el reemplazo recomendado (algoritmos NIST
FIPS 203/204/205). La **clasificación** de cada algoritmo es determinista y
auditable (tabla de conocimiento con tests de regresión en
`tests/test_rules_golden.py`). La **detección** de dónde se usa cada algoritmo
es necesariamente heurística (coincidencia de patrones / análisis estático):
señala evidencia para revisión humana y nunca puede garantizar el 100 %.

**Cada hallazgo del CBOM trae evidencia completa**: ubicación
(archivo:línea o host:puerto), snippet, regla aplicada, versión del paquete
de reglas y timestamp — para que la clasificación sea reproducible.

**Qué queda deliberadamente afuera**: actualización automática de
reglas/software, persistencia/base de datos y API. El análisis de binarios y
Docker (`scan-binary`), el de smart contracts (`scan-contracts`) y la web de
demo (`docs/`) existen pero son, respectivamente, heurística sobre strings,
linter por patrón y solo lectura — no sustituyen a herramientas dedicadas.
La priorización y el índice de riesgo son un modelo explícito y simple, no una
valoración de activos con contexto de negocio.

## Cómo levantarla

Requiere Python 3.10+. Se recomienda un entorno virtual dedicado:

```bash
python -m venv .venv
.venv/Scripts/activate   # Windows; en Linux/Mac: source .venv/bin/activate
pip install -r requirements.txt
```

**Escanear código:**

```bash
python -m pq_cbom.cli scan sample_target
python -m pq_cbom.cli scan sample_target --engine semgrep
```

Genera `sample_target/cbom.json` e imprime un resumen por consola. Otras
opciones: `--rules <paquete.yaml>`, `--output <ruta>`, `--quiet`.

**Escanear claves y certificados en disco (tamaño de clave real):**

```bash
python -m pq_cbom.cli scan-keys ./mi-repo
```

Parsea certificados y claves PEM/DER/SSH y extrae el tamaño de cada clave,
marcando las claves cortas (RSA/DSA < 2048, EC < 256).

**Escanear un host (TLS + certificado):**

```bash
python -m pq_cbom.cli scan-tls ejemplo.com --port 443
```

**Correr los tests:**

```bash
python -m pytest -q
```

`semgrep`, `sslyze` y `cryptography` son dependencias opcionales (ya en
`requirements.txt`) usadas por `--engine semgrep`, `scan-tls` y sus tests
respectivos; los tests correspondientes se saltan automáticamente si no
están instaladas. Los tests del collector TLS no dependen de red externa:
levantan un servidor TLS local con certificado autofirmado
(`tests/tls_test_server.py`).

---

## v2 — Modelo cuántico de seguridad (postura cripto)

A partir de la v2, el MVP incorpora tres capas nuevas que lo convierten de un
scanner puntual en una evaluación de postura criptográfica reutilizable:

### A. Base de conocimiento de algoritmos (`knowledge/algorithms.yaml`)

El *saber* se separó de la *detección*. `rules/pq_rules.yaml` ahora solo
contiene detectores (`id` + patrones regex); la clasificación canónica de cada
algoritmo vive en `knowledge/algorithms.yaml`: familia, problema matemático,
ataque cuántico relevante (Shor/Grover), bits de seguridad clásicos vs.
cuánticos, estado NIST, estándar, fecha de deprecación, reemplazo y
referencias. Es la fuente de verdad única y auditable.

```bash
python -m pq_cbom.cli kb              # lista todos los algoritmos
python -m pq_cbom.cli kb kyber        # consulta un algoritmo (o alias)
```

### B. Descubrimiento pasivo (`scan-passive`)

Inventaría la superficie criptográfica de un dominio a partir de información
pública, sin desplegar un escaneo intrusivo:

- **Certificate Transparency (crt.sh)** — totalmente pasivo: enumera los hosts
  del dominio y analiza la criptografía de los certificados ya publicados
  (tipo de clave, algoritmo de firma). **No contacta al objetivo.**
- **TLS + cabeceras HTTP** — una conexión normal (como un navegador) que lee la
  versión y suite TLS negociadas y las cabeceras de seguridad (HSTS…).
- **DNS (DNSSEC + CAA)** — vía resolver público (DNS-over-HTTPS), sin tocar el
  objetivo: detecta el algoritmo de firma de la zona DNSSEC y los registros CAA.
- **JWKS / OpenID** — algoritmos de firma de JWT publicados en
  `/.well-known/jwks.json` (contacta al objetivo, requiere autorización).

```bash
python -m pq_cbom.cli scan-passive ejemplo.com            # CT logs + TLS/cabeceras
python -m pq_cbom.cli scan-passive ejemplo.com --ct-only  # solo CT logs (pasivo puro)
```

> **Autorización.** CT logs es siempre seguro (no toca al objetivo). La parte
> TLS/cabeceras contacta al dominio: úsala solo contra activos propios o con
> autorización explícita (programa de bug bounty con *scope*, contrato de
> pentest). Esta herramienta es para evaluar la postura cripto de tu propia
> organización, no para analizar sistemas de terceros sin permiso.

### C. Modelo de riesgo cuántico (`risk`)

Agrega un `cbom.json` en una evaluación accionable a nivel de organización:

- **Preparación cuántica**: % de activos ya cuántico-seguros.
- **Exposición HNDL** (*harvest now, decrypt later*): activos asimétricos
  rompibles por Shor — datos cifrados hoy que un adversario puede almacenar
  para descifrar tras el Q-day.
- **Teorema de Mosca**: si la vida útil del dato (X) + el tiempo de migración
  (Y) supera los años hasta el Q-day (Z), la organización **ya** está en riesgo.
- **Índice de riesgo** y **hoja de ruta** por banda de prioridad.

```bash
python -m pq_cbom.cli risk cbom.json
python -m pq_cbom.cli risk cbom.json --shelf-life 15 --migration-time 5 --qday 10
```

### Pipeline completo

```bash
python -m pq_cbom.cli scan ./mi-repo --output cbom.json   # o scan-tls / scan-passive
python -m pq_cbom.cli risk cbom.json                       # evaluación de riesgo
```

---

## Sitio web (landing + demo)

El directorio `docs/` contiene una landing que explica problema y solución, y una
**demo interactiva** que renderiza un reporte real generado por el escáner:
KPIs de postura, preparación cuántica, el teorema de Mosca con sliders en vivo,
top de riesgos HNDL, hoja de ruta y la base de conocimiento buscable.

Es estático (HTML/CSS/JS vanilla, sin build). Los datos de la demo están
empaquetados como JS (`docs/data/*.js`) para que funcione incluso abriendo el
archivo directamente. Para regenerarlos desde el código:

```bash
python -m pq_cbom.cli scan sample_target --output /tmp/cbom.json --quiet
python - <<'PY'
import json
from pq_cbom.knowledge import KnowledgeBase
kb = KnowledgeBase.load()
cbom = json.load(open('/tmp/cbom.json'))
open('docs/data/sample_cbom.js','w').write('window.SAMPLE_CBOM = '+json.dumps(cbom, ensure_ascii=False)+';')
open('docs/data/knowledge.js','w').write('window.KNOWLEDGE = '+json.dumps(
    {'version': kb.version, 'algorithms':[e.to_dict() for e in kb.all()]}, ensure_ascii=False)+';')
PY
```

Para servirlo: cualquier hosting estático (Netlify, GitHub Pages) apuntando a `docs/` (GitHub Pages usa esa carpeta).

---

## v4 — Dependencias, modo CI y smart contracts

### Collector de dependencias (`scan-deps`)

Encuentra la criptografía que entra por librería (aunque no aparezca ningún
algoritmo en el código). Lee `package.json`, `requirements.txt`, `go.mod`,
`pom.xml`, `Cargo.toml`, `Gemfile`... Mapea paquetes a algoritmos cuando es
inequívoco (elliptic → ECDSA, bcrypt → bcrypt) y marca librerías abandonadas o
con CVE conocida. *No es un feed de CVE completo* (lista curada); OSV.dev sería
el siguiente paso.

```bash
python -m pq_cbom.cli scan-deps ./mi-repo
```

### Modo CI (`--fail-on`) y tamaño de clave

- `scan`, `scan-keys`, `scan-deps` aceptan `--fail-on {vulnerable,at_risk,unknown}`
  y devuelven código de salida 1 para romper un build.
- `risk` acepta `--fail-on {critical,high,medium,low}` según la banda de riesgo.
- El modelo de riesgo ahora cuenta **claves cortas** (RSA/DSA <2048, EC <256),
  débiles ya hoy, detectadas por `scan-keys`.

```bash
python -m pq_cbom.cli scan ./repo --fail-on vulnerable     # falla si hay cripto rota
python -m pq_cbom.cli risk cbom.json --fail-on high        # falla si el riesgo es alto
```

### Análisis de smart contracts (`scan-contracts`)

Linter estático de vulnerabilidades de Solidity alineado con el
[SWC Registry](https://swcregistry.io): reentrancy (SWC-107), tx.origin
(SWC-115), delegatecall (SWC-112), selfdestruct (SWC-106), aleatoriedad débil
(SWC-120), overflow en <0.8 (SWC-101), pragma flotante (SWC-103) y más. Incluye
el puente cripto/post-cuántico: `ecrecover` usa ECDSA sobre secp256k1,
vulnerable a Shor. Es heurística por patrón para revisión humana (puede dar
falsos positivos), no análisis simbólico.

```bash
python -m pq_cbom.cli scan-contracts ./contracts --fail-on high
```

---

## v5 — Slither, OSV.dev y binarios/Docker

### Motor Slither para contratos (`scan-contracts --engine slither`)

Igual que `--engine semgrep` para código: `--engine slither` usa el AST real de
Solidity (compila con solc) en vez de regex, eliminando falsos positivos.
Requiere `slither-analyzer` y `solc`; si no están, el CLI lo indica y sugiere el
motor `regex`.

```bash
python -m pq_cbom.cli scan-contracts ./contracts --engine slither
```

### OSV.dev — CVEs reales de dependencias (`scan-deps --osv`)

Consulta la base pública [OSV.dev](https://osv.dev) por las vulnerabilidades
reales (CVE/GHSA con severidad y resumen) de cada dependencia con versión, en
npm, PyPI, Go, Maven, crates.io y RubyGems. `--fail-on-cve` rompe el build si
hay alguna.

```bash
python -m pq_cbom.cli scan-deps ./mi-repo --osv --fail-on-cve
```

### Collector de binarios y Docker (`scan-binary`)

Cripto que no está en el código ni en los manifiestos: la enlazada en binarios
(ELF/PE/Mach-O/.so/.wasm) o instalada en imágenes. Extrae strings y detecta la
versión de la librería cripto (OpenSSL, BoringSSL, libgcrypt, mbedTLS, wolfSSL,
GnuTLS, NSS, libsodium) y los algoritmos presentes; en Dockerfiles, la imagen
base y los paquetes cripto instalados. Es heurística sobre strings, no
desensamblado.

```bash
python -m pq_cbom.cli scan-binary ./build
```
