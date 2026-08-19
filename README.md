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
FIPS 203/204/205). No hay heurísticas ni decisiones en tiempo real — es una
tabla auditable, con tests de regresión (`tests/test_rules_golden.py`) que
fijan el resultado esperado de cada regla.

**Cada hallazgo del CBOM trae evidencia completa**: ubicación
(archivo:línea o host:puerto), snippet, regla aplicada, versión del paquete
de reglas y timestamp — para que la clasificación sea reproducible.

**Qué queda deliberadamente afuera** de este MVP: collectors de cloud o
binarios, actualización automática de reglas/software, persistencia, API y
UI. El priority score es una heurística simple (severidad + ocurrencias),
no el modelo completo de confidencialidad/exposición/vida útil de un
inventario de activos real.

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
