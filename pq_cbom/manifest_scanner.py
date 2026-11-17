"""Collector de manifiestos de dependencias.

Encuentra criptografía que el scanner de código no ve: la que entra por una
librería. Un proyecto puede no escribir "RSA" en ninguna parte y aun así
depender de `node-forge`, `pyjwt` o `go-ethereum` (secp256k1).

Produce dos cosas:
  - Hallazgos CBOM para paquetes que implican un algoritmo concreto
    (md5, bcrypt, elliptic, ed25519-dalek...), que entran al pipeline normal.
  - Un inventario de dependencias cripto-relevantes (librerías generales y
    paquetes abandonados/débiles) para el reporte.

Nota honesta: NO es un feed de CVE/SCA completo. La lista de paquetes débiles
es curada y pequeña; para cobertura CVE real se integraría OSV.dev como paso
futuro.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .scanner import RawMatch

SKIP_DIRS = {".git", "node_modules", "__pycache__", "venv", ".venv", "dist", "build", ".tox"}

MANIFEST_FILES = {
    "requirements.txt", "pipfile", "pyproject.toml", "package.json",
    "go.mod", "pom.xml", "cargo.toml", "gemfile", "build.gradle",
}

# Paquete (substring, minúsculas) -> algorithm_id de la base de conocimiento.
# Solo mapeos INEQUÍVOCOS (el paquete ES ese algoritmo).
ALGO_PACKAGES: list[tuple[str, str]] = [
    ("bcryptjs", "bcrypt"), ("bcrypt", "bcrypt"),
    ("scryptsy", "scrypt"), ("scrypt", "scrypt"),
    ("argon2", "Argon2"),
    ("ed25519-dalek", "Ed25519"), ("tweetnacl", "Ed25519"),
    ("x25519-dalek", "ECDH"),
    ("secp256k1", "ECDSA"), ("go-ethereum", "ECDSA"), ("elliptic", "ECDSA"),
    ("ecdsa", "ECDSA"), ("k256", "ECDSA"),
    ("chacha20", "ChaCha20"),
    ("md5", "MD5"), ("sha1", "SHA1"),
    ("blake2", "BLAKE2"), ("blake3", "BLAKE2"),
]

# Librerías cripto generales (no implican un algoritmo único): inventario.
CRYPTO_LIBS = {
    "cryptography", "pycryptodome", "pycrypto", "node-forge", "crypto-js",
    "openssl", "pyopenssl", "ring", "libsodium", "pynacl", "sodium", "nacl",
    "bouncycastle", "bcprov", "forge", "jose", "jsonwebtoken", "pyjwt",
    "jjwt", "jwt", "web3", "ethers", "noble",
}

# Paquetes abandonados / con debilidades conocidas (curado, no es un CVE feed).
WEAK_LIBS = {
    "pycrypto": "Abandonado desde 2014, con vulnerabilidades sin parchear. Migrar a 'pycryptodome'.",
    "node-forge": "Revisar versión: <1.0.0 tiene varias CVE (p.ej. verificación de firma). Fijar >=1.3.0.",
    "jsonwebtoken": "Revisar versión: <9.0.0 con CVE de verificación (algoritmo). Fijar >=9.0.0.",
    "elliptic": "Revisar versión: <6.5.4 con maleabilidad de firma. Fijar >=6.5.4.",
    "crypto-js": "Revisar versión: <4.2.0 con PRNG débil (CVE-2023-46233). Fijar >=4.2.0.",
}


# Manifiesto -> ecosistema OSV (https://ossf.github.io/osv-schema/#affectedpackage-field).
ECOSYSTEM_BY_MANIFEST = {
    "package.json": "npm",
    "requirements.txt": "PyPI",
    "pipfile": "PyPI",
    "pyproject.toml": "PyPI",
    "go.mod": "Go",
    "pom.xml": "Maven",
    "cargo.toml": "crates.io",
    "gemfile": "RubyGems",
}


@dataclass
class DepsResult:
    matches: list[RawMatch] = field(default_factory=list)
    crypto_libs: list[str] = field(default_factory=list)   # "nombre (archivo)"
    weak_libs: list[str] = field(default_factory=list)      # "nombre: motivo"
    notes: list[str] = field(default_factory=list)


def iter_manifests(target: Path, exclude: set[Path] | None = None):
    exclude = exclude or set()
    for path in target.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.resolve() in exclude:
            continue
        if path.name.lower() in MANIFEST_FILES:
            yield path


def _extract_packages(path: Path) -> list[str]:
    """Devuelve los nombres de paquete declarados en un manifiesto."""
    name = path.name.lower()
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    pkgs: list[str] = []
    if name == "package.json":
        try:
            data = json.loads(text)
            for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                pkgs.extend((data.get(key) or {}).keys())
        except json.JSONDecodeError:
            pass
    elif name in ("requirements.txt", "pipfile"):
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                pkgs.append(re.split(r"[=<>!~\[ ;]", line, maxsplit=1)[0].strip())
    elif name == "pyproject.toml" or name == "cargo.toml":
        # Nombres antes de '=' o entradas de array de dependencias.
        for line in text.splitlines():
            m = re.match(r'\s*["\']?([A-Za-z0-9_.\-]+)["\']?\s*=', line)
            if m:
                pkgs.append(m.group(1))
            for q in re.findall(r'["\']([A-Za-z0-9_.\-]+)[=<>~ ]', line):
                pkgs.append(q)
    elif name == "go.mod":
        for m in re.finditer(r"^\s*([a-z0-9./\-]+)\s+v[0-9]", text, re.MULTILINE):
            pkgs.append(m.group(1))
    elif name == "pom.xml":
        pkgs.extend(re.findall(r"<artifactId>([^<]+)</artifactId>", text))
        pkgs.extend(re.findall(r"<groupId>([^<]+)</groupId>", text))
    elif name == "gemfile" or name == "build.gradle":
        pkgs.extend(re.findall(r"""['"]([A-Za-z0-9_.\-]+)['"]""", text))
    return [p for p in pkgs if p]


def _clean_version(v: str) -> str:
    """Normaliza un spec de versión a algo que OSV pueda consultar."""
    v = v.strip().strip('"\'').lstrip("^~>=< v")
    # Quedarse con el primer token tipo X.Y.Z.
    m = re.match(r"[0-9][0-9A-Za-z.\-]*", v)
    return m.group(0) if m else ""


def extract_package_specs(target: Path, exclude: set[Path] | None = None) -> list[dict]:
    """Devuelve specs {name, version, ecosystem, file} para consulta OSV."""
    specs: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for path in iter_manifests(target, exclude):
        name_l = path.name.lower()
        eco = ECOSYSTEM_BY_MANIFEST.get(name_l)
        if not eco:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        pairs: list[tuple[str, str]] = []
        if name_l == "package.json":
            try:
                data = json.loads(text)
                for key in ("dependencies", "devDependencies"):
                    for n, v in (data.get(key) or {}).items():
                        pairs.append((n, _clean_version(str(v))))
            except json.JSONDecodeError:
                pass
        elif name_l in ("requirements.txt", "pipfile", "pyproject.toml"):
            for line in text.splitlines():
                m = re.match(r'\s*["\']?([A-Za-z0-9_.\-]+)["\']?\s*[=~<>!]+\s*["\']?v?([0-9][0-9A-Za-z.\-]*)', line)
                if m:
                    pairs.append((m.group(1), m.group(2)))
        elif name_l == "go.mod":
            for m in re.finditer(r"^\s*([a-z0-9./\-]+)\s+v([0-9][0-9A-Za-z.\-]*)", text, re.MULTILINE):
                pairs.append((m.group(1), m.group(2)))
        elif name_l == "cargo.toml":
            for m in re.finditer(r'^\s*([A-Za-z0-9_\-]+)\s*=\s*["\']([0-9][0-9A-Za-z.\-]*)["\']', text, re.MULTILINE):
                pairs.append((m.group(1), m.group(2)))
        elif name_l == "gemfile":
            for m in re.finditer(r"""gem\s+['"]([A-Za-z0-9_.\-]+)['"]\s*,\s*['"][~>=< ]*([0-9][0-9A-Za-z.\-]*)""", text):
                pairs.append((m.group(1), m.group(2)))

        for n, v in pairs:
            if not n or not v:
                continue
            key = (eco, n.lower(), v)
            if key in seen:
                continue
            seen.add(key)
            specs.append({"name": n, "version": v, "ecosystem": eco, "file": path.name})
    return specs


def scan_directory(target: Path, exclude: set[Path] | None = None) -> DepsResult:
    """Escanea manifiestos bajo `target` y clasifica sus dependencias cripto."""
    result = DepsResult()
    seen_lib: set[str] = set()
    manifests = 0

    for path in iter_manifests(target, exclude):
        manifests += 1
        for pkg in _extract_packages(path):
            low = pkg.lower()

            # ¿implica un algoritmo concreto?
            for needle, rule_id in ALGO_PACKAGES:
                if needle in low:
                    result.matches.append(
                        RawMatch(rule_id=rule_id, file=str(path), line=0,
                                 snippet=f"dependencia '{pkg}' -> {rule_id}")
                    )
                    break

            # ¿es una librería cripto general?
            base = low.split("/")[-1]
            if any(lib in low for lib in CRYPTO_LIBS) and base not in seen_lib:
                seen_lib.add(base)
                result.crypto_libs.append(f"{pkg} ({path.name})")

            # ¿abandonada / débil?
            for weak, reason in WEAK_LIBS.items():
                if weak in low:
                    entry = f"{pkg}: {reason}"
                    if entry not in result.weak_libs:
                        result.weak_libs.append(entry)

    result.notes.append(f"Analizados {manifests} manifiesto(s) de dependencias.")
    return result
