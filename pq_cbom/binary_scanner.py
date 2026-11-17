"""Collector de binarios compilados e imágenes Docker.

Cripto que no está en el código fuente ni en los manifiestos: la que viene
enlazada en un binario (libcrypto, BoringSSL...) o instalada en una imagen de
contenedor. Dos modos:

  - Binarios (ELF/PE/Mach-O/.so/.dll/.wasm): extrae strings imprimibles y
    detecta (a) versiones de librerías cripto y (b) menciones de algoritmos.
  - Dockerfiles: imagen base y paquetes cripto instalados (apt/apk).

Es heurística sobre strings (como `strings | grep`), no desensamblado: señala
evidencia para revisión. No ejecuta los binarios.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .scanner import RawMatch

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}
_MAX_READ = 16 * 1024 * 1024  # 16 MB por binario

# Magia de archivos binarios ejecutables / objetos.
_MAGICS = (b"\x7fELF", b"MZ", b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa", b"\x00asm")
_BIN_EXT = {".so", ".dll", ".dylib", ".a", ".o", ".bin", ".exe", ".elf", ".wasm", ".node"}

# Patrones de versión de librerías criptográficas.
_LIB_PATTERNS = [
    ("OpenSSL", re.compile(rb"OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)")),
    ("LibreSSL", re.compile(rb"LibreSSL\s+(\d+\.\d+\.\d+)")),
    ("BoringSSL", re.compile(rb"(BoringSSL)")),
    ("libgcrypt", re.compile(rb"[Ll]ibgcrypt\s+(\d+\.\d+\.\d+)")),
    ("mbedTLS", re.compile(rb"[Mm]bed ?TLS\s+(\d+\.\d+\.\d+)")),
    ("wolfSSL", re.compile(rb"wolfSSL\s+(\d+\.\d+\.\d+)")),
    ("GnuTLS", re.compile(rb"GnuTLS\s+(\d+\.\d+\.\d+)")),
    ("NSS", re.compile(rb"NSS/(\d+\.\d+)")),
    ("libsodium", re.compile(rb"libsodium\s+(\d+\.\d+\.\d+)")),
]

# Paquetes cripto instalados vía gestor de paquetes en Dockerfiles.
_DOCKER_CRYPTO_PKGS = re.compile(
    r"\b(openssl|libssl[0-9a-z.\-]*|libssl-dev|libgcrypt[0-9a-z.\-]*|gnutls[0-9a-z.\-]*|"
    r"libsodium[0-9a-z.\-]*|nss|mbedtls|wolfssl|bouncycastle)\b", re.IGNORECASE)

_STRINGS = re.compile(rb"[\x20-\x7e]{5,}")


@dataclass
class BinaryResult:
    matches: list[RawMatch] = field(default_factory=list)
    libraries: list[str] = field(default_factory=list)   # "Lib version (archivo)"
    notes: list[str] = field(default_factory=list)


def _is_binary(path: Path) -> bool:
    if path.suffix.lower() in _BIN_EXT:
        return True
    try:
        with path.open("rb") as f:
            head = f.read(4)
        return any(head.startswith(m) for m in _MAGICS)
    except OSError:
        return False


def iter_files(target: Path, exclude: set[Path] | None = None):
    exclude = exclude or set()
    for path in target.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.resolve() in exclude:
            continue
        yield path


def _scan_binary(path: Path, compiled_patterns, result: BinaryResult) -> None:
    try:
        data = path.open("rb").read(_MAX_READ)
    except OSError:
        return
    strings = b"\n".join(_STRINGS.findall(data))

    # Librerías cripto + versión.
    for lib, pat in _LIB_PATTERNS:
        m = pat.search(data)
        if m:
            ver = m.group(1).decode(errors="ignore") if m.groups() else ""
            entry = f"{lib} {ver}".strip() + f" ({path.name})"
            if entry not in result.libraries:
                result.libraries.append(entry)

    # Algoritmos mencionados (dedupe por rule_id/archivo).
    text = strings.decode("latin-1", errors="ignore")
    seen: set[str] = set()
    for rule_id, patterns in compiled_patterns:
        if rule_id in seen:
            continue
        for pat in patterns:
            mm = pat.search(text)
            if mm:
                seen.add(rule_id)
                result.matches.append(RawMatch(
                    rule_id=rule_id, file=str(path), line=0,
                    snippet=f"string en binario: '{mm.group(0)[:40]}'"))
                break


def _scan_dockerfile(path: Path, result: BinaryResult) -> None:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return
    for i, line in enumerate(text.splitlines(), start=1):
        s = line.strip()
        if s.upper().startswith("FROM "):
            result.libraries.append(f"imagen base: {s[5:].strip()} ({path.name})")
        for m in _DOCKER_CRYPTO_PKGS.finditer(s):
            entry = f"paquete: {m.group(1)} ({path.name})"
            if entry not in result.libraries:
                result.libraries.append(entry)


def scan_directory(target: Path, compiled_patterns, exclude: set[Path] | None = None) -> BinaryResult:
    """Escanea binarios y Dockerfiles bajo `target`."""
    result = BinaryResult()
    bins = 0
    dockerfiles = 0
    for path in iter_files(target, exclude):
        if path.name.lower().startswith("dockerfile") or path.name.lower() == "dockerfile":
            _scan_dockerfile(path, result)
            dockerfiles += 1
        elif _is_binary(path):
            _scan_binary(path, compiled_patterns, result)
            bins += 1
    result.notes.append(f"Analizados {bins} binario(s) y {dockerfiles} Dockerfile(s).")
    return result
