"""Collector de material criptográfico en disco: certificados y claves.

A diferencia del scanner de código (que ve *menciones* de algoritmos), este
collector parsea el material real y extrae el **tamaño de clave** — la
dimensión que faltaba: RSA-1024 no es RSA-4096, aunque ambos sean vulnerables
a Shor. Cubre:

  - Certificados X.509 (PEM y DER): tipo de clave pública + algoritmo de firma.
  - Claves públicas/privadas PEM (RSA/EC/Ed25519/DSA). Las privadas cifradas se
    identifican por cabecera sin descifrarlas.
  - Claves públicas SSH (ssh-rsa, ssh-ed25519, ecdsa-sha2-*, ssh-dss).
  - Bloques PEM embebidos dentro de otros archivos (configs, YAML...).

No ejecuta ni descifra nada: solo lee y parsea. Es análisis estático sobre
ficheros propios del repositorio/sistema.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from .scanner import RawMatch
from .tls_scanner import _classify_public_key, _describe_key


class KeyScanError(RuntimeError):
    """No se pudo escanear material de claves (p.ej. falta 'cryptography')."""


def _require_cryptography() -> None:
    try:
        import cryptography  # noqa: F401
    except ImportError as e:
        raise KeyScanError(
            "El paquete 'cryptography' no está instalado; scan-keys no puede parsear "
            "claves/certificados. Instalar con: pip install cryptography"
        ) from e

KEY_EXTENSIONS = {
    ".pem", ".crt", ".cer", ".der", ".key", ".pub", ".p7b", ".p7c",
    ".p12", ".pfx", ".jks", ".keystore", ".asc", ".gpg", ".ssh",
}

SKIP_DIRS = {".git", "node_modules", "__pycache__", "venv", ".venv", "dist", "build", ".tox"}

_PEM_BLOCK = re.compile(
    r"-----BEGIN ([A-Z0-9 ]+?)-----.*?-----END \1-----", re.DOTALL
)

# Prefijos de clave pública SSH -> algorithm_id de la base de conocimiento.
_SSH_PREFIX = {
    "ssh-rsa": "RSA",
    "ssh-dss": "DSA",
    "ssh-ed25519": "Ed25519",
    "sk-ssh-ed25519@openssh.com": "Ed25519",
    "ecdsa-sha2-nistp256": "ECDSA",
    "ecdsa-sha2-nistp384": "ECDSA",
    "ecdsa-sha2-nistp521": "ECDSA",
    "sk-ecdsa-sha2-nistp256@openssh.com": "ECDSA",
    "sntrup761x25519-sha512@openssh.com": "NTRU-Prime",
}

# Tamaños mínimos recomendados; por debajo se marca "clave corta" en la evidencia.
_MIN_RSA_DSA_BITS = 2048
_MIN_EC_BITS = 256


def _short_key_note(pubkey) -> str:
    """Devuelve ' [CLAVE CORTA]' si la clave está por debajo del mínimo."""
    size = getattr(pubkey, "key_size", None)
    if size is None:
        return ""
    cls = type(pubkey).__name__.lower()
    if "rsa" in cls or "dsa" in cls:
        return " [CLAVE CORTA]" if size < _MIN_RSA_DSA_BITS else ""
    if "ellipticcurve" in cls:
        return " [CLAVE CORTA]" if size < _MIN_EC_BITS else ""
    return ""


def iter_key_files(target: Path, exclude: set[Path] | None = None) -> Iterable[Path]:
    exclude = exclude or set()
    for path in target.rglob("*"):
        if not path.is_file():
            continue
        # SKIP_DIRS relativo al objetivo: no saltar si el OBJETIVO ya vive bajo
        # 'build'/'lib'/'dist' (eso omitía todo el escaneo).
        try:
            rel_parts = path.relative_to(target).parts
        except ValueError:
            rel_parts = path.parts
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        if path.resolve() in exclude:
            continue
        yield path


def _hash_rule_from_sig(sig_name: str) -> str | None:
    s = sig_name.lower()
    if "sha256" in s or "sha-256" in s:
        return "SHA-256"
    if "sha384" in s or "sha512" in s or "sha-384" in s or "sha-512" in s:
        return "SHA-256"
    if "sha1" in s or "sha-1" in s:
        return "SHA1"
    if "md5" in s:
        return "MD5"
    if "sha3" in s:
        return "SHA-3"
    return None


def _analyze_pem_block(block: str, kind: str):
    """Devuelve (algorithm_id, descripción) para un bloque PEM, o None."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    data = block.encode()
    kind_u = kind.upper()

    try:
        if "CERTIFICATE" in kind_u and "REQUEST" not in kind_u:
            cert = x509.load_pem_x509_certificate(data)
            pub = cert.public_key()
            rid = _classify_public_key(pub)
            results = []
            if rid:
                results.append((rid, f"cert: {_describe_key(pub)}{_short_key_note(pub)}"))
            try:
                sig = cert.signature_algorithm_oid._name  # type: ignore[attr-defined]
                hr = _hash_rule_from_sig(sig)
                if hr:
                    results.append((hr, f"cert firma: {sig}"))
            except Exception:  # noqa: BLE001
                pass
            return results
        if "PUBLIC KEY" in kind_u:
            pub = serialization.load_pem_public_key(data)
            rid = _classify_public_key(pub)
            return [(rid, f"clave pública: {_describe_key(pub)}{_short_key_note(pub)}")] if rid else []
        if "PRIVATE KEY" in kind_u:
            try:
                priv = serialization.load_pem_private_key(data, password=None)
                pub = priv.public_key()
                rid = _classify_public_key(pub)
                return [(rid, f"clave privada: {_describe_key(pub)}{_short_key_note(pub)}")] if rid else []
            except (TypeError, ValueError):
                # Cifrada o no parseable: inferir tipo por la cabecera.
                if "RSA" in kind_u:
                    return [("RSA", "clave privada RSA (cifrada/no parseable)")]
                if "EC" in kind_u:
                    return [("ECDSA", "clave privada EC (cifrada/no parseable)")]
                if "OPENSSH" in kind_u:
                    return [("Ed25519", "clave privada OpenSSH (cifrada/no parseable)")]
                return []
    except Exception:  # noqa: BLE001 — un bloque ilegible no aborta el escaneo
        return []
    return []


def _analyze_ssh_line(line: str):
    """Devuelve (algorithm_id, descripción) para una línea de clave pública SSH."""
    parts = line.strip().split()
    if not parts:
        return None
    prefix = parts[0]
    rid = _SSH_PREFIX.get(prefix)
    if rid:
        return (rid, f"clave pública SSH: {prefix}")
    return None


def scan_directory(target: Path, exclude: set[Path] | None = None) -> list[RawMatch]:
    """Escanea `target` buscando certificados y claves; devuelve un RawMatch por
    cada pieza de material criptográfico identificada, con su tamaño."""
    _require_cryptography()
    matches: list[RawMatch] = []
    for path in iter_key_files(target, exclude):
        try:
            # Leer como binario primero (para DER); decodificar texto para PEM/SSH.
            raw = path.read_bytes()
        except OSError:
            continue

        text = raw.decode("utf-8", errors="ignore")

        # 1) Bloques PEM (en archivos .pem o embebidos en configs/YAML).
        found_pem = False
        for m in _PEM_BLOCK.finditer(text):
            found_pem = True
            kind = m.group(1)
            line_no = text[: m.start()].count("\n") + 1
            for rid, desc in _analyze_pem_block(m.group(0), kind):
                matches.append(RawMatch(rule_id=rid, file=str(path), line=line_no, snippet=desc[:200]))

        # 2) Claves públicas SSH (authorized_keys, *.pub, known_hosts).
        for i, line in enumerate(text.splitlines(), start=1):
            res = _analyze_ssh_line(line)
            if res:
                matches.append(RawMatch(rule_id=res[0], file=str(path), line=i, snippet=res[1]))

        # 3) DER binario (.der/.cer) si no había PEM.
        if not found_pem and path.suffix.lower() in {".der", ".cer", ".crt"}:
            res = _analyze_der(raw, str(path))
            matches.extend(res)

    return matches


def _analyze_der(raw: bytes, path: str) -> list[RawMatch]:
    from cryptography import x509

    try:
        cert = x509.load_der_x509_certificate(raw)
    except Exception:  # noqa: BLE001
        return []
    pub = cert.public_key()
    rid = _classify_public_key(pub)
    out: list[RawMatch] = []
    if rid:
        out.append(RawMatch(rule_id=rid, file=path, line=0, snippet=f"cert DER: {_describe_key(pub)}{_short_key_note(pub)}"))
    return out
