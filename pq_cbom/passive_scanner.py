"""Collector de descubrimiento PASIVO de superficie criptográfica.

Dos fuentes, por orden de intrusividad:

  1. Certificate Transparency (crt.sh) — TOTALMENTE PASIVO. Consulta los
     certificados que las CAs ya publicaron para un dominio. No se conecta al
     objetivo: solo lee registros públicos de CT. De cada certificado extrae el
     tipo de clave pública y el algoritmo de firma.

  2. TLS + cabeceras HTTP — UNA conexión normal al objetivo (como un navegador).
     Lee la versión TLS y la suite negociadas y cabeceras de seguridad (HSTS...).
     Es tráfico ordinario, no un escaneo de puertos ni un sondeo agresivo.

AUTORIZACIÓN: la fuente 2 contacta al objetivo. Úsala solo contra dominios
propios o con autorización explícita (bug bounty con scope, contrato de pentest).
La fuente 1 no contacta al objetivo y es siempre segura de usar.

Reutiliza RawMatch y los patrones compilados del RuleSet para mapear evidencia
-> algorithm_id de forma consistente con el resto del pipeline.
"""

from __future__ import annotations

import json
import re
import socket
import ssl
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from .scanner import RawMatch

_PROXY_CA_BUNDLE = Path("/root/.ccr/ca-bundle.crt")
_USER_AGENT = "pq-cbom-passive/1.0 (+cryptographic-posture-scanner)"


class PassiveScanError(RuntimeError):
    """No se pudo completar el descubrimiento pasivo."""


class ScopeError(RuntimeError):
    """Se intentó una acción activa (contactar al objetivo) fuera del scope
    autorizado."""


def in_scope(host: str, scope: set[str] | None) -> bool:
    """True si `host` coincide con una entrada del scope o es subdominio de
    una de ellas. Un scope vacío o None no autoriza nada."""
    if not scope:
        return False
    host = host.strip().lower().rstrip(".")
    for entry in scope:
        entry = entry.strip().lower().lstrip("*.").rstrip(".")
        if host == entry or host.endswith("." + entry):
            return True
    return False


@dataclass
class PassiveResult:
    """Resultado del descubrimiento pasivo: hallazgos + contexto para el reporte."""

    matches: list[RawMatch] = field(default_factory=list)
    discovered_hosts: list[str] = field(default_factory=list)
    tls_version: str | None = None
    tls_cipher: str | None = None
    cert_verified: bool | None = None
    security_headers: dict = field(default_factory=dict)
    jwt_algorithms: list[str] = field(default_factory=list)
    caa_records: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _match_text(
    source: str,
    text: str,
    compiled_patterns: list[tuple[str, list[re.Pattern]]],
    line: int = 0,
) -> list[RawMatch]:
    """Produce un RawMatch por cada algorithm_id cuyos patrones aparezcan en
    `text`. `source` identifica de dónde salió la evidencia."""
    out: list[RawMatch] = []
    for rule_id, patterns in compiled_patterns:
        for pattern in patterns:
            if pattern.search(text):
                out.append(
                    RawMatch(rule_id=rule_id, file=source, line=line, snippet=text.strip()[:200])
                )
                break
    return out


def _http_get(url: str, timeout: int = 15) -> bytes:
    """GET vía urllib, respetando el proxy del entorno y su CA bundle."""
    ctx = ssl.create_default_context()
    if _PROXY_CA_BUNDLE.exists():
        try:
            ctx.load_verify_locations(cafile=str(_PROXY_CA_BUNDLE))
        except OSError:
            pass
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    # urllib toma HTTPS_PROXY/HTTP_PROXY del entorno automáticamente.
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return resp.read()


# ----------------------------------------------------------------------------
# Fuente 1: Certificate Transparency (crt.sh) — pasivo puro
# ----------------------------------------------------------------------------

def scan_ct_logs(
    domain: str,
    compiled_patterns: list[tuple[str, list[re.Pattern]]],
    sample: int = 8,
) -> PassiveResult:
    """Consulta crt.sh por los certificados del dominio, enumera hosts
    descubiertos y analiza la criptografía de hasta `sample` certificados
    únicos recientes. No contacta al objetivo."""
    result = PassiveResult()
    url = f"https://crt.sh/?q={urllib.parse.quote(domain)}&output=json"
    try:
        raw = _http_get(url)
        records = json.loads(raw)
    except Exception as e:  # noqa: BLE001 — red, JSON o proxy
        raise PassiveScanError(f"No se pudo consultar crt.sh para '{domain}': {e}") from e

    # Hosts descubiertos (superficie de ataque).
    hosts: set[str] = set()
    for rec in records:
        for name in str(rec.get("name_value", "")).splitlines():
            name = name.strip().lower()
            if name and "*" not in name:
                hosts.add(name)
    result.discovered_hosts = sorted(hosts)
    result.notes.append(f"crt.sh devolvió {len(records)} entradas, {len(hosts)} hosts únicos.")

    # Certificados únicos por id, más recientes primero.
    seen_ids: list[int] = []
    for rec in records:
        cid = rec.get("id")
        if isinstance(cid, int) and cid not in seen_ids:
            seen_ids.append(cid)
    seen_ids = sorted(seen_ids, reverse=True)[:sample]

    analyzed = 0
    for cid in seen_ids:
        try:
            pem = _http_get(f"https://crt.sh/?d={cid}")
            matches = _analyze_certificate(pem, source=f"ct:crt.sh/cert/{cid}", patterns=compiled_patterns)
            result.matches.extend(matches)
            analyzed += 1
        except Exception:  # noqa: BLE001 — un cert ilegible no debe abortar el escaneo
            continue
    result.notes.append(f"Analizados {analyzed}/{len(seen_ids)} certificados de muestra.")
    return result


def _analyze_certificate(
    pem: bytes, source: str, patterns: list[tuple[str, list[re.Pattern]]]
) -> list[RawMatch]:
    """Extrae tipo de clave pública y algoritmo de firma de un certificado PEM."""
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

    cert = x509.load_pem_x509_certificate(pem)
    evidence: list[str] = []

    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        evidence.append(f"RSA {pub.key_size} bits (clave pública de certificado)")
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        evidence.append(f"ECDSA curva {pub.curve.name} (clave pública de certificado)")
    elif isinstance(pub, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        evidence.append("Ed25519 (clave pública de certificado)")
    elif isinstance(pub, dsa.DSAPublicKey):
        evidence.append("DSA (clave pública de certificado)")

    # Algoritmo de firma (p.ej. sha256WithRSAEncryption, ecdsa-with-SHA384).
    try:
        sig_name = cert.signature_algorithm_oid._name  # type: ignore[attr-defined]
        evidence.append(f"firma: {sig_name}")
    except Exception:  # noqa: BLE001
        pass

    matches: list[RawMatch] = []
    for ev in evidence:
        matches.extend(_match_text(source, ev, patterns))
    return matches


# ----------------------------------------------------------------------------
# Fuente 2: TLS negociado + cabeceras HTTP — una conexión normal al objetivo
# ----------------------------------------------------------------------------

def scan_tls_headers(
    host: str,
    compiled_patterns: list[tuple[str, list[re.Pattern]]],
    port: int = 443,
    timeout: int = 10,
) -> PassiveResult:
    """Abre UNA conexión TLS al objetivo, lee la versión y suite negociadas y
    las cabeceras de seguridad. Contacta al objetivo: usar solo con
    autorización."""
    result = PassiveResult()
    ctx = ssl.create_default_context()
    verified = True
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        raise PassiveScanError(f"No se pudo conectar a {host}:{port}: {e}") from e

    try:
        try:
            ssock = ctx.wrap_socket(sock, server_hostname=host)
        except ssl.SSLCertVerificationError:
            # Para inventario (no confianza) reintentamos sin verificar, solo
            # para leer la versión/suite negociadas.
            verified = False
            sock.close()
            sock = socket.create_connection((host, port), timeout=timeout)
            unverified = ssl._create_unverified_context()  # noqa: SLF001
            ssock = unverified.wrap_socket(sock, server_hostname=host)

        result.cert_verified = verified
        result.tls_version = ssock.version()
        cipher = ssock.cipher()
        result.tls_cipher = cipher[0] if cipher else None

        # Evidencia: versión TLS + nombre de la suite negociada.
        for ev in filter(None, [result.tls_version, result.tls_cipher]):
            result.matches.extend(_match_text(f"tls:{host}:{port}", ev, compiled_patterns))

        # Cabeceras de seguridad (una petición HEAD mínima).
        try:
            request = (
                f"HEAD / HTTP/1.1\r\nHost: {host}\r\n"
                f"User-Agent: {_USER_AGENT}\r\nConnection: close\r\n\r\n"
            )
            ssock.sendall(request.encode())
            chunks = []
            while True:
                data = ssock.recv(4096)
                if not data:
                    break
                chunks.append(data)
                if b"\r\n\r\n" in b"".join(chunks):
                    break
            raw_headers = b"".join(chunks).decode("iso-8859-1", errors="ignore")
            result.security_headers = _parse_security_headers(raw_headers)
        except OSError:
            result.notes.append("No se pudieron leer cabeceras HTTP.")
    finally:
        try:
            ssock.close()
        except Exception:  # noqa: BLE001
            pass

    if not verified:
        result.notes.append("Certificado NO verificado (leído solo para inventario).")
    return result


# ----------------------------------------------------------------------------
# Fuente 3: DNS vía DNS-over-HTTPS — pasivo puro (no contacta al objetivo)
# ----------------------------------------------------------------------------

# Números de algoritmo DNSSEC (RFC 8624) -> algorithm_id de la base de conocimiento.
_DNSSEC_ALG = {
    "1": "RSA", "5": "RSA", "7": "RSA", "8": "RSA", "10": "RSA",
    "3": "DSA", "6": "DSA",
    "13": "ECDSA", "14": "ECDSA",
    "15": "Ed25519", "16": "Ed25519",
}


def scan_dns(domain: str) -> PassiveResult:
    """Consulta DNSSEC (DNSKEY) y CAA del dominio vía DNS-over-HTTPS (dns.google).
    Pregunta a un resolver público, no al objetivo: es pasivo puro."""
    result = PassiveResult()

    # DNSKEY (type 48): algoritmo de firma de la zona DNSSEC.
    try:
        raw = _http_get(f"https://dns.google/resolve?name={urllib.parse.quote(domain)}&type=48")
        data = json.loads(raw)
        for ans in data.get("Answer", []):
            parts = str(ans.get("data", "")).split()
            if len(parts) >= 3:
                rid = _DNSSEC_ALG.get(parts[2])
                if rid:
                    result.matches.append(
                        RawMatch(rule_id=rid, file=f"dnssec:{domain}", line=0,
                                 snippet=f"DNSSEC DNSKEY algoritmo {parts[2]}")
                    )
        if not result.matches:
            result.notes.append(f"DNSSEC: sin DNSKEY para {domain} (zona no firmada o sin datos).")
    except Exception as e:  # noqa: BLE001
        result.notes.append(f"DNSSEC no consultado: {e}")

    # CAA (type 257): qué CAs pueden emitir certificados (gobernanza cripto).
    try:
        raw = _http_get(f"https://dns.google/resolve?name={urllib.parse.quote(domain)}&type=257")
        data = json.loads(raw)
        for ans in data.get("Answer", []):
            d = str(ans.get("data", "")).strip()
            if d:
                result.caa_records.append(d)
        if result.caa_records:
            result.notes.append(f"CAA: {len(result.caa_records)} registro(s).")
    except Exception as e:  # noqa: BLE001
        result.notes.append(f"CAA no consultado: {e}")

    return result


# ----------------------------------------------------------------------------
# Fuente 4: JWKS / OpenID — cripto de tokens JWT (contacta al objetivo)
# ----------------------------------------------------------------------------

def _map_jwt_alg(alg: str) -> str | None:
    a = (alg or "").upper()
    if a.startswith(("RS", "PS")):   # RS256, PS384...
        return "RSA"
    if a.startswith("ES"):           # ES256, ES384...
        return "ECDSA"
    if a == "EDDSA":
        return "Ed25519"
    if a.startswith("HS"):           # HS256...
        return "HMAC"
    return None


def _map_jwk_kty(kty: str) -> str | None:
    k = (kty or "").upper()
    return {"RSA": "RSA", "EC": "ECDSA", "OKP": "Ed25519", "OCT": "HMAC"}.get(k)


def scan_jwks(domain: str) -> PassiveResult:
    """Busca el JWKS del dominio (vía OpenID discovery o /.well-known/jwks.json)
    y extrae los algoritmos de firma de JWT. Contacta al objetivo."""
    result = PassiveResult()
    jwks_url = f"https://{domain}/.well-known/jwks.json"
    algs: set[str] = set()

    # 1) OpenID discovery para localizar el jwks_uri y los algs soportados.
    try:
        raw = _http_get(f"https://{domain}/.well-known/openid-configuration")
        cfg = json.loads(raw)
        if cfg.get("jwks_uri"):
            jwks_url = cfg["jwks_uri"]
        for a in cfg.get("id_token_signing_alg_values_supported", []) or []:
            algs.add(a)
    except Exception:  # noqa: BLE001 — no todos exponen OpenID
        pass

    # 2) JWKS: claves publicadas.
    try:
        raw = _http_get(jwks_url)
        jwks = json.loads(raw)
        for key in jwks.get("keys", []):
            if key.get("alg"):
                algs.add(key["alg"])
            rid = _map_jwk_kty(key.get("kty", ""))
            if rid:
                result.matches.append(
                    RawMatch(rule_id=rid, file=f"jwks:{domain}", line=0,
                             snippet=f"JWKS kty={key.get('kty')} alg={key.get('alg', '?')}")
                )
        result.notes.append(f"JWKS: {len(jwks.get('keys', []))} clave(s) en {jwks_url}.")
    except Exception as e:  # noqa: BLE001
        result.notes.append(f"JWKS no encontrado para {domain}: {e}")

    for a in sorted(algs):
        result.jwt_algorithms.append(a)
        rid = _map_jwt_alg(a)
        if rid:
            result.matches.append(
                RawMatch(rule_id=rid, file=f"jwt:{domain}", line=0, snippet=f"JWT alg={a}")
            )
    return result


def scan(
    domain: str,
    compiled_patterns: list[tuple[str, list[re.Pattern]]],
    include_active: bool = True,
    port: int = 443,
    sample: int = 8,
    authorized_scope: set[str] | None = None,
) -> PassiveResult:
    """Orquesta el descubrimiento pasivo: siempre CT logs (pasivo puro); y, si
    `include_active`, además TLS/cabeceras (una conexión al objetivo).

    La parte activa SOLO se ejecuta si `domain` está dentro de
    `authorized_scope`. Sin scope autorizado, se omite y se deja constancia:
    es la salvaguarda que impide contactar sistemas de terceros sin permiso."""
    result = scan_ct_logs(domain, compiled_patterns, sample=sample)

    # DNS (DNSSEC + CAA): pasivo puro, no contacta al objetivo. Siempre se ejecuta.
    dns = scan_dns(domain)
    result.matches.extend(dns.matches)
    result.caa_records = dns.caa_records
    result.notes.extend(dns.notes)

    # Parte que SÍ contacta al objetivo (TLS/cabeceras + JWKS): solo con autorización.
    if include_active and not in_scope(domain, authorized_scope):
        result.notes.append(
            f"TLS/cabeceras/JWKS OMITIDO: '{domain}' no está en el scope autorizado. "
            f"Autoriza el dominio (--authorize/--scope-file) o usa --ct-only."
        )
        return result
    if include_active:
        try:
            active = scan_tls_headers(domain, compiled_patterns, port=port)
            result.matches.extend(active.matches)
            result.tls_version = active.tls_version
            result.tls_cipher = active.tls_cipher
            result.cert_verified = active.cert_verified
            result.security_headers = active.security_headers
            result.notes.extend(active.notes)
        except PassiveScanError as e:
            result.notes.append(f"TLS/cabeceras omitido: {e}")
        # JWKS / JWT (endpoint público pero contacta al objetivo).
        jwks = scan_jwks(domain)
        result.matches.extend(jwks.matches)
        result.jwt_algorithms = jwks.jwt_algorithms
        result.notes.extend(jwks.notes)
    return result


_INTERESTING_HEADERS = {
    "strict-transport-security",
    "server",
    "x-content-type-options",
    "content-security-policy",
}


def _parse_security_headers(raw: str) -> dict:
    """Extrae cabeceras de seguridad relevantes de una respuesta HTTP cruda."""
    headers: dict[str, str] = {}
    for line in raw.splitlines()[1:]:  # saltar la status line
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        if key in _INTERESTING_HEADERS:
            headers[key] = value.strip()
    return headers
