"""Escanea el protocolo TLS negociable y el certificado de un host via
sslyze (https://github.com/nabla-c0d3/sslyze). Reutiliza RawMatch con
file=hostname y line=puerto."""

from __future__ import annotations

from .scanner import RawMatch


class TlsScanError(RuntimeError):
    """El host no pudo escanearse (DNS, conexion rechazada, timeout, etc.)."""


def _classify_public_key(pubkey) -> str | None:
    """Devuelve el rule_id de rules/pq_rules.yaml segun el tipo de clave
    publica del certificado (RSA/ECDSA/Ed25519/DSA), o None si no se
    reconoce el tipo."""
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

    if isinstance(pubkey, rsa.RSAPublicKey):
        return "RSA"
    if isinstance(pubkey, ec.EllipticCurvePublicKey):
        return "ECDSA"
    if isinstance(pubkey, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        return "Ed25519"
    if isinstance(pubkey, dsa.DSAPublicKey):
        return "DSA"
    return None


def _describe_key(pubkey) -> str:
    """Texto legible con el tipo de clave y su tamano o curva."""
    cls_name = type(pubkey).__name__
    if hasattr(pubkey, "key_size"):
        return f"{cls_name} {pubkey.key_size} bits"
    if hasattr(pubkey, "curve"):
        return f"{cls_name} curva {pubkey.curve.name}"
    return cls_name


def scan_host(hostname: str, port: int = 443, ip_address: str | None = None) -> list[RawMatch]:
    """Conecta a `hostname:port` con sslyze y devuelve un RawMatch por cada
    version TLS aceptada (TLS1.0-1.3) y por el tipo de clave del
    certificado. Lanza TlsScanError si sslyze no esta instalado o si el
    host no pudo escanearse."""
    try:
        from sslyze import (
            ScanCommand,
            ScanCommandAttemptStatusEnum,
            Scanner,
            ServerNetworkLocation,
            ServerScanRequest,
            ServerScanStatusEnum,
        )
    except ImportError as e:
        raise TlsScanError(
            "sslyze no esta instalado en este entorno. Instalar con: pip install sslyze"
        ) from e

    location_kwargs = {"hostname": hostname, "port": port}
    if ip_address:
        location_kwargs["ip_address"] = ip_address
    server_location = ServerNetworkLocation(**location_kwargs)

    request = ServerScanRequest(
        server_location=server_location,
        scan_commands={
            ScanCommand.CERTIFICATE_INFO,
            ScanCommand.TLS_1_0_CIPHER_SUITES,
            ScanCommand.TLS_1_1_CIPHER_SUITES,
            ScanCommand.TLS_1_2_CIPHER_SUITES,
            ScanCommand.TLS_1_3_CIPHER_SUITES,
        },
    )
    scanner = Scanner()
    scanner.queue_scans([request])
    results = list(scanner.get_results())
    if not results:
        raise TlsScanError(f"sslyze no devolvio resultados para {hostname}:{port}")

    result = results[0]
    if result.scan_status != ServerScanStatusEnum.COMPLETED:
        raise TlsScanError(
            f"no se pudo conectar a {hostname}:{port}: {result.connectivity_error_trace}"
        )

    attempts = result.scan_result
    matches: list[RawMatch] = []

    protocol_attempts = {
        "TLS1.0": attempts.tls_1_0_cipher_suites,
        "TLS1.1": attempts.tls_1_1_cipher_suites,
        "TLS1.2": attempts.tls_1_2_cipher_suites,
        "TLS1.3": attempts.tls_1_3_cipher_suites,
    }
    for rule_id, attempt in protocol_attempts.items():
        if attempt.status != ScanCommandAttemptStatusEnum.COMPLETED or not attempt.result:
            continue
        accepted = attempt.result.accepted_cipher_suites
        if accepted:
            matches.append(
                RawMatch(
                    rule_id=rule_id,
                    file=hostname,
                    line=port,
                    snippet=f"{rule_id} aceptado por el servidor ({len(accepted)} cipher suites)",
                )
            )

    cert_attempt = attempts.certificate_info
    if cert_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED and cert_attempt.result:
        for deployment in cert_attempt.result.certificate_deployments:
            leaf_cert = deployment.received_certificate_chain[0]
            pubkey = leaf_cert.public_key()
            rule_id = _classify_public_key(pubkey)
            if rule_id is None:
                continue
            matches.append(
                RawMatch(
                    rule_id=rule_id,
                    file=hostname,
                    line=port,
                    snippet=f"certificado con clave publica {_describe_key(pubkey)}",
                )
            )

    return matches
