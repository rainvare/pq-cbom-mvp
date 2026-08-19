"""Servidor TLS de prueba en 127.0.0.1 con certificado autofirmado en memoria."""

from __future__ import annotations

import datetime
import socket
import ssl
import threading
from contextlib import contextmanager
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID


def _self_signed_cert(tmp_dir: Path, key) -> tuple[Path, Path]:
    """Genera un certificado autofirmado para `key` y lo escribe en
    `tmp_dir` junto con la clave privada. Devuelve (cert_path, key_path)."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_path = tmp_dir / "key.pem"
    cert_path = tmp_dir / "cert.pem"
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


def rsa_key():
    """Genera un par de claves RSA de 2048 bits."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def ec_key():
    """Genera un par de claves EC sobre la curva P-256."""
    return ec.generate_private_key(ec.SECP256R1())


def _free_port() -> int:
    """Devuelve un puerto TCP libre en localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextmanager
def local_tls_server(tmp_path: Path, key, min_version: ssl.TLSVersion, max_version: ssl.TLSVersion):
    """Context manager: levanta un servidor TLS en localhost con la clave y
    el rango de versiones dados, y lo cierra al salir. Yields el puerto."""
    cert_path, key_path = _self_signed_cert(tmp_path, key)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert_path), str(key_path))
    ctx.minimum_version = min_version
    ctx.maximum_version = max_version

    port = _free_port()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(20)

    stop = threading.Event()

    def serve():
        sock.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                tls_conn = ctx.wrap_socket(conn, server_side=True)
                tls_conn.close()
            except Exception:
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        stop.set()
        sock.close()
        thread.join(timeout=2)
