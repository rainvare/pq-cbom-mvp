"""Tests del collector de claves/certificados en disco."""

import datetime
from pathlib import Path

import pytest

from pq_cbom import keyfile_scanner

cryptography = pytest.importorskip("cryptography")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402


def _write_rsa(path, bits):
    k = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    path.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return k


def test_detects_rsa_and_flags_short_key(tmp_path):
    _write_rsa(tmp_path / "weak.key", 1024)
    matches = keyfile_scanner.scan_directory(tmp_path)
    rsa_m = [m for m in matches if m.rule_id == "RSA"]
    assert rsa_m
    assert any("1024" in m.snippet and "CLAVE CORTA" in m.snippet for m in rsa_m)


def test_strong_rsa_not_flagged(tmp_path):
    k = _write_rsa(tmp_path / "strong.key", 2048)
    matches = keyfile_scanner.scan_directory(tmp_path)
    assert any("2048" in m.snippet and "CLAVE CORTA" not in m.snippet for m in matches)


def test_detects_ec_and_ed25519(tmp_path):
    ek = ec.generate_private_key(ec.SECP256R1())
    (tmp_path / "ec.pem").write_bytes(ek.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    edk = ed25519.Ed25519PrivateKey.generate()
    (tmp_path / "ed.pem").write_bytes(edk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    ids = {m.rule_id for m in keyfile_scanner.scan_directory(tmp_path)}
    assert "ECDSA" in ids
    assert "Ed25519" in ids


def test_detects_certificate_key_and_signature(tmp_path):
    ck = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "t")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(n).issuer_name(n)
            .public_key(ck.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(ck, hashes.SHA256()))
    (tmp_path / "server.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    ids = {m.rule_id for m in keyfile_scanner.scan_directory(tmp_path)}
    assert "RSA" in ids       # clave pública del cert
    assert "SHA-256" in ids   # algoritmo de firma


def test_detects_ssh_public_keys(tmp_path):
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ssh = k.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    (tmp_path / "authorized_keys").write_text(ssh + "\n")
    matches = keyfile_scanner.scan_directory(tmp_path)
    assert any(m.rule_id == "RSA" and "SSH" in m.snippet for m in matches)


def test_embedded_pem_in_config(tmp_path):
    k = _write_rsa(tmp_path / "tmp.key", 2048)
    pem = (tmp_path / "tmp.key").read_text()
    (tmp_path / "tmp.key").unlink()
    (tmp_path / "config.yaml").write_text("tls:\n  cert: |\n" + pem)
    ids = {m.rule_id for m in keyfile_scanner.scan_directory(tmp_path)}
    assert "RSA" in ids
