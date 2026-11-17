"""Tests offline del collector pasivo (sin red)."""

import datetime
from pathlib import Path

import pytest

from pq_cbom import passive_scanner
from pq_cbom.rules_engine import RuleSet

RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "pq_rules.yaml"

cryptography = pytest.importorskip("cryptography")


@pytest.fixture(scope="module")
def patterns():
    return RuleSet.load(RULES_PATH).compiled_patterns()


def test_match_text_maps_evidence_to_algorithm_ids(patterns):
    matches = passive_scanner._match_text("src", "RSA 2048 bits", patterns)
    ids = {m.rule_id for m in matches}
    assert "RSA" in ids


def test_match_text_detects_aes256(patterns):
    matches = passive_scanner._match_text("tls", "TLS_AES_256_GCM_SHA384", patterns)
    ids = {m.rule_id for m in matches}
    assert "AES-256" in ids


def test_parse_security_headers():
    raw = (
        "HTTP/1.1 200 OK\r\n"
        "Server: nginx\r\n"
        "Strict-Transport-Security: max-age=63072000\r\n"
        "X-Frame-Options: DENY\r\n\r\n"
    )
    headers = passive_scanner._parse_security_headers(raw)
    assert headers["server"] == "nginx"
    assert "strict-transport-security" in headers
    assert "x-frame-options" not in headers  # no está en la lista de interés


def _self_signed(private_key, hash_alg):
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example")])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
    )
    cert = builder.sign(private_key, hash_alg)
    from cryptography.hazmat.primitives import serialization

    return cert.public_bytes(serialization.Encoding.PEM)


def test_analyze_rsa_certificate(patterns):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = _self_signed(key, hashes.SHA256())
    matches = passive_scanner._analyze_certificate(pem, "ct:test", patterns)
    ids = {m.rule_id for m in matches}
    assert "RSA" in ids
    assert "SHA-256" in ids  # firma sha256WithRSAEncryption


def test_analyze_ec_certificate(patterns):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    pem = _self_signed(key, hashes.SHA256())
    matches = passive_scanner._analyze_certificate(pem, "ct:test", patterns)
    ids = {m.rule_id for m in matches}
    assert "ECDSA" in ids
