"""Tests del collector TLS (sslyze) contra un servidor local (tls_test_server.py).
Se saltan si sslyze o cryptography no estan instalados."""

import importlib.util
import ssl
from pathlib import Path

import pytest

from pq_cbom import tls_scanner
from pq_cbom.build import build_cbom_tls
from pq_cbom.rules_engine import RuleSet

pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("sslyze") is None or importlib.util.find_spec("cryptography") is None,
    reason="sslyze y/o cryptography no estan instalados",
)

from tests.tls_test_server import ec_key, local_tls_server, rsa_key  # noqa: E402

RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "pq_rules.yaml"


def test_tls12_only_server_with_rsa_cert_is_detected_correctly(tmp_path):
    """Servidor que solo negocia TLS 1.2 con certificado RSA: debe verse
    TLS1.2 y RSA, y ningun otro protocolo. (TLS 1.0/1.1 no se prueban aca:
    el OpenSSL de este entorno los rechaza a nivel de cipher suite incluso
    configurando ctx.minimum_version.)"""
    with local_tls_server(tmp_path, rsa_key(), ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2) as port:
        matches = tls_scanner.scan_host("localhost", port=port, ip_address="127.0.0.1")

    rule_ids = {m.rule_id for m in matches}
    assert rule_ids == {"TLS1.2", "RSA"}


def test_tls12_server_with_ec_cert_is_detected_correctly(tmp_path):
    """Servidor que solo negocia TLS 1.2 con certificado de curva eliptica:
    debe verse TLS1.2 y ECDSA, no RSA."""
    with local_tls_server(tmp_path, ec_key(), ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2) as port:
        matches = tls_scanner.scan_host("localhost", port=port, ip_address="127.0.0.1")

    rule_ids = {m.rule_id for m in matches}
    assert rule_ids == {"TLS1.2", "ECDSA"}


def test_build_cbom_tls_classifies_and_prioritizes_end_to_end(tmp_path):
    """build_cbom_tls debe clasificar, ubicar y priorizar los hallazgos
    correctamente, con el vulnerable (RSA) por encima del at_risk (TLS1.2)."""
    with local_tls_server(tmp_path, rsa_key(), ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2) as port:
        entries = build_cbom_tls("localhost", RULES_PATH, port=port, ip_address="127.0.0.1")

    by_rule = {e.classification.rule_id: e for e in entries}
    assert by_rule["TLS1.2"].classification.pq_status == "at_risk"
    assert by_rule["RSA"].classification.pq_status == "vulnerable"
    assert by_rule["RSA"].finding.location == f"localhost:{port}"
    assert by_rule["RSA"].classification.rule_version == RuleSet.load(RULES_PATH).version
    assert by_rule["RSA"].priority.score > by_rule["TLS1.2"].priority.score


def test_unreachable_host_raises_clear_error():
    """scan_host debe lanzar TlsScanError si no puede conectarse al host."""
    with pytest.raises(tls_scanner.TlsScanError):
        tls_scanner.scan_host("localhost", port=1, ip_address="127.0.0.1")
