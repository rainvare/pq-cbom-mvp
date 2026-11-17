"""Tests del collector de binarios y Dockerfiles."""

from pathlib import Path

from pq_cbom import binary_scanner
from pq_cbom.rules_engine import RuleSet

RULES = Path(__file__).resolve().parent.parent / "rules" / "pq_rules.yaml"


def _patterns():
    return RuleSet.load(RULES).compiled_patterns()


def test_detects_library_version_and_algorithms(tmp_path):
    # "Binario" sintético con magia ELF y strings cripto.
    blob = b"\x7fELF" + b"\x00" * 12 + b"OpenSSL 3.0.13  AES-256-GCM  RSA  sha256  "
    (tmp_path / "fake.so").write_bytes(blob)
    result = binary_scanner.scan_directory(tmp_path, _patterns())
    assert any("OpenSSL 3.0.13" in lib for lib in result.libraries)
    ids = {m.rule_id for m in result.matches}
    assert "AES-256" in ids
    assert "RSA" in ids


def test_dockerfile_base_image_and_packages(tmp_path):
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim\nRUN apt-get install -y openssl libssl-dev libgcrypt20\n"
    )
    result = binary_scanner.scan_directory(tmp_path, _patterns())
    joined = " ".join(result.libraries)
    assert "python:3.12-slim" in joined
    assert "openssl" in joined
    assert "libssl-dev" in joined


def test_skips_plain_text_files(tmp_path):
    (tmp_path / "readme.txt").write_text("this mentions RSA and AES but is not a binary")
    result = binary_scanner.scan_directory(tmp_path, _patterns())
    # No es binario ni Dockerfile -> sin hallazgos.
    assert result.matches == []
