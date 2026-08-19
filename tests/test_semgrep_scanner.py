"""Tests del collector semgrep. Se saltan si `semgrep` no esta instalado."""

from pathlib import Path

import pytest

from pq_cbom.build import DEFAULT_SEMGREP_RULES, build_cbom
from pq_cbom.semgrep_scanner import is_available

pytestmark = pytest.mark.skipif(not is_available(), reason="semgrep no esta instalado")

TARGET = Path(__file__).resolve().parent.parent / "sample_target"
RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "pq_rules.yaml"


def test_semgrep_engine_finds_known_algorithms():
    entries = build_cbom(TARGET, RULES_PATH, engine="semgrep", semgrep_rules_path=DEFAULT_SEMGREP_RULES)
    rule_ids = {e.classification.rule_id for e in entries}
    for expected in {"RSA", "ECDH", "MD5", "SHA1", "3DES", "RC4", "AES-128", "AES-256", "TLS1.2"}:
        assert expected in rule_ids, f"no se detecto {expected} con el motor semgrep"


def test_semgrep_engine_covers_go_and_js():
    """Cubre algoritmos detectados en archivos .go y .js de sample_target."""
    entries = build_cbom(TARGET, RULES_PATH, engine="semgrep", semgrep_rules_path=DEFAULT_SEMGREP_RULES)

    go_findings = {e.classification.rule_id for e in entries if e.finding.file.endswith(".go")}
    assert go_findings == {"RSA", "MD5", "DES", "SHA-256"}

    js_findings = {e.classification.rule_id for e in entries if e.finding.file.endswith(".js")}
    assert js_findings == {"RSA", "MD5", "AES-128", "AES-256"}


def test_semgrep_does_not_match_inside_comments():
    """No debe reportar 'RSA' por el comentario de tls_config.yaml, pero si
    debe seguir detectando las claves reales de ese archivo."""
    entries = build_cbom(TARGET, RULES_PATH, engine="semgrep", semgrep_rules_path=DEFAULT_SEMGREP_RULES)
    tls_config_findings = [e for e in entries if "tls_config.yaml" in e.finding.file]
    rule_ids_in_config = {e.classification.rule_id for e in tls_config_findings}
    assert "RSA" not in rule_ids_in_config
    assert "TLS1.2" in rule_ids_in_config
    assert "ECDSA" in rule_ids_in_config


def test_regex_engine_has_the_documented_false_positive():
    """El motor regex si reporta 'RSA' por el comentario de tls_config.yaml."""
    entries = build_cbom(TARGET, RULES_PATH, engine="regex")
    tls_config_findings = [e for e in entries if "tls_config.yaml" in e.finding.file]
    rule_ids_in_config = {e.classification.rule_id for e in tls_config_findings}
    assert "RSA" in rule_ids_in_config


def test_semgrep_and_regex_agree_on_vulnerable_status_for_shared_findings():
    """Ambos motores deben clasificar igual un mismo hallazgo real (no el
    falso positivo) porque comparten el mismo pq_rules.yaml."""
    semgrep_entries = build_cbom(TARGET, RULES_PATH, engine="semgrep", semgrep_rules_path=DEFAULT_SEMGREP_RULES)
    regex_entries = build_cbom(TARGET, RULES_PATH, engine="regex")

    semgrep_rsa = next(e for e in semgrep_entries if e.classification.rule_id == "RSA" and "auth_service.py" in e.finding.file)
    regex_rsa = next(e for e in regex_entries if e.classification.rule_id == "RSA" and "auth_service.py" in e.finding.file and e.finding.line == semgrep_rsa.finding.line)

    assert semgrep_rsa.classification.pq_status == regex_rsa.classification.pq_status == "vulnerable"
