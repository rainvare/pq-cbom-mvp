"""Fija el pq_status esperado para cada rule_id de rules/pq_rules.yaml."""

from pathlib import Path

import pytest

from pq_cbom.rules_engine import RuleSet

RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "pq_rules.yaml"

EXPECTED_STATUS = {
    "RSA": "vulnerable",
    "DSA": "vulnerable",
    "DH": "vulnerable",
    "ECDSA": "vulnerable",
    "ECDH": "vulnerable",
    "Ed25519": "vulnerable",
    "ECC-GENERIC": "vulnerable",
    "ML-KEM": "secure",
    "ML-DSA": "secure",
    "SLH-DSA": "secure",
    "AES-256": "secure",
    "AES-128": "at_risk",
    "AES-GENERIC": "unknown",
    "ChaCha20": "secure",
    "DES": "vulnerable",
    "3DES": "vulnerable",
    "RC4": "vulnerable",
    "MD5": "vulnerable",
    "SHA1": "vulnerable",
    "SHA-256": "secure",
    "SHA-3": "secure",
    "TLS1.0": "vulnerable",
    "TLS1.1": "vulnerable",
    "TLS1.2": "at_risk",
    "TLS1.3": "unknown",
    # --- Añadidos en v2.0 (clasificación desde knowledge/algorithms.yaml) ---
    "ElGamal": "vulnerable",
    "FN-DSA": "secure",
    "HQC": "secure",
    "Classic-McEliece": "secure",
    "BIKE": "secure",
    "NTRU": "secure",
    "FrodoKEM": "secure",
    "Camellia": "secure",
    "Blowfish": "vulnerable",
    "BLAKE2": "secure",
    "PBKDF2": "at_risk",
    "bcrypt": "secure",
    "Argon2": "secure",
    "SSHv1": "vulnerable",
}


@pytest.fixture(scope="module")
def ruleset():
    return RuleSet.load(RULES_PATH)


def test_every_rule_has_a_golden_expectation(ruleset):
    """Toda regla en pq_rules.yaml debe tener una entrada en EXPECTED_STATUS."""
    missing = set(ruleset.rules) - set(EXPECTED_STATUS)
    assert not missing, f"Reglas nuevas sin golden test: {missing}"


def test_every_golden_expectation_matches_a_rule(ruleset):
    """Toda entrada en EXPECTED_STATUS debe corresponder a una regla existente."""
    missing = set(EXPECTED_STATUS) - set(ruleset.rules)
    assert not missing, f"Golden tests para reglas que ya no existen: {missing}"


@pytest.mark.parametrize("rule_id,expected_status", sorted(EXPECTED_STATUS.items()))
def test_rule_classification(ruleset, rule_id, expected_status):
    """El pq_status de cada regla coincide con el valor fijado en EXPECTED_STATUS."""
    rule = ruleset.classify(rule_id)
    assert rule.pq_status == expected_status


def test_vulnerable_and_at_risk_rules_have_replacement(ruleset):
    """Toda regla vulnerable o at_risk debe sugerir un reemplazo."""
    for rule in ruleset.rules.values():
        if rule.pq_status in ("vulnerable", "at_risk"):
            assert rule.replacement, f"{rule.id} deberia sugerir un reemplazo"
