"""Corpus de falsos positivos y negativos de detección (regresión).

Fija el comportamiento correcto en los casos que el review encontró rotos, para
que no vuelvan a aparecer.
"""

from pathlib import Path

import pytest

from pq_cbom.rules_engine import RuleSet
from pq_cbom.scanner import filter_hybrid

RULES = Path(__file__).resolve().parent.parent / "rules" / "pq_rules.yaml"


@pytest.fixture(scope="module")
def pats():
    return RuleSet.load(RULES).compiled_patterns()


def _ids(text, pats):
    hits = []
    for rid, ps in pats:
        for p in ps:
            if p.search(text):
                hits.append(rid)
                break
    return filter_hybrid(hits)


# --- Falsos POSITIVOS que NO deben dispararse ---
@pytest.mark.parametrize("text,forbidden", [
    ("les mots des amis en français", "DES"),
    ("arc4random_buf(buf, 16)", "RC4"),
    ("Miller-Rabin primality test", "Rabin"),   # detector eliminado
    ("from falcon import API", "FN-DSA"),
    ("SSH Protocol 1.2 negotiation", "SSHv1"),
    ("hashlib.sha384(data)", "SHA-3"),          # SHA-384 no es SHA-3
    ("spring-boot-starter-web", "RSA"),
    ("the addresses of the nodes", "DES"),
])
def test_no_false_positive(text, forbidden, pats):
    assert forbidden not in _ids(text, pats), f"FP: '{text}' disparó {forbidden}"


# --- Verdaderos positivos que SÍ deben detectarse ---
def test_ecdhe_detects_key_exchange(pats):
    assert "ECDH" in _ids("ECDHE-RSA-AES256-GCM-SHA384", pats)


def test_hybrid_is_not_vulnerable_ecdh(pats):
    ids = _ids("X25519MLKEM768", pats)
    assert "Hybrid-PQC" in ids
    assert "ECDH" not in ids          # el híbrido absorbe el componente clásico
    assert "ML-KEM" not in ids


def test_hybrid_reverse_order(pats):
    ids = _ids("mlkem768x25519-sha256", pats)
    assert "Hybrid-PQC" in ids
    assert "ECDH" not in ids


def test_mlkem_mldsa_without_hyphen(pats):
    assert "ML-KEM" in _ids("MLKEM768 shared secret", pats)
    assert "ML-DSA" in _ids("signed with mldsa65", pats)


def test_real_des_rc4_still_detected(pats):
    assert "DES" in _ids("Cipher.getInstance(\"DES/CBC/PKCS5Padding\")", pats)
    assert "RC4" in _ids("stream = RC4(key)", pats)


def test_sha3_real_still_detected(pats):
    assert "SHA-3" in _ids("hashlib.sha3_256(x)", pats)
    assert "SHA-3" in _ids("Keccak256(data)", pats)
