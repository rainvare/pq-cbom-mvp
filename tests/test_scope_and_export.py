"""Tests del allowlist de scope y del export CycloneDX."""

from pq_cbom.cyclonedx import to_cyclonedx
from pq_cbom.passive_scanner import in_scope


def test_in_scope_exact_and_subdomain():
    scope = {"example.com"}
    assert in_scope("example.com", scope)
    assert in_scope("api.example.com", scope)
    assert in_scope("a.b.example.com", scope)


def test_in_scope_rejects_outside():
    scope = {"example.com"}
    assert not in_scope("evil.com", scope)
    assert not in_scope("notexample.com", scope)   # no es subdominio
    assert not in_scope("example.com.attacker.net", scope)


def test_in_scope_empty_authorizes_nothing():
    assert not in_scope("example.com", set())
    assert not in_scope("example.com", None)


def test_in_scope_handles_wildcard_entries():
    assert in_scope("api.example.com", {"*.example.com"})


_SAMPLE_CBOM = {
    "cbom_version": "0.1.0-mvp",
    "target": "demo",
    "rules_version": "pq_rules.yaml",
    "engine": "regex",
    "entries": [
        {
            "crypto_asset": {"location": "a.py:1", "detected_by": "test"},
            "classification": {
                "pq_status": "vulnerable", "category": "asymmetric", "rule_id": "RSA",
                "name": "RSA", "rationale": "Shor", "replacement": "ML-KEM-768",
            },
            "priority": {"score": 74, "band": "critical", "recommended_action": "migrar"},
        },
        {
            "crypto_asset": {"location": "b.py:2", "detected_by": "test"},
            "classification": {
                "pq_status": "secure", "category": "symmetric", "rule_id": "AES-256",
                "name": "AES-256", "rationale": "ok", "replacement": None,
            },
            "priority": {"score": 0, "band": "none", "recommended_action": "sin acción"},
        },
    ],
}


def test_cyclonedx_structure():
    bom = to_cyclonedx(_SAMPLE_CBOM)
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    assert len(bom["components"]) == 2
    for c in bom["components"]:
        assert c["type"] == "cryptographic-asset"
        assert "cryptoProperties" in c


def test_cyclonedx_maps_pq_status_and_nist_level():
    bom = to_cyclonedx(_SAMPLE_CBOM)
    rsa = next(c for c in bom["components"] if c["name"] == "RSA")
    statuses = {p["name"]: p["value"] for p in rsa["properties"]}
    assert statuses["pq-cbom:pq_status"] == "vulnerable"
    assert rsa["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 0
    assert rsa["cryptoProperties"]["algorithmProperties"]["primitive"] == "pke"


def test_cyclonedx_replacement_property():
    bom = to_cyclonedx(_SAMPLE_CBOM)
    rsa = next(c for c in bom["components"] if c["name"] == "RSA")
    props = {p["name"]: p["value"] for p in rsa["properties"]}
    assert props["pq-cbom:recommended_replacement"] == "ML-KEM-768"
