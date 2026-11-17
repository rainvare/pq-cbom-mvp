"""Tests del modelo de riesgo cuántico (Mosca + agregación)."""

from types import SimpleNamespace

from pq_cbom.risk_model import assess, mosca


def _entry(pq_status, category, rule_id="X", band="high", action="migrar", location="f:1", replacement="Z", snippet=""):
    return SimpleNamespace(
        finding=SimpleNamespace(location=location, snippet=snippet),
        classification=SimpleNamespace(
            pq_status=pq_status, category=category, rule_id=rule_id, replacement=replacement
        ),
        priority=SimpleNamespace(band=band, recommended_action=action),
    )


def test_assess_counts_short_keys():
    entries = [
        _entry("vulnerable", "asymmetric", "RSA", snippet="clave privada: RSAPublicKey 1024 bits [CLAVE CORTA]"),
        _entry("vulnerable", "asymmetric", "RSA", snippet="clave pública: RSAPublicKey 4096 bits"),
    ]
    a = assess(entries)
    assert a.short_keys == 1
    assert a.short_key_examples and "1024" in a.short_key_examples[0]["evidence"]


def test_mosca_at_risk_when_x_plus_y_exceed_z():
    r = mosca(data_shelf_life_years=10, migration_time_years=5, years_to_qday=10)
    assert r.at_risk is True
    assert r.collapse_risk_years == 5


def test_mosca_safe_margin():
    r = mosca(data_shelf_life_years=2, migration_time_years=2, years_to_qday=15)
    assert r.at_risk is False
    assert r.collapse_risk_years == -11


def test_assess_empty_is_fully_ready():
    a = assess([])
    assert a.total_assets == 0
    assert a.quantum_readiness == 100
    assert a.risk_index == 0
    assert a.risk_band == "none"


def test_assess_counts_hndl_exposure():
    entries = [
        _entry("vulnerable", "asymmetric", "RSA"),
        _entry("vulnerable", "asymmetric", "ECDSA"),
        _entry("vulnerable", "symmetric", "DES"),  # vulnerable pero no HNDL (no asimétrico)
        _entry("secure", "symmetric", "AES-256"),
    ]
    a = assess(entries)
    assert a.hndl_exposed == 2
    assert a.total_assets == 4
    assert a.quantum_readiness == 25
    assert a.risk_band in ("high", "critical")


def test_assess_readiness_all_secure():
    entries = [_entry("secure", "symmetric", "AES-256"), _entry("secure", "hash", "SHA-256")]
    a = assess(entries)
    assert a.quantum_readiness == 100
    assert a.hndl_exposed == 0


def test_roadmap_groups_by_band():
    entries = [
        _entry("vulnerable", "asymmetric", "RSA", band="critical"),
        _entry("at_risk", "symmetric", "AES-128", band="high"),
        _entry("secure", "symmetric", "AES-256", band="none"),  # no entra al roadmap
    ]
    a = assess(entries)
    assert "critical" in a.roadmap
    assert "high" in a.roadmap
    assert "none" not in a.roadmap
    assert "RSA" in a.roadmap["critical"]["algorithms"]
