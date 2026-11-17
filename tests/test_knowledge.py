"""Valida la base de conocimiento y su coherencia con los detectores."""

from pathlib import Path

import pytest

from pq_cbom.knowledge import VALID_FAMILIES, VALID_PQ_STATUS, KnowledgeBase
from pq_cbom.rules_engine import RuleSet

KB_PATH = Path(__file__).resolve().parent.parent / "knowledge" / "algorithms.yaml"
RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "pq_rules.yaml"


@pytest.fixture(scope="module")
def kb():
    return KnowledgeBase.load(KB_PATH)


def test_knowledge_loads(kb):
    assert len(kb) >= 25
    assert "RSA" in kb and "ML-KEM" in kb


def test_every_entry_has_valid_status_and_family(kb):
    for e in kb.all():
        assert e.pq_status in VALID_PQ_STATUS, f"{e.id}: estado inválido"
        assert e.family in VALID_FAMILIES, f"{e.id}: familia inválida"


def test_vulnerable_and_at_risk_have_replacement(kb):
    for e in kb.all():
        if e.pq_status in ("vulnerable", "at_risk"):
            assert e.replacement, f"{e.id} debería sugerir un reemplazo"


def test_secure_entries_have_no_replacement(kb):
    for e in kb.all():
        if e.pq_status == "secure":
            assert e.replacement is None, f"{e.id} seguro no debería tener reemplazo"


def test_every_detector_id_exists_in_knowledge():
    """Todo detector de pq_rules.yaml debe tener su entrada canónica en la KB."""
    kb = KnowledgeBase.load(KB_PATH)
    ruleset = RuleSet.load(RULES_PATH)
    missing = set(ruleset.rules) - set(kb.by_id)
    assert not missing, f"Detectores sin entrada en la base de conocimiento: {missing}"


def test_classification_comes_from_knowledge():
    """El pq_status del detector debe coincidir con el de la KB (fuente de verdad)."""
    kb = KnowledgeBase.load(KB_PATH)
    ruleset = RuleSet.load(RULES_PATH)
    for rule_id, rule in ruleset.rules.items():
        assert rule.pq_status == kb.get(rule_id).pq_status
