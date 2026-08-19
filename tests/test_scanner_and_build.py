"""Tests de integracion del collector de codigo (motor regex) contra sample_target."""

from pathlib import Path

from pq_cbom.build import build_cbom

TARGET = Path(__file__).resolve().parent.parent / "sample_target"
RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "pq_rules.yaml"


def test_build_cbom_finds_known_vulnerable_algorithms():
    entries = build_cbom(TARGET, RULES_PATH)
    rule_ids = {e.classification.rule_id for e in entries}

    for expected in {"RSA", "ECDH", "MD5", "SHA1", "3DES", "RC4"}:
        assert expected in rule_ids, f"no se detecto {expected} en sample_target"


def test_build_cbom_finds_known_secure_algorithms():
    entries = build_cbom(TARGET, RULES_PATH)
    rule_ids = {e.classification.rule_id for e in entries}

    for expected in {"AES-256", "SHA-256"}:
        assert expected in rule_ids, f"no se detecto {expected} en sample_target"


def test_every_entry_has_reproducible_evidence():
    entries = build_cbom(TARGET, RULES_PATH)
    assert entries, "no se generaron hallazgos"
    for e in entries:
        assert Path(e.finding.file).exists()
        assert e.finding.line > 0
        assert e.finding.snippet
        assert e.classification.rule_version  # trazable a la version del paquete de reglas


def test_entries_sorted_by_priority_descending():
    entries = build_cbom(TARGET, RULES_PATH)
    scores = [e.priority.score for e in entries]
    assert scores == sorted(scores, reverse=True)


def test_vulnerable_findings_outrank_secure_ones():
    entries = build_cbom(TARGET, RULES_PATH)
    by_rule = {e.classification.rule_id: e for e in entries}
    assert by_rule["RSA"].priority.score > by_rule["AES-256"].priority.score


def test_scanning_twice_in_a_row_does_not_inflate_findings(tmp_path):
    """Escanear el mismo target dos veces, con un cbom.json ya escrito por
    la primera corrida, debe dar el mismo numero de hallazgos."""
    import shutil

    scan_target = tmp_path / "target"
    shutil.copytree(TARGET, scan_target)
    output_path = scan_target / "cbom.json"

    first_count = len(build_cbom(scan_target, RULES_PATH, output_path=output_path))
    output_path.write_text(
        '{"cbom_version": "0.1.0-mvp", "entries": []}',
        encoding="utf-8",
    )
    second_count = len(build_cbom(scan_target, RULES_PATH, output_path=output_path))

    assert first_count == second_count
