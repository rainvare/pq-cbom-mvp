"""Tests del motor Slither (parseo por fixture + degradación)."""

from pathlib import Path

import pytest

from pq_cbom.contract_slither import SlitherNotAvailable, _parse_slither_json, scan_directory

_SLITHER_JSON = {
    "success": True,
    "results": {
        "detectors": [
            {
                "check": "reentrancy-eth",
                "impact": "High",
                "confidence": "Medium",
                "description": "Reentrancy in C.withdraw(uint256)\n\tExternal calls:\n",
                "elements": [
                    {"source_mapping": {"filename_relative": "C.sol", "lines": [12, 13]}}
                ],
            },
            {
                "check": "solc-version",
                "impact": "Informational",
                "description": "Pragma version ^0.7.0 is too old",
                "elements": [{"source_mapping": {"filename_relative": "C.sol", "lines": [2]}}],
            },
        ]
    },
}


def test_parse_maps_impact_and_critical():
    findings = _parse_slither_json(_SLITHER_JSON)
    by_id = {f.rule_id: f for f in findings}
    assert by_id["reentrancy-eth"].severity == "critical"  # elevado desde High
    assert by_id["reentrancy-eth"].file == "C.sol"
    assert by_id["reentrancy-eth"].line == 12
    assert by_id["solc-version"].severity == "info"


def test_parse_sorts_by_severity():
    findings = _parse_slither_json(_SLITHER_JSON)
    order = ["critical", "high", "medium", "low", "info"]
    idxs = [order.index(f.severity) for f in findings]
    assert idxs == sorted(idxs)


def test_scan_raises_when_slither_missing(tmp_path, monkeypatch):
    import pq_cbom.contract_slither as cs
    monkeypatch.setattr(cs.shutil, "which", lambda _: None)
    with pytest.raises(SlitherNotAvailable):
        scan_directory(tmp_path)
