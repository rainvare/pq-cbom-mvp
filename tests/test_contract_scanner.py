"""Tests del analizador de vulnerabilidades de smart contracts."""

from pathlib import Path

from pq_cbom.contract_scanner import ContractRuleSet, report, scan_directory

RULES = Path(__file__).resolve().parent.parent / "rules" / "contract_rules.yaml"

_CONTRACT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;
contract C {
    function auth() public view returns (bool) { return tx.origin == msg.sender; }
    function withdraw(uint a) public {
        (bool ok,) = msg.sender.call{value: a}("");
    }
    function rand() public view returns (uint) { return block.timestamp; }
    function v(bytes32 h, uint8 x, bytes32 r, bytes32 s) public pure returns (address) {
        return ecrecover(h, x, r, s);
    }
    function p(address t, bytes memory d) public { t.delegatecall(d); }
}
"""


def _scan(tmp_path):
    (tmp_path / "C.sol").write_text(_CONTRACT)
    rs = ContractRuleSet.load(RULES)
    return scan_directory(tmp_path, rs), rs


def test_ruleset_loads():
    rs = ContractRuleSet.load(RULES)
    assert len(rs.rules) >= 10


def test_detects_core_vulnerabilities(tmp_path):
    findings, _ = _scan(tmp_path)
    ids = {f.rule_id for f in findings}
    assert "SWC-115-tx-origin" in ids
    assert "SWC-107-reentrancy" in ids
    assert "SWC-112-delegatecall" in ids
    assert "SWC-120-weak-randomness" in ids
    assert "PQ-ecrecover-ecdsa" in ids   # puente cripto/post-cuántico


def test_findings_sorted_by_severity(tmp_path):
    findings, _ = _scan(tmp_path)
    order = ["critical", "high", "medium", "low", "info"]
    idxs = [order.index(f.severity) for f in findings]
    assert idxs == sorted(idxs)


def test_report_structure(tmp_path):
    findings, rs = _scan(tmp_path)
    rep = report(findings, str(tmp_path), rs.version)
    assert rep["kind"] == "smart-contract-vulnerabilities"
    assert rep["total"] == len(findings)
    assert set(rep["summary"]) == {"critical", "high", "medium", "low", "info"}


def test_comments_are_ignored(tmp_path):
    (tmp_path / "X.sol").write_text("pragma solidity 0.8.20;\n// tx.origin in a comment\n")
    rs = ContractRuleSet.load(RULES)
    findings = scan_directory(tmp_path, rs)
    assert not any(f.rule_id == "SWC-115-tx-origin" for f in findings)
