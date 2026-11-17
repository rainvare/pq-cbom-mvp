"""Analizador de vulnerabilidades de smart contracts (Solidity).

Linter estático por patrón, alineado con el SWC Registry. A diferencia del
pipeline CBOM (que clasifica algoritmos por su estado post-cuántico), aquí el
modelo es de GRAVEDAD de seguridad (critical..info), porque las debilidades de
smart contracts (reentrancy, tx.origin, delegatecall...) no son algoritmos.

Incluye el puente cripto/PQ: `ecrecover` usa ECDSA sobre secp256k1, vulnerable
a Shor, lo que conecta este análisis con el modelo cuántico del resto del tool.

Honesto sobre sus límites: es heurística regex, no análisis simbólico; señala
patrones para revisión humana y puede tener falsos positivos.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path

import yaml

SKIP_DIRS = {".git", "node_modules", "__pycache__", "artifacts", "cache", "out", "lib"}
SOL_EXTENSIONS = {".sol"}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
VALID_SEVERITY = set(SEVERITY_ORDER)


@dataclass
class ContractRule:
    id: str
    severity: str
    category: str
    title: str
    match: list[str]
    rationale: str
    remediation: str
    references: list[str]


@dataclass
class ContractFinding:
    rule_id: str
    severity: str
    category: str
    title: str
    file: str
    line: int
    snippet: str
    rationale: str
    remediation: str
    references: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


class ContractRuleSet:
    def __init__(self, version: str, rules: list[ContractRule]):
        self.version = version
        self.rules = rules

    @classmethod
    def load(cls, path: Path) -> "ContractRuleSet":
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if "version" not in raw or "rules" not in raw:
            raise ValueError("El paquete de reglas de contratos debe tener 'version' y 'rules'.")
        rules = []
        seen = set()
        for r in raw["rules"]:
            for key in ("id", "severity", "category", "title", "match", "rationale", "remediation"):
                if key not in r:
                    raise ValueError(f"Regla de contrato incompleta, falta '{key}': {r.get('id', r)}")
            if r["severity"] not in VALID_SEVERITY:
                raise ValueError(f"Regla {r['id']}: severity inválida '{r['severity']}'.")
            if r["id"] in seen:
                raise ValueError(f"Regla de contrato duplicada: {r['id']}")
            seen.add(r["id"])
            rules.append(ContractRule(
                id=r["id"], severity=r["severity"], category=r["category"], title=r["title"],
                match=r["match"], rationale=r["rationale"], remediation=r["remediation"],
                references=r.get("references", []) or [],
            ))
        return cls(version=raw["version"], rules=rules)

    def compiled(self) -> list[tuple[ContractRule, list[re.Pattern]]]:
        return [(r, [re.compile(p, re.IGNORECASE) for p in r.match]) for r in self.rules]


def iter_sol_files(target: Path):
    for path in target.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in SOL_EXTENSIONS:
            yield path


def _strip_comment(line: str) -> str:
    """Elimina comentarios de línea // para reducir falsos positivos."""
    idx = line.find("//")
    return line[:idx] if idx != -1 else line


def scan_directory(target: Path, ruleset: ContractRuleSet) -> list[ContractFinding]:
    """Aplica las reglas a cada línea de cada .sol bajo `target`."""
    compiled = ruleset.compiled()
    findings: list[ContractFinding] = []
    for path in iter_sol_files(target):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for lineno, raw_line in enumerate(text.splitlines(), start=1):
            line = _strip_comment(raw_line)
            if not line.strip():
                continue
            for rule, patterns in compiled:
                for pat in patterns:
                    if pat.search(line):
                        findings.append(ContractFinding(
                            rule_id=rule.id, severity=rule.severity, category=rule.category,
                            title=rule.title, file=str(path), line=lineno,
                            snippet=line.strip()[:200], rationale=rule.rationale,
                            remediation=rule.remediation, references=rule.references,
                        ))
                        break
    findings.sort(key=lambda f: SEVERITY_ORDER.index(f.severity))
    return findings


def report(findings: list[ContractFinding], target: str, ruleset_version: str) -> dict:
    """Construye el informe JSON de vulnerabilidades de contratos."""
    from collections import Counter

    counts = Counter(f.severity for f in findings)
    return {
        "report_version": "0.1.0",
        "kind": "smart-contract-vulnerabilities",
        "target": target,
        "rules_version": ruleset_version,
        "summary": {sev: counts.get(sev, 0) for sev in SEVERITY_ORDER},
        "total": len(findings),
        "findings": [f.to_dict() for f in findings],
    }
