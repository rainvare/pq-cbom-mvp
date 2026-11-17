"""Estructuras de datos del CBOM: Finding, Classification, Priority y CBOMEntry."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Optional


@dataclass
class Finding:
    """Evidencia cruda de un collector: donde se encontro y con que herramienta."""

    rule_id: str
    location: str  # "path/al/archivo:linea"
    file: str
    line: int
    snippet: str
    detected_by: str
    detected_at: str


@dataclass
class Classification:
    """Resultado de aplicar una regla de rules_engine a un Finding."""

    pq_status: str  # vulnerable | at_risk | secure | unknown
    category: str
    rule_id: str
    rule_version: str
    rationale: str
    replacement: Optional[str]
    primitive: list = None  # encryption | key-exchange | kem | signature | hashing...


@dataclass
class Priority:
    """Resultado de priority.score() para un Finding."""

    score: int
    band: str  # critical | high | medium | low | none
    recommended_action: str


@dataclass
class CBOMEntry:
    """Un hallazgo completo: evidencia + clasificacion + prioridad."""

    finding: Finding
    classification: Classification
    priority: Priority

    def to_dict(self) -> dict:
        """Representacion JSON-serializable de este hallazgo."""
        return {
            "crypto_asset": {
                "rule_id": self.finding.rule_id,
                "location": self.finding.location,
                "file": self.finding.file,
                "line": self.finding.line,
                "evidence_snippet": self.finding.snippet,
                "detected_by": self.finding.detected_by,
                "detected_at": self.finding.detected_at,
            },
            "classification": asdict(self.classification),
            "priority": asdict(self.priority),
        }
