"""Carga la base de conocimiento criptográfica (knowledge/algorithms.yaml).

Es la fuente de verdad del producto: describe cada algoritmo de forma canónica
(familia, impacto cuántico, estado NIST, reemplazo, referencias). Los detectores
solo mapean evidencia -> algorithm_id; la clasificación sale de aquí.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

VALID_PQ_STATUS = {"vulnerable", "at_risk", "secure", "unknown"}
VALID_FAMILIES = {"asymmetric", "symmetric", "hash", "mac", "kdf", "protocol"}

DEFAULT_KNOWLEDGE_PATH = (
    Path(__file__).resolve().parent.parent / "knowledge" / "algorithms.yaml"
)


@dataclass
class AlgorithmEntry:
    """Un algoritmo en la base de conocimiento."""

    id: str
    name: str
    family: str
    pq_status: str
    rationale: str
    replacement: Optional[str] = None
    primitive: list[str] = field(default_factory=list)
    math_problem: Optional[str] = None
    quantum_attack: Optional[str] = None  # shor | grover | none
    classical_bits: Optional[int] = None
    quantum_bits: Optional[int] = None
    nist_status: Optional[str] = None
    standard: Optional[str] = None
    deprecate_by: Optional[str] = None
    references: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        from dataclasses import asdict

        return asdict(self)


class KnowledgeBase:
    """Colección de AlgorithmEntry indexada por id, con su versión."""

    def __init__(self, version: str, entries: list[AlgorithmEntry]):
        self.version = version
        self.by_id: dict[str, AlgorithmEntry] = {e.id: e for e in entries}

    def __contains__(self, algorithm_id: str) -> bool:
        return algorithm_id in self.by_id

    def __len__(self) -> int:
        return len(self.by_id)

    def get(self, algorithm_id: str) -> AlgorithmEntry:
        if algorithm_id not in self.by_id:
            raise KeyError(f"algorithm_id desconocido en la base de conocimiento: {algorithm_id}")
        return self.by_id[algorithm_id]

    def all(self) -> list[AlgorithmEntry]:
        return list(self.by_id.values())

    @classmethod
    def load(cls, path: Path | None = None) -> "KnowledgeBase":
        """Lee y valida knowledge/algorithms.yaml."""
        path = path or DEFAULT_KNOWLEDGE_PATH
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        cls._validate(raw)
        entries = [
            AlgorithmEntry(
                id=a["id"],
                name=a["name"],
                family=a["family"],
                pq_status=a["pq_status"],
                rationale=a["rationale"],
                replacement=a.get("replacement"),
                primitive=a.get("primitive", []) or [],
                math_problem=a.get("math_problem"),
                quantum_attack=a.get("quantum_attack"),
                classical_bits=a.get("classical_bits"),
                quantum_bits=a.get("quantum_bits"),
                nist_status=a.get("nist_status"),
                standard=a.get("standard"),
                deprecate_by=a.get("deprecate_by"),
                references=a.get("references", []) or [],
                aliases=a.get("aliases", []) or [],
            )
            for a in raw["algorithms"]
        ]
        return cls(version=raw["version"], entries=entries)

    @staticmethod
    def _validate(raw: dict) -> None:
        if "version" not in raw or "algorithms" not in raw:
            raise ValueError("La base de conocimiento debe tener 'version' y 'algorithms'.")
        seen = set()
        for a in raw["algorithms"]:
            for key in ("id", "name", "family", "pq_status", "rationale"):
                if key not in a:
                    raise ValueError(f"Algoritmo incompleto, falta '{key}': {a.get('id', a)}")
            if a["pq_status"] not in VALID_PQ_STATUS:
                raise ValueError(
                    f"Algoritmo {a['id']}: pq_status '{a['pq_status']}' inválido "
                    f"(debe ser uno de {sorted(VALID_PQ_STATUS)})"
                )
            if a["family"] not in VALID_FAMILIES:
                raise ValueError(
                    f"Algoritmo {a['id']}: family '{a['family']}' inválida "
                    f"(debe ser una de {sorted(VALID_FAMILIES)})"
                )
            if a["id"] in seen:
                raise ValueError(f"Algoritmo duplicado en la base de conocimiento: {a['id']}")
            seen.add(a["id"])
