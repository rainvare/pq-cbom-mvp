"""Carga el paquete de detectores (rules/pq_rules.yaml) y lo enriquece con la
base de conocimiento (knowledge/algorithms.yaml).

Separación de responsabilidades:
  - rules/pq_rules.yaml  -> DETECCIÓN: id + patrones regex (dónde/cómo se ve).
  - knowledge/algorithms.yaml -> CLASIFICACIÓN: el saber (pq_status, por qué, reemplazo).

Cada detector referencia un algorithm_id de la base de conocimiento, de donde
hereda su clasificación. Se admite el formato antiguo con campos de clasificación
en línea (pq_status/rationale/...) para retrocompatibilidad; si el id existe en la
base de conocimiento, ésta tiene prioridad.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

from .knowledge import KnowledgeBase, VALID_PQ_STATUS


@dataclass
class Rule:
    """Un detector enriquecido con el saber de la base de conocimiento."""

    id: str
    category: str
    match: list[str]
    pq_status: str
    rationale: str
    replacement: Optional[str]
    case_sensitive: bool = False
    primitive: list = field(default_factory=list)
    # Campos enriquecidos desde la base de conocimiento (pueden ser None):
    name: Optional[str] = None
    quantum_attack: Optional[str] = None
    classical_bits: Optional[int] = None
    quantum_bits: Optional[int] = None
    nist_status: Optional[str] = None
    standard: Optional[str] = None
    deprecate_by: Optional[str] = None
    references: list[str] = field(default_factory=list)


class RuleSet:
    """Colección de detectores indexados por id, con sus versiones."""

    def __init__(self, version: str, rules: list[Rule], knowledge_version: str | None = None):
        self.version = version
        self.knowledge_version = knowledge_version
        self.rules = {r.id: r for r in rules}

    @classmethod
    def load(cls, path: Path, knowledge_path: Path | None = None) -> "RuleSet":
        """Lee los detectores desde `path` y los enriquece con la base de
        conocimiento. `knowledge_path` por defecto es knowledge/algorithms.yaml."""
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        kb = KnowledgeBase.load(knowledge_path)
        cls._validate_schema(raw, kb)

        rules: list[Rule] = []
        for r in raw["rules"]:
            rule_id = r["id"]
            if rule_id in kb:
                k = kb.get(rule_id)
                rules.append(
                    Rule(
                        id=rule_id,
                        category=r.get("category", k.family),
                        match=r["match"],
                        pq_status=k.pq_status,
                        rationale=k.rationale,
                        replacement=k.replacement,
                        case_sensitive=bool(r.get("case_sensitive", False)),
                        primitive=k.primitive,
                        name=k.name,
                        quantum_attack=k.quantum_attack,
                        classical_bits=k.classical_bits,
                        quantum_bits=k.quantum_bits,
                        nist_status=k.nist_status,
                        standard=k.standard,
                        deprecate_by=k.deprecate_by,
                        references=k.references,
                    )
                )
            else:
                # Retrocompatibilidad: detector sin entrada en la base de conocimiento.
                rules.append(
                    Rule(
                        id=rule_id,
                        category=r["category"],
                        match=r["match"],
                        pq_status=r["pq_status"],
                        rationale=r["rationale"],
                        replacement=r.get("replacement"),
                        case_sensitive=bool(r.get("case_sensitive", False)),
                    )
                )
        return cls(version=raw["version"], rules=rules, knowledge_version=kb.version)

    @staticmethod
    def _validate_schema(raw: dict, kb: KnowledgeBase) -> None:
        """Verifica que el YAML de detectores sea válido. Un detector debe
        tener id y match; si su id no está en la base de conocimiento, debe
        traer la clasificación en línea (formato antiguo)."""
        if "version" not in raw or "rules" not in raw:
            raise ValueError("El paquete de detectores debe tener 'version' y 'rules'.")
        seen_ids = set()
        for r in raw["rules"]:
            if "id" not in r or "match" not in r:
                raise ValueError(f"Detector incompleto, requiere 'id' y 'match': {r}")
            if r["id"] not in kb:
                for key in ("category", "pq_status", "rationale"):
                    if key not in r:
                        raise ValueError(
                            f"Detector {r['id']} no está en la base de conocimiento y le "
                            f"falta '{key}' (clasificación en línea requerida)."
                        )
                if r["pq_status"] not in VALID_PQ_STATUS:
                    raise ValueError(
                        f"Detector {r['id']}: pq_status '{r['pq_status']}' inválido."
                    )
            if r["id"] in seen_ids:
                raise ValueError(f"Detector duplicado: {r['id']}")
            seen_ids.add(r["id"])

    def compiled_patterns(self) -> list[tuple[str, list[re.Pattern]]]:
        """Por cada detector, su id y sus patrones `match` compilados.
        Case-insensitive por defecto; case-sensitive si el detector lo pide
        (acrónimos que coinciden con palabras comunes: DES, RC4, Falcon...)."""
        out = []
        for rule in self.rules.values():
            flags = 0 if rule.case_sensitive else re.IGNORECASE
            out.append((rule.id, [re.compile(p, flags) for p in rule.match]))
        return out

    def classify(self, rule_id: str) -> Rule:
        """Devuelve la Rule con ese id. Lanza KeyError si no existe."""
        if rule_id not in self.rules:
            raise KeyError(f"rule_id desconocido: {rule_id}")
        return self.rules[rule_id]
