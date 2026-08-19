"""Carga un paquete de reglas YAML y clasifica algoritmos por rule_id."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

VALID_PQ_STATUS = {"vulnerable", "at_risk", "secure", "unknown"}


@dataclass
class Rule:
    id: str
    category: str
    match: list[str]
    pq_status: str
    rationale: str
    replacement: str | None


class RuleSet:
    """Coleccion de reglas indexadas por id, con su version de paquete."""

    def __init__(self, version: str, rules: list[Rule]):
        self.version = version
        self.rules = {r.id: r for r in rules}

    @classmethod
    def load(cls, path: Path) -> "RuleSet":
        """Lee y valida un paquete de reglas YAML desde `path`."""
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        cls._validate_schema(raw)
        rules = [
            Rule(
                id=r["id"],
                category=r["category"],
                match=r["match"],
                pq_status=r["pq_status"],
                rationale=r["rationale"],
                replacement=r.get("replacement"),
            )
            for r in raw["rules"]
        ]
        return cls(version=raw["version"], rules=rules)

    @staticmethod
    def _validate_schema(raw: dict) -> None:
        """Verifica que el YAML tenga los campos requeridos, un pq_status
        valido en cada regla y ids sin duplicar. Lanza ValueError si no."""
        if "version" not in raw or "rules" not in raw:
            raise ValueError("El paquete de reglas debe tener 'version' y 'rules'.")
        seen_ids = set()
        for r in raw["rules"]:
            for key in ("id", "category", "match", "pq_status", "rationale"):
                if key not in r:
                    raise ValueError(f"Regla incompleta, falta '{key}': {r}")
            if r["pq_status"] not in VALID_PQ_STATUS:
                raise ValueError(
                    f"Regla {r['id']}: pq_status '{r['pq_status']}' invalido "
                    f"(debe ser uno de {sorted(VALID_PQ_STATUS)})"
                )
            if r["id"] in seen_ids:
                raise ValueError(f"Regla duplicada: {r['id']}")
            seen_ids.add(r["id"])

    def compiled_patterns(self) -> list[tuple[str, list[re.Pattern]]]:
        """Devuelve, por cada regla, su id junto con sus patrones `match`
        compilados como regex case-insensitive."""
        return [
            (rule.id, [re.compile(p, re.IGNORECASE) for p in rule.match])
            for rule in self.rules.values()
        ]

    def classify(self, rule_id: str) -> Rule:
        """Devuelve la Rule con ese id. Lanza KeyError si no existe."""
        if rule_id not in self.rules:
            raise KeyError(f"rule_id desconocido: {rule_id}")
        return self.rules[rule_id]
