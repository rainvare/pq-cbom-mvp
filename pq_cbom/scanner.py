"""Escanea codigo fuente linea por linea aplicando expresiones regulares."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb",
    ".c", ".h", ".cpp", ".hpp", ".cs", ".php", ".rs", ".kt",
    ".yaml", ".yml", ".json", ".conf", ".cnf", ".ini", ".env",
}

SKIP_DIRS = {".git", "node_modules", "__pycache__", "venv", ".venv", "dist", "build", ".tox"}


@dataclass
class RawMatch:
    rule_id: str
    file: str
    line: int
    snippet: str


def _looks_like_generated_cbom(path: Path) -> bool:
    """Devuelve True si `path` es un JSON cuyo contenido empieza con la
    clave "cbom_version" (un CBOM generado por este mismo programa)."""
    if path.suffix.lower() != ".json":
        return False
    try:
        head = path.open(encoding="utf-8", errors="ignore").read(200)
    except OSError:
        return False
    return '"cbom_version"' in head


def iter_source_files(target: Path, exclude: set[Path] | None = None) -> Iterable[Path]:
    """Recorre `target` y produce los archivos escaneables: extension
    soportada, fuera de SKIP_DIRS, fuera de `exclude`, y que no sean un CBOM
    generado previamente."""
    exclude = exclude or set()
    for path in target.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.resolve() in exclude:
            continue
        if path.suffix.lower() in SCANNABLE_EXTENSIONS:
            if _looks_like_generated_cbom(path):
                continue
            yield path


def scan_directory(
    target: Path,
    compiled_rules: list[tuple[str, list[re.Pattern]]],
    exclude: set[Path] | None = None,
) -> list[RawMatch]:
    """Aplica `compiled_rules` (lista de (rule_id, [regex_compiladas])) a
    cada linea de cada archivo escaneable bajo `target`, salteando las rutas
    en `exclude`. Devuelve un RawMatch por cada (linea, regla) que matchea."""
    matches: list[RawMatch] = []
    for path in iter_source_files(target, exclude):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        lines = text.splitlines()
        for lineno, line in enumerate(lines, start=1):
            for rule_id, patterns in compiled_rules:
                for pattern in patterns:
                    if pattern.search(line):
                        matches.append(
                            RawMatch(
                                rule_id=rule_id,
                                file=str(path),
                                line=lineno,
                                snippet=line.strip()[:200],
                            )
                        )
                        break
    return matches


def now_iso() -> str:
    """Timestamp actual en UTC, formato ISO 8601."""
    return datetime.now(timezone.utc).isoformat()
