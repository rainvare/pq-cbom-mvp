"""Escanea codigo fuente ejecutando el binario `semgrep` y traduce sus
resultados a RawMatch usando el campo metadata.pq_rule_id de cada regla."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from .scanner import RawMatch, _looks_like_generated_cbom


class SemgrepNotAvailable(RuntimeError):
    """El binario `semgrep` no esta instalado o no es ejecutable."""


def is_available() -> bool:
    """True si el binario `semgrep` esta en el PATH."""
    return shutil.which("semgrep") is not None


def _read_snippet(file: str, line: int) -> str:
    """Lee y recorta la linea `line` de `file` (semgrep no incluye el
    codigo fuente en su salida JSON sin autenticarse)."""
    try:
        lines = Path(file).read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return ""
    if 1 <= line <= len(lines):
        return lines[line - 1].strip()[:200]
    return ""


def scan_directory(target: Path, semgrep_rules: Path, exclude: set[Path] | None = None) -> list[RawMatch]:
    """Ejecuta `semgrep --config semgrep_rules` sobre `target` y devuelve un
    RawMatch por cada resultado cuya regla tenga metadata.pq_rule_id,
    salteando las rutas en `exclude`. Lanza SemgrepNotAvailable si el
    binario no esta instalado."""
    if not is_available():
        raise SemgrepNotAvailable(
            "semgrep no esta instalado en este entorno. Instalar con: pip install semgrep"
        )

    proc = subprocess.run(
        [
            "semgrep",
            "--config", str(semgrep_rules),
            str(target),
            "--json",
            "--quiet",
            "--disable-version-check",
            "--metrics=off",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode not in (0, 1):  # 1 = semgrep encontro findings, no es un error
        raise RuntimeError(f"semgrep fallo (exit {proc.returncode}): {proc.stderr[:2000]}")

    exclude = exclude or set()
    payload = json.loads(proc.stdout)
    matches: list[RawMatch] = []
    for result in payload.get("results", []):
        pq_rule_id = result.get("extra", {}).get("metadata", {}).get("pq_rule_id")
        if not pq_rule_id:
            continue
        file = result["path"]
        file_path = Path(file)
        if file_path.resolve() in exclude or _looks_like_generated_cbom(file_path):
            continue
        line = result["start"]["line"]
        matches.append(
            RawMatch(
                rule_id=pq_rule_id,
                file=file,
                line=line,
                snippet=_read_snippet(file, line),
            )
        )
    return matches
