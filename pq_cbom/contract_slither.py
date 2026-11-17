"""Motor Slither para análisis de smart contracts (AST real, no regex).

Igual que `--engine semgrep` para código, este es `--engine slither` para
contratos: invoca Slither (https://github.com/crytic/slither), que compila el
contrato con solc y analiza el AST/CFG, eliminando los falsos positivos de la
heurística regex. Requiere `slither` y `solc` instalados.

Si Slither no está disponible, lanza SlitherNotAvailable (el CLI lo reporta y
sugiere el motor regex). El parseo del JSON es independiente del binario, para
poder testearlo por fixture.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from .contract_scanner import ContractFinding

# Impacto de Slither -> gravedad del informe.
_IMPACT_SEVERITY = {
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Informational": "info",
    "Optimization": "info",
}

# Algunos detectores de alto impacto se elevan a critical.
_CRITICAL_CHECKS = {"reentrancy-eth", "suicidal", "arbitrary-send-eth", "controlled-delegatecall"}


class SlitherNotAvailable(RuntimeError):
    """Slither (o solc) no está instalado en este entorno."""


def _parse_slither_json(data: dict) -> list[ContractFinding]:
    """Convierte la salida JSON de Slither en ContractFinding (independiente
    del binario, para testear por fixture)."""
    findings: list[ContractFinding] = []
    results = (data.get("results") or {}).get("detectors") or []
    for det in results:
        check = det.get("check", "slither")
        impact = det.get("impact", "Informational")
        if check in _CRITICAL_CHECKS:
            severity = "critical"
        else:
            severity = _IMPACT_SEVERITY.get(impact, "info")

        # Ubicación: primer elemento con source_mapping.
        file_, line = "", 0
        for el in det.get("elements", []) or []:
            sm = el.get("source_mapping") or {}
            if sm.get("filename_relative") or sm.get("filename_short") or sm.get("filename_absolute"):
                file_ = sm.get("filename_relative") or sm.get("filename_short") or sm.get("filename_absolute")
                lines = sm.get("lines") or []
                line = lines[0] if lines else 0
                break

        desc = (det.get("description") or "").strip()
        findings.append(ContractFinding(
            rule_id=check,
            severity=severity,
            category="slither",
            title=check.replace("-", " "),
            file=file_ or "(contrato)",
            line=line,
            snippet=desc.splitlines()[0][:200] if desc else check,
            rationale=desc[:500] or f"Detector Slither: {check}",
            remediation="Revisar la recomendación de Slither para este detector.",
            references=[f"https://github.com/crytic/slither/wiki/Detector-Documentation#{check}"],
        ))

    order = ["critical", "high", "medium", "low", "info"]
    findings.sort(key=lambda f: order.index(f.severity) if f.severity in order else 99)
    return findings


def scan_directory(target: Path, timeout: int = 300) -> list[ContractFinding]:
    """Ejecuta Slither sobre `target` y devuelve los hallazgos. Lanza
    SlitherNotAvailable si el binario no está, o RuntimeError si falla."""
    if shutil.which("slither") is None:
        raise SlitherNotAvailable(
            "slither no está instalado. Instalar con: pip install slither-analyzer "
            "(requiere también solc). Alternativa: usar --engine regex."
        )
    try:
        proc = subprocess.run(
            ["slither", str(target), "--json", "-"],
            capture_output=True, text=True, timeout=timeout,
        )
    except FileNotFoundError as e:  # noqa: PERF203
        raise SlitherNotAvailable("slither no se pudo ejecutar.") from e
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"Slither excedió el tiempo límite ({timeout}s).") from e

    # Slither devuelve código !=0 cuando encuentra hallazgos; el JSON va a stdout.
    if not proc.stdout.strip():
        raise RuntimeError(f"Slither no produjo salida JSON. stderr: {proc.stderr[:300]}")
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"No se pudo parsear la salida de Slither: {e}") from e
    return _parse_slither_json(data)
