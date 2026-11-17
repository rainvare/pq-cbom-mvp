"""Modelo de riesgo cuántico a nivel de organización.

No clasifica hallazgos individuales (eso lo hacen rules_engine + knowledge),
sino que los AGREGA en una evaluación accionable para una empresa:

  - Inventario por estado post-cuántico.
  - Exposición "harvest now, decrypt later" (HNDL): datos cifrados HOY con
    criptografía rompible por Shor pueden ser interceptados y almacenados ahora
    para descifrarlos cuando exista un computador cuántico relevante.
  - Teorema de Mosca: si la vida útil del dato (X) más el tiempo de migración
    (Y) supera el tiempo hasta un computador cuántico criptográficamente
    relevante (Z), la organización YA está en riesgo. (X + Y > Z).
  - Índice de riesgo y preparación cuántica (quantum readiness).
  - Hoja de ruta por bandas de prioridad.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

# Penalización por hallazgo según estado, con tope por categoría para que el
# tamaño del codebase no domine el índice (se pondera presencia + volumen acotado).
_STATUS_WEIGHT = {
    "vulnerable": 10,
    "at_risk": 5,
    "unknown": 2,
    "secure": 0,
}
_MAX_OCCURRENCES_COUNTED = 10  # rendimientos decrecientes a partir de aquí


@dataclass
class MoscaResult:
    data_shelf_life_years: int   # X
    migration_time_years: int    # Y
    years_to_qday: int           # Z
    collapse_risk_years: int     # X + Y - Z
    at_risk: bool
    verdict: str


@dataclass
class RiskAssessment:
    total_assets: int
    counts_by_status: dict
    hndl_exposed: int            # hallazgos asimétricos vulnerables (rompibles por Shor)
    hndl_examples: list = field(default_factory=list)
    short_keys: int = 0          # claves por debajo del tamaño mínimo (débiles ya hoy)
    short_key_examples: list = field(default_factory=list)
    quantum_readiness: int = 100  # % de activos ya cuántico-seguros
    risk_index: int = 0           # 0 (bien) .. 100 (crítico)
    risk_band: str = "low"
    mosca: dict | None = None
    roadmap: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        from dataclasses import asdict

        return asdict(self)


def _risk_band(index: int) -> str:
    if index >= 70:
        return "critical"
    if index >= 45:
        return "high"
    if index >= 20:
        return "medium"
    if index > 0:
        return "low"
    return "none"


def mosca(
    data_shelf_life_years: int = 10,
    migration_time_years: int = 5,
    years_to_qday: int = 10,
) -> MoscaResult:
    """Aplica la desigualdad de Mosca. Valores por defecto conservadores:
    datos sensibles 10 años, migración cripto 5 años, Q-day a ~10 años."""
    collapse = data_shelf_life_years + migration_time_years - years_to_qday
    at_risk = collapse > 0
    if at_risk:
        verdict = (
            f"EN RIESGO: X+Y supera Z en {collapse} año(s). Los datos protegidos hoy "
            f"con criptografía clásica podrían descifrarse antes de completar la migración."
        )
    else:
        verdict = (
            f"Margen de {-collapse} año(s): la migración cabe antes del Q-day estimado, "
            f"pero el margen se reduce cada año que se pospone."
        )
    return MoscaResult(
        data_shelf_life_years=data_shelf_life_years,
        migration_time_years=migration_time_years,
        years_to_qday=years_to_qday,
        collapse_risk_years=collapse,
        at_risk=at_risk,
        verdict=verdict,
    )


def assess(
    entries,
    data_shelf_life_years: int = 10,
    migration_time_years: int = 5,
    years_to_qday: int = 10,
) -> RiskAssessment:
    """Agrega una lista de CBOMEntry en una evaluación de riesgo organizacional."""
    total = len(entries)
    counts = Counter(e.classification.pq_status for e in entries)

    # Exposición HNDL: asimétrico vulnerable (rompible por Shor) = lo que de
    # verdad urge, porque el dato capturado hoy se descifra post-Q-day.
    hndl = [
        e for e in entries
        if e.classification.pq_status == "vulnerable" and e.classification.category == "asymmetric"
    ]
    hndl_examples = [
        {
            "rule_id": e.classification.rule_id,
            "location": e.finding.location,
            "replacement": e.classification.replacement,
        }
        for e in hndl[:10]
    ]

    # Claves cortas: material con tamaño por debajo del mínimo (débil ya HOY,
    # independientemente de lo cuántico). El collector lo marca en el snippet.
    short = [
        e for e in entries
        if "CLAVE CORTA" in (getattr(e.finding, "snippet", "") or "")
    ]
    short_examples = [
        {"rule_id": e.classification.rule_id, "location": e.finding.location,
         "evidence": getattr(e.finding, "snippet", "")}
        for e in short[:10]
    ]

    # Índice de riesgo ponderado (presencia + volumen acotado).
    penalty = 0.0
    for status, weight in _STATUS_WEIGHT.items():
        c = counts.get(status, 0)
        if c and weight:
            penalty += weight * min(c, _MAX_OCCURRENCES_COUNTED)
    # Recargo HNDL: lo asimétrico vulnerable pesa extra.
    penalty += 8 * min(len(hndl), 5)
    # Recargo por claves cortas: débiles ya hoy, no solo frente a cuántica.
    penalty += 6 * min(len(short), 5)
    risk_index = int(min(100, penalty))

    secure = counts.get("secure", 0)
    readiness = 100 if total == 0 else round(100 * secure / total)

    m = mosca(data_shelf_life_years, migration_time_years, years_to_qday)
    # Si Mosca dice que ya estamos en riesgo, el índice no puede ser bajo.
    if m.at_risk and hndl:
        risk_index = max(risk_index, 70)

    roadmap = _build_roadmap(entries)

    return RiskAssessment(
        total_assets=total,
        counts_by_status=dict(counts),
        hndl_exposed=len(hndl),
        hndl_examples=hndl_examples,
        short_keys=len(short),
        short_key_examples=short_examples,
        quantum_readiness=readiness,
        risk_index=risk_index,
        risk_band=_risk_band(risk_index),
        mosca=m.__dict__,
        roadmap=roadmap,
    )


def _build_roadmap(entries) -> dict:
    """Agrupa hallazgos no seguros por banda de prioridad -> acción/plazo."""
    bands: dict[str, dict] = {}
    for e in entries:
        if e.classification.pq_status == "secure":
            continue
        band = e.priority.band
        slot = bands.setdefault(band, {"count": 0, "action": e.priority.recommended_action, "algorithms": set()})
        slot["count"] += 1
        slot["algorithms"].add(e.classification.rule_id)
    # set -> lista ordenada para serializar.
    for slot in bands.values():
        slot["algorithms"] = sorted(slot["algorithms"])
    return bands
