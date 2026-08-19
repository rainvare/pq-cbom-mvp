"""Calcula un score de prioridad a partir de pq_status y numero de ocurrencias."""

from __future__ import annotations

from .schema import Priority

_BASE_SCORE = {
    "vulnerable": 70,
    "at_risk": 40,
    "unknown": 20,
    "secure": 0,
}

_ACTION = {
    "vulnerable": "migrar antes de 90 dias",
    "at_risk": "migrar antes de 180 dias",
    "unknown": "revision manual para clasificar",
    "secure": "sin accion requerida",
}


def score(pq_status: str, occurrence_count: int) -> Priority:
    """Devuelve un Priority (score 0-100, banda y accion recomendada) para
    un hallazgo con el pq_status dado, ajustado por cuantas veces se repite
    la misma regla."""
    base = _BASE_SCORE.get(pq_status, 20)
    bump = min(occurrence_count - 1, 10) * 2 if base > 0 else 0
    total = min(base + bump, 100)

    if total >= 70:
        band = "critical"
    elif total >= 40:
        band = "high"
    elif total >= 20:
        band = "medium"
    elif total > 0:
        band = "low"
    else:
        band = "none"

    return Priority(score=total, band=band, recommended_action=_ACTION.get(pq_status, "revision manual"))
