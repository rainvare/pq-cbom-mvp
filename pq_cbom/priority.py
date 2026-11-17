"""Prioridad de un hallazgo según su estado, su PRIMITIVA y su recurrencia.

La banda ya no es un alias del estado: una confidencialidad asimétrica rota
(intercambio de claves, expuesto a HNDL) es crítica; una firma vulnerable es
alta (riesgo de falsificación futura, no de descifrado retroactivo); un hash o
cifrador roto clásicamente es alto; lo at_risk es medio; lo unknown, bajo.
Los plazos se alinean con la transición NIST (2030/2035), no con "90 días".
"""

from __future__ import annotations

from .schema import Priority

_CONFIDENTIALITY = {"encryption", "key-exchange", "kem", "key-transport"}
_SIGNATURE_IDS = {"ECDSA", "Ed25519", "DSA", "Schnorr", "BLS", "GOST-R-34.10"}

_BAND_SCORE = {"critical": 90, "high": 70, "medium": 45, "low": 20, "none": 0}
_ACTION = {
    "critical": "migrar con prioridad: dato expuesto a 'harvest now, decrypt later'",
    "high": "planificar migración a PQC (objetivo NIST: 2030, prohibido 2035)",
    "medium": "revisar y endurecer (tamaño de clave / suite / versión)",
    "low": "revisar manualmente para clasificar",
    "none": "sin acción requerida",
}


def _band(pq_status: str, category: str | None, primitive, rule_id: str | None) -> str:
    if pq_status == "secure":
        return "none"
    if pq_status == "unknown":
        return "low"
    if pq_status == "at_risk":
        return "medium"
    # vulnerable:
    prims = {str(p).lower() for p in (primitive or [])}
    if category == "asymmetric":
        is_sig = (prims & {"signature"} and not (prims & _CONFIDENTIALITY)) or \
                 (not prims and rule_id in _SIGNATURE_IDS)
        if is_sig:
            return "high"           # falsificación futura
        return "critical"          # confidencialidad asimétrica = HNDL
    return "high"                  # simétrico/hash roto clásicamente


def score(pq_status: str, occurrence_count: int,
          category: str | None = None, primitive=None, rule_id: str | None = None) -> Priority:
    """Devuelve un Priority (score, banda, acción) discriminando por primitiva."""
    band = _band(pq_status, category, primitive, rule_id)
    base = _BAND_SCORE[band]
    bump = min(occurrence_count - 1, 10) if base > 0 else 0
    total = min(base + bump, 100)
    return Priority(score=total, band=band, recommended_action=_ACTION[band])
