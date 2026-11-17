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


_CONFIDENTIALITY = {"encryption", "key-exchange", "kem", "key-transport"}
_SIGNATURE = {"signature"}
# Fallback cuando el CBOM no trae `primitive` (datos antiguos): por rule_id.
_FALLBACK_SIG_IDS = {"ECDSA", "Ed25519", "DSA", "Schnorr", "BLS", "GOST-R-34.10"}


def _primitives(entry) -> set:
    prims = getattr(entry.classification, "primitive", None) or []
    return {str(p).lower() for p in prims}


def _is_hndl(entry) -> bool:
    """True si es confidencialidad asimétrica vulnerable (expuesta a HNDL)."""
    if entry.classification.pq_status != "vulnerable" or entry.classification.category != "asymmetric":
        return False
    prims = _primitives(entry)
    if prims:
        return bool(prims & _CONFIDENTIALITY)
    # Sin primitive: todo asimétrico vulnerable que no sea claramente firma.
    return entry.classification.rule_id not in _FALLBACK_SIG_IDS


def _is_signature(entry) -> bool:
    if entry.classification.category != "asymmetric":
        return False
    prims = _primitives(entry)
    if prims:
        return bool(prims & _SIGNATURE) and not (prims & _CONFIDENTIALITY)
    return entry.classification.rule_id in _FALLBACK_SIG_IDS


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

    # Exposición HNDL: SOLO confidencialidad (intercambio de claves / cifrado /
    # KEM) vulnerable. Las FIRMAS no son HNDL: un dato capturado hoy no se
    # "descifra" rompiendo una firma a posteriori (el riesgo de firma es la
    # falsificación futura, que se cuenta aparte).
    hndl = [e for e in entries if _is_hndl(e)]
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

    # Firmas asimétricas vulnerables: riesgo de falsificación futura (no HNDL).
    vuln_sigs = [e for e in entries if e.classification.pq_status == "vulnerable" and _is_signature(e)]
    # Rotos clásicamente que no son asimétricos (DES/MD5/RC4/ECB...): deuda hoy.
    broken_classical = [
        e for e in entries
        if e.classification.pq_status == "vulnerable" and e.classification.category not in ("asymmetric",)
    ]
    at_risk_n = counts.get("at_risk", 0)

    # Índice de riesgo DISCRIMINANTE por tipo de exposición (no por nº de líneas).
    # El intercambio de claves vulnerable (HNDL) domina; una firma o un hash roto
    # pesan menos; un repo sin exposición asimétrica no puede ser "critical".
    idx = 0
    if hndl:
        idx += 45 + 3 * min(len(hndl), 5)          # exposición HNDL: lo más grave
    if vuln_sigs:
        idx += 20 + min(len(vuln_sigs), 5)         # falsificación futura
    if broken_classical:
        idx += 12                                   # cripto rota clásicamente
    if at_risk_n:
        idx += 6
    idx += 5 * min(len(short), 4)                   # claves cortas: débiles hoy
    m = mosca(data_shelf_life_years, migration_time_years, years_to_qday)
    if m.at_risk and hndl:
        idx += 8                                     # Mosca agrava, no fuerza
    risk_index = int(min(100, idx))

    # Preparación cuántica = sobre la CAPA ASIMÉTRICA (lo que la migración PQC
    # aborda), no sobre hashes/simétrico que inflan el número.
    quantum_relevant = [e for e in entries if e.classification.category in ("asymmetric",)]
    pq_ready = sum(1 for e in quantum_relevant if e.classification.pq_status == "secure")
    readiness = 100 if not quantum_relevant else round(100 * pq_ready / len(quantum_relevant))

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
