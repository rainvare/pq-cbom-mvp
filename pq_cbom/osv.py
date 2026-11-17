"""Cliente de OSV.dev — vulnerabilidades conocidas (CVE/GHSA) de dependencias.

A diferencia de la lista curada de `manifest_scanner`, esto consulta la base de
datos pública OSV (https://osv.dev) para obtener las vulnerabilidades REALES de
cada dependencia con su versión. Red: usa la API pública vía el proxy.

API: POST https://api.osv.dev/v1/querybatch  (ids por paquete)
     GET  https://api.osv.dev/v1/vulns/{id}   (detalle de una vulnerabilidad)
"""

from __future__ import annotations

import json
import ssl
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

_UA = "pq-cbom-osv/1.0"


def _ca_bundle() -> str | None:
    import os
    for var in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "PQ_CBOM_CA_BUNDLE"):
        v = os.environ.get(var)
        if v and Path(v).exists():
            return v
    fallback = Path("/root/.ccr/ca-bundle.crt")
    return str(fallback) if fallback.exists() else None


class OsvError(RuntimeError):
    """No se pudo consultar OSV."""


@dataclass
class OsvVuln:
    package: str
    version: str
    ecosystem: str
    vuln_id: str
    summary: str = ""
    severity: str = ""

    def to_dict(self) -> dict:
        from dataclasses import asdict
        return asdict(self)


@dataclass
class OsvResult:
    vulns: list[OsvVuln] = field(default_factory=list)
    queried: int = 0
    notes: list[str] = field(default_factory=list)


def _ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    bundle = _ca_bundle()
    if bundle:
        try:
            ctx.load_verify_locations(cafile=bundle)
        except OSError:
            pass
    return ctx


def _post_json(url: str, payload: dict, timeout: int = 20) -> dict:
    body = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": _UA})
    with urllib.request.urlopen(req, timeout=timeout, context=_ctx()) as resp:
        return json.loads(resp.read())


def _get_json(url: str, timeout: int = 20) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    with urllib.request.urlopen(req, timeout=timeout, context=_ctx()) as resp:
        return json.loads(resp.read())


def _severity_of(detail: dict) -> str:
    """Extrae una etiqueta de severidad del detalle OSV (CVSS o database_specific)."""
    sev = detail.get("database_specific", {}).get("severity")
    if sev:
        return str(sev)
    for s in detail.get("severity", []) or []:
        if s.get("type", "").startswith("CVSS"):
            return f"{s.get('type')}:{s.get('score')}"
    return ""


def query_specs(specs: list[dict], fetch_details: int = 15) -> OsvResult:
    """Consulta OSV para una lista de specs {name, version, ecosystem}. Devuelve
    las vulnerabilidades encontradas; obtiene el detalle de hasta `fetch_details`."""
    result = OsvResult(queried=len(specs))
    if not specs:
        return result

    queries = [{"version": s["version"], "package": {"name": s["name"], "ecosystem": s["ecosystem"]}}
               for s in specs]
    try:
        data = _post_json("https://api.osv.dev/v1/querybatch", {"queries": queries})
    except Exception as e:  # noqa: BLE001
        raise OsvError(f"No se pudo consultar OSV: {e}") from e

    results = data.get("results", [])
    details_fetched = 0
    for spec, res in zip(specs, results):
        for v in res.get("vulns", []) or []:
            vid = v.get("id", "")
            summary, severity = "", ""
            if details_fetched < fetch_details and vid:
                try:
                    detail = _get_json(f"https://api.osv.dev/v1/vulns/{vid}")
                    summary = (detail.get("summary") or detail.get("details") or "")[:160]
                    severity = _severity_of(detail)
                    details_fetched += 1
                except Exception:  # noqa: BLE001
                    pass
            result.vulns.append(OsvVuln(
                package=spec["name"], version=spec["version"], ecosystem=spec["ecosystem"],
                vuln_id=vid, summary=summary, severity=severity,
            ))
    result.notes.append(f"OSV: {len(result.vulns)} vulnerabilidad(es) en {len(specs)} dependencia(s) con versión.")
    return result
