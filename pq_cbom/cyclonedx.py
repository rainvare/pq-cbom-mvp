"""Exporta un CBOM nativo a CycloneDX 1.6 (formato estándar de SBOM/CBOM).

CycloneDX 1.6 añade `cryptographic-asset` como tipo de componente y
`cryptoProperties` para describir algoritmos y protocolos. Esto permite que el
inventario se consuma desde herramientas estándar (Dependency-Track, escáneres
SCA, etc.) en vez de quedar en un JSON propietario.

Referencia: https://cyclonedx.org/docs/1.6/json/
"""

from __future__ import annotations

from datetime import datetime, timezone

# Mapeo familia interna -> primitiva CycloneDX (enum cryptoProperties.algorithmProperties.primitive)
_PRIMITIVE_BY_FAMILY = {
    "asymmetric": "pke",      # refinado abajo según el uso cuando se puede inferir
    "symmetric": "block-cipher",
    "hash": "hash",
    "mac": "mac",
    "kdf": "kdf",
    "protocol": "other",
}

# Nivel de seguridad cuántica NIST (0 = roto por cuántica; 1/3/5 = categorías NIST)
_NIST_LEVEL_BY_STATUS = {
    "vulnerable": 0,
    "at_risk": 1,
    "secure": 3,
    "unknown": None,
}


def _primitive_for(category: str, rule_id: str) -> str:
    rid = rule_id.lower()
    if category == "asymmetric":
        if any(k in rid for k in ("kem", "dh", "ecdh", "kyber", "frodo", "mceliece", "bike", "hqc", "ntru")):
            return "key-agree"
        if any(k in rid for k in ("dsa", "ed25519", "falcon", "fn-", "slh", "sphincs")):
            return "signature"
        return "pke"
    if category == "symmetric":
        if any(k in rid for k in ("chacha", "rc4")):
            return "stream-cipher"
        return "block-cipher"
    return _PRIMITIVE_BY_FAMILY.get(category, "unknown")


def _asset_type(category: str) -> str:
    return "protocol" if category == "protocol" else "algorithm"


def to_cyclonedx(cbom: dict) -> dict:
    """Convierte un CBOM nativo (dict con 'entries') en un BOM CycloneDX 1.6."""
    now = datetime.now(timezone.utc).isoformat()
    components = []

    for i, entry in enumerate(cbom.get("entries", [])):
        asset = entry.get("crypto_asset", {})
        clf = entry.get("classification", {})
        prio = entry.get("priority", {})
        category = clf.get("category", "")
        rule_id = clf.get("rule_id", f"asset-{i}")
        location = asset.get("location", "")
        pq_status = clf.get("pq_status", "unknown")

        crypto_props: dict = {"assetType": _asset_type(category)}
        if category != "protocol":
            crypto_props["algorithmProperties"] = {
                "primitive": _primitive_for(category, rule_id),
                "cryptoFunctions": ["encrypt"] if category == "symmetric" else ["sign", "keygen"],
            }
            level = _NIST_LEVEL_BY_STATUS.get(pq_status)
            if level is not None:
                crypto_props["algorithmProperties"]["nistQuantumSecurityLevel"] = level

        component = {
            "type": "cryptographic-asset",
            "bom-ref": f"{rule_id}:{location}" if location else f"{rule_id}:{i}",
            "name": clf.get("name") or rule_id,
            "cryptoProperties": crypto_props,
            "properties": [
                {"name": "pq-cbom:pq_status", "value": pq_status},
                {"name": "pq-cbom:priority_band", "value": str(prio.get("band", ""))},
                {"name": "pq-cbom:priority_score", "value": str(prio.get("score", ""))},
                {"name": "pq-cbom:location", "value": location},
                {"name": "pq-cbom:detected_by", "value": asset.get("detected_by", "")},
            ],
        }
        if clf.get("replacement"):
            component["properties"].append(
                {"name": "pq-cbom:recommended_replacement", "value": clf["replacement"]}
            )
        if clf.get("rationale"):
            component["description"] = clf["rationale"]
        components.append(component)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": {
                "components": [
                    {"type": "application", "name": "pq-cbom", "version": cbom.get("cbom_version", "0.1.0")}
                ]
            },
            "component": {
                "type": "application",
                "name": cbom.get("target", "unknown-target"),
            },
            "properties": [
                {"name": "pq-cbom:rules_version", "value": str(cbom.get("rules_version", ""))},
                {"name": "pq-cbom:engine", "value": str(cbom.get("engine", ""))},
            ],
        },
        "components": components,
    }
