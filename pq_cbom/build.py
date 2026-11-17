"""Ensambla el CBOM: llama a un collector, clasifica y prioriza cada hallazgo."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from . import (
    binary_scanner,
    keyfile_scanner,
    manifest_scanner,
    passive_scanner,
    scanner,
    semgrep_scanner,
    tls_scanner,
)
from .priority import score as priority_score
from .rules_engine import RuleSet
from .scanner import RawMatch
from .schema import CBOMEntry, Classification, Finding

DEFAULT_SEMGREP_RULES = Path(__file__).resolve().parent.parent / "rules" / "semgrep" / "pq_semgrep_rules.yaml"


def _assemble_entries(raw_matches: list[RawMatch], ruleset: RuleSet, detected_by: str) -> list[CBOMEntry]:
    """Convierte cada RawMatch en un CBOMEntry (Finding + Classification +
    Priority) usando `ruleset`, y devuelve la lista ordenada por score de
    prioridad descendente."""
    occurrence_counts = Counter(m.rule_id for m in raw_matches)
    detected_at = scanner.now_iso()

    entries: list[CBOMEntry] = []
    for m in raw_matches:
        rule = ruleset.classify(m.rule_id)
        finding = Finding(
            rule_id=m.rule_id,
            location=f"{m.file}:{m.line}",
            file=m.file,
            line=m.line,
            snippet=m.snippet,
            detected_by=detected_by,
            detected_at=detected_at,
        )
        classification = Classification(
            pq_status=rule.pq_status,
            category=rule.category,
            rule_id=rule.id,
            rule_version=ruleset.version,
            rationale=rule.rationale,
            replacement=rule.replacement,
            primitive=list(rule.primitive or []),
        )
        priority = priority_score(
            rule.pq_status, occurrence_counts[m.rule_id],
            category=rule.category, primitive=rule.primitive, rule_id=rule.id,
        )
        entries.append(CBOMEntry(finding=finding, classification=classification, priority=priority))

    entries.sort(key=lambda e: e.priority.score, reverse=True)
    return entries


def build_cbom(
    target: Path,
    rules_path: Path,
    engine: str = "regex",
    semgrep_rules_path: Path | None = None,
    output_path: Path | None = None,
) -> list[CBOMEntry]:
    """Escanea codigo fuente bajo `target` con el motor indicado ('regex' o
    'semgrep') y devuelve el CBOM resultante. `output_path`, si se pasa, se
    excluye del propio escaneo."""
    ruleset = RuleSet.load(rules_path)
    exclude = {output_path.resolve()} if output_path else set()

    if engine == "regex":
        raw_matches = scanner.scan_directory(target, ruleset.compiled_patterns(), exclude=exclude)
    elif engine == "semgrep":
        raw_matches = semgrep_scanner.scan_directory(
            target, semgrep_rules_path or DEFAULT_SEMGREP_RULES, exclude=exclude
        )
    else:
        raise ValueError(f"engine desconocido: {engine!r} (usar 'regex' o 'semgrep')")

    return _assemble_entries(raw_matches, ruleset, detected_by=f"pq-cbom-mvp/code-scanner[{engine}]")


def build_cbom_tls(
    hostname: str,
    rules_path: Path,
    port: int = 443,
    ip_address: str | None = None,
) -> list[CBOMEntry]:
    """Escanea el protocolo TLS y el certificado de `hostname:port` via
    sslyze y devuelve el CBOM resultante."""
    ruleset = RuleSet.load(rules_path)
    raw_matches = tls_scanner.scan_host(hostname, port=port, ip_address=ip_address)
    return _assemble_entries(raw_matches, ruleset, detected_by="pq-cbom-mvp/tls-scanner[sslyze]")


def build_cbom_keys(
    target: Path,
    rules_path: Path,
    output_path: Path | None = None,
) -> list[CBOMEntry]:
    """Escanea `target` buscando certificados y claves (material real en disco)
    y devuelve el CBOM con el tamaño de cada clave."""
    ruleset = RuleSet.load(rules_path)
    exclude = {output_path.resolve()} if output_path else set()
    raw_matches = keyfile_scanner.scan_directory(target, exclude=exclude)
    return _assemble_entries(raw_matches, ruleset, detected_by="pq-cbom-mvp/key-scanner")


def build_cbom_deps(
    target: Path,
    rules_path: Path,
    output_path: Path | None = None,
) -> tuple[list[CBOMEntry], "manifest_scanner.DepsResult"]:
    """Escanea manifiestos de dependencias bajo `target` y devuelve el CBOM de
    algoritmos implicados más el inventario de librerías cripto."""
    ruleset = RuleSet.load(rules_path)
    exclude = {output_path.resolve()} if output_path else set()
    result = manifest_scanner.scan_directory(target, exclude=exclude)
    entries = _assemble_entries(result.matches, ruleset, detected_by="pq-cbom-mvp/deps-scanner")
    return entries, result


def build_cbom_binary(
    target: Path,
    rules_path: Path,
    output_path: Path | None = None,
) -> tuple[list[CBOMEntry], "binary_scanner.BinaryResult"]:
    """Escanea binarios y Dockerfiles bajo `target`: algoritmos y librerías
    cripto enlazadas/instaladas."""
    ruleset = RuleSet.load(rules_path)
    exclude = {output_path.resolve()} if output_path else set()
    result = binary_scanner.scan_directory(target, ruleset.compiled_patterns(), exclude=exclude)
    entries = _assemble_entries(result.matches, ruleset, detected_by="pq-cbom-mvp/binary-scanner")
    return entries, result


def build_cbom_passive(
    domain: str,
    rules_path: Path,
    include_active: bool = True,
    port: int = 443,
    sample: int = 8,
    authorized_scope: set[str] | None = None,
) -> tuple[list[CBOMEntry], "passive_scanner.PassiveResult"]:
    """Descubrimiento pasivo (CT logs + opcionalmente TLS/cabeceras) de la
    superficie criptográfica de `domain`. Devuelve el CBOM y el PassiveResult
    con el contexto para el reporte (hosts descubiertos, TLS negociado...).

    La parte activa solo corre si `domain` está en `authorized_scope`."""
    ruleset = RuleSet.load(rules_path)
    result = passive_scanner.scan(
        domain, ruleset.compiled_patterns(), include_active=include_active,
        port=port, sample=sample, authorized_scope=authorized_scope,
    )
    entries = _assemble_entries(result.matches, ruleset, detected_by="pq-cbom-mvp/passive-scanner")
    return entries, result
