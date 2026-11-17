"""CLI: `python -m pq_cbom.cli scan <path>` / `scan-tls <host>`."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from .build import (
    build_cbom,
    build_cbom_deps,
    build_cbom_keys,
    build_cbom_passive,
    build_cbom_tls,
)
from .knowledge import KnowledgeBase
from .passive_scanner import PassiveScanError
from .risk_model import assess as risk_assess
from .semgrep_scanner import SemgrepNotAvailable
from .tls_scanner import TlsScanError

DEFAULT_RULES = Path(__file__).resolve().parent.parent / "rules" / "pq_rules.yaml"
DEFAULT_CONTRACT_RULES = Path(__file__).resolve().parent.parent / "rules" / "contract_rules.yaml"
DEFAULT_SEMGREP_RULES = Path(__file__).resolve().parent.parent / "rules" / "semgrep" / "pq_semgrep_rules.yaml"

_STATUS_ORDER = ["vulnerable", "at_risk", "unknown", "secure"]


def _print_summary(entries) -> None:
    """Imprime el conteo por pq_status y los 15 hallazgos de mayor prioridad."""
    counts = Counter(e.classification.pq_status for e in entries)
    total = len(entries)
    print(f"\n=== Resumen CBOM: {total} hallazgos ===")
    for status in _STATUS_ORDER:
        if counts.get(status):
            print(f"  {status:12s}: {counts[status]}")

    print("\n=== Top prioridades ===")
    for e in entries[:15]:
        if e.priority.score == 0:
            continue
        print(
            f"  [{e.priority.band:8s} {e.priority.score:3d}] {e.classification.rule_id:14s} "
            f"{e.finding.location}"
        )
        print(f"      -> {e.classification.rationale}")
        if e.classification.replacement:
            print(f"      -> reemplazo sugerido: {e.classification.replacement}")


def _write_cbom(entries, output_path: Path, target: str, rules_name: str, engine: str) -> None:
    """Serializa `entries` como CBOM JSON en `output_path`."""
    cbom_json = {
        "cbom_version": "0.1.0-mvp",
        "target": target,
        "rules_version": rules_name,
        "engine": engine,
        "entries": [e.to_dict() for e in entries],
    }
    output_path.write_text(json.dumps(cbom_json, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"CBOM escrito en: {output_path}")


def _print_passive_context(result) -> None:
    """Imprime el contexto del descubrimiento pasivo (hosts, TLS, cabeceras)."""
    print("\n=== Descubrimiento pasivo ===")
    if result.discovered_hosts:
        print(f"  Hosts descubiertos (CT logs): {len(result.discovered_hosts)}")
        for h in result.discovered_hosts[:10]:
            print(f"    - {h}")
        if len(result.discovered_hosts) > 10:
            print(f"    ... y {len(result.discovered_hosts) - 10} más")
    if result.tls_version:
        verif = "verificado" if result.cert_verified else "NO verificado"
        print(f"  TLS negociado: {result.tls_version} / {result.tls_cipher} (cert {verif})")
    if result.security_headers:
        print("  Cabeceras de seguridad:")
        for k, v in result.security_headers.items():
            print(f"    {k}: {v[:80]}")
    if getattr(result, "jwt_algorithms", None):
        print(f"  Algoritmos JWT: {', '.join(result.jwt_algorithms)}")
    if getattr(result, "caa_records", None):
        print(f"  Registros CAA: {len(result.caa_records)}")
        for c in result.caa_records[:5]:
            print(f"    - {c}")
    for note in result.notes:
        print(f"  · {note}")


_PQ_SEVERITY = {"vulnerable": 3, "at_risk": 2, "unknown": 1, "secure": 0}
_BAND_SEVERITY = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}


def _ci_gate_entries(entries, fail_on: str | None) -> int:
    """Devuelve 1 si algún hallazgo alcanza el nivel `fail_on` (o peor)."""
    if not fail_on:
        return 0
    threshold = _PQ_SEVERITY[fail_on]
    worst = [e for e in entries if _PQ_SEVERITY.get(e.classification.pq_status, 0) >= threshold]
    if worst:
        print(f"\n[CI] FALLO: {len(worst)} hallazgo(s) de nivel '{fail_on}' o peor.", file=sys.stderr)
        return 1
    print(f"\n[CI] OK: sin hallazgos de nivel '{fail_on}' o peor.")
    return 0


def _load_cbom_entries(path: Path):
    """Reconstruye objetos con acceso por atributo desde un cbom.json."""
    from types import SimpleNamespace

    data = json.loads(path.read_text(encoding="utf-8"))
    entries = []
    for e in data.get("entries", []):
        asset = e.get("crypto_asset", {})
        entries.append(
            SimpleNamespace(
                finding=SimpleNamespace(
                    location=asset.get("location", ""),
                    snippet=asset.get("evidence_snippet", ""),
                ),
                classification=SimpleNamespace(**e.get("classification", {})),
                priority=SimpleNamespace(**e.get("priority", {})),
            )
        )
    return entries


def _print_risk(a) -> None:
    """Imprime la evaluación de riesgo cuántico agregada."""
    print("\n=== Evaluación de riesgo cuántico ===")
    print(f"  Activos cripto inventariados : {a.total_assets}")
    print(f"  Preparación cuántica         : {a.quantum_readiness}% ya cuántico-seguro")
    print(f"  Índice de riesgo             : {a.risk_index}/100 [{a.risk_band}]")
    print(f"  Exposición HNDL              : {a.hndl_exposed} activos asimétricos rompibles por Shor")
    if getattr(a, "short_keys", 0):
        print(f"  Claves cortas (débiles hoy)  : {a.short_keys}")

    m = a.mosca or {}
    print("\n  -- Teorema de Mosca (harvest now, decrypt later) --")
    print(f"     X vida útil del dato : {m.get('data_shelf_life_years')} años")
    print(f"     Y tiempo de migración: {m.get('migration_time_years')} años")
    print(f"     Z años hasta Q-day   : {m.get('years_to_qday')} años")
    print(f"     {m.get('verdict')}")

    if a.hndl_examples:
        print("\n  -- Prioridad máxima (migrar primero) --")
        for ex in a.hndl_examples[:8]:
            print(f"     [{ex['rule_id']}] {ex['location']}")
            if ex.get("replacement"):
                print(f"        -> {ex['replacement']}")

    if a.roadmap:
        print("\n  -- Hoja de ruta por banda --")
        for band in ["critical", "high", "medium", "low"]:
            slot = a.roadmap.get(band)
            if slot:
                print(f"     [{band:8s}] {slot['count']:3d} hallazgos | {slot['action']}")
                print(f"                 algoritmos: {', '.join(slot['algorithms'])}")


def _print_contracts(rep: dict) -> None:
    """Imprime el resumen del análisis de smart contracts."""
    print(f"\n=== Vulnerabilidades de smart contracts: {rep['total']} hallazgos ===")
    for sev in ["critical", "high", "medium", "low", "info"]:
        n = rep["summary"].get(sev, 0)
        if n:
            print(f"  {sev:9s}: {n}")
    print("\n=== Hallazgos (por gravedad) ===")
    for f in rep["findings"][:20]:
        print(f"  [{f['severity']:8s}] {f['rule_id']:22s} {f['file']}:{f['line']}")
        print(f"      {f['title']}")
        print(f"      -> {f['remediation']}")
    if rep["total"] > 20:
        print(f"  ... y {rep['total'] - 20} más (ver informe JSON)")


def _run_kb(query: str | None) -> int:
    """Lista o busca algoritmos en la base de conocimiento."""
    kb = KnowledgeBase.load()
    if not query:
        print(f"Base de conocimiento v{kb.version} — {len(kb)} algoritmos:\n")
        for e in kb.all():
            print(f"  {e.id:18s} [{e.pq_status:10s}] {e.family:10s} {e.name}")
        return 0

    q = query.lower()
    hits = [
        e for e in kb.all()
        if q in e.id.lower() or q in e.name.lower() or any(q in a.lower() for a in e.aliases)
    ]
    if not hits:
        print(f"Sin coincidencias para '{query}'.")
        return 1
    for e in hits:
        print(f"\n=== {e.id} — {e.name} ===")
        print(f"  familia         : {e.family}")
        print(f"  estado PQ       : {e.pq_status}")
        print(f"  ataque cuántico : {e.quantum_attack}")
        print(f"  bits clásico/Q  : {e.classical_bits} / {e.quantum_bits}")
        print(f"  estado NIST     : {e.nist_status}")
        print(f"  estándar        : {e.standard}")
        print(f"  deprecación     : {e.deprecate_by}")
        print(f"  reemplazo       : {e.replacement}")
        print(f"  razón           : {e.rationale}")
        if e.references:
            print(f"  referencias     : {', '.join(e.references)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Punto de entrada del CLI: parsea argumentos y ejecuta `scan` o `scan-tls`."""
    parser = argparse.ArgumentParser(prog="pq-cbom", description="MVP de CBOM post-cuantico")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Escanea codigo fuente en un directorio")
    scan_p.add_argument("target", type=Path, help="Directorio a escanear")
    scan_p.add_argument("--rules", type=Path, default=DEFAULT_RULES, help="Paquete de reglas YAML")
    scan_p.add_argument(
        "--engine", choices=["regex", "semgrep"], default="regex",
        help="regex: sin dependencias externas. semgrep: AST-aware, no matchea comentarios/strings (requiere el binario semgrep).",
    )
    scan_p.add_argument(
        "--semgrep-rules", type=Path, default=DEFAULT_SEMGREP_RULES,
        help="Paquete de reglas Semgrep (solo aplica con --engine semgrep)",
    )
    scan_p.add_argument("--output", type=Path, default=None, help="Ruta de salida para cbom.json")
    scan_p.add_argument("--fail-on", choices=["vulnerable", "at_risk", "unknown"], default=None,
                        help="Modo CI: salir con código 1 si hay hallazgos de este nivel o peor.")
    scan_p.add_argument("--quiet", action="store_true", help="No imprimir resumen en consola")

    tls_p = sub.add_parser("scan-tls", help="Escanea protocolo TLS y certificado de un host (via sslyze)")
    tls_p.add_argument("host", help="Hostname a escanear")
    tls_p.add_argument("--port", type=int, default=443, help="Puerto TLS (default 443)")
    tls_p.add_argument("--ip", default=None, help="IP a usar en vez de resolver el hostname por DNS")
    tls_p.add_argument("--rules", type=Path, default=DEFAULT_RULES, help="Paquete de reglas YAML")
    tls_p.add_argument("--output", type=Path, default=None, help="Ruta de salida para el CBOM")
    tls_p.add_argument("--quiet", action="store_true", help="No imprimir resumen en consola")

    keys_p = sub.add_parser("scan-keys", help="Escanea certificados y claves en disco (tamaño de clave real)")
    keys_p.add_argument("target", type=Path, help="Directorio a escanear")
    keys_p.add_argument("--rules", type=Path, default=DEFAULT_RULES, help="Paquete de detectores YAML")
    keys_p.add_argument("--output", type=Path, default=None, help="Ruta de salida para cbom.json")
    keys_p.add_argument("--fail-on", choices=["vulnerable", "at_risk", "unknown"], default=None,
                        help="Modo CI: salir con código 1 si hay hallazgos de este nivel o peor.")
    keys_p.add_argument("--quiet", action="store_true", help="No imprimir resumen en consola")

    deps_p = sub.add_parser("scan-deps", help="Escanea manifiestos de dependencias (librerías cripto)")
    deps_p.add_argument("target", type=Path, help="Directorio a escanear")
    deps_p.add_argument("--rules", type=Path, default=DEFAULT_RULES, help="Paquete de detectores YAML")
    deps_p.add_argument("--output", type=Path, default=None, help="Ruta de salida para cbom.json")
    deps_p.add_argument("--fail-on", choices=["vulnerable", "at_risk", "unknown"], default=None,
                        help="Modo CI: salir con código 1 si hay hallazgos de este nivel o peor.")
    deps_p.add_argument("--quiet", action="store_true", help="No imprimir resumen en consola")

    pasv_p = sub.add_parser(
        "scan-passive",
        help="Descubrimiento PASIVO de superficie cripto (CT logs + TLS/cabeceras)",
    )
    pasv_p.add_argument("domain", help="Dominio a inventariar (p.ej. ejemplo.com)")
    pasv_p.add_argument("--rules", type=Path, default=DEFAULT_RULES, help="Paquete de detectores YAML")
    pasv_p.add_argument("--port", type=int, default=443, help="Puerto TLS (default 443)")
    pasv_p.add_argument("--sample", type=int, default=8, help="Nº de certificados de CT a analizar")
    pasv_p.add_argument(
        "--ct-only", action="store_true",
        help="Solo CT logs (pasivo puro, sin contactar al objetivo). Omite TLS/cabeceras.",
    )
    pasv_p.add_argument(
        "--authorize", action="append", default=[], metavar="DOMINIO",
        help="Autoriza TLS/cabeceras contra este dominio (y subdominios). Repetible.",
    )
    pasv_p.add_argument(
        "--scope-file", type=Path, default=None,
        help="Archivo con dominios autorizados (uno por línea) para la parte activa.",
    )
    pasv_p.add_argument("--output", type=Path, default=None, help="Ruta de salida para el CBOM")
    pasv_p.add_argument("--quiet", action="store_true", help="No imprimir resumen en consola")

    risk_p = sub.add_parser("risk", help="Evalúa el riesgo cuántico agregado de un cbom.json")
    risk_p.add_argument("cbom", type=Path, help="Archivo cbom.json generado por un scan")
    risk_p.add_argument("--shelf-life", type=int, default=10, help="X: vida útil del dato en años")
    risk_p.add_argument("--migration-time", type=int, default=5, help="Y: años de migración cripto")
    risk_p.add_argument("--qday", type=int, default=10, help="Z: años hasta el Q-day")
    risk_p.add_argument("--fail-on", choices=["critical", "high", "medium", "low"], default=None,
                        help="Modo CI: salir con código 1 si la banda de riesgo alcanza este nivel o peor.")
    risk_p.add_argument("--output", type=Path, default=None, help="Ruta de salida del informe JSON")

    sc_p = sub.add_parser("scan-contracts", help="Analiza vulnerabilidades de smart contracts (Solidity)")
    sc_p.add_argument("target", type=Path, help="Directorio con archivos .sol")
    sc_p.add_argument("--rules", type=Path, default=DEFAULT_CONTRACT_RULES, help="Reglas de contratos YAML")
    sc_p.add_argument("--output", type=Path, default=None, help="Ruta de salida del informe JSON")
    sc_p.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "info"], default=None,
                      help="Modo CI: salir con código 1 si hay hallazgos de esta gravedad o peor.")
    sc_p.add_argument("--quiet", action="store_true", help="No imprimir resumen en consola")

    kb_p = sub.add_parser("kb", help="Consulta la base de conocimiento de algoritmos")
    kb_p.add_argument("query", nargs="?", default=None, help="id o texto a buscar (vacío = listar todo)")

    exp_p = sub.add_parser("export", help="Exporta un cbom.json a otro formato (CycloneDX)")
    exp_p.add_argument("cbom", type=Path, help="Archivo cbom.json de entrada")
    exp_p.add_argument("--format", choices=["cyclonedx"], default="cyclonedx", help="Formato destino")
    exp_p.add_argument("--output", type=Path, default=None, help="Ruta de salida (default: stdout)")

    args = parser.parse_args(argv)

    if args.command == "scan":
        if not args.target.is_dir():
            print(f"error: '{args.target}' no es un directorio", file=sys.stderr)
            return 1
        output_path = args.output or (args.target / "cbom.json")
        try:
            entries = build_cbom(
                args.target, args.rules, engine=args.engine,
                semgrep_rules_path=args.semgrep_rules, output_path=output_path,
            )
        except SemgrepNotAvailable as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        _write_cbom(entries, output_path, str(args.target), args.rules.name, args.engine)
        if not args.quiet:
            _print_summary(entries)
        return _ci_gate_entries(entries, args.fail_on)

    elif args.command == "scan-tls":
        output_path = args.output or Path(f"cbom_tls_{args.host}_{args.port}.json")
        try:
            entries = build_cbom_tls(args.host, args.rules, port=args.port, ip_address=args.ip)
        except TlsScanError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        _write_cbom(entries, output_path, f"{args.host}:{args.port}", args.rules.name, "tls[sslyze]")
        if not args.quiet:
            _print_summary(entries)

    elif args.command == "scan-keys":
        if not args.target.is_dir():
            print(f"error: '{args.target}' no es un directorio", file=sys.stderr)
            return 1
        output_path = args.output or (args.target / "cbom_keys.json")
        entries = build_cbom_keys(args.target, args.rules, output_path=output_path)
        _write_cbom(entries, output_path, str(args.target), args.rules.name, "keys[cryptography]")
        if not args.quiet:
            _print_summary(entries)
        return _ci_gate_entries(entries, args.fail_on)

    elif args.command == "scan-deps":
        if not args.target.is_dir():
            print(f"error: '{args.target}' no es un directorio", file=sys.stderr)
            return 1
        output_path = args.output or (args.target / "cbom_deps.json")
        entries, deps = build_cbom_deps(args.target, args.rules, output_path=output_path)
        _write_cbom(entries, output_path, str(args.target), args.rules.name, "deps[manifests]")
        if not args.quiet:
            if deps.crypto_libs:
                print("\n=== Dependencias cripto-relevantes ===")
                for lib in deps.crypto_libs[:20]:
                    print(f"  · {lib}")
            if deps.weak_libs:
                print("\n=== Librerías a revisar (abandonadas / CVE conocida) ===")
                for w in deps.weak_libs:
                    print(f"  ⚠ {w}")
            for note in deps.notes:
                print(f"  {note}")
            _print_summary(entries)
        return _ci_gate_entries(entries, args.fail_on)

    elif args.command == "scan-passive":
        output_path = args.output or Path(f"cbom_passive_{args.domain}.json")
        scope = set(args.authorize)
        if args.scope_file:
            if not args.scope_file.is_file():
                print(f"error: scope-file '{args.scope_file}' no existe", file=sys.stderr)
                return 1
            scope.update(
                ln.strip() for ln in args.scope_file.read_text(encoding="utf-8").splitlines()
                if ln.strip() and not ln.strip().startswith("#")
            )
        try:
            entries, result = build_cbom_passive(
                args.domain, args.rules,
                include_active=not args.ct_only, port=args.port, sample=args.sample,
                authorized_scope=scope,
            )
        except PassiveScanError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        _write_cbom(entries, output_path, args.domain, args.rules.name, "passive[ct+tls]")
        if not args.quiet:
            _print_passive_context(result)
            _print_summary(entries)

    elif args.command == "risk":
        if not args.cbom.is_file():
            print(f"error: '{args.cbom}' no existe", file=sys.stderr)
            return 1
        entries = _load_cbom_entries(args.cbom)
        assessment = risk_assess(
            entries,
            data_shelf_life_years=args.shelf_life,
            migration_time_years=args.migration_time,
            years_to_qday=args.qday,
        )
        report = assessment.to_dict()
        if args.output:
            args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
            print(f"Informe de riesgo escrito en: {args.output}")
        _print_risk(assessment)
        if args.fail_on:
            if _BAND_SEVERITY.get(assessment.risk_band, 0) >= _BAND_SEVERITY[args.fail_on]:
                print(f"\n[CI] FALLO: banda de riesgo '{assessment.risk_band}' alcanza '{args.fail_on}' o peor.", file=sys.stderr)
                return 1
            print(f"\n[CI] OK: banda de riesgo '{assessment.risk_band}' por debajo de '{args.fail_on}'.")

    elif args.command == "scan-contracts":
        if not args.target.is_dir():
            print(f"error: '{args.target}' no es un directorio", file=sys.stderr)
            return 1
        from .contract_scanner import ContractRuleSet, report as contract_report, scan_directory as scan_contracts
        ruleset = ContractRuleSet.load(args.rules)
        findings = scan_contracts(args.target, ruleset)
        rep = contract_report(findings, str(args.target), ruleset.version)
        output_path = args.output or (args.target / "contract_report.json")
        output_path.write_text(json.dumps(rep, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Informe de contratos escrito en: {output_path}")
        if not args.quiet:
            _print_contracts(rep)
        if args.fail_on:
            from .contract_scanner import SEVERITY_ORDER
            thr = SEVERITY_ORDER.index(args.fail_on)
            worst = [f for f in findings if SEVERITY_ORDER.index(f.severity) <= thr]
            if worst:
                print(f"\n[CI] FALLO: {len(worst)} hallazgo(s) de gravedad '{args.fail_on}' o peor.", file=sys.stderr)
                return 1
            print(f"\n[CI] OK: sin hallazgos de gravedad '{args.fail_on}' o peor.")

    elif args.command == "kb":
        return _run_kb(args.query)

    elif args.command == "export":
        if not args.cbom.is_file():
            print(f"error: '{args.cbom}' no existe", file=sys.stderr)
            return 1
        from .cyclonedx import to_cyclonedx

        cbom = json.loads(args.cbom.read_text(encoding="utf-8"))
        bom = to_cyclonedx(cbom)
        text = json.dumps(bom, indent=2, ensure_ascii=False)
        if args.output:
            args.output.write_text(text, encoding="utf-8")
            print(f"CycloneDX escrito en: {args.output}")
        else:
            print(text)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
