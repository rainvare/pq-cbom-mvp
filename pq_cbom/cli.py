"""CLI: `python -m pq_cbom.cli scan <path>` / `scan-tls <host>`."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from .build import build_cbom, build_cbom_tls
from .semgrep_scanner import SemgrepNotAvailable
from .tls_scanner import TlsScanError

DEFAULT_RULES = Path(__file__).resolve().parent.parent / "rules" / "pq_rules.yaml"
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
    scan_p.add_argument("--quiet", action="store_true", help="No imprimir resumen en consola")

    tls_p = sub.add_parser("scan-tls", help="Escanea protocolo TLS y certificado de un host (via sslyze)")
    tls_p.add_argument("host", help="Hostname a escanear")
    tls_p.add_argument("--port", type=int, default=443, help="Puerto TLS (default 443)")
    tls_p.add_argument("--ip", default=None, help="IP a usar en vez de resolver el hostname por DNS")
    tls_p.add_argument("--rules", type=Path, default=DEFAULT_RULES, help="Paquete de reglas YAML")
    tls_p.add_argument("--output", type=Path, default=None, help="Ruta de salida para el CBOM")
    tls_p.add_argument("--quiet", action="store_true", help="No imprimir resumen en consola")

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

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
