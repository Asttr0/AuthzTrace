"""Command-line entry point: authztrace run -c authztrace.yaml"""
from __future__ import annotations

import argparse
import sys

from . import __version__
from .config import load_contract
from .engine import run as run_checks
from .matrix import generate
from .report import counts, to_json, to_junit, to_sarif, to_terminal


def _run(args) -> int:
    try:
        contract = load_contract(args.config)
    except (OSError, ValueError) as exc:
        print(f"authztrace: cannot load contract: {exc}", file=sys.stderr)
        return 2

    if args.base_url:
        contract.base_url = args.base_url.rstrip("/")

    checks = generate(contract)
    results = run_checks(contract, checks, timeout=args.timeout)

    print(to_terminal(results, color=not args.no_color))

    if args.sarif:
        with open(args.sarif, "w", encoding="utf-8") as f:
            f.write(to_sarif(results))
        print(f"\nSARIF written to {args.sarif}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            f.write(to_json(results))
        print(f"\nJSON written to {args.json}")

    if args.junit:
        with open(args.junit, "w", encoding="utf-8") as f:
            f.write(to_junit(results))
        print(f"\nJUnit written to {args.junit}")

    c = counts(results)
    # Non-zero exit (fails CI) if a BOLA was proven or a request errored out.
    return 1 if (c["fail"] or c["error"]) else 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="authztrace",
        description="Authorization contract testing for IDOR/BOLA — "
        "prove user A cannot touch user B's objects, in CI.",
    )
    parser.add_argument("--version", action="version", version=f"authztrace {__version__}")
    sub = parser.add_subparsers(dest="command")

    run_p = sub.add_parser("run", help="run an authorization contract against a live API")
    run_p.add_argument(
        "-c", "--config", default="authztrace.yaml",
        help="path to the authorization contract (default: authztrace.yaml)",
    )
    run_p.add_argument("--sarif", metavar="FILE", help="also write SARIF results to FILE")
    run_p.add_argument("--json", metavar="FILE", help="also write machine-readable JSON to FILE")
    run_p.add_argument("--junit", metavar="FILE", help="also write JUnit XML to FILE")
    run_p.add_argument("--base-url", help="override base_url from the contract")
    run_p.add_argument("--timeout", type=float, default=10.0, help="per-request timeout in seconds")
    run_p.add_argument("--no-color", action="store_true", help="disable ANSI colors")

    args = parser.parse_args(argv)

    if args.command == "run":
        return _run(args)

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
