"""Command-line entry point: authztrace run -c authztrace.yaml"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .config import load_contract
from .engine import run as run_checks
from .inference import (
    UnresolvedPolicyError,
    compile_contract,
    discover_source,
    read_decisions,
    review_policies,
    write_evidence,
)
from .matrix import generate
from .openapi import generate_contract, write_contract
from .report import counts, to_json, to_junit, to_sarif, to_terminal


def _exit_code(results, strict: bool = False) -> int:
    c = counts(results)
    if any(result.outcome == "error" and result.category == "setup" for result in results):
        return 2
    if c["fail"] or (strict and c["warn"]):
        return 1
    return 0


def _run(args) -> int:
    try:
        contract = load_contract(args.config)
    except (OSError, ValueError) as exc:
        print(f"authztrace: cannot load contract: {exc}", file=sys.stderr)
        return 2

    if args.base_url:
        contract.base_url = args.base_url.rstrip("/")

    checks = generate(contract)
    results = run_checks(
        contract,
        checks,
        timeout=args.timeout,
        include_unsafe=args.include_unsafe,
    )

    print(to_terminal(results, color=not args.no_color))

    if args.sarif:
        with open(args.sarif, "w", encoding="utf-8") as f:
            f.write(to_sarif(results, artifact_uri=args.config))
        print(f"\nSARIF written to {args.sarif}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            f.write(to_json(results))
        print(f"\nJSON written to {args.json}")

    if args.junit:
        with open(args.junit, "w", encoding="utf-8") as f:
            f.write(to_junit(results))
        print(f"\nJUnit written to {args.junit}")

    return _exit_code(results, strict=args.strict)


def _init(args) -> int:
    if args.from_source:
        evidence_path = args.evidence or str(
            Path(args.output).with_suffix(".evidence.json")
        )
        output_target = Path(args.output).expanduser().resolve()
        evidence_target = Path(evidence_path).expanduser().resolve()
        if output_target == evidence_target:
            print(
                "authztrace: contract and inference evidence must use different paths",
                file=sys.stderr,
            )
            return 2
        if output_target.exists() and not args.force:
            print(
                f"authztrace: cannot infer contract: {args.output} already exists; "
                "pass --force to overwrite",
                file=sys.stderr,
            )
            return 2
        try:
            discovery = discover_source(
                args.from_source,
                framework=args.framework,
                openapi=args.openapi,
                base_url=args.base_url,
            )
            existing = read_decisions(args.decisions) if args.decisions else {}
            write_evidence(discovery, evidence_path, existing)
            decisions = review_policies(
                discovery,
                existing=existing,
                accept_probable=args.accept_probable,
                interactive=not args.non_interactive and sys.stdin.isatty(),
            )
            contract = compile_contract(discovery, decisions)
            write_contract(contract, args.output, force=args.force)
            write_evidence(discovery, evidence_path, decisions)
        except UnresolvedPolicyError as exc:
            print(f"authztrace: source policy review required: {exc}", file=sys.stderr)
            print(f"Evidence written to {evidence_path}", file=sys.stderr)
            return 2
        except EOFError:
            print(
                "authztrace: source policy review was interrupted; no contract was written",
                file=sys.stderr,
            )
            print(f"Evidence written to {evidence_path}", file=sys.stderr)
            return 2
        except (OSError, ValueError, FileExistsError) as exc:
            print(f"authztrace: cannot infer contract: {exc}", file=sys.stderr)
            return 2

        probable = sum(route.policy_state == "probable" for route in discovery.routes)
        print(
            f"Discovered {len(discovery.routes)} object endpoint(s) "
            f"from {discovery.files_scanned} file(s); {probable} had ownership evidence."
        )
        print(f"AuthzTrace contract written to {args.output}")
        print(f"Inference evidence written to {evidence_path}")
        print("Set the generated *_ID and *_TOKEN environment variables before running it.")
        return 0

    try:
        contract = generate_contract(args.from_file, base_url=args.base_url)
        write_contract(contract, args.output, force=args.force)
    except (OSError, ValueError, FileExistsError) as exc:
        print(f"authztrace: cannot generate contract: {exc}", file=sys.stderr)
        return 2

    print(f"AuthzTrace contract written to {args.output}")
    print("Set the generated *_ID and *_TOKEN environment variables before running it.")
    return 0


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
    run_p.add_argument("--strict", action="store_true", help="return non-zero when warnings occur")
    run_p.add_argument(
        "--include-unsafe",
        action="store_true",
        help="execute non-read-only endpoints such as POST, PUT, PATCH, and DELETE",
    )
    run_p.add_argument("--no-color", action="store_true", help="disable ANSI colors")

    init_p = sub.add_parser(
        "init", help="scaffold a contract from OpenAPI or infer one from API source"
    )
    init_source = init_p.add_mutually_exclusive_group(required=True)
    init_source.add_argument(
        "--from",
        dest="from_file",
        help="path to an OpenAPI JSON/YAML file",
    )
    init_source.add_argument(
        "--from-source",
        metavar="DIR",
        help="statically discover API routes and authorization evidence under DIR",
    )
    init_p.add_argument(
        "-o",
        "--output",
        default="authztrace.yaml",
        help="contract path to write (default: authztrace.yaml)",
    )
    init_p.add_argument("--base-url", help="override the generated contract base URL")
    init_p.add_argument(
        "--openapi",
        help="OpenAPI JSON/YAML inventory to reconcile with --from-source",
    )
    init_p.add_argument(
        "--framework",
        choices=("auto", "fastapi"),
        default="auto",
        help="source framework (default: detect automatically)",
    )
    init_p.add_argument(
        "--evidence",
        metavar="FILE",
        help="source-inference evidence path (default: OUTPUT with .evidence.json)",
    )
    init_p.add_argument(
        "--decisions",
        metavar="FILE",
        help="reuse reviewed endpoint decisions from an earlier evidence file",
    )
    init_p.add_argument(
        "--accept-probable",
        action="store_true",
        help="accept only ownership policies supported by source evidence",
    )
    init_p.add_argument(
        "--non-interactive",
        action="store_true",
        help="fail instead of prompting when any policy requires review",
    )
    init_p.add_argument("--force", action="store_true", help="overwrite output if it exists")

    args = parser.parse_args(argv)

    if args.command == "run":
        return _run(args)
    if args.command == "init":
        return _init(args)

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
