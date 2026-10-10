"""
main.py
=======

Heptagon command-line interface.

Commands
--------
    heptagon declare <plan.yaml>
        Validate a plan against the JSON schema, summarize its
        structure.

    heptagon verify <plan.yaml>
        Run all six compliance gates and report.

    heptagon simulate <scenario> --plan <plan.yaml>
        Run a tabletop exercise for the scenario, walk the
        escalation order through the reporting DAG, report gaps.

All commands support ``--json`` for machine-readable output and use
exit codes suitable for CI:

    0  success
    1  plan fails a compliance check (or scenario has gaps)
    2  invalid input (bad file, unknown scenario)
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from heptagon import __version__
from heptagon.cirp.yaml_loader import load_cirp_from_yaml


# ---------------------------------------------------------------------------
# Subcommand implementations
# ---------------------------------------------------------------------------

def cmd_declare(args: argparse.Namespace) -> int:
    try:
        cirp = load_cirp_from_yaml(args.path)
    except FileNotFoundError:
        print(f"ERROR: file not found: {args.path}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    summary = {
        "name": cirp.name,
        "version": cirp.version,
        "teams": len(cirp.teams),
        "stakeholders": len(cirp.stakeholders),
        "scenarios": len(cirp.scenarios),
        "reporting_edges": len(cirp.reporting_chain),
        "team_roles": sorted(t.role for t in cirp.teams),
        "scenario_names": sorted(s.name for s in cirp.scenarios),
    }

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"Plan:         {summary['name']} (v{summary['version']})")
        print(f"Teams:        {summary['teams']}")
        print(f"Stakeholders: {summary['stakeholders']}")
        print(f"Scenarios:    {summary['scenarios']}")
        print(f"Edges:        {summary['reporting_edges']}")
        print()
        print("Team roles:")
        for r in summary["team_roles"]:
            print(f"  - {r}")
        print()
        print("Scenarios:")
        for s in summary["scenario_names"]:
            print(f"  - {s}")

    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    try:
        cirp = load_cirp_from_yaml(args.path)
    except FileNotFoundError:
        print(f"ERROR: file not found: {args.path}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    report = cirp.verify_all()

    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print(f"Plan:              {report['cirp_name']} "
              f"(v{report['cirp_version']})")
        print(f"All checks passed: {report['all_checks_passed']}")
        print()
        for name, result in report["checks"].items():
            status = "PASS" if result.get("ok") else "FAIL"
            print(f"  [{status}] {name}")
            if not result.get("ok"):
                for k, v in result.items():
                    if k == "ok" or not v:
                        continue
                    print(f"          {k}: {v}")

    return 0 if report["all_checks_passed"] else 1


def cmd_simulate(args: argparse.Namespace) -> int:
    try:
        cirp = load_cirp_from_yaml(args.plan)
    except FileNotFoundError:
        print(f"ERROR: file not found: {args.plan}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    try:
        result = cirp.run_tabletop(args.scenario, num_rounds=args.rounds)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(f"Scenario: {result['scenario']}")
        print(f"Rounds:   {result['rounds']}")
        print(f"Valid:    {result['escalation_valid']}")
        print(f"Coverage: {result['coverage_ratio']:.2%}")
        print()
        print("Escalation path:")
        for src, dst, hops in result["escalation_path"]:
            print(f"  {src} -> {dst}  ({hops} hops)")
        if result["escalation_gaps"]:
            print()
            print("Gaps:")
            for src, dst in result["escalation_gaps"]:
                print(f"  {src} -> {dst}  (UNREACHABLE)")
        if result["mandate_violations"]:
            print()
            print("Mandate violations:")
            for role in result["mandate_violations"]:
                print(f"  - {role}")

    return 0 if result["escalation_valid"] else 1


def cmd_keygen(args: argparse.Namespace) -> int:
    """Generate a new Ed25519 keypair and save it to a file."""
    from heptagon.audit.signing import Signer

    out = Path(args.out)
    if out.exists() and not args.force:
        print(f"ERROR: {out} already exists (use --force to overwrite)",
              file=sys.stderr)
        return 2

    signer = Signer.generate()
    signer.save(out)

    info = {
        "path": str(out),
        "algorithm": "ed25519",
        "public_key_hex": signer.public_key_hex,
        "created_utc": signer.created_utc,
    }

    if args.json:
        print(json.dumps(info, indent=2))
    else:
        print(f"Keypair written to: {out}")
        print(f"Algorithm:          ed25519")
        print(f"Public key (hex):   {signer.public_key_hex}")
        print()
        print("Keep the private key secure. Back up the file.")
        print("The public key is safe to share.")

    return 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="heptagon",
        description="Seven coordinates. Every incident. Verified.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"heptagon {__version__}",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # declare
    p = sub.add_parser(
        "declare",
        help="validate a plan against the JSON schema and summarize it",
    )
    p.add_argument("path", type=Path, help="path to cirp.yaml")
    p.add_argument("--json", action="store_true",
                   help="machine-readable output")
    p.set_defaults(func=cmd_declare)

    # verify
    p = sub.add_parser(
        "verify",
        help="run all six compliance gates on a plan",
    )
    p.add_argument("path", type=Path, help="path to cirp.yaml")
    p.add_argument("--json", action="store_true",
                   help="machine-readable output")
    p.set_defaults(func=cmd_verify)

    # keygen
    p = sub.add_parser(
        "keygen",
        help="generate an Ed25519 keypair for signing decisions",
    )
    p.add_argument("--out", type=Path, required=True,
                   help="path to write the keypair JSON")
    p.add_argument("--force", action="store_true",
                   help="overwrite existing file")
    p.add_argument("--json", action="store_true",
                   help="machine-readable output")
    p.set_defaults(func=cmd_keygen)

    # simulate
    p = sub.add_parser(
        "simulate",
        help="run a tabletop exercise for one scenario",
    )
    p.add_argument("scenario", type=str, help="scenario name")
    p.add_argument("--plan", type=Path, required=True,
                   help="path to cirp.yaml")
    p.add_argument("--rounds", type=int, default=20,
                   help="number of simulation rounds (default: 20)")
    p.add_argument("--json", action="store_true",
                   help="machine-readable output")
    p.set_defaults(func=cmd_simulate)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
