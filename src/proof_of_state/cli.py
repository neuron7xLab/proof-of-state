"""``pos`` command line: produce and independently verify state proofs."""

from __future__ import annotations

import argparse
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import bundle_io
from .runner import load_gate_graph, run
from .verifier import verify


def _git_commit(repo: Path) -> str:
    try:
        out = subprocess.run(  # noqa: S603 - fixed git invocation in operator-chosen repo
            ["git", "-C", str(repo), "rev-parse", "HEAD"],  # noqa: S607 - git resolved from PATH by design
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        return out.stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def _cmd_run(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    config = Path(args.config).resolve()
    specs = load_gate_graph(config)
    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    bundle = run(specs, repo, repo_commit=_git_commit(repo), generated_at=generated_at)
    out_path = Path(args.output).resolve()
    bundle_io.write(bundle, out_path)
    print(
        f"POS_RUN rollup={bundle.rollup.value} gates={len(bundle.entries)} "
        f"chain_head={bundle.chain_head[:12]} -> {out_path}"
    )
    # Exit non-zero unless the produced rollup is a clean PASS (UNKNOWN != PASS).
    return 0 if bundle.rollup.value == "pass" else 1


def _cmd_verify(args: argparse.Namespace) -> int:
    bundle = bundle_io.read(Path(args.bundle).resolve())
    repo = Path(args.repo).resolve()
    report = verify(bundle, repo, rerun=not args.no_rerun)
    print(
        f"POS_VERIFY outcome={report.outcome.value} "
        f"chain_intact={report.chain_intact} rollup={bundle.rollup.value}"
    )
    for div in report.divergences:
        print(
            f"  DIVERGENCE gate={div.gate} claimed={div.claimed} "
            f"observed={div.observed} stdout_drift={div.stdout_drift}"
        )
    if report.first_broken_gate:
        print(f"  TAMPER first_broken_gate={report.first_broken_gate}")
    if report.detail:
        print(f"  {report.detail}")
    # Trustworthy only when the bundle reproduced AND its rollup is a real PASS.
    if report.is_trustworthy_pass:
        print("POS_VERIFY_TRUSTWORTHY_PASS")
        return 0
    print(f"POS_VERIFY_NOT_PASS outcome={report.outcome.value}")
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pos",
        description="Proof-of-State: trust-minimized release-state attestation.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="run the declared gate graph and emit a hash-chained bundle")
    run_p.add_argument("repo", help="path to the target repository")
    run_p.add_argument("--config", default="proof_of_state.toml", help="gate-graph TOML (default: proof_of_state.toml)")
    run_p.add_argument("--output", default="proof_of_state.bundle.json", help="bundle output path")
    run_p.set_defaults(func=_cmd_run)

    ver_p = sub.add_parser("verify", help="independently verify a bundle without trusting the producer")
    ver_p.add_argument("bundle", help="path to a proof-of-state bundle JSON")
    ver_p.add_argument("repo", help="path to the repository the bundle claims to describe")
    ver_p.add_argument("--no-rerun", action="store_true", help="check only the hash chain, skip gate reproduction")
    ver_p.set_defaults(func=_cmd_verify)

    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (OSError, ValueError) as exc:
        print(f"POS_ERROR {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
