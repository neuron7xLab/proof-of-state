"""Execute a declared gate graph against a target repository.

The runner is deliberately thin: it shells out to each gate's command in the
target repo, classifies the exit code into a :class:`Verdict`, and records a
sha256 of stdout so drift is observable. It never interprets gate semantics —
the gate command is the source of truth, which is exactly what makes the bundle
independently reproducible by :mod:`proof_of_state.verifier`.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
import time
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # Python < 3.11
    import tomli as tomllib

from .chain import build_chain, rollup
from .models import Bundle, GateResult, GateSpec, Verdict


def load_gate_graph(config_path: Path) -> list[GateSpec]:
    """Load a gate graph from a ``proof_of_state.toml`` file."""
    with config_path.open("rb") as handle:
        data = tomllib.load(handle)
    specs: list[GateSpec] = []
    for raw in data.get("gate", []):
        command = raw["command"]
        if not isinstance(command, list) or not all(isinstance(part, str) for part in command):
            raise ValueError(f"gate '{raw.get('name')}' command must be a list of strings")
        specs.append(
            GateSpec(
                name=str(raw["name"]),
                command=command,
                timeout_seconds=int(raw.get("timeout_seconds", 300)),
                unknown_exit_codes=tuple(int(c) for c in raw.get("unknown_exit_codes", [])),
                required=bool(raw.get("required", True)),
            )
        )
    if not specs:
        raise ValueError("gate graph is empty; declare at least one [[gate]]")
    return specs


def classify(spec: GateSpec, exit_code: int) -> Verdict:
    if exit_code in spec.unknown_exit_codes:
        return Verdict.UNKNOWN
    return Verdict.PASS if exit_code == 0 else Verdict.FAIL


def run_gate(spec: GateSpec, repo: Path) -> GateResult:
    started = time.monotonic()
    try:
        proc = subprocess.run(  # noqa: S603 - commands are operator-declared in the gate graph
            spec.command,
            cwd=repo,
            capture_output=True,
            text=True,
            timeout=spec.timeout_seconds,
            check=False,
        )
        exit_code = proc.returncode
        stdout = (proc.stdout or "") + (proc.stderr or "")
    except subprocess.TimeoutExpired as exc:
        exit_code = 124
        stdout = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
    except FileNotFoundError:
        # Command not present on this host: verdict cannot be established here.
        return GateResult(
            index=0,
            spec=spec,
            verdict=Verdict.UNKNOWN,
            exit_code=127,
            stdout_sha256=hashlib.sha256(b"").hexdigest(),
            duration_seconds=time.monotonic() - started,
        )
    return GateResult(
        index=0,
        spec=spec,
        verdict=classify(spec, exit_code),
        exit_code=exit_code,
        stdout_sha256=hashlib.sha256(stdout.encode("utf-8")).hexdigest(),
        duration_seconds=time.monotonic() - started,
    )


def run(specs: list[GateSpec], repo: Path, *, repo_commit: str, generated_at: str) -> Bundle:
    """Run the gate graph and produce a hash-chained bundle."""
    results: list[GateResult] = []
    for index, spec in enumerate(specs):
        raw = run_gate(spec, repo)
        results.append(
            GateResult(
                index=index,
                spec=raw.spec,
                verdict=raw.verdict,
                exit_code=raw.exit_code,
                stdout_sha256=raw.stdout_sha256,
                duration_seconds=raw.duration_seconds,
            )
        )
    entries = build_chain(results)
    return Bundle(
        repo=str(repo),
        repo_commit=repo_commit,
        generated_at=generated_at,
        entries=entries,
        rollup=rollup(r.verdict for r in results),
    )
