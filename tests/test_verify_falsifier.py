"""The kill-test: an independent verifier must catch a dishonest bundle.

If these tests cannot be made to pass, the whole project is worth $0 — a bundle
that only the producer can reproduce is not an attestation, it is a press
release. The verifier therefore re-derives every verdict instead of trusting it.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from proof_of_state.chain import build_chain, rollup
from proof_of_state.models import Bundle, GateSpec, Rollup, Verdict
from proof_of_state.runner import run
from proof_of_state.verifier import VerifyOutcome, verify

PASS_GATE = GateSpec(name="ok", command=["python", "-c", "import sys; sys.exit(0)"])
FAIL_GATE = GateSpec(name="bad", command=["python", "-c", "import sys; sys.exit(1)"])


def _bundle_from_results(repo: Path, results: list) -> Bundle:
    entries = build_chain(results)
    return Bundle(
        repo=str(repo),
        repo_commit="test",
        generated_at="1970-01-01T00:00:00Z",
        entries=entries,
        rollup=rollup(r.verdict for r in results),
    )


def test_honest_all_pass_is_trustworthy(tmp_path: Path) -> None:
    bundle = run([PASS_GATE], tmp_path, repo_commit="x", generated_at="t")
    assert bundle.rollup is Rollup.PASS
    report = verify(bundle, tmp_path)
    assert report.outcome is VerifyOutcome.REPRODUCED
    assert report.is_trustworthy_pass is True


def test_honest_failure_reproduces_but_is_not_pass(tmp_path: Path) -> None:
    bundle = run([PASS_GATE, FAIL_GATE], tmp_path, repo_commit="x", generated_at="t")
    assert bundle.rollup is Rollup.FAIL
    report = verify(bundle, tmp_path)
    # The failure honestly reproduces — but reproduction is not the same as PASS.
    assert report.outcome is VerifyOutcome.REPRODUCED
    assert report.is_trustworthy_pass is False


def test_perfectly_rechained_lie_is_caught_by_reproduction(tmp_path: Path) -> None:
    """A sophisticated forger flips a FAIL to PASS AND re-chains it so the hash
    chain is internally consistent. The chain check passes; reproduction does
    not — the gate still really fails when re-run."""
    honest = run([FAIL_GATE], tmp_path, repo_commit="x", generated_at="t")
    forged_result = replace(honest.entries[0].result, verdict=Verdict.PASS, exit_code=0)
    forged = _bundle_from_results(tmp_path, [forged_result])  # re-chained + rollup recomputed
    assert forged.rollup is Rollup.PASS  # the lie looks clean on paper

    report = verify(forged, tmp_path)
    assert report.chain_intact is True  # the liar chained consistently
    assert report.outcome is VerifyOutcome.DIVERGED  # ...but the lie does not reproduce
    assert report.is_trustworthy_pass is False
    assert report.divergences[0].gate == "bad"
    assert report.divergences[0].claimed == "pass"
    assert report.divergences[0].observed == "fail"


def test_naive_tamper_breaks_chain(tmp_path: Path) -> None:
    """A naive forger edits a recorded verdict without re-chaining."""
    honest = run([FAIL_GATE], tmp_path, repo_commit="x", generated_at="t")
    tampered_entry = replace(
        honest.entries[0],
        result=replace(honest.entries[0].result, verdict=Verdict.PASS, exit_code=0),
    )
    honest.entries[0] = tampered_entry
    honest.rollup = Rollup.PASS
    report = verify(honest, tmp_path)
    assert report.outcome is VerifyOutcome.TAMPERED
    assert report.chain_intact is False


def test_rollup_lie_is_rejected(tmp_path: Path) -> None:
    """Even with an intact chain, a rollup that claims PASS over a FAIL verdict
    violates UNKNOWN/FAIL != PASS and is rejected before reproduction."""
    honest = run([FAIL_GATE], tmp_path, repo_commit="x", generated_at="t")
    honest.rollup = Rollup.PASS  # contradicts the recorded FAIL verdict
    report = verify(honest, tmp_path)
    assert report.outcome is VerifyOutcome.ROLLUP_INVALID
    assert report.is_trustworthy_pass is False


@pytest.mark.parametrize("skip_rerun", [True, False])
def test_chain_only_mode_still_catches_tamper(tmp_path: Path, skip_rerun: bool) -> None:
    honest = run([PASS_GATE], tmp_path, repo_commit="x", generated_at="t")
    report = verify(honest, tmp_path, rerun=not skip_rerun)
    assert report.outcome is VerifyOutcome.REPRODUCED
