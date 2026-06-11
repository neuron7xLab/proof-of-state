from __future__ import annotations

from dataclasses import replace

from proof_of_state.chain import build_chain, recompute_head
from proof_of_state.models import GateResult, GateSpec, Verdict


def _result(name: str, verdict: Verdict, code: int) -> GateResult:
    return GateResult(
        index=0,
        spec=GateSpec(name=name, command=["true"]),
        verdict=verdict,
        exit_code=code,
        stdout_sha256="0" * 64,
    )


def test_intact_chain_recomputes() -> None:
    results = [
        _result("a", Verdict.PASS, 0),
        _result("b", Verdict.FAIL, 1),
        _result("c", Verdict.UNKNOWN, 127),
    ]
    entries = build_chain(results)
    intact, broken = recompute_head(entries)
    assert intact is True
    assert broken is None


def test_altered_verdict_breaks_chain() -> None:
    results = [_result("a", Verdict.PASS, 0), _result("b", Verdict.FAIL, 1)]
    entries = build_chain(results)
    # Tamper: flip a recorded verdict in place WITHOUT re-chaining (naive forgery).
    forged_result = replace(entries[1].result, verdict=Verdict.PASS, exit_code=0)
    entries[1] = replace(entries[1], result=forged_result)
    intact, broken = recompute_head(entries)
    assert intact is False
    assert broken == "b"


def test_each_link_binds_to_predecessor() -> None:
    results = [_result("a", Verdict.PASS, 0), _result("b", Verdict.PASS, 0)]
    entries = build_chain(results)
    assert entries[0].prev_chain == "0" * 64
    assert entries[1].prev_chain == entries[0].chain
    assert entries[0].chain != entries[1].chain
