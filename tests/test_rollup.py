from __future__ import annotations

from proof_of_state.chain import rollup
from proof_of_state.models import Rollup, Verdict


def test_all_pass_rolls_up_pass() -> None:
    assert rollup([Verdict.PASS, Verdict.PASS]) is Rollup.PASS


def test_any_fail_rolls_up_fail() -> None:
    assert rollup([Verdict.PASS, Verdict.FAIL, Verdict.UNKNOWN]) is Rollup.FAIL


def test_unknown_never_passes() -> None:
    # The single hard invariant: an unestablished verdict cannot roll up to PASS.
    assert rollup([Verdict.PASS, Verdict.UNKNOWN]) is Rollup.PARTIAL
    assert rollup([Verdict.PASS, Verdict.UNKNOWN]) is not Rollup.PASS


def test_empty_is_not_pass() -> None:
    assert rollup([]) is Rollup.PARTIAL
