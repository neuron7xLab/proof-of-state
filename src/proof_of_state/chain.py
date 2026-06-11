"""Tamper-evident sha256 hash-chain over gate results.

Each entry's ``chain`` link binds the deterministic fields of the gate result to
the previous link: ``chain_i = sha256(canonical(result_i) || prev_chain)``. Any
post-hoc edit to a recorded verdict, command or exit code breaks every
subsequent link, so a third party can detect tampering with a single recompute
and without trusting the producer.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable

from .models import GENESIS, EvidenceEntry, GateResult, Rollup, Verdict


def _canonical(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def link(result: GateResult, prev_chain: str) -> str:
    """Compute the chain link for a result given the previous link."""
    payload = _canonical(result.to_chain_fields()) + prev_chain.encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def build_chain(results: Iterable[GateResult]) -> list[EvidenceEntry]:
    """Chain a sequence of results from the genesis link."""
    entries: list[EvidenceEntry] = []
    prev = GENESIS
    for result in results:
        current = link(result, prev)
        entries.append(EvidenceEntry(result=result, prev_chain=prev, chain=current))
        prev = current
    return entries


def recompute_head(entries: list[EvidenceEntry]) -> tuple[bool, str | None]:
    """Independently recompute the chain over the recorded results.

    Returns ``(intact, first_broken_gate)``. ``intact`` is True only if every
    recorded ``chain``/``prev_chain`` link matches a fresh recomputation, i.e.
    no recorded verdict has been altered after the fact.
    """
    prev = GENESIS
    for entry in entries:
        if entry.prev_chain != prev:
            return False, entry.result.spec.name
        expected = link(entry.result, prev)
        if entry.chain != expected:
            return False, entry.result.spec.name
        prev = entry.chain
    return True, None


def rollup(verdicts: Iterable[Verdict]) -> Rollup:
    """Roll gate verdicts into a bundle verdict, enforcing UNKNOWN != PASS."""
    seen = list(verdicts)
    if any(v is Verdict.FAIL for v in seen):
        return Rollup.FAIL
    if any(v is Verdict.UNKNOWN for v in seen):
        return Rollup.PARTIAL  # never PASS while any verdict is unestablished
    return Rollup.PASS if seen else Rollup.PARTIAL
