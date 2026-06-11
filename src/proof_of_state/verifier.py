"""Trust-minimized verification of a Proof-of-State bundle.

This is the load-bearing claim of the whole project: a third party who did NOT
produce the bundle can establish whether it is honest, using two independent
checks that never trust the producer's asserted verdicts.

1. **Integrity** — recompute the sha256 hash-chain over the recorded results.
   Any altered verdict/command/exit code breaks the chain.
2. **Reproduction** — actually re-run each gate in the repository and compare the
   freshly observed verdict against the one the bundle claims. A bundle that
   claims ``pass`` for a gate that really fails is caught here, regardless of an
   intact chain (the producer can chain a lie consistently; they cannot make the
   lie reproduce).

The verdict is fail-closed: anything other than a fully intact chain whose every
claimed verdict reproduces is a non-PASS outcome.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from .chain import recompute_head, rollup
from .models import Bundle
from .runner import run_gate


class VerifyOutcome(str, Enum):
    REPRODUCED = "reproduced"  # chain intact AND every claimed verdict re-runs identically
    DIVERGED = "diverged"  # chain intact but a claimed verdict does not reproduce (forgery)
    TAMPERED = "tampered"  # hash-chain broken: a recorded verdict was edited after the fact
    ROLLUP_INVALID = "rollup_invalid"  # recorded rollup contradicts UNKNOWN != PASS


@dataclass
class GateDivergence:
    gate: str
    claimed: str
    observed: str
    stdout_drift: bool


@dataclass
class VerifyReport:
    outcome: VerifyOutcome
    chain_intact: bool
    rollup_is_pass: bool = False
    first_broken_gate: str | None = None
    divergences: list[GateDivergence] = field(default_factory=list)
    detail: str = ""

    @property
    def is_trustworthy_pass(self) -> bool:
        """True only when the bundle reproduced AND its rollup is a real PASS."""
        return self.outcome is VerifyOutcome.REPRODUCED and self.rollup_is_pass


def _claimed_rollup_consistent(bundle: Bundle) -> bool:
    expected = rollup(entry.result.verdict for entry in bundle.entries)
    return bundle.rollup == expected


def verify(bundle: Bundle, repo: Path, *, rerun: bool = True) -> VerifyReport:
    """Verify a bundle against a repository without trusting its claims."""
    # 1. The producer's rollup must itself obey UNKNOWN != PASS.
    if not _claimed_rollup_consistent(bundle):
        return VerifyReport(
            outcome=VerifyOutcome.ROLLUP_INVALID,
            chain_intact=False,
            detail="recorded rollup contradicts the gate verdicts (UNKNOWN != PASS violated)",
        )

    # 2. Integrity: recompute the hash chain independently.
    intact, broken = recompute_head(bundle.entries)
    if not intact:
        return VerifyReport(
            outcome=VerifyOutcome.TAMPERED,
            chain_intact=False,
            first_broken_gate=broken,
            detail=f"hash chain broken at gate '{broken}'",
        )

    if not rerun:
        return VerifyReport(
            outcome=VerifyOutcome.REPRODUCED,
            chain_intact=True,
            rollup_is_pass=bundle.rollup.value == "pass",
            detail="chain intact (reproduction skipped)",
        )

    # 3. Reproduction: re-run each gate and compare the verdict to the claim.
    divergences: list[GateDivergence] = []
    for entry in bundle.entries:
        claimed = entry.result
        observed = run_gate(claimed.spec, repo)
        if observed.verdict != claimed.verdict:
            divergences.append(
                GateDivergence(
                    gate=claimed.spec.name,
                    claimed=claimed.verdict.value,
                    observed=observed.verdict.value,
                    stdout_drift=observed.stdout_sha256 != claimed.stdout_sha256,
                )
            )

    if divergences:
        return VerifyReport(
            outcome=VerifyOutcome.DIVERGED,
            chain_intact=True,
            divergences=divergences,
            detail=f"{len(divergences)} claimed verdict(s) did not reproduce",
        )

    return VerifyReport(
        outcome=VerifyOutcome.REPRODUCED,
        chain_intact=True,
        rollup_is_pass=bundle.rollup.value == "pass",
        detail="chain intact and every claimed verdict reproduced",
    )
