"""Core data model for Proof-of-State.

A Proof-of-State bundle is a *trust-minimized* claim about the state of a
software repository: an ordered graph of quality gates, each with a verdict, a
sha256 hash-chain link (tamper-evidence), and enough information for an
independent party to **re-run the gate and reproduce the verdict** rather than
believe the producer.

The single hard invariant is ``UNKNOWN != PASS``: a gate whose verdict could not
be established never rolls up to a passing state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

SCHEMA_VERSION = 1
GENESIS = "0" * 64


class Verdict(str, Enum):
    """A single gate verdict. ``UNKNOWN`` is structurally distinct from ``PASS``."""

    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"


class Rollup(str, Enum):
    """Bundle-level rollup. ``UNKNOWN`` and ``PARTIAL`` are never ``PASS``."""

    PASS = "pass"
    FAIL = "fail"
    PARTIAL = "partial"


@dataclass(frozen=True)
class GateSpec:
    """A declared gate: how to (re)produce a verdict from a command."""

    name: str
    command: list[str]
    timeout_seconds: int = 300
    # Exit codes that mean "verdict could not be established" (network down,
    # external service absent). These map to UNKNOWN, never PASS.
    unknown_exit_codes: tuple[int, ...] = ()
    required: bool = True

    def to_chain_fields(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "command": list(self.command),
            "unknown_exit_codes": list(self.unknown_exit_codes),
            "required": self.required,
        }


@dataclass(frozen=True)
class GateResult:
    """The reproducible outcome of running one gate.

    ``duration_seconds`` is metadata only: it is NOT part of the hash chain and
    is NOT compared during verification, because wall-clock time is not
    reproducible. The chain and the verification compare the *verdict* and the
    deterministic command identity.
    """

    index: int
    spec: GateSpec
    verdict: Verdict
    exit_code: int
    stdout_sha256: str
    duration_seconds: float = 0.0

    def to_chain_fields(self) -> dict[str, Any]:
        # Deterministic, reproducible fields only.
        return {
            "index": self.index,
            "spec": self.spec.to_chain_fields(),
            "verdict": self.verdict.value,
            "exit_code": self.exit_code,
            "stdout_sha256": self.stdout_sha256,
        }


@dataclass(frozen=True)
class EvidenceEntry:
    """A chained evidence record: a result plus its tamper-evidence link."""

    result: GateResult
    prev_chain: str
    chain: str


@dataclass
class Bundle:
    """A complete, hash-chained Proof-of-State bundle."""

    repo: str
    repo_commit: str
    generated_at: str
    entries: list[EvidenceEntry] = field(default_factory=list)
    # A freshly built bundle is never PASS until its gates roll up.
    rollup: Rollup = Rollup.PARTIAL
    schema_version: int = SCHEMA_VERSION

    @property
    def chain_head(self) -> str:
        return self.entries[-1].chain if self.entries else GENESIS
