"""Proof-of-State: trust-minimized, replayable release-state attestation.

Existing supply-chain tooling attests *provenance* (where an artifact was built).
Proof-of-State attests *state*: it turns a repository's quality-gate graph into a
hash-chained, fail-closed evidence bundle that an independent party can re-run
and reproduce — never "trust me", always "re-derive it". The single hard
invariant is ``UNKNOWN != PASS``.
"""

from __future__ import annotations

from .models import Bundle, GateResult, GateSpec, Rollup, Verdict
from .verifier import VerifyOutcome, VerifyReport, verify

__version__ = "0.1.0"

__all__ = [
    "Bundle",
    "GateResult",
    "GateSpec",
    "Rollup",
    "Verdict",
    "VerifyOutcome",
    "VerifyReport",
    "verify",
    "__version__",
]
