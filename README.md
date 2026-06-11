# Proof-of-State

**Trust-minimized, replayable release-state attestation.** Existing supply-chain
tools attest *provenance* — *where* an artifact was built (SLSA, sigstore,
in-toto). Proof-of-State attests *state* — that a repository's quality gates
actually hold, in a form an independent party can **re-run and reproduce instead
of believing you**.

One hard invariant: **`UNKNOWN != PASS`**. A gate whose verdict could not be
established never rolls up to a passing state. No green-light theater.

## The whole point (and its kill-test)

A bundle that only its producer can reproduce is not an attestation — it is a
press release. So the load-bearing test is adversarial: **a perfectly
re-signed lie must still be caught.**

```python
# Producer flips a real FAIL to PASS and re-chains it so the hash chain is
# internally consistent. On paper the bundle is a clean PASS.
forged = bundle_with(verdict=PASS)        # chain intact, rollup == pass

report = verify(forged, repo)
assert report.chain_intact is True        # the liar chained consistently...
assert report.outcome == DIVERGED         # ...but the gate still fails when re-run
```

The verifier does two independent things, neither of which trusts the producer:

1. **Integrity** — recompute the sha256 hash-chain over every recorded verdict.
   A naive edit breaks the chain (`TAMPERED`).
2. **Reproduction** — actually re-run each gate and compare the fresh verdict to
   the claim. A consistently-chained lie reproduces as `DIVERGED`.

Only a bundle whose chain is intact **and** whose every verdict reproduces, with
a rollup that is a genuine `PASS`, is reported `POS_VERIFY_TRUSTWORTHY_PASS`.

## Usage

```bash
pip install -e '.[dev]'

# Produce a hash-chained bundle from a declared gate graph
pos run /path/to/repo --config proof_of_state.toml --output state.bundle.json

# Independently verify it — re-runs every gate, trusts nothing
pos verify state.bundle.json /path/to/repo
```

Gate graph (`proof_of_state.toml`): each gate is a command; exit `0` → `pass`,
a declared `unknown_exit_codes` → `unknown` (never `pass`), anything else →
`fail`. See [`examples/proof_of_state.toml`](examples/proof_of_state.toml).

## Design stance

- **Zero runtime dependencies on Python 3.11+** — the tool's own supply-chain
  surface is the standard library (`tomli` only on 3.10).
- **The gate command is the source of truth.** Proof-of-State never interprets
  gate semantics; that is precisely what makes a bundle reproducible by anyone.
- **Fail-closed.** Tamper, divergence, an inconsistent rollup, or a missing
  re-run are all non-PASS outcomes.

## Reference adapter

[`neuron7xLab/bive`](https://github.com/neuron7xLab/bive) is the first reference
instance: its 33-gate `verify-release` spine maps directly onto a Proof-of-State
gate graph.

## Status

`v0.1.0` — kernel. Not yet a cryptographic signing layer (the chain is
tamper-*evident*, not yet signed); see the roadmap in the issues.
