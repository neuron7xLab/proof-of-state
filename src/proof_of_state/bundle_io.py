"""Serialize and deserialize Proof-of-State bundles as canonical JSON."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import (
    SCHEMA_VERSION,
    Bundle,
    EvidenceEntry,
    GateResult,
    GateSpec,
    Rollup,
    Verdict,
)


def _spec_to_dict(spec: GateSpec) -> dict[str, Any]:
    return {
        "name": spec.name,
        "command": list(spec.command),
        "timeout_seconds": spec.timeout_seconds,
        "unknown_exit_codes": list(spec.unknown_exit_codes),
        "required": spec.required,
    }


def _spec_from_dict(data: dict[str, Any]) -> GateSpec:
    return GateSpec(
        name=str(data["name"]),
        command=[str(p) for p in data["command"]],
        timeout_seconds=int(data.get("timeout_seconds", 300)),
        unknown_exit_codes=tuple(int(c) for c in data.get("unknown_exit_codes", [])),
        required=bool(data.get("required", True)),
    )


def to_dict(bundle: Bundle) -> dict[str, Any]:
    return {
        "schema_version": bundle.schema_version,
        "repo": bundle.repo,
        "repo_commit": bundle.repo_commit,
        "generated_at": bundle.generated_at,
        "rollup": bundle.rollup.value,
        "chain_head": bundle.chain_head,
        "entries": [
            {
                "result": {
                    "index": entry.result.index,
                    "spec": _spec_to_dict(entry.result.spec),
                    "verdict": entry.result.verdict.value,
                    "exit_code": entry.result.exit_code,
                    "stdout_sha256": entry.result.stdout_sha256,
                    "duration_seconds": round(entry.result.duration_seconds, 4),
                },
                "prev_chain": entry.prev_chain,
                "chain": entry.chain,
            }
            for entry in bundle.entries
        ],
    }


def from_dict(data: dict[str, Any]) -> Bundle:
    entries: list[EvidenceEntry] = []
    for raw in data.get("entries", []):
        result_raw = raw["result"]
        result = GateResult(
            index=int(result_raw["index"]),
            spec=_spec_from_dict(result_raw["spec"]),
            verdict=Verdict(result_raw["verdict"]),
            exit_code=int(result_raw["exit_code"]),
            stdout_sha256=str(result_raw["stdout_sha256"]),
            duration_seconds=float(result_raw.get("duration_seconds", 0.0)),
        )
        entries.append(
            EvidenceEntry(result=result, prev_chain=str(raw["prev_chain"]), chain=str(raw["chain"]))
        )
    return Bundle(
        repo=str(data["repo"]),
        repo_commit=str(data["repo_commit"]),
        generated_at=str(data["generated_at"]),
        entries=entries,
        rollup=Rollup(data.get("rollup", "unknown")),
        schema_version=int(data.get("schema_version", SCHEMA_VERSION)),
    )


def dumps(bundle: Bundle) -> str:
    return json.dumps(to_dict(bundle), indent=2, sort_keys=True, ensure_ascii=False)


def write(bundle: Bundle, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dumps(bundle) + "\n", encoding="utf-8")


def read(path: Path) -> Bundle:
    return from_dict(json.loads(path.read_text(encoding="utf-8")))
