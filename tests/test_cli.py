from __future__ import annotations

from pathlib import Path

from proof_of_state.cli import main


def _write_graph(repo: Path, *, failing: bool) -> Path:
    exit_code = 1 if failing else 0
    config = repo / "proof_of_state.toml"
    config.write_text(
        "[[gate]]\n"
        'name = "unit"\n'
        f'command = ["python", "-c", "import sys; sys.exit({exit_code})"]\n',
        encoding="utf-8",
    )
    return config


def test_run_then_verify_roundtrip_pass(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    config = _write_graph(tmp_path, failing=False)
    bundle = tmp_path / "b.json"
    rc_run = main(["run", str(tmp_path), "--config", str(config), "--output", str(bundle)])
    assert rc_run == 0
    rc_verify = main(["verify", str(bundle), str(tmp_path)])
    assert rc_verify == 0
    out = capsys.readouterr().out
    assert "POS_VERIFY_TRUSTWORTHY_PASS" in out


def test_run_failing_gate_exits_nonzero(tmp_path: Path) -> None:
    config = _write_graph(tmp_path, failing=True)
    bundle = tmp_path / "b.json"
    rc_run = main(["run", str(tmp_path), "--config", str(config), "--output", str(bundle)])
    assert rc_run == 1
    rc_verify = main(["verify", str(bundle), str(tmp_path)])
    assert rc_verify == 1  # reproduces, but a FAIL rollup is never a trustworthy pass
