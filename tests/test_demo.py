"""The README demo runs, and catches what the README says it catches."""

import importlib.util
import json
from pathlib import Path

import pytest

DEMO = Path(__file__).parent.parent / "examples" / "demo" / "demo.py"


def test_readme_demo(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    spec = importlib.util.spec_from_file_location("airlock_demo", DEMO)
    assert spec is not None and spec.loader is not None
    demo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(demo)

    assert demo.main(tmp_path / "run") == 0
    output = capsys.readouterr().out
    for line in (
        "tampered shard   caught: integrity.hash.mismatch",
        "undeclared file  caught: integrity.entry.unexpected",
        "pickle payload   caught: model.pickle.dangerous-import",
        "clean import accepted (exit 0); tampered import refused (exit 3)",
    ):
        assert line in output
    run = tmp_path / "run"
    for report in ("report.html", "sbom.cdx.json", "oscal.json"):
        assert (run / "import-1" / report).is_file()
    sbom = json.loads((run / "import-1" / "sbom.cdx.json").read_text(encoding="utf-8"))
    types = {c["type"] for c in sbom["components"]}
    assert {"machine-learning-model", "library"} <= types
    report = (run / "import-2" / "report.md").read_text(encoding="utf-8")
    assert "**Verdict: REFUSED" in report and "| SI-7 |" in report
