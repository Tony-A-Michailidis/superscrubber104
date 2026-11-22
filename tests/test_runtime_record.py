"""The evidence says which interpreter produced it, once, not on every finding."""

import platform
from pathlib import Path

from superscrubber104.archive import ZSTD
from tests.models_helpers import inspect
from tests.software_fixtures import write


def test_analysis_and_assessment_record_python_and_zstd(tmp_path: Path) -> None:
    result = inspect(write(tmp_path / "d", {"a.txt": "hello"}))
    expected = {"python": platform.python_version(), "zstd": "yes" if ZSTD else "no"}
    assert dict(result.analysis.tool.extra or {}) == expected
    assert dict(result.assessment.tool.extra or {}) == expected
    assert all(
        f.tool.extra is None
        for f in result.assessment.findings
        if f.tool.name == "superscrubber104"
    )
