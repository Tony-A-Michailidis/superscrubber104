"""Reports: the report model, the control matrix and every output format."""

import json
from dataclasses import replace
from pathlib import Path

import pytest
from click.testing import CliRunner

from airlock.cli import main
from airlock.core.controls import ControlCatalog
from airlock.core.model import Result
from airlock.pack import pack
from airlock.report import FORMATS, Source, build_report, load_source, render
from airlock.report.markdown import cell
from airlock.report.model import Context
from airlock.report.oscal import control_id
from airlock.verify import verify
from tests.data_fixtures import embedding_model
from tests.helpers import NOW, make_site
from tests.models_helpers import inspect, make_policy
from tests.software_fixtures import docker_archive, wheel_bytes, wheel_name, write


@pytest.fixture(scope="module")
def imported(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    """A packed bundle and the directory airlock verify wrote for it."""
    tmp = tmp_path_factory.mktemp("report")
    site = make_site(tmp / "site")
    delivery = write(
        tmp / "delivery",
        {
            **embedding_model("models/embedder"),
            f"vendor/{wheel_name()}": wheel_bytes(),
            "app/main.py": "print('hello')\n",
            "app/requirements.txt": "tinylib==1.0.0\n",
            "images/app.tar": docker_archive(),  # not in the request: needs approval
            "docs/README.md": "# docs\n",
        },
    )
    packed = pack(
        [delivery],
        tmp / "bundle",
        signer=site.pack_key,
        policy=make_policy(tmp / "packer"),
        request_path=site.request,
        now=NOW,
    )
    receiving = site.policy("licences: {allow: [MIT, Apache-2.0]}\n")
    verify(packed.bundle, policy=receiving, now=NOW, out=tmp / "imported")
    return packed.bundle, tmp / "imported"


def test_sources_and_formats(imported: tuple[Path, Path]) -> None:
    bundle, verified = imported
    packed, mine = load_source(bundle), load_source(verified)
    assert packed.context.origin.startswith("bundle (packing side")
    assert mine.context.origin == "this side's verification"
    assert mine.context.receipt is not None and mine.analysis is not None
    for source in (packed, mine):
        for fmt in FORMATS:
            assert render(source, fmt) == render(source, fmt)  # deterministic
    markdown = render(mine, "md")
    assert "**Verdict: NEEDS APPROVAL" in markdown
    assert "| NEEDS APPROVAL | request.artifact.undeclared | images/app.tar |" in markdown
    assert "## Not assessed" in markdown and "vuln.component.known" in markdown
    report = json.loads(render(mine, "json"))
    assert report["kind"] == "Report" and report["verdict"] == "needs-approval"
    assert report["totals"]["units"] == len(mine.analysis.units)


def test_control_matrix(imported: tuple[Path, Path]) -> None:
    report = build_report(load_source(imported[1]))
    controls = {c.id: c for c in report.controls}
    assert set(controls) >= {c.id for c in ControlCatalog.builtin()}
    assert controls["RA-5"].status == "not-assessed"  # no vulnerability scanner configured
    assert controls["CM-8"].status == "findings"  # the undeclared image needs approval
    assert controls["CM-4"].status == "no-rules"
    assert controls["SI-7"].passed > 0 and "integrity.hash.mismatch" in controls["SI-7"].rules
    assert all(c.provided for c in controls.values() if c.id in {"SI-7", "CM-8", "AU-10"})
    assert not any(c.status == "satisfied" for c in report.controls)


def test_cyclonedx(imported: tuple[Path, Path]) -> None:
    sbom = json.loads(render(load_source(imported[1]), "cyclonedx"))
    assert (sbom["bomFormat"], sbom["specVersion"]) == ("CycloneDX", "1.6")
    assert sbom["serialNumber"].startswith("urn:uuid:")

    def flatten(items: list[dict[str, object]]) -> list[dict[str, object]]:
        out = []
        for item in items:
            out.append(item)
            out += flatten(item.get("components", []))  # type: ignore[arg-type]
        return out

    components = flatten(sbom["components"])
    types = {c["type"] for c in components}
    assert {"machine-learning-model", "library", "container", "operating-system"} <= types
    wheel = next(c for c in components if str(c.get("purl", "")).startswith("pkg:pypi/tinylib"))
    assert wheel["hashes"][0]["alg"] == "SHA-256"
    assert wheel["licenses"] == [{"expression": "MIT"}]
    assert len({c["bom-ref"] for c in components}) == len(components)


def test_oscal(imported: tuple[Path, Path]) -> None:
    document = json.loads(render(load_source(imported[1]), "oscal"))["assessment-results"]
    assert document["metadata"]["oscal-version"] == "1.1.2"
    result = document["results"][0]
    states = {f["target"]["target-id"]: f["target"]["status"] for f in result["findings"]}
    assert states["cm-8_obj"] == {"state": "not-satisfied", "reason": "fail"}
    assert states["ra-5_obj"] == {"state": "not-satisfied", "reason": "other"}
    assert "satisfied" not in {s["state"] for s in states.values()}  # never claimed
    assert "ac-4_obj" not in states  # checks ran and found nothing: an observation only
    observed = {o["uuid"] for o in result["observations"]}
    for finding in result["findings"]:
        assert {r["observation-uuid"] for r in finding["related-observations"]} <= observed
    assert control_id("SI-7(1)") == "si-7.1"


def test_html_escapes_what_crossed(tmp_path: Path) -> None:
    result = inspect(write(tmp_path / "d", {"app/settings.ini": "x = 1\n"}))
    hostile = '<script>alert("x")</script>'
    finding = next(f for f in result.assessment.findings if f.result is not Result.PASS)
    poisoned = replace(finding, detail={"note": hostile})
    findings = tuple(poisoned if f.id == finding.id else f for f in result.assessment.findings)
    source = Source(result.analysis, replace(result.assessment, findings=findings), Context("test"))
    page = render(source, "html")
    assert "<script>" not in page and "&lt;script&gt;" in page
    assert "default-src 'none'" in page and "http" not in page.split("<body>")[0].replace(
        "http-equiv", ""
    )
    assert cell("a|b`c") == "a\\|b\\`c"


def test_report_command_and_inspect_out(tmp_path: Path, imported: tuple[Path, Path]) -> None:
    out = tmp_path / "report.html"
    result = CliRunner().invoke(main, ["report", str(imported[0]), "-f", "html", "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert out.read_text(encoding="utf-8").startswith("<!doctype html>")

    delivery = write(tmp_path / "d", embedding_model("models/embedder"))
    result = CliRunner().invoke(
        main, ["model", "inspect", str(delivery), "--out", str(tmp_path / "i")]
    )
    assert (tmp_path / "i" / "assessment.inspect.json").is_file()
    result = CliRunner().invoke(main, ["report", str(tmp_path / "i"), "-f", "cyclonedx"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["bomFormat"] == "CycloneDX"
    result = CliRunner().invoke(main, ["report", str(tmp_path)])
    assert result.exit_code == 2 and "no bundle" in result.output
