"""superscrubber104 request init | show."""

from pathlib import Path

from click.testing import CliRunner

from superscrubber104.cli import main
from superscrubber104.core.request import load_request
from tests.software_fixtures import write


def _delivery(tmp_path: Path) -> Path:
    return write(
        tmp_path / "delivery",
        {
            "models/tiny/config.json": "{}",
            "app/main.py": "print(1)\n",
            "README.md": "# delivery\n",
        },
    )


def test_init_writes_a_request_that_loads(tmp_path: Path) -> None:
    out = tmp_path / "request.yaml"
    result = CliRunner().invoke(
        main,
        ["request", "init", "-o", str(out), "--source", "dev-net", "--destination", "enclave-b"],
    )
    assert result.exit_code == 0, result.output
    request = load_request(out)
    assert (request.source, request.destination) == ("dev-net", "enclave-b")
    assert [e.paths for e in request.contents] == [("**",)]


def test_init_from_a_delivery_declares_every_top_level_item(tmp_path: Path) -> None:
    out = tmp_path / "request.yaml"
    delivery = _delivery(tmp_path)
    result = CliRunner().invoke(main, ["request", "init", "-o", str(out), "--from", str(delivery)])
    assert result.exit_code == 0, result.output
    request = load_request(out)
    assert {e.name: e.paths for e in request.contents} == {
        "app": ("app/**",),
        "models": ("models/**",),
        "top-level-files": ("README.md",),
    }
    shown = CliRunner().invoke(main, ["request", "show", str(out), "--delivery", str(delivery)])
    assert shown.exit_code == 0, shown.output
    assert "3 files, 0 not declared" in shown.output


def test_init_never_overwrites(tmp_path: Path) -> None:
    out = tmp_path / "request.yaml"
    out.write_text("mine\n", encoding="utf-8")
    result = CliRunner().invoke(main, ["request", "init", "-o", str(out)])
    assert result.exit_code == 2
    assert out.read_text(encoding="utf-8") == "mine\n"


def test_show_lists_what_no_entry_declares(tmp_path: Path) -> None:
    delivery = _delivery(tmp_path)
    out = tmp_path / "request.yaml"
    CliRunner().invoke(main, ["request", "init", "-o", str(out), "--from", str(delivery)])
    (delivery / "app" / "extra.sh").write_text("echo hi\n", encoding="utf-8")
    (delivery / "stray.bin").write_bytes(b"\0")
    result = CliRunner().invoke(main, ["request", "show", str(out), "--delivery", str(delivery)])
    assert result.exit_code == 1  # an open gap, as pack will report it
    assert "undeclared: stray.bin" in result.output
    assert "app  [2 files]" in result.output  # the new script is covered by app/**


def test_show_refuses_an_invalid_request(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("apiVersion: airlock/v1alpha1\nkind: TransferRequest\n", encoding="utf-8")
    result = CliRunner().invoke(main, ["request", "show", str(bad)])
    assert result.exit_code == 2
    assert "apiVersion" in result.output


def test_show_prints_the_example_request() -> None:
    example = Path(__file__).parent.parent / "examples" / "request.yaml"
    result = CliRunner().invoke(main, ["request", "show", str(example)])
    assert result.exit_code == 0, result.output
    assert "request   TR-2026-0001" in result.output
    assert "unit model-package" in result.output
    assert "upstream huggingface: example-org/tiny-chat @ 0123456789abcdef" in result.output
