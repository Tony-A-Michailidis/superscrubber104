"""The basics every delivery gets: secrets, executables and active content in documents."""

import json
from pathlib import Path

import pytest

from superscrubber104.core.model import Severity
from tests.data_fixtures import REMOTE_TEMPLATE_RELS, elf_bytes, office_zip, pdf_bytes, pe_bytes
from tests.models_helpers import artifact, findings_of, inspect
from tests.software_fixtures import FAKE_TOKEN, docker_archive, write

# Credential-shaped strings are assembled at run time so that the repository never holds one.
AWS_KEY = "AKIA" + "Q7XZ3M4N5P6R7S8T"
PEM = "-----BEGIN RSA " + "PRIVATE KEY-----\n" + "MIIEow" + "A" * 58 + "\n" + "B" * 64 + "\n"
PASSWORD = "Tr0ub4dor&" + "3xKq9z"
DB_PASS = "Hx7pQ2" + "vL9mZ4"


def _secrets(result) -> dict[str, list[dict[str, object]]]:  # type: ignore[no-untyped-def]
    found: dict[str, list[dict[str, object]]] = {}
    for f in findings_of(result).get("secret.detected", []):
        found.setdefault(f.subject.display, []).append(
            {"type": f.detail["type"], "severity": f.severity}
        )
    return found


def test_secrets_are_found_but_never_recorded(tmp_path: Path) -> None:
    result = inspect(
        write(
            tmp_path / "d",
            {
                "app/settings.py": f'AWS_ACCESS_KEY_ID = "{AWS_KEY}"\nDB_PASSWORD = "{PASSWORD}"\n',
                "deploy/id_rsa": PEM,
                "deploy/service-account.json": json.dumps(
                    {"type": "service_account", "private_key": PEM}
                ),
                "app/.env": f"GITHUB_TOKEN={FAKE_TOKEN}\n",
                "app/db.yaml": f"url: postgres://reporting:{DB_PASS}@db.internal:5432/app\n",
            },
        )
    )
    found = _secrets(result)
    assert {s["type"] for s in found["app/settings.py#line 1"]} == {"aws-access-key-id"}
    assert {s["type"] for s in found["app/settings.py#line 2"]} == {"password-assignment"}
    assert found["deploy/id_rsa#line 1"][0]["type"] == "private-key"
    assert found["deploy/service-account.json#line 1"][0]["type"] == "private-key"
    assert found["app/.env#line 1"][0]["type"] == "github-token"
    assert found["app/db.yaml#line 1"][0]["type"] == "url-credentials"
    dumped = json.dumps([f.detail for f in findings_of(result)["secret.detected"]])
    for secret in (AWS_KEY, PASSWORD, FAKE_TOKEN, "MIIEow", DB_PASS):
        assert secret not in dumped


@pytest.mark.parametrize(
    "text",
    [
        'password = "changeme123"',
        'api_key = "${API_KEY}"',
        'PASSWORD = "<your-password-here>"',
        'secret: "xxxxxxxxxxxx"',
        'HEADER = b"-----BEGIN RSA PRIVATE KEY-----\\n"  # a constant in a parser',
        "url = 'https://user:${PASS}@example.org/'",
    ],
)
def test_placeholders_and_parser_constants_are_quiet(tmp_path: Path, text: str) -> None:
    result = inspect(write(tmp_path / "d", {"app/config.py": text + "\n"}))
    assert "secret.detected" not in findings_of(result)


def test_test_paths_are_low_and_layers_are_searched(tmp_path: Path) -> None:
    layer = {"etc/os-release": "ID=debian\n", "root/.aws/credentials": f"key = {AWS_KEY}\n"}
    result = inspect(
        write(
            tmp_path / "d",
            {
                "lib/tests/test_client.py": f'KEY = "{AWS_KEY}"\n',
                "images/app.tar": docker_archive([layer]),
            },
        )
    )
    found = findings_of(result)["secret.detected"]
    by_path = {f.subject.artifact.display: f for f in found if f.subject.artifact}
    assert by_path["lib/tests/test_client.py"].severity is Severity.LOW
    [layered] = [f for f in found if f.subject.artifact and f.subject.artifact.member]
    assert layered.subject.artifact.member[-1] == "root/.aws/credentials"
    assert layered.severity is Severity.HIGH


def test_executables_are_identified(tmp_path: Path) -> None:
    result = inspect(
        write(
            tmp_path / "d",
            {
                "bin/tool": elf_bytes(),
                "bin/tool.exe": pe_bytes(),
                "bin/run.sh": "#!/usr/bin/env bash\necho hi\n",
                "scripts/setup.ps1": "Write-Host hi\n",
                "lib/Thing.class": b"\xca\xfe\xba\xbe\x00\x00\x00\x41" + b"\0" * 32,
            },
        )
    )
    elf = artifact(result, "bin/tool")
    assert elf.kinds[0] == "executable.elf"
    assert elf.metadata["executable"]["architecture"] == "x86-64"
    pe = artifact(result, "bin/tool.exe").metadata["executable"]
    assert (pe["architecture"], pe["bits"], pe["authenticode"]) == (
        "x86-64",
        64,
        "present (not verified)",
    )
    assert artifact(result, "bin/run.sh").metadata["executable"]["interpreter"] == "bash"
    assert (
        artifact(result, "scripts/setup.ps1").metadata["executable"]["interpreter"] == "powershell"
    )
    assert "executable.mach-o" not in artifact(result, "lib/Thing.class").kinds  # Java, not Mach-O


def _active(result) -> dict[str, tuple[object, Severity]]:  # type: ignore[no-untyped-def]
    return {
        f.subject.display: (f.detail["found"], f.severity)
        for f in findings_of(result).get("document.active-content", [])
    }


def test_active_content_in_documents(tmp_path: Path) -> None:
    ole = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 64 + "_VBA_PROJECT".encode("utf-16-le")
    result = inspect(
        write(
            tmp_path / "d",
            {
                "docs/report.docm": office_zip({"word/vbaProject.bin": b"\0" * 16}),
                "docs/letter.docx": office_zip(
                    {"word/_rels/settings.xml.rels": REMOTE_TEMPLATE_RELS}
                ),
                "docs/clean.docx": office_zip({}),
                "docs/legacy.doc": ole,
                "docs/js.pdf": pdf_bytes(b"/OpenAction << /S /JavaScript /JS (app.alert(1)) >>"),
                "docs/hex.pdf": pdf_bytes(b"/AA << /O << /S /J#61vaScript >> >>"),
                "docs/hidden.pdf": pdf_bytes(
                    b"", object_stream=b"3 0 << /S /Launch /F (cmd.exe) >>"
                ),
                "docs/plain.pdf": pdf_bytes(b"/Pages 2 0 R"),
                "docs/memo.rtf": "{\\rtf1 hello {\\object\\objemb{\\*\\objdata 0105}}}",
                "img/logo.svg": '<svg xmlns="http://www.w3.org/2000/svg" onload="go()"></svg>',
            },
        )
    )
    active = _active(result)
    assert active["docs/report.docm"] == (["VBA macros"], Severity.MEDIUM)
    assert active["docs/letter.docx"] == (["external attachedTemplate"], Severity.HIGH)
    assert active["docs/legacy.doc"][0] == ["VBA macros"]
    assert active["docs/js.pdf"] == (["javascript"], Severity.HIGH)
    assert active["docs/hex.pdf"][0] == ["javascript"]
    assert active["docs/hidden.pdf"] == (["launch action"], Severity.HIGH)
    assert active["docs/memo.rtf"][1] is Severity.HIGH
    assert active["img/logo.svg"][0] == ["script"]
    assert "docs/clean.docx" not in active and "docs/plain.pdf" not in active


def test_secrets_in_very_long_lines(tmp_path: Path) -> None:
    padding = json.dumps({"NextToken": "a" * 50, "items": ["word"] * 20000})
    minified = padding[:-1] + f', "creds": {{"key": "{AWS_KEY}"}}}}\n'
    found = _secrets(inspect(write(tmp_path / "d", {"data/api.json": "{}\n" + minified})))
    assert found == {
        "data/api.json#line 2": [{"type": "aws-access-key-id", "severity": Severity.HIGH}]
    }


def test_a_value_that_names_a_secret_is_not_one(tmp_path: Path) -> None:
    # BuildKit provenance records which build secrets were mounted, by name.
    statement = '{"args": {"git.authheadersecret": "GIT_AUTH_HEADER", "secret": "MY_API_KEY_2"}}'
    found = findings_of(inspect(write(tmp_path / "d", {"provenance.json": statement})))
    assert "secret.detected" not in found


def test_javascript_test_files_are_test_paths(tmp_path: Path) -> None:
    files = {
        path: f'const password = "{PASSWORD}";\n'
        for path in ("src/__tests__/client.ts", "src/client.test.ts", "src/client.spec.js")
    }
    found = findings_of(inspect(write(tmp_path / "d", files)))["secret.detected"]
    assert len(found) == 3
    assert all(f.severity is Severity.LOW for f in found)


def _jwt(claims: dict[str, object]) -> str:
    """A JWT-shaped string, assembled at run time (the repository never holds one)."""
    import base64

    def part(value: dict[str, object]) -> str:
        raw = json.dumps(value, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    return f"{part({'alg': 'EdDSA', 'typ': 'JWT'})}.{part(claims)}." + "s1gnaTure" * 4


def test_hugging_face_evaluation_receipts_are_not_secrets(tmp_path: Path) -> None:
    """Model cards carry signed, public verifyToken receipts (``{"hash", "version"}``)."""
    receipt = _jwt({"hash": "7f28c1b66cba" * 5, "version": 1})
    session = _jwt({"sub": "admin", "exp": 1999999999, "scope": "write"})
    card = (
        "---\nmodel-index:\n- results:\n  - metrics:\n    - type: accuracy\n"
        f"      verified: true\n      verifyToken: {receipt}\n"
        f"      verifyToken: {session}\n---\n"
    )
    result = inspect(
        write(
            tmp_path / "d",
            {
                "model/README.md": card,
                "app/auth.yaml": f"token: {receipt}\nbearer: {session}\n",
            },
        )
    )
    found = _secrets(result)
    # the receipt under verifyToken is quiet; a session token under the same key is not
    assert set(found) == {
        "model/README.md#line 8",
        "app/auth.yaml#line 1",
        "app/auth.yaml#line 2",
    }
    assert {s["type"] for v in found.values() for s in v} == {"jwt"}
