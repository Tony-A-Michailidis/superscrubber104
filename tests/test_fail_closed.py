"""Fail closed: nothing that goes wrong inside the tool can turn into an accept.

Two halves:

* **The guarantee.** A handler, an assembler or a scanner plugin that raises becomes a check error
  on the evidence; a check error is never decided ``allow`` or ``warn`` by a default or a rule;
  and a command that fails part-way exits 3 (refused) with a message, never a traceback.
* **The fuzz.** Every structured document the handlers read is fed back with each of its values
  replaced by one of another JSON type (a list where an object belongs, a number where a list
  belongs, ...). No handler may raise: a malformed document is a finding or "not assessed".
"""

import contextlib
import json
import random
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml
from click.testing import CliRunner

from superscrubber104 import scanners
from superscrubber104.cli import main
from superscrubber104.core.model import Disposition, Result, Verdict
from superscrubber104.formats.sigstore import BundleError, parse_bundle
from superscrubber104.handlers.secrets import SecretsHandler
from superscrubber104.units.model_package import ModelPackageAssembler
from tests.hauler_fixtures import haul, haul_bytes
from tests.model_fixtures import safetensors_bytes
from tests.models_helpers import findings_of, inspect
from tests.software_fixtures import oci_blobs, tar_bytes, write
from tests.zarf_fixtures import NAME, build, package_bytes

# --- the guarantee ------------------------------------------------------------------------------


def _boom(*_: object, **__: object) -> Any:
    raise RuntimeError("a bug")


def _decision(result, rule: str):  # type: ignore[no-untyped-def]
    ids = {f.id for f in findings_of(result)[rule]}
    return [d for d in result.assessment.decisions if d.finding in ids]


def test_a_handler_that_raises_needs_review(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(SecretsHandler, "inspect", _boom)
    result = inspect(write(tmp_path / "d", {"notes.txt": "hello\n"}))
    [error] = findings_of(result)["inventory.handler.error"]
    assert error.result is Result.ERROR and "RuntimeError: a bug" in error.detail["error"]
    assert [d.disposition for d in _decision(result, "inventory.handler.error")] == [
        Disposition.REQUIRE_APPROVAL
    ]
    assert result.assessment.summary.verdict is not Verdict.PASSED


def test_no_default_or_rule_lets_a_check_error_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(SecretsHandler, "inspect", _boom)
    lenient = """
        defaults:
          error: allow
        rules:
          - rule: inventory.handler.error
            error: warn
        """
    result = inspect(write(tmp_path / "d", {"notes.txt": "hello\n"}), policy_yaml=lenient)
    [decision] = _decision(result, "inventory.handler.error")
    assert decision.disposition is Disposition.REQUIRE_APPROVAL
    assert "check error" in decision.matched
    assert result.assessment.summary.verdict is not Verdict.PASSED


def test_an_assembler_that_raises_needs_review(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ModelPackageAssembler, "assemble", _boom)
    model = {"m/model.safetensors": safetensors_bytes({"w": ("F32", [2])})}
    result = inspect(write(tmp_path / "d", model))
    [error] = findings_of(result)["inventory.handler.error"]
    assert error.tool.name == "model-package"
    assert result.assessment.summary.verdict is not Verdict.PASSED


def test_a_scanner_that_raises_is_a_scan_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Any exception from a plugin, not only its own ScanError, is recorded as a scan error."""
    recorded: list[tuple[str, str]] = []

    class Raising:
        name, capability = "raising", "raising"

        def scan(self, *_: object) -> None:
            raise KeyError("unexpected output")

    class Recorder:
        def error(self, rule: str, subject: object, *, tool: object, error: str) -> None:
            recorded.append((rule, error))

    class Ready:
        tool = None

    class Preflight:
        def __init__(self, *_: object) -> None:
            pass

        def run(self) -> tuple[object, Ready]:
            return type("S", (), {"name": "raising"})(), Ready()

    class Ctx:
        recorder = Recorder()
        policy = type("P", (), {"plugins": {"raising": object()}})()

    monkeypatch.setattr(scanners, "Preflight", Preflight)
    monkeypatch.setattr(scanners, "CAPABILITIES", {})
    scanners.run_scanners(Ctx(), [], None, [Raising()])  # type: ignore[arg-type,list-item]
    assert recorded == [("plugin.scan.error", "KeyError: 'unexpected output'")]


def test_a_command_that_fails_part_way_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import superscrubber104.cli as cli

    monkeypatch.setattr(cli, "inspect_paths", _boom)
    root = write(tmp_path / "d", {"notes.txt": "hello\n"})
    result = CliRunner().invoke(main, ["model", "inspect", str(root)])
    assert result.exit_code == 3, result.output
    assert "internal error: RuntimeError: a bug" in result.output
    assert "Traceback" not in result.output


# --- the fuzz -----------------------------------------------------------------------------------

SUBSTITUTES: list[object] = [[1], {"a": 1}, "x", 7, None, [{"a": [1]}], {"a": {"b": "c"}}]
ST = safetensors_bytes({"w": ("F32", [2, 2])})
CONFIG = b'{"model_type": "llama"}'

# (path in the delivery, document, format, files beside it)
DOCUMENTS: dict[str, tuple[str, object, str, dict[str, bytes]]] = {
    "mcp": (".mcp.json", {"mcpServers": {"fs": {"command": "npx", "args": ["-y", "pkg@1.0.0", "/data"], "env": {"API_URL": "https://example.org"}}, "web": {"url": "https://mcp.example.org/sse", "headers": {"Authorization": "Bearer x"}}}}, "json", {}),
    "agent-settings": (".claude/settings.json", {"permissions": {"allow": ["Bash(*)"], "deny": []}, "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "echo hi"}]}]}}, "json", {}),
    "package.json": ("app/package.json", {"name": "app", "version": "1.0.0", "dependencies": {"left-pad": "^1.3.0"}, "scripts": {"postinstall": "node x.js"}}, "json", {}),
    "package-lock": ("app/package-lock.json", {"name": "app", "lockfileVersion": 3, "packages": {"": {"name": "app", "dependencies": {"left-pad": "1.3.0"}}, "node_modules/left-pad": {"version": "1.3.0", "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", "integrity": "sha512-AAAA"}}}, "json", {}),
    "model-config": ("m/config.json", {"model_type": "llama", "architectures": ["LlamaForCausalLM"], "hidden_size": 8, "auto_map": {"AutoModel": "modeling.X"}, "quantization_config": {"quant_method": "gptq", "bits": 4}}, "json", {"m/model.safetensors": ST}),
    "tokenizer-config": ("m/tokenizer_config.json", {"chat_template": "{% for m in messages %}{{ m.content }}{% endfor %}", "model_max_length": 2048, "added_tokens_decoder": {"0": {"content": "<s>"}}}, "json", {"m/model.safetensors": ST, "m/config.json": CONFIG}),
    "notebook": ("n/a.ipynb", {"nbformat": 4, "nbformat_minor": 5, "metadata": {"kernelspec": {"name": "python3"}}, "cells": [{"cell_type": "code", "source": ["import requests\n", "requests.get('https://x')"], "outputs": [{"output_type": "stream", "text": ["hi"]}], "metadata": {}}]}, "json", {}),
    "compose": ("compose.yaml", {"services": {"web": {"image": "nginx:1.25", "ports": ["80:80"], "volumes": ["/var/run/docker.sock:/s"], "environment": {"A": "b"}, "privileged": True}}}, "yaml", {}),
    "kubernetes": ("k8s/deploy.yaml", {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "a"}, "spec": {"template": {"spec": {"hostNetwork": True, "containers": [{"name": "a", "image": "x:1", "securityContext": {"privileged": True}}], "volumes": [{"name": "h", "hostPath": {"path": "/"}}]}}}}, "yaml", {}),
    "helm-chart": ("chart/Chart.yaml", {"apiVersion": "v2", "name": "c", "version": "1.0.0", "dependencies": [{"name": "r", "version": "1.0.0", "repository": "https://x"}]}, "yaml", {}),
    "mlflow": ("mlm/MLmodel", {"artifact_path": "model", "flavors": {"python_function": {"loader_module": "mlflow.sklearn", "env": "conda.yaml"}, "sklearn": {"pickled_model": "model.pkl", "serialization_format": "cloudpickle"}}}, "yaml", {}),
    "vscode-extension": ("ext/extension/package.json", {"name": "e", "publisher": "p", "version": "1.0.0", "engines": {"vscode": "^1.80.0"}, "activationEvents": ["*"], "contributes": {"commands": []}, "extensionDependencies": ["a.b"]}, "json", {"ext/extension.vsixmanifest": b"<PackageManifest/>"}),
    "runtime-profile": ("runtime/chat.runtime.yaml", {"apiVersion": "superscrubber104/v1alpha1", "kind": "RuntimeProfile", "metadata": {"name": "vllm"}, "server": {"name": "vllm", "version": "0.6.0"}, "gpu": {"vendor": "nvidia", "driver": ">=550"}}, "yaml", {}),
    "eval-set": ("eval/smoke.yaml", {"apiVersion": "superscrubber104/v1alpha1", "kind": "EvalSet", "metadata": {"name": "e"}, "items": [{"id": "a", "prompt": "hi", "expect": {"contains": "hello"}}]}, "yaml", {}),
}  # fmt: skip


def _paths(value: object, prefix: tuple[object, ...] = ()) -> Iterator[tuple[object, ...]]:
    yield prefix
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _paths(child, (*prefix, key))
    elif isinstance(value, list):
        for index, child in enumerate(value[:4]):
            yield from _paths(child, (*prefix, index))


def _replaced(value: object, path: tuple[object, ...], new: object) -> object:
    if not path:
        return new
    clone = json.loads(json.dumps(value))
    node = clone
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = new
    return clone


def _variants(document: object, seed: str, per_path: int = 2) -> Iterator[object]:
    rng = random.Random(seed)
    for path in _paths(document):
        for new in rng.sample(SUBSTITUTES, per_path):
            yield _replaced(document, path, new)


def _dump(document: object, fmt: str) -> bytes:
    return (json.dumps(document) if fmt == "json" else yaml.safe_dump(document)).encode()


def _no_handler_errors(root: Path) -> None:
    errors = findings_of(inspect(root)).get("inventory.handler.error", [])
    assert not errors, [(e.subject.display, e.detail.get("error")) for e in errors][:5]


@pytest.mark.parametrize("label", sorted(DOCUMENTS))
def test_documents_of_any_shape_never_crash_a_handler(tmp_path: Path, label: str) -> None:
    path, document, fmt, beside = DOCUMENTS[label]
    files: dict[str, bytes | str] = {}
    for index, variant in enumerate(_variants(document, label)):
        files.update({f"v{index}/{name}": data for name, data in beside.items()})
        files[f"v{index}/{path}"] = _dump(variant, fmt)
    _no_handler_errors(write(tmp_path / "d", files))


def _layout_documents(members: dict[str, bytes]) -> list[str]:
    """The JSON members of an image layout: index.json and every manifest or index blob."""
    names = []
    for name, data in members.items():
        if not (name.endswith("index.json") or "/blobs/sha256/" in f"/{name}"):
            continue
        try:
            parsed = json.loads(data)
        except ValueError:
            continue
        if isinstance(parsed, dict) and ("manifests" in parsed or "layers" in parsed):
            names.append(name)
    return names


def _mutated_members(members: dict[str, bytes], seed: str) -> Iterator[dict[str, bytes]]:
    for name in _layout_documents(members):
        for variant in _variants(json.loads(members[name]), f"{seed}:{name}", per_path=1):
            yield {**members, name: json.dumps(variant).encode()}


def test_image_layouts_of_any_shape_never_crash_a_handler(tmp_path: Path) -> None:
    blobs = {k: v.encode() if isinstance(v, str) else v for k, v in oci_blobs().items()}
    files = {
        f"v{i}/app-oci.tar": tar_bytes(m) for i, m in enumerate(_mutated_members(blobs, "oci"))
    }
    _no_handler_errors(write(tmp_path / "d", files))


def test_zarf_packages_of_any_shape_never_crash_a_handler(tmp_path: Path) -> None:
    members = build()
    files = {
        f"v{i}/{NAME}": package_bytes(m) for i, m in enumerate(_mutated_members(members, "zarf"))
    }
    _no_handler_errors(write(tmp_path / "d", files))


def test_hauls_of_any_shape_never_crash_a_handler(tmp_path: Path) -> None:
    members = haul()
    files = {
        f"v{i}/haul.tar": haul_bytes(m) for i, m in enumerate(_mutated_members(members, "haul"))
    }
    _no_handler_errors(write(tmp_path / "d", files))


SIGSTORE_BUNDLE = {
    "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
    "verificationMaterial": {
        "x509CertificateChain": {"certificates": [{"rawBytes": "AA=="}]},
        "tlogEntries": [{"logIndex": "1", "inclusionPromise": {"signedEntryTimestamp": "AA=="}}],
        "publicKey": {"hint": "k"},
    },
    "dsseEnvelope": {
        "payload": "e30=",
        "payloadType": "application/vnd.in-toto+json",
        "signatures": [{"sig": "AA==", "keyid": ""}],
    },
}


def test_sigstore_bundles_of_any_shape_raise_only_bundle_errors() -> None:
    message = {**SIGSTORE_BUNDLE, "messageSignature": {"messageDigest": {"algorithm": "SHA2_256", "digest": "AA=="}, "signature": "AA=="}}  # fmt: skip
    message.pop("dsseEnvelope")
    for seed, document in (("dsse", SIGSTORE_BUNDLE), ("message", message)):
        for variant in _variants(document, seed, per_path=len(SUBSTITUTES)):
            with contextlib.suppress(BundleError):
                parse_bundle(json.dumps(variant).encode(), artifact=b"artifact")
