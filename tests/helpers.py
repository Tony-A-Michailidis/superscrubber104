"""Builders shared by the end-to-end tests. Everything is synthetic and tiny."""

import hashlib
import io
import tarfile
import textwrap
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from superscrubber104.core.model import Assessment, Disposition, Finding
from superscrubber104.core.policy import Policy, load_policy
from superscrubber104.core.signing import SigningKey, generate_key

NOW = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
SOURCE = "dev-unclass"
ENCLAVE = "enclave-b"


def zip_bytes(files: Mapping[str, bytes], compression: int = zipfile.ZIP_DEFLATED) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression) as archive:
        for name, data in files.items():
            archive.writestr(zipfile.ZipInfo(name), data, compression)
    return buffer.getvalue()


def tar_bytes(files: Mapping[str, bytes], mode: str = "w") -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode=mode) as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def write_tree(root: Path, files: Mapping[str, bytes]) -> Path:
    for name, data in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return root


def make_delivery(root: Path) -> Path:
    """A small mixed delivery: source, a 'model', a document, an archive and an empty directory."""
    write_tree(
        root,
        {
            "app/main.py": b'print("hello")\n',
            "app/settings.ini": b"[app]\nname = example\n",
            "models/tiny/weights.bin": bytes(range(256)) * 4,
            "docs/README.md": b"# Example delivery\n",
            "vendor/lib.zip": zip_bytes({"lib/a.py": b"A = 1\n", "lib/b.py": b"B = 2\n"}),
        },
    )
    (root / "empty").mkdir()
    return root


REQUEST = f"""\
apiVersion: superscrubber104/v1alpha1
kind: TransferRequest
metadata: {{id: TR-TEST-1, title: Test delivery}}
spec:
  purpose: test
  owner: {{name: Test Owner}}
  source: {SOURCE}
  destination: {ENCLAVE}
  direction: low-to-high
  stream: test-stream
  contents:
    - {{name: app, paths: ["app/**"]}}
    - {{name: model, paths: ["models/**"]}}
    - {{name: docs, paths: ["docs/**"]}}
    - {{name: vendor, paths: ["vendor/**"]}}
"""


@dataclass(frozen=True)
class Site:
    """Keys, policy and request for one pair of low and high sides."""

    root: Path
    pack_key: SigningKey
    receipt_key: SigningKey
    request: Path
    # Approver keys by name. The holder is the name up to the first "-", so "alice" and
    # "alice-backup" are two keys held by the same person.
    approvers: dict[str, SigningKey] = field(default_factory=dict)

    def policy(
        self,
        extra: str = "",
        *,
        signer_extra: str = "",
        approver_extra: str = "",
        enclave: str = ENCLAVE,
    ) -> Policy:
        """The receiving side's policy, pinning every key. ``extra`` is appended YAML."""
        keys = self.root / "keys"
        keys.mkdir(exist_ok=True)
        entries = []
        pinned = [
            ("pack", self.pack_key, "[pack, approve]", "packer", signer_extra),
            ("receipt", self.receipt_key, "[receipt]", "receipt-holder", ""),
            *(
                (name, key, "[approve]", name.split("-")[0], approver_extra)
                for name, key in self.approvers.items()
            ),
        ]
        for name, key, roles, holder, more in pinned:
            pem = key.verify_key.pem()
            (keys / f"{name}.pub").write_bytes(pem)
            entries.append(
                f'    - keyId: "{key.key_id}"\n'
                f"      publicKey: keys/{name}.pub\n"
                f'      sha256: "{hashlib.sha256(pem).hexdigest()}"\n'
                f"      holder: {holder}\n"
                f"      roles: {roles}\n" + more
            )
        text = (
            "apiVersion: superscrubber104/v1alpha1\nkind: Policy\n"
            'metadata: {name: test-import, version: "1"}\n'
            f"identity: {{enclave: {enclave}, acceptSources: [{SOURCE}]}}\n"
            "transfer: {maxBundleAge: 30d}\n"
            "trust:\n  signers:\n" + "".join(entries) + textwrap.dedent(extra)
        )
        path = self.root / f"policy-{hashlib.sha256(text.encode()).hexdigest()[:8]}.yaml"
        path.write_text(text, encoding="utf-8")
        return load_policy(path)


def make_site(root: Path) -> Site:
    root.mkdir(parents=True, exist_ok=True)
    request = root / "request.yaml"
    request.write_text(REQUEST, encoding="utf-8")
    approvers = {name: generate_key() for name in ("alice", "alice-backup", "bob")}
    return Site(root, generate_key(), generate_key(), request, approvers)


def failed(assessment: Assessment) -> dict[str, list[Finding]]:
    """Findings that are not passes, grouped by rule."""
    grouped: dict[str, list[Finding]] = {}
    for finding in assessment.findings:
        grouped.setdefault(finding.rule, []).append(finding)
    return grouped


def disposition(assessment: Assessment, rule: str) -> Disposition:
    """The single disposition of every finding of ``rule`` (asserts there is exactly one)."""
    ids = {f.id for f in assessment.findings if f.rule == rule}
    found = {d.disposition for d in assessment.decisions if d.finding in ids}
    assert len(found) == 1, f"{rule}: {found}"
    return found.pop()
