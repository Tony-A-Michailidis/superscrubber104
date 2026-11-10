import hashlib
import re
import socket
from pathlib import Path

import pytest
from click.testing import CliRunner

from airlock import __version__
from airlock.cli import main
from tests.helpers import make_delivery


def run(*args: object) -> tuple[int, str]:
    result = CliRunner().invoke(main, [str(a) for a in args])
    return result.exit_code, result.output


def test_version_and_help() -> None:
    code, output = run("--version")
    assert code == 0
    assert __version__ in output
    code, output = run("--help")
    assert code == 0
    assert "air gap" in output
    for command in ("keygen", "pack", "verify"):
        assert command in output


def test_network_is_blocked_in_tests() -> None:
    with pytest.raises(RuntimeError, match="network"):
        socket.create_connection(("example.invalid", 443))


def test_keygen_pack_verify_and_exit_codes(tmp_path: Path) -> None:
    delivery = make_delivery(tmp_path / "delivery")
    keys, bundle, state = tmp_path / "keys", tmp_path / "bundle", tmp_path / "state"

    code, output = run("keygen", "-o", keys, "--name", "pack", "--holder", "ci")
    assert code == 0
    assert "key id: ed25519:" in output
    assert "holder: ci" in output
    code, output = run("keygen", "-o", keys, "--name", "pack")
    assert code == 2
    assert "refusing to overwrite" in output

    code, output = run("pack", delivery, "-o", bundle, "--key", keys / "pack.key")
    assert code == 0, output
    assert "verdict: PASSED" in output
    assert "signed by ed25519:" in output

    code, output = run("verify", bundle)
    assert code == 2
    assert "no trusted signer" in output

    code, output = run("verify", bundle, "--pubkey", keys / "pack.pub", "--state", state)
    assert code == 0, output
    assert "verdict: PASSED" in output
    assert "trust.signer.unpinned" in output
    assert "receipt.json" in output

    (bundle / "payload" / "models" / "tiny" / "weights.bin").write_bytes(b"swapped")
    (bundle / "payload" / "extra.bin").write_bytes(b"added")
    code, output = run("verify", bundle, "--pubkey", keys / "pack.pub", "--state", state)
    assert code == 3
    assert "REFUSE   integrity.hash.mismatch" in output
    assert "REFUSE   integrity.entry.unexpected" in output
    assert "verdict: REFUSED" in output
    assert output.isascii()


def test_encrypted_key_and_pinned_policy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    delivery = make_delivery(tmp_path / "delivery")
    keys, bundle = tmp_path / "keys", tmp_path / "bundle"
    monkeypatch.setenv("AIRLOCK_TEST_PASSPHRASE", "correct horse")
    code, output = run("keygen", "-o", keys, "--passphrase-env", "AIRLOCK_TEST_PASSPHRASE")
    assert code == 0
    snippet = output[output.index("trust:") :]

    code, output = run("pack", delivery, "-o", bundle, "--key", keys / "signing.key")
    assert code == 2  # the key is encrypted and no passphrase was given
    code, output = run(
        "pack", delivery, "-o", bundle, "--key", keys / "signing.key",
        "--passphrase-env", "AIRLOCK_TEST_PASSPHRASE",
    )  # fmt: skip
    assert code == 0, output

    # The snippet keygen prints is a working trust section.
    policy = keys / "policy.yaml"
    header = 'apiVersion: airlock/v1alpha1\nkind: Policy\nmetadata: {name: cli, version: "1"}\n'
    policy.write_text(header + snippet, encoding="utf-8")
    code, output = run("verify", bundle, "--policy", policy)
    assert code == 0, output
    assert "trust.signer.unpinned" not in output

    policy.write_text(header + "bogus: true\n", encoding="utf-8")
    code, output = run("verify", bundle, "--policy", policy, "--pubkey", keys / "signing.pub")
    assert code == 2
    assert "unknown key" in output


def test_approve_command_clears_a_finding(tmp_path: Path) -> None:
    delivery = make_delivery(tmp_path / "delivery")
    keys, bundle, out = tmp_path / "keys", tmp_path / "bundle", tmp_path / "out"
    key_ids = {}
    for name in ("pack", "reviewer"):
        code, output = run("keygen", "-o", keys, "--name", name)
        assert code == 0
        key_ids[name] = re.search(r"key id: (ed25519:[0-9a-f]{64})", output).group(1)

    signers = "".join(
        f'    - keyId: "{key_ids[name]}"\n'
        f"      publicKey: {name}.pub\n"
        f'      sha256: "{hashlib.sha256((keys / (name + ".pub")).read_bytes()).hexdigest()}"\n'
        f"      holder: {name}\n"
        f"      roles: [{role}]\n"
        for name, role in (("pack", "pack"), ("reviewer", "approve"))
    )
    policy = keys / "policy.yaml"
    policy.write_text(
        'apiVersion: airlock/v1alpha1\nkind: Policy\nmetadata: {name: cli, version: "1"}\n'
        "trust:\n  signers:\n" + signers + "rules:\n"
        '  - {rule: inventory.artifact.unclassified, paths: ["docs/**"],'
        " disposition: require-approval}\n",
        encoding="utf-8",
    )
    assert run("pack", delivery, "-o", bundle, "--key", keys / "pack.key")[0] == 0

    code, output = run("verify", bundle, "--policy", policy, "--out", out)
    assert code == 1
    assert "verdict: NEEDS-APPROVAL" in output
    finding = re.search(r"APPROVE  inventory\.artifact\.unclassified  \[([0-9a-f]{16})\]", output)
    assert finding is not None
    reviewed = ("--assessment", out / "assessment.verify.json", "-f", finding.group(1))

    code, output = run("approve", bundle, "--key", keys / "pack.key", "-j", "ok", *reviewed)
    assert code == 2
    assert "packer cannot approve" in output

    code, output = run(
        "approve", bundle, "--key", keys / "reviewer.key", *reviewed,
        "-j", "Plain project README; read in full.",
    )  # fmt: skip
    assert code == 0, output
    assert f"approved [{finding.group(1)}]" in output

    code, output = run("verify", bundle, "--policy", policy)
    assert code == 0, output
    assert "APPROVED inventory.artifact.unclassified" in output
    assert "approvals: 1 of 1 (reviewer)" in output
    assert "verdict: PASSED" in output
