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
    assert "BLOCK   integrity.hash.mismatch" in output
    assert "BLOCK   integrity.entry.unexpected" in output
    assert "verdict: BLOCKED" in output
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
