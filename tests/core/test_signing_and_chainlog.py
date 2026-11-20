import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from superscrubber104.core import chainlog
from superscrubber104.core.signing import (
    Envelope,
    SigningError,
    VerifyKey,
    generate_key,
    load_signing_key,
    load_verify_key,
    pae,
    save_key,
    sign_envelope,
)

NOW = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)


def test_key_round_trip_and_id(tmp_path: Path) -> None:
    key = generate_key()
    assert key.key_id.startswith("ed25519:")
    assert len(key.key_id) == len("ed25519:") + 64  # full fingerprint, never truncated
    save_key(key, tmp_path / "k.key", tmp_path / "k.pub", None)
    assert load_signing_key(tmp_path / "k.key").key_id == key.key_id
    assert load_verify_key(tmp_path / "k.pub").key_id == key.key_id
    with pytest.raises(SigningError, match="overwrite"):
        save_key(key, tmp_path / "k.key", tmp_path / "other.pub", None)


def test_encrypted_private_key(tmp_path: Path) -> None:
    key = generate_key()
    save_key(key, tmp_path / "k.key", tmp_path / "k.pub", b"correct horse")
    assert b"ENCRYPTED" in (tmp_path / "k.key").read_bytes()
    assert load_signing_key(tmp_path / "k.key", b"correct horse").key_id == key.key_id
    with pytest.raises(SigningError):
        load_signing_key(tmp_path / "k.key")
    with pytest.raises(SigningError):
        load_signing_key(tmp_path / "k.key", b"wrong")


def test_bad_key_files(tmp_path: Path) -> None:
    (tmp_path / "junk.pub").write_text("not a key")
    with pytest.raises(SigningError):
        load_verify_key(tmp_path / "junk.pub")
    with pytest.raises(SigningError):
        load_verify_key(tmp_path / "missing.pub")


def test_pae_matches_the_dsse_specification() -> None:
    # Test vector from the DSSE protocol document.
    assert pae("http://example.com/HelloWorld", b"hello world") == (
        b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
    )


def test_envelope_sign_verify_and_tamper() -> None:
    alice, bob, mallory = generate_key(), generate_key(), generate_key()
    known = {k.key_id: k.verify_key for k in (alice, bob)}
    envelope = sign_envelope("application/x-test", b"payload", alice, mallory)
    restored = Envelope.from_data(json.loads(json.dumps(envelope.to_data())))
    assert restored == envelope
    assert restored.verified_by(known.get) == ([alice.key_id], [])  # mallory is simply unknown

    tampered = Envelope("application/x-test", b"payloae", envelope.signatures)
    assert tampered.verified_by(known.get) == ([], [alice.key_id])
    retyped = Envelope("application/x-other", b"payload", envelope.signatures)
    assert retyped.verified_by(known.get) == ([], [alice.key_id])


@pytest.mark.parametrize(
    "data",
    [
        [],
        {"payloadType": "t", "payload": "!!!", "signatures": []},
        {"payloadType": "t", "payload": "", "signatures": [{"keyid": "k"}]},
        {"payload": "", "signatures": []},
        {"payloadType": 1, "payload": "", "signatures": []},
    ],
)
def test_malformed_envelopes(data: object) -> None:
    with pytest.raises(SigningError):
        Envelope.from_data(data)


# --- chained log --------------------------------------------------------------------------------


def _log(path: Path, count: int = 3) -> tuple[dict[str, VerifyKey], list[chainlog.Event]]:
    key = generate_key()
    for index in range(count):
        chainlog.append(path, "note", {"n": index}, now=NOW + timedelta(minutes=index), signer=key)
    return {key.key_id: key.verify_key}, chainlog.read(path)


def test_chain_appends_and_verifies(tmp_path: Path) -> None:
    keys, events = _log(tmp_path / "log.jsonl")
    assert [e.seq for e in events] == [1, 2, 3]
    assert events[0].prev is None
    assert events[1].prev == events[0].digest
    check = chainlog.verify(events, keys.get)
    assert check.problems() == []
    assert list(check.verified) == events
    assert chainlog.read(tmp_path / "absent.jsonl") == []


def _rewrite(path: Path, index: int, **changes: object) -> None:
    lines = path.read_bytes().splitlines()
    event = json.loads(lines[index])
    event.update(changes)
    lines[index] = json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
    path.write_bytes(b"\n".join(lines) + b"\n")


def test_edited_event_breaks_signature_and_chain(tmp_path: Path) -> None:
    path = tmp_path / "log.jsonl"
    keys, _ = _log(path)
    _rewrite(path, 0, data={"n": 99})
    problems = chainlog.verify(chainlog.read(path), keys.get).problems()
    assert any("event 1" in p and "invalid signature" in p for p in problems)
    assert any("event 2" in p and "chain" in p for p in problems)


def test_removed_and_reordered_events_are_detected(tmp_path: Path) -> None:
    path = tmp_path / "log.jsonl"
    keys, _ = _log(path)
    lines = path.read_bytes().splitlines()
    path.write_bytes(b"\n".join([lines[0], lines[2]]) + b"\n")
    assert chainlog.verify(chainlog.read(path), keys.get).broken
    path.write_bytes(b"\n".join([lines[1], lines[0], lines[2]]) + b"\n")
    assert chainlog.verify(chainlog.read(path), keys.get).broken


def test_unknown_and_missing_signatures(tmp_path: Path) -> None:
    path = tmp_path / "log.jsonl"
    _, events = _log(path, 1)
    check = chainlog.verify(events, lambda _key_id: None)
    assert "untrusted key" in check.problems()[0]
    # In a log that others may append to, an unknown signer is not damage.
    assert check.problems(allow_unknown=True) == []
    assert list(check.unknown) == events
    assert check.verified == ()

    unsigned = tmp_path / "unsigned.jsonl"
    chainlog.append(unsigned, "note", {}, now=NOW, signer=None)
    events = chainlog.read(unsigned)
    check = chainlog.verify(events, lambda _key_id: None)
    assert "not signed" in check.problems()[0]
    assert check.problems(require_signed=False) == []


def test_swapped_signature_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "log.jsonl"
    keys, events = _log(path, 2)
    assert events[1].sig is not None
    _rewrite(path, 0, sig=base64.b64encode(events[1].sig).decode())
    assert chainlog.verify(chainlog.read(path), keys.get).broken


def test_garbage_is_not_a_log(tmp_path: Path) -> None:
    path = tmp_path / "log.jsonl"
    path.write_text('{"seq": 1}\n')
    with pytest.raises(chainlog.ChainError):
        chainlog.read(path)
