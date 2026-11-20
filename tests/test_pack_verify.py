"""End to end: pack on one side, verify on the other, and every way the two can disagree."""

import base64
import json
import shutil
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from airlock import bundle as layout
from airlock.core.errors import ConfigError
from airlock.core.model import Disposition, Result, Verdict
from airlock.core.policy import ArchiveLimits, Limits, Policy
from airlock.core.signing import generate_key
from airlock.pack import PackResult, pack
from airlock.session import EXIT_BLOCKED, EXIT_OK, EXIT_REFUSED, exit_code
from airlock.verify import VerifyResult, verify
from tests.helpers import NOW, Site, disposition, failed, make_delivery, make_site, zip_bytes

MIB = 2**20


@pytest.fixture
def site(tmp_path: Path) -> Site:
    return make_site(tmp_path / "site")


@pytest.fixture
def delivery(tmp_path: Path) -> Path:
    return make_delivery(tmp_path / "delivery")


def do_pack(
    site: Site,
    delivery: Path,
    out: Path,
    *,
    request: bool = True,
    policy: Policy | None = None,
    now: datetime = NOW,
    chunk_size: int = 64,
    bundle_id: str | None = None,
) -> PackResult:
    return pack(
        [delivery],
        out,
        signer=site.pack_key,
        policy=policy or Policy.default(),
        request_path=site.request if request else None,
        now=now,
        chunk_size=chunk_size,
        bundle_id=bundle_id,
    )


def do_verify(
    site: Site,
    bundle: Path,
    *,
    policy: Policy | None = None,
    state: Path | None = None,
    now: datetime | None = None,
) -> VerifyResult:
    return verify(
        bundle,
        policy=policy or site.policy(),
        state=state,
        receipt_signer=site.receipt_key if state else None,
        now=now or NOW + timedelta(hours=1),
    )


@pytest.fixture
def bundle(site: Site, delivery: Path, tmp_path: Path) -> Path:
    result = do_pack(site, delivery, tmp_path / "bundle")
    assert result.signed
    return result.bundle


# --- the normal path ----------------------------------------------------------------------------


def test_pack_then_verify_is_accepted(site: Site, bundle: Path, tmp_path: Path) -> None:
    # a single-volume bundle: everything but the volume index and volumes
    assert {p.name for p in bundle.iterdir()} == layout.BUNDLE_FILES - {
        layout.VOLUMES,
        layout.VOLUME_DIR,
    }
    assert (bundle / "payload/models/tiny/weights.bin").read_bytes() == bytes(range(256)) * 4
    assert (bundle / "payload/empty").is_dir()

    result = do_verify(site, bundle, state=tmp_path / "state")
    assert result.assessment.summary.verdict is Verdict.PASSED
    assert exit_code(result.assessment) == EXIT_OK
    assert not [
        f
        for f in result.assessment.findings
        if f.result is Result.FAIL and f.rule != "inventory.artifact.unclassified"
    ]
    receipt = result.receipt
    assert receipt is not None
    assert receipt.accepted
    assert receipt.enclave == "enclave-b"
    assert receipt.verifier_key_id == site.receipt_key.key_id
    assert [p.name for p in result.outputs] == [
        "assessment.verify.json",
        "analysis.verify.json",  # this side's own analysis, for airlock report
        "request.yaml",
        "receipt.dsse.json",
    ]
    assert (tmp_path / "state" / "ledger.jsonl").read_bytes().count(b"\n") == 1


def test_manifest_is_reproducible_and_says_nothing_about_the_run(
    site: Site, delivery: Path, tmp_path: Path
) -> None:
    first = do_pack(site, delivery, tmp_path / "b1")
    later = do_pack(site, delivery, tmp_path / "b2", request=False, now=NOW + timedelta(days=3))
    assert first.manifest_digest == later.manifest_digest
    assert (tmp_path / "b1/manifest.json").read_bytes() == (
        tmp_path / "b2/manifest.json"
    ).read_bytes()
    assert (tmp_path / "b1/statement.dsse.json").read_bytes() != (
        tmp_path / "b2/statement.dsse.json"
    ).read_bytes()
    manifest = json.loads((tmp_path / "b1/manifest.json").read_bytes())
    assert [e["path"] for e in manifest["entries"]] == sorted(
        e["path"] for e in manifest["entries"]
    )
    weights = next(e for e in manifest["entries"] if e["path"] == "models/tiny/weights.bin")
    assert len(weights["chunks"]) == 16  # 1024 bytes in 64-byte chunks


def test_analysis_looks_inside_archives(bundle: Path) -> None:
    analysis = json.loads((bundle / "analysis.json").read_bytes())
    by_ref = {"!/".join([a["ref"]["path"], *a["ref"]["member"]]): a for a in analysis["artifacts"]}
    assert by_ref["vendor/lib.zip"]["kinds"] == ["archive.zip"]
    assert by_ref["vendor/lib.zip!/lib/a.py"]["mediaType"] == "text/plain"
    assert by_ref["app/main.py"]["kinds"] == ["source.python"]
    assert by_ref["docs/README.md"]["kinds"] == ["unclassified"]


def test_output_must_be_new_and_outside_the_inputs(
    site: Site, delivery: Path, tmp_path: Path
) -> None:
    (tmp_path / "taken").mkdir()
    (tmp_path / "taken" / "file").write_text("x")
    with pytest.raises(ConfigError, match="new or empty"):
        do_pack(site, delivery, tmp_path / "taken")
    with pytest.raises(ConfigError, match="inside input"):
        do_pack(site, delivery, delivery / "out")
    with pytest.raises(ConfigError, match="not an airlock bundle"):
        do_verify(site, delivery)


# --- tampering ----------------------------------------------------------------------------------


def test_modified_file_is_caught_and_located(site: Site, bundle: Path) -> None:
    target = bundle / "payload/models/tiny/weights.bin"
    data = bytearray(target.read_bytes())
    data[200] ^= 0xFF  # one bit-flipped byte, in the fourth 64-byte chunk
    target.write_bytes(bytes(data))

    result = do_verify(site, bundle)
    finding = failed(result.assessment)["integrity.hash.mismatch"][0]
    assert finding.subject.display == "models/tiny/weights.bin"
    assert finding.detail["damagedChunks"] == [3]
    assert disposition(result.assessment, "integrity.hash.mismatch") is Disposition.BLOCK
    assert exit_code(result.assessment) == EXIT_REFUSED


def test_added_removed_and_truncated_content(site: Site, bundle: Path) -> None:
    (bundle / "payload/app/backdoor.py").write_text("import os")
    (bundle / "payload/docs/README.md").unlink()
    (bundle / "payload/empty").rmdir()
    (bundle / "payload/app/main.py").write_bytes(b"")
    (bundle / "notes.txt").write_text("left in the bundle root")

    found = failed(do_verify(site, bundle).assessment)
    unexpected = {f.subject.display for f in found["integrity.entry.unexpected"]}
    assert unexpected == {"app/backdoor.py", "bundle"}
    missing = {f.subject.display for f in found["integrity.entry.missing"]}
    assert missing == {"docs/README.md", "empty"}
    assert found["integrity.hash.mismatch"][0].detail["actualSize"] == 0


def test_tampering_cannot_be_excused_by_policy(site: Site, bundle: Path) -> None:
    (bundle / "payload/app/main.py").write_text("print('changed')")
    lenient = site.policy(
        f"""
        defaults: {{severity: {{critical: allow, high: allow}}}}
        rules:
          - {{rule: "integrity.*", disposition: allow}}
        waivers:
          - id: W-1
            rule: integrity.hash.mismatch
            subject: app/main.py
            justification: please
            approvedBy: "{site.pack_key.key_id}"
            expires: 2030-01-01
        """
    )
    result = do_verify(site, bundle, policy=lenient)
    assert disposition(result.assessment, "integrity.hash.mismatch") is Disposition.BLOCK
    assert exit_code(result.assessment) == EXIT_REFUSED


@pytest.mark.parametrize(
    "name", [layout.MANIFEST, layout.ANALYSIS, layout.ASSESSMENT, layout.REQUEST]
)
def test_modified_control_files(site: Site, bundle: Path, name: str) -> None:
    with (bundle / name).open("ab") as stream:
        stream.write(b" ")
    result = do_verify(site, bundle)
    [finding] = failed(result.assessment)["integrity.statement.subject-mismatch"]
    assert finding.detail["file"] == name
    assert exit_code(result.assessment) == EXIT_REFUSED
    if name == layout.MANIFEST:  # without a trusted manifest, content checks say so
        assert failed(result.assessment)["integrity.hash.mismatch"][0].result is Result.NOT_ASSESSED


def test_statement_edited_after_signing(site: Site, bundle: Path) -> None:
    path = bundle / layout.STATEMENT
    envelope = json.loads(path.read_bytes())
    statement = json.loads(base64.b64decode(envelope["payload"]))
    statement["predicate"]["destination"] = "somewhere-else"
    envelope["payload"] = base64.b64encode(json.dumps(statement).encode()).decode()
    path.write_text(json.dumps(envelope))
    found = failed(do_verify(site, bundle).assessment)
    assert found["integrity.signature.invalid"][0].result is Result.FAIL
    assert found["integrity.signature.untrusted-key"][0].result is Result.FAIL
    # Nothing in an unauthenticated statement is acted on.
    assert "transfer.destination.mismatch" not in found


def test_missing_or_garbled_statement(site: Site, bundle: Path) -> None:
    (bundle / layout.STATEMENT).write_text("{not json")
    result = do_verify(site, bundle)
    assert "integrity.bundle.malformed" in failed(result.assessment)
    assert exit_code(result.assessment) == EXIT_REFUSED
    assert result.receipt is None


def test_repacked_by_someone_else(site: Site, delivery: Path, tmp_path: Path) -> None:
    """An attacker can always build a self-consistent bundle. Only the pinned key stops it."""
    attacker = replace(site, pack_key=generate_key())
    forged = do_pack(attacker, delivery, tmp_path / "forged").bundle
    result = do_verify(site, forged)
    [finding] = failed(result.assessment)["integrity.signature.untrusted-key"]
    assert finding.detail["signedBy"] == [attacker.pack_key.key_id]
    assert exit_code(result.assessment) == EXIT_REFUSED
    assert result.provenance is None


@pytest.mark.parametrize(
    ("signer_extra", "reason"),
    [
        ("      revoked: true\n", "revoked"),
        ("      validUntil: 2026-01-01\n", "expired"),
        ("      validFrom: 2027-01-01\n", "not valid before"),
        ("      sources: [another-network]\n", "may not sign for source"),
    ],
)
def test_pinned_key_that_must_not_be_relied_on(
    site: Site, bundle: Path, signer_extra: str, reason: str
) -> None:
    result = do_verify(site, bundle, policy=site.policy(signer_extra=signer_extra))
    [finding] = failed(result.assessment)["integrity.signature.untrusted-key"]
    assert reason in str(finding.detail["reasons"])
    assert exit_code(result.assessment) == EXIT_REFUSED


def test_command_line_key(site: Site, bundle: Path) -> None:
    result = verify(bundle, policy=Policy.default(), pubkey=site.pack_key.verify_key, now=NOW)
    assert result.assessment.summary.verdict is Verdict.PASSED
    assert disposition(result.assessment, "trust.signer.unpinned") is Disposition.WARN
    other = verify(bundle, policy=Policy.default(), pubkey=generate_key().verify_key, now=NOW)
    assert exit_code(other.assessment) == EXIT_REFUSED
    with pytest.raises(ConfigError, match="pins its own pack signers"):
        verify(bundle, policy=site.policy(), pubkey=site.pack_key.verify_key, now=NOW)


def test_custody_log_must_belong_to_this_bundle(
    site: Site, delivery: Path, bundle: Path, tmp_path: Path
) -> None:
    other = do_pack(site, delivery, tmp_path / "other", now=NOW + timedelta(minutes=5)).bundle
    shutil.copy(other / layout.CUSTODY, bundle / layout.CUSTODY)
    [finding] = failed(do_verify(site, bundle).assessment)["integrity.custody.broken"]
    assert "not the 'packed' event for this bundle" in str(finding.detail["problems"])

    (bundle / layout.CUSTODY).unlink()
    result = do_verify(site, bundle)
    assert "missing or empty" in str(
        failed(result.assessment)["integrity.custody.broken"][0].detail
    )
    assert exit_code(result.assessment) == EXIT_REFUSED


# --- the right bundle, in the right place, at the right time ------------------------------------


def test_bundle_for_another_enclave(site: Site, bundle: Path) -> None:
    result = do_verify(site, bundle, policy=site.policy(enclave="enclave-a"))
    assert disposition(result.assessment, "transfer.destination.mismatch") is Disposition.BLOCK
    assert result.assessment.summary.verdict is Verdict.REFUSED
    assert exit_code(result.assessment) == EXIT_REFUSED


def test_unaccepted_source_and_unbound_destination(
    site: Site, delivery: Path, bundle: Path, tmp_path: Path
) -> None:
    picky = site.policy().identity
    assert picky is not None
    policy = replace(site.policy(), identity=replace(picky, accept_sources=("prod-build",)))
    assert "transfer.source.unaccepted" in failed(do_verify(site, bundle, policy=policy).assessment)

    anonymous = do_pack(site, delivery, tmp_path / "anon", request=False).bundle
    result = do_verify(site, anonymous)
    # A bundle bound to no enclave could be imported anywhere, so this one is refused here.
    assert disposition(result.assessment, "transfer.destination.unbound") is Disposition.BLOCK
    assert result.assessment.summary.verdict is Verdict.REFUSED
    # A bundle that names no source cannot be from an accepted one either.
    assert disposition(result.assessment, "transfer.source.unaccepted") is Disposition.BLOCK


def test_stale_bundle(site: Site, bundle: Path) -> None:
    result = do_verify(site, bundle, now=NOW + timedelta(days=31))
    assert disposition(result.assessment, "replay.bundle.expired") is Disposition.BLOCK
    assert exit_code(result.assessment) == EXIT_REFUSED


def test_replay_and_out_of_order(site: Site, delivery: Path, tmp_path: Path) -> None:
    state = tmp_path / "state"
    monday = do_pack(site, delivery, tmp_path / "monday", now=NOW).bundle
    tuesday = do_pack(site, delivery, tmp_path / "tuesday", now=NOW + timedelta(days=1)).bundle

    first = do_verify(site, tuesday, state=state, now=NOW + timedelta(days=2))
    assert first.assessment.summary.verdict is Verdict.PASSED

    replayed = do_verify(site, tuesday, state=state, now=NOW + timedelta(days=3))
    [again] = failed(replayed.assessment)["replay.bundle.already-accepted"]
    assert again.detail["statement"] == "identical"
    assert "replay.bundle.id-reused" not in failed(replayed.assessment)
    assert replayed.assessment.summary.verdict is Verdict.REFUSED

    older = do_verify(site, monday, state=state, now=NOW + timedelta(days=4))
    assert "replay.bundle.out-of-order" in failed(older.assessment)
    assert "replay.bundle.already-accepted" not in failed(older.assessment)
    assert exit_code(older.assessment) == EXIT_REFUSED

    ledger = (state / "ledger.jsonl").read_bytes().splitlines()
    assert len(ledger) == 3  # every verification is recorded, whatever the verdict
    assert [json.loads(line)["data"]["verdict"] for line in ledger] == [
        "passed",
        "refused",
        "refused",
    ]


def test_a_different_bundle_reusing_an_accepted_id(
    site: Site, delivery: Path, tmp_path: Path
) -> None:
    state = tmp_path / "state"
    first = do_pack(site, delivery, tmp_path / "a", bundle_id="1" * 32).bundle
    (delivery / "extra.txt").write_text("a later change\n")
    second = do_pack(
        site, delivery, tmp_path / "b", bundle_id="1" * 32, now=NOW + timedelta(hours=1)
    ).bundle
    assert do_verify(site, first, state=state).assessment.summary.verdict is Verdict.PASSED
    result = do_verify(site, second, state=state, now=NOW + timedelta(hours=2))
    [reused] = failed(result.assessment)["replay.bundle.id-reused"]
    assert reused.detail["statement"] != reused.detail["acceptedStatement"]
    assert "replay.bundle.already-accepted" not in failed(result.assessment)
    assert result.assessment.summary.verdict is Verdict.REFUSED


def test_a_check_that_did_not_run_never_reads_as_a_finding(site: Site, bundle: Path) -> None:
    from airlock.summary import render

    text = render(do_verify(site, bundle).assessment)
    assert "not assessed: malware.detected" in text
    assert "the check did not run: no malware scanner is configured" in text
    assert "Malware scanner reports a detection" not in text


def test_without_state_replay_checks_are_reported_as_not_assessed(site: Site, bundle: Path) -> None:
    found = failed(do_verify(site, bundle).assessment)
    assert found["replay.bundle.already-accepted"][0].result is Result.NOT_ASSESSED
    assert "state directory" in (found["replay.bundle.out-of-order"][0].not_assessed_reason or "")


def test_clock_regression_ledger_tampering_and_policy_change(
    site: Site, delivery: Path, bundle: Path, tmp_path: Path
) -> None:
    state = tmp_path / "state"
    do_verify(site, bundle, state=state, now=NOW + timedelta(days=2))
    second = do_pack(site, delivery, tmp_path / "second", now=NOW + timedelta(days=1)).bundle

    back_in_time = do_verify(site, second, state=state, now=NOW + timedelta(days=1, hours=1))
    assert "replay.clock.regression" in failed(back_in_time.assessment)

    changed = site.policy("limits: {maxPathLength: 500}\n")
    result = do_verify(site, second, state=state, policy=changed, now=NOW + timedelta(days=5))
    [finding] = failed(result.assessment)["policy.digest.changed"]
    assert finding.detail["current"] == changed.digest
    assert disposition(result.assessment, "policy.digest.changed") is Disposition.ALLOW

    ledger = state / "ledger.jsonl"
    ledger.write_bytes(ledger.read_bytes().replace(b'"passed"', b'"blocked"', 1))
    third = do_pack(site, delivery, tmp_path / "third", now=NOW + timedelta(days=6)).bundle
    result = do_verify(site, third, state=state, now=NOW + timedelta(days=7))
    assert "integrity.ledger.broken" in failed(result.assessment)
    assert exit_code(result.assessment) == EXIT_REFUSED


# --- what the request and the content allow -----------------------------------------------------


def test_undeclared_and_missing_content(site: Site, delivery: Path, tmp_path: Path) -> None:
    (delivery / "surprise.bin").write_bytes(b"not in the request")
    result = do_pack(site, delivery, tmp_path / "b1")
    [finding] = failed(result.assessment)["request.artifact.undeclared"]
    assert finding.subject.display == "surprise.bin"
    assert result.assessment.summary.verdict is Verdict.NEEDS_APPROVAL
    assert result.signed  # approval is the receiving side's call; the bundle can still travel
    assert exit_code(result.assessment) == EXIT_BLOCKED
    verified = do_verify(site, result.bundle)
    assert "request.artifact.undeclared" in failed(verified.assessment)

    (delivery / "surprise.bin").unlink()
    shutil.rmtree(delivery / "docs")
    result = do_pack(site, delivery, tmp_path / "b2")
    [finding] = failed(result.assessment)["request.content.missing"]
    assert finding.detail["content"] == "docs"
    assert result.assessment.summary.verdict is Verdict.BLOCKED


def test_policy_blockers_do_not_stop_the_bundle_from_being_signed(
    site: Site, delivery: Path, tmp_path: Path
) -> None:
    """Whether to override a policy blocker is for approvers and the receiving side."""
    (delivery / "vendor/evil.zip").write_bytes(zip_bytes({"../../../etc/cron.d/x": b"* * * * *"}))
    result = do_pack(site, delivery, tmp_path / "bundle")
    assert disposition(result.assessment, "archive.member.path-traversal") is Disposition.BLOCK
    assert result.assessment.summary.verdict is Verdict.BLOCKED
    assert result.signed
    assert exit_code(result.assessment) == EXIT_BLOCKED
    verified = do_verify(site, result.bundle)
    assert verified.assessment.summary.verdict is Verdict.BLOCKED
    assert exit_code(verified.assessment) == EXIT_BLOCKED


def test_receiving_side_applies_its_own_limits(site: Site, delivery: Path, tmp_path: Path) -> None:
    """A bomb the packer's policy let through is still stopped by the receiver's policy."""
    (delivery / "vendor/data.zip").write_bytes(zip_bytes({"zeros.bin": bytes(8 * MIB)}))
    lax = replace(Policy.default(), limits=Limits(archive=ArchiveLimits(max_ratio=10**6)))
    packed = do_pack(site, delivery, tmp_path / "bundle", policy=lax)
    assert packed.signed
    assert "archive.limit.ratio" not in failed(packed.assessment)

    strict = site.policy("limits: {archive: {maxRatio: 50, ratioMinBytes: 1MiB}}\n")
    result = do_verify(site, packed.bundle, policy=strict)
    [finding] = failed(result.assessment)["archive.limit.ratio"]
    assert finding.subject.display == "vendor/data.zip"
    assert result.assessment.summary.verdict is Verdict.BLOCKED
    assert exit_code(result.assessment) == EXIT_BLOCKED


def test_expired_waiver_is_reported(site: Site, bundle: Path) -> None:
    policy = site.policy(
        f"""
        waivers:
          - id: W-OLD
            rule: request.artifact.undeclared
            subject: old.bin
            justification: was needed once
            approvedBy: "{site.pack_key.key_id}"
            expires: 2026-01-01
        """
    )
    [finding] = failed(do_verify(site, bundle, policy=policy).assessment)["policy.waiver.expired"]
    assert finding.detail["waiver"] == "W-OLD"


def test_unrepresentable_file_name_blocks_the_pack(
    site: Site, delivery: Path, tmp_path: Path
) -> None:
    """A name that is not NFC would not survive every filesystem, so it cannot be tracked."""
    decomposed = "re" + chr(0x301) + "sume" + chr(0x301) + ".txt"  # 'e' + combining acute accent
    (delivery / "docs" / decomposed).write_bytes(b"x")
    result = do_pack(site, delivery, tmp_path / "bundle")
    [finding] = failed(result.assessment)["path.name.unsafe"]
    assert finding.subject.display == "docs/re%CC%81sume%CC%81.txt"
    assert disposition(result.assessment, "path.name.unsafe") is Disposition.BLOCK
    assert result.assessment.summary.verdict is Verdict.REFUSED
    assert not result.signed  # nothing to transfer, and nothing an approval could fix
    assert not (result.bundle / layout.STATEMENT).exists()
    assert (result.bundle / layout.ASSESSMENT).exists()  # the findings can still be reviewed
    assert exit_code(result.assessment) == EXIT_REFUSED
    assert exit_code(do_verify(site, result.bundle).assessment) == EXIT_REFUSED
    manifest = json.loads((result.bundle / "manifest.json").read_bytes())
    assert all("sume" not in e["path"] for e in manifest["entries"])
    analysis = json.loads((result.bundle / "analysis.json").read_bytes())
    assert any(a["ref"]["unsafe"] for a in analysis["artifacts"])  # recorded, not silently dropped
