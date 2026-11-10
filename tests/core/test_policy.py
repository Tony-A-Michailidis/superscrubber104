import hashlib
import textwrap
from datetime import date, timedelta
from pathlib import Path

import pytest

from airlock.core.errors import ConfigError
from airlock.core.model import ArtifactRef, Disposition, Result, Severity, Subject, Unit, UnitKind
from airlock.core.policy import (
    AllowlistMode,
    KeyRole,
    LicencePolicy,
    Policy,
    UpstreamKeyType,
    load_policy,
)
from airlock.core.rules import FindingFactory
from tests.core.helpers import TOOL

EXAMPLES = Path(__file__).parents[2] / "examples"
TODAY = date(2026, 11, 10)
HEADER = """\
apiVersion: airlock/v1alpha1
kind: Policy
metadata: {name: test, version: "1"}
"""


def write_policy(tmp_path: Path, body: str, name: str = "policy.yaml") -> Path:
    path = tmp_path / name
    path.write_text(HEADER + textwrap.dedent(body), encoding="utf-8")
    return path


def pin(tmp_path: Path, name: str, content: bytes) -> str:
    target = tmp_path / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    return hashlib.sha256(content).hexdigest()


# --- Loading ------------------------------------------------------------------------------------


def test_example_policy_loads() -> None:
    policy = load_policy(EXAMPLES / "policy.yaml")
    assert policy.name == "example-import"
    assert policy.rules[1].approvals == 2
    assert policy.limits.archive.max_expanded_bytes == 500 * 2**30
    assert policy.limits.max_artifact_bytes == 2**40
    assert policy.plugins["clamav"].max_db_age == timedelta(days=7)
    assert policy.feed_max_age == {"default": timedelta(days=7), "kev": timedelta(days=2)}
    assert policy.allowlists["models"].mode is AllowlistMode.ENFORCE
    assert policy.control_overrides[0].controls == ("SC-7", "AC-4", "CM-6")
    assert policy.digest.startswith("sha256:")


def test_minimal_policy_uses_safe_defaults(tmp_path: Path) -> None:
    policy = load_policy(write_policy(tmp_path, ""))
    assert policy.defaults.severity[Severity.CRITICAL] is Disposition.BLOCK
    assert policy.defaults.not_assessed is Disposition.WARN
    assert policy.licences.unknown is Disposition.REQUIRE_APPROVAL
    assert policy.limits.archive.max_depth == 4


def test_trust_keys_are_pinned(tmp_path: Path) -> None:
    key_sha = pin(tmp_path, "keys/pack.pub", b"public key bytes")
    gpg_sha = pin(tmp_path, "keys/alma.asc", b"gpg key")
    body = f"""\
    trust:
      signers:
        - keyId: "ed25519:0123456789abcdef"
          publicKey: keys/pack.pub
          sha256: {key_sha}
          roles: [pack, approve]
      upstream:
        - name: almalinux-9
          type: gpg
          file: keys/alma.asc
          sha256: {gpg_sha}
          scope: [rpm, repomd]
    """
    policy = load_policy(write_policy(tmp_path, body))
    assert policy.signers[0].roles == {KeyRole.PACK, KeyRole.APPROVE}
    assert policy.signers_with_role(KeyRole.RECEIPT) == ()
    assert policy.upstream[0].type is UpstreamKeyType.GPG

    # The digest covers pinned files: same policy text, different key content => different digest
    # (after re-pinning), so swapping a key can never go unnoticed.
    other = tmp_path / "other"
    other.mkdir()
    key2 = pin(other, "keys/pack.pub", b"another key")
    gpg2 = pin(other, "keys/alma.asc", b"gpg key")
    body2 = body.replace(key_sha, key2).replace(gpg_sha, gpg2)
    assert load_policy(write_policy(other, body2)).digest != policy.digest


def test_pinned_file_mismatch(tmp_path: Path) -> None:
    pin(tmp_path, "keys/pack.pub", b"tampered")
    body = f"""\
    trust:
      signers:
        - keyId: "ed25519:0123456789abcdef"
          publicKey: keys/pack.pub
          sha256: "{"0" * 64}"
          roles: [pack]
    """
    with pytest.raises(ConfigError, match=r"trust\.signers\[0\]\.publicKey: pinned file"):
        load_policy(write_policy(tmp_path, body))


def test_pinned_file_missing(tmp_path: Path) -> None:
    body = f"""\
    allowlists:
      python: {{mode: enforce, file: allow/python.txt, sha256: "{"0" * 64}"}}
    """
    with pytest.raises(ConfigError, match="cannot read pinned file"):
        load_policy(write_policy(tmp_path, body))


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (
            "rules:\n  - rule: x.y\n    dispositon: block\n",
            r"rules\[0\]: unknown key\(s\): dispositon",
        ),
        ("rules:\n  - rule: x.y\n", r"rules\[0\]: a rule must set"),
        ("rules:\n  - rule: x.y\n    disposition: maybe\n", r"rules\[0\]\.disposition: 'maybe'"),
        ("rules:\n  - rule: x.y\n    disposition: block\n    approvals: 0\n", "at least 1"),
        ("defaults:\n  severity:\n    severe: block\n", r"defaults\.severity: unknown key"),
        ("defaults: {notAssessed: warn}\ndefaults: {notAssessed: block}\n", "duplicate key"),
        ("limits: {maxArtifactBytes: 12XB}\n", "expected a size"),
        ("plugins: {clamav: {maxDbAge: soon}}\n", "expected a duration"),
        ("extra: 1\n", "unknown key"),
        (f"plugins: {{clamav: {{binarySha256: {'1' * 64}}}}}\n", "quote hashes"),
        (
            "waivers:\n  - {id: W1, rule: a.b, subject: x, justification: j,"
            ' approvedBy: "ed25519:0123456789abcdef"}\n',
            "waivers must expire",
        ),
        (
            "waivers:\n  - {id: W1, rule: a.b, subject: x, justification: j,"
            " approvedBy: bob, expires: 2027-01-01}\n",
            r"approvedBy: expected a key id",
        ),
        ("licences: {allow: Apache-2.0}\n", "expected a list of strings"),
        ("controls: {overrides: {'a.*': SI-7}}\n", "expected a list of control ids"),
    ],
)
def test_invalid_policies(tmp_path: Path, body: str, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        load_policy(write_policy(tmp_path, body))


def test_wrong_kind_and_version(tmp_path: Path) -> None:
    path = tmp_path / "p.yaml"
    path.write_text(
        "apiVersion: airlock/v1alpha1\nkind: Request\nmetadata: {name: a, version: b}\n"
    )
    with pytest.raises(ConfigError, match="kind"):
        load_policy(path)
    path.write_text("apiVersion: airlock/v2\nkind: Policy\nmetadata: {name: a, version: b}\n")
    with pytest.raises(ConfigError, match="apiVersion"):
        load_policy(path)


def test_digest_changes_with_text(tmp_path: Path) -> None:
    a = load_policy(write_policy(tmp_path, "rules: []\n", "a.yaml"))
    b = load_policy(write_policy(tmp_path, "rules: []\n# comment\n", "b.yaml"))
    assert a.digest != b.digest


# --- Evaluation ---------------------------------------------------------------------------------

PT = Subject.of_artifact(ArtifactRef("models/x.pt"))
IMAGE = Subject.of_artifact(ArtifactRef("images/legacy.tar"))


@pytest.fixture
def policy(tmp_path: Path) -> Policy:
    body = """\
    defaults:
      approvals: 1
    rules:
      - rule: "malware.*"
        notAssessed: block
      - rule: "offline.*"
        paths: ["dev-tools/**"]
        disposition: warn
      - rule: "offline.*"
        disposition: block
      - rule: "container.*"
        disposition: require-approval
        approvals: 2
      - rule: "container.*"
        disposition: allow
    waivers:
      - id: W-1
        rule: container.user.root
        subject: images/legacy.tar
        sha256: "{sha}"
        justification: isolated namespace
        approvedBy: "ed25519:0123456789abcdef"
        expires: 2027-01-31
      - id: W-2
        rule: "container.*"
        subject: "images/old-*.tar"
        justification: expired exception
        approvedBy: "ed25519:0123456789abcdef"
        expires: 2026-01-31
    """.replace("{sha}", "c" * 64)
    return load_policy(write_policy(tmp_path, body))


def test_pass_is_always_allowed(policy: Policy, findings: FindingFactory) -> None:
    f = findings("malware.scan.detected", PT, Result.PASS, tool=TOOL)
    assert policy.decide(f, today=TODAY).matched == "pass"


def test_defaults_by_severity(policy: Policy, findings: FindingFactory) -> None:
    critical = findings("model.pickle.dangerous-import", PT, Result.FAIL, tool=TOOL)
    d = policy.decide(critical, today=TODAY)
    assert (d.disposition, d.matched) == (Disposition.BLOCK, "defaults.severity.critical")
    low = findings("document.metadata.author", PT, Result.FAIL, tool=TOOL)
    assert policy.decide(low, today=TODAY).disposition is Disposition.WARN


def test_rule_without_outcome_for_result_is_skipped(
    policy: Policy, findings: FindingFactory
) -> None:
    # rules[0] only sets notAssessed, so a FAIL falls through to the defaults
    na = findings("malware.scan.detected", PT, Result.NOT_ASSESSED, tool=TOOL, reason="absent")
    assert policy.decide(na, today=TODAY).matched == "rules[0]"
    fail = findings("malware.scan.detected", PT, Result.FAIL, tool=TOOL)
    assert policy.decide(fail, today=TODAY).matched == "defaults.severity.critical"
    err = findings("model.pickle.dangerous-import", PT, Result.ERROR, tool=TOOL)
    assert policy.decide(err, today=TODAY).matched == "defaults.error"


def test_first_match_wins_with_path_scope(policy: Policy, findings: FindingFactory) -> None:
    dev = Subject.of_artifact(ArtifactRef("dev-tools/ide/settings.json"))
    in_scope = findings("offline.telemetry.enabled", dev, Result.FAIL, tool=TOOL)
    out_of_scope = findings("offline.telemetry.enabled", PT, Result.FAIL, tool=TOOL)
    assert policy.decide(in_scope, today=TODAY).matched == "rules[1]"
    assert policy.decide(out_of_scope, today=TODAY).matched == "rules[2]"
    bundle = findings("offline.telemetry.enabled", Subject.bundle(), Result.FAIL, tool=TOOL)
    assert policy.decide(bundle, today=TODAY).matched == "rules[2]"


def test_unit_subjects_match_on_root(policy: Policy, findings: FindingFactory) -> None:
    unit = Subject.of_unit(Unit(UnitKind.CONTAINER_IMAGE, "x", "dev-tools/img"))
    f = findings("offline.telemetry.enabled", unit, Result.FAIL, tool=TOOL)
    assert policy.decide(f, today=TODAY).matched == "rules[1]"


def test_approvals(policy: Policy, findings: FindingFactory) -> None:
    other = Subject.of_artifact(ArtifactRef("images/app.tar"))
    f = findings("container.user.root", other, Result.FAIL, tool=TOOL)
    d = policy.decide(f, today=TODAY)
    assert (d.disposition, d.approvals_required) == (Disposition.REQUIRE_APPROVAL, 2)
    block = findings("model.pickle.dangerous-import", PT, Result.FAIL, tool=TOOL)
    assert policy.decide(block, today=TODAY).approvals_required == 0


def test_waiver_pinned_to_content(policy: Policy, findings: FindingFactory) -> None:
    f = findings("container.user.root", IMAGE, Result.FAIL, tool=TOOL)
    waived = policy.decide(f, today=TODAY, content_sha256="c" * 64)
    assert (waived.disposition, waived.waiver, waived.matched) == (
        Disposition.ALLOW,
        "W-1",
        "waivers[0]",
    )
    changed = policy.decide(f, today=TODAY, content_sha256="d" * 64)
    assert changed.waiver is None
    assert changed.matched == "rules[3]"
    after_expiry = policy.decide(f, today=date(2027, 2, 1), content_sha256="c" * 64)
    assert after_expiry.waiver is None


def test_expired_waivers(policy: Policy, findings: FindingFactory) -> None:
    assert [w.id for w in policy.expired_waivers(TODAY)] == ["W-2"]
    old = Subject.of_artifact(ArtifactRef("images/old-app.tar"))
    f = findings("container.user.root", old, Result.FAIL, tool=TOOL)
    assert policy.decide(f, today=TODAY).waiver is None


@pytest.mark.parametrize(
    ("licence", "expected"),
    [
        ("MIT", Disposition.ALLOW),
        ("LGPL-2.1-only", Disposition.REQUIRE_APPROVAL),
        ("AGPL-3.0-only", Disposition.BLOCK),
        ("LicenseRef-llama3.1", Disposition.REQUIRE_APPROVAL),
        ("WTFPL", Disposition.REQUIRE_APPROVAL),
        (None, Disposition.REQUIRE_APPROVAL),
    ],
)
def test_licences(licence: str | None, expected: Disposition) -> None:
    licences = load_policy(EXAMPLES / "policy.yaml").licences
    assert licences.decide(licence) is expected


def test_deny_wins_over_allow() -> None:
    licences = LicencePolicy(allow=("GPL-*",), deny=("GPL-3.0-*",))
    assert licences.decide("GPL-3.0-only") is Disposition.BLOCK
    assert licences.decide("GPL-2.0-only") is Disposition.ALLOW
