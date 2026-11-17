import hashlib
import textwrap
from datetime import date, timedelta
from pathlib import Path

import pytest

from airlock.core.errors import ConfigError
from airlock.core.model import (
    ArtifactRef,
    Disposition,
    Result,
    Severity,
    Subject,
    TrustLevel,
    Unit,
    UnitKind,
)
from airlock.core.policy import (
    AllowlistMode,
    KeyRole,
    LicencePolicy,
    Policy,
    UpstreamKeyType,
    evaluate,
    load_policy,
)
from airlock.core.rules import FindingFactory, RuleRegistry
from airlock.core.signing import generate_key
from tests.core.helpers import KEY_ID, TOOL

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


def signer_block(tmp_path: Path, name: str = "pack", extra: str = "") -> tuple[str, str]:
    """A trust.signers entry for a freshly generated key. Returns (yaml, key id)."""
    key = generate_key()
    sha = pin(tmp_path, f"keys/{name}.pub", key.verify_key.pem())
    block = f"""\
        - keyId: "{key.key_id}"
          publicKey: keys/{name}.pub
          sha256: "{sha}"
          holder: {name}-holder
          roles: [pack, approve]
          {extra}
    """
    return block, key.key_id


# --- Loading ------------------------------------------------------------------------------------


def test_example_policy_loads() -> None:
    policy = load_policy(EXAMPLES / "policy.yaml")
    assert policy.name == "example-import"
    assert policy.identity is not None
    assert policy.identity.enclave == "enclave-b"
    assert policy.identity.accept_sources == ("dev-unclass",)
    assert policy.max_bundle_age == timedelta(days=30)
    assert policy.rules[1].approvals == 2
    assert policy.defaults.override_approvals == 2
    assert policy.clock_tolerance == timedelta(minutes=10)
    assert policy.rules[0].overridable
    assert policy.rules[3].where == {"kev": "true"}
    assert policy.limits.archive.max_expanded_bytes == 500 * 2**30
    assert policy.limits.archive.ratio_min_bytes == 16 * 2**20
    assert policy.limits.max_artifact_bytes == 2**40
    assert policy.plugins["clamav"].max_db_age == timedelta(days=7)
    assert policy.feed_max_age == {"default": timedelta(days=7), "kev": timedelta(days=2)}
    assert policy.allowlists["models"].mode is AllowlistMode.ENFORCE
    assert policy.control_overrides[0].controls == ("SC-7", "AC-4", "CM-6")
    assert policy.digest.startswith("sha256:")
    assert policy.catalog().framework == "nist-800-53r5"


def test_default_policy_is_safe() -> None:
    policy = Policy.default()
    assert policy.defaults.severity[Severity.CRITICAL] is Disposition.BLOCK
    assert policy.defaults.not_assessed is Disposition.WARN
    assert policy.licences.unknown is Disposition.REQUIRE_APPROVAL
    assert policy.limits.archive.max_depth == 5
    assert policy.signers == ()


def test_trust_section(tmp_path: Path) -> None:
    block, key_id = signer_block(tmp_path, extra="sources: [dev]\n          validUntil: 2027-01-01")
    gpg_sha = pin(tmp_path, "keys/alma.asc", b"gpg key")
    body = f"""\
    trust:
      signers:
{block}
      upstream:
        - name: almalinux-9
          type: gpg
          file: keys/alma.asc
          sha256: "{gpg_sha}"
          scope: [package.rpm]
          fingerprints: ["ABCD"]
      minimum:
        "package.rpm": signature
        "model.*": pinned-checksum
    """
    policy = load_policy(write_policy(tmp_path, body))
    signer = policy.signer(key_id)
    assert signer is not None
    assert signer.holder == "pack-holder"
    assert signer.load().key_id == key_id
    assert policy.signers_with_role(KeyRole.RECEIPT) == ()
    assert policy.upstream[0].type is UpstreamKeyType.GPG
    assert policy.required_trust("package.rpm") is TrustLevel.SIGNATURE
    assert policy.required_trust("model.gguf") is TrustLevel.PINNED_CHECKSUM
    assert policy.required_trust("archive.zip") is TrustLevel.NONE

    assert signer.problem(KeyRole.PACK, TODAY, "dev") is None
    assert "role" in (signer.problem(KeyRole.RECEIPT, TODAY, "dev") or "")
    assert "source" in (signer.problem(KeyRole.PACK, TODAY, "elsewhere") or "")
    assert "expired" in (signer.problem(KeyRole.PACK, date(2027, 6, 1), "dev") or "")


def test_revoked_key_and_digest_covers_keys(tmp_path: Path) -> None:
    block, key_id = signer_block(tmp_path)
    body = f"    trust:\n      signers:\n{block}"
    policy = load_policy(write_policy(tmp_path, body))
    revoked = load_policy(
        write_policy(tmp_path, body.replace("roles:", "revoked: true\n          roles:"), "r.yaml")
    )
    signer = revoked.signer(key_id)
    assert signer is not None
    assert signer.problem(KeyRole.PACK, TODAY) == "key is revoked"
    assert revoked.digest != policy.digest  # rotation or revocation always changes the digest


def test_key_id_must_match_key_file(tmp_path: Path) -> None:
    block, key_id = signer_block(tmp_path)
    body = f"    trust:\n      signers:\n{block}".replace(key_id, KEY_ID)
    with pytest.raises(ConfigError, match=r"trust\.signers\[0\]\.keyId: key file has key id"):
        load_policy(write_policy(tmp_path, body))


def test_pinned_file_mismatch_and_missing(tmp_path: Path) -> None:
    pin(tmp_path, "keys/pack.pub", b"tampered")
    body = f"""\
    trust:
      signers:
        - keyId: "{KEY_ID}"
          publicKey: keys/pack.pub
          sha256: "{"0" * 64}"
          holder: x
          roles: [pack]
    """
    with pytest.raises(ConfigError, match=r"trust\.signers\[0\]\.publicKey: pinned file"):
        load_policy(write_policy(tmp_path, body))
    missing = f"""\
    allowlists:
      python: {{mode: enforce, file: allow/python.txt, sha256: "{"0" * 64}"}}
    """
    with pytest.raises(ConfigError, match="cannot read pinned file"):
        load_policy(write_policy(tmp_path, missing))


def test_custom_control_catalogue(tmp_path: Path) -> None:
    text = b"framework: itsg-33-site\ntitle: Site profile\ncontrols:\n  SI-7: Integrity\n"
    sha = pin(tmp_path, "controls.yaml", text)
    body = f"""\
    controls:
      catalog: {{file: controls.yaml, sha256: "{sha}"}}
    """
    policy = load_policy(write_policy(tmp_path, body))
    assert policy.catalog().framework == "itsg-33-site"


def test_extensions_are_tolerated_but_covered_by_digest(tmp_path: Path) -> None:
    plain = load_policy(write_policy(tmp_path, "", "a.yaml"))
    extended = load_policy(write_policy(tmp_path, "extensions: {future: {x: 1}}\n", "b.yaml"))
    assert extended.rules == plain.rules
    assert extended.digest != plain.digest


_WAIVER = (
    "waivers:\n  - {{id: W1, rule: {rule}, subject: '{subject}', justification: j,"
    ' approvedBy: "' + KEY_ID + '", expires: 2027-01-01}}\n'
)


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("rules:\n  - rule: x.y\n    dispositon: block\n", r"rules\[0\]: unknown key.*dispositon"),
        ("rules:\n  - rule: x.y\n", r"rules\[0\]: a rule must set"),
        ("rules:\n  - rule: x.y\n    disposition: maybe\n", r"rules\[0\]\.disposition: 'maybe'"),
        ("rules:\n  - rule: x.y\n    disposition: block\n    approvals: 0\n", "at least 1"),
        ("defaults: {overrideApprovals: 0}\n", r"overrideApprovals: must be at least 1"),
        ("rules:\n  - {rule: x.y, disposition: block, overridable: maybe}\n", "true or false"),
        ("rules:\n  - {rule: x.y, disposition: block, where: {cve: 7}}\n", r"where\.cve"),
        ("defaults:\n  severity:\n    severe: block\n", r"defaults\.severity: unknown key"),
        ("defaults: {notAssessed: warn}\ndefaults: {notAssessed: block}\n", "duplicate key"),
        ("limits: {maxArtifactBytes: 12XB}\n", "expected a size"),
        ("plugins: {clamav: {maxDbAge: soon}}\n", "expected a duration"),
        ("extra: 1\n", "unknown key"),
        (f"plugins: {{clamav: {{binarySha256: {'1' * 64}}}}}\n", "quote hashes"),
        ("identity: {acceptSources: [dev]}\n", r"identity\.enclave: required"),
        ("trust: {minimum: {'model.*': strong}}\n", "not one of"),
        (
            "waivers:\n  - {id: W1, rule: a.b, subject: x, justification: j,"
            f' approvedBy: "{KEY_ID}"}}\n',
            "waivers must expire",
        ),
        (
            "waivers:\n  - {id: W1, rule: a.b, subject: x, justification: j,"
            " approvedBy: bob, expires: 2027-01-01}\n",
            r"approvedBy: expected a key id",
        ),
        (_WAIVER.format(rule="'integrity.*'", subject="x"), "exactly one rule id"),
        (_WAIVER.format(rule="a.b", subject="images/**"), "exact subject, or a sha256"),
        ("licences: {allow: Apache-2.0}\n", "expected a list of strings"),
        ("controls: {overrides: {'a.*': SI-7}}\n", "expected a list of control ids"),
    ],
)
def test_invalid_policies(tmp_path: Path, body: str, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        load_policy(write_policy(tmp_path, body))


def test_wrong_kind_and_version(tmp_path: Path) -> None:
    path = tmp_path / "p.yaml"
    meta = "metadata: {name: a, version: b}\n"
    path.write_text("apiVersion: airlock/v1alpha1\nkind: Request\n" + meta)
    with pytest.raises(ConfigError, match="kind"):
        load_policy(path)
    path.write_text("apiVersion: airlock/v2\nkind: Policy\n" + meta)
    with pytest.raises(ConfigError, match="apiVersion"):
        load_policy(path)


# --- Evaluation ---------------------------------------------------------------------------------

PT = Subject.of_path("models/x.pt")
IMAGE = Subject.of_path("images/legacy.tar")


@pytest.fixture
def policy(tmp_path: Path) -> Policy:
    body = f"""\
    rules:
      - rule: "malware.*"
        notAssessed: block
      - rule: "offline.*"
        paths: ["dev-tools/**"]
        disposition: warn
      - rule: "offline.*"
        disposition: block
        overridable: false
      - rule: "container.*"
        disposition: require-approval
        approvals: 2
      - rule: "vuln.component.known"
        where: {{kev: "true"}}
        disposition: block
      - rule: "vuln.*"
        disposition: warn
      - rule: "integrity.*"
        disposition: allow
    waivers:
      - id: W-1
        rule: container.user.root
        subject: "images/*.tar"
        sha256: "{"c" * 64}"
        justification: isolated namespace
        approvedBy: "{KEY_ID}"
        expires: 2027-01-31
      - id: W-2
        rule: container.user.root
        subject: images/old-app.tar
        justification: expired exception
        approvedBy: "{KEY_ID}"
        expires: 2026-01-31
      - id: W-3
        rule: vuln.component.known
        subject: "pkg:pypi/libfoo@1.0"
        where: {{cve: CVE-2026-0001}}
        justification: not reachable
        approvedBy: "{KEY_ID}"
        expires: 2027-01-31
      - id: W-4
        rule: integrity.hash.mismatch
        subject: models/x.pt
        justification: nice try
        approvedBy: "{KEY_ID}"
        expires: 2027-01-31
    """
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
    na = findings("malware.scan.detected", PT, Result.NOT_ASSESSED, tool=TOOL, reason="absent")
    assert policy.decide(na, today=TODAY).matched == "rules[0]"
    fail = findings("malware.scan.detected", PT, Result.FAIL, tool=TOOL)
    assert policy.decide(fail, today=TODAY).matched == "defaults.severity.critical"
    err = findings("model.pickle.dangerous-import", PT, Result.ERROR, tool=TOOL)
    assert policy.decide(err, today=TODAY).matched == "defaults.error"


def test_first_match_wins_with_path_scope(policy: Policy, findings: FindingFactory) -> None:
    dev = Subject.of_path("dev-tools/ide/settings.json")
    in_scope = findings("offline.telemetry.enabled", dev, Result.FAIL, tool=TOOL)
    out_of_scope = findings("offline.telemetry.enabled", PT, Result.FAIL, tool=TOOL)
    assert policy.decide(in_scope, today=TODAY).matched == "rules[1]"
    assert policy.decide(out_of_scope, today=TODAY).matched == "rules[2]"
    bundle = findings("offline.telemetry.enabled", Subject.bundle(), Result.FAIL, tool=TOOL)
    assert policy.decide(bundle, today=TODAY).matched == "rules[2]"
    unit = Subject.of_unit(Unit(UnitKind.CONTAINER_IMAGE, "x", ArtifactRef("dev-tools/img")))
    in_unit = findings("offline.telemetry.enabled", unit, Result.FAIL, tool=TOOL)
    assert policy.decide(in_unit, today=TODAY).matched == "rules[1]"


def test_where_selects_on_finding_attributes(policy: Policy, findings: FindingFactory) -> None:
    libfoo = Subject.of_component("pkg:pypi/libfoo@1.0")

    def vuln(cve: str, kev: str) -> Disposition:
        finding = findings(
            "vuln.component.known",
            libfoo,
            Result.FAIL,
            tool=TOOL,
            attributes={"cve": cve, "kev": kev},
            discriminator=cve,
        )
        decision = policy.decide(finding, today=TODAY)
        return decision.disposition

    assert vuln("CVE-2026-0002", "true") is Disposition.BLOCK
    assert vuln("CVE-2026-0002", "false") is Disposition.WARN
    # The waiver covers one CVE on one component, not every vulnerability in it.
    assert vuln("CVE-2026-0001", "true") is Disposition.ALLOW


def test_approvals(policy: Policy, findings: FindingFactory) -> None:
    f = findings("container.user.root", Subject.of_path("images/app.tar"), Result.FAIL, tool=TOOL)
    d = policy.decide(f, today=TODAY)
    assert (d.disposition, d.approvals_required) == (Disposition.REQUIRE_APPROVAL, 2)
    # A policy blocker can be overridden, by the (larger) override quorum.
    block = policy.decide(
        findings("model.pickle.dangerous-import", PT, Result.FAIL, tool=TOOL), today=TODAY
    )
    assert (block.disposition, block.approvals_required, block.final) == (
        Disposition.BLOCK,
        2,
        False,
    )
    # Unless the policy says that this rule's blocks are not overridable.
    strict = policy.decide(
        findings("offline.telemetry.enabled", PT, Result.FAIL, tool=TOOL), today=TODAY
    )
    assert (strict.disposition, strict.approvals_required, strict.final) == (
        Disposition.BLOCK,
        0,
        True,
    )


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
    f = findings(
        "container.user.root", Subject.of_path("images/old-app.tar"), Result.FAIL, tool=TOOL
    )
    assert policy.decide(f, today=TODAY).waiver is None


def test_integrity_failures_cannot_be_waived_lowered_or_overridden(
    policy: Policy, findings: FindingFactory, registry: RuleRegistry
) -> None:
    tampered = findings("integrity.hash.mismatch", PT, Result.FAIL, tool=TOOL)
    # If the rule were not final, the policy's `integrity.*: allow` rule and waiver W-4 would
    # both apply.
    assert policy.decide(tampered, today=TODAY).waiver == "W-4"
    [decision] = evaluate(policy, registry, [tampered], today=TODAY)
    assert decision.disposition is Disposition.BLOCK
    assert decision.matched == "final"
    assert decision.waiver is None
    assert decision.final
    assert not decision.clearable
    assert decision.approvals_required == 0
    crashed = findings("integrity.hash.mismatch", PT, Result.ERROR, tool=TOOL)
    [decision] = evaluate(policy, registry, [crashed], today=TODAY)
    assert decision.final
    # Being final does not turn "could not check" into a block.
    skipped = findings("integrity.hash.mismatch", PT, Result.NOT_ASSESSED, tool=TOOL, reason="r")
    [decision] = evaluate(policy, registry, [skipped], today=TODAY)
    assert decision.disposition is Disposition.WARN


def test_evaluate_passes_content_hashes(
    policy: Policy, findings: FindingFactory, registry: RuleRegistry
) -> None:
    f = findings("container.user.root", IMAGE, Result.FAIL, tool=TOOL)
    hashes = {"images/legacy.tar": "c" * 64}
    [decision] = evaluate(policy, registry, [f], today=TODAY, content_hashes=hashes)
    assert decision.waiver == "W-1"


@pytest.mark.parametrize(
    ("licence", "expected"),
    [
        ("MIT", Disposition.ALLOW),
        ("LGPL-2.1-only", Disposition.REQUIRE_APPROVAL),
        ("AGPL-3.0-only", Disposition.BLOCK),
        ("LicenseRef-llama3.1", Disposition.REQUIRE_APPROVAL),
        ("WTFPL", Disposition.REQUIRE_APPROVAL),
        (None, Disposition.REQUIRE_APPROVAL),
        ("MIT OR AGPL-3.0-only", Disposition.ALLOW),
        ("MIT AND AGPL-3.0-only", Disposition.BLOCK),
        ("(MIT OR Apache-2.0) AND LGPL-3.0-only", Disposition.REQUIRE_APPROVAL),
        ("Apache-2.0 WITH LLVM-exception", Disposition.ALLOW),
        ("MIT OR", Disposition.REQUIRE_APPROVAL),
        ("(MIT", Disposition.REQUIRE_APPROVAL),
        ("MIT Apache-2.0", Disposition.REQUIRE_APPROVAL),
    ],
)
def test_licences(licence: str | None, expected: Disposition) -> None:
    licences = load_policy(EXAMPLES / "policy.yaml").licences
    assert licences.decide(licence) is expected


def test_deny_wins_over_allow() -> None:
    licences = LicencePolicy(allow=("GPL-*",), deny=("GPL-3.0-*",))
    assert licences.decide("GPL-3.0-only") is Disposition.BLOCK
    assert licences.decide("GPL-2.0-only") is Disposition.ALLOW
