"""Policy: loading, validation and evaluation.

One YAML document per side of the gap. Verify always evaluates with the high side's own policy.
Every file the policy references is pinned by sha256 and covered by the policy digest.
"""

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import date, timedelta
from enum import StrEnum
from fnmatch import fnmatchcase
from pathlib import Path

from airlock.core.canonical import JSON, digest, sha256_digest
from airlock.core.controls import DEFAULT_FRAMEWORK, ControlOverride
from airlock.core.model import API_VERSION, Decision, Disposition, Finding, Result, Severity
from airlock.core.paths import path_matches
from airlock.core.yamlio import Reader, load_yaml_file

KEY_ID = re.compile(r"^ed25519:[0-9a-f]{16}$")
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_HASH_CHUNK = 1 << 20


class KeyRole(StrEnum):
    PACK = "pack"
    APPROVE = "approve"
    RECEIPT = "receipt"


class UpstreamKeyType(StrEnum):
    GPG = "gpg"
    X509 = "x509"
    SIGSTORE = "sigstore"
    CHECKSUM_LIST = "checksum-list"


class AllowlistMode(StrEnum):
    ENFORCE = "enforce"  # unlisted => finding that fails
    REPORT = "report"  # unlisted => informational finding


@dataclass(frozen=True, slots=True)
class PinnedFile:
    declared: str  # path as written in the policy
    path: Path  # resolved against the policy's directory
    sha256: str


@dataclass(frozen=True, slots=True)
class Signer:
    key_id: str
    public_key: PinnedFile
    roles: frozenset[KeyRole]


@dataclass(frozen=True, slots=True)
class UpstreamKey:
    name: str
    type: UpstreamKeyType
    file: PinnedFile
    scope: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Defaults:
    severity: Mapping[Severity, Disposition]
    not_assessed: Disposition
    error: Disposition
    approvals: int


DEFAULTS = Defaults(
    severity={
        Severity.CRITICAL: Disposition.BLOCK,
        Severity.HIGH: Disposition.BLOCK,
        Severity.MEDIUM: Disposition.REQUIRE_APPROVAL,
        Severity.LOW: Disposition.WARN,
        Severity.INFO: Disposition.ALLOW,
    },
    not_assessed=Disposition.WARN,
    error=Disposition.REQUIRE_APPROVAL,
    approvals=1,
)


@dataclass(frozen=True, slots=True)
class RuleOverride:
    rule: str  # rule id glob
    paths: tuple[str, ...] = ()  # optional scope; empty means everywhere
    disposition: Disposition | None = None  # for FAIL
    not_assessed: Disposition | None = None
    error: Disposition | None = None
    approvals: int | None = None

    def outcome_for(self, result: Result) -> Disposition | None:
        if result is Result.FAIL:
            return self.disposition
        if result is Result.NOT_ASSESSED:
            return self.not_assessed
        if result is Result.ERROR:
            return self.error
        return None


@dataclass(frozen=True, slots=True)
class Waiver:
    id: str
    rule: str  # rule id glob
    subject: str  # glob over the finding subject's display form
    justification: str
    approved_by: str  # key id
    expires: date
    sha256: str | None = None  # pins the waiver to exact content


@dataclass(frozen=True, slots=True)
class LicencePolicy:
    allow: tuple[str, ...] = ()
    require_approval: tuple[str, ...] = ()
    deny: tuple[str, ...] = ()
    unknown: Disposition = Disposition.REQUIRE_APPROVAL

    def decide(self, licence_id: str | None) -> Disposition:
        """Deny wins over approval, approval over allow; anything unlisted is ``unknown``."""
        if not licence_id:
            return self.unknown
        for patterns, outcome in (
            (self.deny, Disposition.BLOCK),
            (self.require_approval, Disposition.REQUIRE_APPROVAL),
            (self.allow, Disposition.ALLOW),
        ):
            if any(fnmatchcase(licence_id, p) for p in patterns):
                return outcome
        return self.unknown


@dataclass(frozen=True, slots=True)
class Allowlist:
    mode: AllowlistMode
    entries: tuple[JSON, ...] = ()
    file: PinnedFile | None = None


@dataclass(frozen=True, slots=True)
class ArchiveLimits:
    max_depth: int = 4
    max_members: int = 200_000
    max_ratio: int = 200
    max_expanded_bytes: int = 500 * 2**30


@dataclass(frozen=True, slots=True)
class Limits:
    archive: ArchiveLimits = field(default_factory=ArchiveLimits)
    max_artifact_bytes: int = 2**40
    max_path_length: int = 1024


@dataclass(frozen=True, slots=True)
class PluginPolicy:
    required: bool = False
    binary_sha256: str | None = None
    max_db_age: timedelta | None = None


@dataclass(frozen=True, slots=True)
class Policy:
    name: str
    version: str
    digest: str  # covers the policy bytes and every pinned file
    defaults: Defaults = DEFAULTS
    rules: tuple[RuleOverride, ...] = ()
    waivers: tuple[Waiver, ...] = ()
    signers: tuple[Signer, ...] = ()
    upstream: tuple[UpstreamKey, ...] = ()
    licences: LicencePolicy = field(default_factory=LicencePolicy)
    allowlists: Mapping[str, Allowlist] = field(default_factory=dict)
    limits: Limits = field(default_factory=Limits)
    plugins: Mapping[str, PluginPolicy] = field(default_factory=dict)
    feed_max_age: Mapping[str, timedelta] = field(default_factory=dict)
    control_framework: str = DEFAULT_FRAMEWORK
    control_overrides: tuple[ControlOverride, ...] = ()

    def signers_with_role(self, role: KeyRole) -> tuple[Signer, ...]:
        return tuple(s for s in self.signers if role in s.roles)

    def expired_waivers(self, today: date) -> tuple[Waiver, ...]:
        return tuple(w for w in self.waivers if w.expires < today)

    def decide(
        self, finding: Finding, *, today: date, content_sha256: str | None = None
    ) -> Decision:
        """Decide one finding.

        Order: PASS is always allowed; then the first applicable unexpired waiver; then the first
        rule that matches *and* sets an outcome for this result; then the defaults.
        ``content_sha256`` is the subject's content hash, needed for content-pinned waivers.
        """
        if finding.result is Result.PASS:
            return Decision(finding.id, Disposition.ALLOW, "pass")

        for index, waiver in enumerate(self.waivers):
            if (
                waiver.expires >= today
                and fnmatchcase(finding.rule, waiver.rule)
                and path_matches(waiver.subject, finding.subject.display)
                and (waiver.sha256 is None or waiver.sha256 == content_sha256)
            ):
                return Decision(finding.id, Disposition.ALLOW, f"waivers[{index}]", 0, waiver.id)

        for index, rule in enumerate(self.rules):
            outcome = rule.outcome_for(finding.result)
            if outcome is None or not fnmatchcase(finding.rule, rule.rule):
                continue
            if rule.paths:
                path = finding.subject.path
                if path is None or not any(path_matches(p, path) for p in rule.paths):
                    continue
            approvals = rule.approvals if rule.approvals is not None else self.defaults.approvals
            return self._decision(finding, outcome, f"rules[{index}]", approvals)

        if finding.result is Result.FAIL:
            outcome = self.defaults.severity[finding.severity]
            matched = f"defaults.severity.{finding.severity.value}"
        elif finding.result is Result.NOT_ASSESSED:
            outcome, matched = self.defaults.not_assessed, "defaults.notAssessed"
        else:
            outcome, matched = self.defaults.error, "defaults.error"
        return self._decision(finding, outcome, matched, self.defaults.approvals)

    @staticmethod
    def _decision(finding: Finding, outcome: Disposition, matched: str, approvals: int) -> Decision:
        required = approvals if outcome is Disposition.REQUIRE_APPROVAL else 0
        return Decision(finding.id, outcome, matched, required)


# --- Loading ------------------------------------------------------------------------------------


def load_policy(path: Path) -> Policy:
    """Load, validate and pin-check a policy file."""
    data, raw = load_yaml_file(path)
    return _Parser(path.parent, str(path)).parse(data, raw)


class _Parser:
    def __init__(self, base: Path, source: str) -> None:
        self.base = base
        self.source = source
        self.pinned: dict[str, str] = {}

    def parse(self, data: object, raw: bytes) -> Policy:
        doc = Reader(data, source=self.source)
        if doc.req_str("apiVersion") != API_VERSION:
            raise doc.error(f"unsupported apiVersion; expected {API_VERSION!r}", "apiVersion")
        if doc.req_str("kind") != "Policy":
            raise doc.error("expected kind: Policy", "kind")
        meta = doc.section("metadata")
        name, version = meta.req_str("name"), meta.req_str("version")
        meta.done()

        defaults = self._defaults(doc.opt_section("defaults"))
        signers, upstream = self._trust(doc.opt_section("trust"))
        framework, overrides = self._controls(doc.opt_section("controls"))
        policy = Policy(
            name=name,
            version=version,
            digest="",
            defaults=defaults,
            rules=tuple(self._rule(r) for r in doc.sections("rules")),
            waivers=tuple(self._waiver(w) for w in doc.sections("waivers")),
            signers=signers,
            upstream=upstream,
            licences=self._licences(doc.opt_section("licences")),
            allowlists=self._allowlists(doc),
            limits=self._limits(doc.opt_section("limits")),
            plugins=self._plugins(doc),
            feed_max_age=self._freshness(doc.opt_section("freshness")),
            control_framework=framework,
            control_overrides=overrides,
        )
        doc.done()
        _check_unique([w.id for w in policy.waivers], doc, "waivers", "waiver id")
        _check_unique([s.key_id for s in policy.signers], doc, "trust.signers", "key id")
        policy_digest = digest({"policy": sha256_digest(raw), "files": dict(self.pinned)})
        return replace(policy, digest=policy_digest)

    def _pinned(self, section: Reader, key: str) -> PinnedFile:
        declared = section.req_str(key)
        expected = _sha256_field(section, "sha256", required=True)
        assert expected is not None  # noqa: S101
        path = (self.base / declared).resolve()
        try:
            actual = _hash_file(path)
        except OSError as exc:
            raise section.error(f"cannot read pinned file: {exc}", key) from exc
        if actual != expected:
            raise section.error(
                f"pinned file {declared!r} has sha256 {actual}, policy expects {expected}", key
            )
        self.pinned[declared] = "sha256:" + actual
        return PinnedFile(declared, path, actual)

    def _defaults(self, section: Reader | None) -> Defaults:
        if section is None:
            return DEFAULTS
        severity = dict(DEFAULTS.severity)
        if sev := section.opt_section("severity"):
            for level in Severity:
                severity[level] = sev.opt_enum(level.value, Disposition) or severity[level]
            sev.done()
        approvals = _approvals(section) or DEFAULTS.approvals
        result = Defaults(
            severity=severity,
            not_assessed=section.opt_enum("notAssessed", Disposition) or DEFAULTS.not_assessed,
            error=section.opt_enum("error", Disposition) or DEFAULTS.error,
            approvals=approvals,
        )
        section.done()
        return result

    def _rule(self, section: Reader) -> RuleOverride:
        rule = RuleOverride(
            rule=section.req_str("rule"),
            paths=section.str_list("paths"),
            disposition=section.opt_enum("disposition", Disposition),
            not_assessed=section.opt_enum("notAssessed", Disposition),
            error=section.opt_enum("error", Disposition),
            approvals=_approvals(section),
        )
        section.done()
        if rule.disposition is rule.not_assessed is rule.error is None:
            raise section.error("a rule must set disposition, notAssessed or error")
        return rule

    def _waiver(self, section: Reader) -> Waiver:
        expires = section.opt_date("expires")
        if expires is None:
            raise section.error("waivers must expire", "expires")
        waiver = Waiver(
            id=section.req_str("id"),
            rule=section.req_str("rule"),
            subject=section.req_str("subject"),
            justification=section.req_str("justification"),
            approved_by=_key_id(section, "approvedBy"),
            expires=expires,
            sha256=_sha256_field(section, "sha256", required=False),
        )
        section.done()
        return waiver

    def _trust(self, section: Reader | None) -> tuple[tuple[Signer, ...], tuple[UpstreamKey, ...]]:
        if section is None:
            return (), ()
        signers = []
        for s in section.sections("signers"):
            roles = s.str_list("roles")
            if not roles:
                raise s.error("at least one role is required", "roles")
            try:
                role_set = frozenset(KeyRole(r) for r in roles)
            except ValueError:
                allowed = ", ".join(r.value for r in KeyRole)
                raise s.error(f"roles must be from: {allowed}", "roles") from None
            signers.append(Signer(_key_id(s, "keyId"), self._pinned(s, "publicKey"), role_set))
            s.done()
        upstream = []
        for u in section.sections("upstream"):
            upstream.append(
                UpstreamKey(
                    name=u.req_str("name"),
                    type=u.enum("type", UpstreamKeyType),
                    file=self._pinned(u, "file"),
                    scope=u.str_list("scope"),
                )
            )
            u.done()
        section.done()
        return tuple(signers), tuple(upstream)

    def _licences(self, section: Reader | None) -> LicencePolicy:
        if section is None:
            return LicencePolicy()
        result = LicencePolicy(
            allow=section.str_list("allow"),
            require_approval=section.str_list("requireApproval"),
            deny=section.str_list("deny"),
            unknown=section.opt_enum("unknown", Disposition) or Disposition.REQUIRE_APPROVAL,
        )
        section.done()
        return result

    def _allowlists(self, doc: Reader) -> dict[str, Allowlist]:
        allowlists = {}
        for name, _, reader in doc.mapping("allowlists"):
            section = reader()
            entries = section.raw("entries")
            if entries is not None and not isinstance(entries, list):
                raise section.error("expected a list", "entries")
            allowlists[name] = Allowlist(
                mode=section.enum("mode", AllowlistMode),
                entries=tuple(entries or ()),
                file=self._pinned(section, "file") if section.has("file") else None,
            )
            section.done()
        return allowlists

    def _limits(self, section: Reader | None) -> Limits:
        if section is None:
            return Limits()
        archive = ArchiveLimits()
        if a := section.opt_section("archive"):
            archive = ArchiveLimits(
                max_depth=_positive(a, "maxDepth", a.opt_int("maxDepth"), archive.max_depth),
                max_members=_positive(
                    a, "maxMembers", a.opt_int("maxMembers"), archive.max_members
                ),
                max_ratio=_positive(a, "maxRatio", a.opt_int("maxRatio"), archive.max_ratio),
                max_expanded_bytes=_positive(
                    a,
                    "maxExpandedBytes",
                    a.opt_size("maxExpandedBytes"),
                    archive.max_expanded_bytes,
                ),
            )
            a.done()
        defaults = Limits()
        result = Limits(
            archive=archive,
            max_artifact_bytes=_positive(
                section,
                "maxArtifactBytes",
                section.opt_size("maxArtifactBytes"),
                defaults.max_artifact_bytes,
            ),
            max_path_length=_positive(
                section,
                "maxPathLength",
                section.opt_int("maxPathLength"),
                defaults.max_path_length,
            ),
        )
        section.done()
        return result

    def _plugins(self, doc: Reader) -> dict[str, PluginPolicy]:
        plugins = {}
        for name, _, reader in doc.mapping("plugins"):
            section = reader()
            plugins[name] = PluginPolicy(
                required=bool(section.opt_bool("required")),
                binary_sha256=_sha256_field(section, "binarySha256", required=False),
                max_db_age=section.opt_duration("maxDbAge"),
            )
            section.done()
        return plugins

    def _freshness(self, section: Reader | None) -> dict[str, timedelta]:
        if section is None:
            return {}
        feeds = {}
        if f := section.opt_section("feeds"):
            for name in f.names():
                feeds[name] = f.opt_duration(name)
            f.done()
        section.done()
        return {name: age for name, age in feeds.items() if age is not None}

    def _controls(self, section: Reader | None) -> tuple[str, tuple[ControlOverride, ...]]:
        if section is None:
            return DEFAULT_FRAMEWORK, ()
        framework = section.opt_str("framework") or DEFAULT_FRAMEWORK
        overrides = []
        for rule, value, _ in section.mapping("overrides"):
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                raise section.error("expected a list of control ids", f"overrides.{rule}")
            overrides.append(ControlOverride(rule, tuple(value)))
        section.done()
        return framework, tuple(overrides)


# --- Helpers ------------------------------------------------------------------------------------


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(_HASH_CHUNK):
            h.update(chunk)
    return h.hexdigest()


def _sha256_field(section: Reader, key: str, *, required: bool) -> str | None:
    if isinstance(section.raw(key), int):
        raise section.error("quote hashes so YAML reads them as strings", key)
    value = section.req_str(key) if required else section.opt_str(key)
    if value is not None and not _SHA256_HEX.match(value):
        raise section.error("expected 64 lowercase hex characters", key)
    return value


def _key_id(section: Reader, key: str) -> str:
    value = section.req_str(key)
    if not KEY_ID.match(value):
        raise section.error("expected a key id such as 'ed25519:0123456789abcdef'", key)
    return value


def _approvals(section: Reader) -> int | None:
    value = section.opt_int("approvals")
    if value is not None and value < 1:
        raise section.error("must be at least 1", "approvals")
    return value


def _positive(section: Reader, key: str, value: int | None, default: int) -> int:
    if value is None:
        return default
    if value <= 0:
        raise section.error("must be positive", key)
    return value


def _check_unique(values: Sequence[str], doc: Reader, location: str, what: str) -> None:
    seen = set()
    for value in values:
        if value in seen:
            raise doc.error(f"duplicate {what} {value!r}", location)
        seen.add(value)
