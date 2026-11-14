"""Policy: loading, validation and evaluation.

One YAML document per side of the gap. Verify always evaluates with the receiving side's own
policy. Every file the policy references is pinned by sha256 and covered by the policy digest.
"""

import hashlib
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import date, timedelta
from enum import StrEnum
from fnmatch import fnmatchcase
from pathlib import Path

from airlock.core.canonical import JSON, digest, sha256_digest
from airlock.core.controls import DEFAULT_FRAMEWORK, ControlCatalog, ControlOverride
from airlock.core.model import (
    API_VERSION,
    Decision,
    Disposition,
    Finding,
    Result,
    Severity,
    TrustLevel,
)
from airlock.core.paths import has_glob, path_matches
from airlock.core.rules import RuleRegistry
from airlock.core.signing import SigningError, VerifyKey, load_verify_key
from airlock.core.yamlio import Reader, load_yaml_file

KEY_ID = re.compile(r"^[a-z0-9]+:[0-9a-f]{64}$")
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_RULE_ID = re.compile(r"^[a-z0-9][a-z0-9.-]*$")
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
class Validity:
    """When a key may be relied on. Rotation is done by editing these, which changes the policy
    digest; the receiving side's ledger records every digest change."""

    valid_from: date | None = None
    valid_until: date | None = None
    revoked: bool = False

    def problem(self, today: date) -> str | None:
        if self.revoked:
            return "key is revoked"
        if self.valid_from and today < self.valid_from:
            return f"key is not valid before {self.valid_from}"
        if self.valid_until and today > self.valid_until:
            return f"key expired on {self.valid_until}"
        return None


@dataclass(frozen=True, slots=True)
class Signer:
    key_id: str
    public_key: PinnedFile
    roles: frozenset[KeyRole]
    holder: str  # the person or system holding the key; quorums count distinct holders
    sources: tuple[str, ...] = ()  # networks this key may pack for; empty means any
    validity: Validity = field(default_factory=Validity)

    def problem(self, role: KeyRole, today: date, source: str | None = None) -> str | None:
        """Why this key must not be relied on for ``role`` right now, or None if it may be."""
        if role not in self.roles:
            return f"key does not have the {role.value!r} role"
        if self.sources and source not in self.sources:
            return f"key may not sign for source {source!r}"
        return self.validity.problem(today)

    def load(self) -> VerifyKey:
        return load_verify_key(self.public_key.path)


@dataclass(frozen=True, slots=True)
class UpstreamKey:
    name: str
    type: UpstreamKeyType
    file: PinnedFile
    scope: tuple[str, ...]  # what it may vouch for: artifact kinds, repo ids, publishers
    fingerprints: tuple[str, ...] = ()  # acceptable (sub)key fingerprints inside the file
    validity: Validity = field(default_factory=Validity)


@dataclass(frozen=True, slots=True)
class Identity:
    """Who this policy's owner is. Bundles addressed elsewhere are refused."""

    enclave: str
    accept_sources: tuple[str, ...] = ()  # empty means any source


@dataclass(frozen=True, slots=True)
class Defaults:
    severity: Mapping[Severity, Disposition]
    not_assessed: Disposition
    error: Disposition
    approvals: int  # distinct approvers to clear a require-approval finding
    override_approvals: int  # distinct approvers to override a blocker


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
    override_approvals=2,
)


def _where_matches(where: Mapping[str, str], finding: Finding) -> bool:
    return all(
        key in finding.attributes and fnmatchcase(finding.attributes[key], pattern)
        for key, pattern in where.items()
    )


@dataclass(frozen=True, slots=True)
class RuleOverride:
    rule: str  # rule id glob
    paths: tuple[str, ...] = ()  # optional scope; empty means everywhere
    where: Mapping[str, str] = field(default_factory=dict)  # finding attribute globs
    disposition: Disposition | None = None  # for FAIL
    not_assessed: Disposition | None = None
    error: Disposition | None = None
    approvals: int | None = None
    overridable: bool = True  # false: a block decided by this rule cannot be overridden

    def outcome_for(self, result: Result) -> Disposition | None:
        if result is Result.FAIL:
            return self.disposition
        if result is Result.NOT_ASSESSED:
            return self.not_assessed
        if result is Result.ERROR:
            return self.error
        return None

    def matches(self, finding: Finding) -> bool:
        if not fnmatchcase(finding.rule, self.rule) or not _where_matches(self.where, finding):
            return False
        if not self.paths:
            return True
        path = finding.subject.path
        return path is not None and any(path_matches(p, path) for p in self.paths)


@dataclass(frozen=True, slots=True)
class Waiver:
    """A standing, expiring exception for one rule on one subject."""

    id: str
    rule: str  # exact rule id; waivers never use globs here
    subject: str  # the finding subject's display form; a glob only if ``sha256`` pins content
    justification: str
    approved_by: str  # key id
    expires: date
    sha256: str | None = None  # pins the waiver to exact content
    where: Mapping[str, str] = field(default_factory=dict)

    def applies(self, finding: Finding, today: date, content_sha256: str | None) -> bool:
        return (
            self.expires >= today
            and finding.rule == self.rule
            and path_matches(self.subject, finding.subject.display)
            and (self.sha256 is None or self.sha256 == content_sha256)
            and _where_matches(self.where, finding)
        )


_LICENCE_TOKEN = re.compile(r"\(|\)|[^\s()]+")


@dataclass(frozen=True, slots=True)
class LicencePolicy:
    allow: tuple[str, ...] = ()
    require_approval: tuple[str, ...] = ()
    deny: tuple[str, ...] = ()
    unknown: Disposition = Disposition.REQUIRE_APPROVAL

    def decide(self, expression: str | None) -> Disposition:
        """Decide an SPDX id or expression.

        ``A OR B`` takes the more permissive side (the licensee may choose); ``A AND B`` the more
        restrictive. For a single id, deny wins over approval and approval over allow.
        """
        if not expression:
            return self.unknown
        tokens = _LICENCE_TOKEN.findall(expression)
        try:
            outcome, rest = self._either(tokens)
        except (IndexError, ValueError):
            return self.unknown
        return self.unknown if rest else outcome

    def _either(self, tokens: list[str]) -> tuple[Disposition, list[str]]:
        outcome, tokens = self._both(tokens)
        while tokens and tokens[0].upper() == "OR":
            other, tokens = self._both(tokens[1:])
            outcome = min(outcome, other, key=lambda d: d.rank)
        return outcome, tokens

    def _both(self, tokens: list[str]) -> tuple[Disposition, list[str]]:
        outcome, tokens = self._single(tokens)
        while tokens and tokens[0].upper() == "AND":
            other, tokens = self._single(tokens[1:])
            outcome = max(outcome, other, key=lambda d: d.rank)
        return outcome, tokens

    def _single(self, tokens: list[str]) -> tuple[Disposition, list[str]]:
        head, tokens = tokens[0], tokens[1:]
        if head == "(":
            outcome, tokens = self._either(tokens)
            if tokens[0] != ")":
                raise ValueError("unbalanced parentheses")
            return outcome, tokens[1:]
        if head == ")" or head.upper() in ("AND", "OR", "WITH"):
            raise ValueError(f"unexpected {head!r}")
        if tokens and tokens[0].upper() == "WITH":  # an exception does not change the base terms
            tokens = tokens[2:]
        return self._id(head), tokens

    def _id(self, licence_id: str) -> Disposition:
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
    max_ratio: int = 200  # expanded bytes per byte of the outermost archive
    ratio_min_bytes: int = 16 * 2**20  # the ratio is only judged once this much has expanded
    max_expanded_bytes: int = 500 * 2**30


@dataclass(frozen=True, slots=True)
class Limits:
    archive: ArchiveLimits = field(default_factory=ArchiveLimits)
    max_artifact_bytes: int = 2**40
    max_path_length: int = 1024


@dataclass(frozen=True, slots=True)
class PluginPolicy:
    """One external scanner, or data feed, that the site has chosen to use.

    A plugin runs only when the policy configures it: nothing is picked up from ``PATH`` unless
    the policy says so, and every path is resolved against the policy file's directory.
    """

    required: bool = False  # true: a missing plugin is a failing ``plugin.required.missing``
    path: Path | None = None  # the binary (or, for a feed, the data file); None: look on PATH
    database: Path | None = None  # signature database or vulnerability DB cache directory
    binary_sha256: str | None = None
    files: Mapping[str, str] = field(default_factory=dict)  # pinned data: relative path -> sha256
    min_version: str | None = None
    max_db_age: timedelta | None = None
    timeout: timedelta = timedelta(hours=1)
    args: tuple[str, ...] = ()  # extra arguments, appended to airlock's own


@dataclass(frozen=True, slots=True)
class Policy:
    name: str
    version: str
    digest: str  # covers the policy bytes and every pinned file
    identity: Identity | None = None
    max_bundle_age: timedelta | None = None
    # Allowance for clock drift, on this host and between the two sides.
    clock_tolerance: timedelta = timedelta(minutes=10)
    defaults: Defaults = DEFAULTS
    rules: tuple[RuleOverride, ...] = ()
    waivers: tuple[Waiver, ...] = ()
    signers: tuple[Signer, ...] = ()
    upstream: tuple[UpstreamKey, ...] = ()
    minimum_trust: tuple[tuple[str, TrustLevel], ...] = ()  # (artifact kind glob, level)
    licences: LicencePolicy = field(default_factory=LicencePolicy)
    allowlists: Mapping[str, Allowlist] = field(default_factory=dict)
    limits: Limits = field(default_factory=Limits)
    plugins: Mapping[str, PluginPolicy] = field(default_factory=dict)
    feed_max_age: Mapping[str, timedelta] = field(default_factory=dict)
    control_framework: str = DEFAULT_FRAMEWORK
    control_catalog: PinnedFile | None = None
    control_overrides: tuple[ControlOverride, ...] = ()

    @classmethod
    def default(cls) -> "Policy":
        """Built-in defaults, for use when no policy file is given."""
        return cls(name="builtin-default", version="1", digest=digest("airlock:builtin-default:1"))

    def catalog(self) -> ControlCatalog:
        if self.control_catalog is None:
            return ControlCatalog.builtin(self.control_framework)
        text = self.control_catalog.path.read_text(encoding="utf-8")
        return ControlCatalog.parse(text, source=self.control_catalog.declared)

    def signer(self, key_id: str) -> Signer | None:
        return next((s for s in self.signers if s.key_id == key_id), None)

    def signers_with_role(self, role: KeyRole) -> tuple[Signer, ...]:
        return tuple(s for s in self.signers if role in s.roles)

    def expired_waivers(self, today: date) -> tuple[Waiver, ...]:
        return tuple(w for w in self.waivers if w.expires < today)

    def required_trust(self, kind: str) -> TrustLevel:
        """Minimum upstream trust level for an artifact kind (first matching glob)."""
        return next(
            (level for pattern, level in self.minimum_trust if fnmatchcase(kind, pattern)),
            TrustLevel.NONE,
        )

    def decide(
        self,
        finding: Finding,
        *,
        today: date,
        content_sha256: str | None = None,
        final: bool = False,
    ) -> Decision:
        """Decide one finding.

        ``final`` marks an integrity or authenticity rule. A FAIL or ERROR of such a rule is
        always ``block``: no waiver, rule, default or approval changes that.

        Otherwise the order is: PASS is always allowed; then the first applicable unexpired
        waiver; then the first rule that matches *and* sets an outcome for this result; then the
        defaults. A resulting ``block`` is a policy blocker: it stands unless a quorum of
        approvers overrides it for this bundle (or the deciding rule says it is not overridable).

        ``content_sha256`` is the subject's content hash, needed for content-pinned waivers.
        """
        if finding.result is Result.PASS:
            return Decision(finding.id, Disposition.ALLOW, "pass")
        if final and finding.result in (Result.FAIL, Result.ERROR):
            return Decision(finding.id, Disposition.BLOCK, "final", final=True)

        if not final:
            for index, waiver in enumerate(self.waivers):
                if waiver.applies(finding, today, content_sha256):
                    return Decision(
                        finding.id, Disposition.ALLOW, f"waivers[{index}]", 0, waiver.id
                    )

        outcome, matched, rule = self._outcome(finding)
        if outcome is Disposition.REQUIRE_APPROVAL:
            required = (rule.approvals if rule else None) or self.defaults.approvals
            return Decision(finding.id, outcome, matched, required)
        if outcome is Disposition.BLOCK:
            if rule is not None and not rule.overridable:
                return Decision(finding.id, outcome, matched, final=True)
            required = (rule.approvals if rule else None) or self.defaults.override_approvals
            return Decision(finding.id, outcome, matched, required)
        return Decision(finding.id, outcome, matched)

    def _outcome(self, finding: Finding) -> tuple[Disposition, str, RuleOverride | None]:
        for index, rule in enumerate(self.rules):
            outcome = rule.outcome_for(finding.result)
            if outcome is not None and rule.matches(finding):
                return outcome, f"rules[{index}]", rule
        if finding.result is Result.FAIL:
            level = finding.severity
            return self.defaults.severity[level], f"defaults.severity.{level.value}", None
        if finding.result is Result.NOT_ASSESSED:
            return self.defaults.not_assessed, "defaults.notAssessed", None
        return self.defaults.error, "defaults.error", None


def evaluate(
    policy: Policy,
    registry: RuleRegistry,
    findings: Iterable[Finding],
    *,
    today: date,
    content_hashes: Mapping[str, str] | None = None,
) -> tuple[Decision, ...]:
    """Decide every finding. Rules the registry marks ``final`` cannot be waived or overridden.

    ``content_hashes`` maps a subject's display form to its sha256, for content-pinned waivers.
    """
    hashes = content_hashes or {}
    return tuple(
        policy.decide(
            finding,
            today=today,
            content_sha256=hashes.get(finding.subject.display),
            final=registry.get(finding.rule).final,
        )
        for finding in findings
    )


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

        signers, upstream, minimum = self._trust(doc.opt_section("trust"))
        framework, catalog, overrides = self._controls(doc.opt_section("controls"))
        transfer = doc.opt_section("transfer")
        max_bundle_age = transfer.opt_duration("maxBundleAge") if transfer else None
        clock_tolerance = transfer.opt_duration("clockTolerance") if transfer else None
        if transfer:
            transfer.done()
        policy = Policy(
            name=name,
            version=version,
            digest="",
            identity=self._identity(doc.opt_section("identity")),
            max_bundle_age=max_bundle_age,
            clock_tolerance=clock_tolerance or timedelta(minutes=10),
            defaults=self._defaults(doc.opt_section("defaults")),
            rules=tuple(self._rule(r) for r in doc.sections("rules")),
            waivers=tuple(self._waiver(w) for w in doc.sections("waivers")),
            signers=signers,
            upstream=upstream,
            minimum_trust=minimum,
            licences=self._licences(doc.opt_section("licences")),
            allowlists=self._allowlists(doc),
            limits=self._limits(doc.opt_section("limits")),
            plugins=self._plugins(doc),
            feed_max_age=self._freshness(doc.opt_section("freshness")),
            control_framework=framework,
            control_catalog=catalog,
            control_overrides=overrides,
        )
        # Free-form and ignored by this version, but still covered by the digest. Lets a newer
        # policy carry settings an older tool does not understand without being rejected.
        extensions = doc.raw("extensions")
        if extensions is not None and not isinstance(extensions, dict):
            raise doc.error("expected a mapping", "extensions")
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

    def _identity(self, section: Reader | None) -> Identity | None:
        if section is None:
            return None
        identity = Identity(section.req_str("enclave"), section.str_list("acceptSources"))
        section.done()
        return identity

    def _defaults(self, section: Reader | None) -> Defaults:
        if section is None:
            return DEFAULTS
        severity = dict(DEFAULTS.severity)
        if sev := section.opt_section("severity"):
            for level in Severity:
                severity[level] = sev.opt_enum(level.value, Disposition) or severity[level]
            sev.done()
        result = Defaults(
            severity=severity,
            not_assessed=section.opt_enum("notAssessed", Disposition) or DEFAULTS.not_assessed,
            error=section.opt_enum("error", Disposition) or DEFAULTS.error,
            approvals=_approvals(section) or DEFAULTS.approvals,
            override_approvals=_approvals(section, "overrideApprovals")
            or DEFAULTS.override_approvals,
        )
        section.done()
        return result

    def _rule(self, section: Reader) -> RuleOverride:
        rule = RuleOverride(
            rule=section.req_str("rule"),
            paths=section.str_list("paths"),
            where=_where(section),
            disposition=section.opt_enum("disposition", Disposition),
            not_assessed=section.opt_enum("notAssessed", Disposition),
            error=section.opt_enum("error", Disposition),
            approvals=_approvals(section),
            overridable=section.opt_bool("overridable") is not False,
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
            where=_where(section),
        )
        section.done()
        if not _RULE_ID.match(waiver.rule):
            raise section.error("a waiver names exactly one rule id; globs are not allowed", "rule")
        if waiver.sha256 is None and has_glob(waiver.subject):
            raise section.error(
                "a waiver needs an exact subject, or a sha256 that pins it to content", "subject"
            )
        return waiver

    def _trust(
        self, section: Reader | None
    ) -> tuple[tuple[Signer, ...], tuple[UpstreamKey, ...], tuple[tuple[str, TrustLevel], ...]]:
        if section is None:
            return (), (), ()
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
            key_id = _key_id(s, "keyId")
            pinned = self._pinned(s, "publicKey")
            try:
                actual = load_verify_key(pinned.path).key_id
            except SigningError as exc:
                raise s.error(str(exc), "publicKey") from exc
            if actual != key_id:
                raise s.error(f"key file has key id {actual}, policy says {key_id}", "keyId")
            signers.append(
                Signer(
                    key_id=key_id,
                    public_key=pinned,
                    roles=role_set,
                    holder=s.req_str("holder"),
                    sources=s.str_list("sources"),
                    validity=_validity(s),
                )
            )
            s.done()
        upstream = []
        for u in section.sections("upstream"):
            upstream.append(
                UpstreamKey(
                    name=u.req_str("name"),
                    type=u.enum("type", UpstreamKeyType),
                    file=self._pinned(u, "file"),
                    scope=u.str_list("scope"),
                    fingerprints=u.str_list("fingerprints"),
                    validity=_validity(u),
                )
            )
            u.done()
        minimum = []
        if m := section.opt_section("minimum"):
            for kind in m.names():
                minimum.append((kind, m.enum(kind, TrustLevel)))
            m.done()
        section.done()
        return tuple(signers), tuple(upstream), tuple(minimum)

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
                ratio_min_bytes=_positive(
                    a, "ratioMinBytes", a.opt_size("ratioMinBytes"), archive.ratio_min_bytes
                ),
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
            files = {}
            if f := section.opt_section("files"):
                for file_name in f.names():
                    pin = _sha256_field(f, file_name, required=True)
                    assert pin is not None  # noqa: S101
                    files[file_name] = pin
                f.done()
            path = section.opt_str("path")
            database = section.opt_str("database")
            plugins[name] = PluginPolicy(
                required=bool(section.opt_bool("required")),
                path=(self.base / path).resolve() if path else None,
                database=(self.base / database).resolve() if database else None,
                binary_sha256=_sha256_field(section, "binarySha256", required=False),
                files=files,
                min_version=section.opt_str("minVersion"),
                max_db_age=section.opt_duration("maxDbAge"),
                timeout=section.opt_duration("timeout") or timedelta(hours=1),
                args=section.str_list("args"),
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

    def _controls(
        self, section: Reader | None
    ) -> tuple[str, PinnedFile | None, tuple[ControlOverride, ...]]:
        if section is None:
            return DEFAULT_FRAMEWORK, None, ()
        framework = section.opt_str("framework") or DEFAULT_FRAMEWORK
        catalog = None
        if c := section.opt_section("catalog"):
            catalog = self._pinned(c, "file")
            c.done()
        overrides = []
        for rule, value, _ in section.mapping("overrides"):
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                raise section.error("expected a list of control ids", f"overrides.{rule}")
            overrides.append(ControlOverride(rule, tuple(value)))
        section.done()
        return framework, catalog, tuple(overrides)


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
        raise section.error("expected a key id such as 'ed25519:<64 hex characters>'", key)
    return value


def _validity(section: Reader) -> Validity:
    return Validity(
        valid_from=section.opt_date("validFrom"),
        valid_until=section.opt_date("validUntil"),
        revoked=bool(section.opt_bool("revoked")),
    )


def _where(section: Reader) -> dict[str, str]:
    where = {}
    if w := section.opt_section("where"):
        for name in w.names():
            where[name] = w.req_str(name)
        w.done()
    return where


def _approvals(section: Reader, key: str = "approvals") -> int | None:
    value = section.opt_int(key)
    if value is not None and value < 1:
        raise section.error("must be at least 1", key)
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
