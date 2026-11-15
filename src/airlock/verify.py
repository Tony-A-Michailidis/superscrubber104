"""``airlock verify``: check a bundle on the receiving side.

Nothing is believed because the packing side said so. The signature is checked against keys
pinned in *this* side's policy, every byte is re-hashed, the content is re-inspected with this
side's tool and limits, and decisions are made with this side's policy. The packer's analysis and
assessment are covered by the signature but are never read as input.
"""

import json
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path

from airlock import bundle as layout
from airlock.analysis import finish
from airlock.analyzer import TOOL, Analyzer
from airlock.approvals import count_approvals
from airlock.checks.inventory import check_paths, check_request
from airlock.checks.transfer import check_policy, check_transfer
from airlock.checks.units import check_request_units
from airlock.core import chainlog
from airlock.core.canonical import canonical_bytes, sha256_digest
from airlock.core.errors import AirlockError, ConfigError
from airlock.core.interfaces import Context, Handler
from airlock.core.model import (
    Analysis,
    ApprovalRecord,
    ArtifactRef,
    Assessment,
    Decision,
    EntryType,
    Finding,
    Manifest,
    PluginStatus,
    Provenance,
    Receipt,
    Stage,
    Subject,
)
from airlock.core.policy import KeyRole, Policy
from airlock.core.request import TransferRequest, parse_request
from airlock.core.serde import from_data
from airlock.core.signing import Envelope, Signer, VerifyKey, sign_envelope
from airlock.handlers import default_handlers
from airlock.hashing import hash_stream
from airlock.ledger import Ledger
from airlock.scanners import run_scanners, targets
from airlock.session import Session, utc_now
from airlock.units import default_assemblers
from airlock.walker import FileView, scan

_CONTENT_RULES = (
    "integrity.hash.mismatch",
    "integrity.entry.missing",
    "integrity.entry.unexpected",
)


@dataclass(frozen=True, slots=True)
class VerifyResult:
    assessment: Assessment
    provenance: Provenance | None
    receipt: Receipt | None
    outputs: tuple[Path, ...] = ()
    analysis: Analysis | None = None


class _Verifier:
    def __init__(
        self, bundle: Path, policy: Policy, pubkey: VerifyKey | None, ctx: Context
    ) -> None:
        self.bundle = bundle
        self.policy = policy
        self.pubkey = pubkey
        self.ctx = ctx
        self.recorder = ctx.recorder
        self.subject = Subject.bundle()
        self.subjects: dict[str, str] = {}
        self.provenance: Provenance | None = None
        self.statement_digest: str | None = None
        self.manifest: Manifest | None = None
        self.manifest_digest: str | None = None
        self.request: TransferRequest | None = None
        self.files: dict[str, FileView] = {}
        self.packers: list[str] = []  # trusted keys that signed the statement
        self.custody_check: chainlog.ChainCheck | None = None
        self.plugins: tuple[PluginStatus, ...] = ()
        self.analysis: Analysis | None = None  # this side's own analysis, for reports

    # --- trust ----------------------------------------------------------------------------------

    def resolve(self, key_id: str) -> VerifyKey | None:
        """A key this side knows: pinned in policy, or the command-line key if nothing is pinned."""
        signer = self.policy.signer(key_id)
        if signer is not None:
            return signer.load()
        if self.pubkey is not None and self.pubkey.key_id == key_id:
            return self.pubkey
        return None

    def _malformed(self, what: str, error: object = None) -> None:
        detail = {"file": what} | ({"error": str(error)} if error else {})
        self.recorder.fail(
            "integrity.bundle.malformed", self.subject, tool=TOOL, detail=detail, discriminator=what
        )

    def statement(self) -> None:
        """Check the signature, then read what was signed."""
        rules = ("integrity.signature.invalid", "integrity.signature.untrusted-key")
        path = self.bundle / layout.STATEMENT
        try:
            raw = path.read_bytes()
            envelope = Envelope.from_data(json.loads(raw))
            if envelope.payload_type != layout.STATEMENT_PAYLOAD_TYPE:
                raise ConfigError(f"unexpected payload type {envelope.payload_type!r}")
            subjects, provenance = layout.parse_statement(envelope.payload)
        except (OSError, ValueError, AirlockError) as exc:
            self._malformed(layout.STATEMENT, exc)
            self.recorder.not_assessed(
                rules, self.subject, tool=TOOL, reason="the signed statement could not be read"
            )
            return
        self.statement_digest = sha256_digest(raw)

        today = self.ctx.now.date()
        good, bad = envelope.verified_by(self.resolve)
        if bad:
            self.recorder.fail(
                "integrity.signature.invalid", self.subject, tool=TOOL, detail={"keyIds": [*bad]}
            )
        else:
            self.recorder.passed("integrity.signature.invalid")

        trusted, reasons = [], {}
        for key_id in good:
            signer = self.policy.signer(key_id)
            if signer is None:  # the command-line key
                trusted.append(key_id)
                self.recorder.fail(
                    "trust.signer.unpinned", self.subject, tool=TOOL, detail={"keyId": key_id}
                )
            elif problem := signer.problem(KeyRole.PACK, today, provenance.source):
                reasons[key_id] = problem
            else:
                trusted.append(key_id)
        if trusted:
            self.packers = trusted
            self.recorder.passed("integrity.signature.untrusted-key")
            # Only a statement signed by a trusted key says anything about the bundle.
            self.subjects, self.provenance = subjects, provenance
        else:
            self.recorder.fail(
                "integrity.signature.untrusted-key",
                self.subject,
                tool=TOOL,
                detail={
                    "signedBy": [s.key_id for s in envelope.signatures],
                    "reasons": dict(reasons) or "no signature from a key this side knows",
                },
            )

    def control_files(self) -> None:
        """Compare each signed file with the statement, and load the manifest and request."""
        contents: dict[str, bytes] = {}
        for name, expected in sorted(self.subjects.items()):
            if name not in layout.SIGNED_FILES:
                self._malformed(name, "statement names a file that is not part of a bundle")
                continue
            try:
                data = (self.bundle / name).read_bytes()
            except OSError as exc:
                self._malformed(name, exc)
                continue
            if sha256_digest(data) == f"sha256:{expected}":
                contents[name] = data
                self.recorder.passed("integrity.statement.subject-mismatch")
            else:
                self.recorder.fail(
                    "integrity.statement.subject-mismatch",
                    self.subject,
                    tool=TOOL,
                    detail={"file": name},
                    discriminator=name,
                )

        for item in sorted(self.bundle.iterdir()):
            uncovered = bool(self.subjects) and item.name in layout.SIGNED_FILES
            if item.name not in layout.BUNDLE_FILES or (
                uncovered and item.name not in self.subjects
            ):
                self.recorder.fail(
                    "integrity.entry.unexpected",
                    self.subject,
                    tool=TOOL,
                    detail={"file": item.name, "where": "bundle root"},
                    discriminator=item.name,
                )

        if layout.MANIFEST in contents:
            try:
                self.manifest = from_data(Manifest, json.loads(contents[layout.MANIFEST]))
                self.manifest_digest = sha256_digest(contents[layout.MANIFEST])
            except (ValueError, AirlockError) as exc:
                self._malformed(layout.MANIFEST, exc)
        elif self.subjects and layout.MANIFEST not in self.subjects:
            self._malformed(layout.MANIFEST, "the statement does not cover a manifest")
        if layout.REQUEST in contents:
            try:
                self.request = parse_request(contents[layout.REQUEST], layout.REQUEST)
            except AirlockError as exc:
                self._malformed(layout.REQUEST, exc)

    # --- content --------------------------------------------------------------------------------

    def payload(self) -> None:
        """Re-hash the payload and compare it, in both directions, with the manifest."""
        if self.manifest is None:
            self.recorder.not_assessed(
                _CONTENT_RULES, self.subject, tool=TOOL, reason="there is no trusted manifest"
            )
            return
        recorder, root = self.recorder, self.bundle / layout.PAYLOAD
        found = {s.path: s for s in scan("", root)} if root.is_dir() else {}
        matched = 0

        for entry in self.manifest.entries:
            subject = Subject.of_path(entry.path)
            if entry.carried:
                recorder.not_assessed(
                    ("integrity.hash.mismatch",),
                    subject,
                    tool=TOOL,
                    reason="carried from the base snapshot; delta resolution arrives in phase 1c",
                )
                continue
            if entry.entry_type not in (EntryType.FILE, EntryType.DIRECTORY):
                continue  # links and special files are recorded but never stored
            source = found.pop(entry.path, None)
            if source is None or source.entry_type is not entry.entry_type:
                recorder.fail(
                    "integrity.entry.missing",
                    subject,
                    tool=TOOL,
                    detail={"expected": entry.entry_type.value},
                )
                continue
            recorder.passed("integrity.entry.missing")
            matched += 1
            if entry.entry_type is EntryType.DIRECTORY:
                continue
            with source.location.open("rb") as stream:
                actual = hash_stream(stream, chunk_size=self.manifest.chunk_size)
            self.files[entry.path] = FileView(
                ArtifactRef(entry.path), source.location, actual.size, actual.sha256, self.files.get
            )
            if actual.sha256 == entry.sha256 and actual.size == entry.size:
                recorder.passed("integrity.hash.mismatch")
                continue
            damaged = [
                index
                for index, expected in enumerate(entry.chunks)
                if index >= len(actual.chunks) or actual.chunks[index] != expected
            ]
            recorder.fail(
                "integrity.hash.mismatch",
                subject,
                tool=TOOL,
                detail={
                    "expectedSha256": entry.sha256,
                    "actualSha256": actual.sha256,
                    "expectedSize": entry.size,
                    "actualSize": actual.size,
                    "damagedChunks": [*damaged],
                    "chunkSize": self.manifest.chunk_size,
                },
            )

        for path, source in sorted(found.items()):
            ref = ArtifactRef(path, unsafe=not source.safe)
            recorder.fail(
                "integrity.entry.unexpected",
                Subject.of_artifact(ref),
                tool=TOOL,
                detail={"type": source.entry_type.value},
            )
            if source.safe and source.entry_type is EntryType.FILE:
                with source.location.open("rb") as stream:
                    actual = hash_stream(stream)
                self.files[path] = FileView(
                    ref, source.location, actual.size, actual.sha256, self.files.get
                )
        recorder.passed("integrity.entry.unexpected", matched)

    def inspect(self, handlers: Sequence[Handler]) -> None:
        """Re-run inspection on everything present, with this side's handlers and limits."""
        # The request (verified with the statement) says which folders are knowledge-base corpora.
        corpora = self.request.corpora if self.request else ()
        with tempfile.TemporaryDirectory(prefix="airlock-") as scratch:
            analyzer = Analyzer(replace(self.ctx, corpora=corpora), handlers, Path(scratch))
            for view in self.files.values():
                analyzer.analyze(view)
            analysis = finish(analyzer, default_assemblers())
        self.analysis = analysis
        self.plugins = run_scanners(self.ctx, targets(self.files.values()), analysis)
        if self.manifest is not None:
            check_paths(self.manifest.entries, self.ctx)
            check_request(self.request, self.manifest.entries, self.ctx)
            check_request_units(self.request, analysis.units, self.ctx)

    # --- history --------------------------------------------------------------------------------

    def custody(self) -> None:
        if self.provenance is None:
            self.recorder.not_assessed(
                ("integrity.custody.broken",),
                self.subject,
                tool=TOOL,
                reason="there is no trusted statement to anchor the custody log to",
            )
            return
        # Anyone handling the bundle may append to this log, so an event from an unknown
        # signer is not damage: it simply carries no weight. Damage is a broken chain, a
        # signature that does not verify, or a first event that is not the packer's.
        try:
            events = chainlog.read(self.bundle / layout.CUSTODY)
            self.custody_check = chainlog.verify(events, self.resolve)
            problems = list(self.custody_check.broken)
        except AirlockError as exc:
            events, problems = [], [str(exc)]
        first = events[0] if events else None
        if first is None:
            problems.append("the custody log is missing or empty")
        elif (
            first.type != layout.EVENT_PACKED
            or first.actor not in self.packers
            or self.custody_check is None
            or first not in self.custody_check.verified
            or first.data.get("manifestDigest") != self.manifest_digest
            or first.data.get("statementDigest") != self.statement_digest
            or first.data.get("bundleId") != self.provenance.bundle_id
        ):
            problems.append("the first event is not the 'packed' event for this bundle")
        if problems:
            self.custody_check = None  # approvals in a damaged log are not counted
            self.recorder.fail(
                "integrity.custody.broken",
                self.subject,
                tool=TOOL,
                detail={"problems": [*problems]},
            )
        else:
            self.recorder.passed("integrity.custody.broken")

    def approvals(
        self, findings: Sequence[Finding], decisions: Sequence[Decision]
    ) -> tuple[set[str], tuple[ApprovalRecord, ...]]:
        if self.custody_check is None:
            return set(), ()
        return count_approvals(
            self.custody_check,
            policy=self.policy,
            manifest_digest=self.manifest_digest,
            packers=self.packers,
            findings=findings,
            decisions=decisions,
            today=self.ctx.now.date(),
        )

    def history(self, ledger: Ledger | None) -> None:
        if ledger is not None:
            signed = bool(self.policy.signers_with_role(KeyRole.RECEIPT))
            problems = ledger.load(self.resolve, require_signed=signed)
            if problems:
                self.recorder.fail(
                    "integrity.ledger.broken",
                    self.subject,
                    tool=TOOL,
                    detail={"problems": [*problems]},
                )
            else:
                self.recorder.passed("integrity.ledger.broken")
        check_policy(self.ctx)
        if self.provenance is not None:
            base = self.manifest.base if self.manifest else None
            check_transfer(self.provenance, base, ledger, self.ctx)


def verify(
    bundle: Path,
    *,
    policy: Policy,
    pubkey: VerifyKey | None = None,
    state: Path | None = None,
    receipt_signer: Signer | None = None,
    out: Path | None = None,
    handlers: Sequence[Handler] | None = None,
    now: datetime | None = None,
) -> VerifyResult:
    """Verify ``bundle`` against ``policy``.

    ``state`` is this side's state directory; with it, the import is checked against, and then
    recorded in, the ledger. ``out`` receives the assessment and receipt (default: under ``state``).
    """
    if not (bundle / layout.DESCRIPTOR).is_file():
        raise ConfigError(f"not an airlock bundle (no {layout.DESCRIPTOR}): {bundle}")
    if pubkey is not None and policy.signers_with_role(KeyRole.PACK):
        raise ConfigError("the policy pins its own pack signers; --pubkey cannot add another")
    now = now or utc_now()
    session = Session.start(policy, now)
    ledger = Ledger(state) if state is not None else None

    verifier = _Verifier(bundle, policy, pubkey, session.ctx)
    verifier.statement()
    verifier.control_files()
    verifier.payload()
    verifier.inspect(handlers or default_handlers())
    verifier.custody()
    verifier.history(ledger)

    assessment = session.finish(
        Stage.VERIFY,
        manifest_digest=verifier.manifest_digest,
        content_hashes={path: view.sha256 for path, view in verifier.files.items() if view.sha256},
        approvals=verifier.approvals,
        plugins=verifier.plugins,
    )
    assessment_bytes = layout.encode(assessment)

    receipt: Receipt | None = None
    provenance = verifier.provenance
    if provenance and verifier.manifest_digest and verifier.statement_digest:
        receipt = Receipt(
            bundle_id=provenance.bundle_id,
            manifest_digest=verifier.manifest_digest,
            statement_digest=verifier.statement_digest,
            assessment_digest=sha256_digest(assessment_bytes),
            policy_digest=policy.digest,
            verdict=assessment.summary.verdict,
            verified_at=now,
            bundle_created_at=provenance.created_at,
            enclave=policy.identity.enclave if policy.identity else None,
            source=provenance.source,
            stream=provenance.stream,
            request_id=provenance.request_id,
            verifier_key_id=receipt_signer.key_id if receipt_signer else None,
        )
        if ledger is not None:
            ledger.append(receipt, now=now, signer=receipt_signer)

    outputs: list[Path] = []
    if out is None and state is not None and receipt is not None:
        out = state / "imports" / f"{now:%Y%m%dT%H%M%SZ}-{receipt.bundle_id[:12]}"
    if out is not None:
        out.mkdir(parents=True, exist_ok=True)
        outputs.append(out / "assessment.verify.json")
        outputs[-1].write_bytes(assessment_bytes)
        if verifier.analysis is not None:  # re-derived here; what reports on this import read
            outputs.append(out / "analysis.verify.json")
            outputs[-1].write_bytes(layout.encode(verifier.analysis))
        if verifier.request is not None and (bundle / layout.REQUEST).is_file():
            outputs.append(out / layout.REQUEST)
            outputs[-1].write_bytes((bundle / layout.REQUEST).read_bytes())
        if receipt is not None:
            payload = layout.encode(receipt)
            if receipt_signer is not None:
                envelope = sign_envelope(layout.RECEIPT_PAYLOAD_TYPE, payload, receipt_signer)
                outputs.append(out / "receipt.dsse.json")
                outputs[-1].write_bytes(canonical_bytes(envelope.to_data()))
            else:
                outputs.append(out / "receipt.json")
                outputs[-1].write_bytes(payload)
    return VerifyResult(assessment, provenance, receipt, tuple(outputs), verifier.analysis)
