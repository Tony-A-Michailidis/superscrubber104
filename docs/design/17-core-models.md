# 17. Core data models and policy schema

> **Status: ACCEPTED (2026-11-10).** The recommended answer to each of Q1–Q8 (listed at the end) was adopted.

This covers task 3 ([§20](14-roadmap.md)): the shared core that every module (pack/verify, patch, eval, controls-as-code, gateway) builds on. Concepts come from [§5](03-core-concepts.md).

## 17.1 Implementation choices

- **Stdlib `dataclasses` (frozen, slotted) plus hand-written validation.** No pydantic. Pydantic would be one more compiled wheel to carry across the airlock and keep pinned, and our schemas are small. Validation errors give the YAML path (`rules[3].disposition: expected one of ...`).
- **Canonical JSON for everything that is hashed or signed.** UTF-8, sorted keys, no insignificant whitespace, integers only (no floats), NFC-normalised strings. This is the RFC 8785 (JCS) subset that our data needs.
- **Determinism.** Same inputs give byte-identical `manifest.json`, `sbom.cdx.json` and findings. Timestamps, hostnames and tool run IDs live only in the custody log and the assessment header, never in the manifest (see **Q1**).
- **Paths.** Bundle-relative, POSIX separators, NFC, no `..`, no absolute paths, no drive letters. Case collisions (`A.txt` vs `a.txt`) are a finding, because the high side may be case-insensitive (Windows staging).
- **Hashes.** `sha256` is mandatory and the primary identity. Other algorithms (`sha512`, `md5`) are computed only when needed to check an upstream claim (Glance `os_hash_value`, publisher md5), in the same streaming pass.
- **Schema versioning.** Every serialised document carries `apiVersion: airlock/v1alpha1` and `kind`. We stay on `v1alpha1` until phase 1a is finished.

## 17.2 Enumerations

```python
class Severity(StrEnum):        # how bad, if it's a problem; set by the rule
    CRITICAL, HIGH, MEDIUM, LOW, INFO

class Result(StrEnum):          # what the check observed
    PASS          # check ran, condition not present
    FAIL          # check ran, condition present
    NOT_ASSESSED  # check could not run (plugin absent, encrypted, over size limit, unsupported)
    ERROR         # check crashed or got malformed input; treated at least as NOT_ASSESSED

class Disposition(StrEnum):     # what policy decides to do about a FAIL / NOT_ASSESSED
    ALLOW, WARN, REQUIRE_APPROVAL, BLOCK
```

**Checks observe; policy decides.** A check never says "this is a blocker". It emits `Result` + `Severity`, and the policy engine assigns the `Disposition`. That keeps one rule set across pack, verify, phase 2 and the phase 3 gateway, and lets the high side reach its own decision on the same findings with its own policy.

## 17.3 Artifact

One file, directory entry or archive member.

```python
@dataclass(frozen=True, slots=True)
class ArtifactRef:
    path: str                    # bundle-relative, e.g. "models/qwen/model-00001-of-00004.safetensors"
    member: tuple[str, ...] = () # path inside nested archives: ("layer.tar", "usr/bin/x")
    # display form: "images/app.tar!/layer.tar!/usr/bin/x"

@dataclass(frozen=True, slots=True)
class Artifact:
    ref: ArtifactRef
    entry_type: EntryType        # FILE | DIRECTORY | SYMLINK | HARDLINK | OTHER (device, fifo: always a finding)
    size: int
    hashes: Mapping[str, str]    # {"sha256": "...", ...}
    link_target: str | None      # symlinks are recorded, never followed
    media_type: str | None       # detected from content, not extension
    kind: str                    # handler classification, e.g. "model.safetensors", "archive.tar", "unclassified"
    handler: ToolRef | None      # name + version of the handler that classified it
    metadata: Mapping[str, JSON] # handler-specific (safetensors header summary, GGUF kv, wheel tags...)
```

`kind` is a dotted string, not an enum. Handlers own their namespace, and new types don't need core changes.

## 17.4 Component (SBOM)

Maps directly onto a CycloneDX 1.6 component, so the SBOM writer is a straight transform.

```python
@dataclass(frozen=True, slots=True)
class Component:
    bom_ref: str                 # deterministic: derived from purl or kind+name+version+first artifact hash
    type: ComponentType          # CycloneDX: application, library, framework, container, operating-system,
                                 # device-driver, firmware, file, machine-learning-model, data
    name: str
    version: str | None
    purl: str | None             # pkg:pypi/numpy@2.1.0, pkg:huggingface/org/name@<commit>, pkg:oci/...
    licenses: tuple[LicenseRef, ...]   # SPDX id/expression, or named custom licence (Llama, Gemma...)
    supplier: str | None
    hashes: Mapping[str, str]
    upstream: UpstreamRef | None # source reference: HF repo+commit, Ollama manifest digest, vendor URL+checksum
    evidence: tuple[ArtifactRef, ...]  # the artifacts this component was identified from
    children: tuple[str, ...]    # bom_refs of nested components
    properties: Mapping[str, str]      # CycloneDX properties (airlock:* namespace)
```

## 17.5 Units

A unit is a typed set of artifacts that only works as a whole.

```python
@dataclass(frozen=True, slots=True)
class UnitMember:
    role: str                    # "weights-shard", "weights-index", "tokenizer", "chat-template", "config", "lockfile", "wheel", ...
    artifact: ArtifactRef

@dataclass(frozen=True, slots=True)
class Unit:
    id: str                      # deterministic: f"{kind}:{root path}"
    kind: UnitKind               # MODEL_PACKAGE | RUNTIME_PROFILE | PYTHON_ENVIRONMENT | NODE_ENVIRONMENT |
                                 # REPO_MIRROR | CONTAINER_IMAGE | VM_IMAGE | PATCH_SET | KNOWLEDGE_BASE
    name: str
    root: str                    # bundle-relative directory or file that anchors the unit
    members: tuple[UnitMember, ...]
    components: tuple[str, ...]  # bom_refs
    attributes: Mapping[str, JSON]  # kind-specific record; typed accessors per kind (see below)
```

**How units form (two stages):**
1. While inspecting an artifact, a handler emits `UnitClaim(kind, root, role, artifact, facts)`. For example, the safetensors handler claims "shard 2 of the model package rooted at `models/qwen/`".
2. After the walk, one **`UnitAssembler` per kind** collects the claims for each root, builds the `Unit`, and runs the **unit-level checks**: completeness and consistency, such as shards against the index or the tokenizer's vocab size against the config.

Typed views give type-safe access without fragmenting serialisation, e.g. `ModelPackageView(unit).shards` or `.chat_template_sha256`. In 1a: `MODEL_PACKAGE`, `PYTHON_ENVIRONMENT`, `NODE_ENVIRONMENT` and `CONTAINER_IMAGE`. The other kinds are declared but have no assembler yet.

## 17.6 Finding and assessment

```python
@dataclass(frozen=True, slots=True)
class Finding:
    id: str                      # deterministic: sha256(rule_id, subject, discriminator)[:16]
    rule: str                    # "model.pickle.dangerous-import"
    rule_version: str
    result: Result
    severity: Severity
    subject: Subject             # one of: artifact ref | unit id | bundle | request
    title: str
    detail: Mapping[str, JSON]   # e.g. {"imports": ["os.system"], "opcode_offset": 1042}
    controls: tuple[str, ...]    # ["SI-3", "SR-10"]; copied from the rule registry so evidence stands alone
    tool: ToolRef                # airlock handler, or plugin name+version+db version
    not_assessed_reason: str | None

@dataclass(frozen=True, slots=True)
class Decision:                  # policy engine output, one per finding
    finding: str                 # finding id
    disposition: Disposition
    matched: str                 # which policy entry decided it: "rules[4]", "waivers[1]", "defaults.severity.high"
    approvals_required: int
    waiver: str | None

@dataclass(frozen=True, slots=True)
class Assessment:                # one run of pack or verify
    tool: ToolRef
    stage: Stage                 # PACK | VERIFY | OFFLINE_CHECK | ...
    started_at, finished_at: datetime   # UTC; the only timestamps (see Q1)
    policy_digest: str
    plugins: tuple[PluginStatus, ...]   # every plugin: present/absent, version, binary sha256, db age
    findings: tuple[Finding, ...]
    decisions: tuple[Decision, ...]
    summary: Summary             # counts by result/disposition, overall verdict
```

**Rule registry.** Every check is declared in a registry (`id`, `version`, `title`, default `severity`, `controls`, `rationale`, `remediation`). Findings can only be created from a registered rule, so a check can't ship without a control mapping, and the registry renders straight into docs.

Rule IDs are dotted, stable, lowercase: `<domain>.<subject>.<condition>`, e.g. `integrity.hash.mismatch`, `request.artifact.undeclared`, `archive.path-traversal`, `model.remote-code.required`, `model.package.shard-missing`, `offline.telemetry.enabled`.

## 17.7 Transfer request

```yaml
apiVersion: airlock/v1alpha1
kind: TransferRequest
metadata:
  id: TR-2026-0042
  title: Initial delivery of local RAG assistant
spec:
  purpose: Deploy local RAG assistant v1.0 to disconnected enclave
  owner: { name: Jane Example, contact: jane@example.org }
  source: dev-unclass
  destination: enclave-b
  direction: low-to-high              # only value accepted in phase 1
  approvers:
    - { name: A. Reviewer, role: security, key_id: "ed25519:4f2c…" }
  allowUndeclared: false              # undeclared artifact => finding request.artifact.undeclared
  contents:
    - name: qwen-7b-instruct
      unit: model-package
      paths: ["models/qwen2.5-7b-instruct/**"]
      upstream: { huggingface: Qwen/Qwen2.5-7B-Instruct, revision: a09a3545... }
    - name: app
      paths: ["app/**"]
    - name: wheelhouse
      unit: python-environment
      paths: ["wheels/**", "app/requirements.lock"]
```

Verify reports `request.content.missing` (declared but absent, or the declared unit kind was not formed) and `request.artifact.undeclared`.

## 17.8 Bundle layout and signing

```
bundle/
  airlock-bundle.json      # {apiVersion, kind: Bundle, manifestDigest, layout version}
  manifest.json            # deterministic: artifacts, units, request digest, policy digest
  sbom.cdx.json            # CycloneDX 1.6 incl. ML-BOM
  assessment.pack.json     # low-side findings + decisions (informational on the high side)
  request.yaml             # verbatim copy of the transfer request
  manifest.dsse.json       # DSSE envelope, ed25519 signature
  custody.jsonl            # hash-chained, individually signed events
  payload/                 # artifacts stored as-is at their bundle paths
```

- **Signature format: DSSE** (the in-toto envelope). The payload is an in-toto Statement whose subjects are the digests of `manifest.json`, `sbom.cdx.json`, `assessment.pack.json` and `request.yaml`. DSSE is small enough to implement natively (PAE + ed25519), it's a standard, and it lines up with the later cosign/Sigstore work.
- **Keys:** ed25519, PKCS#8 / SubjectPublicKeyInfo PEM via `cryptography`. `key_id = "ed25519:" + sha256(raw public key)[:16]`.
- **Payload stored as-is** in 1a, so reviewers can inspect it with ordinary tools. Multi-volume packing (1b) adds a `volumes/` layer without changing the manifest.
- **Custody log** (separate from the manifest; see **Q4**): JSON Lines, where each event is `{seq, prev, event, manifestDigest, actor key_id, at, data, sig}`. Events: `packed`, `reviewed`, `approved` (finding IDs + justification), `media-written` (media ID, per-volume hashes), `verified`, `staged`, `receipt`. Appending an approval doesn't touch the signed manifest.
- **Receipt:** a signed `Receipt` document recording the manifest digest, the verify assessment digest, the high-side policy digest, the verifier key ID and time. It contains hashes only, so it is safe to send back outbound if policy allows.

**Exit codes:** `0` no blockers · `1` blocking findings or unapproved `REQUIRE_APPROVAL` · `2` usage or config error · `3` integrity failure (bad signature, hash mismatch, broken custody chain). Integrity failure is kept separate from policy failure because it means tampering, not judgement.

## 17.9 Interfaces

```python
class ArtifactView(Protocol):    # what a handler is allowed to see; no filesystem access beyond this
    ref: ArtifactRef; size: int; hashes: Mapping[str, str]
    def head(self, n: int = 65536) -> bytes: ...
    def open(self) -> BinaryIO: ...            # read-only stream
    def sibling(self, name: str) -> ArtifactView | None: ...  # e.g. find model.safetensors.index.json

class Handler(Protocol):
    name: str; version: str
    kinds: frozenset[str]                       # kinds this handler can produce
    def detect(self, a: ArtifactView) -> Detection | None: ...   # cheap: magic bytes + name; returns kind + confidence
    def inspect(self, a: ArtifactView, ctx: Context) -> Inspection: ...
        # one streaming pass -> metadata, components, unit claims, findings

class UnitAssembler(Protocol):
    kind: UnitKind
    def assemble(self, claims: Sequence[UnitClaim], ctx: Context) -> Iterable[tuple[Unit, list[Finding]]]: ...

class Plugin(Protocol):          # wrapper around an external scanner/tool
    name: str
    def status(self, ctx: Context) -> PluginStatus: ...  # present? version, binary sha256, db version/age
    # concrete capability protocols: MalwareScanner, SastScanner, SecretScanner, SbomGenerator, ImageInspector

class Stager(Protocol):
    name: str
    def accepts(self, unit_or_artifact) -> bool: ...
    def stage(self, bundle: VerifiedBundle, target: Mapping[str, JSON]) -> StageResult: ...
```

`Context` carries the policy, limits, the rule registry, a finding factory (so findings always come from registered rules), and plugin lookup.

**Dispatch:** every handler's `detect()` runs, and the highest-confidence match wins. Ties go to the more specific kind, then to registration order. The generic handler always runs as well (hash, secrets, malware plugin), so "unclassified" is just "generic only". **Q2** covers the deviation from the five-method handler interface in the brief.

**Plugins and "trust nothing that crosses":** the policy can pin plugin binaries by sha256. If a binary is present but doesn't match the pin, that is a `BLOCK`-able finding (`plugin.binary.unpinned`) and the plugin is not run. Its checks are then reported as `NOT_ASSESSED`.

## 17.10 Policy YAML schema

The policy is a single document. Low and high side each have their own, and verify always uses the high side's.

```yaml
apiVersion: airlock/v1alpha1
kind: Policy
metadata:
  name: enclave-b-import
  version: "2026.11.1"            # recorded in every assessment (with the file digest)

defaults:
  severity:                       # FAIL result -> disposition, unless a rule/waiver says otherwise
    critical: block
    high: block
    medium: require-approval
    low: warn
    info: allow
  notAssessed: warn               # check couldn't run; per-rule override available
  error: require-approval
  approvals: 1                    # signatures needed to clear a require-approval

rules:                            # first match wins (firewall semantics, see Q3)
  - rule: "model.pickle.*"
    disposition: block
  - rule: "model.remote-code.required"
    disposition: require-approval
    approvals: 2
  - rule: "offline.*"
    paths: ["dev-tools/**"]       # optional scope: artifact/unit root globs
    disposition: warn
  - rule: "malware.*"
    notAssessed: block            # e.g. ClamAV must actually run on import

waivers:                          # standing exceptions, pinned to exact content
  - id: W-2026-007
    rule: "container.user.root"
    subject: "images/legacy-ingest.tar"
    sha256: "9f86d08…"            # waiver lapses automatically if content changes
    justification: Vendor image; runs in an isolated namespace
    approvedBy: "ed25519:4f2c…"
    expires: 2027-03-31           # expired waiver => finding policy.waiver.expired

trust:
  signers:                        # keys accepted for bundle signatures and custody events
    - keyId: "ed25519:4f2c…"
      publicKey: keys/lowside-pack.pub
      sha256: "…"                 # every referenced key file is pinned
      roles: [pack]
    - keyId: "ed25519:a91b…"
      publicKey: keys/security-officer.pub
      sha256: "…"
      roles: [approve, receipt]
  upstream:                       # vendor/publisher keys (phase 1a: recorded; verification grows per handler)
    - name: almalinux-9
      type: gpg                   # gpg | x509 | sigstore | checksum-list
      file: keys/RPM-GPG-KEY-AlmaLinux-9
      sha256: "…"
      scope: ["rpm", "repomd"]

licences:
  allow: [Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC, PSF-2.0]
  requireApproval: [LicenseRef-llama3.1, LicenseRef-gemma, MPL-2.0, LGPL-*]
  deny: [AGPL-3.0-*, SSPL-1.0]
  unknown: require-approval

allowlists:                       # anti-slopsquatting / approved sources; mode: enforce | report
  python: { mode: enforce, file: allow/python.txt, sha256: "…" }   # name==ver or name specifiers
  npm:    { mode: report,  packages: ["react@^18", "zod"] }
  models:
    mode: enforce
    entries:
      - { id: "huggingface:Qwen/Qwen2.5-7B-Instruct", revision: "a09a3545…" }
  mcpServers: { mode: enforce, entries: [] }

limits:
  archive:
    maxDepth: 4
    maxMembers: 200000
    maxRatio: 200                 # expansion ratio (zip-bomb)
    maxExpandedBytes: 500GiB
  maxArtifactBytes: 1TiB
  maxPathLength: 1024

plugins:                          # optional scanners; pinned like any crossing artifact
  clamav:
    required: false               # true => absence is a finding with notAssessed disposition
    binarySha256: "…"
    maxDbAge: 7d
  gitleaks: { required: false }

freshness:                        # 1c; parsed now so the schema is stable
  feeds: { default: 7d, kev: 2d }

controls:
  framework: nist-800-53r5        # built-in catalogue; ITSG-33 aligns
  overrides:                      # add or replace control IDs per rule
    "offline.*": ["SC-7", "AC-4", "CM-6"]
```

**Evaluation order for each finding:** a `PASS` is always `ALLOW`. Otherwise, apply the first matching unexpired **waiver** whose sha256 still matches. If there is none, apply the first matching **rule**. If no rule matches, use **defaults**: `severity` for a `FAIL`, `notAssessed`/`error` otherwise. The decision records which entry matched (`rules[3]`), so every outcome can be traced back to one policy line.

**Policy hygiene:** referenced files (`keys/…`, `allow/…`) resolve relative to the policy file and **must** be pinned by sha256. The policy digest covers the policy file and every file it references. Unknown keys are an error, not ignored, because a typo like `dispositon: block` must not silently weaken a policy.

I'll also generate JSON Schema for the policy and the transfer request, so editors can validate them while they're being written.

## 17.11 Proposed module placement

```
src/airlock/
  core/
    model.py        # Artifact, Component, Unit, Finding, Decision, Assessment, enums
    request.py      # TransferRequest + loader/validator
    policy.py       # Policy + loader/validator + evaluator
    rules.py        # rule registry, RuleSpec
    controls.py     # control catalogue + mapping (data in core/data/nist-800-53r5.yaml)
    canonical.py    # canonical JSON
    signing.py      # ed25519 keys, DSSE
    custody.py      # hash-chained log
    receipt.py
    interfaces.py   # ArtifactView, Handler, UnitAssembler, Plugin, Stager, Context
```

## Decisions (Q1–Q8, recommendations adopted)

- **Q1 Timestamps.** The brief puts a timestamp on every finding, but that breaks "same inputs, same output". I propose keeping timestamps only on the `Assessment` (run start/finish) and on custody events, since findings belong to exactly one assessment. Is that acceptable for the evidence you'd hand an assessor?
- **Q2 Handler interface.** The brief lists `detect/inventory/components/units/checks`. I propose `detect()` plus a single `inspect()` that returns all four results, because a multi-hundred-GB shard should be read once, not four times. Accept?
- **Q3 Rule matching.** First match wins (firewall-style, easy to audit) versus most specific match wins (more forgiving of ordering). I recommend first match. Agree?
- **Q4 Approvals and custody** (open decision in [§21](16-open-decisions.md)). I recommend a separate hash-chained, per-event signed `custody.jsonl` that references the manifest digest, so the manifest is signed once and never re-signed. Standing exceptions go in the policy `waivers`; per-bundle approvals go in custody events. Agree?
- **Q5 Envelope format.** DSSE + in-toto Statement (standard, cosign-aligned) versus a simpler bespoke `{payload, sig}`. I recommend DSSE.
- **Q6 Two-person sign-off.** Model it generally (`approvals: N`, distinct key IDs with the `approve` role) rather than as a special emergency profile. Agree?
- **Q7 Schema naming.** Kubernetes-style `apiVersion`/`kind`/`metadata`/`spec` for the request, and a flatter shape for the policy. Is that consistent enough, or should the policy also use `spec`?
- **Q8 Case-insensitive collisions.** Treat as `HIGH` by default (Windows/WSUS staging targets), downgradable by policy?
