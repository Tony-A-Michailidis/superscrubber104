# 17. Core data models and policy schema

> **Status: implemented** in `src/superscrubber104/core/` (revision 3, 2026-11-10).
> Revision 1 was reviewed against the brief and found to need structural changes. [§17.12](#1712-review-resolutions) lists each review item and what was done about it.
> The bundle format and the verification procedure built on these models are in [18-bundle-and-verification.md](18-bundle-and-verification.md).

This is the shared core that every module (pack/verify, patch, eval, controls-as-code, gateway) builds on. Concepts come from [§5](03-core-concepts.md).

## 17.1 Ground rules

- **Stdlib frozen dataclasses with hand-written validation.** No pydantic: it would be one more compiled wheel to carry across the airlock. Validation errors name the document path (`rules[3].disposition: 'maybe' is not one of ...`).
- **Two layers, kept apart.**
  - *Integrity* (`Manifest`, `Entry`): paths, sizes, hashes. Independent of tool version, policy and time. Its digest identifies content and nothing else. This is what is signed and re-checked.
  - *Interpretation* (`Analysis`, `Artifact`, `Unit`, `Component`): what the content is. It depends on the tool version, so the receiving side regenerates it and never trusts the packer's copy. The analysis and the assessment record, once each, the Python version and whether zstd could be read (`tool.extra`), because the same tool version reads more on an interpreter that has zstd.
- **Checks observe; policy decides.** A check reports a `Result` and a `Severity`. Only the policy engine assigns a `Disposition`. The receiving side therefore reaches its own decision with its own policy.
- **Two classes of rule.** *Integrity and authenticity* failures (hash mismatch, bad or missing signature, replay, wrong enclave) can never be waived, lowered or overridden. If they could, the airlock would not be a control. *Policy blockers* (a pickle model, remote code, a licence, an unapproved package) can be overridden for one bundle, but only by a quorum of approvers with a written justification, never by the packer, and the override is recorded as signed evidence. See [§17.7](#177-policy).
- **Canonical JSON** for every document that is hashed or signed: UTF-8, sorted keys, no whitespace, NFC strings, **no floats**. Numbers that are not integers are carried as decimal strings; `canonical.jsonable()` coerces handler metadata (floats, bytes, sets) at the boundary.
- **Digests are taken over bytes on disk.** Nothing is parsed and re-serialised before being checked, so two tool versions can never disagree about what a signature covers.
- **Algorithm agility.** Digests are `<algorithm>:<hex>` (`sha256`, `sha384`, `sha512` accepted); key ids are `<algorithm>:<fingerprint>`. sha256 and Ed25519 are the only ones produced today. Confirm both against the destination's approved-algorithm list before publishing.
- **Version skew.** The receiving side must be able to read only three things written by the other side: the signed statement, the manifest and the transfer request. Those are kept small and strict, and the statement and manifest each have an `extensions` map for forward-compatible additions. The packer's analysis and assessment are hash-checked but never parsed, so they can change freely between versions. A policy may carry an `extensions:` section that this version ignores (but that is still covered by the policy digest).

## 17.2 Enumerations

| Enum | Values |
|---|---|
| `Severity` | critical, high, medium, low, info |
| `Result` | pass, fail, not-assessed (could not run), error (check crashed) |
| `Disposition` | allow < warn < require-approval < block |
| `Verdict` | passed, needs-approval, blocked (a policy blocker stands; overridable), refused (an integrity or authenticity failure; final) |
| `TrustLevel` | none < asserted < checksum < pinned-checksum < signature |
| `EntryType` | file, directory, symlink, hardlink, other |
| `UnitKind` | model-package, runtime-profile, python-environment, node-environment, jvm-environment, go-environment, rust-environment, dotnet-environment, terraform-environment, repo-mirror, container-image, vm-image, patch-set, knowledge-base, dataset |
| `SubjectKind` | artifact, unit, component, bundle, request, policy, host (phase 2), tool-call (phase 3) |

Artifact kinds are dotted strings (`archive.zip`, `model.safetensors`), not an enum: handlers own their namespace.

## 17.3 Integrity layer

```python
ArtifactRef(path, member=(), unsafe=False)   # "images/app.tar!/layer.tar!/usr/bin/x"

Entry(path, entry_type, size, hashes, chunks, link_target, carried)

Manifest(entries, chunk_size, base=None, extensions={})
```

- **`ArtifactRef.unsafe`** marks a reference whose name is hostile or unrepresentable (`../../etc/passwd`, a backslash, undecodable bytes, non-NFC Unicode). The name is stored percent-escaped. Such a reference can be inventoried and can be the subject of a finding, but is never turned into a filesystem path. Without this, the very members an archive check exists to report could not be recorded.
- **`Entry.chunks`** holds one sha256 per `Manifest.chunk_size` bytes (64 MiB by default) for files larger than one chunk. Verification can then say *where* a large file is damaged; resumable verification and splitting a file across volumes build on the same hashes.
- **No file modes** in `Entry`: removable media and Windows hosts do not preserve them, so they cannot be verified after transfer. Modes inside archives are covered by the archive's hash and are recorded in the analysis.
- **Symlinks** are recorded with their target and are never followed or recreated.
- **Delta bundles**: the manifest always lists the *full* state. Entries marked `carried` are unchanged from the accepted snapshot named by `base`. Completeness is therefore always judged on the whole state, and deletions are implicit. (Packing and resolving deltas is phase 1c; the fields and the base check exist now.)
- The manifest has no timestamps, host details, tool versions, policy digest or request digest. The same content always gives the same bytes.

## 17.4 Interpretation layer

```python
Artifact(ref, entry_type, size, kinds, hashes, link_target, mode,
         media_type, handlers, metadata, verifications)

Verification(type, level: TrustLevel, result, signer, anchor, detail)

Component(bom_ref, type, name, version, purl, licenses, supplier, hashes, upstream,
          evidence, children, depends_on, verifications, properties)

UnitMember(role, artifact, sha256)
Requirement(relation, name, kind, digest, version, satisfied_by)
Unit(kind, name, root: ArtifactRef, members, requires, components, attributes)

Analysis(tool, artifacts, units, components)
```

- **`Artifact.kinds`** is a tuple, most confident first. Every handler whose `detect()` matches runs, so a polyglot (an executable that is also a model file, a wheel that is also a zip) is inspected as each thing it is.
- **`Verification`** records what was actually checked for the second layer of trust (vendor GPG, Authenticode, publisher checksum, model signature, Glance), which pinned anchor was used, and how strong the result is. `UpstreamRef` on its own is only a claim by the packing side: a repository revision is `asserted`, a digest pinned in the receiver's own policy is `pinned-checksum`, a signature verified against a pinned key is `signature`. Policy sets the minimum level per artifact kind (`trust.minimum`).
- **`Unit.root`** is an `ArtifactRef`, so a unit can live inside an archive (a model in a container layer).
- **`Unit.requires`** expresses what a unit needs beyond its own members: an adapter's base model, a knowledge base's embedding model, the runtime a model was tested on, an image a Helm chart references. `satisfied_by` is a unit id in this bundle, `high-side:<reference>` when a receiving-side inventory supplies it, or empty (a completeness finding).
- **`Unit.digest`** is computed from the kind and the sorted `(role, sha256)` of the members. It is independent of location, so it pins a unit in an allowlist or waiver, links an adapter to its base model, and compares a unit across bundles.
- **`Component.depends_on`** carries the dependency graph (for closure checks); `evidence` lists every place a component occurs.

**How units form:** a handler emits `UnitClaim(kind, root, role, artifact, sha256, facts)` while inspecting an artifact. After the walk, one `UnitAssembler` per kind groups the claims by root, builds the unit and records completeness and consistency findings. Checks that need the whole picture (cross-unit requirements) then run in `analysis.finish`.

## 17.5 Findings and assessments

```python
Subject(kind, artifact | unit | component | name, locator)
Finding(id, rule, rule_version, result, severity, subject, title, controls, tool,
        detail, attributes, not_assessed_reason)
Decision(finding, disposition, matched, approvals_required, waiver, final)
Coverage(rule, rule_version, controls, passed, failed, not_assessed, errors)
Assessment(tool, stage, started_at, finished_at, policy_digest, manifest_digest,
           summary, plugins, coverage, findings, decisions, approvals)
Approval(manifest_digest, finding, finding_digest, justification)   # what an approver signs
ApprovalRecord(finding, key_id, holder, justification, counted, reason)   # what the verifier made of it
```

- **Rule registry.** Every check is declared as a `RuleSpec` (id, version, title, severity, controls, rationale, remediation, `final`, tags). A finding can only be created from a registered rule, so no check ships without a control mapping. Built-in rules are in `superscrubber104/catalog.py`.
- **`RuleSpec.final`** marks the integrity and authenticity rules. A FAIL or ERROR of a final rule is always `block`, and the decision is itself marked `final`: no policy rule, default, waiver or approval changes it. The final rules are:
  - `integrity.*`: hash mismatch, missing or unexpected content, bad or missing signature, untrusted key, edited control files, broken custody log or ledger
  - `replay.bundle.*`, `replay.clock.regression`, `delta.base.unknown`: replayed, out-of-order or stale bundles, a clock that has gone backwards, a delta on an unknown base
  - `transfer.destination.*`, `transfer.source.unaccepted`: a bundle addressed to another enclave, bound to none, or from a source this enclave does not accept
  - `path.name.unsafe`: the file could not be stored at all, so there is nothing an approval could apply to

  Everything else, including archive path traversal, is a matter for policy.
- **Passes are counts, not findings.** `Recorder.passed(rule, n)` increments a counter; only non-passes are individual findings. `Assessment.coverage` has one row for *every* registered rule, so a rule that never ran is visible as such instead of silently absent. A bundle of a million files does not produce a million rows.
- **`Finding.attributes`** are string facets (`cve`, `kev`, `mcp.server`, `mcp.tool`, `class`) that policy `where` clauses select on.
- **`Subject.locator`** narrows a subject to a place inside it (line, byte offset, JSON pointer, tool name).
- **Finding ids** are deterministic: `sha256(rule, subject, discriminator)[:16]`. **`finding_digest()`** covers the rule and its version, the subject, the result and everything that was found (detail and attributes). It leaves out the reporting tool's version and presentation, so an approval given on one side still matches the same finding recomputed by a newer tool on the other. Approvals bind to the digest, so an approval lapses if what was found changes even though the id is the same.
- **Timestamps** exist only on the assessment (run start and finish) and on log events, never on individual findings, so findings stay reproducible.

## 17.6 Transfer request

```yaml
apiVersion: superscrubber104/v1alpha1
kind: TransferRequest
metadata: { id: TR-2026-0001, title: Initial delivery of example RAG assistant }
spec:
  purpose: Deploy example RAG assistant v1.0 to a disconnected enclave
  owner: { name: Example Owner, contact: owner@example.org }
  source: dev-unclass
  destination: enclave-b
  direction: low-to-high          # the only direction accepted for bundles in phase 1
  stream: rag-assistant           # ordering scope for recurring transfers (default: "default")
  profile: routine                # routine | emergency (emergency handling is phase 1c)
  approvers:                      # who is expected to sign; informational
    - { name: Example Reviewer, role: security }
  allowUndeclared: false
  contents:
    - name: chat-model
      unit: model-package
      paths: ["models/tiny-chat/**"]
      upstream: { type: huggingface, reference: example-org/tiny-chat, revision: 0123… }
    - name: app
      paths: ["app/**"]
    - name: policies-corpus       # documents a knowledge base will be built from (doc 22)
      unit: knowledge-base
      paths: ["rag/docs/**"]
```

- The request is written on the packing side, so the receiving side treats it as a claim. Whether an approver's signature counts is decided only by keys pinned in the receiving side's policy.
- A path may be declared by several content entries (`entries_for` returns all of them).
- `request.artifact.undeclared` and `request.content.missing` report the two directions of mismatch. Checking that a declared `unit` actually formed arrives with the unit assemblers (task 5).

## 17.7 Policy

One document per side. Verify always uses the receiving side's own. A working example is [examples/policy.yaml](../../examples/policy.yaml).

```yaml
apiVersion: superscrubber104/v1alpha1
kind: Policy
metadata: { name: enclave-b-import, version: "2026.11.1" }

identity:                         # who owns this policy; bundles addressed elsewhere are refused
  enclave: enclave-b
  acceptSources: [dev-unclass]
transfer:
  maxBundleAge: 30d               # older bundles are possible replays
  clockTolerance: 10m             # allowance for clock drift (default 10m)

trust:
  signers:                        # keys for bundle signatures, approvals and receipts
    - keyId: "ed25519:<64 hex>"   # full fingerprint; must match the key file
      publicKey: keys/lowside-pack.pub
      sha256: "…"                 # every referenced file is pinned
      holder: build-pipeline      # quorums count distinct holders, not keys
      roles: [pack]               # pack | approve | receipt
      sources: [dev-unclass]      # networks this key may pack for (empty: any)
      validFrom: 2026-01-01
      validUntil: 2027-12-31
      revoked: false
  upstream:                       # vendor and publisher keys
    - name: almalinux-9
      type: gpg                   # gpg | x509 | sigstore | checksum-list
      file: keys/RPM-GPG-KEY-AlmaLinux-9
      sha256: "…"
      scope: [package.rpm, repo.dnf]
      fingerprints: ["…"]         # acceptable (sub)keys inside the file
      validUntil: 2030-01-01
    - name: sigstore-public-good  # model signatures, keyless (doc 24)
      type: sigstore              # the file is Sigstore's trusted_root.json
      file: keys/sigstore/trusted_root.json
      sha256: "…"
      scope: ["model.*"]
      identities: ["release@example-org.example"]   # required for sigstore: certificate SANs (globs)
      issuers: ["https://accounts.google.com"]       # optional: OIDC issuers
  minimum:                        # weakest acceptable upstream trust level per artifact kind
    "package.rpm": signature
    "model.*": pinned-checksum

defaults:
  severity: { critical: block, high: block, medium: require-approval, low: warn, info: allow }
  notAssessed: warn
  error: require-approval
  approvals: 1                    # distinct approvers to clear a require-approval finding
  overrideApprovals: 2            # distinct approvers to override a blocker

rules:                            # first match wins
  - rule: "model.pickle.*"
    disposition: block
  - rule: "model.remote-code.required"
    disposition: require-approval
    approvals: 2
  - rule: "offline.*"
    paths: ["dev-tools/**"]       # optional scope: artifact path or unit root globs
    disposition: warn
  - rule: "vuln.component.known"
    where: { kev: "true" }        # optional: globs over finding attributes
    disposition: block
  - rule: "malware.*"
    disposition: block
    overridable: false            # optional: a site may make one of its own blockers final
    notAssessed: block            # the scanner must actually have run

waivers:                          # standing, expiring exceptions
  - id: W-2026-007
    rule: container.user.root     # exactly one rule id; no globs
    subject: images/legacy-ingest.tar
    sha256: "9f86d08…"            # lapses automatically if the content changes
    where: { }                    # optional, e.g. { cve: CVE-2026-0001 }
    justification: Vendor image; runs in an isolated namespace
    approvedBy: "ed25519:…"
    expires: 2027-03-31           # required

licences:
  allow: [Apache-2.0, MIT, BSD-3-Clause]
  requireApproval: [LicenseRef-*, MPL-2.0, LGPL-*]
  deny: [AGPL-*, SSPL-1.0]
  unknown: require-approval

allowlists:
  python: { mode: enforce, file: allow/python.txt, sha256: "…" }
  models: { mode: enforce, entries: [{ id: "huggingface:example-org/tiny-chat", sha256: "…" }] }

limits:
  archive: { maxDepth: 5, maxMembers: 200000, maxRatio: 200, ratioMinBytes: 16MiB, maxExpandedBytes: 500GiB }
  maxArtifactBytes: 1TiB
  maxPathLength: 1024

plugins:                          # optional external scanners; see doc 21 and docs/scanners.md
  clamav:
    required: false               # true: absence is a failing plugin.required.missing
    path: tools/clamav/clamscan   # the binary, relative to this file (default: looked up on PATH)
    database: tools/clamav/db     # signature directory (required: never the host's own)
    binarySha256: "…"
    files: { "main.cvd": "…" }    # pinned data, relative to database; unpinned signature files are refused
    minVersion: "1.4"
    maxDbAge: 7d                  # from the CVD headers; older is plugin.data.stale
    timeout: 2h
    args: []                      # extra arguments, appended
  trivy:
    path: tools/trivy/trivy
    database: tools/trivy/cache   # --cache-dir; db/trivy.db and db/metadata.json must be there
  kev:                            # a data feed: CISA Known Exploited Vulnerabilities
    path: feeds/known_exploited_vulnerabilities.json
    maxDbAge: 2d
  semgrep:                        # static analysis; database is a local rules directory
    path: tools/semgrep/bin/semgrep
    database: tools/semgrep/rules
  bandit:
    path: tools/bandit/bin/bandit

runtimes:                         # model runtimes for superscrubber104 eval (doc 24); same fields as plugins
  llama-cpp:
    path: tools/llama.cpp/llama-cli
    binarySha256: "…"
    args: ["-m", "{model}/model.gguf", "-p", "{prompt}", "--seed", "{seed}", "-n", "{max_tokens}"]
    stdin: false                  # true: the prompt goes on standard input
    versionArgs: ["--version"]

runtime:                          # compatibility rules for runtime profiles (doc 23)
  compatibility:
    - when: {vllm: "0.6.*"}
      requires: {torch: "2.4.*", cuda: ">=12.1"}
      reason: vLLM 0.6 wheels are built against torch 2.4 and CUDA 12

freshness:
  feeds: { default: 7d, kev: 2d }
  mirrors: { default: 30d, apt: 14d }   # repository metadata age (doc 28)

controls:
  framework: nist-800-53r5
  catalog: { file: controls/site-profile.yaml, sha256: "…" }   # optional custom catalogue
  overrides:                      # first matching glob replaces the rule's own control IDs
    "offline.*": [SC-7, AC-4, CM-6]

extensions: { }                   # ignored by this version; still covered by the digest
```

**Evaluation order for one finding**

1. A `pass` is always `allow`.
2. A FAIL or ERROR of a **final** rule is `block`, and the decision is final. Nothing below applies.
3. The first unexpired **waiver** that names this rule, matches the subject, matches `where`, and (if it sets `sha256`) matches the content. (Never for a final rule.)
4. The first **rule** that matches (rule glob, `paths`, `where`) *and* sets an outcome for this result. A rule that only sets `notAssessed` never swallows a FAIL.
5. Otherwise the **defaults**: by severity for a FAIL, `notAssessed` or `error` otherwise.
6. **Fail closed.** A check that crashed (result `error`) is never decided `allow` or `warn` by a default or a rule; such an outcome is raised to `require-approval`. Only a waiver, a recorded human decision, can accept it. Every handler, assembler and scanner exception becomes such an error, and a command that fails part-way exits 3 with a message, never a traceback (tested in `tests/test_fail_closed.py`, which also feeds every structured format back with values of the wrong JSON type).

The decision records which entry decided it (`rules[3]`, `waivers[0]`, `defaults.severity.high`, `final`), so every outcome traces to one policy line.

**Approvals and overrides**

| Decision | Can it be cleared for this bundle? | By whom |
|---|---|---|
| `block`, final | No. Never. | Nobody. Fix the delivery or the trust chain. |
| `block` (a policy blocker) | Yes: an **override** | `overrideApprovals` distinct approvers (default 2), or the deciding rule's `approvals` |
| `block` from a rule with `overridable: false` | No | The site has chosen to make this blocker final |
| `require-approval` | Yes: an **approval** | `approvals` distinct approvers (default 1), or the deciding rule's `approvals` |

An approval or override is a signed `approved` event in the bundle's custody log, made with `superscrubber104 approve`. It counts only if all of these hold:

- It carries a **written justification**, which is part of what is signed.
- The signer is pinned in the *verifying* side's policy with the `approve` role, within its validity window and not revoked.
- **The signer is not the packer**: not the key that signed the bundle, and not another key with the same `holder`.
- It names this manifest and the finding exactly as the verifier found it (by `finding_digest`).
- The quorum counts distinct **holders**, so two keys held by one person are one approver.

Every approval the verifier looked at is kept in the assessment as an `ApprovalRecord` (who, which key, the justification, whether it counted and, if not, why). The assessment's digest is in the signed receipt, so the override is signed evidence on both sides: the approver's signature in the custody log and the verifier's over the outcome. An overridden blocker is still recorded as a blocker; it is overridden, not erased.

**Waivers are policy, not overrides.** A waiver is the policy owner narrowing a rule for one exact subject or exact content until a date. It has the same standing as any other policy rule, changes the policy digest (which the ledger logs), and never applies to a final rule. It is not signed, because the policy file is not signed yet; see the known limits in [18](18-bundle-and-verification.md).

**Policy hygiene**

- Unknown keys are errors (a typo such as `dispositon: block` must not silently weaken a policy). So are duplicate keys, which plain YAML loaders resolve silently.
- Referenced files resolve relative to the policy file and must be pinned by sha256. The policy digest covers the policy bytes and every pinned file, so swapping a key file changes it.
- A signer's `keyId` must match its key file.
- Hashes must be quoted (YAML reads an all-digit hash as a number).
- A waiver names exactly one rule, must expire, and needs an exact subject unless `sha256` pins it to content.
- Licence expressions are evaluated: `A OR B` takes the more permissive side, `A AND B` the more restrictive, `WITH <exception>` does not change the base licence. Anything unparseable is `unknown`.
- Controls may be enhancements of a listed control (`SI-7(1)`).

**Not yet in the schema** (added with the module that needs them; `extensions:` carries them meanwhile): `targets:` and `compatibility:` for runtime profiles (1b), `profiles:` overlays for emergency transfers (1c), `mcp:` server and tool rules shared with phases 2 and 3 (task 6), `eval:` tolerances (1d), and an optional detached signature over the policy itself.

## 17.8 Keys and signatures

- Ed25519, PKCS#8 and SubjectPublicKeyInfo PEM via `cryptography`. Private keys can be passphrase-encrypted. `Signer` is a protocol (`key_id`, `sign`), so a hardware token can replace a key file later.
- Key id: `ed25519:<sha256 of the raw public key>`, never truncated.
- Envelopes are **DSSE**. The bundle statement is an in-toto Statement; receipts are DSSE over the receipt document.
- **One root of trust:** the receiving side's policy (`trust.signers`). `superscrubber104 verify --pubkey` is accepted only when the policy pins no pack signer, and is reported as `trust.signer.unpinned`.
- A pinned key is relied on only if it has the right role, is within its validity window, is not revoked, and (for packing) is allowed to sign for the bundle's source.
- **Rotation** is done by editing `trust` (add the new key, set `validUntil` or `revoked` on the old). That changes the policy digest, and the next import records `policy.digest.changed` in the ledger with both digests.

## 17.9 Chained logs

`core/chainlog.py` is one append-only, hash-chained, per-event signed JSON Lines format: `{seq, prev, type, at, actor, data, sig}`. It serves the custody log that travels with a bundle, the receiving side's ledger, and (phase 3) the gateway audit log.

Edits and reordering are detectable. **Truncation of the tail is not**, so nothing may rely on the absence of a later event. Approvals are safe under that rule (removing one only makes the bundle fail); a "rejected" event would not be, which is why there is none.

`verify()` reports structural damage separately from what is known about each event's signer. In the ledger, which this side writes, an unknown signer is a problem. In a custody log, which anyone handling the bundle may append to, an event from an unknown signer is not damage; it simply carries no weight.

## 17.10 Interfaces

```python
ArtifactView:   ref, size, sha256; head(n), open(), resolve(relative)
Handler:        name, version, kinds; detect(view) -> Detection | None; inspect(view, ctx) -> Inspection
UnitAssembler:  name, version, kind; assemble(claims, ctx) -> Assembly(unit, components, verifications)
Context:        policy, recorder, now, corpora
Scanner:        name, capability, rules, binary_names; version(ready), data(policy), scan(ready, targets, analysis, ctx)
```

- Handlers see content only through `ArtifactView`: read-only bytes, no filesystem paths. `resolve()` reaches other files of the same delivery by relative path (`tokenizer.json`, `onnx/model.onnx_data`) and can never leave it.
- `detect()` is cheap (name and first bytes). `inspect()` makes one streaming pass and returns kind, metadata, components, unit claims and findings. This replaces the brief's five-method interface so that a multi-hundred-GB shard is read once.
- A handler that raises is reported as `inventory.handler.error`; the artifact is still recorded.
- Assemblers work from the claims' facts alone, so units inside archives form like any other. They never reopen artifacts.
- Checks that need the whole delivery (embedding-model links, offline settings, runtime compatibility, mirror content, extension dependencies) are plain functions called from `analysis.finish`, after every unit exists.
- External tools implement `Scanner` (`superscrubber104/scanners/base.py`) and run only after its pre-flight ([21](21-scanners-and-basics.md)).
- Staging targets are functions in `superscrubber104/stage.py` over the content `verify()` hands to its `use` callback ([34](34-staging.md)).
- The first design also declared `BundleCheck`, `Plugin`, `Lookup` and `Stager` protocols. Nothing came to need them, and they were removed rather than left as unused promises.

## 17.11 Module map

```
src/superscrubber104/core/
  model.py        enums and every data model above
  policy.py       policy loader, validator, evaluator; licence decisions
  request.py      transfer request loader
  rules.py        RuleSpec, RuleRegistry, FindingFactory, Recorder
  controls.py     control catalogue and mapping (data/nist-800-53r5.yaml)
  signing.py      Ed25519 keys, DSSE
  chainlog.py     hash-chained signed log
  canonical.py    canonical JSON, digests, jsonable()
  serde.py        strict dataclass <-> JSON (camelCase on the wire)
  paths.py        bundle path rules, hostile-name handling, globs
  yamlio.py       strict YAML (duplicate keys, unknown keys, sizes, durations)
  interfaces.py   protocols
  errors.py
```

## 17.12 Review resolutions

Status: **done** (implemented and tested), **shaped** (the model or schema has the field; the behaviour arrives with the named task), **deferred** (documented, not built).

| # | Review item | Status | What was done |
|---|---|---|---|
| 1 | Manifest mixed integrity with interpretation | done | `Manifest`/`Entry` vs `Analysis`/`Artifact`; policy and request digests moved to the signed statement |
| 2 | No receiving-side state | done | Ledger of receipts (`superscrubber104/ledger.py`), `verify --state`; signed `Inventory` document is 1c |
| 3 | Signed statement could be replayed | done | `Provenance` (bundle id, time, source, destination, stream); policy `identity` and `transfer.maxBundleAge`; replay, ordering and clock checks |
| 4 | Units had no relationships, digest or archive roots | done (model) | `Requirement`, `Unit.digest`, `Unit.root: ArtifactRef`; assemblers use them from task 5 |
| 5 | Hostile names could not be recorded | done | `ArtifactRef.unsafe`, `escape_name`, `check_member_name` |
| 6 | Floats banned with no convention | done | Decimal strings; `jsonable()` at the handler boundary |
| 7 | No chunk hashes or volume index | done | Chunk hashes verified; signed volume index and multi-volume verify (doc 26); resumable verify not yet |
| 8 | Deltas | done | `pack --delta-from`, `verify --base`, carried files re-hashed from accepted bases (doc 26) |
| 9 | Scale | done / deferred | Passes are counts; nested members live in the analysis, not the manifest. Streaming JSON Lines for very large analyses is deferred |
| 10 | Version skew | done | Receiver parses only statement, manifest and request; `extensions` maps; packer analysis never parsed |
| 11 | Integrity checks could be waived | done | `RuleSpec.final`: integrity, authenticity and replay rules cannot be waived, lowered or overridden; waivers restricted to one rule and an exact or content-pinned subject |
| 12 | No record of upstream verification | done (model) | `Verification`, `TrustLevel`, `trust.minimum`; handlers fill it from task 5 |
| 13 | Pinned keys too thin | done | Validity, revocation, holder, sources, fingerprints; full key ids; rotation logged via `policy.digest.changed` |
| 14 | Policy unsigned; two trust roots | done / deferred | Policy is the single root, `--pubkey` only when nothing is pinned. A signature over the policy is deferred |
| 15 | Approvals had no model | done | Owner's decision: integrity and authenticity failures are final; policy blockers are overridable by a quorum with a written justification; the packer cannot approve; overrides are signed evidence. `superscrubber104 approve`, `count_approvals`, `ApprovalRecord` (§17.7) |
| 16 | Scanner pinning incomplete | done | `path`, `database`, `binarySha256`, `files`, `minVersion`, `maxDbAge`; a mismatch is final (`plugin.integrity.mismatch`); see doc 21 |
| 17 | Time | done | `Context.now` is a datetime; `replay.clock.regression` with a drift tolerance and a logged recovery path (`superscrubber104 ledger adjust-clock`); `replay.clock.skew` as an early warning ([18 §18.6](18-bundle-and-verification.md)) |
| 18 | Algorithm agility | done | Digest and key-id grammars accept other algorithms |
| 19 | Runtime profile inputs | deferred to 1b | `Requirement` can already express "supplied by the high side" |
| 20 | Patch documents and profiles | shaped / 1c | `profile` and `stream` on the request and statement |
| 21 | Transfer request gaps | done | `entries_for` returns all matches; typed `upstream`; `stream`, `profile` |
| 22 | Receipt gaps | done | Bundle id, enclave, source, stream, request id, evidence digests; only the receipt crosses back |
| 23 | Components | done (model) | `SubjectKind.COMPONENT`, `depends_on`, licence expressions |
| 24 | Handler interface | done | Multiple kinds, `resolve()`; whole-delivery checks run in `analysis.finish`; staging works on verified content (doc 34) |
| 25 | Mode bits | done | Recorded for archive members (`archive.member.setuid`); deliberately not for payload entries |
| 26 | Policy could only select on rule ids and paths | done / shaped | `where` on rules and waivers; the `mcp:` section comes with the MCP handlers (task 6) |
| 27 | Subjects were bundle-centric | done | `locator`; component, policy, host and tool-call subjects |
| 28 | Audit log | done | Generic `chainlog` |
| 29 | Controls | done | Enhancements; pinned custom catalogue |
