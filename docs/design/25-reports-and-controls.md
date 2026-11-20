# 25. Reports and control mapping

> **Status: implemented** (task 8). Spec: [§18](13-checks-and-controls.md) (evidence and control mapping), the `report` step of [§14](12-transfer-workflow-and-cli.md). Evidence model: [17](17-core-models.md).

Every check already records a structured finding with its controls, result, subject, tool and rule version, and every rule's coverage (passed, failed, not assessed, errors) is in the assessment. A report adds nothing to that evidence: it arranges it for a reader, and renders it in the formats an accreditation package needs.

## 25.1 `superscrubber104 report`

```sh
superscrubber104 report <source> [--format md|html|json|cyclonedx|oscal] [-o FILE] [--policy P]
```

| Source | What it reports |
|---|---|
| a bundle directory | the **packing side's** assessment and analysis, marked as such: what the packer saw, not yet checked by anyone |
| the directory `superscrubber104 verify --out` (or `--state`) wrote | **this side's own** verification: `assessment.verify.json`, `analysis.verify.json` (re-derived here, not the packer's), the request, the receipt |
| the directory `superscrubber104 model inspect --out` wrote | an inspection in place, before anything is packed |
| an assessment file | the assessment alone (no inventory, no SBOM) |

`--policy` reports against that policy's control catalogue (a site catalogue such as an ITSG-33 profile); the default is the built-in NIST SP 800-53 Rev. 5 starter set. Rule-to-control mapping is read from the assessment itself (each rule's coverage records the controls it was mapped to when it ran, policy overrides included), so a report shows what was in force at the time.

All formats are deterministic: no clock is read and no identifier is random. The same source always renders the same bytes, so a report can itself be hashed and signed as evidence.

## 25.2 Formats

| Format | For | Content |
|---|---|---|
| `md` | reviewers, assessment packages | verdict and transfer facts; summary counts and inventory; what needs attention (blocks, approvals) with approval progress; the control matrix with what superscrubber104 evidences for each control; units with their key facts; scanners and feeds (version, database, age, pinned); everything not assessed and why; every finding with its controls and detail; approvals; inventory by kind |
| `html` | the same, in a browser | one self-contained page: inline styles, no scripts, no external fonts, images or links, and a `Content-Security-Policy` of `default-src 'none'`. Light and dark themes. Every value from the delivery is escaped |
| `json` | tools | the report model (`kind: Report`): the same rows as above, with full findings, decisions, coverage and plugin statuses |
| `cyclonedx` | SBOM / ML-BOM | CycloneDX 1.6: every component with purl, SHA-256 and other hashes, licences (an SPDX expression, or names), supplier, upstream reference and revision, how it was verified, and where it occurs in the delivery (`evidence.occurrences`); models as `machine-learning-model`, datasets as `data`; packages found inside an image nested under it; declared dependencies in the dependency graph. The serial number is derived from the analysis digest |
| `oscal` | GRC tools | OSCAL 1.1.2 `assessment-results` (see 25.4) |

The CycloneDX and OSCAL outputs were validated against the official CycloneDX 1.6 and OSCAL 1.1.2 JSON schemas, for both a packed bundle and a verification.

## 25.3 The control matrix

For each control in the catalogue (and any control a rule maps to that the catalogue lacks), the matrix lists the rules that evidence it, the sum of their checks (passed, failed, not assessed, errors), the non-passing findings, a short statement of **what superscrubber104 provides** for that control (`report/evidence.py`, from the brief's starter mapping), and a status:

| Status | Meaning |
|---|---|
| `findings` | a failing check stands: a block, a refusal, or an approval still outstanding |
| `noted` | checks failed, but every one is a warning, allowed, waived or cleared by approval |
| `not-assessed` | its checks could not run (no scanner, an unreadable file, an archive superscrubber104 cannot open) |
| `partly-assessed` | some of its checks ran, some could not |
| `no-findings` | its checks ran and found nothing |
| `not-exercised` | it has rules, but none applied to this delivery |
| `no-rules` | nothing in superscrubber104 evidences it |

Each finding carries an action: `REFUSE` (final), `BLOCK`, `OVERRIDE` (a blocker overridden by an approval quorum), `NEEDS APPROVAL` (until its quorum is met), `APPROVED`, `WARN` or `ok`. A check that did not run is shown as `not assessed: <rule>` with its reason, in every format, and never under the title of what it would have found: "Malware scanner reports a detection" next to a scanner that never ran reads as a detection.

**There is no "satisfied".** superscrubber104 evidences part of a control for one delivery; whether a control is satisfied is the assessor's judgement for the whole system. The wording in every format says so.

## 25.4 OSCAL mapping

* One **observation** per control with evidence (`types: [control-objective]`): what superscrubber104 provides, the rules that ran, the counts.
* One **observation** per non-passing finding (`types: [finding]`), with the rule, result, severity, action and finding id as properties in the `urn:superscrubber104` namespace.
* One OSCAL **finding** per control whose status is `findings`, `noted`, `not-assessed` or `partly-assessed`, targeting `<control>_obj` with state `not-satisfied`: reason `fail` when checks failed, `other` when they could not run. It is linked to the control's observations.
* Controls with `no-findings` get an observation and no OSCAL finding, for the reason above.
* `reviewed-controls` lists the controls with evidence; `import-ap` names the policy by digest (`urn:superscrubber104:policy:sha256:...`), the closest thing superscrubber104 has to an assessment plan. Control ids are converted to OSCAL form (`SI-7(1)` becomes `si-7.1`). UUIDs are v5, derived from the content.

## 25.5 Rule-to-control mapping

Every rule names its controls in `catalog*.py` when it is registered, and an unknown control id is an error at start-up. A site can remap rules in its policy:

```yaml
controls:
  framework: nist-800-53r5
  catalog: { file: controls/site-profile.yaml, sha256: "…" }   # e.g. an ITSG-33 profile
  overrides:
    "offline.*": [SC-7, AC-4, CM-6]
```

The built-in catalogue (`core/data/nist-800-53r5.yaml`) holds the 26 controls superscrubber104 evidences: AC-4, AC-6, AU-10, CM-2, CM-3, CM-4, CM-6, CM-7, CM-8, CM-10, CM-11, IA-5, MP-5, RA-5, SA-11, SA-22, SC-7, SC-28, SI-2, SI-3, SI-7, SI-10, SR-3, SR-4, SR-10, SR-11. Titles are from the public NIST catalogue. **Review every mapping before publishing evidence for an assessment** (the starter mapping is the brief's, and a site's accreditor may read controls differently).

## 25.6 Known limits

- **CM-4** (impact analyses) has evidence (approvals and their justifications) but no rule, so it shows as `no-rules`.
- **Reports are not signed** by `superscrubber104 report`. Their inputs are: the bundle's assessment and analysis are covered by the bundle signature, and a verification's assessment by the signed receipt (its digest). Because rendering is deterministic, anyone can re-render from those signed inputs and compare.
- **OSCAL** carries no assessment plan, assessment subjects or risks; it is the results part only. OSCAL's Unicode-aware patterns were checked with an approximation in validation (Python's `re` lacks `\p{L}`).
- **CycloneDX** output contains components, not the files superscrubber104 could not identify; those are in the manifest and the report's inventory. VEX (vulnerability exploitability statements) is not produced.
- **Large deliveries** produce long reports: every finding is listed, because evidence must be complete. The HTML folds the full lists.
