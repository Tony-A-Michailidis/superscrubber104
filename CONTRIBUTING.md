# Contributing

superscrubber104 decides whether a delivery may cross into a disconnected network, so its own rules matter as much as its features. This page lists them: the guardrails that are never relaxed, the design rules that are easy to break by accident, and how changes are checked.

## Guardrails

- **Public sources only.** Examples, fixtures and documentation are generic. Nothing comes from any employer, client or other non-public environment.
- **Offline first.** No network calls at runtime, ever. superscrubber104 must be vendorable as a bundle of wheels, so that it can cross its own airlock.
- **Never execute what you inspect.** No unpickling, no importing model code, no running install scripts, no mounting images on the host. Static inspection only. The one exception is `superscrubber104 eval`, which runs a model through a runtime the policy pins and pre-flights like a scanner.
- **Trust nothing that crosses, including the scanners.** Scanner binaries, rule packs, vulnerability databases and keys are pinned, verified artifacts too.
- **Never silently drop anything.** An unrecognised file is still inventoried, hashed, signed, scanned and recorded as "unclassified". A check that could not run is reported as "not assessed", never omitted.
- **AI-aware, not AI-only.** Nothing is built that only works for AI files.

## Design rules

**Checks and policy**

- Checks observe, policy decides. A check never sets a disposition: it records a finding through `ctx.recorder`, under a rule registered in `catalog.py` or one of the `catalog_*.py` modules.
- Decide when adding a rule whether it is `final`. Integrity and authenticity rules (a hash, a signature, a replay, the wrong enclave) are: no policy, waiver or approval changes them. A hash mismatch against a record that travelled with the content (an image digest, a wheel `RECORD`, a lockfile hash) is final; anything about what the content *does* is policy.
- A policy `block` can be overridden for one bundle, but only by an approval quorum with a written justification, and never by the packer.
- A parser's failure is "not assessed", never a `final` finding: unreadable and altered are different things.
- A signature earns trust only for what it covers (an RPM header signature without a checked payload digest does not cover the payload). Times and expiry are trusted only from signed fields.

**Evidence**

- The manifest holds integrity facts only. Anything that depends on tool version, policy or time belongs in the analysis, the assessment or the signed statement.
- `verify` trusts nothing the packer derived. It re-hashes and re-analyses, and reads only the statement, the manifest and the request.
- No floats in canonical documents; pass handler metadata through `jsonable()`.
- Reports render evidence; they never add to it or judge it. No control is ever marked "satisfied": that is the assessor's call. Every format is deterministic, with no clock and no random ids.

**Handlers and units**

- A handler reports what one file is (kind, metadata, findings) and makes claims. Units are formed only by assemblers, from claim facts, so they form inside archives too. Handler metadata is namespaced under one key per handler.
- Decisions across units (embedding models, offline settings, runtime compatibility, evaluation references) run in `analysis.finish`, after every unit is assembled.
- `resolve()` does not reach into archives. A check that needs neighbouring files records "not assessed" for nested artifacts; it never skips them or reports their neighbours as missing.
- Archive member names never become filesystem paths. Name members with `core.paths.check_member_name`; hostile names are recorded with `ArtifactRef(..., unsafe=True)`.
- A handler that decompresses anything reads it through `archive.capped` and catches `archive.ARCHIVE_ERRORS`. Untrusted input must never raise out of a handler or expand without a limit.
- Model content is never unpickled, imported or loaded. Use the static readers in `superscrubber104/formats/`; tests patch `pickle.load*` to fail.
- Model-facing text (prompts, templates, tool descriptions) is scanned with `superscrubber104/text.py`.
- External scanners live in `superscrubber104/scanners/` and run only after the pre-flight in `base.py`: found, hashed against their pins, version and database age checked. A pin mismatch is final.

**Commands**

- Exit codes are the same for every command: 0 accepted, 1 a policy blocker or open gap, 2 usage, 3 refused.

## Tests

- Fixtures are synthetic and tiny, built in `tests/*_fixtures.py`. Malicious samples are raw bytes, generated in the test.
- Never put a credential-shaped string in the repository, even in a test: assemble it at run time. Findings never record a secret. Build invisible characters with `chr()`, never as literal escapes.
- Every new format gets a damaged sample in the robustness tests (`tests/test_*_robustness.py`).
- Validate a new parser against a real public file too, downloaded outside the repository, and record the result in its design document.
- Tests replace `run_process` with a stand-in; a real scanner never runs in the test suite. The suite blocks the network: if a test needs a socket, that is a design bug.

## Before you commit

```console
$ ruff check .
$ ruff format .
$ mypy
$ pytest
```

- After adding or changing a rule, regenerate the reference with `superscrubber104 rules -o docs/rules.md`; a test compares the two.
- Documents 17 onwards in `docs/design/` describe what is built. Keep them in step with the code, including their "known limits". Documents 01 to 16 are the original brief and stay as written.
- Every sample of output in the README and the demo's sample output comes from a real run. Re-run and replace them when output changes.
- One commit per completed change, with tests and documentation in the same commit.
