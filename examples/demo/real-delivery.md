# A real delivery

The demo uses small synthetic files. [real-delivery-report.pdf](real-delivery-report.pdf) is the report from a trial on real, public projects: `superscrubber104 model inspect` run in place over a delivery of 3.5 GB. It is the HTML report the tool produced, printed to PDF with every section expanded (71 pages; all findings and the coverage of every rule are at the end). It was produced before the project was renamed, so it calls the tool by its earlier working name, `airlock`, and uses the labels of that time (`APPROVE` for what is now `NEEDS APPROVAL`).

## What was in it

| Folder | Content | Source |
|---|---|---|
| `app/private-gpt` | a RAG application, without its dependencies | github.com/zylon-ai/private-gpt |
| `app/rag-client` | a small client with hash-pinned requirements, and their wheels in `wheels/` | ollama, pypdf, tiktoken from PyPI |
| `mcp/servers` | the MCP reference servers, without `node_modules` | github.com/modelcontextprotocol/servers |
| `mcp/.mcp.json` | an MCP client configuration that starts servers with `uvx` and `npx` | written for the trial |
| `models/all-MiniLM-L6-v2` | an embedding model, with every format the repository publishes | Hugging Face |
| `models/smollm2-135m` | a small chat model, with its ONNX variants and training files | Hugging Face |
| `models/qwen2.5-0.5b-gguf` | one GGUF file | Hugging Face |
| `images/python-3.12-slim.tar` | a container image, from `docker save` (Docker 29) | Docker Hub |

## What superscrubber104 found

1,800 files, 5,645 archive members and 34 units, inspected in 27 seconds with the default policy and no scanners configured. The verdict is `BLOCKED`, with 19 blockers, each a real reason the delivery could not be used on a disconnected network as it stands:

| Blockers | Why |
|---|---|
| 2 × `mcp.server.runtime-fetch` | `uvx` and `npx` download the servers when they start |
| 5 × `*.environment.unresolvable` | private-gpt, three Python MCP servers and the npm workspace were delivered without their packages |
| 8 × `offline.endpoint.cloud-ai` | private-gpt defaults to `api.openai.com` |
| 1 × `model.pickle.unknown-import` | the chat model's `training_args.bin` is a pickle that imports training classes; inference does not need it |
| 3 × `mcp.server.capability` (shell) | the MCP repository's release scripts start processes |

The 91 approvals are mostly licences, because the default policy asks for approval of every licence; a site policy lists the ones it accepts. Malware, vulnerability and static-analysis checks are reported as not assessed.

## With real scanners

The same delivery was then scanned with real scanners, each one pinned by hash in the policy and checked by `superscrubber104 plugins check` first:

| Scanner | Version | Data |
|---|---|---|
| ClamAV (AlmaLinux EPEL) | 1.4.6 | main 63, daily 28189, bytecode 339 |
| Trivy (checked against the release checksums) | 0.76.1 | vulnerability database of the same day |
| CISA KEV catalogue | | 2026.11.18 |
| Semgrep | 1.186.0 | the 337 Python rules of `semgrep-rules` at `a5ad171` |
| Bandit | 1.9.4 | its built-in tests |

The scan took about 13 minutes, most of it ClamAV reading 3.3 GB. What the scanners added:

* **Malware:** none found.
* **Vulnerabilities:** 240 in the container image, 234 of them in its Debian packages. None is in the KEV catalogue. With the default policy, the 48 high-severity ones block and the 124 medium ones need approval.
* **Static analysis:** 7,809 findings, 7,074 of them Bandit's `assert_used` in test files. A site policy that allows findings in tests (they are still recorded) and makes non-security categories warnings brings the static-analysis blockers from 87 to 20, all security findings in production code: raw SQL through `text()`, weak hashes, a Jinja template without autoescaping, and a subprocess call with environment input. [docs/scanners.md](../../docs/scanners.md#tuning) has the policy.
* **Not assessed:** one Semgrep rule timed out on one file, and is recorded as such.

## What the trial changed in superscrubber104

The first run reported 25 blockers and 147 approvals. Several were superscrubber104's mistakes, not the delivery's, and were fixed:

* a multi-platform image saved for one platform was called incomplete;
* coreutils' `sha256sum` binary was taken for a checksum list;
* an application's `skills` package was taken for agent skills;
* TorchScript's own pickle references were called dangerous;
* MCP servers' tests were treated like their servers;
* ONNX variants of a model were reported without a licence.

The scanner run found four more:

* scanners were given paths relative to the operator's directory, but run in a private one, so with `inspect delivery` every scanner failed (the stand-in used by the tests now runs there too);
* clamscan answers "Empty file", not OK, so the delivery's 158 empty `__init__.py` files were reported as not scanned;
* the gap left by a scanner that failed said that no scanner was configured;
* Semgrep's rule ids carried the operator's home directory.

Each fix has a regression test built from the layout the real files had.
