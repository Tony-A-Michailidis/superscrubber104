# A real delivery

The demo uses small synthetic files. [real-delivery-report.html](real-delivery-report.html) is the report from a trial on real, public projects: `airlock model inspect` run in place over a delivery of 3.5 GB. GitHub shows HTML as source; download the file and open it in a browser.

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

## What airlock found

1,800 files, 5,645 archive members and 34 units, inspected in 27 seconds with the default policy and no scanners configured. The verdict is `BLOCKED`, with 19 blockers, each a real reason the delivery could not be used on a disconnected network as it stands:

| Blockers | Why |
|---|---|
| 2 × `mcp.server.runtime-fetch` | `uvx` and `npx` download the servers when they start |
| 5 × `*.environment.unresolvable` | private-gpt, three Python MCP servers and the npm workspace were delivered without their packages |
| 8 × `offline.endpoint.cloud-ai` | private-gpt defaults to `api.openai.com` |
| 1 × `model.pickle.unknown-import` | the chat model's `training_args.bin` is a pickle that imports training classes; inference does not need it |
| 3 × `mcp.server.capability` (shell) | the MCP repository's release scripts start processes |

The 91 approvals are mostly licences, because the default policy asks for approval of every licence; a site policy lists the ones it accepts. Malware, vulnerability and static-analysis checks are reported as not assessed.

## What the trial changed in airlock

The first run reported 25 blockers and 147 approvals. Several were airlock's mistakes, not the delivery's, and were fixed:

* a multi-platform image saved for one platform was called incomplete;
* coreutils' `sha256sum` binary was taken for a checksum list;
* an application's `skills` package was taken for agent skills;
* TorchScript's own pickle references were called dangerous;
* MCP servers' tests were treated like their servers;
* ONNX variants of a model were reported without a licence.

Each fix has a regression test built from the layout the real files had.
