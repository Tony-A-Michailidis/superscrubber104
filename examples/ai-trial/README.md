# A repeatable real-world trial

[`ai-trial.sh`](ai-trial.sh) builds a small AI delivery from public sources, every one pinned to an exact version, and runs it through superscrubber104 from inspection to verification. Anyone can run it and should get the same findings. It complements [the first real delivery](../demo/real-delivery.md), a larger RAG application that was not pinned.

```console
$ examples/ai-trial/ai-trial.sh /tmp/ai-trial
```

It needs bash, Python 3.11 or later with `venv`, git, network access for the downloads (about 1.3 GB), and `superscrubber104` on `PATH`. A run takes about two minutes after the downloads.

## What is in it

| Part | Source | Pinned at | Licence |
|---|---|---|---|
| Model | [distilbert/distilbert-base-uncased-finetuned-sst-2-english](https://huggingface.co/distilbert/distilbert-base-uncased-finetuned-sst-2-english): a sentiment classifier (67M parameters) in five formats: safetensors, a PyTorch pickle, Keras weights for TensorFlow, TorchScript for rust-bert, and an ONNX export with its own config and tokenizer | revision `714eb0fa89d2f80546fda750413ed43d93601a13` | Apache-2.0 |
| Dataset | [stanfordnlp/sst2](https://huggingface.co/datasets/stanfordnlp/sst2): the Stanford Sentiment Treebank the model was fine-tuned on (Parquet) | revision `8d51e7e4887a4caaa95b3fbebbf53c0490b58bbb` | listed as unknown |
| Agent code | [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers): the official MCP reference servers, Python and TypeScript, without their packages | commit `c799c8552b0f27b7a33a7b9233773da144dddcf5` | mixed (no single licence) |
| Agent configuration | `.mcp.json`, written by the script: starts the filesystem server with `npx -y`, as most setups do | | |

The model and dataset are downloaded with Hugging Face's own `hf` tool, which keeps a record of every file it fetched; superscrubber104 checks the files against it.

## A run

From AlmaLinux 10 under WSL, Python 3.12, superscrubber104 after the fixes listed below:

```console
== 2. The delivery, every source pinned ==
512 files, 1.3G

== 3. Inspect it in place ==
[inspect exit 1]
61 of 214 rules exercised, 4038 checks passed; findings: 5 block, 29 need approval, 90 warn, 123 allowed
     14 NEEDS APPROVAL offline.registry.external
      8 NEEDS APPROVAL mcp.server.capability
      3 BLOCK python.environment.unresolvable
      2 NEEDS APPROVAL model.format.code-capable
      1 NEEDS APPROVAL offline.download.runtime
      1 NEEDS APPROVAL mcp.server.remote
      1 NEEDS APPROVAL licence.unidentified
      1 NEEDS APPROVAL licence.approval-required
      1 NEEDS APPROVAL agent.hook.command
      1 BLOCK node.environment.unresolvable
      1 BLOCK mcp.server.runtime-fetch

== 4. The transfer request ==
delivery  512 files, 0 not declared
[show exit 0]

== 5. Pack, then verify as the receiving side ==
[pack exit 1]
[verify exit 1]
84 of 214 rules exercised, 8020 checks passed; findings: 5 block, 29 need approval, 94 warn, 123 allowed
```

The verdict is `BLOCKED`, and each blocker is a reason the delivery would not work on a disconnected network:

| Blockers | Why |
|---|---|
| 4 × `*.environment.unresolvable` | three Python servers and the npm workspace arrive without the packages they need |
| 1 × `mcp.server.runtime-fetch` | `npx -y` downloads the filesystem server when the agent starts it |

The approvals are questions a reviewer has to answer, not noise:

* 14 × `offline.registry.external`: the servers' Dockerfiles pull base images that are not in the delivery.
* 8 × `mcp.server.capability`: what the servers can reach: the fetch server the network, the filesystem, git and memory servers write files, the "everything" server registers tools at run time.
* 2 × `model.format.code-capable`: `pytorch_model.bin` (a pickle, read for its imports and never loaded) and `rust_model.ot` (TorchScript). The safetensors, ONNX and Keras weights files carry no code.
* The model's Apache-2.0 licence (the default policy asks about every licence), and the dataset's unknown one.
* Three from the MCP repository's own developer setup, delivered with it: its `.mcp.json` points an agent at a remote MCP server (`modelcontextprotocol.io`), its `.claude/settings.json` runs a Node script at the start of every agent session, and the git server's Dockerfile installs packages with `apt-get` when the image is built.

The model is recognised as one repository with all four weight files, and `onnx/` as its variant under the same licence. All 17 downloaded files match Hugging Face's download record for that revision.

## What this trial changed in superscrubber104

The first run of this delivery reported 8 blockers and 49 approvals. Several were superscrubber104's mistakes, and each was fixed with a regression test built from the real layout:

| First run | Fix |
|---|---|
| 17 secrets in the model card | Hugging Face `verifyToken` evaluation receipts are public by design; one is skipped only when it is the value of `verifyToken` and its payload holds nothing but `hash` and `version` |
| 3 blockers on the MCP repository's release scripts | a file is MCP server code only if it imports the server SDK, not if it names the package in a comment or a list |
| `onnx/` a separate package without weights or licence, and `onnx/model.onnx` a third | a format folder with its own config is one package, a variant of its repository, under its licence |
| `tf_model.h5` and `rust_model.ot` not counted as weights | Keras `save_weights` files and rust-bert's TorchScript copy count as weights; other `.h5` files stay unclassified, since HDF5 is also a data format |
| the same licence approved once per format folder | a variant whose only licence is its repository's shares the repository's decision |

With the fixes: 5 blockers and 29 approvals, all of them real. The same fixes take the README's SmolLM2 example from 10 approvals to 2.

## Limits

* The servers are delivered as source without their packages, so most of their dependencies are not scanned for vulnerabilities. Trivy, when configured, checks the five MCP server packages themselves and finds none; the unresolvable blockers say what is missing.
* The run configures no scanners, so skills, malware, vulnerabilities and static analysis are recorded as not assessed (the extra warnings). [Doc 21](../../docs/design/21-scanners-and-basics.md) records the same MCP servers run through NVIDIA SkillSpector.
* The run uses the default policy. A site policy would accept Apache-2.0 and decide the dataset's licence once.
* Hugging Face revisions and the git commit are fixed, but the `hf` tool and pip are not: a later `huggingface_hub` could lay the files out differently.
