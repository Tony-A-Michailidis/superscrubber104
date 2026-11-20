# 19. Model packages and model formats

> **Status: implemented** (task 5). Spec: [§7](05-model-packages.md) and the AI rows of [§6](04-artifact-coverage.md). Core models: [17](17-core-models.md).

A model crosses as a **complete, self-consistent unit**. Handlers recognise model files and report what they find; the model-package assembler groups those reports into `ModelPackage` units and checks each package as a whole. Everything is static: no file is unpickled, imported, loaded by a framework or executed, and no ML library is a dependency. The test suite fails if anything calls `pickle.load`, `pickle.loads` or `pickle.Unpickler`.

`superscrubber104 model inspect <path>` produces the records and findings for any directory or file, in place, without packing. `pack` and `verify` run the same checks; the receiving side re-derives every package from the bytes.

## 19.1 Formats

| Format | Recognised by | What is checked |
|---|---|---|
| **safetensors** | 8-byte header length + JSON | Header parsed with duplicate keys rejected; every tensor's byte count matches dtype × shape; offsets cover the data region exactly (no gaps, overlaps or trailing bytes, which is where hidden content would sit). Tensor count, parameters, dtypes, `__metadata__` recorded. |
| **GGUF** | `GGUF` magic | Header and key/values parsed with bounds; tensor table; every tensor of a known quantisation layout lies inside the file (a truncated download is caught). Architecture, quantisation (`Q4_K_M`, ...), context length, tokenizer, embedded chat templates, licence, base models recorded. A self-contained GGUF is checked against itself: block count and vocabulary against its tensors. |
| **Pickle** (`.pkl`, joblib, legacy PyTorch) | `PROTO` opcode; protocols 0/1 by extension | Static opcode walk with stack and memo simulation, so imports hidden behind `STACK_GLOBAL` and the memo are still resolved. Every import classified *dangerous*, *safe* or *unknown*. Streams that cannot be walked to the end are a finding. |
| **PyTorch zip** (`.pt`, `.bin`, `.pth`, `.ckpt`) and **TorchScript** (also `.ot`, as libtorch bindings such as rust-bert save it) | zip with `data.pkl`; `code/` or `constants.pkl` | The zip is a code-capable file; its `data.pkl` (and `*.debug_pkl`) get the pickle checks via the archive walk. TorchScript is code by definition. Inside a torch archive, TorchScript's own references (`__torch__.*` classes, which name code in the archive, and the `torch.jit._pickle` list builders) are expected, not dangerous imports; anything else is classified as usual. |
| **NumPy** `.npy` / `.npz` | `\x93NUMPY` | Object arrays are pickles after the header and get the pickle checks; numeric arrays are recorded. |
| **Keras** `.keras` / `.h5` | zip with `config.json`; HDF5 magic | `Lambda` layers (stored bytecode) and custom objects from outside Keras. `.h5` files are searched for the markers rather than parsed (no HDF5 reader); the finding says so. |
| **ONNX** | `.onnx` + protobuf field 1 | Walked in place with a bounded protobuf reader, skipping weights. Custom operator domains (outside ONNX and ONNX Runtime). External data: path must stay inside the delivery, file must exist, offset + length must fit. |
| **TensorRT, TFLite, Core ML, OpenVINO, SavedModel** | extension or magic | Recognised and recorded; a finding states plainly that the content is not inspected. |
| **llamafile** (APE) | `MZqFpD` | An executable and a model: flagged for executable review. |
| **Package files** | name | `config.json`, `generation_config.json`, `tokenizer.json`, `tokenizer_config.json`, `tokenizer.model`, `vocab.*`, `merges.txt`, `added_tokens.json`, `special_tokens_map.json`, `chat_template.jinja/.json`, `*.safetensors.index.json`, `*.bin.index.json`, `adapter_config.json`, sentence-transformers `modules.json` and module configs, `README.md` (model card front matter, intended use, limitations), `LICENSE*`/`COPYING`/`USE_POLICY*`, custom code (`modeling_*.py` etc.), Ollama `Modelfile`, Hugging Face download records. |
| **Ollama store** | `manifests/...` JSON | Every layer present with exactly the size and sha256 the manifest names; template, licence, params and GGUF layers read. |

### Pickle classification

* **Dangerous** (critical): shell, process, file, network and code-evaluation modules (`os`, `subprocess`, `socket`, `builtins.eval`, `builtins.getattr`, `runpy`, `importlib`, ...), nested deserialisation (`pickle`, `marshal`, `torch.load`, `numpy.load`, `joblib.load`), attribute-access gadgets (`operator.attrgetter`, `functools.partial`), known gadgets (`numpy.testing._private.utils.runstring`), and any name containing a dunder.
* **Safe**: what PyTorch, NumPy and joblib need to rebuild tensors and arrays, plain containers and dtypes. Checked against a real PyTorch checkpoint, which imports exactly `torch._utils._rebuild_tensor_v2`, `torch.*Storage` and `collections.OrderedDict`.
* **Unknown** (high): everything else. A scikit-learn estimator is unknown by default: its class runs its own code on load. A site that trusts a library adds it to the policy (`allowlists.pickle-globals.entries: ["sklearn.*"]`). Dangerous always wins over the allowlist.

## 19.2 Packages

Handlers emit claims (`role` + facts); the assembler groups them by root:

| Root | When |
|---|---|
| The directory | Hugging Face layout (config, shards, index, tokenizer, ...) |
| The file itself | Self-contained formats: GGUF, ONNX, Keras, llamafile, compiled formats |
| The first shard | Split GGUF (`name-00001-of-0000N.gguf`) |
| The manifest | An Ollama model |

A group is a package only if it holds a *core* role: weights, an index, a model config, an adapter, a Modelfile or a manifest. A directory with only a README and a LICENSE is not a package. A file-rooted package (a GGUF) inherits the licence and model card of its directory when that directory is not a package itself. A format variant in a subfolder of a model repository (`onnx/model_int8.onnx`, `openvino/openvino_model.xml`, as Hugging Face repositories keep them) stays its own package but takes the repository's licence and model card, is named `<repository>/onnx/model_int8.onnx` (or `onnx/model_int8.onnx` when the repository itself is inspected), and records `variantOf`. Packages form inside archives too: the assembler works from the claims' facts, not by re-reading files.

### Checks

| Area | Check | Rule |
|---|---|---|
| Completeness | Every file the index names; every shard of an `NNNNN-of-MMMMM` series; ONNX external data; Ollama layers; `auto_map` modules; adapter weights; local Modelfile `FROM` files | `model.package.file-missing` |
| | Weights not named by the index | `model.package.file-unreferenced` |
| | Index tensors and total size against the shard headers | `model.package.index-mismatch` |
| | Transformers-layout weights without `config.json` | `model.package.config-missing` |
| | A text model (config has a vocabulary) without tokenizer files | `model.package.tokenizer-missing` |
| | A Hugging Face package without a model card | `model.package.card-missing` |
| | Adapter base model or Modelfile `FROM` not in the delivery | `model.package.requirement-unmet` |
| Consistency | `config.json` vocabulary, hidden size and layer count against the tensors (skipped for quantised weights, whose shapes are packed) | `model.package.config-mismatch` |
| | Highest tokenizer id against the config's vocabulary | `model.package.tokenizer-mismatch` |
| Code | `auto_map` in `config.json` or `tokenizer_config.json` (`trust_remote_code`) | `model.remote-code.required` |
| | `auto_map` pointing at another repository (`org/repo--module.Class`) | `model.remote-code.external` |
| Templates | Template-injection constructs; invisible characters | `model.template.*` |
| Licence | Declared licences (licence files, card, GGUF, Modelfile, Ollama layer) combined and evaluated against `licences` in policy | `licence.*` |
| Provenance | Hugging Face download records (`.cache/huggingface/download/*.metadata`): weights against their sha256 ETag, small files against their git blob hash; Ollama blobs against their digests | `model.provenance.checksum-mismatch` (final) |
| Approval | Package against `allowlists.models`, by unit digest or by identity and revision | `model.allowlist.unapproved` |
| Trust | Strongest verification on each artifact against `trust.minimum` for its kind | `trust.upstream.insufficient` |
| Request | A content entry declared with `unit: model-package` produced one | `request.content.unit-missing` |

`model.provenance.checksum-mismatch` is **final** like the bundle's own integrity checks: content that differs from the publisher's own record is a hash mismatch, which no policy or approval overrides. Everything else is a policy matter; for example, `trust_remote_code` is a high-severity blocker by default, overridable by a quorum.

### Second layer of trust

Each artifact carries `Verification` records with a `TrustLevel`:

| Evidence | Level |
|---|---|
| Hugging Face download record, Ollama manifest digest | `checksum`: matches a record that travelled with the delivery |
| Policy model allowlist matched by **unit digest** | `pinned-checksum`: matches a digest the receiving side pinned |
| Policy model allowlist matched by identity and revision | `asserted` |
| Signature verified against a pinned key | `signature` (OpenSSF model signing, phase 1d) |

`trust.minimum` in the policy sets the floor per kind, e.g. `{"model.*": pinned-checksum}`. The practical way to reach `pinned-checksum` for a model is to approve it once by its unit digest (shown by `superscrubber104 model inspect --json` and in every package's SBOM component as `superscrubber104:unit-digest`).

## 19.3 The record

`Unit.attributes` for a model package:

| Key | Contents |
|---|---|
| `identity` | name, architecture, modelType, parameters, sizeLabel, publisher |
| `weights` | formats, files, tensors, bytes, dtypes (or GGUF tensor types), quantization, sharded, index |
| `config` | vocab_size, hidden_size, num_hidden_layers, max_position_embeddings, torch_dtype |
| `tokenizer` | files, type, tokens |
| `chatTemplates` | per template: source (`file#key`), sha256, length |
| `remoteCode` | required, autoMap references, code files |
| `adapter` | type, baseModel, rank, alpha, targetModules |
| `embedding` | dimension, pooling, normalize (sentence-transformers) |
| `multimodal` | projectors |
| `licence` | expression, every declaration with its source, gated |
| `modelCard` | pipelineTag, baseModel, libraryName, language, tags, datasets, intendedUse, limitations |
| `provenance` | method, upstream (type, reference, revision, digest), verifiedFiles, weightFilesWithoutRecord, conversion (safetensors `__metadata__`) |
| `allowlist` | the matching entry and how it matched |

`Unit.requires` holds base-model and Modelfile requirements with the package that satisfies them, if any. Each package contributes one CycloneDX `machine-learning-model` component, with a `pkg:huggingface/...@<commit>` purl when the upstream is known.

## 19.4 Policy knobs

```yaml
licences:
  allow: [Apache-2.0, MIT]
  requireApproval: [LicenseRef-*]        # Llama, Gemma, Qwen and other model licences
allowlists:
  models:
    mode: enforce                          # report: informational only
    entries:
      - digest: "sha256:..."               # unit digest: pins every member file
      - id: huggingface:example-org/tiny-chat
        revision: 0123456789abcdef0123456789abcdef01234567
  pickle-globals:
    mode: report
    entries: ["sklearn.*"]                 # classes trusted to run on load
trust:
  minimum:
    "model.*": pinned-checksum
rules:
  - rule: "model.pickle.unknown-import"
    disposition: require-approval          # instead of the default block
```

## 19.5 Known limits

- **Keras `.h5`** is searched for Lambda markers, not parsed; layer names are not available.
- **TensorFlow SavedModel and TFLite** custom operators are not detected; those files are reported as not inspected.
- **Compressed joblib** files are not decompressed; their pickle checks are reported as not assessed. Uncompressed joblib stores array data inside the pickle stream, so the walk stops at the first array and the rest is reported as not assessed.
- **GGUF tensor sizes** are checked only for quantisation types with a well-known fixed layout (F32, F16, BF16, Q4_0 ... Q8_K, IQ4_NL, IQ4_XS, integer types); tensors of other types are listed but not size-checked.
- **Hugging Face cache layout** (`models--org--name/snapshots/<commit>/` with symlinks into `blobs/`) is not understood: links are recorded, never followed. Download with `local_dir` instead; its records are understood.
- **Download records, Ollama blobs and ONNX external data inside archives** are not resolved; those checks are reported as not assessed.
- **Multimodal**: projectors are recorded; whether an architecture *needs* one is not checked. `mmproj` GGUF files form their own packages and are not linked to their model.
- **OpenSSF model signatures** are not verified yet (phase 1d). Conversion history is limited to what safetensors `__metadata__` records.
- **Target compatibility** (link to a `RuntimeProfile`) arrives with runtime profiles (1b).
- **Custom model code** is flagged and pinned by hash; it is not yet scanned (SAST, secrets and egress checks arrive with task 7).
- **Licence identification** is by distinctive phrases and identifiers, not a legal comparison; anything else is reported as unidentified. A package classifier that names only a family (`BSD License`) is not reported when another declaration identifies a licence in that family (`BSD-3-Clause`).
