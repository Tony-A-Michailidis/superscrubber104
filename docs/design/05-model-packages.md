# 7. Model packages

A model crosses as a **complete, self-consistent unit**, never as loose weight files.

**A `ModelPackage` records and checks:**

- **Identity:** model name, family, parameter count, publisher, upstream reference (Hugging Face repo id + **commit SHA**, Ollama registry name + **manifest and layer digests**, or vendor download reference).
- **Weights:** every shard present and matching the index; total size consistent with the config; dtype/quantization recorded.
- **Tokenizer:** files present, hashed, vocabulary size consistent with the config.
- **Chat template:** extracted (from `tokenizer_config.json` or GGUF metadata), hashed and inspected for unusual Jinja constructs. A changed template alters behaviour even with identical weights.
- **Configs:** `config.json`/`generation_config.json` present and consistent with the weights (architecture, layers, hidden size).
- **Code:** any `trust_remote_code` requirement (blocker by default; see [§6](04-artifact-coverage.md)).
- **Adapters:** base model id + hash link verified.
- **Multimodal parts:** projectors/encoders present when the architecture needs them.
- **Licence and use terms:** licence text present, licence identified (Apache-2.0, MIT, Llama, Gemma, Qwen and other custom terms), gated/accepted-terms status recorded, policy allow/deny.
- **Model card:** present or flagged missing; intended use and limitations captured as evidence.
- **Provenance:** publisher checksums verified; OpenSSF model-signing (Sigstore-based) signatures verified when present; conversion history recorded (e.g. "converted from PyTorch to safetensors by X with tool Y v Z").
- **Target compatibility:** the runtime(s) the package is intended for (link to a `RuntimeProfile`).

`airlock model inspect <path>` produces this record standalone. `airlock model convert` is a **stretch goal** (pickle → safetensors in a sandboxed plugin), since conversion itself requires loading the unsafe format.
