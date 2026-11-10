# 19. Suggested repo layout

```
airlock/
  cli.py
  walker.py          # traversal, safe archive extraction, streaming hashing
  manifest.py  sbom.py  signing.py  policy.py  request.py  custody.py  volumes.py  delta.py
  units/             # ModelPackage, RuntimeProfile, PythonEnvironment, RepoMirror, KnowledgeBase, ContainerImage, VMImage, PatchSet
  handlers/
    generic.py  archive.py  binary.py  document.py
    ai/          # safetensors.py gguf.py pickle_scan.py keras.py tf.py onnx.py opaque.py llamafile.py
                 # model_files.py (tokenizer/config/template) remote_code.py adapters.py
                 # runtimes.py gpu_stack.py knowledge.py datasets.py notebooks.py eval_assets.py
    agents/      # mcp.py hooks_skills.py permissions.py prompts.py
    devenv/      # vsix.py python_env.py conda.py node_env.py jvm_env.py go_env.py rust_env.py mirrors.py docsets.py
    container.py  vm.py  iac.py
    source/      # per-language lockfile/manifest parsers
    packages/    # wheel, npm, jar, gomod, crate, nuget, gem, rpm, deb
    windows.py  firmware.py  feeds.py
  checks/            # cross-cutting: secrets, licences, allowlists, prompt_injection, offline_readiness, freshness
  patch/             # inventory collectors, advisory parsers (ALSA, USN, MS), planner, stagers
  eval/              # eval set model, runners (via plugins), comparison
  stagers/           # harbor, dnf, apt, pypi, npm, model store, wsus
  plugins/           # syft grype trivy semgrep bandit clamav gitleaks qemu_img libguestfs ollama llamacpp osslsigncode
  evidence/          # control catalog, mapping, report rendering (md/html/json/oscal)
tests/
examples/            # generic mixed sample delivery (see below)
docs/design/         # detailed specs moved out of this file
```

**`examples/` fixtures (all synthetic and tiny):**
- small app source in Python and TS
- an image tarball
- a tiny safetensors model package (sharded, with tokenizer and template), plus a malicious-pickle test file built safely in tests
- a model with `trust_remote_code`
- a LoRA adapter, and a GGUF with metadata
- an MCP server and config, and an agent hook
- a VSIX stub
- a wheelhouse with lockfile
- a small vector index with a mismatched embedding model
- a corpus with an injected-instruction document
- a Helm chart
- qcow2 images generated with qemu-img (clean, backing file, format-confused) + Glance metadata
- sample Alma/Ubuntu repo metadata
- a code sample that phones home
