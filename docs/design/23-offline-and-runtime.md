# 23. Offline readiness and runtime profiles

> **Status: implemented** (brought forward from 1b at the owner's request). Spec: [§10](08-offline-readiness.md) (offline readiness), [§8](06-runtime-profiles.md) (runtime profiles), the inference-runtime and GPU-stack rows of [§6](04-artifact-coverage.md).

A delivery that tries to reach the internet behind the gap either breaks (an operational risk) or becomes an exfiltration channel (a security risk). A model that crosses without the stack it was tested on may not run at all. This doc covers both.

## 23.1 Offline readiness

`airlock offline-check <paths>` prints the report; `pack`, `verify` and `model inspect` record the same findings. Every finding carries an `impact` attribute: `will-break`, `egress-risk` or `informational`. Where a setting fixes it, the finding also carries that `fix`, and the command collects the fixes into a **recommended high-side configuration** (environment variables and editor settings).

### What is read

The delivery's **own** code and configuration: source, notebooks, shell scripts and entrypoints, Dockerfiles, Compose files, Kubernetes manifests, `.env` and other configuration files, and VS Code settings. Third-party code (`site-packages`, `node_modules`, `vendor`, wheels, npm tarballs, container image layers) is left out: libraries are full of download code paths the application may never take. Lockfiles are left out too; their remote sources are reported by the package handlers. Container images are judged by their configuration: the entrypoint and command, and the recorded offline settings in their environment.

### Findings

| Rule | Impact | Found |
|---|---|---|
| `offline.download.runtime` | will-break | `snapshot_download`, `hf_hub_download`; `pipeline("task")` without a model; `torch.hub`; `nltk.download`; spaCy downloads; `ollama pull`; installs and fetches (`pip install`, `apt-get install`, `wget`, `curl`, `git clone`) in scripts and entrypoints; installs and fetches in a Dockerfile's `RUN` (it will not build on the high side); an image whose entrypoint or command downloads at start; tiktoken without `TIKTOKEN_CACHE_DIR`; **a model or dataset id passed to `from_pretrained`, `SentenceTransformer`, `CrossEncoder` or `load_dataset` that is not in the delivery** (unless the call passes `local_files_only=True`) |
| `offline.config.missing` | will-break | Hugging Face libraries used without `HF_HUB_OFFLINE`/`TRANSFORMERS_OFFLINE` set anywhere; NLTK without `NLTK_DATA` |
| `offline.telemetry.enabled` | egress-risk | Gradio, Streamlit, Chroma, vLLM, Weights & Biases used without their switch-off setting; LangSmith tracing switched on; Sentry, PostHog, Mixpanel, Datadog SDKs; VS Code `telemetry.telemetryLevel` not `off` |
| `offline.update.enabled` | egress-risk | VS Code `update.mode`, `extensions.autoUpdate`, `extensions.autoCheckUpdates` on (explicitly or by default) |
| `offline.endpoint.cloud-ai` | egress-risk | hosted AI hostnames (OpenAI, Azure OpenAI, Anthropic, Bedrock, Vertex, Gemini, Cohere, Mistral, Groq, OpenRouter, Together, Fireworks, DeepSeek, Perplexity, Hugging Face inference, xAI, Voyage, Jina) at high severity; AI client constructors without a base URL (`OpenAI()`, `ChatOpenAI()`, `Anthropic()`, ...) at medium: they call their vendor by default |
| `offline.registry.external` | will-break | images named in Compose files, Kubernetes manifests and Dockerfile `FROM` lines (not build stages) that are not delivered; Docker Hub's implicit registry and `library/` namespace are normalised, and digests are compared |
| `offline.endpoint.external` | informational | external hosts named in code and configuration, one finding per file (local, private, example and XML-namespace hosts excluded) |
| `offline.network.public-service` | informational | public DNS resolvers and NTP pools |

A setting counts wherever it is made: a `.env` file, a manifest, a Dockerfile `ENV`, `os.environ` in code, a library's own switch in code (`analytics_enabled=False`, `anonymized_telemetry=False`, `gatherUsageStats = false`, `wandb.init(mode="offline")`), or a delivered image's environment. The decisions that need the whole delivery (is that model delivered? that image? is that setting made anywhere?) are made by `airlock/checks/offline.py` after every file has been read.

### Policy

```yaml
rules:
  - rule: "offline.*"
    where: {impact: egress-risk}
    disposition: block
  - rule: "offline.*"
    paths: ["dev-tools/**"]
    disposition: warn
```

## 23.2 The detected stack

Every delivery's inference stack is assembled from what is in it:

| Source | Components |
|---|---|
| Python distributions | every distribution by name and version; CUDA from local versions (`torch 2.4.0+cu121` → CUDA 12.1) and from `nvidia-cuda-runtime-cuNN`; cuDNN, NCCL, TensorRT from their NVIDIA wheels; servers from `vllm`, `sglang`, `tensorrt-llm`, `llama-cpp-python` |
| OS packages (DEB, RPM, APK) | `cuda-cudart-12-4` and friends, `libcudnn9`, `libnccl2` (with its `+cuda12.4`), `nvidia-driver-*`, `libnvinfer*` |
| Container images | `CUDA_VERSION`, `NV_CUDNN_VERSION`, `NCCL_VERSION`, `TENSORRT_VERSION` from NVIDIA base images; servers from image names (`vllm/vllm-openai`, `huggingface/text-generation-inference`, `nvidia/tritonserver`, `ollama/ollama`, `ggml-org/llama.cpp`, `lmsysorg/sglang`) |
| Installers | NVIDIA driver `.run` files, CUDA toolkit `.run` (with its bundled driver), cuDNN and TensorRT archives, driver and CUDA DEB/RPM files, by NVIDIA's file naming |
| Server binaries | `ollama`, `llama-server`, `llama-cli`, `tritonserver` |
| Triton model repositories | `config.pbtxt`: platform, backend, instance kind. A Python-backend model is `runtime.triton.python-backend`: its `model.py` runs inside the server |

When models and an inference stack cross without a runtime profile, `runtime.profile.undeclared` (info) records the detected stack for reference.

## 23.3 Runtime profiles

A `RuntimeProfile` file crosses with the models and declares what they were tested on:

```yaml
apiVersion: airlock/v1alpha1
kind: RuntimeProfile
metadata: {name: chat-gpu}
spec:
  models: [models/tiny-chat]
  server: {name: vllm, version: 0.6.3}
  accelerator: {vendor: nvidia, driver: "550.54.15", cuda: "12.4", cudnn: "9.1", computeCapability: "8.0", memoryGiB: 40}
  frameworks:
    - {name: torch, version: 2.4.0}
    - {name: transformers, version: "4.44"}
  os: {name: ubuntu, version: "22.04"}
  highSide:                        # already installed there (from its inventory)
    - {name: nvidia-driver, version: 550.54.15}
  settings: {contextLength: 8192, quantization: awq, temperature: 0}
```

It forms a `runtime-profile` unit. Each declared model must be a delivered model package (`runtime.model.missing`). Each declared component (server, driver, CUDA, cuDNN, NCCL, TensorRT, frameworks) must be delivered or listed under `highSide` (`runtime.component.missing`). A delivered component must match the declared version: a declared `12.4` accepts `12.4.1`, and operators and globs are honoured (`runtime.component.mismatch`). The unit's requirements record what satisfied each one: `delivery`, `high-side:<name>`, or nothing.

## 23.4 Compatibility

Checked on the delivered stack, and on each profile's effective stack (delivered, declared and high side):

* **Driver against CUDA**, from NVIDIA's published table of minimum Linux drivers per CUDA release (`units/runtime_profile.py`, `CUDA_DRIVER`). A driver below the CUDA major version's minimum (450.80.02 for 11.x, 525.60.13 for 12.x, 580.65.06 for 13.x) cannot run it: high. One between that and the exact release's minimum relies on minor-version compatibility (no PTX JIT): low.
* **One Python environment with two CUDA major versions** (`torch+cu118` beside `nvidia-*-cu12`): high.
* **The policy's own table**:

  ```yaml
  runtime:
    compatibility:
      - when: {vllm: "0.6.*"}
        requires: {torch: "2.4.*", cuda: ">=12.1"}
        reason: vLLM 0.6 wheels are built against torch 2.4 and CUDA 12
  ```

  Keys are stack components (any of the names above, or a Python distribution). Values are constraints: comma-separated clauses, each an operator (`>=`, `<=`, `>`, `<`, `==`, `!=`) and a version, or a glob. When every `when` holds and a `requires` component is present at a version that does not satisfy its constraint, the result is `runtime.incompatible`.

## 23.5 Rules

| Rule | Severity |
|---|---|
| `offline.endpoint.cloud-ai` | high (medium for a client without a base URL) |
| `offline.download.runtime`, `offline.telemetry.enabled`, `offline.update.enabled`, `offline.registry.external` | medium |
| `offline.config.missing`, `offline.endpoint.external`, `offline.network.public-service` | low |
| `runtime.component.missing`, `runtime.model.missing`, `runtime.incompatible` | high (low for minor-version compatibility) |
| `runtime.component.mismatch`, `runtime.triton.python-backend` | medium |
| `runtime.profile.undeclared` | info |

None is final: each describes what content does or needs.

## 23.6 Known limits

- **Offline detection is by pattern.** A download behind a helper function, a URL assembled at run time, or telemetry in a library the table does not know is missed. Third-party code is deliberately not read.
- **Hub ids** are matched to delivered directories and packages by name. A model delivered under a different path is reported as missing; deliver it at the path the code uses, or point the code at the local path.
- **Templated images** (`${TAG}`, `{{ .Values.image }}`) cannot be resolved and are skipped; Helm charts are not rendered.
- **The driver table is for Linux.** Windows drivers have different minimums. Compute capability, GPU memory and TensorRT engines' target architecture are recorded from the profile, not checked.
- **Versions from container image names** are taken from the tag; a tag like `latest` gives no version.
