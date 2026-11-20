# 10. Offline readiness and egress

A delivery that tries to reach the internet behind the gap either breaks (operational risk) or becomes an exfiltration channel (security risk). `superscrubber104 offline-check` (also run inside `pack`/`verify`) produces an **offline readiness report**:

- **Auto-download paths:**
  - Hugging Face `from_pretrained` without local paths or offline flags
  - missing `HF_HUB_OFFLINE`/`TRANSFORMERS_OFFLINE`
  - `ollama pull` in scripts or entrypoints
  - `pip`/`npm`/`apt`/`dnf` installs at container start or runtime
  - `torch.hub` and NLTK/spaCy model downloads
  - Terraform providers or Helm dependencies not vendored
- **Telemetry and tracking:**
  - framework/library analytics (e.g. Gradio, Streamlit, Chroma, Hugging Face telemetry, LangSmith/W&B tracing, PostHog-style SDKs)
  - IDE and extension telemetry settings
  - container images with analytics enabled by default
- **Auto-update mechanisms:** IDE/extension auto-update, runtime self-updaters, update checks at startup.
- **Hard-coded external endpoints:**
  - public URLs and hostnames, public DNS resolvers, NTP servers
  - cloud AI API endpoints and SDK clients (OpenAI, Anthropic, Azure, Bedrock, Vertex…) and their API-key variables
  - external container registries in manifests
- **Expected configuration:** a recommended offline configuration (environment variables and settings) is generated for the high side as part of the evidence.

Each finding is classified as *will break*, *egress risk*, or *informational*. Policy decides blockers.
