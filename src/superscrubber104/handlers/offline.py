"""Offline readiness: what a delivery will try to fetch, report or call once it runs.

This reads the delivery's own code and configuration (source, notebooks, scripts, Dockerfiles,
Compose and Kubernetes manifests, ``.env`` and settings files). Third-party code (``site-packages``,
``node_modules``, wheels, image layers) is left out: libraries are full of download code paths
that the application may never take, so what matters is what the application itself calls.

Clear-cut cases are findings here: a snapshot download, ``torch.hub``, ``nltk.download``,
``ollama pull``, installs in scripts and Dockerfiles, telemetry switched on, cloud AI hosts and
clients, public DNS and NTP servers, external hosts. What depends on the rest of the delivery is
recorded in the artifact's ``offline`` metadata and decided afterwards by ``check_offline``: a
model id passed to ``from_pretrained`` (is that model in the delivery?), images named by
manifests (are they delivered?), libraries with telemetry or on-demand downloads (is their
offline setting set anywhere?).
"""

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass

from superscrubber104 import __version__
from superscrubber104.core.interfaces import ArtifactView, Context, Detection, Inspection
from superscrubber104.core.model import UNCLASSIFIED, ArtifactRef, Severity, Subject, ToolRef
from superscrubber104.handlers.common import full_path, name_of, read_text

TOOL = ToolRef("superscrubber104.offline", __version__)
_LIMIT = 8 << 20
H, M, L = Severity.HIGH, Severity.MEDIUM, Severity.LOW

_CODE = frozenset(
    [
        ".py",
        ".pyw",
        ".ipynb",
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".jsx",
        ".sh",
        ".bash",
        ".zsh",
        ".ps1",
        ".psm1",
        ".bat",
        ".cmd",
        ".rb",
        ".go",
        ".java",
        ".kt",
        ".rs",
        ".cs",
        ".r",
    ]
)
_CONFIG = frozenset([".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".env", ".properties"])
_LOCKFILES = frozenset(
    [
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "uv.lock",
        "pipfile.lock",
        "composer.lock",
        "cargo.lock",
        "go.sum",
        "pylock.toml",
    ]
)
_DEPENDENCY = re.compile(
    r"(^|/)(site-packages|dist-packages|node_modules|\.venv|venv|\.tox|__pycache__|\.git|vendor)/"
)
_PACKAGE_ARCHIVES = (".whl", ".tgz", ".egg", ".jar", ".nupkg", ".gem", ".crate", ".tar.gz", ".zip")
_LAYER = re.compile(r"(^|/)(layer\.tar|blobs/sha256/[0-9a-f]{64})$")


@dataclass(frozen=True, slots=True)
class _Pattern:
    rule: str
    impact: str
    severity: Severity
    what: str
    regex: re.Pattern[str]
    fix: tuple[tuple[str, str], ...] = ()


def _p(rule: str, impact: str, severity: Severity, what: str, regex: str, *fix: str) -> _Pattern:
    pairs = tuple((f.split("=", 1)[0], f.split("=", 1)[1]) for f in fix)
    return _Pattern(rule, impact, severity, what, re.compile(regex), pairs)


_DL, _TEL, _AI = (
    "offline.download.runtime",
    "offline.telemetry.enabled",
    "offline.endpoint.cloud-ai",
)
_WB, _EG = "will-break", "egress-risk"
_INSTALL = (
    r"\b(?:pip3?|uv\s+pip|conda|mamba|micromamba|npm|yarn|pnpm|apt-get|apt|yum|dnf|apk|gem)"
    r"\s+(?:install|add|i|ci)\b"
)
_FETCH = r"\b(?:wget|curl)\s+[^|;&]*https?://|\bgit\s+clone\b|\bgit\s+lfs\s+pull\b"

# Applied to code, scripts and configuration.
_PATTERNS = (
    _p(_DL, _WB, M, "hub snapshot download", r"\b(?:snapshot_download|hf_hub_download)\s*\("),
    _p(
        _DL,
        _WB,
        M,
        "pipeline without a model downloads a default model",
        r"\bpipeline\s*\(\s*[\"'][\w-]+[\"']\s*\)",
    ),
    _p(
        _DL,
        _WB,
        M,
        "torch.hub download",
        r"\btorch\.hub\.(?:load|load_state_dict_from_url|download_url_to_file)\s*\(|\bload_state_dict_from_url\s*\(",
    ),
    _p(_DL, _WB, M, "NLTK data download", r"\bnltk\.download\s*\("),
    _p(_DL, _WB, M, "spaCy model download", r"\bspacy\.cli\.download\s*\(|\bspacy\s+download\b"),
    _p(_DL, _WB, M, "ollama pull", r"\bollama\s+pull\b|\bollama\.pull\s*\("),
    _p(
        _TEL,
        _EG,
        M,
        "LangSmith tracing switched on",
        r"\b(?:LANGCHAIN_TRACING_V2|LANGSMITH_TRACING)[\"']?\s*[=:,]\s*[\"']?(?i:true|1)\b",
        "LANGCHAIN_TRACING_V2=false",
        "LANGSMITH_TRACING=false",
    ),
    _p(
        _TEL,
        _EG,
        M,
        "Sentry error reporting",
        r"\bsentry_sdk\.init\s*\(|@sentry/(?:node|browser|react)",
    ),
    _p(
        _TEL,
        _EG,
        M,
        "PostHog analytics",
        r"\b(?:from|import)\s+posthog\b|\bposthog-js\b|\bnew PostHog\(",
    ),
    _p(_TEL, _EG, M, "Mixpanel analytics", r"\b(?:from|import)\s+mixpanel\b|\bmixpanel\.init\("),
    _p(_TEL, _EG, M, "Datadog tracing", r"\b(?:from|import)\s+ddtrace\b|\bdd-trace\b"),
    _p(
        _AI,
        _EG,
        H,
        "cloud AI endpoint",
        r"\b(?:api\.openai\.com|[\w-]+\.openai\.azure\.com|api\.anthropic\.com|bedrock-runtime(?:\.[\w-]+)?\.amazonaws\.com"
        r"|[\w-]*aiplatform\.googleapis\.com|generativelanguage\.googleapis\.com|api\.cohere\.(?:ai|com)"
        r"|api\.mistral\.ai|api\.groq\.com|openrouter\.ai|api\.together\.(?:xyz|ai)|api\.fireworks\.ai"
        r"|api\.deepseek\.com|api\.perplexity\.ai|api-inference\.huggingface\.co|router\.huggingface\.co"
        r"|api\.x\.ai|api\.voyageai\.com|api\.jina\.ai)\b",
    ),
    _p(
        "offline.network.public-service",
        "informational",
        L,
        "public DNS or time server",
        r"(?<![\d.])(?:8\.8\.8\.8|8\.8\.4\.4|1\.1\.1\.1|1\.0\.0\.1|9\.9\.9\.9|208\.67\.222\.222)(?![\d.])"
        r"|\b(?:[\w-]+\.)?pool\.ntp\.org\b|\btime\.(?:google|windows|apple|cloudflare)\.com\b",
    ),
)
# Applied to shell scripts, entrypoints, notebooks and Makefiles: installing or fetching on run.
_RUNTIME_SHELL = (
    _p(_DL, _WB, M, "installs packages when it runs", _INSTALL),
    _p(_DL, _WB, M, "fetches content when it runs", _FETCH),
)
_DOCKER_RUN = re.compile(r"^\s*RUN\b(?P<cmd>.*)$", re.I)
_DOCKER_FROM = re.compile(
    r"^\s*FROM\s+(?:--platform=\S+\s+)?(?P<image>\S+)(?:\s+AS\s+(?P<stage>\S+))?", re.I
)
_MANIFEST_IMAGE = re.compile(r"^\s*-?\s*image:\s*[\"']?(?P<image>[^\s\"'#]+)")
_HUB_REF = re.compile(
    r"(?:\.from_pretrained|\bSentenceTransformer|\bCrossEncoder|\bload_dataset)\s*\(\s*"
    r"(?:pretrained_model_name_or_path\s*=\s*|path\s*=\s*)?[\"'](?P<id>[A-Za-z0-9][\w.-]*(?:/[\w.-]+)?)[\"']"
)
_LOCAL_BUILDERS = frozenset(
    [
        "json",
        "csv",
        "parquet",
        "text",
        "imagefolder",
        "audiofolder",
        "videofolder",
        "arrow",
        "webdataset",
        "pandas",
        "sql",
        "generator",
        "xml",
    ]
)
_CLIENT = re.compile(
    r"\b(?P<client>OpenAI|AsyncOpenAI|AzureOpenAI|Anthropic|AsyncAnthropic|ChatOpenAI|ChatAnthropic"
    r"|OpenAIEmbeddings|ChatGoogleGenerativeAI|ChatMistralAI|ChatCohere)\s*\((?P<args>[^)]{0,400})\)"
)
_BASE_URL = re.compile(r"base_url|api_base|openai_api_base|baseURL|anthropic_api_url|endpoint")
_IMPORT = re.compile(
    r"^\s*(?:from|import)\s+(?P<lib>transformers|huggingface_hub|datasets|sentence_transformers"
    r"|diffusers|gradio|streamlit|chromadb|vllm|wandb|tiktoken|nltk|spacy|langchain\w*|llama_index"
    r"|peft|accelerate|timm|open_clip|ultralytics)\b"
    r"|require\(\s*[\"'](?P<js>chromadb|@gradio/client|@xenova/transformers|@huggingface/transformers)[\"']",
    re.M,
)
_SETTING = re.compile(
    r"\b(?P<key>HF_HUB_OFFLINE|TRANSFORMERS_OFFLINE|HF_DATASETS_OFFLINE|HF_HUB_DISABLE_TELEMETRY"
    r"|DO_NOT_TRACK|ANONYMIZED_TELEMETRY|GRADIO_ANALYTICS_ENABLED|STREAMLIT_BROWSER_GATHER_USAGE_STATS"
    r"|VLLM_NO_USAGE_STATS|WANDB_MODE|WANDB_DISABLED|TIKTOKEN_CACHE_DIR|NLTK_DATA|HF_HOME"
    r"|SENTENCE_TRANSFORMERS_HOME|TORCH_HOME|OLLAMA_MODELS)[\"']?\s*[=:,]\s*[\"']?(?P<value>[\w./:\\~$-]*)"
)
_CODE_SETTINGS = (
    (re.compile(r"\banalytics_enabled\s*=\s*False\b"), "GRADIO_ANALYTICS_ENABLED", "False"),
    (re.compile(r"\banonymized_telemetry\s*=\s*False\b"), "ANONYMIZED_TELEMETRY", "False"),
    (
        re.compile(r"\bgatherUsageStats\s*=\s*false\b"),
        "STREAMLIT_BROWSER_GATHER_USAGE_STATS",
        "false",
    ),
    (
        re.compile(r"\bwandb\.init\([^)]*mode\s*=\s*[\"'](?:offline|disabled)"),
        "WANDB_MODE",
        "offline",
    ),
)
_URL_HOST = re.compile(r"https?://(?P<host>[A-Za-z0-9.-]+\.[A-Za-z]{2,})(?::\d+)?")
_QUIET_HOSTS = re.compile(
    r"(^|\.)(localhost|local|internal|lan|intranet|corp|home\.arpa|example\.(com|org|net)|test|invalid"
    r"|w3\.org|json-schema\.org|schema\.org|purl\.org|xmlns\.com|openxmlformats\.org|spdx\.org"
    r"|opensource\.org|apache\.org|gnu\.org|mozilla\.org|python\.org|readthedocs\.io)$"
)
_VSCODE_DEFAULTS = (
    ("telemetry.telemetryLevel", "all", "off", "offline.telemetry.enabled", _EG),
    ("update.mode", "default", "none", "offline.update.enabled", _EG),
    ("extensions.autoUpdate", True, False, "offline.update.enabled", _EG),
    ("extensions.autoCheckUpdates", True, False, "offline.update.enabled", _EG),
)


def _role(view: ArtifactView) -> str | None:
    name = name_of(view.ref).lower()
    path = full_path(view.ref).lower()
    if name in _LOCKFILES:
        return None
    if name == "settings.json" and ("/.vscode/" in f"/{path}" or "code/user/" in path):
        return "vscode"
    if name.startswith(("dockerfile", "containerfile")) or name.endswith(".dockerfile"):
        return "dockerfile"
    if name.startswith(("docker-compose", "compose.")) and name.endswith((".yml", ".yaml")):
        return "manifest"
    if name.startswith(("entrypoint", "docker-entrypoint", "start", "run")) and name.endswith(
        ".sh"
    ):
        return "shell"
    if name in ("procfile", "makefile") or name.endswith((".sh", ".bash", ".ps1", ".bat", ".cmd")):
        return "shell"
    if name.endswith(".ipynb"):
        return "notebook"
    extension = name[name.rfind(".") :] if "." in name else ""
    if extension in _CODE:
        return "code"
    if extension in _CONFIG or name.startswith(".env"):
        return "config"
    return None


_INSTALLED = re.compile(
    r"(^|/)(site-packages|dist-packages|node_modules|\.venv|venv|\.tox|__pycache__|\.git)/"
)


def deployable(ref: ArtifactRef) -> bool:
    """Configuration someone would apply: anywhere in the delivery, archives included, except
    inside installed packages and container image layers (what is baked into an image is not
    applied to the cluster)."""
    parts = (ref.path, *ref.member)
    return not any(_INSTALLED.search(f"/{p}") for p in parts) and not any(
        _LAYER.search(p) for p in parts[:-1]
    )


def first_party(ref: ArtifactRef) -> bool:
    """The delivery's own files: not third-party packages, not inside packages or image layers."""
    parts = (ref.path, *ref.member)
    if any(_DEPENDENCY.search(f"/{p}") for p in parts):
        return False
    if ref.member:
        if ref.path.lower().endswith(_PACKAGE_ARCHIVES) and not ref.path.lower().endswith(".zip"):
            return False
        if any(_LAYER.search(p) for p in parts[:-1]):
            return False
    return True


def _lines(text: str) -> Iterator[tuple[int, str]]:
    for number, line in enumerate(text.splitlines(), start=1):
        if len(line) <= 4096:
            yield number, line


class OfflineHandler:
    """Runs on first-party code and configuration; never classifies a file."""

    name = "offline"
    version = "1"
    kinds: frozenset[str] = frozenset()

    def detect(self, artifact: ArtifactView) -> Detection | None:
        if _role(artifact) and first_party(artifact.ref) and artifact.size <= _LIMIT:
            return Detection(UNCLASSIFIED, 0)
        return None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        role = _role(artifact)
        assert role is not None  # noqa: S101 - only called after detect()
        text = read_text(artifact, _LIMIT)
        hits: dict[tuple[str, str], list[tuple[int, str, _Pattern]]] = {}
        if role == "vscode":
            self._vscode(artifact, text, ctx)
        patterns = list(_PATTERNS)
        if role == "shell":  # notebooks: notebook.cell.network covers installs
            patterns += _RUNTIME_SHELL
        meta: dict[str, object] = {}
        hub: list[dict[str, object]] = []
        images: list[dict[str, object]] = []
        stages: set[str] = set()
        hosts: dict[str, int] = {}
        for number, line in _lines(text):
            for pattern in patterns:
                if pattern.regex.search(line):
                    hits.setdefault((pattern.rule, pattern.what), []).append(
                        (number, line, pattern)
                    )
            if role == "dockerfile":
                if match := _DOCKER_FROM.match(line):
                    image = match["image"]
                    if match["stage"]:
                        stages.add(match["stage"].lower())
                    if image.lower() != "scratch" and image.lower() not in stages:
                        images.append({"image": image, "line": number})
                if (match := _DOCKER_RUN.match(line)) and re.search(
                    f"{_INSTALL}|{_FETCH}", match["cmd"]
                ):
                    what = "the image build installs or fetches over the network"
                    pattern = _Pattern(_DL, _WB, M, what, _DOCKER_RUN)
                    hits.setdefault((_DL, what), []).append((number, line, pattern))
            elif role in ("manifest", "config") and (match := _MANIFEST_IMAGE.match(line)):
                images.append({"image": match["image"], "line": number})
            for match in _HUB_REF.finditer(line):
                if "local_files_only=True" not in line and match["id"] not in _LOCAL_BUILDERS:
                    hub.append({"id": match["id"], "line": number})
            for match in _CLIENT.finditer(line):
                if not _BASE_URL.search(match["args"]):
                    what = f"{match['client']} client without a base URL calls its vendor"
                    pattern = _Pattern(_AI, _EG, M, what, _CLIENT)
                    hits.setdefault((_AI, what), []).append((number, line, pattern))
            if role in ("code", "config", "shell", "manifest", "dockerfile"):
                for match in _URL_HOST.finditer(line):
                    host = match["host"].lower()
                    if not _QUIET_HOSTS.search(host) and not re.match(r"^[\d.]+$", host):
                        hosts.setdefault(host, number)
        self._record(ctx, artifact, hits)
        if hosts:
            ctx.recorder.fail(
                "offline.endpoint.external",
                Subject.of_artifact(artifact.ref),
                tool=TOOL,
                detail={
                    "what": f"names {len(hosts)} external host(s)",
                    "hosts": [{"host": h, "line": n} for h, n in sorted(hosts.items())][:30],
                },
                attributes={"impact": "informational"},
            )
        else:
            ctx.recorder.passed("offline.endpoint.external")
        libraries = sorted({m["lib"] or m["js"] for m in _IMPORT.finditer(text)})
        settings = {m["key"]: m["value"] for m in _SETTING.finditer(text)}
        for regex, key, value in _CODE_SETTINGS:
            if regex.search(text):
                settings.setdefault(key, value)
        found: dict[str, object] = {
            "libraries": libraries,
            "settings": settings,
            "hubRefs": hub[:200],
            "images": images[:200],
        }
        meta.update({key: value for key, value in found.items() if value})
        return Inspection(kind=UNCLASSIFIED, metadata={"offline": meta} if meta else {})

    def _record(
        self,
        ctx: Context,
        view: ArtifactView,
        hits: dict[tuple[str, str], list[tuple[int, str, _Pattern]]],
    ) -> None:
        recorded = set()
        for (rule, what), found in sorted(hits.items()):
            number, line, pattern = found[0]
            detail: dict[str, object] = {
                "what": what,
                "lines": [n for n, _, _ in found][:50],
                "evidence": line.strip()[:200],
            }
            if pattern.fix:
                detail["fix"] = dict(pattern.fix)
            ctx.recorder.fail(
                rule,
                Subject.of_artifact(view.ref, locator=f"line {number}"),
                tool=TOOL,
                detail=detail,
                attributes={"impact": pattern.impact, "what": what},
                severity=pattern.severity,
                discriminator=what,
            )
            recorded.add(rule)
        for rule in (_DL, _TEL, _AI, "offline.network.public-service"):
            if rule not in recorded:
                ctx.recorder.passed(rule)

    def _vscode(self, view: ArtifactView, text: str, ctx: Context) -> None:
        cleaned = re.sub(r"^\s*//.*$", "", text, flags=re.M)
        try:
            settings = json.loads(cleaned)
        except ValueError:
            return
        if not isinstance(settings, dict):
            return
        for key, default, wanted, rule, impact in _VSCODE_DEFAULTS:
            value = settings.get(key, default)
            if value != wanted:
                ctx.recorder.fail(
                    rule,
                    Subject.of_artifact(view.ref, locator=key),
                    tool=TOOL,
                    detail={
                        "setting": key,
                        "value": value,
                        "default": key not in settings,
                        "fix": {key: wanted},
                    },
                    attributes={"impact": impact, "what": key},
                    discriminator=key,
                )
