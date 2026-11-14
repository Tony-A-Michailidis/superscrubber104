"""Offline readiness questions that need the whole delivery to answer.

Handlers record what each file uses (libraries, offline settings, model ids passed to
``from_pretrained``, images named by manifests); this check decides, across the delivery:

* a model or dataset id that code loads from the hub is ``offline.download.runtime`` unless the
  delivery holds it (a directory of that name, a model package of that name, a hub cache entry);
* an image a Compose file, Kubernetes manifest or Dockerfile names is ``offline.registry.external``
  unless an image of that name (or digest) is in the delivery;
* a library that downloads on demand or reports telemetry is a finding unless its setting is
  made somewhere: in a ``.env`` file, a manifest, code, or a delivered image's environment.

Every finding carries the setting that fixes it; ``airlock offline-check`` collects them into a
recommended configuration for the high side.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from airlock import __version__
from airlock.core.interfaces import Context
from airlock.core.model import Artifact, Severity, Subject, ToolRef, Unit, UnitKind

TOOL = ToolRef("airlock.offline", __version__)
_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off"})


@dataclass(frozen=True, slots=True)
class _Need:
    libraries: tuple[str, ...]
    rule: str
    impact: str
    severity: Severity
    what: str
    accepted: tuple[tuple[str, frozenset[str] | None], ...]  # key, accepted values (None: any)
    fix: tuple[tuple[str, str], ...]


_HF = (
    "transformers", "huggingface_hub", "datasets", "sentence_transformers", "diffusers", "peft",
    "timm", "open_clip", "@xenova/transformers", "@huggingface/transformers",
)  # fmt: skip
_CACHE = "<directory with the encodings>"
_NEEDS = (
    _Need(_HF, "offline.config.missing", "will-break", Severity.LOW,
          "Hugging Face libraries are used without offline mode",
          (("HF_HUB_OFFLINE", _TRUE), ("TRANSFORMERS_OFFLINE", _TRUE)),
          (("HF_HUB_OFFLINE", "1"), ("TRANSFORMERS_OFFLINE", "1"), ("HF_DATASETS_OFFLINE", "1"),
           ("HF_HUB_DISABLE_TELEMETRY", "1"))),
    _Need(("tiktoken",), "offline.download.runtime", "will-break", Severity.MEDIUM,
          "tiktoken downloads its encodings on first use",
          (("TIKTOKEN_CACHE_DIR", None),), (("TIKTOKEN_CACHE_DIR", _CACHE),)),
    _Need(("nltk",), "offline.config.missing", "will-break", Severity.LOW,
          "NLTK looks for its data online", (("NLTK_DATA", None),),
          (("NLTK_DATA", "<directory with the NLTK data>"),)),
    _Need(("gradio", "@gradio/client"), "offline.telemetry.enabled", "egress-risk", Severity.MEDIUM,
          "Gradio sends usage analytics by default", (("GRADIO_ANALYTICS_ENABLED", _FALSE),),
          (("GRADIO_ANALYTICS_ENABLED", "False"),)),
    _Need(("streamlit",), "offline.telemetry.enabled", "egress-risk", Severity.MEDIUM,
          "Streamlit gathers usage statistics by default",
          (("STREAMLIT_BROWSER_GATHER_USAGE_STATS", _FALSE),),
          (("STREAMLIT_BROWSER_GATHER_USAGE_STATS", "false"),)),
    _Need(("chromadb",), "offline.telemetry.enabled", "egress-risk", Severity.MEDIUM,
          "Chroma sends anonymised telemetry by default", (("ANONYMIZED_TELEMETRY", _FALSE),),
          (("ANONYMIZED_TELEMETRY", "False"),)),
    _Need(("vllm",), "offline.telemetry.enabled", "egress-risk", Severity.MEDIUM,
          "vLLM reports usage statistics by default",
          (("VLLM_NO_USAGE_STATS", _TRUE), ("DO_NOT_TRACK", _TRUE)),
          (("VLLM_NO_USAGE_STATS", "1"), ("DO_NOT_TRACK", "1"))),
    _Need(("wandb",), "offline.telemetry.enabled", "egress-risk", Severity.MEDIUM,
          "Weights & Biases syncs runs to its servers by default",
          (("WANDB_MODE", frozenset({"offline", "disabled"})), ("WANDB_DISABLED", _TRUE)),
          (("WANDB_MODE", "offline"),)),
)  # fmt: skip


def _offline(artifact: Artifact) -> Mapping[str, object]:
    meta = artifact.metadata.get("offline")
    return meta if isinstance(meta, dict) else {}


def _settings(artifacts: Sequence[Artifact]) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for artifact in artifacts:
        settings = _offline(artifact).get("settings")
        for key, value in settings.items() if isinstance(settings, dict) else []:
            found.setdefault(str(key), set()).add(str(value).strip("\"'").lower())
        container = artifact.metadata.get("container")
        images = container.get("images") if isinstance(container, dict) else None
        for image in images if isinstance(images, list) else []:
            env = image.get("settings") if isinstance(image, dict) else None
            for key, value in env.items() if isinstance(env, dict) else []:
                found.setdefault(str(key), set()).add(str(value).lower())
    return found


def _satisfied(need: _Need, settings: dict[str, set[str]]) -> bool:
    for key, accepted in need.accepted:
        values = settings.get(key, set())
        if values and (accepted is None or values & accepted):
            return True
    return False


def _normalise_image(reference: str) -> tuple[str, str]:
    """(name, tag or digest), with Docker Hub's implicit registry and namespace removed."""
    name, _, digest = reference.partition("@")
    tag = "latest"
    if ":" in name.rsplit("/", 1)[-1]:
        name, tag = name.rsplit(":", 1)
    for prefix in ("docker.io/", "index.docker.io/", "registry-1.docker.io/"):
        name = name.removeprefix(prefix)
    return name.removeprefix("library/"), digest or tag


def _registry(name: str) -> str:
    first = name.split("/", 1)[0]
    is_host = "/" in name and ("." in first or ":" in first or first == "localhost")
    return first if is_host else "docker.io"


def _delivered_images(artifacts: Sequence[Artifact]) -> tuple[set[tuple[str, str]], set[str]]:
    names: set[tuple[str, str]] = set()
    digests: set[str] = set()
    for artifact in artifacts:
        container = artifact.metadata.get("container")
        images = container.get("images") if isinstance(container, dict) else None
        for image in images if isinstance(images, list) else []:
            if not isinstance(image, dict):
                continue
            for key in ("manifestDigest", "configDigest"):
                if isinstance(image.get(key), str):
                    digests.add(str(image[key]))
            if isinstance(image.get("name"), str):
                names.add(_normalise_image(str(image["name"])))
    return names, digests


def _present_locally(model: str, artifacts: Sequence[Artifact], units: Sequence[Unit]) -> bool:
    lowered = model.lower()
    last = lowered.rsplit("/", 1)[-1]
    cache = "models--" + lowered.replace("/", "--")
    for unit in units:
        if unit.kind in (UnitKind.MODEL_PACKAGE, UnitKind.DATASET) and (
            unit.name.lower() in (lowered, last)
            or unit.root.display.lower().rstrip("/").endswith((f"/{last}", lowered))
            or unit.root.display.lower() == last
        ):
            return True
    for artifact in artifacts:
        path = f"/{artifact.ref.display.lower()}"
        if f"/{lowered}/" in path or f"/{cache}/" in path:
            return True
    return False


def check_offline(artifacts: Sequence[Artifact], units: Sequence[Unit], ctx: Context) -> None:
    recorder = ctx.recorder
    settings = _settings(artifacts)
    users: dict[str, Artifact] = {}
    for artifact in artifacts:
        libraries = _offline(artifact).get("libraries")
        for library in libraries if isinstance(libraries, list) else []:
            users.setdefault(str(library), artifact)

    for need in _NEEDS:
        user = next((users[lib] for lib in need.libraries if lib in users), None)
        if user is None:
            continue
        if _satisfied(need, settings):
            recorder.passed(need.rule)
            continue
        recorder.fail(
            need.rule,
            Subject.of_artifact(user.ref),
            tool=TOOL,
            detail={"what": need.what, "fix": dict(need.fix)},
            attributes={"impact": need.impact, "what": need.what},
            severity=need.severity,
            discriminator=need.what,
        )

    for artifact in artifacts:
        refs = _offline(artifact).get("hubRefs")
        for ref in refs if isinstance(refs, list) else []:
            model = str(ref.get("id")) if isinstance(ref, dict) else ""
            if not model or _present_locally(model, artifacts, units):
                continue
            recorder.fail(
                "offline.download.runtime",
                Subject.of_artifact(artifact.ref, locator=f"line {ref.get('line')}"),
                tool=TOOL,
                detail={
                    "what": "loads a model or dataset from the hub that is not in the delivery",
                    "model": model,
                    "fix": {"HF_HUB_OFFLINE": "1"},
                },
                attributes={"impact": "will-break", "what": "hub model not delivered"},
                discriminator=f"hub:{model}",
            )

    names, digests = _delivered_images(artifacts)
    for artifact in artifacts:
        images = _offline(artifact).get("images")
        for entry in images if isinstance(images, list) else []:
            reference = str(entry.get("image")) if isinstance(entry, dict) else ""
            if not reference or "$" in reference or "{{" in reference:
                continue  # templated: cannot be resolved statically
            name, tag = _normalise_image(reference)
            if (name, tag) in names or tag in digests:
                recorder.passed("offline.registry.external")
                continue
            recorder.fail(
                "offline.registry.external",
                Subject.of_artifact(artifact.ref, locator=f"line {entry.get('line')}"),
                tool=TOOL,
                detail={"image": reference, "registry": _registry(name)},
                attributes={"impact": "will-break", "what": "image not delivered"},
                discriminator=reference,
            )
