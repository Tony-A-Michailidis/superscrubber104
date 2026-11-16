"""The inference stack: runtime profile declarations, GPU stack installers, servers, Triton.

* **Runtime profiles** (``kind: RuntimeProfile`` YAML) declare the stack a set of models was tested
  on: inference server, accelerator, driver, CUDA, cuDNN, frameworks, OS, and what the high side
  already has installed. The runtime-profile assembler checks them against what is delivered.
* **GPU stack installers** are recognised by NVIDIA's own file naming: the driver
  (``NVIDIA-Linux-x86_64-550.54.15.run``), the CUDA toolkit (``cuda_12.4.1_550.54.15_linux.run``,
  which bundles a driver), cuDNN and TensorRT archives, and driver/CUDA DEB and RPM packages.
* **Inference servers** delivered as binaries (``ollama``, ``llama-server``, ``tritonserver``).
* **Triton model repositories**: ``config.pbtxt`` is read for platform, backend and instance
  kind; a Python-backend model runs its own ``model.py`` inside the server and is flagged.

Versions found here, in Python packages (``torch 2.4.0+cu121``, ``nvidia-cudnn-cu12``), in OS
packages and in container images (``CUDA_VERSION``) together make the delivery's detected stack.
"""

import re
from typing import Any

import yaml

from airlock import __version__
from airlock.core.interfaces import ArtifactView, Context, Detection, Inspection
from airlock.core.model import Subject, ToolRef, UnitKind
from airlock.core.yamlio import load_untrusted_yaml
from airlock.handlers.common import make_claim, mapping, name_of, read_text

TOOL = ToolRef("airlock.runtime", __version__)

# (component, regex over the file name with a "version" group)
_V = r"\d+\.\d+(?:\.\d+)?"  # 550.54.15, 12.4.1, 12.4
_V4 = r"\d+\.\d+\.\d+(?:\.\d+)?"  # 9.1.0.70, 10.0.1.6
_INSTALLERS = (
    ("nvidia-driver", re.compile(rf"^NVIDIA-Linux-[\w]+-(?P<version>{_V})\.run$")),
    ("cuda", re.compile(rf"^cuda_(?P<version>{_V})_(?P<driver>{_V})_linux.*\.run$")),
    ("cuda", re.compile(rf"^cuda_(?P<version>{_V})_(?P<driver>{_V})_windows\.exe$")),
    ("cudnn", re.compile(rf"^cudnn-[\w-]+?-(?P<version>{_V4})_cuda(?P<cuda>\d+)-archive")),
    ("tensorrt", re.compile(rf"^TensorRT-(?P<version>{_V4})\..*cuda-(?P<cuda>\d+\.\d+)")),
    ("nvidia-driver", re.compile(rf"^nvidia-driver-(?:\d+-)?(?:open-)?\d*[_-](?P<version>{_V})")),
    (
        "cuda",
        re.compile(
            rf"^cuda-(?:toolkit|runtime|cudart)-(?P<major>\d+)-(?P<minor>\d+)[_-](?P<version>{_V})"
        ),
    ),
    ("cudnn", re.compile(rf"^libcudnn\d+(?:-cuda-\d+)?[_-](?P<version>{_V4})")),
)
_SERVER_BINARIES = {
    "ollama": "ollama",
    "ollama.exe": "ollama",
    "llama-server": "llama.cpp",
    "llama-server.exe": "llama.cpp",
    "llama-cli": "llama.cpp",
    "llama-cli.exe": "llama.cpp",
    "tritonserver": "triton",
}
_PBTXT_FIELD = re.compile(
    r"^\s*(?P<key>name|platform|backend|max_batch_size)\s*:\s*\"?(?P<value>[^\"\s]+)", re.M
)


def _profile(view: ArtifactView, ctx: Context) -> Inspection:
    try:
        data = load_untrusted_yaml(read_text(view, 1 << 20))
    except (yaml.YAMLError, ValueError, RecursionError) as exc:
        # A profile that cannot be read declares nothing: what it would have been checked for is
        # said to be not assessed, and the delivery is then treated as having no profile.
        ctx.recorder.not_assessed(
            ("runtime.component.missing", "runtime.component.mismatch", "runtime.model.missing"),
            Subject.of_artifact(view.ref),
            tool=TOOL,
            reason=f"the runtime profile is not valid YAML: {str(exc)[:200]}",
        )
        return Inspection(kind="runtime.profile", metadata={"runtimeProfile": {"error": True}})
    doc = mapping(data)
    spec = mapping(doc.get("spec"))
    name = str(mapping(doc.get("metadata")).get("name") or name_of(view.ref))
    facts: dict[str, Any] = {"name": name, "spec": spec}
    return Inspection(
        kind="runtime.profile",
        metadata={"runtimeProfile": {"name": name}},
        claims=(make_claim(view, UnitKind.RUNTIME_PROFILE, "profile", facts, root=view.ref),),
    )


def _installer(view: ArtifactView, ctx: Context) -> Inspection:
    name = name_of(view.ref)
    for component, regex in _INSTALLERS:
        if match := regex.match(name):
            found = {k: v for k, v in match.groupdict().items() if v}
            if component == "cuda" and "major" in found:
                found["version"] = f"{found.pop('major')}.{found.pop('minor')}"
            info: dict[str, object] = {"component": component, **found}
            return Inspection(kind=f"runtime.{component}", metadata={"runtime": info})
    raise ValueError("not an installer")  # unreachable after detect()


def _server(view: ArtifactView, ctx: Context) -> Inspection:
    server = _SERVER_BINARIES[name_of(view.ref).lower()]
    return Inspection(
        kind="runtime.server", metadata={"runtime": {"component": server, "binary": True}}
    )


def _triton(view: ArtifactView, ctx: Context) -> Inspection:
    text = read_text(view, 1 << 20)
    fields = {m["key"]: m["value"] for m in _PBTXT_FIELD.finditer(text)}
    gpu = "KIND_GPU" in text
    backend = fields.get("backend") or fields.get("platform")
    subject = Subject.of_artifact(view.ref)
    if fields.get("backend") == "python":
        ctx.recorder.fail(
            "runtime.triton.python-backend",
            subject,
            tool=TOOL,
            detail={"model": fields.get("name"), "note": "model.py runs inside the server"},
        )
    else:
        ctx.recorder.passed("runtime.triton.python-backend")
    info = {"component": "triton", "model": fields.get("name"), "backend": backend, "gpu": gpu}
    return Inspection(kind="runtime.triton-model", metadata={"runtime": info})


def _dispatch(view: ArtifactView):  # type: ignore[no-untyped-def]
    name = name_of(view.ref)
    lowered = name.lower()
    if lowered.endswith((".yaml", ".yml")) and re.search(
        rb"(?m)^kind:\s*RuntimeProfile\s*$", view.head(4096)
    ):
        return _profile
    if any(regex.match(name) for _, regex in _INSTALLERS):
        return _installer
    if lowered in _SERVER_BINARIES and view.head(4)[:2] in (b"\x7fE", b"MZ", b"\xcf\xfa"):
        return _server
    if lowered == "config.pbtxt":
        return _triton
    return None


class RuntimeHandler:
    name = "runtime"
    version = "1"
    kinds = frozenset(
        {
            "runtime.profile",
            "runtime.nvidia-driver",
            "runtime.cuda",
            "runtime.cudnn",
            "runtime.tensorrt",
            "runtime.server",
            "runtime.triton-model",
        }
    )

    def detect(self, artifact: ArtifactView) -> Detection | None:
        return Detection("runtime", 65) if _dispatch(artifact) else None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        handler = _dispatch(artifact)
        assert handler is not None  # noqa: S101 - only called after detect()
        result: Inspection = handler(artifact, ctx)
        return result
