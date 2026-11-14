"""Runtime profiles, the detected inference stack, and compatibility.

**The detected stack** is assembled from everything delivered: Python distributions
(``torch 2.4.0+cu121`` gives CUDA 12.1; ``nvidia-cudnn-cu12`` gives cuDNN), OS packages
(``cuda-cudart-12-4``, ``libcudnn9``, ``libnccl2``, ``nvidia-driver-550``), container images
(``CUDA_VERSION`` and friends from NVIDIA base images; ``vllm/vllm-openai``, ``tritonserver``,
``ollama`` and other server image names), installers and server binaries recognised by the
runtime handler.

**A runtime profile** (``kind: RuntimeProfile``) declares the stack its models were tested on.
Each declared component must be delivered, at the declared version, or listed under
``highSide`` as already installed there; each declared model must be a delivered model package.

**Compatibility** is checked on the delivered stack, and on each profile's effective stack
(delivered plus declared plus high side):

* NVIDIA driver against CUDA, from NVIDIA's published table: a driver older than the CUDA major
  version's minimum cannot run it; one older than the exact release's minimum relies on CUDA
  minor-version compatibility (low severity: JIT-compiled PTX is not available);
* one Python environment mixing CUDA major versions (``+cu118`` beside ``nvidia-*-cu12``);
* the policy's own ``runtime.compatibility`` rules.
"""

import re
from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace

from airlock import __version__
from airlock.core.canonical import JSON, jsonable
from airlock.core.interfaces import Assembly, Context
from airlock.core.model import (
    Artifact,
    Component,
    Requirement,
    Severity,
    Subject,
    ToolRef,
    Unit,
    UnitClaim,
    UnitKind,
    UnitMember,
)
from airlock.core.policy import CompatibilityRule
from airlock.units.facts import as_dict, as_list, as_str
from airlock.versions import matches_declared, satisfies

TOOL = ToolRef("airlock.runtime-profile", __version__)

# Minimum Linux driver for each CUDA release (GA), from NVIDIA's CUDA Toolkit release notes,
# and the minimum for each major version under minor-version compatibility.
CUDA_DRIVER = {
    (11, 0): "450.36.06", (11, 1): "455.23", (11, 2): "460.27.03", (11, 3): "465.19.01",
    (11, 4): "470.42.01", (11, 5): "495.29.05", (11, 6): "510.39.01", (11, 7): "515.43.04",
    (11, 8): "520.61.05", (12, 0): "525.60.13", (12, 1): "530.30.02", (12, 2): "535.54.03",
    (12, 3): "545.23.06", (12, 4): "550.54.14", (12, 5): "555.42.02", (12, 6): "560.28.03",
    (12, 8): "570.26", (12, 9): "575.51.03", (13, 0): "580.65.06",
}  # fmt: skip
CUDA_FAMILY_DRIVER = {11: "450.80.02", 12: "525.60.13", 13: "580.65.06"}

_SERVERS = {"vllm", "tgi", "tritonserver", "ollama", "llama.cpp", "sglang", "tensorrt-llm"}
_PYPI_SERVERS = {
    "vllm": "vllm", "sglang": "sglang", "text-generation-server": "tgi",
    "tensorrt-llm": "tensorrt-llm", "llama-cpp-python": "llama.cpp",
}  # fmt: skip
_IMAGE_SERVERS = (
    (re.compile(r"(^|/)vllm/vllm-openai$"), "vllm"),
    (re.compile(r"(^|/)huggingface/text-generation-inference$"), "tgi"),
    (re.compile(r"(^|/)nvidia/tritonserver$"), "tritonserver"),
    (re.compile(r"(^|/)ollama/ollama$"), "ollama"),
    (re.compile(r"(^|/)(ggerganov|ggml-org)/llama\.cpp$"), "llama.cpp"),
    (re.compile(r"(^|/)lmsysorg/sglang$"), "sglang"),
)
_IMAGE_ENV = {
    "CUDA_VERSION": "cuda", "NV_CUDNN_VERSION": "cudnn", "CUDNN_VERSION": "cudnn",
    "NCCL_VERSION": "nccl", "TENSORRT_VERSION": "tensorrt", "TRT_VERSION": "tensorrt",
    "ROCM_VERSION": "rocm",
}  # fmt: skip
_CU_LOCAL = re.compile(r"\+cu(\d{2,3})$")
_CU_NAME = re.compile(r"-cu(?:da)?(\d{2})x?(?:-|$)|^jax-cuda(\d{2})-")
_OS_PACKAGES = (
    (re.compile(r"^cuda-(?:cudart|runtime|toolkit|libraries)-(\d+)-(\d+)$"), "cuda"),
    (re.compile(r"^libcudnn\d+"), "cudnn"),
    (re.compile(r"^libnccl2$"), "nccl"),
    (re.compile(r"^(?:nvidia-driver|libnvidia-compute)-\d+"), "nvidia-driver"),
    (re.compile(r"^(?:libnvinfer\d+|tensorrt)$"), "tensorrt"),
)


@dataclass(slots=True)
class Stack:
    """Component name -> {version or "" -> where it was found}."""

    found: dict[str, dict[str, str]]

    def add(self, name: str, version: str | None, source: str) -> None:
        self.found.setdefault(name, {}).setdefault(version or "", source)

    def versions(self, name: str) -> list[str]:
        return [v for v in self.found.get(name, {}) if v]

    def has(self, name: str) -> bool:
        return name in self.found

    def summary(self) -> dict[str, JSON]:
        return {
            name: jsonable(sorted(v for v in versions if v) or ["unknown version"])
            for name, versions in sorted(self.found.items())
        }


def _cuda_from_local(version: str) -> str | None:
    match = _CU_LOCAL.search(version)
    if not match:
        return None
    digits = match.group(1)
    return f"{digits[:-1]}.{digits[-1]}"


def _canon(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def detect_stack(artifacts: Sequence[Artifact], components: Sequence[Component]) -> Stack:
    stack = Stack({})
    for component in components:
        purl, version = component.purl or "", component.version or ""
        where = component.evidence[0].display if component.evidence else component.name
        name = _canon(component.name)
        if purl.startswith("pkg:pypi/"):
            stack.add(name, version, where)
            if name in _PYPI_SERVERS:
                stack.add(_PYPI_SERVERS[name], version, where)
            if cuda := _cuda_from_local(version):
                stack.add("cuda", cuda, where)
            if name.startswith("nvidia-cuda-runtime-cu"):
                stack.add("cuda", ".".join(version.split(".")[:2]), where)
            elif name.startswith("nvidia-cudnn-cu"):
                stack.add("cudnn", version, where)
            elif name.startswith("nvidia-nccl-cu"):
                stack.add("nccl", version, where)
            elif name in ("tensorrt", "tensorrt-cu12", "tensorrt-cu11"):
                stack.add("tensorrt", version, where)
        elif purl.startswith(("pkg:deb/", "pkg:rpm/", "pkg:apk/")):
            for regex, key in _OS_PACKAGES:
                if match := regex.match(component.name):
                    if key == "cuda" and match.groups():
                        stack.add("cuda", f"{match.group(1)}.{match.group(2)}", where)
                    else:
                        stack.add(key, re.split(r"[-~+]", version)[0], where)
                    if key == "nccl" and (built := re.search(r"\+cuda(\d+\.\d+)", version)):
                        stack.add("cuda", built.group(1), where)
    for artifact in artifacts:
        runtime = artifact.metadata.get("runtime")
        if isinstance(runtime, dict) and isinstance(runtime.get("component"), str):
            where = artifact.ref.display
            stack.add(str(runtime["component"]), as_str(runtime.get("version")), where)
            if runtime["component"] == "cuda" and as_str(runtime.get("driver")):
                stack.add("nvidia-driver", as_str(runtime.get("driver")), f"{where} (bundled)")
            if runtime["component"] == "triton":
                stack.add("tritonserver", None, where)
        container = artifact.metadata.get("container")
        for image in as_list(as_dict(container).get("images")):
            info = as_dict(image)
            where = f"{artifact.ref.display} ({as_str(info.get('name')) or 'image'})"
            for key, value in as_dict(info.get("settings")).items():
                if key in _IMAGE_ENV and isinstance(value, str) and value:
                    stack.add(_IMAGE_ENV[key], value, where)
            if image := as_str(info.get("name")):
                repository, _, tag = (
                    image.rpartition(":") if ":" in image.rsplit("/", 1)[-1] else (image, "", "")
                )
                for regex, server in _IMAGE_SERVERS:
                    if regex.search(repository):
                        stack.add(server, tag.lstrip("v").split("-")[0] or None, where)
    return stack


# --- checks -------------------------------------------------------------------------------------


def _builtin_rules() -> list[CompatibilityRule]:
    rules = []
    for major, driver in CUDA_FAMILY_DRIVER.items():
        rules.append(
            CompatibilityRule(
                {"cuda": f">={major},<{major + 1}"},
                {"nvidia-driver": f">={driver}"},
                f"CUDA {major}.x needs NVIDIA driver {driver} or newer",
            )
        )
    for (major, minor), driver in CUDA_DRIVER.items():
        rules.append(
            CompatibilityRule(
                {
                    "cuda": f">={major}.{minor},<{major}.{minor + 1}",
                    "nvidia-driver": f">={CUDA_FAMILY_DRIVER[major]}",  # else the rule above
                },
                {"nvidia-driver": f">={driver}"},
                f"CUDA {major}.{minor} needs driver {driver} for full compatibility; older "
                "drivers of the same major version rely on minor-version compatibility "
                "(no PTX JIT)",
                Severity.LOW,
            )
        )
    return rules


def _check_rules(
    stack: Stack, rules: Iterable[CompatibilityRule], subject: Subject, ctx: Context
) -> None:
    for rule in rules:
        when_met = all(
            any(satisfies(v, constraint) for v in stack.versions(key))
            for key, constraint in rule.when.items()
        )
        if not when_met:
            continue
        for key, constraint in rule.requires.items():
            versions = stack.versions(key)
            if versions and not any(satisfies(v, constraint) for v in versions):
                ctx.recorder.fail(
                    "runtime.incompatible",
                    subject,
                    tool=TOOL,
                    detail={
                        "reason": rule.reason,
                        "when": dict(rule.when),
                        "requires": {key: constraint},
                        "found": {key: versions, **{k: stack.versions(k) for k in rule.when}},
                    },
                    severity=rule.severity,
                    discriminator=f"{rule.reason}|{key}",
                )


def _mixed_cuda(units: Sequence[Unit], components: Sequence[Component], ctx: Context) -> None:
    for unit in units:
        if unit.kind is not UnitKind.PYTHON_ENVIRONMENT:
            continue
        members = {m.artifact for m in unit.members}
        majors: dict[str, list[str]] = defaultdict(list)
        for component in components:
            if not (component.purl or "").startswith("pkg:pypi/"):
                continue
            if not members & set(component.evidence):
                continue
            version = component.version or ""
            cuda = _cuda_from_local(version)
            name_match = _CU_NAME.search(_canon(component.name))
            major = (
                cuda.split(".")[0]
                if cuda
                else next((g for g in (name_match.groups() if name_match else ()) if g), None)
            )
            if major:
                majors[major].append(f"{component.name} {version}")
        if len(majors) > 1:
            ctx.recorder.fail(
                "runtime.incompatible",
                Subject.of_unit(unit),
                tool=TOOL,
                detail={
                    "reason": "one environment holds packages built for different CUDA major "
                    "versions",
                    "packages": {f"CUDA {k}": v[:10] for k, v in sorted(majors.items())},
                },
                discriminator="mixed-cuda",
            )


class RuntimeProfileAssembler:
    name = "runtime-profile"
    version = __version__
    kind = UnitKind.RUNTIME_PROFILE

    def assemble(self, claims: Sequence[UnitClaim], ctx: Context) -> Iterable[Assembly]:
        for claim in claims:
            name = as_str(claim.facts.get("name")) or "runtime profile"
            yield Assembly(
                Unit(
                    kind=UnitKind.RUNTIME_PROFILE,
                    name=name,
                    root=claim.root,
                    members=(UnitMember("profile", claim.artifact, claim.sha256),),
                    attributes={"declared": jsonable(claim.facts.get("spec"))},
                )
            )


def _declared(spec: dict[str, JSON]) -> list[tuple[str, str]]:
    """(component, version) pairs a profile declares."""
    out: list[tuple[str, str]] = []
    server = as_dict(spec.get("server"))
    if name := as_str(server.get("name")):
        key = {"triton": "tritonserver", "text-generation-inference": "tgi"}.get(
            name.lower(), name.lower()
        )
        out.append((key, as_str(server.get("version")) or ""))
    accelerator = as_dict(spec.get("accelerator"))
    for field, key in (("driver", "nvidia-driver"), ("cuda", "cuda"), ("cudnn", "cudnn"),
                       ("nccl", "nccl"), ("tensorrt", "tensorrt"), ("rocm", "rocm")):  # fmt: skip
        if value := accelerator.get(field):
            out.append((key, str(value)))
    for framework in as_list(spec.get("frameworks")):
        info = as_dict(framework)
        if name := as_str(info.get("name")):
            out.append(
                (_canon(name), as_str(info.get("version")) or str(info.get("version") or ""))
            )
    return out


def _model_matches(reference: str, unit: Unit) -> bool:
    wanted = reference.lower().rstrip("/")
    root = unit.root.display.lower().rstrip("/")
    return wanted in (root, unit.name.lower()) or root.endswith(f"/{wanted}")


def link_runtime_profiles(
    units: Sequence[Unit],
    artifacts: Sequence[Artifact],
    components: Sequence[Component],
    ctx: Context,
) -> list[Unit]:
    stack = detect_stack(artifacts, components)
    rules = [*_builtin_rules(), *ctx.policy.compatibility]
    _mixed_cuda(units, components, ctx)
    models = [u for u in units if u.kind is UnitKind.MODEL_PACKAGE]
    profiles = [u for u in units if u.kind is UnitKind.RUNTIME_PROFILE]
    if not profiles:
        _check_rules(stack, rules, Subject.bundle(), ctx)
        inference = {
            k for k in stack.found if k in _SERVERS or k in ("cuda", "torch", "tensorflow", "jax")
        }
        if models and inference:
            ctx.recorder.fail(
                "runtime.profile.undeclared",
                Subject.bundle(),
                tool=TOOL,
                detail={"models": [m.id for m in models][:20], "detected": stack.summary()},
            )
        return list(units)

    linked: list[Unit] = []
    for unit in units:
        if unit.kind is not UnitKind.RUNTIME_PROFILE:
            linked.append(unit)
            continue
        spec = as_dict(unit.attributes.get("declared"))
        subject = Subject.of_unit(unit)
        requires: list[Requirement] = []
        high_side = {
            _canon(str(as_dict(e).get("name"))): str(as_dict(e).get("version") or "")
            for e in as_list(spec.get("highSide"))
            if as_dict(e).get("name")
        }
        effective = Stack({k: dict(v) for k, v in stack.found.items()})
        for model in as_list(spec.get("models")):
            reference = str(model)
            match = next((m for m in models if _model_matches(reference, m)), None)
            requires.append(
                Requirement(
                    "model",
                    reference,
                    UnitKind.MODEL_PACKAGE,
                    satisfied_by=match.id if match else None,
                )
            )
            if match is None:
                ctx.recorder.fail(
                    "runtime.model.missing", subject, tool=TOOL, detail={"model": reference},
                    discriminator=reference,
                )  # fmt: skip
        for key, version in _declared(spec):
            delivered = stack.versions(key) if stack.has(key) else []
            satisfied_by = None
            if stack.has(key):
                satisfied_by = "delivery"
                if (
                    version
                    and delivered
                    and not any(matches_declared(v, version) for v in delivered)
                ):
                    ctx.recorder.fail(
                        "runtime.component.mismatch",
                        subject,
                        tool=TOOL,
                        detail={"component": key, "declared": version, "delivered": delivered},
                        discriminator=key,
                    )
            elif key in high_side:
                satisfied_by = f"high-side:{key}"
                effective.add(key, high_side[key] or version or None, "high side")
            else:
                ctx.recorder.fail(
                    "runtime.component.missing",
                    subject,
                    tool=TOOL,
                    detail={
                        "component": key,
                        "version": version or None,
                        "note": "deliver it, or list it under highSide with the installed version",
                    },
                    discriminator=key,
                )
            if version and not delivered:
                effective.add(key, version, "declared")
            requires.append(
                Requirement("runtime", key, version=version or None, satisfied_by=satisfied_by)
            )
        _check_rules(effective, rules, subject, ctx)
        attributes = {**unit.attributes, "detected": stack.summary()}
        linked.append(replace(unit, requires=(*unit.requires, *requires), attributes=attributes))
    return linked
