"""Infrastructure code: Kubernetes manifests, Compose files, Helm charts, Terraform and Ansible.

What matters on the high side is what this code will do when it is applied there:

* **Workload posture** (Kubernetes pod specs in any workload kind, Compose services): privileged
  containers, host namespaces, container-runtime sockets, broad capabilities and host paths
  (``iac.workload.privileged``, ``iac.workload.host-access``), explicit root
  (``iac.workload.root``).
* **Images by tag** rather than digest (``iac.image.unpinned``): a tag can be repointed; a digest
  cannot. Whether each image is in the delivery is the offline check's job (doc 23).
* **Dependencies fetched at deploy time** (``iac.dependency.unresolvable``): Helm chart
  dependencies not vendored under ``charts/``, Terraform modules from registries or git not in
  ``.terraform/modules``, Ansible collections and roles not installed alongside.
* **Terraform providers**: ``.terraform.lock.hcl`` is a lockfile (``h1:`` and ``zh:`` hashes per
  provider); provider packages in a filesystem mirror are hashed against it (doc 29's assembler).

Templated files (Helm ``templates/``, anything with ``{{``) are not rendered; they are recorded as
not assessed for posture.
"""

import posixpath
import re
from collections.abc import Iterator, Mapping
from typing import Any

import yaml

from superscrubber104 import __version__
from superscrubber104.core.interfaces import ArtifactView, Context, Detection, Inspection
from superscrubber104.core.model import Subject, ToolRef, UnitClaim, UnitKind
from superscrubber104.core.yamlio import load_untrusted_yaml, load_untrusted_yaml_all
from superscrubber104.formats.golang import ZipHashError, zip_hash
from superscrubber104.handlers.common import (
    TooLarge,
    full_path,
    mapping,
    name_of,
    read_json,
    read_text,
)
from superscrubber104.handlers.offline import deployable
from superscrubber104.handlers.packages.locked import (
    component,
    distribution_claim,
    lockfile_claim,
    requirement,
)

TOOL = ToolRef("superscrubber104.iac", __version__)
_LIMIT = 16 << 20
_PROVIDER_LIMIT = 4 << 30  # the largest providers expand to several hundred megabytes
_K8S_API = re.compile(r"^apiVersion:\s*['\"]?(?P<api>[a-z0-9.-]+/)?v\d[a-z0-9]*['\"]?\s*$", re.M)
_K8S_KIND = re.compile(r"^kind:\s*['\"]?[A-Z][A-Za-z0-9]+['\"]?\s*$", re.M)
_COMPOSE = re.compile(r"^(docker-)?compose(\.[\w-]+)?\.ya?ml$")
_TF_ZIP = re.compile(
    r"^terraform-provider-(?P<type>[a-z0-9-]+)_(?P<version>[^_]+)_(?P<os>[a-z0-9]+)_(?P<arch>[a-z0-9]+)\.zip$"
)
_TF_BINARY = re.compile(
    r"^terraform-provider-(?P<type>[a-z0-9-]+)_v(?P<version>[^_]+?)(_x\d+)?(\.exe)?$"
)
_TF_PROVIDER = re.compile(r'provider\s+"(?P<address>[^"]+)"\s*\{(?P<body>.*?)\n\}', re.S)
_TF_MODULE = re.compile(r'^\s*module\s+"(?P<name>[^"]+)"\s*\{', re.M)
_TF_SOURCE = re.compile(r'^\s*source\s*=\s*"(?P<source>[^"]+)"', re.M)
_PRIVILEGED_CAPS = frozenset(
    {"ALL", "SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "SYS_RAWIO", "DAC_READ_SEARCH", "BPF"}
)
_HOST_CAPS = frozenset({"NET_ADMIN", "NET_RAW", "SYS_TIME", "SYS_BOOT"})
_RUNTIME_SOCKETS = ("docker.sock", "containerd.sock", "crio.sock", "podman.sock")
_SENSITIVE_HOST_PATHS = ("/", "/etc", "/root", "/proc", "/sys", "/var/lib/kubelet", "/boot", "/dev")
_POD_PATHS: Mapping[str, tuple[str, ...]] = {
    "Pod": ("spec",),
    "CronJob": ("spec", "jobTemplate", "spec", "template", "spec"),
}
_TEMPLATED_KINDS = frozenset(
    {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "ReplicationController"}
)

TERRAFORM = UnitKind.TERRAFORM_ENVIRONMENT


def _kind(view: ArtifactView) -> str | None:
    name = name_of(view.ref)
    lower = name.lower()
    path = full_path(view.ref)
    if lower == ".terraform.lock.hcl":
        return "terraform.lockfile"
    if lower.endswith(".tf"):
        return "terraform.config"
    if _TF_ZIP.match(name) or (_TF_BINARY.match(name) and path.count("/") >= 5):
        return "terraform.provider"
    if view.size > _LIMIT or not deployable(view.ref):
        return None
    if name == "Chart.yaml":
        return "helm.chart"
    if _COMPOSE.match(lower):
        return "compose.file"
    if lower in ("requirements.yml", "requirements.yaml") and (
        b"collections:" in view.head(4096)
        or b"roles:" in view.head(4096)
        or b"src:" in view.head(4096)
    ):
        return "ansible.requirements"
    if lower.endswith((".yaml", ".yml")):
        head = view.head(1 << 16).decode("utf-8", "replace")
        if "/templates/" in f"/{path}" and "{{" in head:
            return "helm.template"  # rendered at install time; the chart records it once
        if _K8S_KIND.search(head) and (match := _K8S_API.search(head)):
            if (match["api"] or "").startswith("superscrubber104/"):
                return None
            return "kubernetes.manifest"
    return None


def _dig(document: Any, path: tuple[str, ...]) -> Any:
    for key in path:
        document = document.get(key) if isinstance(document, dict) else None
    return document


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _image_problem(image: str) -> str | None:
    if "@sha256:" in image:
        return None
    last = image.rsplit("/", 1)[-1]
    if ":" not in last:
        return "no tag (means latest)"
    if last.endswith(":latest"):
        return "latest"
    return "tag, not digest"


class _Posture:
    """Collects posture problems per workload and records them."""

    def __init__(self, view: ArtifactView, ctx: Context) -> None:
        self.view, self.ctx = view, ctx
        self.counts = {"privileged": 0, "host": 0, "root": 0, "unpinned": 0}

    def record(
        self,
        workload: str,
        privileged: list[str],
        host: list[str],
        root: list[str],
        images: dict[str, str],
    ) -> None:
        subject = Subject.of_artifact(self.view.ref, locator=workload)
        for rule, items, key in (
            ("iac.workload.privileged", privileged, "privileged"),
            ("iac.workload.host-access", host, "host"),
            ("iac.workload.root", root, "root"),
        ):
            if items:
                self.counts[key] += 1
                self.ctx.recorder.fail(
                    rule,
                    subject,
                    tool=TOOL,
                    detail={"workload": workload, "settings": sorted(set(items))},
                    discriminator=workload,
                )
            else:
                self.ctx.recorder.passed(rule)
        if images:
            self.counts["unpinned"] += 1
            self.ctx.recorder.fail(
                "iac.image.unpinned",
                subject,
                tool=TOOL,
                detail={
                    "workload": workload,
                    "images": [{"image": i, "why": w} for i, w in sorted(images.items())],
                },
                discriminator=workload,
            )
        else:
            self.ctx.recorder.passed("iac.image.unpinned")

    def pod(self, workload: str, spec: dict[str, Any]) -> None:
        privileged: list[str] = []
        host: list[str] = []
        root: list[str] = []
        images: dict[str, str] = {}
        for flag, bucket in (("hostPID", privileged), ("hostNetwork", host), ("hostIPC", host)):
            if spec.get(flag) is True:
                bucket.append(flag)
        pod_security = mapping(spec.get("securityContext"))
        if pod_security.get("runAsUser") == 0:
            root.append("pod runAsUser: 0")
        if pod_security.get("runAsNonRoot") is False:
            root.append("pod runAsNonRoot: false")
        for volume in _list(spec.get("volumes")):
            path = str(_dig(volume, ("hostPath", "path")) or "")
            if not path:
                continue
            if path.endswith(_RUNTIME_SOCKETS):
                privileged.append(f"hostPath {path}")
            else:
                host.append(f"hostPath {path}")
        containers = [
            *_list(spec.get("initContainers")),
            *_list(spec.get("containers")),
            *_list(spec.get("ephemeralContainers")),
        ]
        for container in containers:
            if not isinstance(container, dict):
                continue
            name = str(container.get("name", "?"))
            security = mapping(container.get("securityContext"))
            if security.get("privileged") is True:
                privileged.append(f"{name}: privileged")
            if security.get("allowPrivilegeEscalation") is True:
                privileged.append(f"{name}: allowPrivilegeEscalation")
            if security.get("runAsUser") == 0:
                root.append(f"{name}: runAsUser 0")
            for cap in _list(_dig(security, ("capabilities", "add"))):
                cap = str(cap).upper().removeprefix("CAP_")
                if cap in _PRIVILEGED_CAPS:
                    privileged.append(f"{name}: capability {cap}")
                elif cap in _HOST_CAPS:
                    host.append(f"{name}: capability {cap}")
            for port in _list(container.get("ports")):
                if isinstance(port, dict) and port.get("hostPort"):
                    host.append(f"{name}: hostPort {port['hostPort']}")
            image = str(container.get("image") or "")
            if image and (problem := _image_problem(image)):
                images[image] = problem
        self.record(workload, privileged, host, root, images)


class IacHandler:
    name = "iac"
    version = "1"
    kinds = frozenset(
        {
            "kubernetes.manifest",
            "compose.file",
            "helm.chart",
            "helm.template",
            "terraform.lockfile",
            "terraform.config",
            "terraform.provider",
            "ansible.requirements",
        }
    )

    def detect(self, artifact: ArtifactView) -> Detection | None:
        kind = _kind(artifact)
        return Detection(kind, 75) if kind else None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        kind = _kind(artifact) or "kubernetes.manifest"
        if kind == "helm.template":
            return Inspection(kind=kind, metadata={"iac": {"templated": True}})
        try:
            if kind == "terraform.provider":
                return self._provider(artifact)
            if kind == "terraform.lockfile":
                return self._tf_lock(artifact)
            text = read_text(artifact, _LIMIT)
            if kind == "terraform.config":
                return self._tf_config(artifact, text, ctx)
            if "{{" in text:
                ctx.recorder.not_assessed(
                    ("iac.workload.privileged", "iac.workload.host-access", "iac.image.unpinned"),
                    Subject.of_artifact(artifact.ref),
                    tool=TOOL,
                    reason="templated (Helm or Go templates): deliver the rendered output to have "
                    "it checked",
                )
                return Inspection(kind=kind, metadata={"iac": {"templated": True}})
            if kind == "kubernetes.manifest":
                return self._kubernetes(artifact, text, ctx)
            if kind == "compose.file":
                return self._compose(artifact, text, ctx)
            if kind == "helm.chart":
                return self._helm(artifact, text, ctx)
            return self._ansible(artifact, text, ctx)
        except (yaml.YAMLError, TooLarge, ValueError, RecursionError) as exc:
            ctx.recorder.not_assessed(
                ("iac.workload.privileged", "iac.dependency.unresolvable"),
                Subject.of_artifact(artifact.ref),
                tool=TOOL,
                reason=f"could not be read: {str(exc)[:200]}",
            )
            return Inspection(kind=kind, metadata={"iac": {"error": str(exc)[:300]}})

    # --- Kubernetes and Compose -----------------------------------------------------------------

    def _kubernetes(self, view: ArtifactView, text: str, ctx: Context) -> Inspection:
        posture = _Posture(view, ctx)
        kinds: dict[str, int] = {}
        for document in _documents(load_untrusted_yaml_all(text, aliases=True)):
            kind = str(document.get("kind", ""))
            kinds[kind] = kinds.get(kind, 0) + 1
            name = str(_dig(document, ("metadata", "name")) or "?")
            path = _POD_PATHS.get(kind) or (
                ("spec", "template", "spec") if kind in _TEMPLATED_KINDS else None
            )
            spec = _dig(document, path) if path else None
            if isinstance(spec, dict):
                posture.pod(f"{kind}/{name}", spec)
        return Inspection(
            kind="kubernetes.manifest", metadata={"iac": {"kinds": kinds, **posture.counts}}
        )

    def _compose(self, view: ArtifactView, text: str, ctx: Context) -> Inspection:
        document = mapping(load_untrusted_yaml(text, aliases=True))
        posture = _Posture(view, ctx)
        services = mapping(document.get("services"))
        for name, service in sorted(services.items()):
            service = mapping(service)
            privileged: list[str] = []
            host: list[str] = []
            root: list[str] = []
            if service.get("privileged") is True:
                privileged.append("privileged")
            for key, bucket in (
                ("pid", privileged),
                ("network_mode", host),
                ("ipc", host),
                ("userns_mode", privileged),
            ):
                if service.get(key) == "host":
                    bucket.append(f"{key}: host")
            for cap in _list(service.get("cap_add")):
                cap = str(cap).upper().removeprefix("CAP_")
                (
                    privileged if cap in _PRIVILEGED_CAPS else host if cap in _HOST_CAPS else []
                ).append(f"cap_add {cap}")
            for volume in _list(service.get("volumes")):
                source = (
                    str(volume.get("source", ""))
                    if isinstance(volume, dict)
                    else str(volume).split(":", 1)[0]
                )
                if source.endswith(_RUNTIME_SOCKETS):
                    privileged.append(f"mounts {source}")
                elif source.startswith("/") and source.rstrip("/") in (*_SENSITIVE_HOST_PATHS, ""):
                    host.append(f"mounts {source}")
            for device in _list(service.get("devices")):
                host.append(f"device {str(device).split(':', 1)[0]}")
            if str(service.get("user", "")).split(":", 1)[0] in ("0", "root"):
                root.append(f"user: {service['user']}")
            image = str(service.get("image") or "")
            images = (
                {image: problem}
                if image and "$" not in image and (problem := _image_problem(image))
                else {}
            )
            posture.record(f"service/{name}", privileged, host, root, images)
        return Inspection(
            kind="compose.file", metadata={"iac": {"services": len(services), **posture.counts}}
        )

    # --- Helm and Ansible dependencies ----------------------------------------------------------

    def _helm(self, view: ArtifactView, text: str, ctx: Context) -> Inspection:
        chart = mapping(load_untrusted_yaml(text, aliases=True))
        locked = {}
        lock_view = view.resolve("Chart.lock") or view.resolve("requirements.lock")
        if lock_view is not None:
            lock = mapping(load_untrusted_yaml(read_text(lock_view, _LIMIT), aliases=True))
            locked = {
                str(d.get("name")): str(d.get("version"))
                for d in _list(lock.get("dependencies"))
                if isinstance(d, dict)
            }
        dependencies = _list(chart.get("dependencies"))
        if not dependencies and (legacy := view.resolve("requirements.yaml")) is not None:
            dependencies = _list(
                mapping(load_untrusted_yaml(read_text(legacy, _LIMIT), aliases=True)).get(
                    "dependencies"
                )
            )
        missing = []
        for dependency in dependencies:
            if not isinstance(dependency, dict):
                continue
            name = str(dependency.get("name", ""))
            repository = str(dependency.get("repository") or "")
            version = locked.get(name) or str(dependency.get("version", ""))
            if repository.startswith("file://"):
                local = repository.removeprefix("file://")
                if view.resolve(posixpath.join(local, "Chart.yaml")) is None:
                    missing.append({"chart": name, "repository": repository})
                continue
            if view.resolve(f"charts/{name}-{version}.tgz") or view.resolve(
                f"charts/{name}/Chart.yaml"
            ):
                continue
            missing.append({"chart": name, "version": version, "repository": repository})
        _dependencies(view, ctx, "helm", missing, len(dependencies))
        ctx.recorder.not_assessed(
            ("iac.workload.privileged", "iac.workload.host-access", "iac.image.unpinned"),
            Subject.of_artifact(view.ref, locator="templates"),
            tool=TOOL,
            reason="chart templates are not rendered: deliver the output of helm template "
            "to have the workloads checked",
        )
        summary = {
            "name": chart.get("name"),
            "version": chart.get("version"),
            "type": chart.get("type", "application"),
            "dependencies": len(dependencies),
            "missing": len(missing),
        }
        return Inspection(kind="helm.chart", metadata={"iac": summary})

    def _ansible(self, view: ArtifactView, text: str, ctx: Context) -> Inspection:
        document = load_untrusted_yaml(text, aliases=True)
        if isinstance(document, list):  # the old roles-only format
            document = {"roles": document}
        document = mapping(document)
        missing: list[dict[str, str]] = []
        total = 0
        for entry in _list(document.get("collections")):
            entry = {"name": entry} if isinstance(entry, str) else mapping(entry)
            name = str(entry.get("name", ""))
            total += 1
            if (
                entry.get("type") in ("git", "url")
                or name.startswith(("http", "git"))
                or name.endswith((".tar.gz", ".tgz"))
            ):
                if name.endswith((".tar.gz", ".tgz")) and view.resolve(name):
                    continue
                missing.append(
                    {
                        "collection": name,
                        "source": str(entry.get("source") or entry.get("type") or "url"),
                    }
                )
                continue
            namespace, _, collection = name.partition(".")
            version = str(entry.get("version") or "")
            candidates = [
                f"{base}/ansible_collections/{namespace}/{collection}/MANIFEST.json"
                for base in ("collections", ".", "../collections")
            ]
            if any(view.resolve(c) for c in candidates):
                continue
            if version and view.resolve(f"{namespace}-{collection}-{version}.tar.gz"):
                continue
            missing.append({"collection": name, "version": version})
        for entry in _list(document.get("roles")):
            entry = {"name": entry} if isinstance(entry, str) else mapping(entry)
            name = str(entry.get("name") or entry.get("src") or "")
            total += 1
            role = name.rsplit("/", 1)[-1].removesuffix(".git")
            if any(
                view.resolve(f"{base}/{role}/{marker}")
                for base in ("roles", "../roles")
                for marker in ("meta/main.yml", "tasks/main.yml")
            ):
                continue
            missing.append({"role": name})
        _dependencies(view, ctx, "ansible", missing, total)
        return Inspection(
            kind="ansible.requirements",
            metadata={"iac": {"requirements": total, "missing": len(missing)}},
        )

    # --- Terraform ------------------------------------------------------------------------------

    def _tf_config(self, view: ArtifactView, text: str, ctx: Context) -> Inspection:
        modules = []
        for match in _TF_MODULE.finditer(text):
            block = text[match.end() : match.end() + 4000]
            source = _TF_SOURCE.search(block.split("\n}", 1)[0])
            if source:
                modules.append((match["name"], source["source"]))
        remote = [(n, s) for n, s in modules if not s.startswith(("./", "../", "/"))]
        installed: set[str] = set()
        manifest = view.resolve(".terraform/modules/modules.json")
        if manifest is not None:
            try:
                installed = {
                    str(m.get("Key"))
                    for m in _list(mapping(read_json(manifest)).get("Modules"))
                    if isinstance(m, dict)
                }
            except (TooLarge, ValueError):
                installed = set()
        missing = [{"module": n, "source": s} for n, s in remote if n not in installed]
        if remote:
            _dependencies(view, ctx, "terraform", missing, len(remote))
        return Inspection(
            kind="terraform.config",
            metadata={"iac": {"modules": len(modules), "remoteModules": len(remote)}},
        )

    def _tf_lock(self, view: ArtifactView) -> Inspection:
        requirements = []
        for match in _TF_PROVIDER.finditer(read_text(view, _LIMIT)):
            body = match["body"]
            version = re.search(r'^\s*version\s*=\s*"([^"]+)"', body, re.M)
            hashes = []
            for value in re.findall(r'"((?:h1|zh):[^"]+)"', body):
                scheme, _, digest = value.partition(":")
                hashes.append(f"sha256:{digest}" if scheme == "zh" else value)
            requirements.append(
                requirement(match["address"], version.group(1) if version else "", hashes)
            )
        claim = lockfile_claim(view, TERRAFORM, "terraform", ".terraform.lock.hcl", requirements)
        return Inspection(
            kind="terraform.lockfile",
            metadata={"iac": {"providers": len(requirements)}},
            claims=(claim,),
        )

    def _provider(self, view: ArtifactView) -> Inspection:
        name = name_of(view.ref)
        parts = full_path(view.ref).split("/")
        if match := _TF_ZIP.match(name):  # packed mirror: <host>/<namespace>/<type>/<file>.zip
            address = "/".join(parts[-4:-1]) if len(parts) >= 4 else match["type"]
            version = match["version"]
            hashes = [f"sha256:{view.sha256}"] if view.sha256 else []
            try:
                with view.open() as stream:
                    hashes.append(zip_hash(stream, _PROVIDER_LIMIT))
            except ZipHashError:
                pass  # still a provider by name and sha256 (zh:); h1: cannot be offered
        else:  # unpacked: <host>/<namespace>/<type>/<version>/<os_arch>/<binary>
            match = _TF_BINARY.match(name)
            assert match is not None  # noqa: S101 - detect() matched the name
            address = "/".join(parts[-6:-3])
            version = parts[-3]
            hashes = []  # h1 covers the whole directory, which one file cannot see
        if address.count("/") == 1:  # registry.terraform.io is implied
            address = f"registry.terraform.io/{address}"
        purl = f"pkg:terraform/{address}@{version}"
        part = component(view, address, version, purl)
        claims: tuple[UnitClaim, ...] = (
            distribution_claim(
                view, TERRAFORM, "terraform", address, version, hashes, part.bom_ref
            ),
        )
        return Inspection(
            kind="terraform.provider",
            metadata={"iac": {"provider": address, "version": version}},
            components=(part,),
            claims=claims,
        )


def _documents(documents: list[object]) -> Iterator[dict[str, Any]]:
    for document in documents:
        if isinstance(document, dict) and document.get("kind") == "List":
            yield from (item for item in _list(document.get("items")) if isinstance(item, dict))
        elif isinstance(document, dict):
            yield document


def _dependencies(
    view: ArtifactView, ctx: Context, tool: str, missing: list[Any], total: int
) -> None:
    if view.ref.nested:
        # Inside an archive the files beside this one cannot be looked up.
        if total:
            ctx.recorder.not_assessed(
                ("iac.dependency.unresolvable",),
                Subject.of_artifact(view.ref),
                tool=TOOL,
                reason="inside an archive: whether its dependencies are vendored cannot be "
                "checked; deliver it unpacked",
            )
        return
    if missing:
        ctx.recorder.fail(
            "iac.dependency.unresolvable",
            Subject.of_artifact(view.ref),
            tool=TOOL,
            detail={"tool": tool, "missing": missing[:100], "count": len(missing)},
            attributes={"tool": tool},
        )
    elif total:
        ctx.recorder.passed("iac.dependency.unresolvable")
