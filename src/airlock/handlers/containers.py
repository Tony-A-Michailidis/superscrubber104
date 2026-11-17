"""Container images: ``docker save`` archives and OCI image layouts, as a tar or a directory.

The image structure is read from its own documents (``manifest.json``, ``index.json``, image
manifests and configs), never by running a container engine:

* **Integrity.** OCI blobs are named by the sha256 of their content and descriptors carry sizes;
  legacy ``docker save`` layers are recorded by digest in the config. Every one is checked. A
  difference is a hash mismatch, which is final.
* **Completeness.** Every config, manifest and layer referenced must be in the archive.
* **Configuration.** The image's user (root by default), and literal credentials in ``ENV``.

The layers themselves are tar archives, so the ordinary archive walk opens them and every file
inside goes through the other handlers: models, packages, agent configurations and OS package
databases in an image are inspected like any others. Compressed image archives (``.tar.gz``) are
walked that way too, but their image-level checks are not run.
"""

import hashlib
import json
import re
import tarfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import IO, Any, Protocol

from airlock import __version__
from airlock.core.interfaces import ArtifactView, Context, Detection, Inspection
from airlock.core.model import ArtifactRef, Subject, ToolRef, UnitKind
from airlock.handlers.common import is_literal_secret, make_claim, name_of

TOOL = ToolRef("airlock.containers", __version__)
_DIGEST = re.compile(r"^sha256:([0-9a-f]{64})$")
_JSON_LIMIT = 16 << 20
_INDEX_TYPES = (
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
)


class _Store(Protocol):
    def exists(self, path: str) -> bool: ...

    def size(self, path: str) -> int | None: ...

    def sha256(self, path: str) -> str | None: ...

    def json(self, path: str) -> Any: ...

    def blobs(self) -> Iterator[str]:
        """Blobs to check even when nothing references them."""
        ...


class MemoryStore:
    """An OCI layout already read in one streaming pass by another handler (a Zarf package).

    ``digests`` and ``sizes`` cover every file; ``documents`` holds the small JSON ones (index,
    manifests, configs). Paths are relative to the layout's root.
    """

    def __init__(
        self, digests: dict[str, str], sizes: dict[str, int], documents: dict[str, bytes]
    ) -> None:
        self.digests, self.sizes, self.documents = digests, sizes, documents

    def exists(self, path: str) -> bool:
        return path in self.digests

    def size(self, path: str) -> int | None:
        return self.sizes.get(path)

    def sha256(self, path: str) -> str | None:
        return self.digests.get(path)

    def json(self, path: str) -> Any:
        if path not in self.documents:
            raise ValueError(f"{path} is missing or was too large to read")
        return json.loads(self.documents[path])

    def blobs(self) -> Iterator[str]:
        return (p for p in sorted(self.digests) if p.startswith("blobs/sha256/"))


class _TarStore:
    """An image archive read in place. Members are hashed only when asked."""

    def __init__(self, stream: IO[bytes]) -> None:
        self.tar = tarfile.open(fileobj=stream, mode="r:")  # noqa: SIM115 - closed by the caller
        self.members = {m.name.removeprefix("./"): m for m in self.tar.getmembers() if m.isfile()}
        self._hashes: dict[str, str] = {}

    def exists(self, path: str) -> bool:
        return path in self.members

    def size(self, path: str) -> int | None:
        member = self.members.get(path)
        return member.size if member else None

    def _open(self, path: str) -> IO[bytes]:
        handle = self.tar.extractfile(self.members[path])
        if handle is None:
            raise ValueError(f"{path} has no content")
        return handle

    def sha256(self, path: str) -> str | None:
        if path not in self.members:
            return None
        if path not in self._hashes:
            digest = hashlib.sha256()
            with self._open(path) as handle:
                while block := handle.read(1 << 20):
                    digest.update(block)
            self._hashes[path] = digest.hexdigest()
        return self._hashes[path]

    def json(self, path: str) -> Any:
        if self.members[path].size > _JSON_LIMIT:
            raise ValueError(f"{path} is too large")
        with self._open(path) as handle:
            return json.loads(handle.read())

    def blobs(self) -> Iterator[str]:
        return (p for p in self.members if p.startswith("blobs/sha256/"))


class _DirStore:
    """An OCI layout directory, read through the delivery (its files are already hashed)."""

    def __init__(self, index: ArtifactView) -> None:
        self.index = index

    def exists(self, path: str) -> bool:
        return self.index.resolve(path) is not None

    def size(self, path: str) -> int | None:
        view = self.index.resolve(path)
        return view.size if view else None

    def sha256(self, path: str) -> str | None:
        view = self.index.resolve(path)
        return view.sha256 if view else None

    def json(self, path: str) -> Any:
        view = self.index.resolve(path)
        if view is None or view.size > _JSON_LIMIT:
            raise ValueError(f"{path} is missing or too large")
        with view.open() as stream:
            return json.loads(stream.read())

    def blobs(self) -> Iterator[str]:
        return iter(())  # blobs are checked as they are referenced


@dataclass
class _Image:
    name: str | None
    manifest_digest: str | None
    config_path: str
    layers: list[tuple[str, int | None]]  # (path, size declared by the descriptor)
    config: dict[str, Any] = field(default_factory=dict)
    config_digest: str | None = None  # the image ID: sha256 of the config


def _blob(digest: str) -> str | None:
    match = _DIGEST.match(digest)
    return f"blobs/sha256/{match[1]}" if match else None


class _Reader:
    def __init__(self, store: _Store, ctx: Context, view: ArtifactView) -> None:
        self.store = store
        self.ctx = ctx
        self.view = view
        self.missing: list[str] = []
        self.mismatched: list[dict[str, object]] = []
        self.checked: set[str] = set()

    def need(self, path: str | None, what: str) -> bool:
        if path is None or not self.store.exists(path):
            self.missing.append(f"{what}: {path}")
            return False
        return True

    def verify(self, path: str, size: int | None = None, expected: str | None = None) -> None:
        """A blob's content must hash to its name (or to ``expected``) and match its size."""
        if path in self.checked:
            return
        self.checked.add(path)
        actual = self.store.sha256(path)
        want = expected or (path.rsplit("/", 1)[-1] if path.startswith("blobs/sha256/") else None)
        actual_size = self.store.size(path)
        if (want and actual != want) or (size is not None and actual_size != size):
            self.mismatched.append(
                {
                    "blob": path,
                    "expected": want,
                    "actual": actual,
                    "expectedSize": size,
                    "actualSize": actual_size,
                }
            )

    def images(self) -> list[_Image]:
        images: list[_Image] = []
        if self.store.exists("index.json"):
            images = self._oci(self.store.json("index.json"), depth=0)
        if self.store.exists("manifest.json"):
            docker = self._docker(self.store.json("manifest.json"))
            if images:  # docker save 25+ writes both; take the tags from manifest.json
                tags = {i.config_path: i.name for i in docker}
                for image in images:
                    image.name = image.name or tags.get(image.config_path)
            else:
                images = docker
        for image in images:
            if self.need(image.config_path, "config"):
                self.verify(image.config_path)
                config_sha = self.store.sha256(image.config_path)
                image.config_digest = f"sha256:{config_sha}" if config_sha else None
                config = self.store.json(image.config_path)
                image.config = config if isinstance(config, dict) else {}
            diff_ids = (
                ((image.config.get("rootfs") or {}).get("diff_ids") or []) if image.config else []
            )
            for index, (path, size) in enumerate(image.layers):
                if not self.need(path, "layer"):
                    continue
                if path.startswith("blobs/sha256/"):
                    self.verify(path, size)
                elif index < len(diff_ids) and isinstance(diff_ids[index], str):
                    # legacy docker save: an uncompressed layer.tar, recorded by its diff_id
                    match = _DIGEST.match(diff_ids[index])
                    self.verify(path, expected=match[1] if match else None)
        return images

    def _oci(self, index: Any, depth: int) -> list[_Image]:
        images = []
        for descriptor in (index.get("manifests") or []) if isinstance(index, dict) else []:
            if not isinstance(descriptor, dict):
                continue
            path = _blob(str(descriptor.get("digest", "")))
            if not self.need(path, "manifest"):
                continue
            assert path is not None  # noqa: S101
            self.verify(
                path, descriptor.get("size") if type(descriptor.get("size")) is int else None
            )
            document = self.store.json(path)
            if descriptor.get("mediaType") in _INDEX_TYPES or (
                isinstance(document, dict) and "manifests" in document
            ):
                if depth < 2:
                    images += self._oci(document, depth + 1)
                continue
            annotations = descriptor.get("annotations") or {}
            name = annotations.get("io.containerd.image.name") or annotations.get(
                "org.opencontainers.image.ref.name"
            )
            config = (document.get("config") or {}) if isinstance(document, dict) else {}
            layers = [
                (
                    _blob(str(layer.get("digest", "")))
                    or f"<invalid digest {layer.get('digest')}>",
                    layer.get("size") if type(layer.get("size")) is int else None,
                )
                for layer in (document.get("layers") or [])
                if isinstance(layer, dict)
            ]
            config_path = _blob(str(config.get("digest", ""))) or "<missing config digest>"
            images.append(_Image(name, str(descriptor.get("digest")), config_path, layers))
        return images

    def _docker(self, manifest: Any) -> list[_Image]:
        images = []
        for entry in manifest if isinstance(manifest, list) else []:
            if not isinstance(entry, dict):
                continue
            tags = [t for t in entry.get("RepoTags") or [] if isinstance(t, str)]
            layers: list[tuple[str, int | None]] = [
                (str(layer), None) for layer in entry.get("Layers") or []
            ]
            images.append(_Image(tags[0] if tags else None, None, str(entry.get("Config")), layers))
        return images


# Environment values that are recorded (names of everything else only): offline and telemetry
# switches, and the CUDA stack a base image declares. None of them is a secret.
RECORDED_ENV = frozenset(
    {
        "HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE", "HF_DATASETS_OFFLINE", "HF_HUB_DISABLE_TELEMETRY",
        "DO_NOT_TRACK", "ANONYMIZED_TELEMETRY", "GRADIO_ANALYTICS_ENABLED",
        "STREAMLIT_BROWSER_GATHER_USAGE_STATS", "VLLM_NO_USAGE_STATS", "WANDB_MODE",
        "TIKTOKEN_CACHE_DIR", "NLTK_DATA", "HF_HOME", "CUDA_VERSION", "NVIDIA_REQUIRE_CUDA",
        "NV_CUDNN_VERSION", "CUDNN_VERSION", "NCCL_VERSION", "NV_LIBNCCL_PACKAGE_VERSION",
        "TENSORRT_VERSION", "TRT_VERSION", "PYTORCH_VERSION", "NVIDIA_VISIBLE_DEVICES",
        "ROCM_VERSION", "OLLAMA_VERSION",
    }
)  # fmt: skip
_START_DOWNLOAD = re.compile(
    r"\bollama\s+pull\b|\b(?:pip3?|uv\s+pip|npm|apt-get|apk|dnf|yum)\s+(?:install|add|ci)\b"
    r"|\b(?:wget|curl)\s+\S*https?://|\bgit\s+clone\b|\bhuggingface-cli\s+download\b"
)


def _summary(image: _Image) -> dict[str, object]:
    config = image.config.get("config") or {} if image.config else {}
    env = [e for e in config.get("Env") or [] if isinstance(e, str)]
    settings = {
        key: value for key, _, value in (e.partition("=") for e in env) if key in RECORDED_ENV
    }
    return {
        "name": image.name,
        "manifestDigest": image.manifest_digest,
        "configDigest": image.config_digest,
        "os": image.config.get("os"),
        "architecture": image.config.get("architecture"),
        "created": image.config.get("created"),
        "user": config.get("User") or "",
        "entrypoint": config.get("Entrypoint"),
        "cmd": config.get("Cmd"),
        "workingDir": config.get("WorkingDir"),
        "exposedPorts": sorted((config.get("ExposedPorts") or {}).keys()),
        "env": sorted(e.split("=", 1)[0] for e in env),
        "settings": settings,
        "labels": dict(list((config.get("Labels") or {}).items())[:50]),
        "layers": len(image.layers),
        "history": len(image.config.get("history") or []),
    }


def _check_config(image: _Image, ctx: Context, view: ArtifactView) -> None:
    config = image.config.get("config") or {} if image.config else {}
    locator = f"image {image.name or image.config_path}"
    subject = Subject.of_artifact(view.ref, locator=locator)
    user = str(config.get("User") or "").strip()
    if user in ("", "root", "0") or user.startswith(("root:", "0:")):
        ctx.recorder.fail(
            "container.user.root",
            subject,
            tool=TOOL,
            detail={"user": user or "(not set)"},
            attributes={"image": image.name or ""},
        )
    else:
        ctx.recorder.passed("container.user.root")
    literal = [
        e.split("=", 1)[0]
        for e in config.get("Env") or []
        if isinstance(e, str) and "=" in e and is_literal_secret(*e.split("=", 1))
    ]
    if literal:
        ctx.recorder.fail(
            "container.env.credential",
            subject,
            tool=TOOL,
            detail={"variables": literal, "note": "values are not recorded"},
        )
    else:
        ctx.recorder.passed("container.env.credential")
    start = [str(p) for key in ("Entrypoint", "Cmd") for p in (config.get(key) or [])]
    command = " ".join(start)
    if _START_DOWNLOAD.search(command):
        ctx.recorder.fail(
            "offline.download.runtime",
            subject,
            tool=TOOL,
            detail={
                "what": "the image downloads or installs when it starts",
                "evidence": command[:300],
            },
            attributes={"impact": "will-break", "what": "download at container start"},
            discriminator="start",
        )


def inspect_store(
    store: _Store,
    ctx: Context,
    view: ArtifactView,
    kind: str,
    root: ArtifactRef | None = None,
) -> Inspection:
    """Check the images in ``store`` and claim them, as ``view``, for the unit rooted at ``root``
    (by default the archive itself, or the directory holding a layout)."""
    reader = _Reader(store, ctx, view)
    images = reader.images()
    if not images:
        return Inspection(kind="unclassified")
    for blob in store.blobs():  # unreferenced blobs must still hash to their names
        reader.verify(blob)
    subject = Subject.of_artifact(view.ref)
    if reader.missing:
        ctx.recorder.fail(
            "container.image.incomplete",
            subject,
            tool=TOOL,
            detail={"missing": reader.missing[:50]},
        )
    else:
        ctx.recorder.passed("container.image.incomplete")
    if reader.mismatched:
        ctx.recorder.fail(
            "container.layer.digest-mismatch",
            subject,
            tool=TOOL,
            detail={"blobs": reader.mismatched[:50]},
        )
    else:
        ctx.recorder.passed("container.layer.digest-mismatch", max(len(reader.checked), 1))
    for image in images:
        if image.config:
            _check_config(image, ctx, view)
    summaries = [_summary(image) for image in images]
    if root is None and isinstance(store, _TarStore):
        root = view.ref
    claims = tuple(
        make_claim(view, UnitKind.CONTAINER_IMAGE, "image", {"image": s}, root=root)
        for s in summaries
    )
    return Inspection(
        kind=kind,
        metadata={"container": {"images": summaries, "blobsChecked": len(reader.checked)}},
        claims=claims,
    )


_BLOB_PATH = re.compile(r"(?:^|/)blobs/sha256/[0-9a-f]{64}$")


def _layout_part(view: ArtifactView) -> bool:
    """The oci-layout marker, or a content-addressed blob, of an OCI layout directory."""
    if view.ref.member:
        return False
    if name_of(view.ref) == "oci-layout":
        return view.resolve("index.json") is not None
    return bool(_BLOB_PATH.search(view.ref.path)) and view.resolve("../../oci-layout") is not None


class ContainerImageHandler:
    name = "container-image"
    version = "1"
    kinds = frozenset(
        {"container.image.archive", "container.image.oci-layout", "container.image.part"}
    )

    def detect(self, artifact: ArtifactView) -> Detection | None:
        name = name_of(artifact.ref)
        if artifact.head(512)[257:262] == b"ustar" and name.lower().endswith(".tar"):
            return Detection("container.image.archive", 60)
        if name == "index.json" and artifact.resolve("oci-layout") is not None:
            return Detection("container.image.oci-layout", 90)
        if _layout_part(artifact):
            return Detection("container.image.part", 50)
        return None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        if name_of(artifact.ref) == "index.json":
            return inspect_store(_DirStore(artifact), ctx, artifact, "container.image.oci-layout")
        if _layout_part(artifact):
            # A blob or marker of an OCI layout directory; index.json is where it is checked.
            return Inspection(kind="container.image.part")
        try:
            with artifact.open() as stream:
                store = _TarStore(stream)
                if not (
                    store.exists("manifest.json")
                    or (store.exists("index.json") and store.exists("oci-layout"))
                ):
                    return Inspection(kind="unclassified")
                return inspect_store(store, ctx, artifact, "container.image.archive")
        except (tarfile.TarError, ValueError, KeyError) as exc:
            return Inspection(
                kind="unclassified", metadata={"container": {"unreadable": str(exc)[:200]}}
            )


def image_name(name: str | None) -> tuple[str, str | None]:
    """('registry/repo', 'tag') from 'registry/repo:tag'."""
    if not name:
        return "untagged", None
    repository, _, tag = name.rpartition(":")
    if not repository or "/" in tag:
        return name, None
    return repository, tag
