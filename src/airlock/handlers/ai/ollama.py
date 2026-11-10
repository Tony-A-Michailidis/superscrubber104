"""Ollama model stores.

An Ollama model is a manifest (``manifests/<registry>/<namespace>/<model>/<tag>``) listing layers
by digest, stored as ``blobs/sha256-<hex>``. Layer media types say what each blob is: the GGUF
weights, a chat template, a system prompt, parameters, a licence, an adapter or a projector.

The manifest is the unit. Every layer must be present, with exactly the size and sha256 the
manifest names: a blob whose content does not match its own name is corrupt or has been swapped,
which is a checksum failure, not a matter of policy.
"""

import json
import posixpath
import re

from airlock.core.interfaces import ArtifactView, Context, Detection, Inspection
from airlock.core.model import Subject, UnitClaim
from airlock.formats import gguf
from airlock.handlers.ai.common import TOOL, check_template, claim, read_bytes
from airlock.handlers.ai.weights import summarise
from airlock.licences import identify_text

_LAYER_ROLES = {
    "application/vnd.ollama.image.model": "weights",
    "application/vnd.ollama.image.template": "chat-template",
    "application/vnd.ollama.image.system": "system-prompt",
    "application/vnd.ollama.image.params": "params",
    "application/vnd.ollama.image.license": "licence",
    "application/vnd.ollama.image.adapter": "adapter-weights",
    "application/vnd.ollama.image.projector": "projector",
    "application/vnd.ollama.image.messages": "messages",
}
_DIGEST = re.compile(r"^sha256:([0-9a-f]{64})$")
_BLOB = re.compile(r"/blobs/sha256-[0-9a-f]{64}$")
_STORE_RULES = ("model.package.file-missing", "model.provenance.checksum-mismatch")


def _full(view: ArtifactView) -> str:
    return (view.ref.path, *view.ref.member)[-1]


class OllamaManifestHandler:
    name = "ollama"
    version = "1"
    kinds = frozenset({"model.ollama.manifest", "model.ollama.blob"})

    def detect(self, artifact: ArtifactView) -> Detection | None:
        full = f"/{_full(artifact)}"
        if "/manifests/" in full and artifact.head(1) == b"{" and artifact.size < 1 << 20:
            return Detection("model.ollama.manifest", 70)
        if _BLOB.search(full):
            return Detection("model.ollama.blob", 40)
        return None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        if _BLOB.search(f"/{_full(artifact)}"):
            # Content-addressed store entry; the manifest that names it checks it.
            return Inspection(kind="model.ollama.blob")
        try:
            manifest = json.loads(read_bytes(artifact, 1 << 20))
        except (ValueError, OSError):
            return Inspection(kind="unclassified")
        layers = manifest.get("layers") if isinstance(manifest, dict) else None
        if not isinstance(layers, list) or manifest.get("schemaVersion") != 2:
            return Inspection(kind="unclassified")
        if not any(
            isinstance(layer, dict)
            and str(layer.get("mediaType", "")).startswith("application/vnd.ollama")
            for layer in layers
        ):
            return Inspection(kind="unclassified")

        full = _full(artifact)
        store, _, name_path = full.rpartition("manifests/")
        parts = name_path.split("/")
        registry, namespace, model, tag = ["", "", "", "", *parts][-4:]
        reference = "/".join(p for p in (registry, namespace, model) if p)
        subject = Subject.of_artifact(artifact.ref)
        if artifact.ref.nested:
            ctx.recorder.not_assessed(
                _STORE_RULES,
                subject,
                tool=TOOL,
                reason="the blobs of a model store inside an archive are not resolved",
            )

        claims: list[UnitClaim] = []
        summary_layers = []
        facts: dict[str, object] = {}
        config = manifest.get("config")
        entries = [*layers, *([config] if isinstance(config, dict) else [])]
        for layer in entries:
            if not isinstance(layer, dict):
                continue
            media_type = str(layer.get("mediaType", ""))
            role = _LAYER_ROLES.get(media_type, "ollama-config" if layer is config else "layer")
            match = _DIGEST.match(str(layer.get("digest", "")))
            size = layer.get("size")
            summary_layers.append({"role": role, "digest": layer.get("digest"), "size": size})
            if match is None or artifact.ref.nested:
                continue
            blob_path = posixpath.join(store, "blobs", f"sha256-{match[1]}")
            blob = artifact.resolve(posixpath.relpath(blob_path, posixpath.dirname(full)))
            if blob is None:
                ctx.recorder.fail(
                    "model.package.file-missing",
                    subject,
                    tool=TOOL,
                    detail={"file": blob_path, "role": role, "digest": layer.get("digest")},
                    discriminator=blob_path,
                )
                continue
            ctx.recorder.passed("model.package.file-missing")
            if blob.sha256 != match[1] or (type(size) is int and blob.size != size):
                ctx.recorder.fail(
                    "model.provenance.checksum-mismatch",
                    Subject.of_artifact(blob.ref),
                    tool=TOOL,
                    detail={
                        "source": "ollama manifest",
                        "manifest": artifact.ref.display,
                        "expected": match[1],
                        "actual": blob.sha256,
                        "expectedSize": size,
                        "actualSize": blob.size,
                    },
                )
                continue
            ctx.recorder.passed("model.provenance.checksum-mismatch")
            layer_facts = self._layer_facts(role, blob, ctx)
            blob_facts: dict[str, object] = {"layer": media_type}
            if role == "licence":
                blob_facts["identifier"] = layer_facts.pop("licenceIdentifier", None)
            claims.append(claim(blob, role, blob_facts, root=artifact.ref))
            facts.update(layer_facts)

        facts.update(
            {
                "format": "ollama",
                "registry": registry,
                "reference": reference,
                "tag": tag,
                "layers": summary_layers,
                "manifestSha256": artifact.sha256,
            }
        )
        claims.insert(0, claim(artifact, "ollama-manifest", facts, root=artifact.ref))
        return Inspection(
            kind="model.ollama.manifest",
            metadata={"ollama": {"model": f"{reference}:{tag}", "layers": len(summary_layers)}},
            claims=tuple(claims),
        )

    @staticmethod
    def _layer_facts(role: str, blob: ArtifactView, ctx: Context) -> dict[str, object]:
        if role == "weights":
            try:
                with blob.open() as stream:
                    return {"gguf": summarise(gguf.parse(stream, blob.size))}
            except (gguf.GGUFError, OSError):
                return {}  # the GGUF handler reports the blob as malformed
        if role in ("chat-template", "licence", "system-prompt") and blob.size <= 1 << 20:
            text = read_bytes(blob, 1 << 20).decode("utf-8", "replace")
            if role == "chat-template":
                return {"chatTemplates": [check_template(ctx, blob, text, "template")]}
            if role == "licence":
                return {"licenceIdentifier": identify_text(text)}
        if role == "params" and blob.size <= 1 << 20:
            try:
                params = json.loads(read_bytes(blob, 1 << 20))
            except ValueError:
                return {}
            return {"params": params} if isinstance(params, dict) else {}
        return {}
