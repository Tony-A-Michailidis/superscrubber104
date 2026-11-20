"""Handlers for weight formats that cannot run code: safetensors and GGUF."""

import re

from superscrubber104.core.interfaces import ArtifactView, Context, Detection, Inspection
from superscrubber104.core.model import Subject, UnitClaim
from superscrubber104.formats import gguf, safetensors
from superscrubber104.handlers.ai.common import (
    SHARD,
    TOOL,
    check_template,
    claim,
    malformed,
    name_of,
    sibling,
)

OLLAMA_BLOB = re.compile(r"^sha256-[0-9a-f]{64}$")
_QUANT_TENSOR_SUFFIXES = {".qweight": "gptq-or-awq", ".q_weight": "exl2", ".weight_scale": "fp8"}


def weight_role(name: str) -> str:
    if name.startswith("adapter_model"):
        return "adapter-weights"
    if name.startswith("mmproj"):
        return "projector"
    if SHARD.match(name):
        return "weights-shard"
    return "weights"


def shard_facts(name: str) -> dict[str, object]:
    match = SHARD.match(name)
    if not match:
        return {}
    return {
        "shard": {
            "prefix": match["prefix"],
            "index": int(match["index"]),
            "total": int(match["total"]),
            "ext": match["ext"],
        }
    }


class SafetensorsHandler:
    name = "safetensors"
    version = "1"
    kinds = frozenset({"model.safetensors"})

    def detect(self, artifact: ArtifactView) -> Detection | None:
        if safetensors.looks_like(artifact.head(16), artifact.size):
            return Detection("model.safetensors", 100)
        if name_of(artifact.ref).endswith(".safetensors"):
            return Detection("model.safetensors", 50)
        return None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        try:
            with artifact.open() as stream:
                header = safetensors.parse(stream, artifact.size)
        except (safetensors.SafetensorsError, OSError) as exc:
            malformed(ctx, artifact, "safetensors", exc)
            return Inspection(
                kind="model.safetensors", metadata={"safetensors": {"error": str(exc)}}
            )
        ctx.recorder.passed("model.weights.malformed")

        name = name_of(artifact.ref)
        quantization = sorted(
            {
                method
                for tensor in header.tensors
                for suffix, method in _QUANT_TENSOR_SUFFIXES.items()
                if tensor.endswith(suffix)
            }
        )
        summary = {
            "tensors": len(header.tensors),
            "parameters": header.parameters,
            "dataBytes": header.data_bytes,
            "headerBytes": header.header_bytes,
            "dtypes": header.dtype_counts(),
            "metadata": header.metadata,
        }
        if header.unknown_dtypes:
            summary["unknownDtypes"] = sorted(header.unknown_dtypes)
        facts: dict[str, object] = {
            "format": "safetensors",
            "file": name,
            **summary,
            "quantization": quantization[0] if quantization else None,
            "tensorShapes": {n: [*t.shape] for n, t in header.tensors.items()},
            **shard_facts(name),
        }
        return Inspection(
            kind="model.safetensors",
            media_type="application/vnd.safetensors",
            metadata={"safetensors": summary},
            claims=(claim(artifact, weight_role(name), facts),),
        )


class GGUFHandler:
    name = "gguf"
    version = "1"
    kinds = frozenset({"model.gguf"})

    def detect(self, artifact: ArtifactView) -> Detection | None:
        if gguf.looks_like(artifact.head(8)):
            return Detection("model.gguf", 100)
        if name_of(artifact.ref).endswith(".gguf"):
            return Detection("model.gguf", 50)
        return None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        try:
            with artifact.open() as stream:
                model = gguf.parse(stream, artifact.size)
        except (gguf.GGUFError, OSError) as exc:
            malformed(ctx, artifact, "gguf", exc)
            return Inspection(kind="model.gguf", metadata={"gguf": {"error": str(exc)}})
        ctx.recorder.passed("model.weights.malformed")

        name = name_of(artifact.ref)
        templates = [
            check_template(ctx, artifact, value, key)
            for key, value in sorted(model.metadata.items())
            if key.startswith("tokenizer.chat_template") and isinstance(value, str)
        ]
        split_count = model.number("split.count") or 0
        split = split_count > 1 or SHARD.match(name) is not None
        if not split:
            self._consistency(artifact, model, ctx)

        summary = summarise(model)
        metadata = {"gguf": {**summary, "chatTemplates": templates}}
        if OLLAMA_BLOB.match(name):
            # Part of an Ollama model store; the manifest handler builds that unit.
            return Inspection(kind="model.gguf", metadata=metadata)

        facts: dict[str, object] = {
            "format": "gguf",
            "file": name,
            **summary,
            "chatTemplates": templates,
            "licence": {
                "identifier": model.text("general.license"),
                "name": model.text("general.license.name"),
            },
            "baseModels": base_models(model),
            **shard_facts(name),
        }
        general_type = (model.text("general.type") or "").lower()
        if general_type == "mmproj" or name.startswith("mmproj") or model.architecture == "clip":
            role, root = "projector", artifact.ref
        elif general_type == "adapter" or model.text("adapter.type"):
            role, root = "adapter-weights", artifact.ref
        elif split:
            match = SHARD.match(name)
            first = f"{match['prefix']}-00001-of-{match['total']}.gguf" if match else name
            role, root = "weights-shard", sibling(artifact.ref, first)
            if match is None:
                facts["shard"] = {
                    "index": (model.number("split.no") or 0) + 1,
                    "total": split_count,
                    "prefix": name,
                    "ext": "gguf",
                }
        else:
            role, root = "gguf", artifact.ref
        unit_claim: UnitClaim = claim(artifact, role, facts, root=root)
        return Inspection(
            kind="model.gguf",
            media_type="application/vnd.gguf",
            metadata=metadata,
            claims=(unit_claim,),
        )

    @staticmethod
    def _consistency(artifact: ArtifactView, model: gguf.GGUF, ctx: Context) -> None:
        """A self-contained GGUF must agree with itself; llama.cpp refuses files that do not."""
        problems = []
        block_count = model.arch("block_count")
        blocks = {
            int(m.group(1)) for t in model.tensors if (m := re.match(r"^blk\.(\d+)\.", t.name))
        }
        if type(block_count) is int and blocks and len(blocks) != block_count:
            problems.append(
                {"check": "block count", "metadata": block_count, "tensors": len(blocks)}
            )
        tokens = model.array_length("tokenizer.ggml.tokens")
        embedding = next((t for t in model.tensors if t.name == "token_embd.weight"), None)
        rows = embedding.dims[1] if embedding is not None and len(embedding.dims) == 2 else None
        if tokens is not None and rows is not None and rows != tokens:
            problems.append({"check": "vocabulary", "tokens": tokens, "embeddingRows": rows})
        width = model.arch("embedding_length")
        if type(width) is int and embedding is not None and embedding.dims[0] != width:
            problems.append(
                {"check": "embedding width", "metadata": width, "tensor": embedding.dims[0]}
            )
        subject = Subject.of_artifact(artifact.ref)
        if problems:
            ctx.recorder.fail(
                "model.package.config-mismatch", subject, tool=TOOL, detail={"problems": problems}
            )
        else:
            ctx.recorder.passed("model.package.config-mismatch")


def summarise(model: gguf.GGUF) -> dict[str, object]:
    return {
        "version": model.version,
        "architecture": model.architecture,
        "name": model.text("general.name"),
        "basename": model.text("general.basename"),
        "sizeLabel": model.text("general.size_label"),
        "organization": model.text("general.organization"),
        "repository": model.text("general.source.huggingface.repository")
        or model.text("general.source.url")
        or model.text("general.repo_url"),
        "type": model.text("general.type"),
        "quantization": model.quantization,
        "quantizedBy": model.text("general.quantized_by"),
        "parameters": model.parameters,
        "tensors": len(model.tensors),
        "tensorTypes": model.type_counts(),
        "uncheckedTensorTypes": sorted(model.unsized_types),
        "dataBytes": model.data_bytes,
        "contextLength": model.arch("context_length"),
        "embeddingLength": model.arch("embedding_length"),
        "blockCount": model.arch("block_count"),
        "tokenizer": model.text("tokenizer.ggml.model"),
        "vocabSize": model.array_length("tokenizer.ggml.tokens"),
        "split": {"no": model.number("split.no"), "count": model.number("split.count")}
        if model.number("split.count")
        else None,
    }


def base_models(model: gguf.GGUF) -> list[dict[str, object]]:
    count = model.number("general.base_model.count") or 0
    return [
        {
            "name": model.text(f"general.base_model.{i}.name"),
            "organization": model.text(f"general.base_model.{i}.organization"),
            "repository": model.text(f"general.base_model.{i}.repo_url"),
        }
        for i in range(min(count, 16))
    ]
