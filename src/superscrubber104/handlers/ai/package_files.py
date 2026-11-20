"""The files around the weights that make a model usable: configs, tokenizers, templates, shard
indexes, adapter configs, sentence-transformers modules, model cards, licences, custom model code,
Ollama Modelfiles and Hugging Face download records.

Each file becomes a claim on the model package rooted at its directory, carrying the facts the
assembler needs; nothing here decides whether a directory *is* a model package (a README.md or a
LICENSE alone does not make one). Files are matched by name, parsed with size limits, and never
executed or imported.
"""

import hashlib
import posixpath
import re
from collections.abc import Callable
from typing import Any

import yaml

from superscrubber104.core.interfaces import ArtifactView, Context, Detection, Inspection
from superscrubber104.core.model import ArtifactRef, Subject, UnitClaim
from superscrubber104.core.paths import is_bundle_path
from superscrubber104.core.yamlio import load_untrusted_yaml
from superscrubber104.formats.protobuf import LEN, Message, ProtobufError
from superscrubber104.handlers.ai.common import (
    TOOL,
    TooLarge,
    check_template,
    claim,
    name_of,
    parent_of,
    read_bytes,
    read_json,
)
from superscrubber104.handlers.datasets import is_dataset_card
from superscrubber104.licences import identify_text

_REMOTE_CODE = re.compile(
    r"^(modeling|configuration|tokenization|processing|image_processing|feature_extraction"
    r"|video_processing|modular)_[A-Za-z0-9_]+\.py$"
)
_LICENCE_FILE = re.compile(r"^(licen[cs]e|copying|use_policy|notice)([._-].*)?$", re.IGNORECASE)
_ST_MODULE_DIR = re.compile(r"^\d+_(Pooling|Dense|Normalize|Transformer|LayerNorm|WordEmbeddings)$")
_HF_METADATA = ".cache/huggingface/download/"
_CONFIG_KEYS = (
    "model_type", "architectures", "vocab_size", "hidden_size", "num_hidden_layers",
    "num_attention_heads", "max_position_embeddings", "torch_dtype", "auto_map",
    "_name_or_path", "tie_word_embeddings", "num_nextn_predict_layers", "is_encoder_decoder",
    "transformers_version", "n_layer", "n_embd", "n_ctx", "d_model",
)  # fmt: skip
_GENERATION_KEYS = (
    "temperature", "top_p", "top_k", "do_sample", "max_new_tokens", "max_length",
    "repetition_penalty", "bos_token_id", "eos_token_id", "pad_token_id",
)  # fmt: skip
_TEXT_LIMIT = 1 << 20
_TOKENIZER_LIMIT = 256 << 20

Facts = dict[str, object]


def _max_id(values: Any) -> int | None:
    ids = [v for v in values if type(v) is int and v >= 0]
    return max(ids) if ids else None


def _pick(data: dict[str, Any], keys: tuple[str, ...]) -> Facts:
    return {k: data[k] for k in keys if k in data}


def _text(view: ArtifactView, limit: int = _TEXT_LIMIT) -> str:
    return read_bytes(view, limit).decode("utf-8", "replace")


# --- one function per kind of file; each returns (kind, role, facts, metadata) or None ---------

Result = tuple[str, str, Facts, Facts] | None


def _config(view: ArtifactView, ctx: Context) -> Result:
    data = read_json(view)
    if not isinstance(data, dict):
        return None
    directory = name_of(parent_of(view.ref))
    if _ST_MODULE_DIR.match(directory):
        facts = {
            "module": directory,
            **_pick(data, ("word_embedding_dimension", "in_features", "out_features")),
        }
        modes = [
            k.removeprefix("pooling_mode_")
            for k, v in data.items()
            if k.startswith("pooling_mode_") and v is True
        ]
        facts["pooling"] = modes[0] if modes else None
        return "model.config.sentence-transformers", "st-module", facts, {}
    if not ({"model_type", "architectures"} & set(data)):
        return None
    facts = _pick(data, _CONFIG_KEYS)
    quantization = data.get("quantization_config")
    if isinstance(quantization, dict):
        facts["quantization"] = quantization.get("quant_method") or "unspecified"
    elif isinstance(data.get("quantization"), dict):  # MLX
        bits = data["quantization"].get("bits")
        facts["quantization"] = f"mlx-{bits}bit" if bits else "mlx"
    for nested in ("text_config", "llm_config", "language_config"):
        if isinstance(data.get(nested), dict):
            facts["textConfig"] = _pick(data[nested], _CONFIG_KEYS)
            break
    facts["vision"] = isinstance(data.get("vision_config"), dict) or "vision_tower" in str(
        data.get("architectures")
    )
    summary = _pick(data, ("model_type", "architectures"))
    return "model.config", "config", facts, {"modelConfig": summary}


def _tokenizer_config(view: ArtifactView, ctx: Context) -> Result:
    data = read_json(view)
    if not isinstance(data, dict):
        return None
    facts = _pick(data, ("tokenizer_class", "model_max_length", "auto_map"))
    templates = []
    template = data.get("chat_template")
    if isinstance(template, str):
        templates.append(check_template(ctx, view, template, "chat_template"))
    elif isinstance(template, list):
        for entry in template:
            if isinstance(entry, dict) and isinstance(entry.get("template"), str):
                name = str(entry.get("name", "default"))
                templates.append(
                    check_template(ctx, view, entry["template"], f"chat_template[{name}]")
                )
    facts["chatTemplates"] = templates
    decoder = data.get("added_tokens_decoder")
    if isinstance(decoder, dict):
        facts["maxTokenId"] = _max_id(int(k) for k in decoder if str(k).isdigit())
    return "model.tokenizer-config", "tokenizer-config", facts, {}


def _tokenizer_json(view: ArtifactView, ctx: Context) -> Result:
    data = read_json(view, _TOKENIZER_LIMIT)
    if not isinstance(data, dict) or not isinstance(data.get("model"), dict):
        return None
    model = data["model"]
    vocab = model.get("vocab")
    ids: list[int] = []
    entries = 0
    if isinstance(vocab, dict):
        entries, ids = len(vocab), [v for v in vocab.values() if type(v) is int]
    elif isinstance(vocab, list):  # Unigram: [[piece, score], ...]
        entries = len(vocab)
        ids = [entries - 1] if entries else []
    added = data.get("added_tokens")
    if isinstance(added, list):
        ids += [t["id"] for t in added if isinstance(t, dict) and type(t.get("id")) is int]
    facts = {"type": model.get("type"), "vocabEntries": entries, "maxTokenId": _max_id(ids)}
    return "model.tokenizer", "tokenizer", facts, {"tokenizer": facts}


def _vocab_json(view: ArtifactView, ctx: Context) -> Result:
    data = read_json(view, _TOKENIZER_LIMIT)
    if not isinstance(data, dict):
        return None
    return (
        "model.tokenizer",
        "tokenizer",
        {"vocabEntries": len(data), "maxTokenId": _max_id(data.values())},
        {},
    )


def _added_tokens(view: ArtifactView, ctx: Context) -> Result:
    data = read_json(view)
    if not isinstance(data, dict):
        return None
    return "model.tokenizer", "tokenizer-added", {"maxTokenId": _max_id(data.values())}, {}


def _vocab_txt(view: ArtifactView, ctx: Context) -> Result:
    lines = read_bytes(view, _TOKENIZER_LIMIT).count(b"\n")
    return (
        "model.tokenizer",
        "tokenizer",
        {"vocabEntries": lines, "maxTokenId": lines - 1 if lines else None},
        {},
    )


def _sentencepiece(view: ArtifactView, ctx: Context) -> Result:
    with view.open() as stream:
        message = Message.of_stream(stream, view.size)
        try:
            pieces = sum(1 for f in message.fields() if f.number == 1 and f.wire_type == LEN)
        except ProtobufError:
            return (
                "model.tokenizer",
                "tokenizer",
                {"type": "sentencepiece", "error": "unreadable"},
                {},
            )
    facts = {
        "type": "sentencepiece",
        "vocabEntries": pieces,
        "maxTokenId": pieces - 1 if pieces else None,
    }
    return "model.tokenizer", "tokenizer", facts, {"tokenizer": facts}


def _simple(kind: str, role: str) -> Callable[[ArtifactView, Context], Result]:
    def handle(view: ArtifactView, ctx: Context) -> Result:
        return kind, role, {}, {}

    return handle


def _generation(view: ArtifactView, ctx: Context) -> Result:
    data = read_json(view)
    if not isinstance(data, dict):
        return None
    facts = _pick(data, _GENERATION_KEYS)
    return "model.generation-config", "generation-config", facts, {"generation": facts}


def _chat_template_file(view: ArtifactView, ctx: Context) -> Result:
    if name_of(view.ref).endswith(".json"):
        data = read_json(view, _TEXT_LIMIT)
        template = data.get("chat_template") if isinstance(data, dict) else None
        if not isinstance(template, str):
            return None
    else:
        template = _text(view)
    summary = check_template(ctx, view, template, "template")
    return "model.chat-template", "chat-template", {"chatTemplates": [summary]}, {}


def _index(view: ArtifactView, ctx: Context) -> Result:
    data = read_json(view)
    if not isinstance(data, dict) or not isinstance(data.get("weight_map"), dict):
        return None
    weight_map = {k: v for k, v in data["weight_map"].items() if isinstance(v, str)}
    meta: dict[str, Any] = data["metadata"] if isinstance(data.get("metadata"), dict) else {}
    name = name_of(view.ref)
    files = sorted(set(weight_map.values()))
    facts = {
        "format": "safetensors" if ".safetensors." in name else "pytorch",
        "weightMap": weight_map,
        "totalSize": meta.get("total_size") if type(meta.get("total_size")) is int else None,
        "files": files,
    }
    return (
        "model.weights-index",
        "weights-index",
        facts,
        {"index": {"tensors": len(weight_map), "files": len(files)}},
    )


def _adapter_config(view: ArtifactView, ctx: Context) -> Result:
    data = read_json(view)
    if not isinstance(data, dict):
        return None
    facts = _pick(
        data,
        (
            "peft_type",
            "base_model_name_or_path",
            "revision",
            "r",
            "lora_alpha",
            "task_type",
            "target_modules",
        ),
    )
    return "model.adapter-config", "adapter-config", facts, {"adapter": facts}


def _st_modules(view: ArtifactView, ctx: Context) -> Result:
    data = read_json(view)
    if not isinstance(data, list):
        return None
    modules = [{"path": m.get("path"), "type": m.get("type")} for m in data if isinstance(m, dict)]
    return "model.sentence-transformers", "sentence-transformers", {"modules": modules}, {}


def _model_card(view: ArtifactView, ctx: Context) -> Result:
    text = _text(view)
    facts: Facts = {}
    if text.startswith("---"):
        end = text.find("\n---", 3)
        if 0 < end < 256 * 1024:
            try:
                front = load_untrusted_yaml(text[3:end])
            except yaml.YAMLError:
                front = None
            if isinstance(front, dict):
                if is_dataset_card(front):
                    return None  # the datasets handler reads it
                facts = _card_facts(front)
    for heading, key in (
        ("intended use", "intendedUse"),
        ("limitations", "limitations"),
        ("bias, risks", "limitations"),
    ):
        match = re.search(
            rf"^#+[^\n]*{heading}[^\n]*\n(?P<body>.*?)(?=^#|\Z)", text, re.I | re.M | re.S
        )
        if match and key not in facts:
            facts[key] = match["body"].strip()[:2000]
    # Front matter makes a README a model card; any README still describes the package it is in.
    return ("model.card" if facts else "unclassified"), "model-card", facts, {}


def _card_facts(front: dict[Any, Any]) -> Facts:
    def scalars(value: object, limit: int = 50) -> list[str] | str | None:
        if isinstance(value, str | int | float | bool):
            return str(value)
        if isinstance(value, list):
            return [str(v) for v in value[:limit] if isinstance(v, str | int | float)]
        return None

    facts: Facts = {
        "license": scalars(front.get("license")),
        "licenseName": scalars(front.get("license_name")),
        "licenseLink": scalars(front.get("license_link")),
        "baseModel": scalars(front.get("base_model")),
        "pipelineTag": scalars(front.get("pipeline_tag")),
        "libraryName": scalars(front.get("library_name")),
        "language": scalars(front.get("language")),
        "tags": scalars(front.get("tags")),
        "datasets": scalars(front.get("datasets")),
        "gated": any(str(k).startswith("extra_gated") for k in front) or bool(front.get("gated")),
    }
    return {k: v for k, v in facts.items() if v not in (None, [], False)} | {
        "gated": facts["gated"]
    }


def _licence(view: ArtifactView, ctx: Context) -> Result:
    if view.size > _TEXT_LIMIT * 4:
        return None
    identifier = identify_text(_text(view, _TEXT_LIMIT * 4))
    facts: Facts = {"identifier": identifier, "file": name_of(view.ref)}
    return "document.licence", "licence", facts, {"licence": facts}


def _remote_code(view: ArtifactView, ctx: Context) -> Result:
    module = name_of(view.ref).removesuffix(".py")
    digest = view.sha256 or hashlib.sha256(read_bytes(view, 16 << 20)).hexdigest()
    return "model.remote-code", "remote-code", {"module": module, "sha256": digest}, {}


def _modelfile(view: ArtifactView, ctx: Context) -> Result:
    text = _text(view)
    facts: Facts = {"parameters": {}}
    for instruction, argument in _modelfile_instructions(text):
        if instruction == "FROM":
            facts["from"] = argument
        elif instruction == "ADAPTER":
            facts["adapter"] = argument
        elif instruction == "TEMPLATE":
            facts["chatTemplates"] = [check_template(ctx, view, argument, "TEMPLATE")]
        elif instruction == "SYSTEM":
            facts["systemPromptSha256"] = hashlib.sha256(argument.encode()).hexdigest()
        elif instruction == "LICENSE":
            facts["licenceIdentifier"] = identify_text(argument)
        elif instruction == "PARAMETER":
            key, _, value = argument.partition(" ")
            facts["parameters"][key] = value.strip()  # type: ignore[index]
    if "from" not in facts:
        return None
    for key in ("from", "adapter"):
        reference = facts.get(key)
        if isinstance(reference, str):
            facts[f"{key}Kind"] = _modelfile_reference(view, ctx, reference, key)
    return "model.ollama.modelfile", "modelfile", facts, {}


def _modelfile_instructions(text: str) -> list[tuple[str, str]]:
    result = []
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index].strip()
        index += 1
        if not line or line.startswith("#"):
            continue
        instruction, _, argument = line.partition(" ")
        argument = argument.strip()
        if argument.startswith('"""'):
            body = argument[3:]
            while '"""' not in body and index < len(lines):
                body += "\n" + lines[index]
                index += 1
            argument = body.split('"""', 1)[0]
        result.append((instruction.upper(), argument.strip('"')))
    return result


def _modelfile_reference(view: ArtifactView, ctx: Context, reference: str, key: str) -> str:
    """Check a FROM or ADAPTER reference. Returns 'file', 'directory', 'registry' or 'escape'."""
    subject = Subject.of_artifact(view.ref, locator=key.upper())
    path_like = reference.startswith(("./", "../", "/", "~")) or re.match(
        r"^[A-Za-z]:[\\/]", reference
    )
    has_suffix = reference.lower().endswith((".gguf", ".safetensors", ".bin", ".pt"))
    if not path_like and not has_suffix:
        return "registry"
    relative = reference.removeprefix("./")
    if reference.startswith(("/", "~")) or ":" in reference[:3] or not is_bundle_path(relative):
        ctx.recorder.fail(
            "model.package.path-escape",
            subject,
            tool=TOOL,
            detail={"reference": reference, "note": "the path points outside the delivery"},
            discriminator=key,
        )
        return "escape"
    if not has_suffix:
        return "directory"
    if view.resolve(relative) is None and not view.ref.nested:
        ctx.recorder.fail(
            "model.package.file-missing",
            subject,
            tool=TOOL,
            detail={"file": relative, "role": key},
            discriminator=relative,
        )
    return "file"


def _hf_metadata(view: ArtifactView, ctx: Context) -> Result:
    """``huggingface_hub`` writes, per downloaded file, the commit and the ETag. For LFS files
    (the weights) the ETag is the file's sha256; for small files it is its git blob sha1."""
    lines = _text(view, 4096).splitlines()
    if len(lines) < 2:
        return None
    commit, etag = lines[0].strip(), lines[1].strip().strip('"')
    full = (view.ref.path, *view.ref.member)[-1]
    model_dir, _, relative = full.partition(_HF_METADATA)
    model_dir = model_dir.rstrip("/")
    relative = relative.removesuffix(".metadata")
    if not relative or not is_bundle_path(relative):
        return None
    if view.ref.member:
        outer = view.ref.member[:-1]
        root = ArtifactRef(view.ref.path, (*outer, model_dir) if model_dir else outer)
    else:
        root = ArtifactRef(model_dir or ".")
    facts: Facts = {
        "file": relative,
        "commit": commit,
        "etag": etag,
        "verified": "unchecked",
        "_root": root,
    }
    result: Result = ("model.hf-download-metadata", "hf-download-metadata", facts, {})
    if view.ref.member:
        return result  # files inside archives cannot be resolved; recorded, not verified
    target = view.resolve(
        posixpath.relpath(posixpath.join(model_dir, relative), posixpath.dirname(full))
    )
    if target is None:
        facts["verified"] = "file-absent"
        return result
    facts["targetPath"] = target.ref.path
    if re.fullmatch(r"[0-9a-f]{64}", etag):
        method, actual = "sha256", target.sha256
    elif re.fullmatch(r"[0-9a-f]{40}", etag) and target.size <= 64 << 20:
        content = read_bytes(target, 64 << 20)
        method = "git-blob-sha1"
        actual = hashlib.sha1(
            b"blob %d\0" % len(content) + content, usedforsecurity=False
        ).hexdigest()
    else:
        return result
    if actual == etag:
        facts["verified"] = method
        ctx.recorder.passed("model.provenance.checksum-mismatch")
    else:
        facts["verified"] = "mismatch"
        ctx.recorder.fail(
            "model.provenance.checksum-mismatch",
            Subject.of_artifact(target.ref),
            tool=TOOL,
            detail={
                "source": "huggingface download record",
                "record": view.ref.display,
                "method": method,
                "expected": etag,
                "actual": actual,
                "commit": commit,
            },
        )
    return result


_BY_NAME: dict[str, Callable[[ArtifactView, Context], Result]] = {
    "config.json": _config,
    "tokenizer_config.json": _tokenizer_config,
    "tokenizer.json": _tokenizer_json,
    "vocab.json": _vocab_json,
    "added_tokens.json": _added_tokens,
    "vocab.txt": _vocab_txt,
    "tokenizer.model": _sentencepiece,
    "spiece.model": _sentencepiece,
    "sentencepiece.bpe.model": _sentencepiece,
    "merges.txt": _simple("model.tokenizer", "tokenizer-merges"),
    "special_tokens_map.json": _simple("model.tokenizer-config", "special-tokens"),
    "generation_config.json": _generation,
    "chat_template.jinja": _chat_template_file,
    "chat_template.json": _chat_template_file,
    "adapter_config.json": _adapter_config,
    "modules.json": _st_modules,
    "config_sentence_transformers.json": _simple("model.config.sentence-transformers", "st-config"),
    "sentence_bert_config.json": _simple("model.config.sentence-transformers", "st-config"),
    "preprocessor_config.json": _simple("model.processor-config", "processor"),
    "processor_config.json": _simple("model.processor-config", "processor"),
    "readme.md": _model_card,
    "modelfile": _modelfile,
}


def _dispatch(view: ArtifactView) -> Callable[[ArtifactView, Context], Result] | None:
    name = name_of(view.ref)
    full = (view.ref.path, *view.ref.member)[-1]
    if _HF_METADATA in f"/{full}" and name.endswith(".metadata"):
        return _hf_metadata
    lowered = name.lower()
    if lowered in ("readme.md", "modelfile") or lowered.endswith(".modelfile"):
        return _BY_NAME["modelfile" if "modelfile" in lowered else "readme.md"]
    if name in _BY_NAME:
        return _BY_NAME[name]
    if name.endswith((".safetensors.index.json", ".bin.index.json")):
        return _index
    if _REMOTE_CODE.match(name):
        return _remote_code
    if _LICENCE_FILE.match(name):
        return _licence
    return None


class PackageFileHandler:
    name = "model-files"
    version = "1"
    kinds = frozenset(
        {
            "model.config", "model.config.sentence-transformers", "model.tokenizer",
            "model.tokenizer-config", "model.generation-config", "model.chat-template",
            "model.weights-index", "model.adapter-config", "model.sentence-transformers",
            "model.card", "document.licence", "model.remote-code", "model.ollama.modelfile",
            "model.hf-download-metadata", "model.processor-config",
        }
    )  # fmt: skip

    def detect(self, artifact: ArtifactView) -> Detection | None:
        return Detection("model.config", 60) if _dispatch(artifact) else None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        handle = _dispatch(artifact)
        assert handle is not None  # noqa: S101
        try:
            result = handle(artifact, ctx)
        except TooLarge as exc:
            return Inspection(kind="unclassified", metadata={"modelFile": {"skipped": str(exc)}})
        except (ValueError, UnicodeDecodeError, OSError) as exc:
            return Inspection(
                kind="unclassified", metadata={"modelFile": {"unreadable": str(exc)[:200]}}
            )
        if result is None:
            return Inspection(kind="unclassified")
        kind, role, facts, metadata = result
        root = facts.pop("_root", None)
        if role == "st-module":
            root = parent_of(parent_of(artifact.ref))
        unit_claim: UnitClaim = claim(
            artifact, role, facts, root=root if isinstance(root, ArtifactRef) else None
        )
        return Inspection(kind=kind, metadata=metadata, claims=(unit_claim,))
