"""Model packages: a model crosses as a complete, self-consistent unit, never as loose weights.

Claims are grouped by root: a directory for Hugging Face style packages, the file itself for
self-contained formats (GGUF, ONNX, Keras, llamafile), the manifest for an Ollama model, and the
first shard for split GGUF. A group becomes a package only if it holds weights, a model config, an
index, an adapter, a Modelfile or a manifest; a directory with just a README.md and a LICENSE
does not.

Each package is checked for completeness (shards, index, external files, layers, code modules,
adapter base models), internal consistency (index against shards, config against tensors,
tokenizer against vocabulary), remote code, licence, provenance and the model allowlist, and is
recorded with the attributes documented in docs/design/19-model-packages.md.
"""

import re
from collections import defaultdict
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field

from superscrubber104 import __version__
from superscrubber104.checks.licences import check_licences
from superscrubber104.core.canonical import JSON, jsonable
from superscrubber104.core.interfaces import Assembly, Context
from superscrubber104.core.model import (
    ArtifactRef,
    Component,
    ComponentType,
    LicenseRef,
    Requirement,
    Result,
    Severity,
    Subject,
    SubjectKind,
    ToolRef,
    TrustLevel,
    Unit,
    UnitClaim,
    UnitKind,
    UnitMember,
    UpstreamRef,
    Verification,
)
from superscrubber104.core.policy import AllowlistMode
from superscrubber104.handlers.ai.common import name_of, parent_of
from superscrubber104.handlers.common import relative_to
from superscrubber104.licences import Declared, combine, normalise_identifier

TOOL = ToolRef("superscrubber104.model-package", __version__)

CORE_ROLES = frozenset(
    {
        "weights", "weights-shard", "weights-index", "adapter-weights", "adapter-config",
        "config", "gguf", "keras", "onnx", "llamafile", "opaque-model", "sentence-transformers",
        "modelfile", "ollama-manifest", "projector", "classic-model", "mlflow-model",
    }
)  # fmt: skip
WEIGHT_ROLES = (
    "weights", "weights-shard", "adapter-weights", "projector", "gguf", "keras", "onnx",
    "llamafile", "opaque-model", "classic-model",
)  # fmt: skip
_SHARED_ROLES = frozenset({"licence", "model-card"})  # a directory's, shared with its GGUF files
_TOKENIZER_ROLES = ("tokenizer", "tokenizer-added")
_REPO_ID = re.compile(r"^[A-Za-z0-9][\w.-]*/[\w.-]+$")
_EMBEDDING = re.compile(r"(?:^|\.)(?:embed_tokens|wte|word_embeddings|tok_embeddings)\.weight$")
_LAYER = re.compile(r"^(?:model\.|transformer\.|gpt_neox\.)?(?:layers|h)\.(\d+)\.")

Facts = Mapping[str, JSON]


# --- typed access to claim facts ----------------------------------------------------------------


def _int(value: object) -> int:
    return value if type(value) is int else 0


def _str(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _dict(value: object) -> dict[str, JSON]:
    return value if isinstance(value, dict) else {}


def _list(value: object) -> list[JSON]:
    return value if isinstance(value, list) else []


# --- grouping -----------------------------------------------------------------------------------


@dataclass
class _Package:
    root: ArtifactRef
    claims: list[UnitClaim]
    name: str = ""
    attributes: dict[str, object] = field(default_factory=dict)
    requires: list[Requirement] = field(default_factory=list)
    upstream: UpstreamRef | None = None
    verifications: dict[ArtifactRef, list[Verification]] = field(default_factory=dict)
    aliases: set[str] = field(default_factory=set)
    licence: str | None = None
    variant_of: ArtifactRef | None = None  # the model repository a format variant belongs to

    @property
    def id(self) -> str:
        return f"{UnitKind.MODEL_PACKAGE.value}:{self.root.display}"

    @property
    def subject(self) -> Subject:
        return Subject(SubjectKind.UNIT, unit=self.id)

    def role(self, *roles: str) -> list[UnitClaim]:
        return [c for c in self.claims if c.role in roles]

    def first(self, *roles: str) -> Facts:
        found = self.role(*roles)
        return found[0].facts if found else {}

    def weights(self) -> list[UnitClaim]:
        return self.role(*WEIGHT_ROLES)

    def gguf(self) -> Facts:
        found = [c.facts for c in self.weights() if c.facts.get("format") == "gguf"]
        return found[0] if found else _dict(self.first("ollama-manifest").get("gguf"))

    def facts_list(self, key: str) -> Iterator[JSON]:
        for c in self.claims:
            yield from _list(c.facts.get(key))

    def members(self) -> tuple[UnitMember, ...]:
        seen = {(c.artifact, c.role): c.sha256 for c in self.claims}
        return tuple(UnitMember(role, ref, sha) for (ref, role), sha in sorted(seen.items()))


def _group(claims: Sequence[UnitClaim]) -> list[_Package]:
    groups: dict[ArtifactRef, list[UnitClaim]] = defaultdict(list)
    for c in claims:
        groups[c.root].append(c)
    packages = {
        root: _Package(root, list(cs))
        for root, cs in groups.items()
        if any(c.role in CORE_ROLES for c in cs)
    }

    def is_file(root: ArtifactRef) -> bool:
        return any(c.artifact == root for c in packages[root].claims)

    # onnx/ with its own config and tokenizer but no weights (Optimum's export): the weight
    # files in it, each a package on its own until now (onnx/model.onnx), are its weights.
    for root in [r for r in packages if not is_file(r) and not packages[r].weights()]:
        for inner in [r for r in packages if r != root and parent_of(r) == root and is_file(r)]:
            packages[root].claims.extend(packages.pop(inner).claims)
    for root, package in packages.items():
        if is_file(root):
            continue
        owner = parent_of(root)
        if (
            owner != root
            and owner in packages
            and not is_file(owner)
            and not package.role(*_SHARED_ROLES)
        ):
            # A format folder in a model repository: under its licence and model card.
            package.variant_of = owner
            package.claims.extend(c for c in groups[owner] if c.role in _SHARED_ROLES)
    for root, package in packages.items():
        directory = parent_of(root)
        if not is_file(root) or directory in packages:
            continue
        shared = [c for c in groups.get(directory, []) if c.role in _SHARED_ROLES]
        owner = parent_of(directory)
        if (
            not shared
            and owner != directory
            and owner in packages
            and not any(c.artifact == owner for c in packages[owner].claims)
        ):
            # onnx/model.onnx, openvino/openvino_model.xml: a format variant in a model
            # repository, under the repository's licence and model card.
            shared = [c for c in groups[owner] if c.role in _SHARED_ROLES]
            package.variant_of = owner
        package.claims.extend(shared)
    return [packages[root] for root in sorted(packages)]


class ModelPackageAssembler:
    name = "model-package"
    version = "1"
    kind = UnitKind.MODEL_PACKAGE

    def assemble(self, claims: Sequence[UnitClaim], ctx: Context) -> Iterable[Assembly]:
        packages = _group(claims)
        for package in packages:
            _Checks(package, ctx).run()
        _resolve_requirements(packages, ctx)
        return [_finish(package, ctx) for package in packages]


# --- checks -------------------------------------------------------------------------------------


class _Checks:
    def __init__(self, package: _Package, ctx: Context) -> None:
        self.p = package
        self.ctx = ctx
        self.missing_reported: set[str] = set()

    def fail(
        self,
        rule: str,
        detail: Mapping[str, object],
        discriminator: str = "",
        severity: Severity | None = None,
    ) -> None:
        self.ctx.recorder.fail(
            rule,
            self.p.subject,
            tool=TOOL,
            detail=detail,
            discriminator=discriminator,
            severity=severity,
        )

    def passed(self, *rules: str) -> None:
        for rule in rules:
            self.ctx.recorder.passed(rule)

    def missing(self, file: str, role: str, **extra: object) -> None:
        if file not in self.missing_reported:
            self.missing_reported.add(file)
            detail = {"file": file, "role": role, **extra}
            self.fail("model.package.file-missing", detail, discriminator=file)

    def run(self) -> None:
        p = self.p
        p.attributes["identity"] = self.identity()
        if p.variant_of is not None:
            p.attributes["variantOf"] = p.variant_of.display
        p.attributes["weights"] = self.weights()
        self.index()
        self.shards()
        self.config()
        self.tokenizer()
        p.attributes["chatTemplates"] = list(p.facts_list("chatTemplates"))
        self.remote_code()
        self.requirements()
        self.embedding()
        self.card()
        self.licence()
        self.provenance()
        self.signature()
        if not self.missing_reported:
            self.passed("model.package.file-missing")

    # identity and weights

    def identity(self) -> dict[str, object]:
        p = self.p
        config = p.first("config")
        gguf = p.gguf()
        ollama = p.first("ollama-manifest")
        architectures = _list(config.get("architectures"))
        architecture = (
            _str(architectures[0] if architectures else None)
            or _str(config.get("model_type"))
            or _str(gguf.get("architecture"))
        )
        name_or_path = _str(config.get("_name_or_path"))
        if ollama:
            name = f"{ollama.get('reference')}:{ollama.get('tag')}"
            reference = str(ollama.get("reference"))
            p.aliases |= {reference, reference.rsplit("/", 1)[-1]}
        elif name_or_path and _REPO_ID.match(name_or_path):
            name = name_or_path
        else:
            root_name = name_of(p.root) if p.root.path != "." else None
            if p.variant_of is not None:  # all-MiniLM-L6-v2/onnx/model.onnx, not model.onnx
                within = relative_to(p.root, p.variant_of)
                repository = name_of(p.variant_of) if p.variant_of.path != "." else None
                if within:
                    root_name = f"{repository}/{within}" if repository else within
            name = _str(gguf.get("name")) or root_name or architecture or "unnamed model"
        p.name = name
        candidates = (name, name_or_path, gguf.get("name"), gguf.get("basename"), name_of(p.root))
        p.aliases |= {a for a in candidates if isinstance(a, str) and a}
        p.aliases = {a.lower() for a in p.aliases}
        own = [c for c in p.weights() if c.role not in ("adapter-weights", "projector")]
        parameters = sum(_int(c.facts.get("parameters")) for c in own) or _int(
            gguf.get("parameters")
        )
        return {
            "name": name,
            "architecture": architecture,
            "modelType": _str(config.get("model_type")),
            "parameters": parameters or None,
            "sizeLabel": _str(gguf.get("sizeLabel")),
            "publisher": name.split("/", 1)[0]
            if _REPO_ID.match(name)
            else _str(gguf.get("organization")),
        }

    def weights(self) -> dict[str, object]:
        p = self.p
        weights = p.weights()
        formats = {str(c.facts["format"]) for c in weights if c.facts.get("format")}
        if p.first("ollama-manifest"):
            formats.add("ollama")
        dtypes: dict[str, int] = defaultdict(int)
        for c in weights:
            for key in ("dtypes", "tensorTypes"):
                for dtype, count in _dict(c.facts.get(key)).items():
                    dtypes[dtype] += _int(count)
        quantization = (
            _str(p.first("config").get("quantization"))
            or next((q for c in weights if (q := _str(c.facts.get("quantization")))), None)
            or _str(p.gguf().get("quantization"))
        )
        return {
            "formats": sorted(formats),
            "files": sorted(name_of(c.artifact) for c in weights),
            "tensors": sum(_int(c.facts.get("tensors")) for c in weights) or None,
            "bytes": sum(_int(c.facts.get("dataBytes")) for c in weights) or None,
            "dtypes": dict(sorted(dtypes.items())),
            "quantization": quantization,
            "sharded": bool(p.role("weights-shard")),
            "index": [name_of(c.artifact) for c in p.role("weights-index")],
        }

    # completeness

    def index(self) -> None:
        p = self.p
        for idx in p.role("weights-index"):
            fmt = idx.facts.get("format")
            files = [f for f in _list(idx.facts.get("files")) if isinstance(f, str)]
            index_name = name_of(idx.artifact)
            family = [c for c in p.role("weights", "weights-shard") if _family(c) == fmt]
            present = {name_of(c.artifact): c for c in family}
            for file in files:
                if file not in present:
                    self.missing(file, "weights-shard", index=index_name)
            for file in sorted(set(present) - set(files)):
                detail = {"file": file, "index": index_name}
                self.fail("model.package.file-unreferenced", detail, discriminator=file)
            if fmt == "safetensors":
                self._index_contents(idx, files, present)

    def _index_contents(
        self, idx: UnitClaim, files: list[str], present: dict[str, UnitClaim]
    ) -> None:
        by_file: dict[str, set[str]] = defaultdict(set)
        for tensor, file in _dict(idx.facts.get("weightMap")).items():
            by_file[str(file)].add(tensor)
        problems: list[dict[str, object]] = []
        for file in files:
            if file not in present:
                continue
            actual = set(_dict(present[file].facts.get("tensorShapes")))
            expected = by_file.get(file, set())
            if actual != expected:
                problems.append(
                    {
                        "file": file,
                        "inIndexNotInShard": sorted(expected - actual)[:20],
                        "inShardNotInIndex": sorted(actual - expected)[:20],
                    }
                )
        total = idx.facts.get("totalSize")
        if type(total) is int and all(f in present for f in files):
            data = sum(_int(present[f].facts.get("dataBytes")) for f in files)
            if data != total:
                problems.append({"indexTotalSize": total, "shardDataBytes": data})
        index_name = name_of(idx.artifact)
        if problems:
            detail = {"index": index_name, "problems": problems}
            self.fail("model.package.index-mismatch", detail, discriminator=index_name)
        else:
            self.passed("model.package.index-mismatch")

    def shards(self) -> None:
        series: dict[tuple[str, int, str], set[int]] = defaultdict(set)
        for c in self.p.role("weights-shard"):
            shard = _dict(c.facts.get("shard"))
            if shard:
                key = (str(shard.get("prefix")), _int(shard.get("total")), str(shard.get("ext")))
                series[key].add(_int(shard.get("index")))
        for (prefix, total, ext), indices in sorted(series.items()):
            for index in range(1, total + 1):
                if index not in indices:
                    pattern = f"{prefix}-*-of-{total:05d}.{ext}"
                    file = f"{prefix}-{index:05d}-of-{total:05d}.{ext}"
                    self.missing(file, "weights-shard", series=pattern)

    # consistency

    def config(self) -> None:
        p = self.p
        config = p.first("config")
        transformers_layout = bool(
            p.role("weights-index", "weights-shard", "tokenizer-config", *_TOKENIZER_ROLES)
        )
        if not config:
            if transformers_layout and p.role("weights", "weights-shard"):
                self.fail("model.package.config-missing", {})
            else:
                self.passed("model.package.config-missing")
            return
        self.passed("model.package.config-missing")
        text = _dict(config.get("textConfig")) or dict(config)
        keys = (
            "vocab_size",
            "hidden_size",
            "num_hidden_layers",
            "max_position_embeddings",
            "torch_dtype",
        )
        p.attributes["config"] = {k: text[k] for k in keys if text.get(k) is not None}

        tensors: dict[str, list[JSON]] = {}
        for c in p.role("weights", "weights-shard"):
            if c.facts.get("format") == "safetensors":
                for name, shape in _dict(c.facts.get("tensorShapes")).items():
                    tensors[name] = _list(shape)
        if not tensors:
            return
        vocab = _int(text.get("vocab_size"))
        hidden = (
            _int(text.get("hidden_size")) or _int(text.get("n_embd")) or _int(text.get("d_model"))
        )
        layers = _int(text.get("num_hidden_layers")) or _int(text.get("n_layer"))
        problems: list[dict[str, object]] = []
        embedding = next(
            (s for n, s in sorted(tensors.items()) if _EMBEDDING.search(n) and len(s) == 2), None
        )
        # Quantised weights are packed into other shapes, so only unquantised ones are compared.
        if embedding and not config.get("quantization"):
            if vocab and embedding[0] != vocab:
                problems.append(
                    {"check": "vocabulary", "config": vocab, "embeddingRows": embedding[0]}
                )
            if hidden and embedding[1] != hidden:
                problems.append(
                    {"check": "hidden size", "config": hidden, "embeddingWidth": embedding[1]}
                )
        indices = {int(m.group(1)) for n in tensors if (m := _LAYER.match(n))}
        extra = _int(config.get("num_nextn_predict_layers"))  # multi-token prediction layers
        in_range = layers <= len(indices) <= layers + extra
        if layers and indices and not config.get("vision") and not in_range:
            problems.append({"check": "layers", "config": layers, "tensors": len(indices)})
        if problems:
            self.fail("model.package.config-mismatch", {"problems": problems})
        else:
            self.passed("model.package.config-mismatch")

    def tokenizer(self) -> None:
        p = self.p
        config = p.first("config")
        tokenizers = p.role(*_TOKENIZER_ROLES)
        sources = p.role(*_TOKENIZER_ROLES, "tokenizer-config")
        ids = [c.facts["maxTokenId"] for c in sources if type(c.facts.get("maxTokenId")) is int]
        max_id = max((i for i in ids if isinstance(i, int)), default=None)
        vocab = _int((_dict(config.get("textConfig")) or dict(config)).get("vocab_size"))
        types = sorted({str(c.facts["type"]) for c in tokenizers if c.facts.get("type")})
        if tokenizers or max_id is not None:
            files = p.role(
                *_TOKENIZER_ROLES, "tokenizer-config", "tokenizer-merges", "special-tokens"
            )
            p.attributes["tokenizer"] = {
                "files": sorted(name_of(c.artifact) for c in files),
                "type": types[0] if types else None,
                "tokens": max_id + 1 if max_id is not None else None,
            }
        if vocab and p.role("weights", "weights-shard") and not tokenizers:
            self.fail("model.package.tokenizer-missing", {"configVocabSize": vocab})
        else:
            self.passed("model.package.tokenizer-missing")
        if vocab and max_id is not None and max_id + 1 > vocab:
            detail = {"configVocabSize": vocab, "tokenizerTokens": max_id + 1}
            self.fail("model.package.tokenizer-mismatch", detail)
        else:
            self.passed("model.package.tokenizer-mismatch")

    # code, requirements, embeddings

    def remote_code(self) -> None:
        p = self.p
        references: set[str] = set()
        for c in p.role("config", "tokenizer-config"):
            for value in _dict(c.facts.get("auto_map")).values():
                references |= {
                    v for v in (value if isinstance(value, list) else [value]) if isinstance(v, str)
                }
        modules = {str(c.facts.get("module")): c for c in p.role("remote-code")}
        p.attributes["remoteCode"] = {
            "required": bool(references),
            "autoMap": sorted(references),
            "files": sorted(name_of(c.artifact) for c in modules.values()),
        }
        if not references:
            self.passed("model.remote-code.required", "model.remote-code.external")
            return
        detail = {"autoMap": sorted(references), "files": sorted(f"{m}.py" for m in modules)}
        self.fail("model.remote-code.required", detail)
        external = sorted(r for r in references if "--" in r)
        if external:
            self.fail("model.remote-code.external", {"references": external})
        else:
            self.passed("model.remote-code.external")
        for reference in sorted(references - set(external)):
            module = reference.rsplit(".", 1)[0]
            if module not in modules:
                self.missing(f"{module}.py", "remote-code", reference=reference)

    def requirements(self) -> None:
        p = self.p
        adapter = p.first("adapter-config")
        if adapter:
            p.attributes["adapter"] = {
                "type": adapter.get("peft_type"),
                "baseModel": adapter.get("base_model_name_or_path"),
                "rank": adapter.get("r"),
                "alpha": adapter.get("lora_alpha"),
                "targetModules": adapter.get("target_modules"),
            }
            base = _str(adapter.get("base_model_name_or_path"))
            if base:
                revision = _str(adapter.get("revision"))
                p.requires.append(
                    Requirement("base-model", base, UnitKind.MODEL_PACKAGE, version=revision)
                )
            if not p.role("adapter-weights"):
                self.missing("adapter_model.safetensors", "adapter-weights")
        for c in p.role("adapter-weights"):
            for base_model in _list(c.facts.get("baseModels")):
                ref = _dict(base_model)
                name = _str(ref.get("repository")) or _str(ref.get("name"))
                if name:
                    p.requires.append(Requirement("base-model", name, UnitKind.MODEL_PACKAGE))
        modelfile = p.first("modelfile")
        for key, relation in (("from", "base-model"), ("adapter", "adapter")):
            if modelfile.get(f"{key}Kind") == "registry":
                p.requires.append(
                    Requirement(relation, str(modelfile.get(key)), UnitKind.MODEL_PACKAGE)
                )
        projectors = p.role("projector")
        if projectors:
            p.attributes["multimodal"] = {
                "projectors": sorted(name_of(c.artifact) for c in projectors)
            }

    def embedding(self) -> None:
        p = self.p
        modules = _list(p.first("sentence-transformers").get("modules"))
        if not modules:
            return
        pooling = p.first("st-module")
        p.attributes["embedding"] = {
            "dimension": pooling.get("word_embedding_dimension")
            or p.first("config").get("hidden_size"),
            "pooling": pooling.get("pooling"),
            "normalize": any(str(_dict(m).get("type", "")).endswith("Normalize") for m in modules),
        }

    # evidence

    def card(self) -> None:
        p = self.p
        card = p.first("model-card")
        keys = (
            "pipelineTag",
            "baseModel",
            "libraryName",
            "language",
            "tags",
            "datasets",
            "intendedUse",
            "limitations",
            "gated",
        )
        if card:
            p.attributes["modelCard"] = {
                k: card[k] for k in keys if card.get(k) not in (None, [], "")
            }
            self.passed("model.package.card-missing")
        elif p.role("config"):  # Hugging Face style packages are expected to carry one
            self.fail("model.package.card-missing", {})
        else:
            self.passed("model.package.card-missing")

    def licence(self) -> None:
        p = self.p
        declared: list[Declared] = []
        for c in p.role("licence"):
            declared.append(
                Declared(f"licence-file:{name_of(c.artifact)}", _str(c.facts.get("identifier")))
            )
        card = p.first("model-card")
        card_name = _str(card.get("licenseName"))
        values = card.get("license")
        for value in values if isinstance(values, list) else [values] if values else []:
            text = str(value)
            declared.append(
                Declared("model-card", normalise_identifier(text, card_name), card_name or text)
            )
        for c in p.weights():
            licence = _dict(c.facts.get("licence"))
            identifier, name = _str(licence.get("identifier")), _str(licence.get("name"))
            if identifier:
                declared.append(
                    Declared(
                        "gguf-metadata", normalise_identifier(identifier, name), name or identifier
                    )
                )
        for role, source in (
            ("modelfile", "modelfile"),
            ("ollama-manifest", "ollama-licence-layer"),
        ):
            facts = p.first(role)
            if "licenceIdentifier" in facts:
                declared.append(Declared(source, _str(facts["licenceIdentifier"])))
        inherited = (
            p.variant_of is not None
            and all(c.root == p.variant_of for c in p.role("licence", "model-card"))
            and not any(_dict(c.facts.get("licence")) for c in p.weights())
        )
        if inherited:
            # Its only licence is the repository's: decided once, on the repository, so a site
            # is not asked to approve the same licence for every format folder.
            p.licence = combine(declared)[0]
            p.attributes["licenceFrom"] = p.variant_of.display if p.variant_of else None
        else:
            p.licence = check_licences(p.subject, declared, self.ctx)
        p.attributes["licence"] = {
            "expression": p.licence,
            "declared": [
                {"source": d.source, "identifier": d.identifier, "name": d.name} for d in declared
            ],
            "gated": bool(card.get("gated")),
        }

    def provenance(self) -> None:
        p = self.p
        records = p.role("hf-download-metadata")
        ollama = p.first("ollama-manifest")
        method: str | None = None
        verified = 0
        if ollama:
            method = "ollama-manifest"
            digest = f"sha256:{ollama.get('manifestSha256')}"
            p.upstream = UpstreamRef(
                "ollama", str(ollama.get("reference")), str(ollama.get("tag")), digest
            )
            for c in p.claims:
                if c.role != "ollama-manifest":
                    check = Verification(
                        "ollama-manifest-digest",
                        TrustLevel.CHECKSUM,
                        Result.PASS,
                        anchor=p.root.display,
                    )
                    p.verifications.setdefault(c.artifact, []).append(check)
                    verified += 1
        elif records:
            method = "huggingface-download-record"
            commits = sorted({x for r in records if (x := _str(r.facts.get("commit")))})
            name_or_path = _str(p.first("config").get("_name_or_path"))
            reference = name_or_path if name_or_path and _REPO_ID.match(name_or_path) else "unknown"
            if commits:
                p.upstream = UpstreamRef(
                    "huggingface", reference, commits[0] if len(commits) == 1 else None
                )
            if len(commits) > 1:
                p.attributes["provenanceNote"] = "files were downloaded from more than one commit"
            for r in records:
                target, how = _str(r.facts.get("targetPath")), r.facts.get("verified")
                if target and how in ("sha256", "git-blob-sha1"):
                    detail: dict[str, JSON] = {"commit": r.facts.get("commit"), "method": how}
                    check = Verification(
                        "huggingface-download-record",
                        TrustLevel.CHECKSUM,
                        Result.PASS,
                        detail=detail,
                    )
                    p.verifications.setdefault(ArtifactRef(target), []).append(check)
                    verified += 1
        else:
            repository = _str(p.gguf().get("repository"))
            if repository:
                p.upstream = UpstreamRef("url", repository)
                method = "gguf-metadata (asserted)"
        weights = p.weights()
        conversion = next((m for c in weights if (m := _dict(c.facts.get("metadata")))), None)
        p.attributes["provenance"] = {  # signature() adds the publisher's signature
            "method": method,
            "upstream": _upstream(p.upstream),
            "verifiedFiles": verified,
            "weightFilesWithoutRecord": sum(
                1 for c in weights if c.artifact not in p.verifications
            ),
            "conversion": conversion,
        }

    def signature(self) -> None:
        """The publisher's model signature: verified files, and package files it leaves out."""
        p = self.p
        signature = p.first("signature")
        if not signature:
            return
        covered = {_signed_path(p.root, str(n)) for n in _list(signature.get("covered"))}
        if signature.get("status") == "verified":
            for ref in covered:
                p.verifications.setdefault(ref, []).append(
                    Verification(
                        "model-signing",
                        TrustLevel.SIGNATURE,
                        Result.PASS,
                        signer=_str(signature.get("signer")),
                        anchor=_str(signature.get("anchor")),
                        detail={"method": signature.get("method")},
                    )
                )
        ignored = {str(n) for n in _list(signature.get("ignored"))}
        own = _str(signature.get("signature"))
        unsigned = sorted(
            name
            for c in p.claims
            if c.role != "signature"
            and c.artifact not in covered
            and (name := relative_to(c.artifact, p.root) or c.artifact.display) != own
        )
        missing = [str(n) for n in _list(signature.get("missing"))]
        p.attributes["signature"] = {
            "status": signature.get("status"),
            "method": signature.get("method"),
            "signer": signature.get("signer"),
            "signedFiles": len(covered),
        }
        if unsigned or missing:
            self.fail(
                "model.signature.incomplete",
                {
                    "unsigned": unsigned[:100],
                    "signedButMissing": missing[:100],
                    "ignoredBySigner": sorted(ignored & set(unsigned)),
                },
            )
        else:
            self.passed("model.signature.incomplete")


def _signed_path(root: ArtifactRef, name: str) -> ArtifactRef:
    if root.member:
        return ArtifactRef(root.path, (*root.member[:-1], f"{root.member[-1]}/{name}"))
    return ArtifactRef(name if root.path == "." else f"{root.path}/{name}")


def _upstream(upstream: UpstreamRef | None) -> dict[str, str | None] | None:
    if upstream is None:
        return None
    return {
        "type": upstream.type,
        "reference": upstream.reference,
        "revision": upstream.revision,
        "digest": upstream.digest,
    }


def _family(claim: UnitClaim) -> str:
    fmt = str(claim.facts.get("format", ""))
    return "pytorch" if fmt.startswith("pytorch") else fmt


# --- across packages ----------------------------------------------------------------------------


def _resolve_requirements(packages: Sequence[_Package], ctx: Context) -> None:
    """Satisfy each requirement with another package in the delivery, matched by name."""
    for package in packages:
        resolved = []
        for need in package.requires:
            wanted = need.name.lower()
            short = wanted.rsplit("/", 1)[-1]
            match = next(
                (
                    other
                    for other in packages
                    if other is not package
                    and (
                        wanted in other.aliases
                        or short in {a.rsplit("/", 1)[-1] for a in other.aliases}
                    )
                ),
                None,
            )
            if match is None:
                ctx.recorder.fail(
                    "model.package.requirement-unmet",
                    package.subject,
                    tool=TOOL,
                    detail={
                        "relation": need.relation,
                        "name": need.name,
                        "note": "not in this delivery; it must already be on the receiving side",
                    },
                    discriminator=f"{need.relation}:{need.name}",
                )
                resolved.append(need)
            else:
                ctx.recorder.passed("model.package.requirement-unmet")
                resolved.append(
                    Requirement(
                        need.relation, need.name, need.kind, need.digest, need.version, match.id
                    )
                )
        package.requires = resolved


def _finish(package: _Package, ctx: Context) -> Assembly:
    members = package.members()
    digest = Unit(UnitKind.MODEL_PACKAGE, package.name, package.root, members).digest
    _allowlist(package, digest, ctx)
    bom_ref = f"model:{package.id}"
    upstream = package.upstream
    purl = None
    if (
        upstream
        and upstream.type == "huggingface"
        and _REPO_ID.match(upstream.reference)
        and upstream.revision
    ):
        org, name = upstream.reference.split("/", 1)
        purl = f"pkg:huggingface/{org.lower()}/{name}@{upstream.revision}"
    identity = _dict(jsonable(package.attributes.get("identity")))
    weights = _dict(jsonable(package.attributes.get("weights")))
    properties = {
        "superscrubber104:unit-digest": digest,
        "superscrubber104:architecture": identity.get("architecture"),
        "superscrubber104:parameters": identity.get("parameters"),
        "superscrubber104:quantization": weights.get("quantization"),
        "superscrubber104:formats": ",".join(str(f) for f in _list(weights.get("formats"))) or None,
    }
    component = Component(
        bom_ref=bom_ref,
        type=ComponentType.MACHINE_LEARNING_MODEL,
        name=package.name,
        version=upstream.revision if upstream else None,
        purl=purl,
        licenses=(LicenseRef(expression=package.licence),) if package.licence else (),
        supplier=_str(identity.get("publisher")),
        upstream=upstream,
        evidence=tuple(m.artifact for m in members),
        properties={k: str(v) for k, v in properties.items() if v is not None},
    )
    unit = Unit(
        kind=UnitKind.MODEL_PACKAGE,
        name=package.name,
        root=package.root,
        members=members,
        requires=tuple(package.requires),
        components=(bom_ref,),
        attributes={
            k: jsonable(v) for k, v in package.attributes.items() if v not in (None, {}, [])
        },
    )
    verifications = {ref: tuple(v) for ref, v in package.verifications.items()}
    return Assembly(unit, (component,), verifications)


def _allowlist(package: _Package, digest: str, ctx: Context) -> None:
    """Match the package against the policy's model allowlist, by unit digest or identity."""
    allowlist = ctx.policy.allowlists.get("models")
    if allowlist is None:
        return
    upstream = package.upstream
    identity = f"{upstream.type}:{upstream.reference}" if upstream else None
    revision = upstream.revision if upstream else None
    for index, entry in enumerate(allowlist.entries):
        if not isinstance(entry, dict):
            continue
        by_digest = entry.get("digest") == digest
        by_identity = (
            identity is not None
            and entry.get("id") == identity
            and entry.get("revision") in (None, revision)
        )
        if not (by_digest or by_identity):
            continue
        anchor = f"allowlists.models[{index}]"
        level = TrustLevel.PINNED_CHECKSUM if by_digest else TrustLevel.ASSERTED
        for member in package.members():
            check = Verification("policy-allowlist", level, Result.PASS, anchor=anchor)
            package.verifications.setdefault(member.artifact, []).append(check)
        package.attributes["allowlist"] = {
            "entry": anchor,
            "matchedBy": "digest" if by_digest else "identity",
        }
        ctx.recorder.passed("model.allowlist.unapproved")
        return
    ctx.recorder.fail(
        "model.allowlist.unapproved",
        package.subject,
        tool=TOOL,
        detail={
            "identity": identity,
            "revision": revision,
            "unitDigest": digest,
            "mode": allowlist.mode.value,
        },
        severity=Severity.INFO if allowlist.mode is AllowlistMode.REPORT else None,
    )
