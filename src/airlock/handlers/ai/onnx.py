"""ONNX models: custom operators and external data.

The model is a protobuf ``ModelProto``. It is walked in place with the bounded reader in
``airlock.formats.protobuf``; tensor payloads are skipped, so a 2 GB model is read in milliseconds.

* **Custom operators.** A node in a domain that neither ONNX nor the common runtimes define needs
  an operator library (native code) registered at load time. Domains defined by the model's own
  local functions are not custom.
* **External data.** Large tensors can live in separate files named by the model. Each location
  must stay inside the model's directory (an absolute path or ``..`` would make the runtime read
  any file on the host), must exist in the delivery, and must be long enough for the declared
  offset and length.
"""

from collections import Counter
from dataclasses import dataclass, field

from airlock.core.interfaces import ArtifactView, Context, Detection, Inspection
from airlock.core.model import Subject, UnitClaim
from airlock.core.paths import is_bundle_path
from airlock.formats.protobuf import LEN, Message, ProtobufError
from airlock.handlers.ai.common import TOOL, claim, name_of

STANDARD_DOMAINS = frozenset(
    {"", "ai.onnx", "ai.onnx.ml", "ai.onnx.training", "ai.onnx.preview.training"}
)
# Operators shipped with ONNX Runtime itself: runtime-specific, but not third-party code.
RUNTIME_DOMAINS = frozenset(
    {"com.microsoft", "com.microsoft.nchwc", "com.microsoft.experimental", "com.ms.internal.nhwc"}
)


@dataclass
class _Model:
    ir_version: int | None = None
    producer: str | None = None
    producer_version: str | None = None
    opsets: dict[str, int] = field(default_factory=dict)
    function_domains: set[str] = field(default_factory=set)
    node_domains: Counter[str] = field(default_factory=Counter)
    custom_ops: set[str] = field(default_factory=set)
    nodes: int = 0
    initializers: int = 0
    external: list[dict[str, object]] = field(default_factory=list)
    metadata: dict[str, str] = field(default_factory=dict)


def _tensor(message: Message, model: _Model, name_hint: str = "") -> None:
    name, entries, external = name_hint, {}, False
    for f in message.fields():
        if f.number == 8 and f.wire_type == LEN:
            name = message.text(f)
        elif f.number == 13 and f.wire_type == LEN:  # external_data: StringStringEntryProto
            entry = message.sub(f)
            key = value = ""
            for e in entry.fields():
                if e.number == 1 and e.wire_type == LEN:
                    key = entry.text(e)
                elif e.number == 2 and e.wire_type == LEN:
                    value = entry.text(e)
            entries[key] = value
        elif f.number == 14:  # data_location: 1 = EXTERNAL
            external = f.value == 1
    if external or entries:
        model.external.append({"tensor": name, **entries})


def _node(message: Message, model: _Model) -> None:
    model.nodes += 1
    op_type, domain = "", ""
    for f in message.fields():
        if f.number == 4 and f.wire_type == LEN:
            op_type = message.text(f)
        elif f.number == 7 and f.wire_type == LEN:
            domain = message.text(f)
        elif f.number == 5 and f.wire_type == LEN:  # AttributeProto: may hold subgraphs/tensors
            attribute = message.sub(f)
            for a in attribute.fields():
                if a.wire_type != LEN:
                    continue
                if a.number in (6, 11):  # g, graphs
                    _graph(attribute.sub(a), model)
                elif a.number in (5, 10):  # t, tensors
                    _tensor(attribute.sub(a), model)
    model.node_domains[domain] += 1
    if domain not in STANDARD_DOMAINS | RUNTIME_DOMAINS:
        model.custom_ops.add(f"{domain}::{op_type}")


def _graph(message: Message, model: _Model) -> None:
    for f in message.fields():
        if f.wire_type != LEN:
            continue
        if f.number == 1:
            _node(message.sub(f), model)
        elif f.number == 5:
            model.initializers += 1
            _tensor(message.sub(f), model)
        elif f.number == 15:  # sparse_initializer: values (1) and indices (2) are tensors
            sparse = message.sub(f)
            for s in sparse.fields():
                if s.number in (1, 2) and s.wire_type == LEN:
                    _tensor(sparse.sub(s), model)


def _parse(message: Message) -> _Model:
    model = _Model()
    for f in message.fields():
        if f.number == 1:
            model.ir_version = f.value
        elif f.number == 2 and f.wire_type == LEN:
            model.producer = message.text(f)
        elif f.number == 3 and f.wire_type == LEN:
            model.producer_version = message.text(f)
        elif f.number == 7 and f.wire_type == LEN:
            _graph(message.sub(f), model)
        elif f.number == 8 and f.wire_type == LEN:  # opset_import
            opset = message.sub(f)
            domain, version = "", 0
            for o in opset.fields():
                if o.number == 1 and o.wire_type == LEN:
                    domain = opset.text(o)
                elif o.number == 2:
                    version = o.value
            model.opsets[domain or "ai.onnx"] = version
        elif f.number == 14 and f.wire_type == LEN:  # metadata_props
            entry = message.sub(f)
            key = value = ""
            for e in entry.fields():
                if e.number == 1 and e.wire_type == LEN:
                    key = entry.text(e)
                elif e.number == 2 and e.wire_type == LEN:
                    value = entry.text(e, 4096)
            if len(model.metadata) < 64:
                model.metadata[key] = value
        elif f.number == 25 and f.wire_type == LEN:  # functions: model-local operators
            function = message.sub(f)
            for fn in function.fields():
                if fn.number == 10 and fn.wire_type == LEN:
                    model.function_domains.add(function.text(fn))
    model.custom_ops = {
        op for op in model.custom_ops if op.split("::", 1)[0] not in model.function_domains
    }
    return model


class ONNXHandler:
    name = "onnx"
    version = "1"
    kinds = frozenset({"model.onnx"})

    def detect(self, artifact: ArtifactView) -> Detection | None:
        head = artifact.head(2)
        if name_of(artifact.ref).lower().endswith(".onnx") and head[:1] == b"\x08":
            return Detection("model.onnx", 80)
        return None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        subject = Subject.of_artifact(artifact.ref)
        try:
            with artifact.open() as stream:
                model = _parse(Message.of_stream(stream, artifact.size))
        except (ProtobufError, OSError) as exc:
            ctx.recorder.fail(
                "model.weights.malformed",
                subject,
                tool=TOOL,
                detail={"format": "onnx", "error": str(exc)},
            )
            return Inspection(kind="model.onnx", metadata={"onnx": {"error": str(exc)}})
        ctx.recorder.passed("model.weights.malformed")

        if model.custom_ops:
            ctx.recorder.fail(
                "model.onnx.custom-op",
                subject,
                tool=TOOL,
                detail={"operators": sorted(model.custom_ops)[:100]},
            )
        else:
            ctx.recorder.passed("model.onnx.custom-op")
        claims = [claim(artifact, "onnx", {"format": "onnx"}, root=artifact.ref)]
        claims += self._external(artifact, model, ctx)

        summary = {
            "irVersion": model.ir_version,
            "producer": model.producer,
            "producerVersion": model.producer_version,
            "opsets": model.opsets,
            "nodes": model.nodes,
            "initializers": model.initializers,
            "domains": dict(sorted(model.node_domains.items())),
            "runtimeSpecificOps": sum(model.node_domains[d] for d in RUNTIME_DOMAINS),
            "externalTensors": len(model.external),
            "metadata": model.metadata,
        }
        return Inspection(kind="model.onnx", metadata={"onnx": summary}, claims=tuple(claims))

    def _external(self, artifact: ArtifactView, model: _Model, ctx: Context) -> list[UnitClaim]:
        claims: list[UnitClaim] = []
        sizes: dict[str, int] = {}
        subject = Subject.of_artifact(artifact.ref)
        for entry in model.external:
            location = str(entry.get("location", ""))
            locator = f"tensor {entry.get('tensor')}"
            if not is_bundle_path(location):
                ctx.recorder.fail(
                    "model.package.path-escape",
                    Subject.of_artifact(artifact.ref, locator=locator),
                    tool=TOOL,
                    detail={"location": location},
                    discriminator=location,
                )
                continue
            if location not in sizes:
                target = artifact.resolve(location)
                if target is None:
                    if artifact.ref.nested:
                        ctx.recorder.not_assessed(
                            ("model.package.file-missing",),
                            subject,
                            tool=TOOL,
                            reason="external data of a model inside an archive is not resolved",
                        )
                    else:
                        ctx.recorder.fail(
                            "model.package.file-missing",
                            subject,
                            tool=TOOL,
                            detail={"file": location, "role": "external-data"},
                            discriminator=location,
                        )
                    sizes[location] = -1
                    continue
                sizes[location] = target.size
                claims.append(claim(target, "external-data", root=artifact.ref))
                ctx.recorder.passed("model.package.file-missing")
            size = sizes[location]
            if size < 0:
                continue
            offset_text, length = str(entry.get("offset") or "0"), entry.get("length")
            offset = int(offset_text) if offset_text.isdigit() else 0
            if isinstance(length, str) and length.isdigit() and offset + int(length) > size:
                ctx.recorder.fail(
                    "model.weights.malformed",
                    Subject.of_artifact(artifact.ref, locator=locator),
                    tool=TOOL,
                    detail={
                        "format": "onnx",
                        "error": f"external data {location} is {size} bytes; tensor needs "
                        f"bytes {offset} to {offset + int(length)}",
                    },
                    discriminator=f"{location}:{offset}",
                )
        return claims
