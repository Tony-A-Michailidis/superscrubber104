"""Handlers for formats that can run code when loaded: pickle and everything built on it.

Covers bare pickles, joblib files, legacy PyTorch files (a sequence of pickles followed by raw
storage), PyTorch zip checkpoints and TorchScript archives (a zip around ``data.pkl``) and NumPy
arrays of Python objects (a pickle after an ``.npy`` header). Every pickle stream is analysed
statically by ``superscrubber104.formats.pickle_scan``; nothing is ever unpickled.

Findings:

* ``model.format.code-capable`` once per file a user would load, recommending safetensors;
* ``model.pickle.dangerous-import`` / ``model.pickle.unknown-import`` for what the stream imports;
* ``model.pickle.malformed`` when the stream cannot be analysed to the end, since a parser that
  gives up early is exactly what a crafted file aims for.
"""

import pickle
import posixpath
import re
import zipfile
from typing import IO

from superscrubber104.core.interfaces import ArtifactView, Context, Detection, Inspection
from superscrubber104.core.model import Subject, UnitClaim
from superscrubber104.formats import pickle_scan
from superscrubber104.handlers.ai.common import SHARD, TOOL, claim, name_of
from superscrubber104.handlers.ai.weights import shard_facts, weight_role

# .ot: TorchScript saved through libtorch bindings (tch, rust-bert).
TORCH_SUFFIXES = (".pt", ".pth", ".bin", ".ckpt", ".pt2", ".ptl", ".tar", ".ot")
_PICKLE_SUFFIXES = (".pkl", ".pickle", ".joblib", ".sav", ".p")
# The first pickle of a legacy torch.save() file is this magic number.
LEGACY_TORCH_MAGIC = pickle.dumps(0x1950A86A20F9469CFC6C, protocol=2)[:-1]
_ZLIB = (b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda")
_IMPORT_RULES = ("model.pickle.dangerous-import", "model.pickle.unknown-import")
_REMEDIATION = (
    "Loading this file runs code. Convert weights to safetensors in an isolated environment "
    "before transfer; for other data, use a data-only format or confirm what loads it."
)


def _is_pickle_start(head: bytes) -> bool:
    return (
        len(head) >= 3
        and head[0] == 0x80
        and head[1] in (2, 3, 4, 5)
        and head[2] in pickle_scan._OPCODES
    )


def _code_capable(ctx: Context, view: ArtifactView, fmt: str) -> None:
    ctx.recorder.fail(
        "model.format.code-capable",
        Subject.of_artifact(view.ref),
        tool=TOOL,
        detail={"format": fmt, "remediation": _REMEDIATION},
        attributes={"format": fmt},
    )


def _inside_torch_archive(view: ArtifactView) -> bool:
    """A data.pkl inside a PyTorch zip: the zip itself carries the code-capable finding."""
    if not view.ref.member:
        return False
    outer = (view.ref.path, *view.ref.member[:-1])[-1]
    return outer.lower().endswith(TORCH_SUFFIXES) and name_of(view.ref).endswith(
        (".pkl", ".debug_pkl")
    )


def scan_and_report(
    ctx: Context, view: ArtifactView, stream: IO[bytes], size: int
) -> pickle_scan.PickleScan:
    """Scan one pickle stream and record what it imports."""
    result = pickle_scan.scan(stream, size=size)
    allowed = [
        str(entry)
        for entry in ctx.policy.allowlists.get("pickle-globals", _EMPTY).entries
        if isinstance(entry, str)
    ]
    verdicts: dict[str, list[str]] = {"dangerous": [], "unknown": [], "safe": []}
    # TorchScript's own references are expected inside a torch archive, which carries the
    # code-capable finding for the code it holds.
    torchscript = _inside_torch_archive(view)
    for module, attr in result.globals:
        verdict = pickle_scan.classify(module, attr, allowed, torchscript=torchscript)
        verdicts[verdict].append(f"{module}.{attr}")
    subject = Subject.of_artifact(view.ref)
    if verdicts["dangerous"]:
        ctx.recorder.fail(
            "model.pickle.dangerous-import",
            subject,
            tool=TOOL,
            detail={"imports": verdicts["dangerous"][:50]},
        )
    else:
        ctx.recorder.passed("model.pickle.dangerous-import")
    if verdicts["unknown"] or result.dynamic_globals:
        ctx.recorder.fail(
            "model.pickle.unknown-import",
            subject,
            tool=TOOL,
            detail={
                "imports": verdicts["unknown"][:50],
                "unresolvedImports": result.dynamic_globals,
                "hint": "add trusted classes to the policy's 'pickle-globals' allowlist",
            },
        )
    else:
        ctx.recorder.passed("model.pickle.unknown-import")

    if result.error is not None:
        joblib = any(module.startswith("joblib.") for module, _ in result.globals)
        if joblib:
            ctx.recorder.not_assessed(
                _IMPORT_RULES,
                Subject.of_artifact(view.ref, locator=f"offset {result.error_offset}"),
                tool=TOOL,
                reason="joblib stores array data inside the pickle stream; the stream after "
                "the first array was not analysed",
            )
        else:
            ctx.recorder.fail(
                "model.pickle.malformed",
                subject,
                tool=TOOL,
                detail={"error": result.error, "offset": result.error_offset},
            )
    else:
        ctx.recorder.passed("model.pickle.malformed")
    return result


class _Empty:
    entries: tuple[object, ...] = ()


_EMPTY = _Empty()


def _summary(result: pickle_scan.PickleScan) -> dict[str, object]:
    return {
        "protocol": result.protocol,
        "pickles": result.pickles,
        "opcodes": result.opcodes,
        "calls": result.calls,
        "persistentIds": result.persistent_ids,
        "imports": [f"{m}.{n}" for m, n in result.globals][:200],
        "complete": result.complete,
    }


def _weights_claim(view: ArtifactView, fmt: str) -> tuple[UnitClaim, ...]:
    """PyTorch weight files in a model directory belong to its package."""
    name = name_of(view.ref)
    # rust_model.ot: the same weights for rust-bert, saved by tch (libtorch) as TorchScript
    stem_ok = name.startswith(
        ("pytorch_model", "adapter_model", "model", "consolidated", "rust_model")
    )
    if not (stem_ok or SHARD.match(name) or name.endswith((".pt", ".pth", ".ckpt"))):
        return ()
    facts = {"format": fmt, "file": name, **shard_facts(name)}
    return (claim(view, weight_role(name), facts),)


class PickleHandler:
    name = "pickle"
    version = "1"
    kinds = frozenset({"model.pickle", "model.pytorch.legacy", "model.joblib"})

    def detect(self, artifact: ArtifactView) -> Detection | None:
        head = artifact.head(64)
        name = name_of(artifact.ref).lower()
        if _is_pickle_start(head):
            return Detection("model.pickle", 90)
        if name.endswith(_PICKLE_SUFFIXES) and (head[:2] in _ZLIB or head[:2] == b"ZF"):
            return Detection("model.joblib", 70)
        if name.endswith(_PICKLE_SUFFIXES) and head[:1] in (b"(", b"}", b"]", b"c", b"N", b"I"):
            return Detection("model.pickle", 60)  # protocol 0 or 1: no header to recognise
        return None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        head = artifact.head(64)
        name = name_of(artifact.ref).lower()
        if head.startswith(LEGACY_TORCH_MAGIC):
            kind, fmt = "model.pytorch.legacy", "pytorch-legacy"
        elif name.endswith(".joblib"):
            kind, fmt = "model.joblib", "joblib"
        else:
            kind, fmt = "model.pickle", "pickle"

        if head[:2] in _ZLIB or head[:2] == b"ZF":
            _code_capable(ctx, artifact, "joblib-compressed")
            ctx.recorder.not_assessed(
                (*_IMPORT_RULES, "model.pickle.malformed"),
                Subject.of_artifact(artifact.ref),
                tool=TOOL,
                reason="compressed joblib file; decompression is not supported, so the pickle "
                "inside was not analysed",
            )
            return Inspection(kind="model.joblib", metadata={"pickle": {"compressed": True}})

        if not _inside_torch_archive(artifact):
            _code_capable(ctx, artifact, fmt)
        with artifact.open() as stream:
            result = scan_and_report(ctx, artifact, stream, artifact.size)
        claims = _weights_claim(artifact, fmt) if kind != "model.joblib" else ()
        return Inspection(
            kind=kind,
            media_type="application/x-python-pickle",
            metadata={"pickle": {**_summary(result), "trailingData": result.trailing_bytes}},
            claims=claims,
        )


class TorchZipHandler:
    """PyTorch zip checkpoints and TorchScript archives.

    Only the zip's central directory is read here; ``data.pkl`` and friends are members, so the
    archive walk hands them to the pickle handler.
    """

    name = "pytorch-zip"
    version = "1"
    kinds = frozenset({"model.pytorch.zip", "model.torchscript", "model.pytorch.export"})

    def detect(self, artifact: ArtifactView) -> Detection | None:
        name = name_of(artifact.ref).lower()
        if artifact.head(4) == b"PK\x03\x04" and name.endswith(TORCH_SUFFIXES):
            return Detection("model.pytorch.zip", 80)
        return None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        try:
            with artifact.open() as stream, zipfile.ZipFile(stream) as archive:
                names = archive.namelist()
        except (zipfile.BadZipFile, OSError, ValueError):
            return Inspection(kind="unclassified")  # the archive walk reports corrupt zips
        bases = {posixpath.basename(n) for n in names}
        if any("/code/" in f"/{n}" for n in names) or "constants.pkl" in bases:
            kind, fmt = "model.torchscript", "torchscript"
        elif name_of(artifact.ref).lower().endswith(".pt2") or any(
            n.endswith("serialized_exported_program.json") for n in names
        ):
            kind, fmt = "model.pytorch.export", "pytorch-export"
        elif "data.pkl" in bases:
            kind, fmt = "model.pytorch.zip", "pytorch-zip"
        else:
            return Inspection(kind="unclassified")
        _code_capable(ctx, artifact, fmt)
        records = sum(1 for n in names if re.search(r"/data/\d+$", n))
        return Inspection(
            kind=kind,
            metadata={"pytorch": {"format": fmt, "members": len(names), "storages": records}},
            claims=_weights_claim(artifact, fmt),
        )


_NPY_DESCR = re.compile(
    r"""['"]descr['"]\s*:\s*(?P<descr>'[^']*'|"[^"]*"|\[.*?\]\s*(?=,\s*['"]))""", re.S
)


class NumpyHandler:
    """``.npy`` arrays. Object arrays are pickles after the header and get the pickle checks."""

    name = "numpy"
    version = "1"
    kinds = frozenset({"data.numpy", "data.numpy.object"})

    def detect(self, artifact: ArtifactView) -> Detection | None:
        return Detection("data.numpy", 100) if artifact.head(6) == b"\x93NUMPY" else None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        head = artifact.head(16)
        major = head[6] if len(head) > 6 else 0
        width = 2 if major == 1 else 4
        length = int.from_bytes(head[8 : 8 + width], "little")
        start = 8 + width
        if major not in (1, 2, 3) or length > 1 << 20 or start + length > artifact.size:
            return Inspection(kind="data.numpy", metadata={"numpy": {"error": "invalid header"}})
        with artifact.open() as stream:
            stream.seek(start)
            text = stream.read(length).decode("utf-8" if major == 3 else "latin-1", "replace")
            match = _NPY_DESCR.search(text)
            descr = match["descr"] if match else ""
            objects = "O" in descr.replace("'", " ").replace('"', " ").split() or "|O" in descr
            summary: dict[str, object] = {"descr": descr.strip("'\""), "objects": objects}
            if not objects:
                return Inspection(kind="data.numpy", metadata={"numpy": summary})
            _code_capable(ctx, artifact, "numpy-object-array")
            stream.seek(start + length)
            result = scan_and_report(ctx, artifact, stream, artifact.size)
        return Inspection(
            kind="data.numpy.object",
            metadata={"numpy": summary, "pickle": _summary(result)},
        )
