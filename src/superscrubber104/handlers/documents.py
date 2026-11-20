"""Documents that can run code or fetch content when they are opened.

* Office Open XML (``.docx``, ``.xlsm``, ``.pptx``, ...): VBA projects, ActiveX controls,
  embedded OLE objects, and relationships to external templates or objects (remote template
  injection).
* Legacy Office (OLE2 ``.doc``, ``.xls``, ``.ppt``): VBA storage and embedded packages.
* PDF: JavaScript, launch actions, embedded files, rich media, XFA forms, form submission. Names
  are decoded (``/J#61vaScript``) and compressed object streams are opened, which is where
  modern PDFs keep their dictionaries.
* RTF: embedded OLE objects (the usual carrier for equation-editor exploits).
* SVG: scripts and event handlers.

This is a static look for the constructs that carry active content, not a malware verdict.
"""

import re
import zipfile
import zlib
from collections.abc import Callable, Iterator
from typing import ClassVar

from superscrubber104 import __version__
from superscrubber104.archive import ARCHIVE_ERRORS
from superscrubber104.core.interfaces import ArtifactView, Context, Detection, Inspection
from superscrubber104.core.model import Severity, Subject, ToolRef
from superscrubber104.handlers.common import name_of

TOOL = ToolRef("superscrubber104.documents", __version__)
_OOXML = frozenset(
    {
        "docx", "docm", "dotx", "dotm", "xlsx", "xlsm", "xlsb", "xltx", "xltm", "xlam", "pptx",
        "pptm", "potx", "potm", "ppsx", "ppsm", "ppam",
    }
)  # fmt: skip
_OLE = frozenset(["doc", "dot", "xls", "xlt", "xla", "ppt", "pot", "pps"])
_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_PDF_LIMIT = 512 << 20
_INFLATE_LIMIT = 16 << 20
_PDF_NAMES = {
    b"JavaScript": ("javascript", Severity.HIGH),
    b"JS": ("javascript", Severity.HIGH),
    b"Launch": ("launch action", Severity.HIGH),
    b"EmbeddedFile": ("embedded file", Severity.MEDIUM),
    b"RichMedia": ("rich media", Severity.MEDIUM),
    b"XFA": ("XFA form", Severity.MEDIUM),
    b"SubmitForm": ("form submission", Severity.MEDIUM),
    b"ImportData": ("data import", Severity.MEDIUM),
    b"GoToE": ("go to embedded file", Severity.MEDIUM),
}
_PDF_NAME = re.compile(rb"/([A-Za-z0-9#]{2,40})")
_HEX = re.compile(rb"#([0-9A-Fa-f]{2})")
_STREAM = re.compile(rb"stream\r?\n")


def _utf16(text: str) -> bytes:
    return text.encode("utf-16-le")


def _extension(view: ArtifactView) -> str:
    name = name_of(view.ref).lower()
    return name.rsplit(".", 1)[-1] if "." in name else ""


def _chunks(view: ArtifactView, limit: int, size: int = 4 << 20) -> Iterator[bytes]:
    """Overlapping chunks, so a marker split across a boundary is still seen."""
    tail, read = b"", 0
    with view.open() as stream:
        while read < limit:
            block = stream.read(size)
            if not block:
                return
            read += len(block)
            yield tail + block
            tail = block[-256:]


def _ooxml(view: ArtifactView) -> list[tuple[str, Severity]]:
    found: list[tuple[str, Severity]] = []
    with view.open() as stream, zipfile.ZipFile(stream) as archive:
        names = archive.namelist()
        if any(n.lower().endswith("vbaproject.bin") for n in names):
            found.append(("VBA macros", Severity.MEDIUM))
        if any("/activex/" in n.lower() for n in names):
            found.append(("ActiveX controls", Severity.MEDIUM))
        if any("/embeddings/" in n.lower() for n in names):
            found.append(("embedded objects", Severity.MEDIUM))
        for name in names:
            if not name.endswith(".rels"):
                continue
            info = archive.getinfo(name)
            if info.file_size > 1 << 20:
                continue
            rels = archive.read(name).decode("utf-8", "replace")
            for rel in re.findall(r"<Relationship\b[^>]*>", rels):
                if 'TargetMode="External"' not in rel:
                    continue
                kind = re.search(r'Type="[^"]*/([A-Za-z]+)"', rel)
                kind_name = kind.group(1) if kind else "unknown"
                if kind_name in ("attachedTemplate", "oleObject", "frame", "subDocument"):
                    found.append((f"external {kind_name}", Severity.HIGH))
    return found


def _ole(view: ArtifactView) -> list[tuple[str, Severity]]:
    markers = {
        _utf16("_VBA_PROJECT"): ("VBA macros", Severity.MEDIUM),
        _utf16("Macros"): ("VBA macros", Severity.MEDIUM),
        _utf16("\x01Ole10Native"): ("embedded package", Severity.HIGH),
        _utf16("ObjectPool"): ("embedded objects", Severity.MEDIUM),
    }
    found: dict[str, Severity] = {}
    for chunk in _chunks(view, 256 << 20):
        for marker, (what, severity) in markers.items():
            if marker in chunk:
                found[what] = severity
    return list(found.items())


def _pdf_names(data: bytes, found: dict[str, Severity]) -> None:
    for match in _PDF_NAME.finditer(data):
        name = _HEX.sub(lambda m: bytes([int(m.group(1), 16)]), match.group(1))
        if name in _PDF_NAMES:
            what, severity = _PDF_NAMES[name]
            found[what] = severity


def _pdf(view: ArtifactView) -> list[tuple[str, Severity]]:
    found: dict[str, Severity] = {}
    inflated = 0
    for chunk in _chunks(view, _PDF_LIMIT):
        _pdf_names(chunk, found)
        for match in _STREAM.finditer(chunk):
            if b"/ObjStm" not in chunk[max(0, match.start() - 400) : match.start()]:
                continue
            body = chunk[match.end() : match.end() + (8 << 20)]
            try:
                decoder = zlib.decompressobj()
                data = decoder.decompress(body, _INFLATE_LIMIT)
            except zlib.error:
                continue
            inflated += len(data)
            _pdf_names(data, found)
            if inflated > 256 << 20:
                break
    return list(found.items())


def _rtf(view: ArtifactView) -> list[tuple[str, Severity]]:
    for chunk in _chunks(view, 256 << 20):
        if re.search(rb"\\obj(?:data|emb|link|autlink|update)\b", chunk):
            return [("embedded OLE object", Severity.HIGH)]
    return []


def _svg(view: ArtifactView) -> list[tuple[str, Severity]]:
    for chunk in _chunks(view, 64 << 20):
        if re.search(rb"(?i)<script\b|\son[a-z]+\s*=|javascript:", chunk):
            return [("script", Severity.MEDIUM)]
    return []


def _format(view: ArtifactView) -> str | None:
    head = view.head(1024)
    extension = _extension(view)
    if head.startswith(b"PK\x03\x04") and extension in _OOXML:
        return "ooxml"
    if head.startswith(_OLE_MAGIC) and extension in _OLE:
        return "ole"
    if head.startswith(b"%PDF-"):
        return "pdf"
    if head.startswith(b"{\\rt"):
        return "rtf"
    if extension == "svg" and b"<svg" in head:
        return "svg"
    return None


class DocumentHandler:
    name = "documents"
    version = "1"
    kinds = frozenset(
        {"document.office", "document.office-legacy", "document.pdf", "document.rtf", "image.svg"}
    )
    _KINDS: ClassVar[dict[str, str]] = {
        "ooxml": "document.office",
        "ole": "document.office-legacy",
        "pdf": "document.pdf",
        "rtf": "document.rtf",
        "svg": "image.svg",
    }
    _READERS: ClassVar[dict[str, Callable[[ArtifactView], list[tuple[str, Severity]]]]] = {
        "ooxml": _ooxml,
        "ole": _ole,
        "pdf": _pdf,
        "rtf": _rtf,
        "svg": _svg,
    }

    def detect(self, artifact: ArtifactView) -> Detection | None:
        fmt = _format(artifact)
        return Detection(self._KINDS[fmt], 70) if fmt else None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        fmt = _format(artifact)
        assert fmt is not None  # noqa: S101 - only called after detect()
        try:
            found = self._READERS[fmt](artifact)
        except (*ARCHIVE_ERRORS, KeyError) as exc:
            ctx.recorder.not_assessed(
                ("document.active-content",),
                Subject.of_artifact(artifact.ref),
                tool=TOOL,
                reason=f"the document could not be read: {exc}"[:300],
            )
            return Inspection(kind=self._KINDS[fmt])
        unique = dict(found)
        if unique:
            worst = max(unique.values(), key=lambda s: s.rank)
            ctx.recorder.fail(
                "document.active-content",
                Subject.of_artifact(artifact.ref),
                tool=TOOL,
                detail={"format": fmt, "found": sorted(unique)},
                attributes={"format": fmt},
                severity=worst,
            )
        else:
            ctx.recorder.passed("document.active-content")
        return Inspection(
            kind=self._KINDS[fmt], metadata={"document": {"activeContent": sorted(unique)}}
        )
