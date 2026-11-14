"""Text of documents, as a retrieval pipeline would read it, and the tricks that hide text.

A knowledge-base loader extracts text and hands it to a model; a human reviewer looks at the
rendered page. What is in the first but not the second is where a planted instruction hides:
CSS that hides an element, Word's hidden-text and white-text runs, PDF text in the invisible
rendering mode, RTF's hidden-text control word. This module returns the text and names those
constructs. It is a static reader: nothing is rendered, no macro or script is run, and every
read is bounded.
"""

import html
import re
import zipfile
import zlib
from dataclasses import dataclass, field
from typing import BinaryIO

TEXT_LIMIT = 16 << 20  # characters returned per document
_READ_LIMIT = 64 << 20
_INFLATE_LIMIT = 32 << 20

PLAIN = frozenset(
    {".txt", ".text", ".md", ".markdown", ".rst", ".adoc", ".json", ".jsonl", ".ndjson", ".csv",
     ".tsv", ".yaml", ".yml", ".log", ".tex"}
)  # fmt: skip
MARKUP = frozenset({".html", ".htm", ".xhtml", ".xml", ".svg"})
OFFICE = frozenset({".docx", ".docm", ".pptx", ".pptm", ".xlsx", ".xlsm", ".odt", ".odp", ".ods"})
OTHER = frozenset({".pdf", ".rtf"})
DOCUMENTS = PLAIN | MARKUP | OFFICE | OTHER

_HIDDEN_CSS = re.compile(
    r"(?i)(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|pt|em)?\s*[;\"']"
    r"|opacity\s*:\s*0(?:\.0+)?\s*[;\"']|(?<![-\w])color\s*:\s*(?:#fff(?:fff)?|white)\b"
    r"|left\s*:\s*-\d{3,}px)"
)
_OFFICE_PARTS = re.compile(
    r"^(word/(document|header\d*|footer\d*|footnotes|endnotes|comments)\.xml"
    r"|ppt/(slides/slide|notesSlides/notesSlide)\d+\.xml|xl/sharedStrings\.xml|content\.xml)$"
)
_BREAK = re.compile(r"</w:p>|</a:p>|<w:br\s*/>|<w:tab\s*/>|</text:p>|</si>|</t>")
_TAG = re.compile(r"<[^>]+>")
_PDF_STREAM = re.compile(rb"stream\r?\n")
_PDF_STRING = re.compile(
    rb"\((?:\\.|[^\\()]|\((?:\\.|[^\\()])*\))*\)\s*(?:Tj|'|\")|\[(?:[^\]]*)\]\s*TJ"
)
_PDF_LITERAL = re.compile(rb"\((?:\\.|[^\\()]|\((?:\\.|[^\\()])*\))*\)")
_PDF_TJ_TOKEN = re.compile(rb"\((?:\\.|[^\\()]|\((?:\\.|[^\\()])*\))*\)|-?\d+(?:\.\d+)?")
_PDF_ESCAPES = {b"n": b"\n", b"r": b"\r", b"t": b"\t", b"b": b"\b", b"f": b"\f"}
_RTF_GROUP = re.compile(r"\{\\\*[^{}]*\}")
_RTF_CONTROL = re.compile(r"\\([a-z]+)(-?\d+)? ?|\\'([0-9a-f]{2})|\\([{}\\])")


@dataclass(slots=True)
class Extracted:
    text: str = ""
    hidden: list[str] = field(default_factory=list)  # constructs that hide text from a reader
    problem: str | None = None  # why the text could not be read


def suffix(name: str) -> str:
    lowered = name.lower()
    return lowered[lowered.rfind(".") :] if "." in lowered else ""


def _bounded(stream: BinaryIO) -> bytes:
    return stream.read(_READ_LIMIT)


def _markup(raw: str, out: Extracted) -> None:
    if _HIDDEN_CSS.search(raw):
        out.hidden.append("CSS that hides text")
    out.text = raw  # tags and comments stay: loaders differ in what they keep


def _office(stream: BinaryIO, out: Extracted) -> None:
    parts: list[str] = []
    with zipfile.ZipFile(stream) as archive:
        for info in archive.infolist():
            if not _OFFICE_PARTS.match(info.filename) or info.file_size > _INFLATE_LIMIT:
                continue
            xml = archive.read(info).decode("utf-8", "replace")
            if "<w:vanish/>" in xml or "<w:vanish " in xml:
                out.hidden.append("hidden text (Word vanish)")
            if re.search(r'<w:color w:val="(?:FFFFFF|ffffff)"', xml):
                out.hidden.append("white text")
            if re.search(r'<w:sz w:val="[12]"', xml):
                out.hidden.append("text of one point or less")
            if "comments" in info.filename or "notesSlide" in info.filename:
                out.hidden.append("comments or speaker notes")
            parts.append(html.unescape(_TAG.sub("", _BREAK.sub("\n", xml))))
    out.text = "\n".join(parts)
    out.hidden = sorted(set(out.hidden))


def _pdf_literal(raw: bytes) -> bytes:
    body = raw[1:-1]
    result = bytearray()
    i = 0
    while i < len(body):
        char = body[i : i + 1]
        if char == b"\\" and i + 1 < len(body):
            nxt = body[i + 1 : i + 2]
            if nxt in _PDF_ESCAPES:
                result += _PDF_ESCAPES[nxt]
                i += 2
                continue
            octal = re.match(rb"[0-7]{1,3}", body[i + 1 : i + 4])
            if octal:
                result.append(int(octal.group(0), 8) & 0xFF)
                i += 1 + len(octal.group(0))
                continue
            result += nxt
            i += 2
            continue
        result += char
        i += 1
    return bytes(result)


def _pdf_text(content: bytes) -> list[str]:
    """Text shown by Tj, ', " and TJ. In a TJ array, numbers are kerning: only a wide gap is a
    space, so a word split for kerning ("Intr" -120 "oduction") is joined again."""
    pieces = []
    for match in _PDF_STRING.finditer(content):
        shown = match.group(0)
        if not shown.rstrip().endswith(b"TJ"):
            pieces.append(_pdf_literal(_PDF_LITERAL.findall(shown)[0]).decode("latin-1"))
            continue
        words = []
        for token in _PDF_TJ_TOKEN.finditer(shown):
            if token.group(0).startswith(b"("):
                words.append(_pdf_literal(token.group(0)).decode("latin-1"))
            elif float(token.group(0)) < -200:
                words.append(" ")
        pieces.append("".join(words))
    return pieces


def _pdf(stream: BinaryIO, out: Extracted) -> None:
    data = _bounded(stream)
    if b"/Encrypt" in data:
        out.problem = "the PDF is encrypted"
        return
    pieces: list[str] = []
    inflated = 0
    invisible = False
    for match in _PDF_STREAM.finditer(data):
        body = data[match.end() : match.end() + _INFLATE_LIMIT]
        try:
            content = zlib.decompressobj().decompress(body, _INFLATE_LIMIT)
        except zlib.error:
            end = body.find(b"endstream")
            content = body[: end if end >= 0 else 0]  # an uncompressed stream
        inflated += len(content)
        if b"BT" not in content:
            continue
        if re.search(rb"(?<![\d.])3\s+Tr\b", content):
            invisible = True
        pieces.extend(_pdf_text(content))
        if inflated > _READ_LIMIT:
            break
    if invisible:
        out.hidden.append("PDF text in invisible rendering mode")
    out.text = " ".join(pieces)
    if not out.text.strip():
        out.problem = "no text could be extracted (scanned images, or fonts without a text map)"


def _rtf(raw: str, out: Extracted) -> None:
    if re.search(r"\\v(?![a-z])", raw):
        out.hidden.append("RTF hidden text")

    def replace(match: re.Match[str]) -> str:
        word, hex_char, literal = match.group(1), match.group(3), match.group(4)
        if hex_char:
            return bytes([int(hex_char, 16)]).decode("cp1252", "replace")
        if literal:
            return literal
        return "\n" if word in ("par", "line") else ""

    out.text = _RTF_CONTROL.sub(replace, _RTF_GROUP.sub("", raw)).replace("{", "").replace("}", "")


def extract(name: str, stream: BinaryIO) -> Extracted:
    """Text and hiding constructs of one document; ``problem`` says why there is no text."""
    out = Extracted()
    kind = suffix(name)
    try:
        if kind in OFFICE:
            _office(stream, out)
        elif kind == ".pdf":
            _pdf(stream, out)
        else:
            raw = _bounded(stream).decode("utf-8", "replace")
            if kind == ".rtf":
                _rtf(raw, out)
            elif kind in MARKUP or kind in (".md", ".markdown"):
                _markup(raw, out)
            else:
                out.text = raw
    except (zipfile.BadZipFile, KeyError, OSError, ValueError) as exc:
        out.problem = f"unreadable: {exc}"[:200]
    out.text = out.text[:TEXT_LIMIT]
    return out
