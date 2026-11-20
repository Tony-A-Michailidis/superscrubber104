"""Static inspection of chat templates.

A chat template is code: it decides exactly what text the model sees around every message, so a
changed template changes behaviour even when the weights are identical. Templates are Jinja for
Hugging Face and GGUF models and Go templates for Ollama. They are never rendered here.

Two things are flagged:

* constructs that legitimate templates do not need and template-injection payloads do: dunder
  attributes, the ``attr`` filter, imports and includes, process and file access names;
* invisible characters (zero-width, bidirectional overrides, Unicode tag characters) that let a
  template carry text a reviewer cannot see.
"""

import hashlib
import re
from dataclasses import dataclass

from superscrubber104.text import invisible_characters

_SUSPICIOUS = (
    (re.compile(r"__[A-Za-z0-9_]+__"), "dunder attribute"),
    (re.compile(r"\|\s*attr\s*\("), "attr filter"),
    (re.compile(r"\{%-?\s*(?:import|from|include|extends)\b"), "template import or include"),
    # Not plain "system": every template compares message roles with 'system'.
    (
        re.compile(r"\b(?:popen|subprocess|os\.system|eval|exec|import_module|builtins)\b"),
        "code execution name",
    ),
    (re.compile(r"\b(?:open|read_text|write_text|listdir)\s*\("), "file access"),
    (re.compile(r"\bself\s*\.\s*_"), "private template attribute"),
    (
        re.compile(r"\{\{\s*(?:config|request|cycler|joiner|lipsum)\s*[.|\[]"),
        "template global access",
    ),
)


@dataclass(frozen=True, slots=True)
class TemplateReport:
    sha256: str
    length: int
    suspicious: tuple[tuple[str, str], ...]  # (reason, excerpt)
    invisible: tuple[str, ...]  # code points, e.g. "U+200B"


def inspect_template(text: str) -> TemplateReport:
    suspicious = []
    for pattern, reason in _SUSPICIOUS:
        match = pattern.search(text)
        if match:
            start = max(match.start() - 20, 0)
            suspicious.append((reason, text[start : match.end() + 20]))
    invisible = invisible_characters(text)
    return TemplateReport(
        sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        length=len(text),
        suspicious=tuple(suspicious),
        invisible=invisible,
    )
