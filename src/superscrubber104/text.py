"""Text inspection shared by handlers: invisible characters and instructions aimed at models.

Prompt injection is a data-borne attack that no traditional scanner sees: text written for a
model, hidden in content the model will read (a tool description, a skill, an instructions file,
a document destined for a RAG corpus). The patterns below are the well-known, public shapes of
it. They are heuristics: they find the common forms, not every possible phrasing, and the finding
says what matched so a reviewer can judge.
"""

import re
from dataclasses import dataclass

# Zero-width and directional marks, bidi embeddings and overrides, invisible operators, bidi
# isolates, the byte-order mark, and Unicode tag characters. Built from code points so this
# source file itself contains no invisible characters.
_INVISIBLE_RANGES = (
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x2064),
    (0x2066, 0x2069),
    (0xFEFF, 0xFEFF),
    (0xE0000, 0xE007F),
)
INVISIBLE = re.compile("[" + "".join(f"{chr(a)}-{chr(b)}" for a, b in _INVISIBLE_RANGES) + "]")

_INJECTION = (
    (
        re.compile(
            r"\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}?\b(?:previous|prior|above"
            r"|earlier|all|any|other|system|developer)\b[^.\n]{0,30}?\b(?:instructions?|prompts?"
            r"|rules|guidelines|directions|guardrails)\b",
            re.IGNORECASE,
        ),
        "instruction override",
    ),
    (
        re.compile(r"\byou are now\b|\bnew (?:system )?instructions?\s*:", re.IGNORECASE),
        "role reassignment",
    ),
    (
        re.compile(r"<\s*/?\s*(?:important|system|instructions?|admin|secret)\s*>", re.IGNORECASE),
        "pseudo-markup aimed at the model",
    ),
    (
        re.compile(
            r"\b(?:do not|don't|never)\s+(?:tell|inform|mention|reveal|show|alert)\b[^.\n]{0,40}?"
            r"\b(?:the )?(?:user|human|operator|developer)\b",
            re.IGNORECASE,
        ),
        "concealment from the user",
    ),
    (
        re.compile(
            r"\b(?:read|cat|open|send|upload|post|exfiltrate|include|attach|copy)\b[^\n]{0,60}?"
            r"(?:~/\.ssh|id_rsa|id_ed25519|\.aws/credentials|\.netrc|/etc/passwd|/etc/shadow"
            r"|\.kube/config|mcp\.json|\.env\b|credentials\.json|private[_ ]key)",
            re.IGNORECASE,
        ),
        "request for secrets or credentials",
    ),
    (
        re.compile(
            r"\b(?:before|after|whenever|every time)\s+(?:you\s+)?(?:use|call|run|invoke)\s+"
            r"(?:this|any|the\s+\w+)\s+tool\b[^.\n]{0,80}?\b(?:must|always|first)\b",
            re.IGNORECASE,
        ),
        "tool-use precondition",
    ),
)


@dataclass(frozen=True, slots=True)
class TextReport:
    injections: tuple[tuple[str, str], ...]  # (reason, excerpt)
    invisible: tuple[str, ...]  # code points, e.g. "U+200B"


def invisible_characters(text: str) -> tuple[str, ...]:
    return tuple(sorted({f"U+{ord(c):04X}" for c in INVISIBLE.findall(text)}))


def excerpt(text: str, start: int, end: int, margin: int = 30) -> str:
    snippet = text[max(start - margin, 0) : end + margin]
    return INVISIBLE.sub(lambda m: f"<U+{ord(m.group()):04X}>", " ".join(snippet.split()))


def scan_text(text: str) -> TextReport:
    found = []
    for pattern, reason in _INJECTION:
        match = pattern.search(text)
        if match:
            found.append((reason, excerpt(text, match.start(), match.end())))
    return TextReport(tuple(found), invisible_characters(text))
