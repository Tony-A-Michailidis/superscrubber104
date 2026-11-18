"""Credentials in any text: source, configs, notebooks, datasets, files inside image layers.

This runs on every text artifact, including archive members, so a key left in a container layer
or a wheel is found as readily as one in the project's own code. Patterns are for credentials
with a recognisable shape (cloud keys, platform tokens, private keys) plus a generic
``password = "..."`` assignment that ignores placeholders and low-entropy values.

The secret itself is never recorded: a finding carries the type, the line and the length. Hits
under test, example and fixture paths are reported at low severity, because packages routinely
ship dummy keys for their own tests.
"""

import math
import re
from collections import Counter, defaultdict
from collections.abc import Iterator
from dataclasses import dataclass

from airlock import __version__
from airlock.core.interfaces import ArtifactView, Context, Detection, Inspection
from airlock.core.model import UNCLASSIFIED, Severity, Subject, ToolRef
from airlock.handlers.common import TEST_CONTEXT, TEST_PATH, full_path

TOOL = ToolRef("airlock.secrets", __version__)
_LIMIT = 256 << 20
_LINE_LIMIT = 1 << 20
H, M = Severity.HIGH, Severity.MEDIUM


@dataclass(frozen=True, slots=True)
class _Kind:
    name: str
    severity: Severity
    pattern: str


_KINDS = (
    _Kind("aws-access-key-id", H, r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    _Kind("github-token", H, r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
    _Kind("github-fine-grained-token", H, r"\bgithub_pat_[A-Za-z0-9_]{60,255}\b"),
    _Kind("gitlab-token", H, r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
    _Kind("slack-token", H, r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"),
    _Kind("slack-webhook", H, r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/\w{16,}"),
    _Kind("anthropic-api-key", H, r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}"),
    _Kind("openai-api-key", H, r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}"),
    _Kind("openai-api-key", H, r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b"),
    _Kind("huggingface-token", H, r"\bhf_[A-Za-z0-9]{34,40}\b"),
    _Kind("google-api-key", H, r"\bAIza[0-9A-Za-z_-]{35}\b"),
    _Kind("stripe-live-key", H, r"\b[rs]k_live_[0-9A-Za-z]{24,}\b"),
    _Kind("npm-token", H, r"\bnpm_[A-Za-z0-9]{36}\b"),
    _Kind("pypi-token", H, r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}"),
    _Kind("azure-storage-key", H, r"\bAccountKey=[A-Za-z0-9+/]{86}=="),
    _Kind("private-key", H, r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY"),
    _Kind("jwt", M, r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{16,}"),
    _Kind(
        "url-credentials",
        M,
        r"\b[a-z][a-z0-9+.-]{1,20}://[^\s/:@'\"<>]{1,64}:(?P<urlpass>[^\s/@'\"<>]{6,128})@[\w.-]+",
    ),
    _Kind(
        "password-assignment",
        M,
        r"(?i:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token"
        r"|client[_-]?secret)\b[\"']?\s*[:=]\s*[\"'](?P<value>[^\"'\s]{8,128})[\"']",
    ),
)
_PATTERN = re.compile("|".join(f"(?P<k{i}>{k.pattern})" for i, k in enumerate(_KINDS)))
# Literals at least one of which every pattern contains, lower-cased. Finding them with
# bytes.find runs at memory speed; only the lines that hold one go through the patterns.
_TRIGGERS = tuple(
    t.encode()
    for t in (
        "akia", "asia", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "glpat-", "xox",
        "hooks.slack", "sk-", "hf_", "aiza", "_live_", "npm_", "pypi-", "accountkey=",
        "private key", "eyj", "://", "passw", "secret", "api_key", "api-key", "apikey",
        "access_token", "access-token", "accesstoken", "auth_token", "auth-token", "authtoken",
    )
)  # fmt: skip
_BLOCK = 8 << 20
_LONG_LINE = 4096
_BEFORE, _AFTER = 160, 640  # window around a trigger in a long line
_PEM_INLINE = re.compile(r"-----(?:\\r)?\\n[A-Za-z0-9+/=]{40,}")  # JSON: "...KEY-----\nMII..."
_PEM_END = " \t\r\n\"'`,;)"  # what may follow a header that stands alone on its line
_PEM_BODY = re.compile(r"^\s*(?:[A-Za-z0-9+/=]{40,}|Proc-Type:|b3BlbnNzaC1rZXktdjE)")
_PLACEHOLDER = re.compile(
    r"(?i)(\$\{|\{\{|%\(|<[a-z_]+>|^\*+$|x{4,}|change.?me|example|placeholder|your[_-]|dummy"
    r"|redacted|secret|password|passw0rd|token|^test|fake|sample|\.\.\.)"
)
# A value that names where the secret is kept (GIT_AUTH_HEADER, as BuildKit's provenance
# records build secrets) is a reference, not a secret.
_VARIABLE_NAME = re.compile(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+")
# Vendors' documented example credentials (AKIAIOSFODNN7EXAMPLE) and obvious dummies.
_EXAMPLE = re.compile(r"(?i)example|x{6,}|0{10,}|dummy|fake|sample|placeholder")


def _entropy(value: str) -> float:
    counts = Counter(value)
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


def _plausible(kind: _Kind, match: re.Match[str]) -> bool:
    """Drop documentation examples, placeholders and low-entropy values."""
    value = match.group("value") or match.group("urlpass")
    if value is None:  # a typed token: only documented examples and dummies are dropped
        return not _EXAMPLE.search(match.group(0))
    return (
        not _PLACEHOLDER.search(value)
        and not _VARIABLE_NAME.fullmatch(value)
        and _entropy(value) >= 3.0
    )


def _blocks(view: ArtifactView) -> Iterator[bytes]:
    """Whole lines, in blocks of about ``_BLOCK`` bytes, up to ``_LIMIT``."""
    carry = b""
    read = 0
    with view.open() as stream:
        while read < _LIMIT:
            chunk = stream.read(_BLOCK)
            if not chunk:
                break
            read += len(chunk)
            data = carry + chunk
            cut = data.rfind(b"\n") + 1
            if cut == 0 and len(data) < _LINE_LIMIT:
                carry = data
                continue
            cut = cut or len(data)
            carry = data[cut:]
            yield data[:cut]
    if carry:
        yield carry


def _is_word(byte: int) -> bool:
    return byte == 0x5F or 0x30 <= byte <= 0x39 or 0x41 <= byte <= 0x5A or 0x61 <= byte <= 0x7A


def _widen(block: bytes, at: int, step: int, limit: int) -> int:
    """Move a window edge out to the end of the word it cuts, so ``\\b`` keeps its meaning."""
    for _ in range(64):
        if at == limit or not _is_word(block[at - 1 if step < 0 else at]):
            break
        at += step
    return at


def _candidates(block: bytes) -> list[tuple[int, int, list[tuple[int, int]]]]:
    """Each line holding a trigger literal: (start, end, windows to search), in order.

    A short line is searched whole. A long one (minified JSON, a data file on one line) is
    searched only around its triggers, so a megabyte line costs what its matches cost.
    """
    low = block.lower()  # ASCII only, so offsets are unchanged
    hits: dict[int, list[int]] = defaultdict(list)
    ends: dict[int, int] = {}
    for literal in _TRIGGERS:
        at = low.find(literal)
        while at != -1:
            if literal == b"://" and low.find(b"@", at, at + 200) == -1:
                at = low.find(literal, at + 3)  # credentials in a URL need user:pass@
                continue
            start = low.rfind(b"\n", 0, at) + 1
            end = ends.get(start)
            if end is None:
                end = low.find(b"\n", at)
                end = len(low) if end == -1 else end
                ends[start] = end
            hits[start].append(at)
            at = low.find(literal, end if end - start <= _LONG_LINE else at + len(literal))
    lines = []
    for start in sorted(hits):
        end = ends[start]
        if end - start <= _LONG_LINE:
            lines.append((start, end, [(start, end)]))
            continue
        windows: list[tuple[int, int]] = []
        for at in sorted(hits[start]):
            low_edge = _widen(block, max(start, at - _BEFORE), -1, start)
            high_edge = _widen(block, min(end, at + _AFTER), 1, end)
            if windows and low_edge <= windows[-1][1]:
                windows[-1] = (windows[-1][0], max(windows[-1][1], high_edge))
            else:
                windows.append((low_edge, high_edge))
        lines.append((start, end, windows))
    return lines


def is_text(head: bytes) -> bool:
    if not head or b"\x00" in head:
        return False
    try:
        head[: max(len(head) - 3, 1)].decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


class SecretsHandler:
    """Runs on every text artifact; never classifies one."""

    name = "secrets"
    version = "1"
    kinds: frozenset[str] = frozenset()

    def detect(self, artifact: ArtifactView) -> Detection | None:
        return Detection(UNCLASSIFIED, 0) if is_text(artifact.head(65536)) else None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        recorder = ctx.recorder
        test_path = bool(TEST_PATH.search(full_path(artifact.ref)))
        found = 0
        pending_key: tuple[int, _Kind] | None = None
        first_line = 1  # line number of the current block's first line
        for block in _blocks(artifact):
            if pending_key is not None:  # a key header ended the previous block
                body = block.lstrip(b"\r\n").split(b"\n", 1)[0].decode("utf-8", "replace")
                if _PEM_BODY.match(body):
                    found += self._record(ctx, artifact, *pending_key, test_path)
                pending_key = None
            counted, number = 0, first_line
            for start, end, windows in _candidates(block):
                number += block.count(b"\n", counted, start)
                counted = start
                header = None
                for low_edge, high_edge in windows:
                    text = block[low_edge:high_edge].decode("utf-8", "replace")
                    found, header = self._line(ctx, artifact, number, text, test_path, found)
                if header is not None:
                    following = block[end + 1 :].lstrip(b"\r\n").split(b"\n", 1)[0]
                    if end >= len(block) - 1:
                        pending_key = (number, header)
                    elif _PEM_BODY.match(following.decode("utf-8", "replace")):
                        found += self._record(ctx, artifact, number, header, test_path)
            first_line += block.count(b"\n")
        if artifact.size > _LIMIT:
            recorder.not_assessed(
                ("secret.detected",),
                Subject.of_artifact(artifact.ref),
                tool=TOOL,
                reason="only the first 256 MiB were searched",
            )
        if not found:
            recorder.passed("secret.detected")
        return Inspection(kind=UNCLASSIFIED)

    def _line(
        self, ctx: Context, view: ArtifactView, number: int, line: str, test_path: bool, found: int
    ) -> tuple[int, _Kind | None]:
        """Record what one line holds. Returns the new count, and a private-key header that
        stands alone on its line (its body, on the next line, decides whether it is a key)."""
        header: _Kind | None = None
        for match in _PATTERN.finditer(line):
            index = int(next(k for k, v in match.groupdict().items() if v and k[0] == "k")[1:])
            kind = _KINDS[index]
            if kind.name == "private-key":
                rest = line[match.end() :]
                if _PEM_INLINE.match(rest):
                    found += self._record(ctx, view, number, kind, test_path)
                elif rest.startswith("-----") and not rest[5:].strip(_PEM_END):
                    header = kind  # only a real key body counts
                continue
            if _plausible(kind, match):
                found += self._record(ctx, view, number, kind, test_path, len(match[0]))
        return found, header

    def _record(
        self,
        ctx: Context,
        view: ArtifactView,
        line: int,
        kind: _Kind,
        test_path: bool,
        length: int | None = None,
    ) -> int:
        detail: dict[str, object] = {"type": kind.name, "line": line}
        if length is not None:
            detail["length"] = length
        if test_path:
            detail["context"] = TEST_CONTEXT
        ctx.recorder.fail(
            "secret.detected",
            Subject.of_artifact(view.ref, locator=f"line {line}"),
            tool=TOOL,
            detail=detail,
            attributes={"type": kind.name},
            severity=Severity.LOW if test_path else kind.severity,
            discriminator=f"{kind.name}:{line}",
        )
        return 1
