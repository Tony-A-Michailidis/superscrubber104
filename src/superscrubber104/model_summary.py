"""Plain-text rendering of model package records."""

from collections.abc import Iterable

from superscrubber104.core.canonical import JSON
from superscrubber104.core.model import Unit, UnitKind


def _get(data: JSON, *path: str) -> JSON:
    for key in path:
        if not isinstance(data, dict):
            return None
        data = data.get(key)
    return data


def _count(value: JSON) -> str:
    if type(value) is not int:
        return "?"
    for unit, size in (("B", 10**9), ("M", 10**6), ("K", 10**3)):
        if value >= size:
            return f"{value / size:.1f}{unit}"
    return str(value)


def render_package(unit: Unit) -> str:
    a = dict(unit.attributes)
    lines = [f"model package  {unit.root.display}  ({unit.name})"]

    def row(label: str, text: str | None) -> None:
        if text:
            lines.append(f"  {label:<14} {text}")

    identity = a.get("identity")
    architecture = _get(identity, "architecture")
    parameters = _get(identity, "parameters")
    row("architecture", ", ".join(x for x in (
        str(architecture) if architecture else None,
        f"{_count(parameters)} parameters" if parameters else None,
    ) if x) or None)  # fmt: skip

    weights = a.get("weights")
    formats = _get(weights, "formats")
    files = _get(weights, "files")
    dtypes = _get(weights, "dtypes")
    quantization = _get(weights, "quantization")
    parts = [
        "/".join(str(f) for f in formats) if isinstance(formats, list) else None,
        f"{len(files)} file(s)" if isinstance(files, list) else None,
        str(quantization) if quantization else None,
        ", ".join(f"{k} x{v}" for k, v in dtypes.items()) if isinstance(dtypes, dict) else None,
    ]
    row("weights", ", ".join(p for p in parts if p))

    tokenizer = a.get("tokenizer")
    if isinstance(tokenizer, dict):
        kind = tokenizer.get("type") or "files present"
        row("tokenizer", f"{kind}, {tokenizer.get('tokens') or '?'} tokens")
    templates = a.get("chatTemplates")
    for template in templates if isinstance(templates, list) else []:
        if isinstance(template, dict):
            digest = str(template.get("sha256"))[:16]
            row("chat template", f"sha256:{digest}... ({template.get('source')})")

    licence = a.get("licence")
    if isinstance(licence, dict):
        gated = " (gated)" if licence.get("gated") else ""
        row("licence", f"{licence.get('expression') or 'not identified'}{gated}")
    remote = a.get("remoteCode")
    if isinstance(remote, dict) and remote.get("required"):
        auto_map = remote.get("autoMap")
        names = ", ".join(str(x) for x in auto_map) if isinstance(auto_map, list) else ""
        row("remote code", f"REQUIRED: {names}")
    adapter = a.get("adapter")
    if isinstance(adapter, dict):
        base, rank = adapter.get("baseModel"), adapter.get("rank")
        row("adapter", f"{adapter.get('type')} on {base}, rank {rank}")
    embedding = a.get("embedding")
    if isinstance(embedding, dict):
        dimension, pooling = embedding.get("dimension"), embedding.get("pooling")
        normalised = bool(embedding.get("normalize"))
        row("embedding", f"dimension {dimension}, pooling {pooling}, normalised {normalised}")

    provenance = a.get("provenance")
    if isinstance(provenance, dict):
        upstream = provenance.get("upstream")
        where = ""
        if isinstance(upstream, dict):
            where = f" {upstream.get('reference')}" + (
                f"@{upstream.get('revision')}" if upstream.get("revision") else ""
            )
        method = provenance.get("method") or "none recorded"
        verified = provenance.get("verifiedFiles") or 0
        row("provenance", f"{method}{where}, {verified} file(s) verified")
    for need in unit.requires:
        satisfied = f"satisfied by {need.satisfied_by}" if need.satisfied_by else "NOT IN DELIVERY"
        row("requires", f"{need.relation} {need.name} ({satisfied})")
    row("members", str(len(unit.members)))
    return "\n".join(lines)


def render_packages(units: Iterable[Unit]) -> str:
    packages = [u for u in units if u.kind is UnitKind.MODEL_PACKAGE]
    if not packages:
        return "no model packages found"
    return "\n\n".join(render_package(u) for u in packages)
