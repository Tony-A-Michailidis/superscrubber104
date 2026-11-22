"""``superscrubber104 request init | show``: write a transfer request, and read one back.

``init`` writes a commented, valid skeleton. Given the delivery, it declares one content entry per
top-level directory, and one for the files at the top. Nothing is guessed: a ``unit`` line is a
promise that a unit of that kind forms there (``pack`` checks it), so the operator adds it.

``show`` validates a request and prints it. Given the delivery, it shows what each entry covers
and lists the files no entry declares, which is what ``pack`` will judge
(``request.artifact.undeclared``).
"""

import json
import os
from dataclasses import dataclass
from pathlib import Path

from superscrubber104.core.model import API_VERSION
from superscrubber104.core.request import TransferRequest, parse_request

_UNDECLARED_SHOWN = 20


def _q(value: str) -> str:
    """A YAML scalar that means exactly ``value`` (JSON strings are YAML)."""
    return json.dumps(value, ensure_ascii=False)


def _files(root: Path) -> list[str]:
    """Every file under ``root``, as a delivery-relative POSIX path. Links are not followed."""
    out = []
    for directory, dirs, names in os.walk(root, followlinks=False):
        dirs.sort()
        for name in sorted(names):
            out.append((Path(directory) / name).relative_to(root).as_posix())
    return out


def _contents(delivery: Path | None) -> list[str]:
    if delivery is None:
        return ["    - name: everything", '      paths: ["**"]']
    lines: list[str] = []
    top_files = []
    for entry in sorted(delivery.iterdir(), key=lambda p: p.name):
        if entry.is_dir() and not entry.is_symlink():
            lines += [f"    - name: {_q(entry.name)}", f"      paths: [{_q(entry.name + '/**')}]"]
        else:
            top_files.append(entry.name)
    if top_files:
        lines += [
            "    - name: top-level-files",
            f"      paths: [{', '.join(_q(n) for n in top_files)}]",
        ]
    return lines or ["    - name: everything", '      paths: ["**"]']


def skeleton(
    *,
    delivery: Path | None = None,
    request_id: str = "TR-0001",
    title: str = "Describe this delivery",
    source: str = "low-side",
    destination: str = "high-side",
    stream: str = "default",
    owner: str = "Delivery owner",
) -> str:
    """A transfer request to edit. It is checked before it is returned."""
    lines = [
        "# Transfer request: what is meant to cross, and who answers for it.",
        "# Schema: docs/design/17-core-models.md. Check it: superscrubber104 request show",
        f"apiVersion: {API_VERSION}",
        "kind: TransferRequest",
        "metadata:",
        f"  id: {_q(request_id)}",
        f"  title: {_q(title)}",
        "spec:",
        '  purpose: "Why this delivery is needed on the other side"',
        "  owner:",
        f"    name: {_q(owner)}",
        "    # contact: owner@example.org",
        "  # The networks it moves between. The receiving side refuses a bundle addressed to",
        "  # another enclave, or from a source its policy does not accept.",
        f"  source: {_q(source)}",
        f"  destination: {_q(destination)}",
        "  direction: low-to-high",
        "  # Bundles in one stream are expected to arrive in the order they were packed.",
        f"  stream: {_q(stream)}",
        "  # Who is expected to approve. Whether an approval counts is decided by the keys the",
        "  # receiving side's policy pins, never by this list.",
        "  approvers: []",
        "  # Files no entry below declares are reported (request.artifact.undeclared).",
        "  allowUndeclared: false",
        "  # One entry per item. Add 'unit: model-package' (or python-environment,",
        "  # knowledge-base, container-image, ...) to require that such a unit forms under the",
        "  # paths, and 'upstream:' to name where it came from.",
        "  contents:",
        *_contents(delivery),
    ]
    text = "\n".join(lines) + "\n"
    parse_request(text.encode("utf-8"), "request init")  # never write what would not load
    return text


@dataclass(frozen=True)
class Shown:
    text: str
    undeclared: int  # files the request does not declare, when a delivery was given


def show(request: TransferRequest, delivery: Path | None = None) -> Shown:
    lines = [
        f"request   {request.id}: {request.title}",
        f"purpose   {request.purpose}",
        f"owner     {request.owner.name}"
        + (f" <{request.owner.contact}>" if request.owner.contact else ""),
        f"transfer  {request.source} -> {request.destination} ({request.direction.value}), "
        f"stream {request.stream}, profile {request.profile.value}",
        "approvers "
        + (
            ", ".join(f"{a.name} ({a.role})" for a in request.approvers)
            if request.approvers
            else "none named"
        ),
        f"undeclared files {'allowed' if request.allow_undeclared else 'reported'}",
        f"digest    {request.digest}",
        "",
        f"contents ({len(request.contents)}):",
    ]
    files = _files(delivery) if delivery is not None else None
    for entry in request.contents:
        unit = f"  unit {entry.unit.value}" if entry.unit else ""
        covered = (
            f"  [{sum(1 for f in files if entry.covers(f))} files]" if files is not None else ""
        )
        lines.append(f"  {entry.name}{unit}{covered}")
        lines.append(f"    paths    {', '.join(entry.paths)}")
        if entry.upstream:
            up = entry.upstream
            where = " @ ".join(x for x in (up.reference, up.revision or up.digest) if x)
            lines.append(f"    upstream {up.type}: {where}")
    undeclared = [f for f in files if not request.entries_for(f)] if files is not None else []
    if files is not None:
        lines += ["", f"delivery  {len(files)} files, {len(undeclared)} not declared"]
        lines += [f"  undeclared: {f}" for f in undeclared[:_UNDECLARED_SHOWN]]
        if len(undeclared) > _UNDECLARED_SHOWN:
            lines.append(f"  ... and {len(undeclared) - _UNDECLARED_SHOWN} more")
    return Shown("\n".join(lines), 0 if request.allow_undeclared else len(undeclared))
