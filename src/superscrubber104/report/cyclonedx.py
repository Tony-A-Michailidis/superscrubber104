"""The analysis as a CycloneDX 1.6 SBOM and ML-BOM.

Every component superscrubber104 identified, with its purl, hashes, licences, supplier, upstream
reference, where it occurs in the delivery, and how it was verified. Models are
``machine-learning-model`` components and datasets ``data`` components, so one document covers
software and AI. Components found inside another (packages in an image) are nested under it;
declared dependencies go in the dependency graph.

Output is deterministic: the serial number is derived from the content, and the timestamp is the
assessment's, so the same delivery and assessment always give the same document.
"""

import hashlib
import json
import uuid
from collections.abc import Mapping
from typing import Any

from superscrubber104 import bundle as layout
from superscrubber104.core.model import Analysis, Assessment, Component
from superscrubber104.core.serde import format_timestamp

_HASHES = {"sha256": "SHA-256", "sha512": "SHA-512", "sha1": "SHA-1", "md5": "MD5"}
_NAMESPACE = uuid.UUID("6f5f3a7e-6b2c-5f4e-9a3b-2c1d0e9f8a7b")


def _licences(component: Component) -> list[dict[str, Any]]:
    expressions = [lic.expression for lic in component.licenses if lic.expression]
    if expressions:
        joined = " AND ".join(f"({e})" if " " in e else e for e in sorted(set(expressions)))
        return [{"expression": joined}]
    return [{"license": {"name": lic.name}} for lic in component.licenses if lic.name]


def _component(component: Component, nested: Mapping[str, list[Component]]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "bom-ref": component.bom_ref,
        "type": component.type.value,
        "name": component.name,
    }
    if component.version:
        out["version"] = component.version
    if component.supplier:
        out["supplier"] = {"name": component.supplier}
    if component.purl:
        out["purl"] = component.purl
    hashes = [
        {"alg": _HASHES[alg], "content": value}
        for alg, value in sorted(component.hashes.items())
        if alg in _HASHES
    ]
    if hashes:
        out["hashes"] = hashes
    if licences := _licences(component):
        out["licenses"] = licences
    properties = [{"name": k, "value": v} for k, v in sorted(component.properties.items())]
    if component.upstream is not None:
        upstream = component.upstream
        properties.append(
            {"name": "superscrubber104:upstream", "value": f"{upstream.type}:{upstream.reference}"}
        )
        if upstream.revision:
            properties.append(
                {"name": "superscrubber104:upstream-revision", "value": upstream.revision}
            )
        if upstream.type == "huggingface" and "/" in upstream.reference:
            out["externalReferences"] = [
                {"type": "distribution", "url": f"https://huggingface.co/{upstream.reference}"}
            ]
    for verification in component.verifications:
        properties.append(
            {
                "name": "superscrubber104:verification",
                "value": " ".join(
                    (verification.type, verification.level.value, verification.result.value)
                ),
            }
        )
    if properties:
        out["properties"] = properties
    if component.evidence:
        out["evidence"] = {
            "occurrences": [{"location": r.display} for r in component.evidence[:100]]
        }
    children = nested.get(component.bom_ref, [])
    if children:
        out["components"] = [
            _component(c, nested) for c in sorted(children, key=lambda c: c.bom_ref)
        ]
    return out


def render_cyclonedx(
    analysis: Analysis, assessment: Assessment | None = None, *, title: str = "delivery"
) -> str:
    by_ref = {c.bom_ref: c for c in analysis.components}
    parent: dict[str, str] = {}
    for component in sorted(analysis.components, key=lambda c: c.bom_ref):
        for child in component.children:
            if child in by_ref and child != component.bom_ref and child not in parent:
                parent[child] = component.bom_ref
    # A cycle would nest a component inside itself; keep anything in one at the top level.
    for child in list(parent):
        seen, node = {child}, parent.get(child)
        while node is not None:
            if node in seen:
                parent.pop(child, None)
                break
            seen.add(node)
            node = parent.get(node)
    nested: dict[str, list[Component]] = {}
    for child, owner in parent.items():
        nested.setdefault(owner, []).append(by_ref[child])
    top = [
        c for c in sorted(analysis.components, key=lambda c: c.bom_ref) if c.bom_ref not in parent
    ]
    digest = hashlib.sha256(layout.encode(analysis)).hexdigest()
    document: dict[str, Any] = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(_NAMESPACE, digest)}",
        "version": 1,
        "metadata": {
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": analysis.tool.name,
                        "version": analysis.tool.version,
                    }
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": "superscrubber104:delivery",
                "name": title,
            },
            "properties": [
                {"name": "superscrubber104:analysis-digest", "value": f"sha256:{digest}"}
            ],
        },
        "components": [_component(c, nested) for c in top],
    }
    if assessment is not None:
        document["metadata"]["timestamp"] = format_timestamp(assessment.finished_at)
        if assessment.manifest_digest:
            document["metadata"]["properties"].append(
                {"name": "superscrubber104:manifest-digest", "value": assessment.manifest_digest}
            )
    dependencies = [
        {"ref": c.bom_ref, "dependsOn": sorted(d for d in c.depends_on if d in by_ref)}
        for c in sorted(analysis.components, key=lambda c: c.bom_ref)
        if any(d in by_ref for d in c.depends_on)
    ]
    if dependencies:
        document["dependencies"] = dependencies
    return json.dumps(document, indent=2, sort_keys=False, ensure_ascii=False) + "\n"
