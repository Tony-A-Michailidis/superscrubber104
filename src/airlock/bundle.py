"""Bundle layout and the signed statement.

    bundle/
      airlock-bundle.json     marker; a pointer only, never trusted
      statement.dsse.json     DSSE envelope: in-toto Statement signed by the packer
      manifest.json           integrity inventory (subject of the statement)
      analysis.json           the packer's interpretation (subject; informational on import)
      assessment.pack.json    the packer's findings (subject; informational on import)
      request.yaml            transfer request, verbatim (subject; optional)
      custody.jsonl           hash-chained, signed custody events (appended after signing)
      payload/                content, stored as-is at its bundle paths

Digests are always taken over the bytes on disk. Nothing is parsed and re-serialised before it is
checked, so differences between tool versions cannot change what a signature covers.
"""

import json
from collections.abc import Mapping
from pathlib import Path

from airlock.core.canonical import JSON, canonical_bytes
from airlock.core.errors import SerializationError
from airlock.core.model import Provenance
from airlock.core.serde import from_data, to_data

DESCRIPTOR = "airlock-bundle.json"
STATEMENT = "statement.dsse.json"
MANIFEST = "manifest.json"
ANALYSIS = "analysis.json"
ASSESSMENT = "assessment.pack.json"
REQUEST = "request.yaml"
CUSTODY = "custody.jsonl"
PAYLOAD = "payload"

SIGNED_FILES = (MANIFEST, ANALYSIS, ASSESSMENT, REQUEST)
BUNDLE_FILES = frozenset({DESCRIPTOR, STATEMENT, CUSTODY, PAYLOAD, *SIGNED_FILES})

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "urn:airlock:bundle:v1alpha1"
STATEMENT_PAYLOAD_TYPE = "application/vnd.in-toto+json"
RECEIPT_PAYLOAD_TYPE = "application/vnd.airlock.receipt+json"

EVENT_PACKED = "packed"


def encode(document: object) -> bytes:
    """Canonical bytes of a model object."""
    return canonical_bytes(to_data(document))


def write(path: Path, document: object) -> bytes:
    data = encode(document)
    path.write_bytes(data)
    return data


def build_statement(subjects: Mapping[str, str], provenance: Provenance) -> bytes:
    """In-toto Statement naming each signed file by sha256, with the transfer's provenance."""
    statement: JSON = {
        "_type": STATEMENT_TYPE,
        "subject": [
            {"name": name, "digest": {"sha256": sha256}}
            for name, sha256 in sorted(subjects.items())
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": to_data(provenance),
    }
    return canonical_bytes(statement)


def parse_statement(payload: bytes) -> tuple[dict[str, str], Provenance]:
    """Subjects (file name -> sha256 hex) and provenance. Raises SerializationError if malformed."""
    try:
        statement = json.loads(payload)
        if statement["_type"] != STATEMENT_TYPE or statement["predicateType"] != PREDICATE_TYPE:
            raise SerializationError("not an airlock bundle statement")
        subjects = {str(s["name"]): str(s["digest"]["sha256"]) for s in statement["subject"]}
        provenance = from_data(Provenance, statement["predicate"])
    except (KeyError, TypeError, ValueError) as exc:
        raise SerializationError(f"malformed statement: {exc}") from exc
    return subjects, provenance
