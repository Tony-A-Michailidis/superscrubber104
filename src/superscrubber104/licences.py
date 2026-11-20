"""Licence identification: from licence texts, model card identifiers and GGUF metadata.

Results are SPDX identifiers where one exists, and ``LicenseRef-<name>`` for the custom terms
common on models (Llama, Gemma, Qwen and others). Identification is by distinctive phrases in the
text: enough to tell licences apart, not a legal comparison. Anything not recognised is reported
as unidentified, never guessed.
"""

import re
from dataclasses import dataclass

# (phrases that must all appear, case-insensitive) -> identifier. Most specific first.
_TEXT_SIGNATURES: tuple[tuple[tuple[str, ...], str], ...] = (
    (("llama 4 community license",), "LicenseRef-llama4"),
    (("llama 3.3 community license",), "LicenseRef-llama3.3"),
    (("llama 3.2 community license",), "LicenseRef-llama3.2"),
    (("llama 3.1 community license",), "LicenseRef-llama3.1"),
    (("meta llama 3 community license",), "LicenseRef-llama3"),
    (("llama 2 community license",), "LicenseRef-llama2"),
    (("gemma terms of use",), "LicenseRef-gemma"),
    (("qwen research license",), "LicenseRef-qwen-research"),
    (("tongyi qianwen license",), "LicenseRef-qwen"),
    (("qwen license agreement",), "LicenseRef-qwen"),
    (("mistral ai research license",), "LicenseRef-mistral-research"),
    (("mistral ai non-production license",), "LicenseRef-mistral-non-production"),
    (("deepseek license agreement",), "LicenseRef-deepseek"),
    (("nvidia open model license",), "LicenseRef-nvidia-open-model"),
    (("falcon", "tii"), "LicenseRef-falcon"),
    (("openrail",), "LicenseRef-openrail"),
    (("responsible ai license",), "LicenseRef-openrail"),
    (("gnu affero general public license", "version 3"), "AGPL-3.0-only"),
    (("gnu lesser general public license", "version 3"), "LGPL-3.0-only"),
    (("gnu lesser general public license", "version 2.1"), "LGPL-2.1-only"),
    (("gnu general public license", "version 3"), "GPL-3.0-only"),
    (("gnu general public license", "version 2"), "GPL-2.0-only"),
    (("mozilla public license", "2.0"), "MPL-2.0"),
    (("apache license", "version 2.0"), "Apache-2.0"),
    (("permission is hereby granted, free of charge",), "MIT"),
    (("redistribution and use in source and binary forms", "neither the name"), "BSD-3-Clause"),
    (("redistribution and use in source and binary forms",), "BSD-2-Clause"),
    (("permission to use, copy, modify, and/or distribute this software",), "ISC"),
    (("this is free and unencumbered software released into the public domain",), "Unlicense"),
    (("attribution-noncommercial-sharealike 4.0",), "CC-BY-NC-SA-4.0"),
    (("attribution-noncommercial-noderivatives 4.0",), "CC-BY-NC-ND-4.0"),
    (("attribution-noncommercial 4.0",), "CC-BY-NC-4.0"),
    (("attribution-sharealike 4.0",), "CC-BY-SA-4.0"),
    (("creative commons attribution 4.0",), "CC-BY-4.0"),
    (("cc0 1.0 universal",), "CC0-1.0"),
)

# Hugging Face model card / GGUF identifiers -> SPDX or LicenseRef
_IDENTIFIERS = {
    "apache-2.0": "Apache-2.0", "mit": "MIT", "bsd-2-clause": "BSD-2-Clause",
    "bsd-3-clause": "BSD-3-Clause", "isc": "ISC", "unlicense": "Unlicense",
    "cc0-1.0": "CC0-1.0", "cc-by-4.0": "CC-BY-4.0", "cc-by-sa-4.0": "CC-BY-SA-4.0",
    "cc-by-nc-4.0": "CC-BY-NC-4.0", "cc-by-nc-sa-4.0": "CC-BY-NC-SA-4.0",
    "cc-by-nc-nd-4.0": "CC-BY-NC-ND-4.0", "gpl-2.0": "GPL-2.0-only", "gpl-3.0": "GPL-3.0-only",
    "lgpl-2.1": "LGPL-2.1-only", "lgpl-3.0": "LGPL-3.0-only", "agpl-3.0": "AGPL-3.0-only",
    "mpl-2.0": "MPL-2.0", "afl-3.0": "AFL-3.0", "artistic-2.0": "Artistic-2.0",
    "bsl-1.0": "BSL-1.0", "wtfpl": "WTFPL", "zlib": "Zlib", "postgresql": "PostgreSQL",
    "llama2": "LicenseRef-llama2", "llama3": "LicenseRef-llama3",
    "llama3.1": "LicenseRef-llama3.1", "llama3.2": "LicenseRef-llama3.2",
    "llama3.3": "LicenseRef-llama3.3", "llama4": "LicenseRef-llama4",
    "gemma": "LicenseRef-gemma", "openrail": "LicenseRef-openrail",
    "openrail++": "LicenseRef-openrail", "bigscience-openrail-m": "LicenseRef-openrail",
    "creativeml-openrail-m": "LicenseRef-openrail",
    "bigscience-bloom-rail-1.0": "LicenseRef-openrail",
    "deepseek": "LicenseRef-deepseek", "qwen": "LicenseRef-qwen",
}  # fmt: skip
_SPDX_SHAPE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]*$")
_KNOWN_SPDX = {value.lower(): value for value in _IDENTIFIERS.values()}


@dataclass(frozen=True, slots=True)
class Declared:
    """One statement of a licence, and where it was found."""

    source: str  # "licence-file:LICENSE", "model-card", "gguf-metadata", ...
    identifier: str | None  # SPDX id or LicenseRef-*, None if not identified
    name: str | None = None  # free-text name, when given


def identify_text(text: str) -> str | None:
    """Identify a licence from its text (the first 64 KiB are enough)."""
    sample = " ".join(text[:65536].lower().split())
    for phrases, identifier in _TEXT_SIGNATURES:
        if all(phrase in sample for phrase in phrases):
            return identifier
    return None


def normalise_identifier(value: str, name: str | None = None) -> str | None:
    """Map a model card or GGUF licence identifier to SPDX or LicenseRef.

    ``other`` with a ``license_name`` becomes ``LicenseRef-<name>``.
    """
    key = value.strip().lower()
    if not key:
        return None
    if key in _IDENTIFIERS:
        return _IDENTIFIERS[key]
    if key in _KNOWN_SPDX:
        return _KNOWN_SPDX[key]
    if key == "other":
        if name and name.strip():
            slug = re.sub(r"[^a-z0-9.]+", "-", name.strip().lower()).strip("-")
            return f"LicenseRef-{slug}" if slug else None
        return None
    if value.startswith("LicenseRef-") or (
        _SPDX_SHAPE.match(value) and any(c.isupper() for c in value)
    ):
        return value.strip()  # already looks like an SPDX identifier
    return None


# Names of licence families, as Python package classifiers give them, and the identifiers that
# make each one specific ("BSD License" beside BSD-3-Clause says nothing more).
_FAMILIES = {
    "bsd license": ("BSD-", "0BSD"),
    "gnu general public license (gpl)": ("GPL-",),
    "gnu lesser general public license (lgpl)": ("LGPL-",),
    "gnu library or lesser general public license (lgpl)": ("LGPL-",),
    "gnu affero general public license": ("AGPL-",),
    "apache software license": ("Apache-",),
    "mozilla public license": ("MPL-",),
    "mit license": ("MIT",),
    "isc license (iscl)": ("ISC",),
    "academic free license (afl)": ("AFL-",),
    "artistic license": ("Artistic-",),
}


def made_specific(name: str | None, identifiers: list[str]) -> bool:
    """Whether a family name (``BSD License``) is made specific by one of ``identifiers``."""
    prefixes = _FAMILIES.get((name or "").strip().lower())
    return prefixes is not None and any(i.startswith(prefixes) for i in identifiers)


def combine(declared: list[Declared]) -> tuple[str | None, bool]:
    """One expression for everything declared, and whether the declarations disagree.

    Distinct identifiers are joined with AND: when sources disagree, every set of terms that
    might apply has to be acceptable.
    """
    identifiers = sorted({d.identifier for d in declared if d.identifier})
    if not identifiers:
        return None, False
    expression = " AND ".join(f"({i})" if " " in i else i for i in identifiers)
    return expression, len(identifiers) > 1
