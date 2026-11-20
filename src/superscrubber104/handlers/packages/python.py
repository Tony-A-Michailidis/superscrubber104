"""Python packages, installed environments and lockfiles.

* **Wheels**: metadata, tags (platform, Python, CUDA build), licence, and every file checked
  against the wheel's own ``RECORD`` (a difference means the wheel was modified after it was
  built). ``.pth`` files that run code at interpreter start are flagged.
* **Source distributions**: installing one runs its build backend, so they are flagged.
* **Installed packages** (``*.dist-info`` in site-packages, a virtualenv or a container layer):
  inventoried as components, grouped into an environment per installation prefix.
* **Lockfiles** (``requirements*.txt``, ``uv.lock``, ``poetry.lock``, ``Pipfile.lock``,
  ``pylock.toml``): each locked requirement with its version, hashes and source. Pinning,
  hashing and remote sources are checked here; whether the delivery can actually satisfy the
  lockfile offline is checked by the Python environment assembler.

Nothing is installed, built or imported.
"""

import base64
import csv
import hashlib
import io
import json
import re
import tomllib
import zipfile
from collections.abc import Callable
from dataclasses import dataclass, field
from email.parser import HeaderParser
from typing import Any

from superscrubber104 import __version__
from superscrubber104.checks.licences import check_licences
from superscrubber104.core.interfaces import ArtifactView, Context, Detection, Inspection
from superscrubber104.core.model import (
    ArtifactRef,
    Component,
    ComponentType,
    LicenseRef,
    Severity,
    Subject,
    ToolRef,
    UnitKind,
)
from superscrubber104.handlers.common import (
    TooLarge,
    full_path,
    make_claim,
    name_of,
    parent_of,
    read_text,
)
from superscrubber104.licences import Declared, identify_text, normalise_identifier

TOOL = ToolRef("superscrubber104.python", __version__)
_METADATA_LIMIT = 4 << 20
_RECORD_LIMIT = 32 << 20
_SITE = re.compile(r"(?:^|/)(?:lib|Lib|lib64)/(?:python[\d.]+/)?(?:site|dist)-packages/")
_REQUIREMENTS = re.compile(r"^(?:requirements|constraints)[\w.-]*\.(?:txt|lock)$", re.IGNORECASE)
_PYLOCK = re.compile(r"^pylock(?:\.[\w-]+)?\.toml$")
# Python sdists are .tar.gz (or legacy .zip); .tgz is how npm names its tarballs.
_SDIST = re.compile(r"^(?P<name>.+?)-(?P<version>\d[^-]*?)\.(?:tar\.gz|zip)$")
_REQUIREMENT = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?P<spec>[^;@]*)"
    r"(?:@\s*(?P<url>\S+))?\s*(?:;(?P<markers>.*))?$"
)
_KNOWN_PTH = frozenset({"distutils-precedence.pth", "_virtualenv.pth"})

# Trove licence classifiers -> SPDX; None where the classifier does not say which variant.
_CLASSIFIERS = {
    "MIT License": "MIT",
    "MIT No Attribution License (MIT-0)": "MIT-0",
    "Apache Software License": "Apache-2.0",
    "ISC License (ISCL)": "ISC",
    "Python Software Foundation License": "PSF-2.0",
    "The Unlicense (Unlicense)": "Unlicense",
    "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "Historical Permission Notice and Disclaimer (HPND)": "HPND",
    "GNU General Public License v2 (GPLv2)": "GPL-2.0-only",
    "GNU General Public License v3 (GPLv3)": "GPL-3.0-only",
    "GNU Lesser General Public License v2 (LGPLv2)": "LGPL-2.0-only",
    "GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0-only",
    "GNU Affero General Public License v3": "AGPL-3.0-only",
    "BSD License": None,
}
_SHORT_LICENCES = {
    "mit": "MIT",
    "mit license": "MIT",
    "apache 2.0": "Apache-2.0",
    "apache-2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "apache 2": "Apache-2.0",
    "bsd-3-clause": "BSD-3-Clause",
    "bsd 3-clause": "BSD-3-Clause",
    "new bsd": "BSD-3-Clause",
    "bsd-2-clause": "BSD-2-Clause",
    "isc": "ISC",
    "psf": "PSF-2.0",
    "mpl-2.0": "MPL-2.0",
}


# --- names and versions -------------------------------------------------------------------------


def canon_name(name: str) -> str:
    """PEP 503 normalised project name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def canon_version(version: str) -> str:
    """Enough of PEP 440 normalisation to compare locked and file versions: case, a leading 'v',
    and trailing zero release segments ('1.0' == '1.0.0')."""
    text = version.strip().lower().removeprefix("v")
    match = re.match(r"^(\d+(?:\.\d+)*)(.*)$", text)
    if not match:
        return text
    release = match.group(1).split(".")
    while len(release) > 1 and release[-1] == "0":
        release.pop()
    return ".".join(str(int(p)) for p in release) + match.group(2)


@dataclass(frozen=True, slots=True)
class WheelName:
    name: str
    version: str
    python: str
    abi: str
    platform: str


def parse_wheel_name(filename: str) -> WheelName | None:
    if not filename.endswith(".whl"):
        return None
    parts = filename[:-4].split("-")
    if len(parts) not in (5, 6):
        return None
    return WheelName(parts[0], parts[1], parts[-3], parts[-2], parts[-1])


def pypi_purl(name: str, version: str) -> str:
    return f"pkg:pypi/{canon_name(name)}@{version}"


def _bom_ref(purl: str, ref: ArtifactRef) -> str:
    return f"{purl}#{hashlib.sha256(ref.display.encode()).hexdigest()[:12]}"


# --- metadata and licences ----------------------------------------------------------------------


@dataclass
class _Metadata:
    name: str
    version: str
    licences: list[Declared] = field(default_factory=list)
    requires_python: str | None = None
    requires: list[str] = field(default_factory=list)
    summary: str | None = None


def parse_metadata(text: str, source: str) -> _Metadata | None:
    headers = HeaderParser().parsestr(text)
    name, version = headers.get("Name"), headers.get("Version")
    if not name or not version:
        return None
    meta = _Metadata(name.strip(), version.strip())
    meta.requires_python = headers.get("Requires-Python")
    meta.requires = [str(r) for r in headers.get_all("Requires-Dist") or []][:500]
    meta.summary = (headers.get("Summary") or "")[:300] or None
    expression = headers.get("License-Expression")
    if expression:
        meta.licences.append(Declared(f"{source}:License-Expression", expression.strip()))
    for classifier in headers.get_all("Classifier") or []:
        if str(classifier).startswith("License :: "):
            label = str(classifier).rsplit(" :: ", 1)[-1]
            meta.licences.append(Declared(f"{source}:Classifier", _CLASSIFIERS.get(label), label))
    licence = (headers.get("License") or "").strip()
    if licence and not expression and licence.upper() != "UNKNOWN":
        short = (
            _SHORT_LICENCES.get(licence.lower()) or normalise_identifier(licence)
            if len(licence) < 64
            else None
        )
        identifier = short or (identify_text(licence) if len(licence) >= 64 else None)
        meta.licences.append(Declared(f"{source}:License", identifier, licence[:100]))
    return meta


def _component(meta: _Metadata, ref: ArtifactRef, kind: str, sha256: str | None) -> Component:
    purl = pypi_purl(meta.name, meta.version)
    return Component(
        bom_ref=_bom_ref(purl, ref),
        type=ComponentType.LIBRARY,
        name=meta.name,
        version=meta.version,
        purl=purl,
        licenses=tuple(
            LicenseRef(expression=d.identifier, name=d.name)
            for d in meta.licences
            if d.identifier or d.name
        ),
        hashes={"sha256": sha256} if sha256 and kind != "installed" else {},
        evidence=(ref,),
        properties={"superscrubber104:python-distribution": kind},
    )


def _pth_code(text: str) -> list[str]:
    """Lines of a .pth file that Python executes at start-up."""
    return [
        line.strip()[:200] for line in text.splitlines() if line.startswith(("import ", "import\t"))
    ]


def _check_pth(ctx: Context, ref: ArtifactRef, name: str, text: str) -> None:
    lines = _pth_code(text)
    if not lines:
        ctx.recorder.passed("python.package.pth-file")
        return
    known = name in _KNOWN_PTH
    ctx.recorder.fail(
        "python.package.pth-file",
        Subject.of_artifact(ref),
        tool=TOOL,
        detail={
            "file": name,
            "lines": lines[:10],
            "note": "a standard packaging file name" if known else None,
        },
        severity=Severity.INFO if known else None,
        discriminator=name,
    )


# --- wheels, sdists, installed ------------------------------------------------------------------


def _record_problems(archive: zipfile.ZipFile, record_path: str) -> list[dict[str, str]]:
    """Every file listed with a hash must match it; every file must be listed."""
    info = archive.getinfo(record_path)
    if info.file_size > _RECORD_LIMIT:
        return [{"file": record_path, "problem": "RECORD is too large to check"}]
    listed: dict[str, str] = {}
    for row in csv.reader(io.StringIO(archive.read(info).decode("utf-8", "replace"))):
        if row:
            listed[row[0]] = row[1] if len(row) > 1 else ""
    problems = []
    names = {i.filename for i in archive.infolist() if not i.is_dir()}
    dist_info = record_path.rsplit("/", 1)[0]
    for path, recorded in sorted(listed.items()):
        if not recorded:
            continue  # RECORD itself, and signatures, are listed without a hash
        algorithm, _, expected = recorded.partition("=")
        if path not in names:
            problems.append({"file": path, "problem": "listed in RECORD but missing"})
            continue
        if algorithm != "sha256":
            continue
        digest = hashlib.sha256()
        with archive.open(path) as handle:
            while block := handle.read(1 << 20):
                digest.update(block)
        actual = base64.urlsafe_b64encode(digest.digest()).rstrip(b"=").decode()
        if actual != expected:
            problems.append({"file": path, "problem": "content differs from RECORD"})
    ignored = {record_path, f"{dist_info}/RECORD.jws", f"{dist_info}/RECORD.p7s"}
    for path in sorted(names - set(listed) - ignored):
        problems.append({"file": path, "problem": "not listed in RECORD"})
    return problems


def _wheel(view: ArtifactView, ctx: Context) -> Inspection:
    filename = name_of(view.ref)
    parsed = parse_wheel_name(filename)
    if parsed is None:
        return Inspection(kind="unclassified")
    with view.open() as stream, zipfile.ZipFile(stream) as archive:
        names = archive.namelist()
        metadata_path = next(
            (n for n in names if re.fullmatch(r"[^/]+\.dist-info/METADATA", n)), None
        )
        if metadata_path is None:
            return Inspection(
                kind="python.wheel", metadata={"pythonWheel": {"error": "no METADATA"}}
            )
        meta = parse_metadata(
            archive.read(metadata_path)[:_METADATA_LIMIT].decode("utf-8", "replace"), "METADATA"
        )
        record = f"{metadata_path.rsplit('/', 1)[0]}/RECORD"
        problems = (
            _record_problems(archive, record)
            if record in names
            else [{"file": record, "problem": "no RECORD"}]
        )
        for path in names:
            if path.endswith(".pth") and path.count("/") <= 2:
                _check_pth(
                    ctx,
                    view.ref,
                    path.rsplit("/", 1)[-1],
                    archive.read(path)[:65536].decode("utf-8", "replace"),
                )
    if problems:
        ctx.recorder.fail(
            "python.wheel.record-mismatch",
            Subject.of_artifact(view.ref),
            tool=TOOL,
            detail={"problems": problems[:50]},
        )
    else:
        ctx.recorder.passed("python.wheel.record-mismatch")
    if meta is None:
        return Inspection(
            kind="python.wheel",
            metadata={"pythonWheel": {"error": "METADATA lacks Name or Version"}},
        )
    component = _component(meta, view.ref, "wheel", view.sha256)
    check_licences(Subject.of_component(component.bom_ref), meta.licences, ctx)
    local = parsed.version.split("+", 1)[1] if "+" in parsed.version else None
    facts = {
        "name": canon_name(meta.name),
        "version": canon_version(meta.version),
        "rawVersion": meta.version,
        "filename": filename,
        "format": "wheel",
        "bomRef": component.bom_ref,
        "tags": {"python": parsed.python, "abi": parsed.abi, "platform": parsed.platform},
        "local": local,
    }
    summary = {k: facts[k] for k in ("name", "rawVersion", "tags", "local")} | {
        "requiresPython": meta.requires_python,
        "summary": meta.summary,
    }
    return Inspection(
        kind="python.wheel",
        metadata={"pythonWheel": summary},
        components=(component,),
        claims=(make_claim(view, UnitKind.PYTHON_ENVIRONMENT, "distribution", facts),),
    )


def _sdist(view: ArtifactView, ctx: Context) -> Inspection:
    match = _SDIST.match(name_of(view.ref))
    assert match is not None  # noqa: S101
    ctx.recorder.fail(
        "python.package.build-script",
        Subject.of_artifact(view.ref),
        tool=TOOL,
        detail={
            "file": name_of(view.ref),
            "note": "installing a source distribution runs its build backend",
        },
    )
    meta = _Metadata(match["name"], match["version"])
    component = _component(meta, view.ref, "sdist", view.sha256)
    facts = {
        "name": canon_name(meta.name),
        "version": canon_version(meta.version),
        "rawVersion": meta.version,
        "filename": name_of(view.ref),
        "format": "sdist",
        "bomRef": component.bom_ref,
    }
    return Inspection(
        kind="python.sdist",
        components=(component,),
        claims=(make_claim(view, UnitKind.PYTHON_ENVIRONMENT, "distribution", facts),),
    )


def site_root(ref: ArtifactRef) -> ArtifactRef:
    """The installation prefix a dist-info belongs to (a virtualenv, /usr/local, ...)."""
    path = full_path(ref)
    match = _SITE.search(path)
    if match is None:
        return parent_of(parent_of(ref))
    prefix = path[: match.start()].rstrip("/")
    if not ref.member:
        return ArtifactRef(prefix or ".")
    outer = ref.member[:-1]
    return ArtifactRef(ref.path, (*outer, prefix) if prefix else outer)


def _installed(view: ArtifactView, ctx: Context) -> Inspection:
    meta = parse_metadata(read_text(view, _METADATA_LIMIT), "METADATA")
    if meta is None:
        return Inspection(kind="unclassified")
    component = _component(meta, view.ref, "installed", None)
    if meta.licences:
        check_licences(Subject.of_component(component.bom_ref), meta.licences, ctx)
    facts = {
        "name": canon_name(meta.name),
        "version": canon_version(meta.version),
        "rawVersion": meta.version,
        "bomRef": component.bom_ref,
    }
    return Inspection(
        kind="python.installed",
        components=(component,),
        claims=(
            make_claim(
                view, UnitKind.PYTHON_ENVIRONMENT, "installed", facts, root=site_root(view.ref)
            ),
        ),
    )


def _pth(view: ArtifactView, ctx: Context) -> Inspection:
    _check_pth(ctx, view.ref, name_of(view.ref), read_text(view, 65536))
    return Inspection(kind="python.pth")


def _venv(view: ArtifactView, ctx: Context) -> Inspection:
    values = dict(
        (k.strip(), v.strip())
        for k, _, v in (line.partition("=") for line in read_text(view, 65536).splitlines())
        if _
    )
    facts: dict[str, object] = {
        k: values[k]
        for k in ("version", "version_info", "home", "include-system-site-packages")
        if k in values
    }
    return Inspection(
        kind="python.virtualenv",
        claims=(make_claim(view, UnitKind.PYTHON_ENVIRONMENT, "venv", facts),),
    )


# --- lockfiles ----------------------------------------------------------------------------------


@dataclass
class _Lock:
    format: str
    requirements: list[dict[str, Any]] = field(default_factory=list)
    indexes: list[str] = field(default_factory=list)
    find_links: list[str] = field(default_factory=list)
    no_index: bool = False


def _requirement(
    name: str,
    version: str | None,
    *,
    pinned: bool,
    hashes: list[str],
    source: str = "index",
    markers: str | None = None,
    url: str | None = None,
) -> dict[str, Any]:
    return {
        "name": canon_name(name),
        "displayName": name,
        "version": canon_version(version) if version else None,
        "pinned": pinned,
        "hashes": sorted({h.removeprefix("sha256:").lower() for h in hashes if h}),
        "source": source,
        "markers": markers.strip() if markers else None,
        "url": url,
    }


def _requirements_txt(text: str) -> _Lock:
    lock = _Lock("requirements.txt")
    logical: list[str] = []
    buffer = ""
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].rstrip() if not raw.lstrip().startswith("#") else ""
        if line.endswith("\\"):
            buffer += line[:-1] + " "
            continue
        logical.append((buffer + line).strip())
        buffer = ""
    for line in logical:
        if not line:
            continue
        tokens = line.split()
        options = {
            "--index-url": lock.indexes,
            "-i": lock.indexes,
            "--extra-index-url": lock.indexes,
            "--find-links": lock.find_links,
            "-f": lock.find_links,
        }
        if tokens[0] in options and len(tokens) > 1:
            options[tokens[0]].append(tokens[1])
            continue
        if any(tokens[0].startswith(f"{o}=") for o in options):
            option, _, value = tokens[0].partition("=")
            options[option].append(value)
            continue
        if tokens[0] == "--no-index":
            lock.no_index = True
            continue
        if tokens[0] in ("-r", "-c", "--requirement", "--constraint") or tokens[0].startswith("--"):
            continue
        hashes = [t.split("=", 1)[1] for t in tokens if t.startswith("--hash=")]
        spec_text = " ".join(t for t in tokens if not t.startswith("--hash="))
        if tokens[0] in ("-e", "--editable"):
            lock.requirements.append(
                _requirement(
                    spec_text.split()[-1],
                    None,
                    pinned=False,
                    hashes=[],
                    source="editable",
                    url=spec_text.split()[-1],
                )
            )
            continue
        if re.match(r"^(?:git\+|hg\+|svn\+|bzr\+|https?://|file:)", spec_text):
            lock.requirements.append(
                _requirement(
                    spec_text.split("#egg=")[-1] if "#egg=" in spec_text else spec_text,
                    None,
                    pinned=False,
                    hashes=hashes,
                    source="url",
                    url=spec_text,
                )
            )
            continue
        match = _REQUIREMENT.match(spec_text)
        if not match:
            continue
        spec, url = (match["spec"] or "").strip(), match["url"]
        exact = re.fullmatch(r"===?\s*([^,\s]+)", spec)
        source = "url" if url else "index"
        lock.requirements.append(
            _requirement(
                match["name"],
                exact.group(1) if exact else None,
                pinned=bool(exact),
                hashes=hashes,
                source=source,
                markers=match["markers"],
                url=url,
            )
        )
    return lock


def _hashes(items: Any) -> list[str]:
    found = []
    for item in items if isinstance(items, list) else [items]:
        if isinstance(item, dict):
            value = item.get("hash") or (item.get("hashes") or {}).get("sha256")
            if isinstance(value, str):
                found.append(value)
    return found


def _uv_lock(text: str) -> _Lock:
    lock = _Lock("uv.lock")
    for package in tomllib.loads(text).get("package", []):
        if not isinstance(package, dict) or not package.get("name"):
            continue
        source = package.get("source") or {}
        if "editable" in source or "virtual" in source:
            continue  # the project itself
        kind = (
            "vcs"
            if "git" in source
            else "url"
            if "url" in source
            else "path"
            if "path" in source or "directory" in source
            else "index"
        )
        hashes = _hashes(package.get("wheels")) + _hashes(package.get("sdist"))
        lock.requirements.append(
            _requirement(
                package["name"],
                package.get("version"),
                pinned=True,
                hashes=hashes,
                source=kind,
                url=source.get("git") or source.get("url"),
            )
        )
    return lock


def _poetry_lock(text: str) -> _Lock:
    lock = _Lock("poetry.lock")
    document = tomllib.loads(text)
    legacy = (document.get("metadata") or {}).get("files") or {}
    for package in document.get("package", []):
        if not isinstance(package, dict) or not package.get("name"):
            continue
        source = package.get("source") or {}
        kinds = {"git": "vcs", "url": "url", "file": "path", "directory": "path"}
        kind = kinds.get(str(source.get("type")), "index")
        files = package.get("files") or legacy.get(package["name"]) or []
        lock.requirements.append(
            _requirement(
                package["name"],
                package.get("version"),
                pinned=True,
                hashes=_hashes(files),
                source=kind,
                url=source.get("url"),
            )
        )
    return lock


def _pipfile_lock(text: str) -> _Lock:
    lock = _Lock("Pipfile.lock")
    document = json.loads(text)
    for section in ("default", "develop"):
        for name, entry in (document.get(section) or {}).items():
            if not isinstance(entry, dict):
                continue
            version = str(entry.get("version") or "")
            exact = re.fullmatch(r"===?\s*(\S+)", version)
            kind = (
                "vcs"
                if "git" in entry
                else "path"
                if "path" in entry or "file" in entry
                else "index"
            )
            lock.requirements.append(
                _requirement(
                    name,
                    exact.group(1) if exact else None,
                    pinned=bool(exact) or kind != "index",
                    hashes=list(entry.get("hashes") or []),
                    source=kind,
                    markers=entry.get("markers"),
                    url=entry.get("git"),
                )
            )
    for source in (document.get("_meta") or {}).get("sources") or []:
        if isinstance(source, dict) and isinstance(source.get("url"), str):
            lock.indexes.append(source["url"])
    return lock


def _pylock(text: str) -> _Lock:
    lock = _Lock("pylock.toml")
    for package in tomllib.loads(text).get("packages", []):
        if not isinstance(package, dict) or not package.get("name"):
            continue
        kind = (
            "vcs"
            if "vcs" in package
            else "path"
            if "directory" in package
            else "url"
            if "archive" in package
            else "index"
        )
        hashes = _hashes(package.get("wheels")) + _hashes(package.get("sdist"))
        lock.requirements.append(
            _requirement(
                package["name"],
                package.get("version"),
                pinned=bool(package.get("version")),
                hashes=hashes,
                source=kind,
                markers=package.get("marker"),
            )
        )
    for index in [
        package.get("index")
        for package in tomllib.loads(text).get("packages", [])
        if isinstance(package, dict)
    ]:
        if isinstance(index, str) and index not in lock.indexes:
            lock.indexes.append(index)
    return lock


_DEFAULT_INDEXES = (
    "https://pypi.org/simple",
    "https://pypi.org/simple/",
    "https://pypi.python.org/simple",
)


def _lockfile(parse: Callable[[str], _Lock]) -> Callable[[ArtifactView, Context], Inspection]:
    def handle(view: ArtifactView, ctx: Context) -> Inspection:
        try:
            lock = parse(read_text(view, 32 << 20))
        except (ValueError, tomllib.TOMLDecodeError) as exc:
            return Inspection(
                kind="unclassified", metadata={"pythonLock": {"unreadable": str(exc)[:200]}}
            )
        if not lock.requirements:
            return Inspection(kind="unclassified")
        subject = Subject.of_artifact(view.ref)
        recorder = ctx.recorder
        index_reqs = [r for r in lock.requirements if r["source"] == "index"]
        unpinned = [r["displayName"] for r in index_reqs if not r["pinned"]]
        unhashed = [r["displayName"] for r in index_reqs if r["pinned"] and not r["hashes"]]
        remote = [
            {"requirement": r["displayName"], "source": r["source"], "url": r["url"]}
            for r in lock.requirements
            if r["source"] in ("url", "vcs")
        ]
        remote += [{"index": i} for i in lock.indexes if i not in _DEFAULT_INDEXES]
        for rule, items, detail_key in (
            ("python.requirements.unpinned", unpinned, "requirements"),
            ("python.requirements.unhashed", unhashed, "requirements"),
            ("python.requirements.remote-source", remote, "sources"),
        ):
            if items:
                recorder.fail(
                    rule, subject, tool=TOOL, detail={detail_key: items[:100], "count": len(items)}
                )
            else:
                recorder.passed(rule)
        facts = {
            "format": lock.format,
            "requirements": lock.requirements,
            "indexes": lock.indexes,
            "findLinks": lock.find_links,
            "noIndex": lock.no_index,
        }
        summary = {
            "format": lock.format,
            "requirements": len(lock.requirements),
            "unpinned": len(unpinned),
            "unhashed": len(unhashed),
        }
        return Inspection(
            kind="python.lockfile",
            metadata={"pythonLock": summary},
            claims=(
                make_claim(view, UnitKind.PYTHON_ENVIRONMENT, "lockfile", facts, root=view.ref),
            ),
        )

    return handle


# --- dispatch -----------------------------------------------------------------------------------


def _inside_wheel(ref: ArtifactRef) -> bool:
    outer = (ref.path, *ref.member[:-1])[-1] if ref.member else ""
    return outer.endswith(".whl")


def _dispatch(view: ArtifactView) -> Callable[[ArtifactView, Context], Inspection] | None:
    name = name_of(view.ref)
    path = full_path(view.ref)
    head = view.head(4)
    if name.endswith(".whl") and head[:2] == b"PK":
        return _wheel
    if _SDIST.match(name) and (head[:2] == b"\x1f\x8b" or head[:2] == b"PK" or head[:3] == b"BZh"):
        return _sdist
    if _inside_wheel(view.ref):
        return None  # the wheel handler covers its own contents
    if name == "METADATA" and re.search(r"[^/]+\.dist-info/METADATA$", path):
        return _installed
    if name.endswith(".pth"):
        return _pth
    if name == "pyvenv.cfg":
        return _venv
    if _REQUIREMENTS.match(name):
        return _lockfile(_requirements_txt)
    if name == "uv.lock":
        return _lockfile(_uv_lock)
    if name == "poetry.lock":
        return _lockfile(_poetry_lock)
    if name == "Pipfile.lock":
        return _lockfile(_pipfile_lock)
    if _PYLOCK.match(name):
        return _lockfile(_pylock)
    return None


class PythonPackageHandler:
    name = "python-packages"
    version = "1"
    kinds = frozenset(
        {
            "python.wheel",
            "python.sdist",
            "python.installed",
            "python.pth",
            "python.virtualenv",
            "python.lockfile",
        }
    )

    def detect(self, artifact: ArtifactView) -> Detection | None:
        return Detection("python", 75) if _dispatch(artifact) else None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        handle = _dispatch(artifact)
        assert handle is not None  # noqa: S101
        try:
            return handle(artifact, ctx)
        except TooLarge as exc:
            return Inspection(kind="unclassified", metadata={"python": {"skipped": str(exc)}})
        except (zipfile.BadZipFile, KeyError, ValueError, UnicodeDecodeError) as exc:
            return Inspection(
                kind="unclassified", metadata={"python": {"unreadable": str(exc)[:200]}}
            )
