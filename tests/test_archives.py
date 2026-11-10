"""Archive inspection: nothing is extracted, hostile members are reported, bombs are stopped."""

import gzip
import hashlib
import io
import tarfile
import warnings
import zipfile
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

from airlock.analyzer import Analyzer
from airlock.archive import detect_format
from airlock.core.interfaces import ArtifactView, Context, Detection, Handler, Inspection
from airlock.core.model import Artifact, ArtifactRef, EntryType, Finding, Result
from airlock.core.policy import ArchiveLimits, Limits, Policy
from airlock.handlers.generic import GenericHandler, sniff_media_type
from airlock.session import Session
from airlock.walker import FileView
from tests.helpers import NOW, tar_bytes, zip_bytes

MIB = 2**20
SMALL = ArchiveLimits(max_ratio=100, ratio_min_bytes=MIB, max_expanded_bytes=64 * MIB)


@dataclass
class Outcome:
    artifacts: dict[str, Artifact]
    findings: dict[str, list[Finding]]
    scratch_left_behind: list[Path]

    def rules(self) -> set[str]:
        return set(self.findings)

    def one(self, rule: str) -> Finding:
        [finding] = self.findings[rule]
        return finding


def analyze(
    tmp_path: Path,
    data: bytes,
    name: str = "sample.bin",
    *,
    limits: ArchiveLimits = SMALL,
    handlers: tuple[Handler, ...] = (),
) -> Outcome:
    source = tmp_path / "input.bin"
    source.write_bytes(data)
    scratch = tmp_path / "scratch"
    scratch.mkdir(exist_ok=True)
    policy = replace(Policy.default(), limits=Limits(archive=limits))
    session = Session.start(policy, NOW)
    analyzer = Analyzer(session.ctx, (*handlers, GenericHandler()), scratch)
    view = FileView(ArtifactRef(name), source, len(data), hashlib.sha256(data).hexdigest())
    analyzer.analyze(view)
    findings: dict[str, list[Finding]] = {}
    for finding in session.ctx.recorder.findings:
        findings.setdefault(finding.rule, []).append(finding)
    findings.pop("inventory.artifact.unclassified", None)
    return Outcome(
        {a.ref.display: a for a in analyzer.artifacts}, findings, list(scratch.iterdir())
    )


def patch(data: bytes, old: bytes, new: bytes) -> bytes:
    """Rewrite member names in raw archive bytes (for names the writers refuse to produce)."""
    assert len(old) == len(new)
    assert old in data
    return data.replace(old, new)


# --- formats ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (zip_bytes({"a": b"1"}), "zip"),
        (zip_bytes({}), "zip"),
        (tar_bytes({"a": b"1"}), "tar"),
        (tar_bytes({"a": b"1"}, "w:gz"), "gzip"),
        (tar_bytes({"a": b"1"}, "w:bz2"), "bzip2"),
        (tar_bytes({"a": b"1"}, "w:xz"), "xz"),
        (b"7z\xbc\xaf\x27\x1c" + b"\x00" * 20, "7z"),
        (b"plain text", None),
        (b"", None),
    ],
)
def test_format_is_detected_from_content(data: bytes, expected: str | None) -> None:
    assert detect_format(data[:65536]) == expected


def test_media_type_sniffing() -> None:
    assert sniff_media_type(b"\x7fELF\x02\x01") == "application/x-elf"
    assert sniff_media_type(b"hello\n") == "text/plain"
    assert sniff_media_type("héllo".encode()) == "text/plain"
    assert sniff_media_type(b"\x00\x01\x02") == "application/octet-stream"
    assert sniff_media_type(b"") == "application/x-empty"


def test_zip_members_are_inventoried_with_hashes(tmp_path: Path) -> None:
    inner = zip_bytes({"deep/x.txt": b"deep"})
    out = analyze(
        tmp_path, zip_bytes({"a.txt": b"alpha", "dir/": b"", "inner.zip": inner}), "a.zip"
    )
    assert out.rules() == set()
    assert out.artifacts["a.zip"].kinds == ("archive.zip",)
    assert out.artifacts["a.zip!/a.txt"].sha256 == hashlib.sha256(b"alpha").hexdigest()
    assert out.artifacts["a.zip!/a.txt"].media_type == "text/plain"
    assert out.artifacts["a.zip!/dir"].entry_type is EntryType.DIRECTORY
    assert out.artifacts["a.zip!/inner.zip"].kinds == ("archive.zip",)
    assert out.artifacts["a.zip!/inner.zip"].sha256 == hashlib.sha256(inner).hexdigest()
    assert out.artifacts["a.zip!/inner.zip!/deep/x.txt"].size == 4
    assert out.scratch_left_behind == []


@pytest.mark.parametrize("mode", ["w", "w:gz", "w:bz2", "w:xz"])
def test_tar_and_compressed_tar(tmp_path: Path, mode: str) -> None:
    out = analyze(tmp_path, tar_bytes({"./pkg/a.py": b"a = 1\n", "pkg/b.py": b"b"}, mode), "p.tar")
    assert out.rules() == set()
    assert {"p.tar!/pkg/a.py", "p.tar!/pkg/b.py"} <= set(out.artifacts)
    assert out.scratch_left_behind == []


def test_single_compressed_file(tmp_path: Path) -> None:
    out = analyze(tmp_path, gzip.compress(b"notes\n"), "docs/notes.txt.gz")
    assert out.artifacts["docs/notes.txt.gz!/notes.txt"].sha256 == (
        hashlib.sha256(b"notes\n").hexdigest()
    )
    out = analyze(tmp_path, gzip.compress(b"x"), "blob")
    assert "blob!/data" in out.artifacts


def test_unsupported_formats_are_reported_as_not_assessed(tmp_path: Path) -> None:
    out = analyze(tmp_path, b"7z\xbc\xaf\x27\x1c" + b"\x00" * 64, "a.7z")
    assert out.artifacts["a.7z"].kinds == ("archive.7z",)
    traversal = out.one("archive.member.path-traversal")
    assert traversal.result is Result.NOT_ASSESSED
    assert "7z" in (traversal.not_assessed_reason or "")


# --- hostile members ----------------------------------------------------------------------------


def test_zip_path_traversal_is_reported_and_nothing_is_written(tmp_path: Path) -> None:
    data = zip_bytes(
        {
            "ok.txt": b"fine",
            "../../evil.txt": b"evil",
            "/abs/evil.txt": b"evil",
            "aaXaaXwin.dll": b"x",
        }
    )
    data = patch(data, b"aaXaaXwin.dll", b"..\\..\\win.dll")
    before = {p for p in tmp_path.parent.rglob("*") if "evil" in p.name or "win.dll" in p.name}
    out = analyze(tmp_path, data, "bad.zip")

    hits = out.findings["archive.member.path-traversal"]
    assert sorted(f.subject.display for f in hits) == [
        "bad.zip!/..%5C..%5Cwin.dll",
        "bad.zip!/../../evil.txt",
        "bad.zip!//abs/evil.txt",
    ]
    assert all(f.result is Result.FAIL and f.subject.artifact.unsafe for f in hits)  # type: ignore[union-attr]
    # The members are still inventoried and hashed, under their escaped names.
    assert out.artifacts["bad.zip!/../../evil.txt"].sha256 == hashlib.sha256(b"evil").hexdigest()
    assert out.artifacts["bad.zip!/ok.txt"].ref.unsafe is False
    after = {p for p in tmp_path.parent.rglob("*") if "evil" in p.name or "win.dll" in p.name}
    assert after == before
    assert out.scratch_left_behind == []


def test_unsafe_member_names(tmp_path: Path) -> None:
    data = patch(zip_bytes({"a_b.txt": b"x"}), b"a_b.txt", b"a\\b.txt")
    out = analyze(tmp_path, data, "odd.zip")
    assert out.one("archive.member.unsafe-name").subject.display == "odd.zip!/a%5Cb.txt"


def test_tar_links_devices_and_setuid(tmp_path: Path) -> None:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:

        def add(
            name: str, kind: bytes, link: str = "", mode: int = 0o644, data: bytes = b""
        ) -> None:
            info = tarfile.TarInfo(name)
            info.type, info.linkname, info.mode, info.size = kind, link, mode, len(data)
            archive.addfile(info, io.BytesIO(data) if data else None)

        add("bin/tool", tarfile.REGTYPE, mode=0o4755, data=b"\x7fELF")
        add("lib/ok.so", tarfile.SYMTYPE, link="real.so")
        add("lib/escape", tarfile.SYMTYPE, link="../../etc/shadow")
        add("abs", tarfile.SYMTYPE, link="/etc/passwd")
        add("hard", tarfile.LNKTYPE, link="../outside")
        add("dev/null", tarfile.CHRTYPE)
        add("pipe", tarfile.FIFOTYPE)
        add("/etc/cron.d/job", tarfile.REGTYPE, data=b"* * * * * root sh\n")
    out = analyze(tmp_path, buffer.getvalue(), "rootfs.tar")

    escapes = sorted(f.subject.display for f in out.findings["archive.member.link-escape"])
    assert escapes == ["rootfs.tar!/abs", "rootfs.tar!/hard", "rootfs.tar!/lib/escape"]
    special = sorted(f.subject.display for f in out.findings["archive.member.special-file"])
    assert special == ["rootfs.tar!/dev/null", "rootfs.tar!/pipe"]
    assert out.one("archive.member.setuid").subject.display == "rootfs.tar!/bin/tool"
    assert out.one("archive.member.path-traversal").subject.display == "rootfs.tar!//etc/cron.d/job"
    assert out.artifacts["rootfs.tar!/lib/ok.so"].link_target == "real.so"
    assert out.artifacts["rootfs.tar!/bin/tool"].mode == 0o4755
    assert out.artifacts["rootfs.tar!/bin/tool"].media_type == "application/x-elf"


def test_zip_symlink_escape(tmp_path: Path) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        link = zipfile.ZipInfo("link")
        link.create_system = 3
        link.external_attr = 0o120777 << 16
        archive.writestr(link, "../../../etc/passwd")
    out = analyze(tmp_path, buffer.getvalue(), "l.zip")
    assert out.one("archive.member.link-escape").detail["target"] == "../../../etc/passwd"
    assert out.artifacts["l.zip!/link"].entry_type is EntryType.SYMLINK


def test_duplicate_members(tmp_path: Path) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive, warnings.catch_warnings():
        warnings.simplefilter("ignore")
        archive.writestr("config.json", b'{"safe": true}')
        archive.writestr("config.json", b'{"safe": false}')
    out = analyze(tmp_path, buffer.getvalue(), "d.zip")
    assert out.one("archive.member.duplicate").subject.display == "d.zip!/config.json"


def test_encrypted_members_are_reported(tmp_path: Path) -> None:
    data = bytearray(zip_bytes({"secret.txt": b"hidden"}, zipfile.ZIP_STORED))
    data[6] |= 1  # general-purpose flag bit 0 in the local header ...
    central = data.index(b"PK\x01\x02")
    data[central + 8] |= 1  # ... and in the central directory
    out = analyze(tmp_path, bytes(data), "e.zip")
    assert out.one("archive.member.encrypted").subject.display == "e.zip!/secret.txt"
    assert out.artifacts["e.zip!/secret.txt"].sha256 is None


def test_corrupt_archives(tmp_path: Path) -> None:
    good = zip_bytes({"a.txt": b"alpha" * 100})
    out = analyze(tmp_path, good[: len(good) // 2], "cut.zip")
    assert out.one("archive.format.unreadable").subject.display == "cut.zip"
    out = analyze(tmp_path, gzip.compress(b"x" * 5000)[:-20], "cut.gz")
    assert "archive.format.unreadable" in out.rules()
    assert out.scratch_left_behind == []


# --- bombs and limits ---------------------------------------------------------------------------


def test_zip_bomb_is_stopped_at_the_ratio(tmp_path: Path) -> None:
    bomb = zip_bytes({"zeros.bin": bytes(32 * MIB)})
    assert len(bomb) < 64 * 1024
    out = analyze(tmp_path, bomb, "bomb.zip")
    finding = out.one("archive.limit.ratio")
    assert finding.subject.display == "bomb.zip"
    expanded = finding.detail["expandedBytes"]
    assert isinstance(expanded, int)
    assert expanded < 8 * MIB  # inspection stopped early; it did not expand everything
    assert out.scratch_left_behind == []


def test_nested_bomb_counts_against_the_outermost_archive(tmp_path: Path) -> None:
    inner = zip_bytes({"zeros.bin": bytes(32 * MIB)})
    outer = zip_bytes({"readme.txt": b"hi", "layer.zip": zip_bytes({"inner.zip": inner})})
    out = analyze(tmp_path, outer, "nested.zip")
    finding = out.one("archive.limit.ratio")
    assert finding.subject.display == "nested.zip"
    assert finding.detail["stoppedIn"] == "nested.zip!/layer.zip!/inner.zip"
    assert "nested.zip!/readme.txt" in out.artifacts  # what was seen before the stop is kept
    assert out.scratch_left_behind == []


def test_gzip_bomb(tmp_path: Path) -> None:
    out = analyze(tmp_path, gzip.compress(bytes(32 * MIB)), "bomb.gz")
    assert "archive.limit.ratio" in out.rules()
    assert out.scratch_left_behind == []


def test_small_archives_are_not_judged_on_ratio(tmp_path: Path) -> None:
    out = analyze(tmp_path, zip_bytes({"zeros.bin": bytes(512 * 1024)}), "small.zip")
    assert out.rules() == set()


def test_expanded_size_and_member_limits(tmp_path: Path) -> None:
    data = zip_bytes({f"f{i}.bin": bytes([i]) * 4096 for i in range(20)}, zipfile.ZIP_STORED)
    tight = replace(SMALL, max_expanded_bytes=10_000)
    assert "archive.limit.expanded-size" in analyze(tmp_path, data, "big.zip", limits=tight).rules()
    few = replace(SMALL, max_members=5)
    out = analyze(tmp_path, data, "many.zip", limits=few)
    assert out.one("archive.limit.members").detail["members"] == 6
    assert len(out.artifacts) == 1 + 5


def test_depth_limit(tmp_path: Path) -> None:
    level3 = zip_bytes({"secret.txt": b"deep"})
    level2 = zip_bytes({"l3.zip": level3, "two.txt": b"2"})
    level1 = zip_bytes({"l2.zip": level2, "one.txt": b"1"})
    out = analyze(tmp_path, level1, "l1.zip", limits=replace(SMALL, max_depth=2))
    assert out.one("archive.limit.depth").subject.display == "l1.zip!/l2.zip!/l3.zip"
    assert "l1.zip!/l2.zip!/two.txt" in out.artifacts
    assert "l1.zip!/l2.zip!/l3.zip" in out.artifacts  # recorded and hashed, but not opened
    assert "l1.zip!/l2.zip!/l3.zip!/secret.txt" not in out.artifacts


# --- handlers on members ------------------------------------------------------------------------


class MagicHandler:
    name = "magic"
    version = "1"
    kinds = frozenset({"test.magic"})

    def detect(self, artifact: ArtifactView) -> Detection | None:
        return Detection("test.magic", 100) if artifact.head(5) == b"MAGIC" else None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        with artifact.open() as stream:
            body = stream.read()
        return Inspection(kind="test.magic", metadata={"length": len(body), "ratio": 0.5})


class BrokenHandler:
    name = "broken"
    version = "1"
    kinds = frozenset({"test.broken"})

    def detect(self, artifact: ArtifactView) -> Detection | None:
        raise RuntimeError("boom")

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        raise AssertionError("unreachable")


def test_handlers_can_read_members_they_recognise(tmp_path: Path) -> None:
    body = b"MAGIC" + b"x" * 100_000  # longer than the head sample
    data = tar_bytes({"model.bin": body, "other.txt": b"plain"}, "w:gz")
    out = analyze(tmp_path, data, "m.tgz", handlers=(MagicHandler(),))
    member = out.artifacts["m.tgz!/model.bin"]
    assert member.kinds == ("test.magic",)
    assert member.metadata == {"length": len(body), "ratio": "0.5"}  # floats become strings
    assert [h.name for h in member.handlers] == ["magic", "generic"]
    assert out.artifacts["m.tgz!/other.txt"].kinds == ("unclassified",)
    assert out.scratch_left_behind == []


def test_polyglot_gets_every_kind(tmp_path: Path) -> None:
    class ZipAware(MagicHandler):
        name = "zipaware"
        kinds = frozenset({"test.package"})

        def detect(self, artifact: ArtifactView) -> Detection | None:
            return Detection("test.package", 80) if artifact.head(2) == b"PK" else None

        def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
            return Inspection(kind="test.package")

    out = analyze(tmp_path, zip_bytes({"a": b"1"}), "p.whl", handlers=(ZipAware(),))
    assert out.artifacts["p.whl"].kinds == ("archive.zip", "test.package")
    assert "p.whl!/a" in out.artifacts


def test_a_failing_handler_does_not_hide_the_artifact(tmp_path: Path) -> None:
    out = analyze(tmp_path, b"anything", "file.bin", handlers=(BrokenHandler(),))
    error = out.one("inventory.handler.error")
    assert error.result is Result.ERROR
    assert error.tool.name == "broken"
    assert out.artifacts["file.bin"].kinds == ("unclassified",)
