import hashlib
import io
import os
from pathlib import Path

import pytest

from airlock.core.errors import ConfigError
from airlock.core.model import ArtifactRef, EntryType
from airlock.hashing import hash_stream
from airlock.walker import FileView, plan_inputs, scan
from tests.helpers import write_tree

MKFIFO = vars(os).get("mkfifo")  # absent on Windows


@pytest.mark.parametrize("size", [0, 1, 63, 64, 65, 128, 200])
def test_hash_stream_chunks(size: int) -> None:
    data = bytes(i % 251 for i in range(size))
    sink = io.BytesIO()
    result = hash_stream(io.BytesIO(data), sink=sink, chunk_size=64)
    assert result.size == size
    assert result.sha256 == hashlib.sha256(data).hexdigest()
    assert sink.getvalue() == data
    expected = [hashlib.sha256(data[i : i + 64]).hexdigest() for i in range(0, size, 64)]
    assert list(result.chunks) == (expected if size > 64 else [])


def test_hash_stream_can_be_aborted() -> None:
    seen = []

    def budget(count: int) -> None:
        seen.append(count)
        if sum(seen) > 100:
            raise RuntimeError("stop")

    with pytest.raises(RuntimeError):
        hash_stream(io.BytesIO(b"x" * 1000), chunk_size=64, on_bytes=budget)
    assert sum(seen) < 200  # stopped early, not after reading everything


def test_scan_is_sorted_and_complete(tmp_path: Path) -> None:
    root = write_tree(tmp_path / "d", {"b/z.txt": b"z", "b/a.txt": b"a", "a.txt": b"a"})
    (root / "empty").mkdir()
    found = [(s.path, s.entry_type) for s in scan("", root)]
    assert found == [
        ("a.txt", EntryType.FILE),
        ("b", EntryType.DIRECTORY),
        ("b/a.txt", EntryType.FILE),
        ("b/z.txt", EntryType.FILE),
        ("empty", EntryType.DIRECTORY),
    ]
    assert all(s.safe for s in scan("", root))
    prefixed = [s.path for s in scan("top", root)]
    assert prefixed[0] == "top"
    assert "top/b/a.txt" in prefixed


def test_symlinks_are_recorded_not_followed(tmp_path: Path) -> None:
    root = write_tree(tmp_path / "d", {"real/file.txt": b"x"})
    outside = write_tree(tmp_path / "outside", {"secret.txt": b"s"})
    try:
        (root / "link").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symbolic links are not available here")
    found = {s.path: s for s in scan("", root)}
    assert found["link"].entry_type is EntryType.SYMLINK
    assert found["link"].link_target
    assert not any(path.startswith("link/") for path in found)


@pytest.mark.skipif(MKFIFO is None, reason="needs POSIX")
def test_unrepresentable_and_special_names(tmp_path: Path) -> None:
    root = tmp_path / "d"
    root.mkdir()
    (root / "back\\slash.txt").write_bytes(b"x")
    (root / "bad\\dir").mkdir()
    (root / "bad\\dir" / "inside.txt").write_bytes(b"x")
    assert MKFIFO is not None
    MKFIFO(root / "pipe")
    found = {s.path: s for s in scan("", root)}
    assert not found["back%5Cslash.txt"].safe
    assert not found["bad%5Cdir"].safe
    assert len(found) == 3  # unsafe directories are reported, not entered
    assert found["pipe"].entry_type is EntryType.OTHER


def test_plan_inputs(tmp_path: Path) -> None:
    a = write_tree(tmp_path / "a", {"x": b"1"})
    b = write_tree(tmp_path / "b", {"y": b"2"})
    single = tmp_path / "a" / "x"
    assert plan_inputs([a]) == [("", a)]
    assert plan_inputs([a, b]) == [("a", a), ("b", b)]
    assert plan_inputs([single]) == [("x", single)]
    other = write_tree(tmp_path / "other" / "a", {"x": b"1"})
    with pytest.raises(ConfigError, match="both named"):
        plan_inputs([a, other])
    with pytest.raises(ConfigError, match="does not exist"):
        plan_inputs([tmp_path / "missing"])


def test_file_view_resolves_only_within_the_delivery(tmp_path: Path) -> None:
    root = write_tree(tmp_path, {"m/model.bin": b"abcdef", "m/sub/extra.bin": b"e", "top": b"t"})
    views: dict[str, FileView] = {}
    for name in ("m/model.bin", "m/sub/extra.bin", "top"):
        views[name] = FileView(ArtifactRef(name), root / name, 1, None, views.get)
    model = views["m/model.bin"]
    assert model.head(3) == b"abc"
    with model.open() as stream:
        assert stream.read() == b"abcdef"
    assert model.resolve("sub/extra.bin") is views["m/sub/extra.bin"]
    assert model.resolve("../top") is views["top"]
    assert model.resolve("missing") is None
    assert model.resolve("../../etc/passwd") is None
    assert model.resolve("/etc/passwd") is None
