import io
from typing import BinaryIO

from airlock.core.interfaces import ArtifactView, Context, Detection, Handler, Inspection
from airlock.core.model import ArtifactRef


class _Bytes:
    def __init__(self, path: str, data: bytes) -> None:
        self.ref = ArtifactRef(path)
        self.size = len(data)
        self.sha256 = "0" * 64
        self._data = data

    def head(self, n: int = 65536) -> bytes:
        return self._data[:n]

    def open(self) -> BinaryIO:
        return io.BytesIO(self._data)

    def sibling(self, name: str) -> ArtifactView | None:
        return None


class _MagicHandler:
    name = "magic"
    version = "1"
    kinds = frozenset({"test.magic"})

    def detect(self, artifact: ArtifactView) -> Detection | None:
        return Detection("test.magic", 100) if artifact.head(5) == b"MAGIC" else None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        return Inspection(kind="test.magic", metadata={"size": artifact.size})


def test_handler_protocol_is_structural() -> None:
    handler = _MagicHandler()
    assert isinstance(handler, Handler)
    assert handler.detect(_Bytes("a.bin", b"MAGIC rest")) == Detection("test.magic", 100)
    assert handler.detect(_Bytes("b.bin", b"other")) is None
