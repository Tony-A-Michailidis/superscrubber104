"""Static reader for the header of a FAISS index file.

Every FAISS index begins with a four-character type code and the same header: dimension,
vector count, two fixed sentinels (``1 << 20``), the trained flag and the metric. The sentinels
make the format recognisable without trusting the file name. For flat indexes, which store the
vectors directly, the stored byte count is checked against dimension x count, which catches a
truncated or mismatched file.
"""

import struct
from dataclasses import dataclass

HEADER = 37
_SENTINEL = 1 << 20
_METRICS = {0: "inner-product", 1: "l2", 2: "l1", 3: "linf", 4: "lp", 20: "canberra"}
_FLAT = (b"IxFI", b"IxF2", b"IxFl")


@dataclass(frozen=True, slots=True)
class FaissInfo:
    type_code: str
    dimension: int
    vectors: int
    trained: bool
    metric: str
    problem: str | None = None


def looks_like_faiss(head: bytes) -> bool:
    if len(head) < HEADER or not head[:4].isascii() or not head[:1].isalpha():
        return False
    first, second = struct.unpack_from("<qq", head, 16)
    return bool(first == _SENTINEL and second == _SENTINEL)


def read_faiss(head: bytes, size: int) -> FaissInfo:
    """``head`` must hold at least the first 64 bytes; ``size`` is the file size."""
    if not looks_like_faiss(head):
        raise ValueError("not a FAISS index header")
    code = head[:4]
    dimension, vectors = struct.unpack_from("<iq", head, 4)
    trained = head[32] != 0
    (metric,) = struct.unpack_from("<i", head, 33)
    problem = None
    if not 0 < dimension <= 1 << 16 or vectors < 0:
        problem = f"implausible header (dimension {dimension}, vectors {vectors})"
    elif code in _FLAT:
        # The vectors follow as a float count and the floats; a metric above L2 adds an argument.
        at = HEADER + (4 if metric > 1 else 0)
        if len(head) >= at + 8:
            (stored,) = struct.unpack_from("<Q", head, at)
            expected = dimension * vectors
            if stored != expected:
                problem = f"stores {stored} values; {vectors} vectors x {dimension} need {expected}"
            elif size < at + 8 + stored * 4:
                problem = "the file is shorter than its vectors: truncated"
    return FaissInfo(
        type_code=code.decode("ascii"),
        dimension=dimension,
        vectors=vectors,
        trained=trained,
        metric=_METRICS.get(metric, str(metric)),
        problem=problem,
    )
