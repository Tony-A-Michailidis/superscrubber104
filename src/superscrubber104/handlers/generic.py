"""The handler that accepts everything.

It never claims to know what a file is; it only records a media type sniffed from content. A file
that no other handler recognises is therefore still inventoried, hashed and signed, and shows up
as "unclassified" rather than disappearing.
"""

from superscrubber104.core.interfaces import ArtifactView, Context, Detection, Inspection
from superscrubber104.core.model import UNCLASSIFIED

_MAGIC = (
    (b"\x7fELF", "application/x-elf"),
    (b"MZ", "application/vnd.microsoft.portable-executable"),
    (b"\xcf\xfa\xed\xfe", "application/x-mach-binary"),
    (b"\xfe\xed\xfa\xcf", "application/x-mach-binary"),
    (b"\xca\xfe\xba\xbe", "application/x-mach-binary"),
    (b"%PDF-", "application/pdf"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF8", "image/gif"),
    (b"PK\x03\x04", "application/zip"),
    (b"PK\x05\x06", "application/zip"),
    (b"\x1f\x8b", "application/gzip"),
    (b"BZh", "application/x-bzip2"),
    (b"\xfd7zXZ\x00", "application/x-xz"),
    (b"\x28\xb5\x2f\xfd", "application/zstd"),
    (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed"),
    (b"SQLite format 3\x00", "application/vnd.sqlite3"),
    (b"#!", "text/x-shellscript"),
)


def sniff_media_type(head: bytes) -> str:
    """Media type from leading bytes. The file name is deliberately not consulted."""
    if not head:
        return "application/x-empty"
    for magic, media_type in _MAGIC:
        if head.startswith(magic):
            return media_type
    if head[257:262] == b"ustar":
        return "application/x-tar"
    if b"\x00" not in head:
        try:
            # A multi-byte character may be cut at the end of the sample; ignore that.
            head[: len(head) - 3 if len(head) > 3 else len(head)].decode("utf-8")
        except UnicodeDecodeError:
            return "application/octet-stream"
        return "text/plain"
    return "application/octet-stream"


class GenericHandler:
    name = "generic"
    version = "1"
    kinds = frozenset({UNCLASSIFIED})

    def detect(self, artifact: ArtifactView) -> Detection | None:
        return Detection(UNCLASSIFIED, 0)

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        return Inspection(kind=UNCLASSIFIED, media_type=sniff_media_type(artifact.head(4096)))
