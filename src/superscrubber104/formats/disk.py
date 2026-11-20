"""Static readers for virtual disk and media formats: qcow2, VMDK, VHD, VHDX, raw (MBR, GPT, LUKS)
and ISO 9660.

Only headers and metadata are read, through ``seek`` and short reads: never the guest data, never
a mount. Each reader returns a ``DiskInfo`` with what matters for transfer: the format as the
bytes say it is, the virtual size, anything the image depends on outside itself (backing files,
parents, external data files, extents), encryption, unclean state and internal snapshots.
"""

import re
import struct
import uuid
from dataclasses import dataclass, field
from typing import BinaryIO

QCOW2_MAGIC = b"QFI\xfb"
VMDK_MAGIC = b"KDMV"
VHDX_MAGIC = b"vhdxfile"
VHD_COOKIE = b"conectix"
LUKS_MAGIC = b"LUKS\xba\xbe"
_DESCRIPTOR = b"# Disk DescriptorFile"
_SECTOR = 512

_QCOW2_EXT_BACKING_FORMAT = 0xE2792ACA
_QCOW2_EXT_DATA_FILE = 0x44415441
_QCOW2_INCOMPATIBLE = {
    0: "dirty",
    1: "corrupt",
    2: "external data file",
    3: "compression type",
    4: "extended L2",
}
_QCOW2_CRYPT = {1: "aes", 2: "luks"}

_VHDX_METADATA_REGION = uuid.UUID("8B7CA206-4790-4B9A-B8FE-575F050F886E")
_VHDX_FILE_PARAMETERS = uuid.UUID("CAA16737-FA36-4D43-B3B6-33F0AA44E76B")
_VHDX_DISK_SIZE = uuid.UUID("2FA54224-CD1B-4876-B211-5DBED83BF4B8")
_VHDX_PARENT_LOCATOR = uuid.UUID("A8D35F2D-B30B-454D-ABF7-D3D84834AB0C")

GPT_TYPES = {
    "C12A7328-F81F-11D2-BA4B-00A0C93EC93B": "efi-system",
    "21686148-6449-6E6F-744E-656564454649": "bios-boot",
    "0FC63DAF-8483-4772-8E79-3D69D8477DE4": "linux-filesystem",
    "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709": "linux-root-x86-64",
    "BC13C2FF-59E6-4262-A352-B275FD6F7172": "linux-boot",
    "E6D6D379-F507-44C2-A23C-238F2A3DF928": "linux-lvm",
    "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F": "linux-swap",
    "CA7D7CCB-63ED-4C53-861C-1742536059CC": "linux-luks",
    "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7": "microsoft-basic-data",
    "E3C9E316-0B5C-4DB8-817D-F92DF00215AE": "microsoft-reserved",
    "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC": "windows-recovery",
}
MBR_TYPES = {
    0x83: "linux",
    0x8E: "linux-lvm",
    0x82: "linux-swap",
    0x07: "ntfs-exfat",
    0x0B: "fat32",
    0x0C: "fat32-lba",
    0xEF: "efi-system",
    0xEE: "gpt-protective",
    0x05: "extended",
    0x0F: "extended-lba",
}


class DiskError(ValueError):
    pass


@dataclass(slots=True)
class DiskInfo:
    format: str
    virtual_size: int | None = None
    version: str | None = None
    depends_on: list[dict[str, str]] = field(default_factory=list)  # {"kind", "name"}
    encrypted: str | None = None  # how: luks, aes, luks-partition
    unclean: list[str] = field(default_factory=list)
    snapshots: int = 0
    details: dict[str, object] = field(default_factory=dict)


def _read(stream: BinaryIO, offset: int, size: int) -> bytes:
    stream.seek(offset)
    data = stream.read(size)
    if len(data) < size:
        raise DiskError("truncated")
    return data


def sniff(head: bytes) -> str | None:
    """The format the first bytes say, for formats whose magic is at the start."""
    if head.startswith(QCOW2_MAGIC):
        return "qcow2"
    if head.startswith(VMDK_MAGIC) or head.startswith(_DESCRIPTOR):
        return "vmdk"
    if head.startswith(VHDX_MAGIC):
        return "vhdx"
    if head.startswith(VHD_COOKIE):
        return "vhd"  # a dynamic disk keeps a copy of the footer at the start
    if head.startswith(LUKS_MAGIC):
        return "luks"
    if len(head) >= 0x8006 and head[0x8001:0x8006] == b"CD001":
        return "iso"
    if len(head) >= 520 and head[512:520] == b"EFI PART":
        return "raw"
    if len(head) >= 512 and head[510:512] == b"\x55\xaa":
        return "raw"
    return None


# --- qcow2 --------------------------------------------------------------------------------------


def read_qcow2(stream: BinaryIO) -> DiskInfo:
    header = _read(stream, 0, 104)
    (magic, version, backing_offset, backing_size, cluster_bits, size, crypt, _l1, _l1o,
     _rt, _rtc, snapshots, _so) = struct.unpack(">4sIQIIQIIQQIIQ", header[:72])  # fmt: skip
    if magic != QCOW2_MAGIC:
        raise DiskError("not qcow2")
    info = DiskInfo("qcow2", size, f"v{version}", snapshots=snapshots)
    info.details["clusterSize"] = 1 << cluster_bits if cluster_bits < 32 else None
    extensions_at = 72
    if version >= 3:
        incompatible = struct.unpack(">Q", header[72:80])[0]
        extensions_at = struct.unpack(">I", header[100:104])[0]
        for bit, name in _QCOW2_INCOMPATIBLE.items():
            if incompatible & (1 << bit) and name in ("dirty", "corrupt"):
                info.unclean.append(name)
        info.details["incompatibleFeatures"] = [
            n for b, n in _QCOW2_INCOMPATIBLE.items() if incompatible & (1 << b)
        ]
    if crypt in _QCOW2_CRYPT:
        info.encrypted = _QCOW2_CRYPT[crypt]
    if backing_offset and 0 < backing_size <= 4096:
        name = _read(stream, backing_offset, backing_size).decode("utf-8", "replace")
        info.depends_on.append({"kind": "backing file", "name": name})
    # Header extensions: (type, length, data padded to 8), ending with type 0.
    offset = extensions_at
    for _ in range(64):
        try:
            kind, length = struct.unpack(">II", _read(stream, offset, 8))
        except DiskError:
            break
        if kind == 0 or length > 65536:
            break
        data = _read(stream, offset + 8, length)
        if kind == _QCOW2_EXT_BACKING_FORMAT:
            info.details["backingFormat"] = data.decode("ascii", "replace")
        elif kind == _QCOW2_EXT_DATA_FILE:
            info.depends_on.append(
                {"kind": "external data file", "name": data.decode("utf-8", "replace")}
            )
        offset += 8 + ((length + 7) // 8) * 8
    return info


# --- VMDK ---------------------------------------------------------------------------------------

_EXTENT = re.compile(
    r'^(?P<access>RW|RDONLY|NOACCESS)\s+(?P<sectors>\d+)\s+(?P<type>\w+)(?:\s+"(?P<file>[^"]*)")?',
    re.M,
)
_DDB = re.compile(r'^(?P<key>[\w.]+)\s*=\s*"?(?P<value>[^"\n]*)"?\s*$', re.M)


def parse_vmdk_descriptor(text: str) -> DiskInfo:
    fields = {m["key"]: m["value"] for m in _DDB.finditer(text)}
    extents = [m.groupdict() for m in _EXTENT.finditer(text)]
    info = DiskInfo("vmdk", sum(int(e["sectors"]) for e in extents) * _SECTOR or None)
    info.details["createType"] = fields.get("createType")
    info.details["adapterType"] = fields.get("ddb.adapterType")
    info.details["extents"] = [{"type": e["type"], "file": e["file"]} for e in extents]
    parent = fields.get("parentCID", "ffffffff").lower()
    if parent not in ("ffffffff", "") or fields.get("parentFileNameHint"):
        info.depends_on.append(
            {"kind": "parent disk", "name": fields.get("parentFileNameHint", "")}
        )
    return info


def read_vmdk(stream: BinaryIO) -> DiskInfo:
    head = _read(stream, 0, 512) if stream.seek(0, 2) >= 512 else b""
    stream.seek(0)
    if not head.startswith(VMDK_MAGIC):
        text = stream.read(64 << 10).decode("utf-8", "replace")
        if not text.startswith(_DESCRIPTOR.decode()):
            raise DiskError("not vmdk")
        info = parse_vmdk_descriptor(text)
        info.details["descriptorOnly"] = True
        return info
    version, flags, capacity, _grain, desc_offset, desc_size = struct.unpack("<IIQQQQ", head[4:44])
    unclean_shutdown = head[72]
    compress = struct.unpack("<H", head[77:79])[0]
    descriptor = ""
    if desc_offset and 0 < desc_size <= 2048:
        raw = _read(stream, desc_offset * _SECTOR, desc_size * _SECTOR)
        descriptor = raw.split(b"\x00", 1)[0].decode("utf-8", "replace")
    info = parse_vmdk_descriptor(descriptor) if descriptor else DiskInfo("vmdk")
    info.virtual_size = capacity * _SECTOR
    info.version = f"v{version}"
    info.details["compressed"] = compress == 1
    info.details["flags"] = flags
    if unclean_shutdown:
        info.unclean.append("unclean shutdown")
    return info


# --- VHD and VHDX -------------------------------------------------------------------------------


def read_vhd(stream: BinaryIO) -> DiskInfo:
    end = stream.seek(0, 2)
    footer = _read(stream, end - 512, 512)
    if not footer.startswith(VHD_COOKIE):
        footer = _read(stream, 0, 512)
        if not footer.startswith(VHD_COOKIE):
            raise DiskError("not vhd")
    data_offset, _timestamp = struct.unpack(">QI", footer[16:28])
    current_size = struct.unpack(">Q", footer[48:56])[0]
    disk_type, checksum = struct.unpack(">II", footer[60:68])
    computed = ~(sum(footer[:64]) + sum(footer[68:])) & 0xFFFFFFFF
    types = {2: "fixed", 3: "dynamic", 4: "differencing"}
    info = DiskInfo("vhd", current_size)
    info.details["diskType"] = types.get(disk_type, str(disk_type))
    info.details["creator"] = footer[28:32].decode("ascii", "replace").strip()
    if computed != checksum:
        info.unclean.append("footer checksum mismatch")
    if footer[84]:
        info.unclean.append("saved state")
    if disk_type == 4 and data_offset < end:
        header = _read(stream, data_offset, 1024)
        name = header[64:576].decode("utf-16-be", "replace").split("\x00", 1)[0]
        info.depends_on.append({"kind": "parent disk", "name": name})
    return info


def _guid(data: bytes) -> uuid.UUID:
    return uuid.UUID(bytes_le=data)


def read_vhdx(stream: BinaryIO) -> DiskInfo:
    if _read(stream, 0, 8) != VHDX_MAGIC:
        raise DiskError("not vhdx")
    info = DiskInfo("vhdx")
    # Two headers at 64 KiB and 128 KiB; the one with the higher sequence number is current.
    headers = []
    for offset in (64 << 10, 128 << 10):
        block = _read(stream, offset, 80)
        if block[:4] == b"head":
            headers.append((struct.unpack("<Q", block[8:16])[0], block))
    if not headers:
        raise DiskError("vhdx has no valid header")
    current = max(headers)[1]
    if current[48:64] != b"\x00" * 16:
        info.unclean.append("log not replayed")
    region = _read(stream, 192 << 10, 64 << 10)
    if region[:4] != b"regi":
        raise DiskError("vhdx region table missing")
    count = struct.unpack("<I", region[8:12])[0]
    metadata_at = None
    for i in range(min(count, 2047)):
        entry = region[16 + i * 32 : 48 + i * 32]
        if _guid(entry[:16]) == _VHDX_METADATA_REGION:
            metadata_at = struct.unpack("<Q", entry[16:24])[0]
    if metadata_at is None:
        raise DiskError("vhdx metadata region missing")
    table = _read(stream, metadata_at, 64 << 10)
    if table[:8] != b"metadata":
        raise DiskError("vhdx metadata table missing")
    entries = struct.unpack("<H", table[10:12])[0]
    for i in range(min(entries, 2047)):
        entry = table[32 + i * 32 : 64 + i * 32]
        item, offset, length = _guid(entry[:16]), *struct.unpack("<II", entry[16:24])
        if length > 1 << 20:
            continue
        if item == _VHDX_DISK_SIZE:
            info.virtual_size = struct.unpack("<Q", _read(stream, metadata_at + offset, 8))[0]
        elif item == _VHDX_FILE_PARAMETERS:
            block_size, flags = struct.unpack("<II", _read(stream, metadata_at + offset, 8))
            info.details["blockSize"] = block_size
            info.details["hasParent"] = bool(flags & 2)
        elif item == _VHDX_PARENT_LOCATOR:
            locator = _read(stream, metadata_at + offset, length)
            pairs = struct.unpack("<H", locator[18:20])[0]
            values = {}
            for j in range(min(pairs, 64)):
                k_off, v_off, k_len, v_len = struct.unpack(
                    "<IIHH", locator[20 + j * 12 : 32 + j * 12]
                )
                key = locator[k_off : k_off + k_len].decode("utf-16-le", "replace")
                values[key] = locator[v_off : v_off + v_len].decode("utf-16-le", "replace")
            name = (
                values.get("relative_path")
                or values.get("absolute_win32_path")
                or values.get("volume_path", "")
            )
            info.depends_on.append({"kind": "parent disk", "name": name})
    if info.details.get("hasParent") and not info.depends_on:
        info.depends_on.append({"kind": "parent disk", "name": ""})
    return info


# --- raw, LUKS, ISO -----------------------------------------------------------------------------


def read_raw(stream: BinaryIO) -> DiskInfo:
    size = stream.seek(0, 2)
    info = DiskInfo("raw", size)
    head = _read(stream, 0, min(size, 4096 + 1024))
    if head.startswith(LUKS_MAGIC):
        info.encrypted = "luks"
        info.details["layout"] = "luks"
        return info
    partitions: list[dict[str, object]] = []
    for sector in (512, 4096):
        if len(head) >= sector + 92 and head[sector : sector + 8] == b"EFI PART":
            entries_lba, count, entry_size = struct.unpack("<QII", head[sector + 72 : sector + 88])
            info.details["layout"] = "gpt"
            info.details["sectorSize"] = sector
            if 0 < entry_size <= 1024 and count <= 256:
                table = _read(stream, entries_lba * sector, count * entry_size)
                for i in range(count):
                    entry = table[i * entry_size : (i + 1) * entry_size]
                    kind = _guid(entry[:16])
                    if kind.int == 0:
                        continue
                    first, last = struct.unpack("<QQ", entry[32:48])
                    name = entry[56:128].decode("utf-16-le", "replace").split("\x00", 1)[0]
                    label = GPT_TYPES.get(str(kind).upper(), str(kind).upper())
                    partitions.append(
                        {"type": label, "name": name, "bytes": (last - first + 1) * sector}
                    )
            break
    else:
        if len(head) >= 512 and head[510:512] == b"\x55\xaa":
            info.details["layout"] = "mbr"
            for i in range(4):
                entry = head[446 + i * 16 : 462 + i * 16]
                code = entry[4]
                if code:
                    _start, sectors = struct.unpack("<II", entry[8:16])
                    partitions.append(
                        {"type": MBR_TYPES.get(code, f"0x{code:02x}"), "bytes": sectors * _SECTOR}
                    )
        else:
            info.details["layout"] = "unknown"
    info.details["partitions"] = partitions
    if any(p["type"] == "linux-luks" for p in partitions):
        info.encrypted = "luks-partition"
    return info


def read_iso(stream: BinaryIO) -> DiskInfo:
    info = DiskInfo("iso")
    for index in range(16, 64):
        descriptor = _read(stream, index * 2048, 2048)
        if descriptor[1:6] != b"CD001":
            raise DiskError("not ISO 9660")
        kind = descriptor[0]
        if kind == 255:
            break
        if kind == 0 and descriptor[7:30] == b"EL TORITO SPECIFICATION":
            info.details["bootable"] = True
        if kind == 1:
            info.details["systemId"] = descriptor[8:40].decode("ascii", "replace").strip()
            info.details["volumeId"] = descriptor[40:72].decode("ascii", "replace").strip()
            blocks = struct.unpack("<I", descriptor[80:84])[0]
            block_size = struct.unpack("<H", descriptor[128:130])[0]
            info.virtual_size = blocks * block_size
    info.details.setdefault("bootable", False)
    return info


READERS = {
    "qcow2": read_qcow2,
    "vmdk": read_vmdk,
    "vhd": read_vhd,
    "vhdx": read_vhdx,
    "raw": read_raw,
    "luks": read_raw,
    "iso": read_iso,
}


def read_disk(stream: BinaryIO, detected: str) -> DiskInfo:
    return READERS[detected](stream)
