"""Synthetic virtual disks: just the headers and metadata each reader looks at, laid out as the
format specifications describe. The readers were also checked against real images (a CirrOS qcow2
and an Alpine ISO)."""

import io
import struct
import tarfile
import uuid
from collections.abc import Mapping

MIB = 1 << 20


def qcow2(
    *,
    size: int = 64 * MIB,
    version: int = 3,
    backing: str | None = None,
    crypt: int = 0,
    incompatible: int = 0,
    snapshots: int = 0,
    data_file: str | None = None,
) -> bytes:
    backing_offset = 1024 if backing else 0
    backing_bytes = (backing or "").encode()
    header = struct.pack(
        ">4sIQIIQIIQQIIQ",
        b"QFI\xfb", version, backing_offset, len(backing_bytes), 16, size, crypt,
        0, 0, 0, 0, snapshots, 0,
    )  # fmt: skip
    if version >= 3:
        header += struct.pack(">QQQII", incompatible, 0, 0, 4, 104)
    extensions = b""
    if data_file:
        name = data_file.encode()
        extensions += struct.pack(">II", 0x44415441, len(name)) + name + b"\x00" * (-len(name) % 8)
    extensions += struct.pack(">II", 0, 0)
    out = bytearray(header + extensions)
    out += b"\x00" * (2048 - len(out))
    if backing:
        out[backing_offset : backing_offset + len(backing_bytes)] = backing_bytes
    return bytes(out)


def vmdk_descriptor(
    *,
    create_type: str = "monolithicFlat",
    extent: str = "disk-flat.vmdk",
    parent: str | None = None,
) -> str:
    parent_lines = (
        f'parentCID=1a2b3c4d\nparentFileNameHint="{parent}"\n' if parent else "parentCID=ffffffff\n"
    )
    return (
        "# Disk DescriptorFile\nversion=1\nCID=fffffffe\n" + parent_lines
        + f'createType="{create_type}"\n\n# Extent description\nRW 4096 FLAT "{extent}" 0\n\n'
        + '# The Disk Data Base\nddb.adapterType = "lsilogic"\n'
    )  # fmt: skip


def vmdk_sparse(*, sectors: int = 4096, unclean: bool = False, name: str = "disk.vmdk") -> bytes:
    descriptor = (
        f'# Disk DescriptorFile\nversion=1\nparentCID=ffffffff\ncreateType="streamOptimized"\n'
        f'RW {sectors} SPARSE "{name}"\n'
    ).encode()
    header = bytearray(512)
    header[0:4] = b"KDMV"
    struct.pack_into("<IIQQQQ", header, 4, 3, 0x30001, sectors, 128, 1, 2)
    header[72] = 1 if unclean else 0
    struct.pack_into("<H", header, 77, 1)
    return bytes(header) + descriptor.ljust(1024, b"\x00")


def _vhd_footer(size: int, disk_type: int, data_offset: int) -> bytes:
    footer = bytearray(512)
    footer[0:8] = b"conectix"
    struct.pack_into(">IIQI", footer, 8, 2, 0x00010000, data_offset, 0)
    footer[28:32] = b"qemu"
    struct.pack_into(">I", footer, 32, 0x00050003)
    footer[36:40] = b"Wi2k"
    struct.pack_into(">QQIII", footer, 40, size, size, 0, disk_type, 0)
    footer[68:84] = uuid.UUID(int=1).bytes
    checksum = ~sum(footer) & 0xFFFFFFFF
    struct.pack_into(">I", footer, 64, checksum)
    return bytes(footer)


def vhd_fixed(size: int = 4096, *, break_checksum: bool = False) -> bytes:
    footer = bytearray(_vhd_footer(size, 2, 0xFFFFFFFFFFFFFFFF))
    if break_checksum:
        footer[64] ^= 0xFF
    return b"\x00" * size + bytes(footer)


def vhd_differencing(parent: str, size: int = 8 * MIB) -> bytes:
    footer = _vhd_footer(size, 4, 512)
    header = bytearray(1024)
    header[0:8] = b"cxsparse"
    name = parent.encode("utf-16-be")
    header[64 : 64 + len(name)] = name
    return footer + bytes(header) + b"\x00" * 512 + footer


def vhdx(*, size: int = 16 * MIB, parent: str | None = None, dirty: bool = False) -> bytes:
    out = bytearray(2 * MIB)
    out[0:8] = b"vhdxfile"
    for offset, sequence in ((64 << 10, 1), (128 << 10, 2)):
        out[offset : offset + 4] = b"head"
        struct.pack_into("<Q", out, offset + 8, sequence)
        if dirty and sequence == 2:
            out[offset + 48 : offset + 64] = uuid.UUID(int=7).bytes_le
    region = 192 << 10
    metadata = 1 * MIB
    out[region : region + 4] = b"regi"
    struct.pack_into("<I", out, region + 8, 1)
    out[region + 16 : region + 32] = uuid.UUID("8B7CA206-4790-4B9A-B8FE-575F050F886E").bytes_le
    struct.pack_into("<QII", out, region + 32, metadata, 1 * MIB, 1)
    out[metadata : metadata + 8] = b"metadata"
    items: list[tuple[str, bytes]] = [
        ("CAA16737-FA36-4D43-B3B6-33F0AA44E76B", struct.pack("<II", 32 * MIB, 2 if parent else 0)),
        ("2FA54224-CD1B-4876-B211-5DBED83BF4B8", struct.pack("<Q", size)),
    ]
    if parent:
        key, value = "relative_path".encode("utf-16-le"), parent.encode("utf-16-le")
        locator = uuid.UUID(int=9).bytes_le + struct.pack("<HH", 0, 1)
        start = len(locator) + 12
        locator += struct.pack("<IIHH", start, start + len(key), len(key), len(value)) + key + value
        items.append(("A8D35F2D-B30B-454D-ABF7-D3D84834AB0C", locator))
    struct.pack_into("<H", out, metadata + 10, len(items))
    data_at = 64 << 10
    for index, (guid, payload) in enumerate(items):
        entry = metadata + 32 + index * 32
        out[entry : entry + 16] = uuid.UUID(guid).bytes_le
        struct.pack_into("<II", out, entry + 16, data_at, len(payload))
        out[metadata + data_at : metadata + data_at + len(payload)] = payload
        data_at += 4096
    return bytes(out)


def raw_gpt(partitions: list[str]) -> bytes:
    """A GPT disk; ``partitions`` are type GUIDs."""
    out = bytearray(64 << 10)
    out[510:512] = b"\x55\xaa"
    out[446 + 4] = 0xEE
    out[512:520] = b"EFI PART"
    struct.pack_into("<QII", out, 512 + 72, 2, 128, 128)
    for index, kind in enumerate(partitions):
        entry = 1024 + index * 128
        out[entry : entry + 16] = uuid.UUID(kind).bytes_le
        out[entry + 16 : entry + 32] = uuid.UUID(int=index + 1).bytes_le
        struct.pack_into("<QQ", out, entry + 32, 2048 + index * 4096, 2048 + index * 4096 + 4095)
        name = f"part{index}".encode("utf-16-le")
        out[entry + 56 : entry + 56 + len(name)] = name
    return bytes(out)


def raw_mbr() -> bytes:
    out = bytearray(4096)
    out[510:512] = b"\x55\xaa"
    out[446 + 4] = 0x83
    struct.pack_into("<II", out, 446 + 8, 2048, 6)
    return bytes(out)


def iso(volume: str = "TEST_DISC", *, bootable: bool = True) -> bytes:
    out = bytearray(20 * 2048)
    pvd = 16 * 2048
    out[pvd] = 1
    out[pvd + 1 : pvd + 6] = b"CD001"
    out[pvd + 6] = 1
    out[pvd + 8 : pvd + 40] = b"LINUX".ljust(32)
    out[pvd + 40 : pvd + 72] = volume.encode().ljust(32)
    struct.pack_into("<I", out, pvd + 80, 20)
    struct.pack_into("<H", out, pvd + 128, 2048)
    next_sector = 17 * 2048
    if bootable:
        out[next_sector] = 0
        out[next_sector + 1 : next_sector + 6] = b"CD001"
        out[next_sector + 7 : next_sector + 30] = b"EL TORITO SPECIFICATION"
        next_sector += 2048
    out[next_sector] = 255
    out[next_sector + 1 : next_sector + 6] = b"CD001"
    return bytes(out)


def ovf(files: Mapping[str, int | None]) -> bytes:
    references = "".join(
        f'<File ovf:href="{name}" ovf:id="f{i}"'
        + (f' ovf:size="{size}"' if size is not None else "")
        + "/>"
        for i, (name, size) in enumerate(files.items())
    )
    return (
        '<?xml version="1.0"?><Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1" '
        'xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1">'
        f"<References>{references}</References>"
        '<DiskSection><Disk ovf:capacity="16" ovf:capacityAllocationUnits="byte * 2^30" ovf:diskId="d0" '
        'ovf:fileRef="f0" ovf:format="http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized"/></DiskSection>'
        '<VirtualSystem ovf:id="appliance"><OperatingSystemSection ovf:id="96"><Description>Ubuntu 64-bit</Description>'
        "</OperatingSystemSection></VirtualSystem></Envelope>"
    ).encode()


def tar(files: Mapping[str, bytes]) -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return out.getvalue()
