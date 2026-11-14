"""Executables and scripts: what they are and what they run on.

Native binaries (ELF, PE, Mach-O) are identified from their headers: format, architecture, word
size, whether a PE file is a DLL or a .NET assembly, and whether it carries an Authenticode
signature (recorded as present; verifying it arrives with Windows patching in 1c). Scripts are
identified by their interpreter line or extension. Nothing is executed or loaded; the malware
scan, when configured, covers the content.
"""

import struct

from airlock.core.interfaces import ArtifactView, Context, Detection, Inspection
from airlock.handlers.common import name_of

_ELF_MACHINES = {
    3: "x86", 62: "x86-64", 40: "arm", 183: "aarch64", 243: "riscv", 8: "mips", 20: "ppc",
    21: "ppc64", 22: "s390", 258: "loongarch",
}  # fmt: skip
_ELF_TYPES = {1: "relocatable", 2: "executable", 3: "shared-object", 4: "core"}
_PE_MACHINES = {0x14C: "x86", 0x8664: "x86-64", 0xAA64: "aarch64", 0x1C4: "arm", 0x0: "any"}
_MACHO = {
    b"\xcf\xfa\xed\xfe": (64, "<"), b"\xce\xfa\xed\xfe": (32, "<"),
    b"\xfe\xed\xfa\xcf": (64, ">"), b"\xfe\xed\xfa\xce": (32, ">"),
}  # fmt: skip
_MACHO_CPUS = {7: "x86", 0x01000007: "x86-64", 12: "arm", 0x0100000C: "aarch64"}
_SCRIPT_EXTENSIONS = {
    ".sh": "sh", ".bash": "bash", ".ps1": "powershell", ".psm1": "powershell", ".bat": "cmd",
    ".cmd": "cmd", ".vbs": "vbscript", ".vbe": "vbscript", ".wsf": "windows-script-host",
    ".hta": "html-application", ".js": None, ".jse": "jscript", ".scr": None,
}  # fmt: skip


def _elf(head: bytes) -> dict[str, object] | None:
    if len(head) < 20 or head[4] not in (1, 2) or head[5] not in (1, 2):
        return None
    order = "<" if head[5] == 1 else ">"
    kind, machine = struct.unpack_from(f"{order}HH", head, 16)
    return {
        "format": "elf",
        "bits": 32 if head[4] == 1 else 64,
        "endian": "little" if order == "<" else "big",
        "type": _ELF_TYPES.get(kind, str(kind)),
        "architecture": _ELF_MACHINES.get(machine, f"machine-{machine}"),
    }


def _pe(head: bytes) -> dict[str, object] | None:
    if len(head) < 64:
        return None
    (offset,) = struct.unpack_from("<I", head, 0x3C)
    if offset + 24 > len(head) or head[offset : offset + 4] != b"PE\0\0":
        return None
    machine, _, _, _, _, optional_size, characteristics = struct.unpack_from(
        "<HHIIIHH", head, offset + 4
    )
    optional = offset + 24
    info: dict[str, object] = {
        "format": "pe",
        "architecture": _PE_MACHINES.get(machine, f"machine-{machine:#x}"),
        "dll": bool(characteristics & 0x2000),
    }
    if optional + 2 > len(head):
        return info
    (magic,) = struct.unpack_from("<H", head, optional)
    info["bits"] = 64 if magic == 0x20B else 32
    directories = optional + (112 if magic == 0x20B else 96)
    subsystem_at = optional + 68
    if subsystem_at + 2 <= len(head):
        (subsystem,) = struct.unpack_from("<H", head, subsystem_at)
        info["subsystem"] = {2: "gui", 3: "console", 10: "efi-application"}.get(
            subsystem, str(subsystem)
        )

    def directory(index: int) -> int | None:
        at = directories + index * 8
        if optional_size < (at - optional) + 8 or at + 8 > len(head):
            return None
        _, size = struct.unpack_from("<II", head, at)
        return int(size)

    security, clr = directory(4), directory(14)
    if security is not None:
        info["authenticode"] = "present (not verified)" if security else "absent"
    if clr:
        info["dotnet"] = True
    return info


def _macho(head: bytes) -> dict[str, object] | None:
    found = _MACHO.get(head[:4])
    if found is None:
        if head[:4] == b"\xca\xfe\xba\xbe" and len(head) >= 8:
            (count,) = struct.unpack_from(">I", head, 4)
            if 0 < count < 32:  # a Java class file has its version here, which is >= 45 << 16
                return {"format": "mach-o", "universal": True, "architectures": count}
        return None
    bits, order = found
    (cpu,) = struct.unpack_from(f"{order}I", head, 4)
    return {"format": "mach-o", "bits": bits, "architecture": _MACHO_CPUS.get(cpu, str(cpu))}


def _script(view: ArtifactView, head: bytes) -> dict[str, object] | None:
    name = name_of(view.ref).lower()
    if head.startswith(b"#!"):
        line = head[2:256].split(b"\n", 1)[0].decode("utf-8", "replace").strip()
        parts = line.split()
        interpreter = parts[0].rsplit("/", 1)[-1] if parts else ""
        if interpreter == "env" and len(parts) > 1:
            interpreter = next((p for p in parts[1:] if not p.startswith("-")), interpreter)
        return {"format": "script", "interpreter": interpreter or "unknown"}
    extension = name[name.rfind(".") :] if "." in name else ""
    if _SCRIPT_EXTENSIONS.get(extension):
        return {"format": "script", "interpreter": _SCRIPT_EXTENSIONS[extension]}
    return None


def _identify(view: ArtifactView) -> tuple[str, dict[str, object]] | None:
    head = view.head(4096)
    if head.startswith(b"\x7fELF"):
        info = _elf(head)
        return ("executable.elf", info) if info else None
    if head.startswith(b"MZ"):
        info = _pe(head)
        return ("executable.pe", info) if info else None
    info = _macho(head)
    if info:
        return "executable.mach-o", info
    info = _script(view, head)
    return ("executable.script", info) if info else None


class ExecutableHandler:
    name = "executables"
    version = "1"
    kinds = frozenset({"executable.elf", "executable.pe", "executable.mach-o", "executable.script"})

    def detect(self, artifact: ArtifactView) -> Detection | None:
        found = _identify(artifact)
        return Detection(found[0], 60) if found else None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        found = _identify(artifact)
        assert found is not None  # noqa: S101 - only called after detect()
        kind, info = found
        return Inspection(kind=kind, metadata={"executable": info})
