"""``qemu-img``: an independent read of each VM disk image, and its consistency check.

airlock reads disk headers itself (``formats/disk.py``). With this plugin configured, ``qemu-img
info`` and ``qemu-img check`` also run on every disk image, read-only, with the format given
explicitly (``-f``) so that qemu never probes it, and with ``-U`` so that it takes no locks. Any
difference between the two readings, and any corruption or leak ``check`` reports, is
``vm.image.check``.

``qemu-img`` parses untrusted input, like any scanner: pin its hash and keep it current.
"""

import json
from collections.abc import Sequence

from airlock.core.interfaces import Context
from airlock.core.model import Analysis, Subject
from airlock.core.policy import PluginPolicy
from airlock.scanners.base import DataInfo, Ready, ScanError, Target

_QEMU_FORMATS = {"qcow2": "qcow2", "vmdk": "vmdk", "vhd": "vpc", "vhdx": "vhdx", "raw": "raw"}
_CHECKABLE = frozenset({"qcow2", "vhdx", "vdi", "qed", "parallels"})


def _formats(analysis: Analysis) -> dict[str, str]:
    """Top-level disk images and the format airlock read from their headers."""
    out = {}
    for artifact in analysis.artifacts:
        if artifact.ref.nested:
            continue
        image = artifact.metadata.get("vmImage")
        if (
            isinstance(image, dict)
            and isinstance(image.get("format"), str)
            and not image.get("error")
        ):
            fmt = _QEMU_FORMATS.get(str(image["format"]))
            if fmt:
                out[artifact.ref.path] = fmt
    return out


def has_disk_images(analysis: Analysis) -> bool:
    return any(k.startswith("vm.image.") for a in analysis.artifacts for k in a.kinds)


class QemuImg:
    name = "qemu-img"
    capability = "vm-images"
    rules: tuple[str, ...] = ("vm.image.check",)
    binary_names: tuple[str, ...] = ("qemu-img",)

    def version(self, ready: Ready) -> str | None:
        out = ready.run(["--version"]).stdout
        first = out.split("\n", 1)[0]
        return first.split("version", 1)[1].split()[0] if "version" in first else None

    def data(self, policy: PluginPolicy) -> DataInfo:
        return DataInfo(version="none")  # no database

    def scan(
        self, ready: Ready, targets: Sequence[Target], analysis: Analysis, ctx: Context
    ) -> None:
        formats = _formats(analysis)
        static = {
            a.ref.path: a.metadata.get("vmImage") for a in analysis.artifacts if not a.ref.nested
        }
        for target in targets:
            fmt = formats.get(target.ref.path)
            if fmt is None:
                continue
            subject = Subject.of_artifact(target.ref)
            completed = ready.run(
                ["info", "--output=json", "-U", "-f", fmt, str(target.location)], ok=(0, 1)
            )
            if completed.returncode != 0:
                ctx.recorder.fail(
                    "vm.image.check",
                    subject,
                    tool=ready.tool,
                    detail={"step": "info", "error": completed.stderr.strip()[:500]},
                )
                continue
            try:
                info = json.loads(completed.stdout)
            except json.JSONDecodeError as exc:
                raise ScanError(f"qemu-img info output is not JSON: {exc}") from exc
            problems = _compare(info, static.get(target.ref.path))
            if fmt in _CHECKABLE:
                checked = ready.run(
                    ["check", "--output=json", "-U", "-f", fmt, str(target.location)],
                    ok=(0, 1, 2, 3),
                )
                try:
                    result = json.loads(checked.stdout) if checked.stdout.strip() else {}
                except json.JSONDecodeError:
                    result = {}
                for key in ("corruptions", "leaks", "check-errors"):
                    if result.get(key):
                        problems.append(f"{key}: {result[key]}")
                if checked.returncode == 1 and not result:
                    problems.append(f"check failed: {checked.stderr.strip()[:300]}")
            if problems:
                ctx.recorder.fail(
                    "vm.image.check",
                    subject,
                    tool=ready.tool,
                    detail={"problems": problems, "qemuFormat": fmt},
                )
            else:
                ctx.recorder.passed("vm.image.check")


def _compare(info: dict[str, object], static: object) -> list[str]:
    problems = []
    if isinstance(info.get("backing-filename"), str):
        problems.append(f"backing file {info['backing-filename']}")
    if info.get("dirty-flag"):
        problems.append("dirty")
    specific = info.get("format-specific")
    data = specific.get("data") if isinstance(specific, dict) else None
    if isinstance(data, dict) and data.get("corrupt"):
        problems.append("marked corrupt")
    if isinstance(static, dict):
        size = static.get("virtualSize")
        if (
            isinstance(size, int)
            and isinstance(info.get("virtual-size"), int)
            and size != info["virtual-size"]
        ):
            problems.append(f"virtual size: airlock read {size}, qemu-img {info['virtual-size']}")
        if bool(static.get("encrypted")) != bool(info.get("encrypted")):
            problems.append(
                f"encryption: airlock read {static.get('encrypted')}, "
                f"qemu-img {info.get('encrypted')}"
            )
    return problems
