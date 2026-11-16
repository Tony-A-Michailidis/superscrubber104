"""``osslsigncode``: Authenticode signatures on Windows updates and binaries, verified on Linux.

Windows updates (``.msu``, ``.cab``), installers (``.msi``) and binaries (``.exe``, ``.dll``,
``.sys``) carry Authenticode signatures. ``osslsigncode verify`` checks them on the Linux host,
against the root certificates pinned under ``plugins.osslsigncode.database`` (``roots.pem``, and
``tsa-roots.pem`` for timestamps), never the host's trust store.

* the content does not match its signature (a digest mismatch): ``authenticode.signature.invalid``,
  final;
* the signature holds but does not chain to a pinned root: ``authenticode.signature.untrusted``;
* no signature: ``authenticode.signature.missing``.
"""

import re
from collections.abc import Sequence
from pathlib import Path

from airlock.core.interfaces import Context
from airlock.core.model import Analysis, Subject
from airlock.core.policy import PluginPolicy
from airlock.scanners.base import DataInfo, Ready, Target

WINDOWS_SUFFIXES = (".msu", ".cab", ".msi", ".exe", ".dll", ".sys", ".msix", ".appx")
_ROOTS = "roots.pem"
_TSA_ROOTS = "tsa-roots.pem"
_SIGNER = re.compile(r"Signer #0:\s*\n\s*Subject:\s*(?P<subject>.+)")


def _windows_targets(analysis: Analysis) -> set[str]:
    out = set()
    for artifact in analysis.artifacts:
        if artifact.ref.nested:
            continue
        if "executable.pe" in artifact.kinds or artifact.ref.path.lower().endswith(
            WINDOWS_SUFFIXES
        ):
            out.add(artifact.ref.path)
    return out


def has_windows_packages(analysis: Analysis) -> bool:
    return bool(_windows_targets(analysis))


class Authenticode:
    name = "osslsigncode"
    capability = "authenticode"
    rules: tuple[str, ...] = (
        "authenticode.signature.invalid",
        "authenticode.signature.untrusted",
        "authenticode.signature.missing",
    )
    binary_names: tuple[str, ...] = ("osslsigncode",)

    def version(self, ready: Ready) -> str | None:
        match = re.search(r"osslsigncode\s+(\d[\w.]*)", ready.run(["--version"], ok=(0, 1)).stdout)
        return match.group(1) if match else None

    def data(self, policy: PluginPolicy) -> DataInfo:
        if policy.database is None:
            return DataInfo(
                problem="plugins.osslsigncode.database (the pinned root certificates) is not set"
            )
        roots = policy.database / _ROOTS
        if not roots.is_file():
            return DataInfo(problem=f"no {_ROOTS} in {policy.database}")
        files = [_ROOTS] + ([_TSA_ROOTS] if (policy.database / _TSA_ROOTS).is_file() else [])
        count = roots.read_text(encoding="ascii", errors="replace").count("BEGIN CERTIFICATE")
        return DataInfo(version=f"{count} roots", files=tuple(files))

    def scan(
        self, ready: Ready, targets: Sequence[Target], analysis: Analysis, ctx: Context
    ) -> None:
        wanted = _windows_targets(analysis)
        database = ready.policy.database
        assert database is not None  # noqa: S101 - data() refused it otherwise
        args_roots = ["-CAfile", str(database / _ROOTS)]
        if (database / _TSA_ROOTS).is_file():
            args_roots += ["-TSA-CAfile", str(database / _TSA_ROOTS)]
        for target in targets:
            if target.ref.path not in wanted:
                continue
            completed = ready.run(
                ["verify", "-in", str(target.location), *args_roots], ok=(0, 1, 255)
            )
            self._record(
                target, completed.stdout + completed.stderr, completed.returncode, ready, ctx
            )

    def _record(self, target: Target, output: str, code: int, ready: Ready, ctx: Context) -> None:
        """Classify osslsigncode's verdict.

        Only a digest mismatch is final: there the tool says the content is not what was signed.
        Any other failure (an unknown issuer, an expired certificate without a timestamp, a
        revoked one) is a matter of whom the policy trusts. Output with no verdict at all is not
        guessed at.
        """
        subject = Subject.of_artifact(target.ref)
        text = output.lower()
        signer = match["subject"].strip() if (match := _SIGNER.search(output)) else None
        detail = {"signer": signer, "output": _excerpt(output)}
        if "no signature found" in text or "failed to extract the signature" in text:
            ctx.recorder.fail(
                "authenticode.signature.missing",
                subject,
                tool=ready.tool,
                detail={"file": Path(target.ref.path).name},
            )
        elif "mismatch" in text:
            ctx.recorder.passed("authenticode.signature.missing")
            ctx.recorder.fail(
                "authenticode.signature.invalid", subject, tool=ready.tool, detail=detail
            )
        elif code == 0 and "signature verification: ok" in text:
            for rule in self.rules:
                ctx.recorder.passed(rule)
        elif "signature verification: failed" in text:
            ctx.recorder.passed("authenticode.signature.missing")
            ctx.recorder.fail(
                "authenticode.signature.untrusted", subject, tool=ready.tool, detail=detail
            )
        else:
            ctx.recorder.not_assessed(
                self.rules,
                subject,
                tool=ready.tool,
                reason=f"osslsigncode gave no verdict (exit {code}): "
                + ("; ".join(_excerpt(output)[:3]) or "no output"),
            )


def _excerpt(output: str) -> list[str]:
    keep = [
        line.strip()
        for line in output.splitlines()
        if re.search(r"(?i)verif|mismatch|error|unable|signer|subject", line)
    ]
    return keep[:20]
