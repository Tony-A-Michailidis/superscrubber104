"""Jupyter notebooks: code with its outputs saved alongside.

A notebook is source code that also carries whatever it printed last time it ran. Outputs are
recorded and flagged (they are data, and nobody reviews them as code); cells that install
packages or download content are flagged as needing the network; shell escapes are flagged.
Secrets in cells and outputs are found by the secrets scan, which reads every text file.
"""

import re

from superscrubber104 import __version__
from superscrubber104.core.interfaces import ArtifactView, Context, Detection, Inspection
from superscrubber104.core.model import Subject, ToolRef
from superscrubber104.handlers.common import TooLarge, mapping, name_of, read_json

TOOL = ToolRef("superscrubber104.notebooks", __version__)
_LIMIT = 256 << 20
_NETWORK = re.compile(
    r"^\s*(?:[!%]{1,2}\s*(?:pip3?|uv\s+pip|conda|mamba|micromamba|poetry|npm|yarn|pnpm|apt(?:-get)?"
    r"|yum|dnf|apk|brew)\s+(?:install|add|i)\b"
    r"|!\s*(?:wget|curl|git\s+clone|git\s+lfs|huggingface-cli\s+download|hf\s+download|gsutil"
    r"|aws\s+s3|az\s+storage|kaggle|ollama\s+pull|docker\s+pull|gdown)\b)",
    re.MULTILINE,
)
_SHELL = re.compile(r"^\s*(?:!(?!=)|%%(?:bash|sh|script|cmd|powershell)\b|%(?:system|sx)\b)", re.M)


def _source(cell: dict[str, object]) -> str:
    source = cell.get("source")
    if isinstance(source, list):
        return "".join(str(s) for s in source)
    return str(source or "")


class NotebookHandler:
    name = "notebooks"
    version = "1"
    kinds = frozenset({"notebook.jupyter"})

    def detect(self, artifact: ArtifactView) -> Detection | None:
        if not name_of(artifact.ref).lower().endswith(".ipynb"):
            return None
        return Detection("notebook.jupyter", 80) if b"{" in artifact.head(64) else None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        recorder, subject = ctx.recorder, Subject.of_artifact(artifact.ref)
        try:
            data = read_json(artifact, _LIMIT)
        except (TooLarge, ValueError, UnicodeDecodeError) as exc:
            recorder.not_assessed(
                ("notebook.output.saved", "notebook.cell.network", "notebook.cell.shell"),
                subject,
                tool=TOOL,
                reason=f"the notebook could not be read: {exc}"[:300],
            )
            return Inspection(kind="notebook.jupyter")
        cells = data.get("cells") if isinstance(data, dict) else None
        cells = [c for c in cells if isinstance(c, dict)] if isinstance(cells, list) else []
        meta = mapping(data.get("metadata") if isinstance(data, dict) else None)
        kernel = mapping(meta.get("kernelspec"))
        language = mapping(meta.get("language_info"))

        outputs: dict[str, int] = {}
        with_output: list[int] = []
        network: list[dict[str, object]] = []
        shell: list[dict[str, object]] = []
        code_cells = 0
        for index, cell in enumerate(cells, start=1):
            if cell.get("cell_type") != "code":
                continue
            code_cells += 1
            source = _source(cell)
            if match := _NETWORK.search(source):
                network.append({"cell": index, "command": match.group(0).strip()[:200]})
            elif match := _SHELL.search(source):
                line = source[match.start() :].split("\n", 1)[0]
                shell.append({"cell": index, "command": line.strip()[:200]})
            cell_outputs = cell.get("outputs")
            if isinstance(cell_outputs, list) and cell_outputs:
                with_output.append(index)
                for output in cell_outputs:
                    if not isinstance(output, dict):
                        continue
                    kinds = output.get("data")
                    names = list(kinds) if isinstance(kinds, dict) else []
                    for name in names or [str(output.get("output_type", "output"))]:
                        outputs[name] = outputs.get(name, 0) + 1

        if with_output:
            recorder.fail(
                "notebook.output.saved",
                subject,
                tool=TOOL,
                detail={"cells": with_output[:100], "outputTypes": dict(sorted(outputs.items()))},
            )
        else:
            recorder.passed("notebook.output.saved")
        for rule, hits in (("notebook.cell.network", network), ("notebook.cell.shell", shell)):
            if hits:
                recorder.fail(rule, subject, tool=TOOL, detail={"cells": hits[:50]})
            else:
                recorder.passed(rule)
        summary = {
            "cells": len(cells),
            "codeCells": code_cells,
            "cellsWithOutput": len(with_output),
            "kernel": kernel.get("name"),
            "language": language.get("name") or kernel.get("language"),
            "nbformat": data.get("nbformat") if isinstance(data, dict) else None,
        }
        return Inspection(kind="notebook.jupyter", metadata={"notebook": summary})
