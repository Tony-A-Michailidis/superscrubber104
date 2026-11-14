"""Source code: language recognition, minified code and git bundles.

Recognising source turns "unclassified" into a language, which is what scanner plugins (SAST,
secrets) and reviewers select on. Minified or generated code is flagged because it cannot be
reviewed. Git bundles are recognised so their history can be scanned for secrets (task 7).
"""

from airlock import __version__
from airlock.core.interfaces import ArtifactView, Context, Detection, Inspection
from airlock.core.model import Subject, ToolRef
from airlock.handlers.common import name_of

TOOL = ToolRef("airlock.source", __version__)

LANGUAGES = {
    ".py": "python",
    ".pyi": "python",
    ".ipynb": "python-notebook",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".scala": "scala",
    ".groovy": "groovy",
    ".go": "go",
    ".rs": "rust",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".cs": "csharp",
    ".fs": "fsharp",
    ".vb": "vb",
    ".swift": "swift",
    ".m": "objective-c",
    ".rb": "ruby",
    ".php": "php",
    ".pl": "perl",
    ".pm": "perl",
    ".lua": "lua",
    ".r": "r",
    ".jl": "julia",
    ".dart": "dart",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".ps1": "powershell",
    ".psm1": "powershell",
    ".psd1": "powershell",
    ".bat": "batch",
    ".cmd": "batch",
    ".sql": "sql",
    ".css": "css",
    ".scss": "css",
    ".html": "html",
    ".htm": "html",
    ".vue": "vue",
    ".svelte": "svelte",
    ".tf": "terraform",
    ".hcl": "hcl",
    ".proto": "protobuf",
}
_MINIFIABLE = frozenset({"javascript", "css", "typescript"})
_GIT_BUNDLE = (b"# v2 git bundle\n", b"# v3 git bundle\n")


class SourceHandler:
    name = "source"
    version = "1"
    kinds = frozenset(
        {f"source.{language}" for language in LANGUAGES.values()} | {"source.git-bundle"}
    )

    @staticmethod
    def _language(view: ArtifactView) -> str | None:
        name = name_of(view.ref).lower()
        dot = name.rfind(".")
        return LANGUAGES.get(name[dot:]) if dot > 0 else None

    def detect(self, artifact: ArtifactView) -> Detection | None:
        if artifact.head(16).startswith(_GIT_BUNDLE):
            return Detection("source.git-bundle", 100)
        language = self._language(artifact)
        return Detection(f"source.{language}", 30) if language else None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        head = artifact.head(65536)
        if head.startswith(_GIT_BUNDLE):
            refs = [
                line.split(b" ", 1)[-1].decode("utf-8", "replace")
                for line in head.split(b"\n\n", 1)[0].splitlines()[1:]
                if b" " in line
            ]
            return Inspection(
                kind="source.git-bundle", metadata={"gitBundle": {"refs": refs[:100]}}
            )
        language = self._language(artifact)
        assert language is not None  # noqa: S101
        if b"\x00" in head[:8192]:
            return Inspection(kind="unclassified")  # a binary with a source-like name
        lines = head.count(b"\n") + 1
        minified = language in _MINIFIABLE and artifact.size > 2048 and len(head) / lines > 500
        if minified or name_of(artifact.ref).endswith((".min.js", ".min.css")):
            ctx.recorder.fail(
                "source.minified",
                Subject.of_artifact(artifact.ref),
                tool=TOOL,
                detail={"averageLineLength": int(len(head) / lines)},
                attributes={"language": language},
            )
        return Inspection(
            kind=f"source.{language}", media_type=None, metadata={"source": {"language": language}}
        )
