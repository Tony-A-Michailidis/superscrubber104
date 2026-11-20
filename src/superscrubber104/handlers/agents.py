"""Agent and MCP assets: what an AI agent will be allowed to do once it runs on the other side.

* **MCP client configurations** (``.mcp.json``, ``claude_desktop_config.json``, Cursor, VS Code
  and Cline files): servers launched through a shell, fetched at launch (``npx``, ``uvx``,
  ``docker run``), reached over the network, or given literal credentials; auto-approved tools.
* **Agent settings** (``.claude/settings*.json``): permission modes and allow rules broader than
  least privilege, and hooks, which run shell commands on agent events without a prompt.
* **Text the model reads** (skills, slash commands, subagents, instruction files such as
  ``AGENTS.md`` and ``.cursorrules``, system prompts, MCP tool descriptions): injected
  instructions and invisible characters.
* **Scripts** bundled with hooks and skills: they are code; network use is an egress path.
* **MCP server source** (Python ``mcp``/``fastmcp``, TypeScript ``@modelcontextprotocol/sdk``):
  the tools it registers, their descriptions, and what the code can reach (shell, filesystem
  writes, network, credentials, dynamic tool registration).

All of it is static pattern matching over text: nothing is run. Findings carry attributes (server,
capability, setting) so the same evidence can drive agent-configuration review (phase 2) and the
MCP gateway policy (phase 3).
"""

import posixpath
import re
from collections.abc import Callable, Iterable, Mapping
from typing import Any
from urllib.parse import urlparse

import yaml

from superscrubber104 import __version__
from superscrubber104.core.interfaces import ArtifactView, Context, Detection, Inspection
from superscrubber104.core.model import Severity, Subject, ToolRef
from superscrubber104.core.yamlio import load_untrusted_yaml
from superscrubber104.handlers.common import (
    TEST_CONTEXT,
    TEST_PATH,
    TooLarge,
    full_path,
    is_literal_secret,
    items,
    mapping,
    name_of,
    read_json,
    read_text,
)
from superscrubber104.text import scan_text

TOOL = ToolRef("superscrubber104.agents", __version__)

_MCP_CONFIG_NAMES = frozenset(
    {
        "mcp.json",
        ".mcp.json",
        "claude_desktop_config.json",
        "cline_mcp_settings.json",
        "mcp_settings.json",
        "mcp_config.json",
    }
)
_INSTRUCTION_NAMES = frozenset(
    {
        "claude.md",
        "claude.local.md",
        "agents.md",
        "gemini.md",
        ".cursorrules",
        ".windsurfrules",
        "copilot-instructions.md",
        ".clinerules",
        "conventions.md",
    }
)
_SHELLS = frozenset({"bash", "sh", "zsh", "dash", "ksh", "fish", "cmd", "powershell", "pwsh"})
_FETCHERS = frozenset({"npx", "bunx", "pnpx", "uvx", "pipx", "deno"})
_SCRIPT_EXTENSIONS = (
    ".sh",
    ".bash",
    ".zsh",
    ".py",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".ps1",
    ".rb",
    ".pl",
)
_SYSTEM_PROMPT = re.compile(r"(?i)(^|[_.-])system[_-]?prompt")
_NETWORK = re.compile(
    r"\b(?:curl|wget|nc|ncat|netcat|socat|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|scp|rsync|ftp"
    r"|telnet)\b|https?://|\brequests\.(?:get|post|put)\b|\burllib\.request\b"
    r"|(?<!def )(?<!function )\bfetch\s*\(|\bhttpx\."
)
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0", ""})  # noqa: S104 - a name, not a bind

# --- MCP server source ------------------------------------------------------------------------

_MCP_PY = re.compile(r"^\s*(?:from|import)\s+(?:mcp|fastmcp)\b", re.M)
_MCP_JS = re.compile(r"@modelcontextprotocol/(?:sdk|server)\b")
# @mcp.tool(...) [more decorators] def name(...): """docstring"""
_PY_TOOL = re.compile(
    r"@(?:\w+\.)*tool\s*\((?P<args>(?:[^()]|\([^()]*\))*)\)[ \t]*\n(?:[ \t]*@[^\n]*\n)*"
    r"[ \t]*(?:async\s+)?def\s+(?P<name>\w+)\s*\((?:[^()]|\([^()]*\))*\)"
    r"[^:\n]*:[ \t]*(?:\n\s*(?P<q>\"\"\"|''')(?P<doc>.*?)(?P=q))?",
    re.S,
)
_LITERAL_NAME = re.compile(r"""\bname\s*=\s*(['"])(?P<n>[\w.-]+)\1""")
# What a tool's name says it does, for code the scan cannot see (helpers in other modules).
_TOOL_NAME_CAPABILITY = {
    "shell": re.compile(r"(?i)(exec|shell|run_command|bash|terminal|subprocess|powershell)"),
    "filesystem-write": re.compile(
        r"(?i)(^|_)(write|delete|remove|move|rename|edit|append|create_directory|mkdir|copy)(_|$)"
    ),
    "network": re.compile(
        r"(?i)(^|_)(fetch|http|request|download|browse|navigate|web_search|url)(_|$)"
    ),
    "credentials": re.compile(r"(?i)(secret|credential|token|password|keychain)"),
    "dynamic-tools": re.compile(r"(?!x)x"),  # not visible in a tool's name
}
_JS_TOOL = re.compile(
    r"\.(?:tool|registerTool)\(\s*(['\"`])(?P<name>[^'\"`\n]+)\1\s*,\s*"
    r"(?:(['\"`])(?P<desc>(?:(?!\3).){0,4000})\3|\{(?P<body>.{0,4000}?)\})",
    re.S,
)
_NAME_DESCRIPTION = re.compile(
    r"""name\s*[:=]\s*(['"])(?P<name>[\w.-]+)\1\s*,\s*description\s*[:=]\s*(['"`])(?P<desc>(?:(?!\3).){0,4000})\3""",
    re.S,
)
_DESCRIPTION = re.compile(r"""description\s*[:=]\s*(['"`])(?P<d>(?:(?!\1).){0,4000})\1""", re.S)
_CREDENTIAL_NAME = r"(?i:token|secret|passw|api_?key|credential|auth)"
_CAPABILITIES: dict[str, tuple[Severity, dict[str, re.Pattern[str]]]] = {
    "shell": (
        Severity.HIGH,
        {
            "python": re.compile(
                r"\bsubprocess\.(?:run|Popen|call|check_call|check_output)\b|\bos\.(?:system|popen"
                r"|exec\w*|spawn\w*)\b|\bpty\.spawn\b|\bcreate_subprocess_(?:shell|exec)\b"
            ),
            "javascript": re.compile(
                r"\bchild_process\b|\bexecSync\b|\bspawnSync\b|\bexecFile\b|\bexeca\b"
            ),
        },
    ),
    "filesystem-write": (
        Severity.MEDIUM,
        {
            "python": re.compile(
                r"\bopen\([^)]*['\"][^'\"]*[wax+][^'\"]*['\"]|\.write_(?:text|bytes)\(|\bshutil\.(?:copy\w*"
                r"|move|rmtree)\b|\bos\.(?:remove|unlink|rename|replace|rmdir|makedirs)\b|\.unlink\("
            ),
            "javascript": re.compile(
                r"\bfs(?:\.promises)?\.(?:writeFile|appendFile|rm|rmdir|unlink|rename|mkdir|copyFile)"
                r"|\bwriteFileSync\b|\bappendFileSync\b|\bunlinkSync\b|\brmSync\b"
            ),
        },
    ),
    "network": (
        Severity.MEDIUM,
        {
            "python": re.compile(
                r"\brequests\.(?:get|post|put|patch|delete|head|request|Session)\b"
                r"|\b(?:httpx|aiohttp|urllib3)\.|\burllib\.request\b|\bsocket\.socket\b"
                r"|\bhttp\.client\b"
            ),
            "javascript": re.compile(
                r"(?<!function )\bfetch\s*\(|\baxios\b|\bhttps?\.(?:request|get)\b|\bnet\.connect\b"
                r"|\bnew WebSocket\b"
            ),
        },
    ),
    "credentials": (
        Severity.LOW,
        {
            # Credential-named variables, a keyring, or the whole environment handed out;
            # reading PORT or a path setting is configuration, not a credential.
            "python": re.compile(
                r"\bos\.(?:environ(?:\.get)?|getenv)\s*[\[(]\s*['\"]\w*"
                + _CREDENTIAL_NAME
                + r"|\bkeyring\b|\b(?:json\.dumps|dict)\(\s*os\.environ\b"
            ),
            "javascript": re.compile(
                r"\bprocess\.env(?:\.|\[\s*['\"`])\w*"
                + _CREDENTIAL_NAME
                + r"|\bkeytar\b|JSON\.stringify\([^)\n]*\bprocess\.env\b"
            ),
        },
    ),
    "dynamic-tools": (
        Severity.MEDIUM,
        {
            # The tool list, not the client's roots, which also announce list changes.
            "python": re.compile(
                r"\btools?_list_changed\b|tools/list_changed|\badd_tool\s*\(|\bremove_tool\s*\("
            ),
            "javascript": re.compile(
                r"\btools\s*:\s*\{\s*listChanged\b|sendToolListChanged|\.removeTool\s*\("
                r"|\.enable\(\)"
            ),
        },
    ),
}


# --- helpers ------------------------------------------------------------------------------------


def _check_prompt(ctx: Context, view: ArtifactView, text: str, locator: str | None = None) -> None:
    report = scan_text(text)
    subject = Subject.of_artifact(view.ref, locator=locator)
    discriminator = locator or ""
    if report.injections:
        ctx.recorder.fail(
            "agent.prompt.injection",
            subject,
            tool=TOOL,
            detail={"matches": [{"reason": r, "excerpt": e} for r, e in report.injections]},
            discriminator=discriminator,
        )
    else:
        ctx.recorder.passed("agent.prompt.injection")
    if report.invisible:
        ctx.recorder.fail(
            "agent.prompt.hidden-characters",
            subject,
            tool=TOOL,
            detail={"characters": [*report.invisible]},
            discriminator=discriminator,
        )
    else:
        ctx.recorder.passed("agent.prompt.hidden-characters")


def _front_matter(text: str) -> tuple[dict[str, Any], str]:
    """YAML front matter and the body. Aliases are refused; bad front matter is ignored."""
    if not text.startswith("---"):
        return {}, text
    end = text.find("\n---", 3)
    if end < 0 or end > 256 * 1024:
        return {}, text
    try:
        data = load_untrusted_yaml(text[3:end])
    except yaml.YAMLError:
        data = None
    return (data if isinstance(data, dict) else {}), text[end + 4 :]


def _tools_list(value: object) -> list[str]:
    if isinstance(value, str):
        return [t.strip() for t in value.split(",") if t.strip()]
    if isinstance(value, list):
        return [str(t) for t in value]
    return []


def _broad_tool(entry: str) -> str | None:
    """Why a permission entry is broad, or None."""
    compact = entry.replace(" ", "")
    if compact in ("*", "Bash", "Bash(*)", "Bash(:*)", "Bash(*:*)", "Shell", "shell"):
        return "unrestricted shell"
    if compact in ("WebFetch", "WebFetch(*)", "WebSearch"):
        return "unrestricted web access"
    return None


# --- MCP client configuration -------------------------------------------------------------------


def _servers(data: Mapping[str, Any]) -> dict[str, Any]:
    for path in (("mcpServers",), ("servers",), ("mcp", "servers")):
        node: Any = data
        for key in path:
            node = node.get(key) if isinstance(node, dict) else None
        if isinstance(node, dict):
            return {str(k): v for k, v in node.items() if isinstance(v, dict)}
    return {}


def _mcp_config(view: ArtifactView, ctx: Context) -> Inspection:
    data = read_json(view, 4 << 20)
    servers = _servers(data) if isinstance(data, dict) else {}
    if not servers:
        return Inspection(kind="unclassified")
    recorder = ctx.recorder
    inventory = []
    for name, server in sorted(servers.items()):
        locator = f"server {name}"
        subject = Subject.of_artifact(view.ref, locator=locator)
        attributes = {"server": name}
        command = str(server.get("command") or "")
        args = [str(a) for a in items(server.get("args")) if isinstance(a, str | int | float)]
        url = str(server.get("url") or server.get("serverUrl") or "")
        program = posixpath.basename(command.replace("\\", "/")).lower().removesuffix(".exe")
        transport = "http" if url else "stdio"
        inventory.append(
            {
                "name": name,
                "transport": transport,
                "command": program or None,
                "host": urlparse(url).hostname if url else None,
                "disabled": bool(server.get("disabled")),
            }
        )

        if program in _SHELLS or (args[:1] in (["-c"], ["/c"], ["-Command"])):
            recorder.fail(
                "mcp.server.shell",
                subject,
                tool=TOOL,
                detail={"command": command, "args": args[:20]},
                attributes=attributes,
            )
        else:
            recorder.passed("mcp.server.shell")

        fetched = (
            program in _FETCHERS
            or (program == "docker" and "run" in args)
            or (program == "uv" and args[:1] == ["run"] and "--with" in args)
        )
        if fetched:
            recorder.fail(
                "mcp.server.runtime-fetch",
                subject,
                tool=TOOL,
                detail={"command": command, "args": args[:20]},
                attributes=attributes,
            )
        else:
            recorder.passed("mcp.server.runtime-fetch")

        host = urlparse(url).hostname or "" if url else None
        if host is not None and host.lower() not in _LOCAL_HOSTS:
            recorder.fail(
                "mcp.server.remote",
                subject,
                tool=TOOL,
                detail={"url": f"{urlparse(url).scheme}://{host}"},
                attributes=attributes | {"host": host},
            )
        else:
            recorder.passed("mcp.server.remote")

        literal = [
            key
            for field in ("env", "headers")
            if isinstance(server.get(field), dict)
            for key, value in server[field].items()
            if is_literal_secret(str(key), value)
        ]
        literal += [
            f"args[{i}]"
            for i, a in enumerate(args)
            if is_literal_secret(a.split("=", 1)[0], a.split("=", 1)[-1]) and "=" in a
        ]
        if literal:
            recorder.fail(
                "mcp.config.credential",
                subject,
                tool=TOOL,
                detail={"keys": literal, "note": "values are not recorded"},
                attributes=attributes,
            )
        else:
            recorder.passed("mcp.config.credential")

        approved = _tools_list(server.get("alwaysAllow")) + _tools_list(server.get("autoApprove"))
        if approved or server.get("trust") is True:
            recorder.fail(
                "agent.permissions.broad",
                subject,
                tool=TOOL,
                detail={
                    "autoApprovedTools": approved[:50],
                    "trustAll": server.get("trust") is True,
                },
                attributes=attributes | {"setting": "auto-approve"},
            )
    return Inspection(kind="agent.mcp-config", metadata={"mcpConfig": {"servers": inventory}})


# --- agent settings -----------------------------------------------------------------------------


def _settings(view: ArtifactView, ctx: Context) -> Inspection:
    data = read_json(view, 4 << 20)
    if not isinstance(data, dict):
        return Inspection(kind="unclassified")
    recorder = ctx.recorder
    permissions = mapping(data.get("permissions"))
    broad: list[dict[str, object]] = []
    mode = permissions.get("defaultMode")
    if mode == "bypassPermissions":
        broad.append(
            {"setting": "permissions.defaultMode", "value": mode, "why": "no confirmations"}
        )
    for entry in _tools_list(permissions.get("allow")):
        why = _broad_tool(entry)
        if why:
            broad.append({"setting": "permissions.allow", "value": entry, "why": why})
    if data.get("enableAllProjectMcpServers") is True:
        broad.append(
            {
                "setting": "enableAllProjectMcpServers",
                "value": True,
                "why": "every project MCP server is trusted",
            }
        )
    if broad:
        recorder.fail(
            "agent.permissions.broad",
            Subject.of_artifact(view.ref, locator="permissions"),
            tool=TOOL,
            detail={"settings": broad},
            attributes={"setting": ",".join(sorted({str(b["setting"]) for b in broad}))},
        )
    else:
        recorder.passed("agent.permissions.broad")

    commands = []
    hooks = mapping(data.get("hooks"))
    for event, matchers in hooks.items():
        for matcher in matchers if isinstance(matchers, list) else []:
            if not isinstance(matcher, dict):
                continue
            for hook in matcher.get("hooks") or []:
                if isinstance(hook, dict) and isinstance(hook.get("command"), str):
                    commands.append(
                        {
                            "event": event,
                            "matcher": matcher.get("matcher") or "*",
                            "command": hook["command"],
                        }
                    )
    for index, hook in enumerate(commands):
        subject = Subject.of_artifact(view.ref, locator=f"hooks.{hook['event']}[{index}]")
        recorder.fail(
            "agent.hook.command",
            subject,
            tool=TOOL,
            detail=hook,
            attributes={"event": str(hook["event"])},
        )
        if _NETWORK.search(str(hook["command"])):
            recorder.fail("agent.hook.network", subject, tool=TOOL, detail=hook)
        else:
            recorder.passed("agent.hook.network")
    literal = (
        [k for k, v in (data.get("env") or {}).items() if is_literal_secret(str(k), v)]
        if isinstance(data.get("env"), dict)
        else []
    )
    if literal:
        recorder.fail(
            "mcp.config.credential",
            Subject.of_artifact(view.ref, locator="env"),
            tool=TOOL,
            detail={"keys": literal, "note": "values are not recorded"},
        )
    summary = {
        "defaultMode": mode,
        "allow": len(_tools_list(permissions.get("allow"))),
        "deny": len(_tools_list(permissions.get("deny"))),
        "hooks": len(commands),
    }
    return Inspection(kind="agent.settings", metadata={"agentSettings": summary})


# --- text the model reads -----------------------------------------------------------------------


def _markdown_agent_file(kind: str) -> Callable[[ArtifactView, Context], Inspection]:
    def handle(view: ArtifactView, ctx: Context) -> Inspection:
        text = read_text(view)
        meta, _ = _front_matter(text)
        _check_prompt(ctx, view, text)
        tools = _tools_list(meta.get("allowed-tools") or meta.get("tools"))
        broad = [t for t in tools if _broad_tool(t)]
        if broad:
            ctx.recorder.fail(
                "agent.permissions.broad",
                Subject.of_artifact(view.ref, locator="front matter"),
                tool=TOOL,
                detail={
                    "settings": [
                        {"setting": "allowed-tools", "value": t, "why": _broad_tool(t)}
                        for t in broad
                    ]
                },
                attributes={"setting": "allowed-tools"},
            )
        summary = {
            "name": meta.get("name"),
            "description": str(meta.get("description") or "")[:500],
            "tools": tools,
        }
        return Inspection(kind=kind, metadata={"agentFile": summary})

    return handle


def _prompt_text(kind: str) -> Callable[[ArtifactView, Context], Inspection]:
    def handle(view: ArtifactView, ctx: Context) -> Inspection:
        _check_prompt(ctx, view, read_text(view))
        return Inspection(kind=kind)

    return handle


def _script(view: ArtifactView, ctx: Context) -> Inspection:
    text = read_text(view, 4 << 20)
    path = f"/{full_path(view.ref)}"
    subject = Subject.of_artifact(view.ref)
    if _in_skill(view, path):
        ctx.recorder.fail(
            "agent.skill.scripts", subject, tool=TOOL, detail={"script": name_of(view.ref)}
        )
    match = _NETWORK.search(text)
    if match:
        start = text.rfind("\n", 0, match.start()) + 1
        line = text[
            start : text.find("\n", match.end()) if "\n" in text[match.end() :] else len(text)
        ]
        ctx.recorder.fail(
            "agent.hook.network", subject, tool=TOOL, detail={"line": line.strip()[:300]}
        )
    else:
        ctx.recorder.passed("agent.hook.network")
    return Inspection(kind="agent.script")


# --- MCP server source --------------------------------------------------------------------------


def _mcp_tools(text: str, language: str) -> list[tuple[str, str]]:
    tools: dict[str, str] = {}
    if language == "python":
        for m in _PY_TOOL.finditer(text):
            args = m.group("args") or ""
            described = _DESCRIPTION.search(args)
            literal = _LITERAL_NAME.search(args)
            name = literal.group("n") if literal else m.group("name")
            tools[name] = (described.group("d") if described else "") or (m.group("doc") or "")
    else:
        for m in _JS_TOOL.finditer(text):
            body = m.group("body") or ""
            described = _DESCRIPTION.search(body)
            tools[m.group("name")] = m.group("desc") or (described.group("d") if described else "")
    for m in _NAME_DESCRIPTION.finditer(text):
        tools.setdefault(m.group("name"), m.group("desc"))
    return sorted(tools.items())


def _mcp_server(view: ArtifactView, ctx: Context) -> Inspection:
    text = read_text(view, 4 << 20)
    language = "python" if name_of(view.ref).endswith(".py") else "javascript"
    marker = _MCP_PY if language == "python" else _MCP_JS
    if not marker.search(text):
        return Inspection(kind="unclassified")
    tools = _mcp_tools(text, language)
    for name, description in tools:
        if description:
            _check_prompt(ctx, view, description, locator=f"tool {name}")
    found = []
    # A server's own tests and tooling spawn processes and write files to exercise it; what they
    # do is recorded, at low severity.
    test_path = bool(TEST_PATH.search(full_path(view.ref)))
    for capability, (severity, patterns) in _CAPABILITIES.items():
        match = patterns[language].search(text)
        named = sorted(n for n, _ in tools if _TOOL_NAME_CAPABILITY[capability].search(n))
        if match is None and not named:
            ctx.recorder.passed("mcp.server.capability")
            continue
        found.append(capability)
        evidence: dict[str, object]
        if match is not None:
            line_no = text.count("\n", 0, match.start()) + 1
            line_start = text.rfind("\n", 0, match.start()) + 1
            end = text.find("\n", match.end())
            evidence = {"code": text[line_start : end if end >= 0 else None].strip()[:300]}
            locator = f"line {line_no}"
        else:
            # The code is elsewhere (a helper module); the tool names still say what it does.
            evidence, locator = {"toolNames": named[:20]}, "tool names"
        detail: dict[str, object] = {"capability": capability, "evidence": evidence}
        if test_path:
            detail["context"] = TEST_CONTEXT
        ctx.recorder.fail(
            "mcp.server.capability",
            Subject.of_artifact(view.ref, locator=locator),
            tool=TOOL,
            detail=detail,
            attributes={"capability": capability, "language": language},
            severity=Severity.LOW if test_path else severity,
            discriminator=capability,
        )
    summary = {"language": language, "tools": [n for n, _ in tools], "capabilities": found}
    return Inspection(kind="agent.mcp-server", metadata={"mcpServer": summary})


# --- dispatch -----------------------------------------------------------------------------------


def _in_skill(view: ArtifactView, path: str) -> bool:
    """A file in an agent skill: under ``skills/<name>/`` where that folder holds a SKILL.md (an
    application's own ``skills`` package is not one), or anywhere under ``.claude/skills/``."""
    parts = path.strip("/").split("/")
    at = [i for i, part in enumerate(parts[:-2]) if part == "skills"]
    if not at:
        return False
    i = at[-1]
    if i > 0 and parts[i - 1] == ".claude":
        return True
    below = len(parts) - (i + 3)  # folders between the skill's folder and the file
    return view.resolve("../" * below + "SKILL.md") is not None


def _dispatch(view: ArtifactView) -> Callable[[ArtifactView, Context], Inspection] | None:
    name = name_of(view.ref)
    lowered = name.lower()
    path = f"/{full_path(view.ref)}"
    if lowered in _MCP_CONFIG_NAMES or (
        lowered.endswith(".json") and "mcp" in lowered and "/." in path
    ):
        return _mcp_config
    if (
        path.endswith(("/.claude/settings.json", "/.claude/settings.local.json"))
        or lowered == "managed-settings.json"
    ):
        return _settings
    if name == "SKILL.md":
        return _markdown_agent_file("agent.skill")
    if lowered.endswith(".md") and "/.claude/commands/" in path:
        return _markdown_agent_file("agent.command")
    if lowered.endswith(".md") and "/.claude/agents/" in path:
        return _markdown_agent_file("agent.subagent")
    if (
        lowered in _INSTRUCTION_NAMES
        or (lowered.endswith((".mdc", ".md")) and "/.cursor/rules/" in path)
        or lowered.endswith(".instructions.md")
    ):
        return _prompt_text("agent.instructions")
    if (
        _SYSTEM_PROMPT.search(lowered)
        and lowered.endswith((".txt", ".md", ".j2", ".jinja", ".prompt", ".tmpl"))
    ) or lowered.endswith((".prompt", ".prompty")):
        return _prompt_text("agent.system-prompt")
    if lowered.endswith(_SCRIPT_EXTENSIONS) and (
        "/.claude/hooks/" in path
        or _in_skill(view, path)
        or ("/hooks/" in path and "/.claude/" in path)
    ):
        return _script
    if lowered.endswith((".py", ".js", ".mjs", ".cjs", ".ts", ".mts")) and view.size < 4 << 20:
        head = view.head(65536).decode("utf-8", "replace")
        if _MCP_PY.search(head) or _MCP_JS.search(head):
            return _mcp_server
    return None


class AgentHandler:
    name = "agents"
    version = "1"
    kinds = frozenset(
        {
            "agent.mcp-config",
            "agent.settings",
            "agent.skill",
            "agent.command",
            "agent.subagent",
            "agent.instructions",
            "agent.system-prompt",
            "agent.script",
            "agent.mcp-server",
        }
    )

    def detect(self, artifact: ArtifactView) -> Detection | None:
        return Detection("agent", 70) if _dispatch(artifact) else None

    def inspect(self, artifact: ArtifactView, ctx: Context) -> Inspection:
        handle = _dispatch(artifact)
        assert handle is not None  # noqa: S101 - only called after detect()
        try:
            return handle(artifact, ctx)
        except TooLarge as exc:
            return Inspection(kind="unclassified", metadata={"agents": {"skipped": str(exc)}})
        except (ValueError, UnicodeDecodeError) as exc:
            return Inspection(
                kind="unclassified", metadata={"agents": {"unreadable": str(exc)[:200]}}
            )


def handlers() -> Iterable[AgentHandler]:
    return (AgentHandler(),)
