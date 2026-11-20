"""Offline readiness: downloads, telemetry, updates, cloud AI and external images."""

import json
from pathlib import Path

from click.testing import CliRunner

from superscrubber104.cli import main
from superscrubber104.core.model import Finding, Result, Severity
from tests.models_helpers import findings_of, inspect
from tests.software_fixtures import docker_archive, write

MAIN = """\
import gradio as gr
import nltk
import tiktoken
from langchain_openai import ChatOpenAI
from openai import OpenAI
from transformers import AutoModel, AutoTokenizer

model = AutoModel.from_pretrained("example-org/missing-model")
tokenizer = AutoTokenizer.from_pretrained("models/tiny")
cached = AutoModel.from_pretrained("example-org/other", local_files_only=True)
llm = ChatOpenAI(model="gpt-4o")
local = OpenAI(base_url="http://localhost:8000/v1", api_key="unused")
nltk.download("punkt")
encoding = tiktoken.get_encoding("cl100k_base")
URL = "https://api.anthropic.com/v1/messages"
DOCS = "https://docs.vendor-tools.io/reference"
"""

FILES: dict[str, bytes | str] = {
    "app/main.py": MAIN,
    "app/.env": "GRADIO_ANALYTICS_ENABLED=False\n",
    "models/tiny/config.json": json.dumps({"model_type": "bert", "architectures": ["BertModel"]}),
    "deploy/docker-compose.yml": (
        "services:\n  llm:\n    image: ollama/ollama:0.3.12\n"
        "  app:\n    image: registry.example.org/team/app:1.0\n"
    ),
    "deploy/Dockerfile": (
        "FROM python:3.12-slim AS build\nRUN pip install -r requirements.txt\n"
        'FROM build\nCMD ["python", "main.py"]\n'
    ),
    "deploy/entrypoint.sh": "#!/bin/sh\nollama pull llama3\nexec ollama serve\n",
    "deploy/network.yaml": "dns:\n  servers: [8.8.8.8]\n",
    ".vscode/settings.json": '{\n  // team settings\n  "telemetry.telemetryLevel": "all"\n}\n',
    "venv/lib/python3.12/site-packages/lib/hub.py": 'x = M.from_pretrained("org/x")\n',
    "images/app.tar": docker_archive(cmd=["sh", "-c", "ollama pull llama3 && ollama serve"]),
}


def _by_rule(found: dict[str, list[Finding]]) -> dict[str, list[tuple[str, str]]]:
    return {
        rule: sorted(
            (f.subject.display, str(f.detail.get("what") or f.detail.get("setting") or ""))
            for f in fs
            if f.result is Result.FAIL
        )
        for rule, fs in found.items()
        if rule.startswith("offline.")
    }


def test_offline_readiness(tmp_path: Path) -> None:
    found = findings_of(inspect(write(tmp_path / "d", FILES)))
    rules = _by_rule(found)

    downloads = {d for d, _ in rules["offline.download.runtime"]}
    assert {
        "app/main.py#line 8",  # example-org/missing-model is not delivered
        "app/main.py#line 13",  # nltk.download
        "app/main.py",  # tiktoken without TIKTOKEN_CACHE_DIR
        "deploy/Dockerfile#line 2",  # the build installs
        "deploy/entrypoint.sh#line 2",  # ollama pull
        "images/app.tar#image registry.example.org/team/app:1.0",  # pulls when it starts
    } == downloads
    hub = next(f for f in found["offline.download.runtime"] if f.subject.display.endswith("line 8"))
    assert hub.detail["model"] == "example-org/missing-model"

    cloud = {
        (d, f.severity) for f in found["offline.endpoint.cloud-ai"] for d in [f.subject.display]
    }
    assert cloud == {
        ("app/main.py#line 11", Severity.MEDIUM),
        ("app/main.py#line 15", Severity.HIGH),
    }

    # the delivered app image is found by its tag; the others would be pulled
    assert sorted(str(f.detail["image"]) for f in found["offline.registry.external"]) == [
        "ollama/ollama:0.3.12",
        "python:3.12-slim",  # the Dockerfile's base image (its build stage is not an image)
    ]
    fixes = {k for f in found["offline.config.missing"] for k in f.detail["fix"]}
    assert {"HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE", "NLTK_DATA"} <= fixes
    telemetry = rules["offline.telemetry.enabled"]
    assert [d for d, _ in telemetry] == [
        ".vscode/settings.json#telemetry.telemetryLevel"
    ]  # gradio is off
    assert {d for d, _ in rules["offline.update.enabled"]} == {
        ".vscode/settings.json#extensions.autoUpdate",
        ".vscode/settings.json#extensions.autoCheckUpdates",
        ".vscode/settings.json#update.mode",
    }
    assert rules["offline.network.public-service"][0][0] == "deploy/network.yaml#line 2"
    [external] = found["offline.endpoint.external"]
    assert [h["host"] for h in external.detail["hosts"]] == [
        "api.anthropic.com",
        "docs.vendor-tools.io",
    ]
    assert not any("site-packages" in d for fs in rules.values() for d, _ in fs)


def test_offline_check_command(tmp_path: Path) -> None:
    root = write(tmp_path / "d", FILES)
    result = CliRunner().invoke(main, ["offline-check", str(root)])
    assert result.exit_code == 1, result.output
    assert "Will break on a network with no internet:" in result.output
    assert "HF_HUB_OFFLINE=1" in result.output and "TIKTOKEN_CACHE_DIR=" in result.output
    assert '"telemetry.telemetryLevel": off' in result.output

    clean = write(tmp_path / "e", {"app/main.py": "print('hello')\n"})
    result = CliRunner().invoke(main, ["offline-check", str(clean), "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["verdict"] == "passed"
