"""airlock demo: a mixed AI delivery crosses the gap, then someone tampers with it in transit.

    python examples/demo/demo.py [WORKDIR]

1. Builds a small but complete delivery: a sharded chat model with its tokenizer, chat template,
   card and licence; the application that serves it; a pinned Python wheel; an MCP server and
   its client configuration; a folder of documents declared as a knowledge-base corpus; an
   evaluation set.
2. Packs it on the "low side" and verifies it on the "high side": accepted.
3. Tampers with the bundle as someone with access to the transfer media could: changes bytes in
   one model shard, slips in an undeclared file, and adds a pickle whose payload would run a
   shell command if anything ever unpickled it (airlock never does).
4. Verifies again: refused, with all three caught, and renders the evidence as reports.

Everything is synthetic and generated here; nothing is downloaded and nothing is executed. Exit
code 0 means the demo behaved as described.
"""

import base64
import hashlib
import io
import json
import re
import shutil
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

SOURCE, ENCLAVE = "dev-unclass", "enclave-b"
_DTYPE = {"F16": 2, "F32": 4}


# --- the delivery -------------------------------------------------------------------------------


def safetensors(tensors: dict[str, tuple[str, list[int]]]) -> bytes:
    header: dict[str, object] = {"__metadata__": {"format": "pt"}}
    offset = 0
    for name, (dtype, shape) in tensors.items():
        size = _DTYPE[dtype]
        for d in shape:
            size *= d
        header[name] = {"dtype": dtype, "shape": shape, "data_offsets": [offset, offset + size]}
        offset += size
    raw = json.dumps(header).encode()
    raw += b" " * (-len(raw) % 8)
    data = bytes((i * 7) % 251 for i in range(offset))  # deterministic, not all zeros
    return struct.pack("<Q", len(raw)) + raw + data


def wheel(name: str, version: str) -> bytes:
    dist = f"{name}-{version}.dist-info"
    files = {
        f"{name}/__init__.py": b"def tidy(text):\n    return ' '.join(text.split())\n",
        f"{dist}/METADATA": (
            f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\n"
            "Summary: text helpers\nLicense-Expression: MIT\n"
        ).encode(),
        f"{dist}/WHEEL": (
            b"Wheel-Version: 1.0\nGenerator: demo\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ),
    }

    def record(data: bytes) -> str:
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        return f"sha256={digest}"

    lines = "".join(f"{p},{record(d)},{len(d)}\n" for p, d in files.items()) + f"{dist}/RECORD,,\n"
    files[f"{dist}/RECORD"] = lines.encode()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for path, data in files.items():
            archive.writestr(zipfile.ZipInfo(path, (2026, 1, 1, 0, 0, 0)), data)
    return buffer.getvalue()


def build_delivery(root: Path) -> None:
    vocab, hidden = 32, 8
    shard1 = {
        "model.embed_tokens.weight": ("F16", [vocab, hidden]),
        "model.layers.0.self_attn.q_proj.weight": ("F16", [hidden, hidden]),
    }
    shard2 = {
        "model.layers.1.self_attn.q_proj.weight": ("F16", [hidden, hidden]),
        "model.norm.weight": ("F16", [hidden]),
        "lm_head.weight": ("F16", [vocab, hidden]),
    }
    a, b = safetensors(shard1), safetensors(shard2)
    data_bytes = sum(len(s) - 8 - int.from_bytes(s[:8], "little") for s in (a, b))
    weight_map = {t: "model-00001-of-00002.safetensors" for t in shard1}
    weight_map |= {t: "model-00002-of-00002.safetensors" for t in shard2}
    template = (
        "{% for m in messages %}<|{{ m['role'] }}|>\n{{ m['content'] }}\n{% endfor %}"
        "{% if add_generation_prompt %}<|assistant|>\n{% endif %}"
    )
    wheel_bytes = wheel("tidytext", "1.2.0")
    files: dict[str, bytes | str] = {
        # the model, in Hugging Face layout
        "models/tiny-chat/model-00001-of-00002.safetensors": a,
        "models/tiny-chat/model-00002-of-00002.safetensors": b,
        "models/tiny-chat/model.safetensors.index.json": json.dumps(
            {"metadata": {"total_size": data_bytes}, "weight_map": weight_map}
        ),
        "models/tiny-chat/config.json": json.dumps(
            {
                "architectures": ["LlamaForCausalLM"],
                "model_type": "llama",
                "vocab_size": vocab,
                "hidden_size": hidden,
                "num_hidden_layers": 2,
                "torch_dtype": "float16",
                "_name_or_path": "example-org/tiny-chat",
            }
        ),
        "models/tiny-chat/tokenizer.json": json.dumps(
            {"model": {"type": "BPE", "vocab": {f"t{i}": i for i in range(vocab)}}}
        ),
        "models/tiny-chat/tokenizer_config.json": json.dumps(
            {"tokenizer_class": "LlamaTokenizer", "chat_template": template}
        ),
        "models/tiny-chat/README.md": (
            "---\nlicense: apache-2.0\npipeline_tag: text-generation\n---\n# Tiny chat\n\n"
            "## Intended use\n\nThe airlock demo.\n\n## Limitations\n\nIt knows nothing.\n"
        ),
        "models/tiny-chat/LICENSE": "                                 Apache License\n"
        "                           Version 2.0, January 2004\n",
        # the application, its dependency and its offline settings
        "app/chat.py": (
            "from transformers import AutoModelForCausalLM, AutoTokenizer\n\n"
            'MODEL = "models/tiny-chat"\n'
            "tokenizer = AutoTokenizer.from_pretrained(MODEL)\n"
            "model = AutoModelForCausalLM.from_pretrained(MODEL)\n"
        ),
        "app/requirements.txt": (
            f"tidytext==1.2.0 --hash=sha256:{hashlib.sha256(wheel_bytes).hexdigest()}\n"
        ),
        "app/.env": "HF_HUB_OFFLINE=1\nTRANSFORMERS_OFFLINE=1\nHF_HUB_DISABLE_TELEMETRY=1\n",
        "vendor/tidytext-1.2.0-py3-none-any.whl": wheel_bytes,
        # an MCP server that searches the policy documents, and its client configuration
        "mcp/docs_server.py": (
            "from pathlib import Path\n\nfrom mcp.server.fastmcp import FastMCP\n\n"
            'server = FastMCP("policy-docs")\n\n\n'
            "@server.tool()\n"
            "def search_docs(query: str) -> str:\n"
            '    """Find the policy documents that mention the query."""\n'
            '    docs = sorted(Path("rag/docs").glob("*.md"))\n'
            "    hits = [d.name for d in docs if query.lower() in d.read_text().lower()]\n"
            '    return "\\n".join(hits)\n'
        ),
        ".mcp.json": json.dumps(
            {"mcpServers": {"policy-docs": {"command": "python", "args": ["mcp/docs_server.py"]}}},
            indent=2,
        ),
        # documents a knowledge base will be built from (declared as such in the request)
        "rag/docs/leave.md": "# Leave\n\nRequest leave two weeks ahead through your manager.\n",
        "rag/docs/travel.md": "# Travel\n\nBook travel through the travel desk; keep receipts.\n",
        # an evaluation set that crosses with the model
        "eval/smoke.yaml": (
            "apiVersion: airlock/v1alpha1\nkind: EvalSet\nmetadata: {name: smoke}\nspec:\n"
            "  model: models/tiny-chat\n  settings: {temperature: 0, seed: 42}\n"
            "  cases:\n    - id: greeting\n      prompt: Say hello.\n"
            "      expect: {contains: hello}\n"
        ),
    }
    for path, data in files.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data.encode() if isinstance(data, str) else data)


REQUEST = f"""\
apiVersion: airlock/v1alpha1
kind: TransferRequest
metadata: {{id: TR-2026-042, title: Policy assistant release 1.0}}
spec:
  purpose: Deploy the policy assistant on the classified network
  owner: {{name: Assistant team}}
  source: {SOURCE}
  destination: {ENCLAVE}
  direction: low-to-high
  stream: policy-assistant
  contents:
    - {{name: chat-model, paths: ["models/tiny-chat/**"], unit: model-package}}
    - {{name: application, paths: ["app/**", "vendor/**", "mcp/**", ".mcp.json"]}}
    - {{name: policy-corpus, paths: ["rag/docs/**"], unit: knowledge-base}}
    - {{name: evaluation, paths: ["eval/**"]}}
"""


def policy(name: str, signer: str = "") -> str:
    return (
        f"apiVersion: airlock/v1alpha1\nkind: Policy\nmetadata: {{name: {name}, version: '1'}}\n"
        + (
            f"identity: {{enclave: {ENCLAVE}, acceptSources: [{SOURCE}]}}\n"
            "transfer: {maxBundleAge: 30d}\n" + signer
            if signer
            else ""
        )
        + "licences:\n  allow: [Apache-2.0, MIT]\n"
    )


# --- running it ---------------------------------------------------------------------------------


def airlock(work: Path, *args: str, show: int = 40) -> tuple[int, str]:
    """Run the airlock CLI as an operator would, and print what they would see."""
    print(f"\n$ airlock {' '.join(args)}")
    proc = subprocess.run(  # noqa: S603 - the demo runs airlock itself
        [sys.executable, "-m", "airlock", *args],
        cwd=work,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    output = (proc.stdout + proc.stderr).rstrip()
    lines = output.splitlines()
    for line in lines[:show]:
        print(f"  {line}")
    if len(lines) > show:
        print(f"  ... ({len(lines) - show} more lines)")
        for line in lines[show:]:  # the counts and the verdict are always worth seeing
            if "rules exercised" in line or line.startswith("verdict:"):
                print(f"  {line}")
    print(f"  [exit {proc.returncode}]")
    return proc.returncode, output


def main(work: Path) -> int:
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    print(f"Working in {work}")
    build_delivery(work / "delivery")
    (work / "request.yaml").write_text(REQUEST, encoding="utf-8")
    (work / "low").mkdir()
    (work / "low" / "policy.yaml").write_text(policy("low-side"), encoding="utf-8")

    print("\n== 1. Keys: the build pipeline's packing key ==")
    _, out = airlock(
        work, "keygen", "-o", "keys", "--name", "pack", "--holder", "build-pipeline", show=3
    )
    key_id = re.search(r"key id: (\S+)", out)
    if key_id is None:
        print("keygen did not print a key id")
        return 1
    pin = hashlib.sha256((work / "keys" / "pack.pub").read_bytes()).hexdigest()
    signer = (
        "trust:\n  signers:\n"
        f'    - keyId: "{key_id.group(1)}"\n      publicKey: ../keys/pack.pub\n'
        f'      sha256: "{pin}"\n      holder: build-pipeline\n      roles: [pack]\n'
        f"      sources: [{SOURCE}]\n"
    )
    (work / "high").mkdir()
    (work / "high" / "policy.yaml").write_text(policy("high-side", signer), encoding="utf-8")

    print("\n== 2. Low side: pack the delivery ==")
    packed, _ = airlock(
        work, "pack", "delivery", "--request", "request.yaml", "--key", "keys/pack.key",
        "--policy", "low/policy.yaml", "-o", "bundle", show=12,
    )  # fmt: skip

    print("\n== 3. High side: verify the bundle as it arrived ==")
    clean, _ = airlock(
        work, "verify", "bundle", "--policy", "high/policy.yaml", "--state", "high/state",
        "--out", "import-1", show=12,
    )  # fmt: skip
    airlock(work, "report", "import-1", "--format", "html", "-o", "import-1/report.html", show=2)
    airlock(
        work, "report", "import-1", "--format", "cyclonedx", "-o", "import-1/sbom.cdx.json", show=2
    )
    airlock(work, "report", "import-1", "--format", "oscal", "-o", "import-1/oscal.json", show=2)

    print("\n== 4. In transit: someone with access to the media tampers with the bundle ==")
    payload = work / "bundle" / "payload"
    shard = payload / "models" / "tiny-chat" / "model-00002-of-00002.safetensors"
    data = bytearray(shard.read_bytes())
    data[-16:] = b"\xff" * 16  # a few weights changed; the file still parses
    shard.write_bytes(bytes(data))
    print(f"  changed 16 bytes of {shard.relative_to(work).as_posix()}")
    (payload / "app" / "patch-notes.txt").write_text("trust me\n", encoding="utf-8")
    print("  added app/patch-notes.txt, which no one declared")
    # A pickle whose payload calls os.system: raw opcodes, never unpickled by anything here.
    pickled = b"\x80\x02cos\nsystem\nq\x00X\x0c\x00\x00\x00echo pwned!!q\x01\x85q\x02Rq\x03."
    (payload / "models" / "tiny-chat" / "training_args.bin").write_bytes(pickled)
    print("  added models/tiny-chat/training_args.bin, a pickle that would run a shell command")

    print("\n== 5. High side: verify the tampered bundle ==")
    tampered, _ = airlock(
        work, "verify", "bundle", "--policy", "high/policy.yaml", "--state", "high/state",
        "--out", "import-2", show=30,
    )  # fmt: skip
    airlock(work, "report", "import-2", "--format", "md", "-o", "import-2/report.md", show=2)
    airlock(work, "report", "import-2", "--format", "html", "-o", "import-2/report.html", show=2)

    assessment = json.loads(
        (work / "import-2" / "assessment.verify.json").read_text(encoding="utf-8")
    )
    failed = {
        (f["rule"], f["subject"].get("artifact", {}).get("path"))
        for f in assessment["findings"]
        if f["result"] == "fail"
    }
    caught = {
        "tampered shard": (
            "integrity.hash.mismatch",
            "models/tiny-chat/model-00002-of-00002.safetensors",
        ),
        "undeclared file": ("integrity.entry.unexpected", "app/patch-notes.txt"),
        "pickle payload": ("model.pickle.dangerous-import", "models/tiny-chat/training_args.bin"),
    }
    print("\n== Result ==")
    ok = packed == 0 and clean == 0 and tampered == 3
    for what, finding in caught.items():
        found = finding in failed
        ok &= found
        print(f"  {what:<16} {'caught' if found else 'MISSED'}: {finding[0]} on {finding[1]}")
    print(f"  clean import accepted (exit {clean}); tampered import refused (exit {tampered})")
    if ("replay.bundle.already-accepted", None) in failed:
        print("  and the ledger noticed the same bundle id arriving a second time, altered")
    print(f"  reports: {(work / 'import-1').as_posix()}/ and {(work / 'import-2').as_posix()}/")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1] if len(sys.argv) > 1 else "airlock-demo").resolve()))
