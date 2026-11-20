"""Scale test: pack and verify a large synthetic delivery, and measure time and peak memory.

    python examples/scale/scale.py WORK_DIR [--small 100000] [--large-gib 8] [--shard-gib 2]
                                            [--members 50000]

Builds a delivery under WORK_DIR with:

* ``--small`` small source and text files spread over nested directories;
* model weights totalling ``--large-gib`` GiB as safetensors shards, random-filled (incompressible,
  so nothing is faster than it would be with real weights);
* a zip with ``--members`` members, and a gzipped tar of the small files' first thousand;

then runs ``superscrubber104 keygen``, ``pack --link`` and ``verify``, each as its own process,
and prints wall time, throughput and peak resident memory for each. Peak memory is the point:
superscrubber104 hashes and parses by streaming, so it should not grow with the size of the files.

Needs disk space for the delivery (``--large-gib`` plus a little); ``--link`` hard-links the files
into the bundle instead of copying them. Linux or WSL (it reads peak memory with ``resource``).
"""

import argparse
import io
import json
import os
import resource
import struct
import subprocess
import sys
import tarfile
import time
import zipfile
from pathlib import Path

CHUNK = 1 << 20


def small_files(root: Path, count: int) -> int:
    total = 0
    for i in range(count):
        directory = root / "app" / f"pkg{i // 1000:03d}" / f"mod{(i // 50) % 20:02d}"
        directory.mkdir(parents=True, exist_ok=True)
        if i % 3 == 0:
            body = f"# notes {i}\n\n" + "Some documentation text that is not code.\n" * (i % 7 + 1)
            path = directory / f"notes{i}.md"
        else:
            body = f'"""Module {i}."""\n\n\ndef f{i}(x: int) -> int:\n    return x + {i}\n'
            path = directory / f"m{i}.py"
        path.write_text(body, encoding="utf-8")
        total += len(body)
    return total


def safetensors_shard(path: Path, tensor: str, size: int) -> int:
    """One F32 tensor of about ``size`` bytes, random-filled (incompressible); its byte size."""
    elements = size // 4
    header = json.dumps(
        {tensor: {"dtype": "F32", "shape": [elements], "data_offsets": [0, elements * 4]}}
    ).encode()
    header += b" " * (-len(header) % 8)
    with path.open("wb") as out:
        out.write(struct.pack("<Q", len(header)) + header)
        remaining = elements * 4
        while remaining:
            n = min(CHUNK * 16, remaining)
            out.write(os.urandom(n))
            remaining -= n
    return elements * 4


def model(root: Path, gib: float, shard_gib: float) -> int:
    target = root / "models" / "big-model"
    target.mkdir(parents=True)
    total = int(gib * (1 << 30))
    shards = max(1, round(gib / shard_gib))
    names = [f"model-{i + 1:05d}-of-{shards:05d}.safetensors" for i in range(shards)]
    weight_map, written = {}, 0
    for i, name in enumerate(names):
        tensor = f"model.layers.{i}.weight"
        written += safetensors_shard(target / name, tensor, total // shards)
        weight_map[tensor] = name
    (target / "model.safetensors.index.json").write_text(
        json.dumps({"metadata": {"total_size": written}, "weight_map": weight_map}),
        encoding="utf-8",
    )
    (target / "config.json").write_text(
        json.dumps({"architectures": ["LlamaForCausalLM"], "model_type": "llama"}), encoding="utf-8"
    )
    (target / "README.md").write_text(
        "---\nlicense: apache-2.0\n---\n\n# big-model\n\nSynthetic weights for a scale test.\n",
        encoding="utf-8",
    )
    return written


def archives(root: Path, members: int) -> None:
    target = root / "archives"
    target.mkdir()
    with zipfile.ZipFile(target / "many-members.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        for i in range(members):
            archive.writestr(f"docs/{i // 1000:03d}/page{i}.txt", f"page {i}\n" * 4)
    with tarfile.open(target / "sources.tar.gz", "w:gz") as archive:
        for path in sorted((root / "app").rglob("*"))[:1000]:
            if path.is_file():
                data = path.read_bytes()
                info = tarfile.TarInfo(path.relative_to(root).as_posix())
                info.size, info.mtime = len(data), 0
                archive.addfile(info, io.BytesIO(data))


def measure(args: list[str]) -> int:
    """Run one command and print its peak resident memory (this process's only child)."""
    code = subprocess.run(args, check=False).returncode  # noqa: S603 - superscrubber104 itself
    peak_kib = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    print(f"PEAK_RSS_KIB={peak_kib}", file=sys.stderr)
    return code


def run(work: Path, name: str, *args: str) -> tuple[int, float, int, str]:
    command = [sys.executable, __file__, "--measure", sys.executable, "-m", "superscrubber104"]
    start = time.monotonic()
    proc = subprocess.run(  # noqa: S603 - the scale test runs superscrubber104 itself
        [*command, *args], cwd=work, capture_output=True, text=True, check=False
    )
    elapsed = time.monotonic() - start
    peak = next(
        int(line.split("=", 1)[1])
        for line in proc.stderr.splitlines()
        if line.startswith("PEAK_RSS_KIB=")
    )
    tail = [
        line for line in proc.stdout.splitlines() if "rules exercised" in line or "verdict" in line
    ]
    (work / f"{name}.txt").write_text(proc.stdout + proc.stderr, encoding="utf-8")
    return proc.returncode, elapsed, peak, "\n".join(tail)


def size_of(root: Path) -> tuple[int, int]:
    files = [p for p in root.rglob("*") if p.is_file()]
    return len(files), sum(p.stat().st_size for p in files)


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--measure":
        return measure(sys.argv[2:])
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("work", type=Path)
    parser.add_argument("--small", type=int, default=100_000)
    parser.add_argument("--large-gib", type=float, default=8)
    parser.add_argument("--members", type=int, default=50_000)
    parser.add_argument("--shard-gib", type=float, default=2, help="size of each weights file")
    options = parser.parse_args()
    work: Path = options.work.resolve()
    if work.exists() and any(work.iterdir()):
        parser.error(f"{work} is not empty")
    delivery = work / "delivery"
    delivery.mkdir(parents=True)

    start = time.monotonic()
    small_files(delivery, options.small)
    model(delivery, options.large_gib, options.shard_gib)
    archives(delivery, options.members)
    count, total = size_of(delivery)
    print(
        f"delivery: {count} files, {total / (1 << 30):.2f} GiB "
        f"(built in {time.monotonic() - start:.0f} s)"
    )

    keygen = ("keygen", "-o", "keys", "--name", "pack", "--holder", "scale")
    if run(work, "keygen", *keygen)[0] != 0:
        print("keygen failed")
        return 1
    print(f"\n{'step':8} {'exit':>4} {'wall':>9} {'MiB/s':>8} {'peak RSS':>10}")
    results = {}
    for name, args in (
        ("pack", ("pack", "delivery", "--key", "keys/pack.key", "-o", "bundle", "--link")),
        ("verify", ("verify", "bundle", "--pubkey", "keys/pack.pub", "--out", "import")),
    ):
        code, elapsed, peak, tail = run(work, name, *args)
        rate = total / (1 << 20) / elapsed
        print(f"{name:8} {code:>4} {elapsed:>8.0f}s {rate:>8.0f} {peak / 1024:>8.0f} MiB")
        results[name] = (code, tail)
    for name, (_, tail) in results.items():
        print(f"\n{name}: {tail}")
    return 0 if all(code in (0, 1) for code, _ in results.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
