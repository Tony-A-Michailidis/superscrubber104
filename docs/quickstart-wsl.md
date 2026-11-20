# Quick start: install and run the demo on WSL (AlmaLinux 9 or 10)

This guide installs superscrubber104 under the Windows Subsystem for Linux, runs its tests, runs the demo, and then packs and verifies a small delivery of your own. It takes about ten minutes on a connected machine.

## 1. Get AlmaLinux in WSL

From Windows PowerShell:

```powershell
wsl --list --online               # shows the exact distribution names
wsl --install -d AlmaLinux-10     # or AlmaLinux-9
```

Open the AlmaLinux shell. `wsl -l -v` from PowerShell shows which distributions you have.

## 2. Install Git and Python

superscrubber104 needs Python 3.11 or later.

**AlmaLinux 10:** the system Python is 3.12.

```bash
sudo dnf install -y git python3 python3-pip
python3 --version
```

**AlmaLinux 9:** the system Python is 3.9, which is too old. Install 3.12 alongside it:

```bash
sudo dnf install -y git python3.12 python3.12-pip
python3.12 --version
```

Below, `python3.12` means `python3` on AlmaLinux 10.

## 3. Get the code

Clone into the Linux filesystem (your home directory), not under `/mnt/c`, which is much slower:

```bash
git clone https://github.com/Tony-A-Michailidis/airlock ~/superscrubber104
cd ~/superscrubber104
```

To pick up later changes: `cd ~/superscrubber104 && git pull`.

## 4. Install superscrubber104

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[dev]"
superscrubber104 --help
```

Run `source ~/superscrubber104/.venv/bin/activate` in every new shell. `[dev]` adds pytest, ruff and mypy; to run superscrubber104 without them, `pip install .` is enough.

## 5. Run the tests

```bash
pytest
```

Expect about 735 passed and a few skipped, in under a minute. Two of the skipped tests read zstd-compressed Zarf packages and Hauler hauls, which needs Python 3.14 or the `zstd` extra (see step 8).

## 6. Run the demo

```bash
python examples/demo/demo.py ~/superscrubber104-demo
```

The demo plays both sides of an air gap with the `superscrubber104` command:

1. **Keys:** a build pipeline's packing key, pinned in the receiving side's policy.
2. **Low side:** packs a delivery (a small model, a vendored wheel, an app, an MCP server, a knowledge-base corpus and an evaluation set) into a signed bundle.
3. **High side:** verifies the bundle, which is accepted.
4. **In transit:** someone tampers with the bundle. They change a model shard, add a file and plant a malicious pickle.
5. **High side:** verifies again, and the bundle is refused.

The full output of a run is in [examples/demo/sample-output.md](../examples/demo/sample-output.md). It ends like this:

```text
== Result ==
  tampered shard   caught: integrity.hash.mismatch on models/tiny-chat/model-00002-of-00002.safetensors
  undeclared file  caught: integrity.entry.unexpected on app/patch-notes.txt
  pickle payload   caught: model.pickle.dangerous-import on models/tiny-chat/training_args.bin
  clean import accepted (exit 0); tampered import refused (exit 3)
  and the ledger noticed the same signed bundle arriving a second time
```

Each import directory under `~/superscrubber104-demo/` holds the evidence:
* `report.html`;
* `sbom.cdx.json` (CycloneDX with an ML-BOM);
* `oscal.json`;
* the assessment and the receipt.

To open them in Windows:

```bash
explorer.exe ~/superscrubber104-demo/import-2
```

## 7. Try it on your own files

```bash
mkdir -p ~/try/delivery/app && cd ~/try
printf 'requests==2.32.3\n' > delivery/app/requirements.txt
printf 'print("hello")\n'   > delivery/app/main.py

# a signing key for the packing side (it prints a policy snippet that pins it)
superscrubber104 keygen -o keys --name pack --holder build-pipeline

# inspect in place, without packing: works on any content, not only models
superscrubber104 model inspect delivery

# pack into a signed bundle
superscrubber104 pack delivery --key keys/pack.key -o bundle

# verify as the receiving side, keeping a ledger of imports
superscrubber104 verify bundle --pubkey keys/pack.pub --state high-state --out import-1

# render the evidence: md, html, json, cyclonedx or oscal
superscrubber104 report import-1 -f html -o import-1/report.html
explorer.exe import-1
```

This sample ends `BLOCKED` with exit code 1, and that is the correct result:
* `requirements.txt` asks for `requests`, but the delivery doesn't carry it (`python.environment.unresolvable`). A disconnected host could not install it.
* The requirement is not pinned by hash.
* No scanners are configured, so malware, vulnerability and static-analysis checks are recorded as "not assessed" rather than left out.

Add the wheels with hashes, or have an approval quorum override the blocker, and the result changes.

Exit codes are the same for every command:

| Code | Meaning |
|---|---|
| 0 | accepted |
| 1 | a policy blocker or an open gap (overridable by approvals) |
| 2 | usage error |
| 3 | refused: integrity or authenticity failed, or the tool failed part-way (never overridable) |

Without `--policy`, the built-in default policy is used. `superscrubber104 rules` lists every check, and the same list is in [rules.md](rules.md).

## 8. Optional: zstd, for Zarf packages and Hauler hauls

Zarf and Hauler compress with zstd by default. Python reads zstd from 3.14; before that, superscrubber104's optional `zstd` extra adds the backport of the same module. Without either, such a package is still hashed and recorded, but its contents are reported as "not assessed".

The simplest way, on the Python you already have:

```bash
cd ~/superscrubber104
pip install -e ".[dev,zstd]"
pytest            # the two zstd tests now run too
```

Or use Python 3.14 itself. AlmaLinux has no Python 3.14 package; `uv` installs one. On a connected machine:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
source ~/.bashrc
uv python install 3.14
cd ~/superscrubber104
uv venv -p 3.14 .venv314
source .venv314/bin/activate
uv pip install -e ".[dev]"
pytest            # the two zstd tests now run too
```

## 9. Optional: external scanners

ClamAV, Trivy, Semgrep, Bandit, qemu-img and osslsigncode run as optional plugins. Each must be pinned by hash in a policy before superscrubber104 will run it. See [scanners.md](scanners.md). On AlmaLinux:
* ClamAV comes from EPEL (`sudo dnf install -y epel-release && sudo dnf install -y clamav`);
* qemu-img comes from AppStream (`sudo dnf install -y qemu-img`).

## Troubleshooting

| Symptom | Fix |
|---|---|
| `superscrubber104: command not found` | activate the environment: `source ~/superscrubber104/.venv/bin/activate` |
| pip says `requires a different Python` | on AlmaLinux 9 the venv was made with the system 3.9; recreate it with `python3.12 -m venv .venv` |
| zstd archives reported "not assessed" | expected before Python 3.14 without the `zstd` extra (step 8) |
| everything is slow | the clone is under `/mnt/c`; clone into `~` instead (step 3) |
