# Quick start: install and run the demo on WSL (AlmaLinux 9 or 10)

This guide installs airlock under the Windows Subsystem for Linux, runs its tests, runs the demo, and then packs and verifies a small delivery of your own. It takes about ten minutes on a connected machine.

## 1. Get AlmaLinux in WSL

From Windows PowerShell:

```powershell
wsl --list --online               # shows the exact distribution names
wsl --install -d AlmaLinux-10     # or AlmaLinux-9
```

Open the AlmaLinux shell. `wsl -l -v` from PowerShell shows which distributions you have.

## 2. Install Git and Python

airlock needs Python 3.11 or later.

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

Clone the repository into the Linux filesystem; working under `/mnt/c` is much slower. If your checkout is on the Windows side, for example `C:\src\airlock`, clone that:

```bash
git config --global --add safe.directory /mnt/c/src/airlock   # Git refuses a repo owned by your Windows user without this
git clone /mnt/c/src/airlock ~/airlock
cd ~/airlock
```

To pick up later changes made on the Windows side: `cd ~/airlock && git pull`.

## 4. Install airlock

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[dev]"
airlock --help
```

Run `source ~/airlock/.venv/bin/activate` in every new shell. `[dev]` adds pytest, ruff and mypy; to run airlock without them, `pip install .` is enough.

## 5. Run the tests

```bash
pytest
```

Expect about 720 passed and 2 skipped, in under a minute. The two skipped tests read zstd-compressed Zarf packages and Hauler hauls, which needs Python 3.14 (see step 8).

## 6. Run the demo

```bash
python examples/demo/demo.py ~/airlock-demo
```

The demo plays both sides of an air gap with the `airlock` command:

1. **Keys:** a build pipeline's packing key, pinned in the receiving side's policy.
2. **Low side:** packs a delivery (a small model, a vendored wheel, an app, an MCP server, a knowledge-base corpus and an evaluation set) into a signed bundle.
3. **High side:** verifies the bundle, which is accepted.
4. **In transit:** someone tampers with the bundle. They change a model shard, add a file and plant a malicious pickle.
5. **High side:** verifies again, and the bundle is refused.

It ends like this:

```text
== Result ==
  tampered shard   caught: integrity.hash.mismatch on models/tiny-chat/model-00002-of-00002.safetensors
  undeclared file  caught: integrity.entry.unexpected on app/patch-notes.txt
  pickle payload   caught: model.pickle.dangerous-import on models/tiny-chat/training_args.bin
  clean import accepted (exit 0); tampered import refused (exit 3)
  and the ledger noticed the same bundle id arriving a second time, altered
```

Each import directory under `~/airlock-demo/` holds the evidence:
* `report.html`;
* `sbom.cdx.json` (CycloneDX with an ML-BOM);
* `oscal.json`;
* the assessment and the receipt.

To open them in Windows:

```bash
explorer.exe ~/airlock-demo/import-2
```

## 7. Try it on your own files

```bash
mkdir -p ~/try/delivery/app && cd ~/try
printf 'requests==2.32.3\n' > delivery/app/requirements.txt
printf 'print("hello")\n'   > delivery/app/main.py

# a signing key for the packing side (it prints a policy snippet that pins it)
airlock keygen -o keys --name pack --holder build-pipeline

# inspect in place, without packing: works on any content, not only models
airlock model inspect delivery

# pack into a signed bundle
airlock pack delivery --key keys/pack.key -o bundle

# verify as the receiving side, keeping a ledger of imports
airlock verify bundle --pubkey keys/pack.pub --state high-state --out import-1

# render the evidence: md, html, json, cyclonedx or oscal
airlock report import-1 -f html -o import-1/report.html
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
| 3 | refused: integrity or authenticity failed (never overridable) |

Without `--policy`, the built-in default policy is used. `airlock rules` lists every check, and the same list is in [rules.md](rules.md).

## 8. Optional: Python 3.14, for Zarf packages and Hauler hauls

Zarf and Hauler compress with zstd by default. Python reads zstd from 3.14, and airlock adds no dependency for it. On an older Python, such a package is still hashed and recorded, but its contents are reported as "not assessed".

AlmaLinux has no Python 3.14 package; `uv` installs one. On a connected machine:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
source ~/.bashrc
uv python install 3.14
cd ~/airlock
uv venv -p 3.14 .venv314
source .venv314/bin/activate
uv pip install -e ".[dev]"
pytest            # the two zstd tests now run too
```

## 9. Optional: external scanners

ClamAV, Trivy, Semgrep, Bandit, qemu-img and osslsigncode run as optional plugins. Each must be pinned by hash in a policy before airlock will run it. See [scanners.md](scanners.md). On AlmaLinux:
* ClamAV comes from EPEL (`sudo dnf install -y epel-release && sudo dnf install -y clamav`);
* qemu-img comes from AppStream (`sudo dnf install -y qemu-img`).

## Troubleshooting

| Symptom | Fix |
|---|---|
| `fatal: detected dubious ownership` when cloning | `git config --global --add safe.directory <path>` (step 3) |
| `airlock: command not found` | activate the environment: `source ~/airlock/.venv/bin/activate` |
| pip says `requires a different Python` | on AlmaLinux 9 the venv was made with the system 3.9; recreate it with `python3.12 -m venv .venv` |
| zstd archives reported "not assessed" | expected before Python 3.14 (step 8) |
| everything is slow | the clone is under `/mnt/c`; clone into `~` instead (step 3) |
