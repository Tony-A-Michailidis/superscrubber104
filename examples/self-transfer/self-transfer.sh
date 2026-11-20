#!/usr/bin/env bash
# superscrubber104 crosses its own airlock.
#
#   examples/self-transfer/self-transfer.sh [WORK_DIR]
#
# Low side (connected): build superscrubber104's wheel, download the wheels it depends on, lock
# them by hash, and pack them into a signed bundle with superscrubber104 itself.
# High side (no network): check the first crossing with standard tools only (sha256sum and pip's
# hash checking), install from the bundle, then let the installed superscrubber104 verify the
# signed bundle it arrived in. See README.md beside this script for the trust chain.
#
# Needs bash, python3 (3.11+) with venv, sha256sum, and network access for the low side. The high
# side runs inside `unshare -rn` (a network namespace with no interfaces) when the kernel allows
# it; otherwise it says so and runs with pip's --no-index only.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="${1:-$(mktemp -d)}"
PYTHON="${PYTHON:-python3}"
SOURCE=build-net
ENCLAVE=enclave-high

step() { printf '\n== %s ==\n' "$*"; }
run() { printf '$ %s\n' "$*"; "$@"; }

rm -rf "$WORK"
mkdir -p "$WORK"
cd "$WORK"
echo "Working in $WORK"

step "1. Low side: the operator's own copy of superscrubber104"
"$PYTHON" -m venv low-venv
low-venv/bin/python -m pip install --quiet --upgrade pip
low-venv/bin/python -m pip install --quiet "$REPO"
LOW=low-venv/bin/superscrubber104
run "$LOW" --version

step "2. Low side: build the delivery (superscrubber104 and the wheels it depends on)"
mkdir -p delivery/wheels
low-venv/bin/python -m pip wheel --quiet --no-deps --wheel-dir delivery/wheels "$REPO"
# Exactly the versions the low side runs, as wheels only: nothing is built on the high side.
low-venv/bin/python -m pip freeze --exclude superscrubber104 --exclude pip > pins.txt
low-venv/bin/python -m pip download --quiet --only-binary=:all: --no-deps \
  --dest delivery/wheels --requirement pins.txt
# A lock with every wheel's hash, so pip installs these files and nothing else.
low-venv/bin/python - delivery <<'EOF'
import hashlib, sys
from pathlib import Path

root = Path(sys.argv[1])
lines = []
for wheel in sorted((root / "wheels").glob("*.whl")):
    name, version = wheel.name.split("-")[:2]
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    lines.append(f"{name}=={version} --hash=sha256:{digest}")
(root / "requirements.txt").write_text("\n".join(lines) + "\n")
print("\n".join(lines))
EOF
# Checksums any high side can check before it has superscrubber104.
(cd delivery && sha256sum requirements.txt wheels/*.whl > SHA256SUMS)
ANCHOR="$(sha256sum delivery/SHA256SUMS | cut -d' ' -f1)"
echo "SHA256SUMS digest, to send out of band: $ANCHOR"

step "3. Keys and policies"
run "$LOW" keygen -o keys --name pack --holder build-pipeline | tee keygen.txt
KEY_ID="$(sed -n 's/.*key id: \([^ ]*\).*/\1/p' keygen.txt | head -1)"
PIN="$(sha256sum keys/pack.pub | cut -d' ' -f1)"
mkdir -p low high
cat > request.yaml <<EOF
apiVersion: superscrubber104/v1alpha1
kind: TransferRequest
metadata: {id: TR-SELF-001, title: superscrubber104 crosses its own airlock}
spec:
  purpose: Install superscrubber104 on the disconnected side
  owner: {name: Tooling team}
  source: $SOURCE
  destination: $ENCLAVE
  direction: low-to-high
  stream: superscrubber104
  contents:
    - {name: superscrubber104, paths: ["**"]}
EOF
LICENCES='licences:
  allow: [Apache-2.0, MIT, MIT-0, BSD-3-Clause, "Apache-2.0 OR BSD-3-Clause"]'
cat > low/policy.yaml <<EOF
apiVersion: superscrubber104/v1alpha1
kind: Policy
metadata: {name: low-side, version: '1'}
$LICENCES
EOF
cat > high/policy.yaml <<EOF
apiVersion: superscrubber104/v1alpha1
kind: Policy
metadata: {name: high-side, version: '1'}
identity: {enclave: $ENCLAVE, acceptSources: [$SOURCE]}
transfer: {maxBundleAge: 30d}
trust:
  signers:
    - keyId: "$KEY_ID"
      publicKey: pack.pub
      sha256: "$PIN"
      holder: build-pipeline
      roles: [pack]
      sources: [$SOURCE]
$LICENCES
EOF
cp keys/pack.pub high/pack.pub   # the public key travels ahead of time, like the anchor

step "4. Low side: superscrubber104 packs itself"
set +e
run "$LOW" pack delivery --request request.yaml --key keys/pack.key --policy low/policy.yaml \
  -o bundle | tail -4
PACKED=${PIPESTATUS[0]}
set -e
echo "[pack exit $PACKED]"

step "5. Carry it across: only the bundle, the public key and the anchor"
mkdir -p media
cp -r bundle media/bundle
cp -r high media/high
echo "$ANCHOR" > media/anchor.txt

step "6. High side, with no network"
HIGH_SIDE="$(cat <<'EOF'
set -euo pipefail
cd media
if "$PYTHON" -c 'import socket; socket.create_connection(("pypi.org", 443), 5)' 2>/dev/null; then
  echo "pypi.org is reachable: this is not a disconnected side"
  [ "${ALLOW_NETWORK:-}" = 1 ] || exit 4
else
  echo "no network: pypi.org cannot be reached"
fi
printf '\n-- 6a. check the first crossing with standard tools --\n'
echo "expected: $(cat anchor.txt)"
echo "actual:   $(sha256sum bundle/payload/SHA256SUMS | cut -d' ' -f1)"
test "$(sha256sum bundle/payload/SHA256SUMS | cut -d' ' -f1)" = "$(cat anchor.txt)"
(cd bundle/payload && sha256sum --check --quiet SHA256SUMS) && echo "every file matches SHA256SUMS"
printf '\n-- 6b. install from the bundle, offline, every wheel checked against its hash --\n'
"$PYTHON" -m venv high-venv
high-venv/bin/python -m pip install --quiet --no-index --find-links bundle/payload/wheels \
  --require-hashes --requirement bundle/payload/requirements.txt
high-venv/bin/superscrubber104 --version
printf '\n-- 6c. the installed superscrubber104 verifies the signed bundle it came in --\n'
set +e
high-venv/bin/superscrubber104 verify bundle --policy high/policy.yaml --state high/state \
  --out high/import-1 > verify.txt
code=$?
set -e
grep -v '^wrote' verify.txt | tail -2
echo "[verify exit $code]"
exit "$code"
EOF
)"
TAMPERED="$(cat <<'EOF'
set -uo pipefail
cd tampered
wheel="$(ls bundle/payload/wheels/cryptography-*.whl)"
printf 'x' >> "$wheel"
echo "appended one byte to ${wheel#bundle/payload/}"
(cd bundle/payload && sha256sum --check --quiet SHA256SUMS) && exit 1
"$PYTHON" -m venv venv
if venv/bin/python -m pip install --quiet --no-index --find-links bundle/payload/wheels \
  --require-hashes --requirement bundle/payload/requirements.txt > pip.txt 2>&1; then
  echo "pip installed the altered wheel"
  exit 1
fi
grep -m1 "DO NOT MATCH" pip.txt
echo "pip refused the altered wheel; nothing was installed"
test ! -x venv/bin/superscrubber104
EOF
)"
export PYTHON
set +e
if unshare -rn true 2>/dev/null; then
  unshare -rn bash -c "$HIGH_SIDE"
elif [ "${REQUIRE_NO_NETWORK:-}" = 1 ]; then
  echo "unshare -rn is not available, and REQUIRE_NO_NETWORK=1"
  exit 4
else
  echo "unshare -rn is not available here: running with pip --no-index only"
  ALLOW_NETWORK=1 bash -c "$HIGH_SIDE"
fi
VERIFIED=$?
set -e

step "7. The same media, altered in transit: the first-crossing checks refuse it"
cp -r media tampered
set +e
bash -c "$TAMPERED"
CAUGHT=$?
set -e

step "Result"
echo "pack exit $PACKED, verify exit $VERIFIED, tampered copy refused: $([ $CAUGHT = 0 ] && echo yes || echo NO)"
[ "$VERIFIED" = 0 ] && [ "$CAUGHT" = 0 ]
