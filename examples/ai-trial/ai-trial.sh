#!/usr/bin/env bash
# A repeatable real-world trial: public AI assets, every source pinned, run through
# superscrubber104 from inspection to verification.
#
#   examples/ai-trial/ai-trial.sh WORK_DIR
#
# Builds WORK_DIR/delivery (about 1.3 GB) from a Hugging Face model in five formats, the dataset it
# was fine-tuned on, the official MCP reference servers and an agent configuration that starts one
# of them. Then inspects it, writes and checks a transfer request, packs and verifies it. Results
# are in WORK_DIR; README.md beside this script records what a run found.
#
# Needs bash, python3 (3.11+) with venv, git, network access, and superscrubber104 on PATH (or
# SUPERSCRUBBER104 set to the command to run it).
set -euo pipefail

WORK="${1:?usage: ai-trial.sh WORK_DIR}"
PYTHON="${PYTHON:-python3}"
SS="${SUPERSCRUBBER104:-superscrubber104}"

MODEL=distilbert/distilbert-base-uncased-finetuned-sst-2-english
MODEL_REV=714eb0fa89d2f80546fda750413ed43d93601a13
DATASET=stanfordnlp/sst2
DATASET_REV=8d51e7e4887a4caaa95b3fbebbf53c0490b58bbb
SERVERS=https://github.com/modelcontextprotocol/servers.git
SERVERS_REV=c799c8552b0f27b7a33a7b9233773da144dddcf5

step() { printf '\n== %s ==\n' "$*"; }
ss() { $SS "$@"; }  # word-split on purpose: SS may be a command with arguments
summary() {  # the counts, then one line per rule that blocks or needs approval
    grep -m1 "rules exercised" "$1"
    grep -E "^(BLOCK|NEEDS APPROVAL|REFUSE)" "$1" | awk '{print $1, $2, $3}' | sed 's/ \[.*//' \
        | sort | uniq -c | sort -rn || true
}

mkdir -p "$WORK"
cd "$WORK"
if [ -e delivery ]; then
    echo "$WORK/delivery exists; use an empty directory"
    exit 2
fi

step "1. A downloader, kept apart from superscrubber104"
"$PYTHON" -m venv hf
hf/bin/python -m pip install --quiet --disable-pip-version-check --upgrade huggingface_hub
hf/bin/python -c 'import huggingface_hub as h; print("huggingface_hub", h.__version__)'

step "2. The delivery, every source pinned"
mkdir delivery
hf/bin/hf download "$MODEL" --revision "$MODEL_REV" \
    --local-dir delivery/models/distilbert-sst2 >> download.log 2>&1
hf/bin/hf download "$DATASET" --repo-type dataset --revision "$DATASET_REV" \
    --local-dir delivery/datasets/sst2 >> download.log 2>&1
git init --quiet delivery/mcp/servers
git -C delivery/mcp/servers fetch --quiet --depth 1 "$SERVERS" "$SERVERS_REV"
git -C delivery/mcp/servers checkout --quiet FETCH_HEAD
rm -rf delivery/mcp/servers/.git
cat > delivery/.mcp.json <<'EOF'
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/srv/data"]
    }
  }
}
EOF
echo "$(find delivery -type f | wc -l) files, $(du -sh delivery | cut -f1)"

set +e
step "3. Inspect it in place"
ss model inspect delivery --out inspect > inspect.txt
echo "[inspect exit $?]"
summary inspect.txt
ss report inspect -f html -o inspect/report.html > /dev/null

step "4. The transfer request"
ss request init -o request.yaml --from delivery --source dev-unclass --destination enclave-b \
    > /dev/null
ss request show request.yaml --delivery delivery | tail -1
echo "[show exit ${PIPESTATUS[0]}]"

step "5. Pack, then verify as the receiving side"
ss keygen -o keys --name pack --holder build-pipeline > /dev/null 2>&1
ss pack delivery --request request.yaml --key keys/pack.key -o bundle --link > pack.txt
echo "[pack exit $?]"
ss verify bundle --pubkey keys/pack.pub --state state --out import > verify.txt
echo "[verify exit $?]"
summary verify.txt
ss report import -f html -o import/report.html > /dev/null
echo
echo "Reports: $WORK/inspect/report.html and $WORK/import/report.html"
