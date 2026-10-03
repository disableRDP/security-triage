#!/usr/bin/env bash
# Build a Harbor task that runs one skill's scripts under strace with no network.
# usage: make_task.sh <skill_dir> <task_dir>
set -euo pipefail
skill="$1"; task="$2"
here="$(cd "$(dirname "$0")/.." && pwd)"
name="$(basename "$skill")"
harden="${HARDEN:-0}"
agent_user="sandbox"; [ "$harden" = "1" ] && agent_user="root"
rm -rf "$task"; mkdir -p "$task/environment" "$task/solution" "$task/tests"

cp -r "$skill" "$task/environment/skill"
cp -r "$here/monitor" "$task/environment/monitor"
{ cat "$here/image/Dockerfile" | grep -v '^USER sandbox$' | grep -v '^WORKDIR'
  echo 'COPY skill /skill'
  echo 'USER sandbox'
  echo 'WORKDIR /workspace'; } > "$task/environment/Dockerfile"

cat > "$task/task.toml" <<TOML
schema_version = "1.1"

[task]
name = "triage-sandbox/$name"
description = "Observe what a skill's scripts attempt when run with no network."

[agent]
timeout_sec = 120.0
user = "$agent_user"

[verifier]
timeout_sec = 60.0
user = "root"

[environment]
build_timeout_sec = 600.0
cpus = 1
memory_mb = 512
storage_mb = 2048
network_mode = "no-network"
TOML

echo "Run the skill's scripts under observation. (The oracle agent ignores this text.)" > "$task/instruction.md"

if [ "$harden" = "1" ]; then
  { echo '#!/bin/bash'; echo 'RUN_AS=sandbox /monitor/run_under_strace.sh /skill /tmp/strace 20'; } > "$task/solution/solve.sh"
  cat > "$task/environment/docker-compose.yaml" <<'YML'
services:
  main:
    network_mode: none
    pids_limit: 128
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - NET_RAW
      - MKNOD
      - SETFCAP
      - AUDIT_WRITE
      - SYS_CHROOT
YML
else
  { echo '#!/bin/bash'; echo '/monitor/run_under_strace.sh /skill /tmp/strace 20'; } > "$task/solution/solve.sh"
fi

cat > "$task/tests/test.sh" <<'SH'
#!/bin/bash
mkdir -p /logs/verifier
python3 /monitor/analyze_trace.py /tmp/strace > /logs/verifier/ioc_report.json
cp /tmp/strace/*.stdout /logs/verifier/ 2>/dev/null
python3 - <<'PY'
import json
d = json.load(open("/logs/verifier/ioc_report.json"))
rank = {"clean": 0, "review": 1, "high": 2}
json.dump({
    "verdict_rank": rank[d["verdict"]],
    "ioc_count": sum(len(s["iocs"]) for s in d["scripts"].values()),
    "coverage_gaps": len(d["coverage_gaps"]),
}, open("/logs/verifier/reward.json", "w"))
PY
SH
chmod +x "$task/solution/solve.sh" "$task/tests/test.sh"
