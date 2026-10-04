#!/usr/bin/env bash
# Tier 4: run a skill's own scripts/*.py and scripts/*.sh in a locked-down
# container under strace, then analyze what they tried to do. OPT-IN: this
# executes untrusted code, so it only runs with TRIAGE_EXECUTE=1.
#
# usage: sandbox_run.sh <target_dir> <out_dir> <skill_dir> [<skill_dir> ...]
#   every <skill_dir> must be inside <target_dir>.
#
# Writes <out_dir>/dynamic/result.json = {"status", "detail", "output"}; the
# caller (triage.sh) turns that into a manifest entry. Exit codes:
#   0 ran / partial   2 skipped (Docker unavailable, nothing to run)
#   3 not requested   4 error   5 REFUSED: containment probe failed
#
# Design (why each piece exists is in evals/sandbox/README.md):
#   --network none      the only mode verified fully contained (--internal
#                       reaches the host; Harbor's default resolves DNS)
#   root tracer + setpriv  a same-uid script can truncate its own strace file
#   cap-drop ALL, no-new-privileges, read-only rootfs, pids/mem/cpu limits
#   traces stream out over stdout as a tar: the container needs no writable
#   host mount, so the suspect has nothing on the host to tamper with
#   containment probe   runs first, in an identical container, as the script
#                       user; any failed or unevaluable check = refuse to run
set -uo pipefail

TARGET="${1:-}"; OUT="${2:-}"; shift 2 2>/dev/null || true
SKILLS=("$@")
HERE="$(cd "$(dirname "$0")" && pwd)"
SANDBOX_DIR="$HERE/../evals/sandbox"
PER_SCRIPT_TIMEOUT="${TRIAGE_EXEC_TIMEOUT:-20}"

pick_python() {
  for c in python3 python py; do
    command -v "$c" >/dev/null 2>&1 || continue
    "$c" --version >/dev/null 2>&1 && { echo "$c"; return 0; }
  done
  return 1
}
PY="$(pick_python)" || { echo "error: no working python interpreter" >&2; exit 4; }

if [[ -z "$TARGET" || -z "$OUT" || ${#SKILLS[@]} -eq 0 ]]; then
  echo "usage: sandbox_run.sh <target_dir> <out_dir> <skill_dir>..." >&2
  exit 4
fi
DYN="$OUT/dynamic"; mkdir -p "$DYN"

finish() {  # finish <exit> <status> <detail> [output]
  "$PY" - "$2" "$3" "${4:-}" > "$DYN/result.json" <<'PY'
import json, sys
print(json.dumps({"status": sys.argv[1], "detail": sys.argv[2], "output": sys.argv[3]}))
PY
  exit "$1"
}

if [[ "${TRIAGE_EXECUTE:-0}" != "1" ]]; then
  finish 3 skipped "execution not requested: set TRIAGE_EXECUTE=1 to run skill scripts in a sandbox (this executes untrusted code)"
fi

# Nothing to run? Don't even touch Docker. Files we will not execute are
# named so a clean result is not read as "the whole skill was exercised".
runnable=0; notrun=()
for s in "${SKILLS[@]}"; do
  [[ -d "$s/scripts" ]] || continue
  for f in "$s"/scripts/*; do
    [[ -f "$f" ]] || continue
    case "$f" in
      *.py|*.sh) runnable=$((runnable+1)) ;;
      *) notrun+=("${f#"$TARGET"/}") ;;
    esac
  done
done
if [[ $runnable -eq 0 ]]; then
  finish 2 skipped "no scripts/*.py or scripts/*.sh in any skill, so nothing to execute (install hooks such as package.json/setup.py are never executed by this tier)"
fi

# `docker info`, not `command -v docker`: a CLI with no running daemon is the common case.
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  finish 2 skipped "Docker is not installed or its daemon is not running - script execution was not performed; static tiers stand alone"
fi

export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'   # Git Bash must not rewrite /target etc.
hostpath() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi; }
# Native Windows Python cannot open MSYS paths like /tmp/x, so every path handed to $PY goes through this.
pypath() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi; }

TAG="triage-sandbox:$("$PY" - "$(pypath "$SANDBOX_DIR")" <<'PY'
import hashlib, os, sys
h = hashlib.sha256()
for root in ("image", "monitor"):
    for dp, _, fs in sorted(os.walk(os.path.join(sys.argv[1], root))):
        for f in sorted(fs):
            h.update(f.encode()); h.update(open(os.path.join(dp, f), "rb").read())
print(h.hexdigest()[:12])
PY
)"
if ! docker image inspect "$TAG" >/dev/null 2>&1; then
  echo "building sandbox image $TAG ..." >&2
  docker build -q -t "$TAG" -f "$(hostpath "$SANDBOX_DIR/image/Dockerfile")" "$(hostpath "$SANDBOX_DIR")" >"$DYN/build.log" 2>&1 \
    || finish 4 ran-with-errors "sandbox image build failed, see dynamic/build.log" "$DYN/build.log"
fi

# A listener on the HOST. If the sandbox can reach it, the sandbox is not contained.
python_listener_port="$DYN/listener.port"
"$PY" -c '
import http.server, sys
s = http.server.ThreadingHTTPServer(("0.0.0.0", 0), http.server.SimpleHTTPRequestHandler)
open(sys.argv[1], "w").write(str(s.server_address[1]))
s.serve_forever()' "$python_listener_port" >/dev/null 2>&1 &
LISTENER=$!
cleanup() { kill "$LISTENER" 2>/dev/null; docker rm -f $(docker ps -aq --filter "name=triage-sbx-$$-") >/dev/null 2>&1 || true; }
trap cleanup EXIT
for _ in $(seq 1 50); do [[ -s "$python_listener_port" ]] && break; sleep 0.1; done
PROBE_PORT="$(cat "$python_listener_port" 2>/dev/null || true)"

# Identical for the probe and for the scripts. Only the command differs.
# (setpriv --reset-env wipes the container env, so the probe's port is passed after `env` in $DROP.)
sandbox_flags=(
  --user 0 --network none
  --cap-drop ALL --cap-add SETUID --cap-add SETGID --cap-add SYS_PTRACE
  --security-opt no-new-privileges --read-only
  --tmpfs /tmp:rw,mode=1777 --tmpfs /workspace:rw,mode=1777 --tmpfs /trace:rw,mode=0755
  --pids-limit 128 --memory 512m --cpus 1
  -v "$(hostpath "$TARGET"):/target:ro"
)
DROP='setpriv --reuid=sandbox --regid=sandbox --init-groups --reset-env env PYTHONDONTWRITEBYTECODE=1'

# docker_timed <seconds> <name> <stdout_file> <stderr_file> -- <docker run args...>; echoes exit code.
docker_timed() {
  local secs="$1" name="$2" so="$3" se="$4"; shift 5
  docker run --rm --name "$name" "$@" >"$so" 2>"$se" &
  local pid=$!
  # Watchdog polls instead of one long sleep, and has its output detached:
  # a lingering `sleep` holding this function's stdout open would block the
  # caller's $(...) until it expired (found by running it, not by reading it).
  ( for ((i = 0; i < secs; i++)); do kill -0 "$pid" 2>/dev/null || exit 0; sleep 1; done
    docker kill "$name" >/dev/null 2>&1 ) >/dev/null 2>&1 &
  local dog=$!
  wait "$pid"; local rc=$?
  kill "$dog" 2>/dev/null; wait "$dog" 2>/dev/null
  echo "$rc"
}

summary=(); gaps=(); executed=0; n=0
for s in "${SKILLS[@]}"; do
  [[ -d "$s/scripts" ]] || continue
  rel="${s#"$TARGET"}"; rel="${rel#/}"
  n=$((n+1)); d="$DYN/$n"; mkdir -p "$d"
  count="$(find "$s/scripts" -maxdepth 1 -type f \( -name '*.py' -o -name '*.sh' \) | wc -l)"
  [[ "$count" -gt 0 ]] || continue

  # 1. containment probe, same flags, same user the scripts will run as
  rc="$(docker_timed 60 "triage-sbx-$$-probe$n" "$d/probe.json" "$d/probe.err" -- \
        "${sandbox_flags[@]}" "$TAG" $DROP "PROBE_HOST_PORT=$PROBE_PORT" python3 /monitor/containment_probe.py)"
  if [[ "$rc" != "0" ]]; then
    failed="$("$PY" -c '
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    print("; ".join(c["name"] + " (" + c["detail"] + ")" for c in d["checks"] if not c["ok"]))
except Exception:
    print("probe produced no result (exit " + sys.argv[2] + "), see " + sys.argv[1] + " / .err")' "$(pypath "$d/probe.json")" "$rc")"
    finish 5 ran-with-errors "REFUSED to execute anything: the containment probe failed in this environment, so nothing was run and no dynamic result is reported. Failed checks: $failed" "$d/probe.json"
  fi

  # 2. the scripts, one container per skill, traces streamed back as a tar
  limit=$(( count * PER_SCRIPT_TIMEOUT + 60 ))
  rc="$(docker_timed "$limit" "triage-sbx-$$-run$n" "$d/trace.tar" "$d/run.err" -- \
        "${sandbox_flags[@]}" -e RUN_AS=sandbox "$TAG" bash -c \
        '/monitor/run_under_strace.sh "$1" /trace "$2"; tar -C /trace -cf - .' _ "/target/$rel" "$PER_SCRIPT_TIMEOUT")"
  mkdir -p "$d/trace"
  "$PY" - "$(pypath "$d/trace.tar")" "$(pypath "$d/trace")" <<'PY' || gaps+=("skill $rel: trace output unreadable")
import os, sys, tarfile
# The tar comes from inside the sandbox: take regular files by bare name only.
with tarfile.open(sys.argv[1]) as t:
    for m in t.getmembers():
        name = os.path.basename(m.name)
        if m.isfile() and name == m.name.lstrip("./") and name not in ("", ".", ".."):
            with open(os.path.join(sys.argv[2], name), "wb") as fh:
                fh.write(t.extractfile(m).read())
PY
  if [[ "$rc" == "137" && ! -f "$d/trace/exit_codes.txt" ]]; then
    gaps+=("skill $rel: the sandbox hit its overall time limit (${limit}s) and was killed; no results were recovered")
    continue
  fi
  "$PY" "$(pypath "$SANDBOX_DIR/monitor/analyze_trace.py")" "$(pypath "$d/trace")" > "$d/analysis.json" 2>>"$d/run.err" \
    || { gaps+=("skill $rel: trace analysis failed, see $d/run.err"); continue; }
  executed=$((executed+count))
  line="$("$PY" - "$(pypath "$d/analysis.json")" "$rel" <<'PY'
import json, sys
a = json.load(open(sys.argv[1]))
per = ", ".join(f"{k}={v['verdict']}" for k, v in a["scripts"].items())
print(f"{sys.argv[2] or '.'}: {per or 'no scripts'}")
for g in a["coverage_gaps"]:
    print("GAP " + sys.argv[2] + ": " + g)
PY
)"
  while IFS= read -r l; do
    case "$l" in GAP\ *) gaps+=("${l#GAP }") ;; *) summary+=("$l") ;; esac
  done <<< "$line"
done

[[ ${#notrun[@]} -gt 0 ]] && gaps+=("not executed (not .py/.sh): ${notrun[*]:0:5}")
detail="executed $executed script(s) with no arguments under --network none, containment probe passed before each run. Dynamic results (never a safety verdict; an argument- or time-gated payload is invisible here): ${summary[*]-}"
if [[ ${#gaps[@]} -gt 0 ]]; then
  gapstr="$(printf '%s; ' "${gaps[@]}")"
  finish 0 partial "$detail. COVERAGE GAPS: $gapstr" "$DYN"
fi
finish 0 ran "$detail" "$DYN"
