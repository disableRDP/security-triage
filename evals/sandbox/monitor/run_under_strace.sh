#!/usr/bin/env bash
# Run every script in <skill>/scripts under strace, one trace file each.
# usage: run_under_strace.sh <skill_dir> <out_dir> [timeout_seconds]
skill="$1"; out="$2"; limit="${3:-20}"
# Interpreters otherwise try to write .pyc caches into their read-only install dir,
# which shows up as a flood of fake "write outside workspace" events.
export PYTHONDONTWRITEBYTECODE=1
# RUN_AS=<user>: the tracer stays root and a setpriv wrapper drops the *script* to <user>
# (with HOME/USER reset), so the script cannot open, truncate or kill the tracer or its
# trace file. (strace -u was tried first and did NOT drop the tracee's privileges here: a
# tamper canary running under it truncated a root-owned trace.)
drop=(); [ -n "${RUN_AS:-}" ] && drop=(setpriv --reuid="$RUN_AS" --regid="$RUN_AS" --init-groups --reset-env env PYTHONDONTWRITEBYTECODE=1)
mkdir -p "$out"
for f in "$skill"/scripts/*; do
  [ -f "$f" ] || continue
  name="$(basename "$f")"
  case "$f" in
    *.py) interp=(python3) ;;
    *.sh) interp=(bash) ;;
    *) continue ;;
  esac
  timeout --signal=KILL "$limit" strace -f -qq -s 200 -e trace=file,network,process \
    -o "$out/$name.trace" "${drop[@]}" "${interp[@]}" "$f" > "$out/$name.stdout" 2> "$out/$name.stderr"
  echo "$name exit=$?" >> "$out/exit_codes.txt"
done
