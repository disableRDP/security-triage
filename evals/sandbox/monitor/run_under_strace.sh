#!/usr/bin/env bash
# Run every script in <skill>/scripts under strace, one trace file each.
# usage: run_under_strace.sh <skill_dir> <out_dir> [timeout_seconds]
skill="$1"; out="$2"; limit="${3:-20}"
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
    -o "$out/$name.trace" "${interp[@]}" "$f" > "$out/$name.stdout" 2> "$out/$name.stderr"
  echo "$name exit=$?" >> "$out/exit_codes.txt"
done
