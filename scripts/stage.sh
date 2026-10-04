#!/usr/bin/env bash
# Normalize a triage input (local dir, git URL, zip, or registry reference)
# to a local directory path, WITHOUT executing any install/build/postinstall
# step. Prints the staged path, or REGISTRY:<ecosystem>:<name>[@version] for
# a registry reference, to stdout. Everything else goes to stderr.
set -euo pipefail

pick_python() {
  for c in python3 python py; do
    command -v "$c" >/dev/null 2>&1 || continue
    "$c" --version >/dev/null 2>&1 && { echo "$c"; return 0; }
  done
  return 1
}
PY="$(pick_python)" || { echo "error: no working python interpreter found (tried python3, python, py)" >&2; exit 1; }

input="${1:-}"
if [[ -z "$input" ]]; then
  echo "usage: stage.sh <local-path|git-url|zip-path|ecosystem:name[@version]>" >&2
  exit 1
fi

# TRIAGE_CLONE_DEPTH=full fetches the whole history (needed for TRIAGE_GIT_HISTORY=1 in
# triage.sh, which scans past commits for secrets that were committed and later removed).
# The default stays a depth-1 clone: full history costs time and disk on big repos.
depth_args=(--depth 1)
[[ "${TRIAGE_CLONE_DEPTH:-}" == "full" ]] && depth_args=()

STAGE_ROOT="${TRIAGE_STAGE_ROOT:-${TMPDIR:-/tmp}/security-triage-stage}"
mkdir -p "$STAGE_ROOT"

# Registry reference: npm:left-pad, pypi:requests@2.0.0, go:..., rubygems:...,
# cargo:..., github_action:owner/repo
if [[ "$input" =~ ^(npm|pypi|go|rubygems|cargo|github_action):[^:]+ ]]; then
  echo "REGISTRY:${input}"
  exit 0
fi

# Zip file
if [[ "$input" == *.zip && -f "$input" ]]; then
  dest="$(mktemp -d "$STAGE_ROOT/zip.XXXXXX")"
  # Extract member by member so the exact set of extracted files is recorded in
  # "$dest.expected": the integrity check at the end of triage.sh compares it
  # with what is still on disk (antivirus can delete files between extraction
  # and the scan, and a zip has no git index to compare against). Refuses a
  # zip whose declared size is absurd (a zip bomb would fill the disk).
  "$PY" - "$input" "$dest" "${TRIAGE_ZIP_MAX_BYTES:-2000000000}" "${TRIAGE_ZIP_MAX_FILES:-100000}" >&2 <<'PY'
import os, sys, zipfile
src, dest, max_bytes, max_files = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
with zipfile.ZipFile(src) as zf:
    infos = [i for i in zf.infolist() if not i.is_dir()]
    total = sum(i.file_size for i in infos)
    if total > max_bytes or len(infos) > max_files:
        sys.exit(f"error: zip declares {len(infos)} files / {total} bytes, over the limit "
                 f"({max_files} files / {max_bytes} bytes); raise TRIAGE_ZIP_MAX_BYTES / TRIAGE_ZIP_MAX_FILES to scan it anyway")
    expected = []
    for i in zf.infolist():
        p = zf.extract(i, dest)          # zipfile strips absolute paths and '..'
        if not i.is_dir():
            expected.append(os.path.relpath(p, dest).replace(os.sep, "/"))
with open(dest + ".expected", "w", encoding="utf-8", newline=chr(10)) as fh:   # LF even on Windows: a CR here breaks the comparison
    fh.write("\n".join(sorted(expected)) + "\n")
PY
  echo "$dest"
  exit 0
fi

# Unambiguous git URL forms
if [[ "$input" =~ ^(https?://|git@|git://) ]]; then
  dest="$(mktemp -d "$STAGE_ROOT/git.XXXXXX")"
  echo "Cloning (${TRIAGE_CLONE_DEPTH:-shallow}, no hooks executed by a plain clone): $input" >&2
  git clone ${depth_args[@]+"${depth_args[@]}"} --no-tags -c core.hooksPath=/dev/null "$input" "$dest" >&2
  echo "$dest"
  exit 0
fi

# Local path - checked before the bare "org/repo" shorthand below, so an
# existing relative directory is never misread as a git shorthand.
if [[ -d "$input" ]]; then
  cd "$input" && pwd
  exit 0
fi

# Bare "org/repo" shorthand (GitHub), only once it's confirmed NOT a local dir
if [[ "$input" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]]; then
  dest="$(mktemp -d "$STAGE_ROOT/git.XXXXXX")"
  echo "Cloning (${TRIAGE_CLONE_DEPTH:-shallow}, no hooks executed by a plain clone): https://github.com/$input" >&2
  git clone ${depth_args[@]+"${depth_args[@]}"} --no-tags -c core.hooksPath=/dev/null "https://github.com/$input" "$dest" >&2
  echo "$dest"
  exit 0
fi

echo "error: could not recognize input as a local dir, git URL, zip, or registry reference: $input" >&2
exit 1
