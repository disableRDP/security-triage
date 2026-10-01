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
  "$PY" -c "import zipfile,sys; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" "$input" "$dest" >&2
  echo "$dest"
  exit 0
fi

# Unambiguous git URL forms
if [[ "$input" =~ ^(https?://|git@|git://) ]]; then
  dest="$(mktemp -d "$STAGE_ROOT/git.XXXXXX")"
  echo "Cloning (shallow, no hooks executed by a plain clone): $input" >&2
  git clone --depth 1 --no-tags -c core.hooksPath=/dev/null "$input" "$dest" >&2
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
  echo "Cloning (shallow, no hooks executed by a plain clone): https://github.com/$input" >&2
  git clone --depth 1 --no-tags -c core.hooksPath=/dev/null "https://github.com/$input" "$dest" >&2
  echo "$dest"
  exit 0
fi

echo "error: could not recognize input as a local dir, git URL, zip, or registry reference: $input" >&2
exit 1
