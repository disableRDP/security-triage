#!/usr/bin/env bash
# Walk a staged directory and print one "<ecosystem> <path>" line per
# package manifest found. Purely mechanical file-presence checks - no
# semantic guessing about what the repo "is".
set -euo pipefail

root="${1:-}"
if [[ -z "$root" || ! -d "$root" ]]; then
  echo "usage: detect_manifests.sh <staged-dir>" >&2
  exit 1
fi

while IFS= read -r -d '' f; do
  case "$(basename "$f")" in
    package.json) echo "npm $f" ;;
    pyproject.toml|setup.py) echo "pypi $f" ;;
    Gemfile) echo "rubygems $f" ;;
    *.gemspec) echo "rubygems $f" ;;
    go.mod) echo "go $f" ;;
    Cargo.toml) echo "cargo $f" ;;
    action.yml|action.yaml) echo "github_action $f" ;;
  esac
done < <(find "$root" \
  \( -name node_modules -o -name .git -o -name vendor -o -name dist -o -name build \) -prune -o \
  -type f -print0)
