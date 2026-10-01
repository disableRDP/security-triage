#!/usr/bin/env bash
# Layered static-analysis pipeline (v1). Every tier is either input-agnostic
# or self-scoping, so every applicable tier always runs - nothing here picks
# a single "right" tool and discards the rest. A missing CLI is recorded as
# skipped (with its install command) rather than failing the whole run; a
# CLI that errors is recorded as ran-with-errors with its stderr captured,
# rather than silently dropped or allowed to crash later tiers.
set -uo pipefail

pick_python() {
  for c in python3 python py; do
    command -v "$c" >/dev/null 2>&1 || continue
    "$c" --version >/dev/null 2>&1 && { echo "$c"; return 0; }
  done
  return 1
}
PY="$(pick_python)" || { echo "error: no working python interpreter found (tried python3, python, py)" >&2; exit 1; }

TARGET="${1:-}"
OUT="${2:-}"
if [[ -z "$TARGET" || -z "$OUT" ]]; then
  echo "usage: triage.sh <staged-dir|REGISTRY:eco:name[@ver]> <output-dir>" >&2
  exit 1
fi
mkdir -p "$OUT"

REGISTRY_ECO=""
REGISTRY_NAME=""
DIR_TARGET=""
if [[ "$TARGET" == REGISTRY:* ]]; then
  rest="${TARGET#REGISTRY:}"
  REGISTRY_ECO="${rest%%:*}"
  REGISTRY_NAME="${rest#*:}"
else
  DIR_TARGET="$TARGET"
fi

TIERS_JSON="$OUT/manifest.json"
entries=()

record() {
  # record <tier> <tool> <status> <detail> <output_path_or_empty>
  local tier="$1" tool="$2" status="$3" detail="$4" path="${5:-}"
  entries+=("$("$PY" - "$tier" "$tool" "$status" "$detail" "$path" <<'PY'
import json, sys
tier, tool, status, detail, path = sys.argv[1:6]
print(json.dumps({"tier": tier, "tool": tool, "status": status, "detail": detail, "output": path}))
PY
)")
}

have() { command -v "$1" >/dev/null 2>&1; }

run_capture() {
  # run_capture <outfile> <errfile> -- <cmd...>
  local outfile="$1" errfile="$2"; shift 2
  [[ "$1" == "--" ]] && shift
  "$@" >"$outfile" 2>"$errfile"
  echo $?
}

echo "== Tier 0: secrets + known CVEs ==" >&2

if have gitleaks; then
  f="$OUT/tier0_gitleaks.json"; e="$OUT/tier0_gitleaks.err"
  if [[ -n "$DIR_TARGET" ]]; then
    rc=$(run_capture "$f" "$e" -- gitleaks detect --no-git -s "$DIR_TARGET" -f json -r "$f")
    [[ "$rc" == "0" || "$rc" == "1" ]] && record 0 gitleaks ran "exit $rc (1 = leaks found, expected)" "$f" \
      || record 0 gitleaks ran-with-errors "exit $rc, see $e" "$e"
  else
    record 0 gitleaks skipped "registry references are scanned by tier 2, not gitleaks" ""
  fi
else
  record 0 gitleaks skipped "gitleaks not installed - see https://github.com/gitleaks/gitleaks for install" ""
fi

if have osv-scanner; then
  f="$OUT/tier0_osv.json"; e="$OUT/tier0_osv.err"
  if [[ -n "$DIR_TARGET" ]]; then
    rc=$(run_capture "$f" "$e" -- osv-scanner scan source --format json -r "$DIR_TARGET")
    [[ "$rc" == "0" || "$rc" == "1" ]] && record 0 osv-scanner ran "exit $rc (1 = vulns found, expected)" "$f" \
      || record 0 osv-scanner ran-with-errors "exit $rc, see $e" "$e"
  else
    record 0 osv-scanner skipped "no local manifest for a bare registry reference" ""
  fi
else
  record 0 osv-scanner skipped "osv-scanner not installed - see https://github.com/google/osv-scanner for install" ""
fi

echo "== Tier 1: skill / MCP / agent-surface risk (self-scoping) ==" >&2

if have skillspector; then
  f="$OUT/tier1_skillspector.json"; e="$OUT/tier1_skillspector.err"
  if [[ -n "$DIR_TARGET" ]]; then
    # LLM-assisted analysis is opt-in (TRIAGE_SKILLSPECTOR_LLM=1): without a
    # provider configured it would otherwise error or hang on missing
    # credentials, so v1 defaults to static-only (--no-llm).
    llm_flag="--no-llm"
    [[ "${TRIAGE_SKILLSPECTOR_LLM:-0}" == "1" ]] && llm_flag=""
    rc=$(run_capture "$f" "$e" -- skillspector scan "$DIR_TARGET" --format json $llm_flag)
    # skillspector exits non-zero when it has findings to report (no
    # --fail-on-findings needed to trigger it) - exit 0 or 1 both mean the
    # JSON output is valid; anything else is a real tool-invocation error.
    [[ "$rc" == "0" || "$rc" == "1" ]] && record 1 skillspector ran "exit $rc (llm=${TRIAGE_SKILLSPECTOR_LLM:-0})" "$f" \
      || record 1 skillspector ran-with-errors "exit $rc, see $e" "$e"
  else
    record 1 skillspector skipped "no local files for a bare registry reference" ""
  fi
else
  record 1 skillspector skipped "not installed - pip install git+https://github.com/NVIDIA/skillspector.git" ""
fi

# No separate MCP-server-specific tool is used here. skillspector's plain
# `scan` already picks up an MCP manifest (mcp.json/server.json) as a
# normal component alongside everything else in the directory - verified
# directly: scanning a directory containing only mcp.json + index.js
# listed both as components with no special flag needed. skillspector's
# own `--mcp-registry` flag is NOT a fit here despite the name - it
# expects a bulk registry-listing payload (`{"servers": [...]}`, e.g. a
# feed from the MCP registry API), not one server's own manifest, so it
# doesn't apply to triaging a single third-party MCP server. An
# unverified, single-maintainer scanner (skill-audit-mcp) was considered
# for this gap and rejected: it would add local-code-execution trust
# exposure for coverage the plain scan above already provides.

echo "== Tier 2: registry-package behavioral heuristics ==" >&2

if have guarddog; then
  if [[ -n "$REGISTRY_ECO" ]]; then
    f="$OUT/tier2_guarddog_${REGISTRY_ECO}.json"; e="${f%.json}.err"
    rc=$(run_capture "$f" "$e" -- guarddog "$REGISTRY_ECO" scan "$REGISTRY_NAME" --output-format json)
    [[ "$rc" == "0" ]] && record 2 guarddog ran "registry:$REGISTRY_ECO:$REGISTRY_NAME" "$f" \
      || record 2 guarddog ran-with-errors "exit $rc, see $e" "$e"
  elif [[ -n "$DIR_TARGET" ]]; then
    manifests="$(bash "$(dirname "$0")/detect_manifests.sh" "$DIR_TARGET" || true)"
    if [[ -z "$manifests" ]]; then
      record 2 guarddog skipped "no package manifest found in target" ""
    else
      while read -r eco path; do
        [[ -z "$eco" ]] && continue
        f="$OUT/tier2_guarddog_${eco}_$(basename "$(dirname "$path")" | tr -c 'A-Za-z0-9._-' '_').json"
        e="${f%.json}.err"
        rc=$(run_capture "$f" "$e" -- guarddog "$eco" scan "$(dirname "$path")" --output-format json)
        [[ "$rc" == "0" ]] && record 2 guarddog ran "manifest:$path" "$f" \
          || record 2 guarddog ran-with-errors "manifest:$path exit $rc, see $e" "$e"
      done <<< "$manifests"
    fi
  fi
else
  record 2 guarddog skipped "not installed - pip install guarddog" ""
fi

echo "== Tier 3: general SAST ==" >&2

if have semgrep; then
  if [[ -n "$DIR_TARGET" ]]; then
    f="$OUT/tier3_semgrep.json"; e="$OUT/tier3_semgrep.err"
    rc=$(run_capture "$f" "$e" -- semgrep --config auto --json "$DIR_TARGET")
    [[ "$rc" == "0" || "$rc" == "1" ]] && record 3 semgrep ran "exit $rc" "$f" \
      || record 3 semgrep ran-with-errors "exit $rc, see $e" "$e"
  else
    record 3 semgrep skipped "no local files for a bare registry reference" ""
  fi
else
  record 3 semgrep skipped "not installed - pip install semgrep" ""
fi

{
  printf '{\n  "target": %s,\n  "tiers": [\n' "$("$PY" -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$TARGET")"
  for i in "${!entries[@]}"; do
    printf '    %s' "${entries[$i]}"
    [[ $i -lt $((${#entries[@]}-1)) ]] && printf ','
    printf '\n'
  done
  printf '  ]\n}\n'
} > "$TIERS_JSON"

echo "manifest: $TIERS_JSON" >&2
cat "$TIERS_JSON"
