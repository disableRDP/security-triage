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
    # osv-scanner's exit codes: 0 = clean, 1 = vulns found, 128 = no
    # package manifest/lockfile present at all - a real, common, non-error
    # outcome (verified directly: this skill's own repo has no lockfile
    # and exits 128 with "No package sources found"), not a tool failure.
    case "$rc" in
      0|1) record 0 osv-scanner ran "exit $rc (1 = vulns found, expected)" "$f" ;;
      128) record 0 osv-scanner ran "exit 128 (no package manifest/lockfile in target - nothing to check)" "$f" ;;
      *) record 0 osv-scanner ran-with-errors "exit $rc, see $e" "$e" ;;
    esac
  else
    record 0 osv-scanner skipped "no local manifest for a bare registry reference" ""
  fi
else
  record 0 osv-scanner skipped "osv-scanner not installed - see https://github.com/google/osv-scanner for install" ""
fi

echo "== Tier 1: skill / MCP / agent-surface risk (self-scoping) ==" >&2

# Find real SKILL.md files, excluding test/fixture paths (test fixtures
# for an unrelated feature can contain a mock .claude/skills/ tree that
# isn't actually meant to be reviewed as a real skill - confirmed
# directly on a real monorepo: 46 real skills under /skills, 1 decoy
# under /tests/fixtures/.../.claude/skills).
real_skill_mds=()
mcp_manifest_found=""
if [[ -n "$DIR_TARGET" ]]; then
  while IFS= read -r f; do
    case "$f" in
      */test/*|*/tests/*|*/fixture/*|*/fixtures/*|*/__fixtures__/*|*/__tests__/*) continue ;;
    esac
    real_skill_mds+=("$f")
  done < <(find "$DIR_TARGET" -iname "SKILL.md" 2>/dev/null)
  for name in server.json mcp.json .mcp.json mcp-manifest.json; do
    found="$(find "$DIR_TARGET" -iname "$name" -print -quit 2>/dev/null)"
    [[ -n "$found" ]] && { mcp_manifest_found="$found"; break; }
  done
fi

if have skillspector; then
  if [[ -z "$DIR_TARGET" ]]; then
    record 1 skillspector skipped "no local files for a bare registry reference" ""
  elif [[ ${#real_skill_mds[@]} -eq 0 && -z "$mcp_manifest_found" ]]; then
    # Measured directly: SkillSpector took 10m2s (67% of a ~15min total
    # pipeline run) on a 23872-file repo with no SKILL.md/MCP manifest at
    # all - and per tool-notes.md, its output is discarded whenever one
    # isn't present anyway. Mirrors GuardDog's existing per-manifest gate
    # for tier 2 - that gate was missing here, which was an
    # inconsistency, not a deliberate choice.
    record 1 skillspector skipped "no SKILL.md/MCP manifest found - SkillSpector's analysis would be inapplicable and is discarded by rule anyway (see references/tool-notes.md); skipping avoids ~10min of wasted runtime on a large tree" ""
  else
    llm_flag="--no-llm"
    [[ "${TRIAGE_SKILLSPECTOR_LLM:-0}" == "1" ]] && llm_flag=""
    if [[ ${#real_skill_mds[@]} -eq 0 ]]; then
      # MCP manifest only, no SKILL.md: scan the whole target as before -
      # there's no "collection" structure to scope down to.
      f="$OUT/tier1_skillspector.json"; e="$OUT/tier1_skillspector.err"
      rc=$(run_capture "$f" "$e" -- skillspector scan "$DIR_TARGET" --format json $llm_flag)
      [[ "$rc" == "0" || "$rc" == "1" ]] && record 1 skillspector ran "exit $rc (llm=${TRIAGE_SKILLSPECTOR_LLM:-0}, marker:$mcp_manifest_found)" "$f" \
        || record 1 skillspector ran-with-errors "exit $rc, see $e" "$e"
    else
      # Scope the scan to each distinct skills-collection root instead of
      # the whole repo: a single SKILL.md is scanned via its own
      # directory (no --recursive needed); multiple SKILL.mds sharing a
      # common parent (e.g. skills/<name>/SKILL.md x46) are scanned once
      # against that shared parent with --recursive, which is what the
      # flag is for. This is what actually fixes the runtime problem for
      # monorepos - the earlier whole-repo-or-nothing gate above only
      # helped the zero-SKILL.md case, not this one.
      declare -A roots_seen
      idx=0
      for skill_md in "${real_skill_mds[@]}"; do
        skill_dir="$(dirname "$skill_md")"
        collection_root="$(dirname "$skill_dir")"
        # If this SKILL.md is the only one under its collection_root,
        # scan its own directory directly instead (handles the common
        # single-skill-repo case correctly).
        siblings=0
        for other in "${real_skill_mds[@]}"; do
          [[ "$(dirname "$(dirname "$other")")" == "$collection_root" ]] && siblings=$((siblings+1))
        done
        if [[ $siblings -le 1 ]]; then
          root="$skill_dir"; recursive_flag=""
        else
          root="$collection_root"; recursive_flag="--recursive"
        fi
        [[ -n "${roots_seen[$root]:-}" ]] && continue
        roots_seen[$root]=1
        idx=$((idx+1))
        f="$OUT/tier1_skillspector_${idx}.json"; e="${f%.json}.err"
        rc=$(run_capture "$f" "$e" -- skillspector scan "$root" --format json $recursive_flag $llm_flag)
        [[ "$rc" == "0" || "$rc" == "1" ]] && record 1 skillspector ran "root:$root recursive:${recursive_flag:-no} exit $rc" "$f" \
          || record 1 skillspector ran-with-errors "root:$root exit $rc, see $e" "$e"

        # --recursive has a hardcoded 32-skill budget (_MULTI_SKILL_MAX_SKILLS
        # in skillspector/cli.py, no flag or env override); everything past it
        # is silently left unscanned. Found when 14 of 46 skills in a real
        # monorepo came back as "aggregate_scan_limit" - not scanned at all,
        # not just trimmed from the report. Scan whatever it skipped one at
        # a time so a large collection never gets partial coverage reported
        # as complete.
        if [[ -n "$recursive_flag" && ( "$rc" == "0" || "$rc" == "1" ) ]]; then
          scanned_names="$("$PY" - "$f" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
print("\n".join(s["name"] for s in d.get("skills", []) if "issues" in s and "name" in s))
PY
)"
          xn=0
          for other in "${real_skill_mds[@]}"; do
            odir="$(dirname "$other")"
            [[ "$(dirname "$odir")" == "$root" ]] || continue
            grep -qxF "$(basename "$odir")" <<< "$scanned_names" && continue
            xn=$((xn+1))
            xf="$OUT/tier1_skillspector_${idx}_x${xn}.json"; xe="${xf%.json}.err"
            xrc=$(run_capture "$xf" "$xe" -- skillspector scan "$odir" --format json $llm_flag)
            [[ "$xrc" == "0" || "$xrc" == "1" ]] && record 1 skillspector ran "root:$odir recursive:no (past --recursive's 32-skill cap) exit $xrc" "$xf" \
              || record 1 skillspector ran-with-errors "root:$odir exit $xrc, see $xe" "$xe"
          done
        fi
      done
    fi
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
