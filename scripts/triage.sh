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
# File list of a bare directory target, taken before any tool runs (see the
# integrity check at the end of this script).
if [[ "$TARGET" != REGISTRY:* && -d "$TARGET" ]]; then
  (cd "$TARGET" && find . -type f -not -path './.git/*' | sed 's|^\./||' | LC_ALL=C sort -u) > "$OUT/.integrity-start.txt"
fi

# Scanner config that lives OUTSIDE the target. Several scanners read
# suppression/ignore settings from the directory being scanned, which lets a
# hostile target switch off its own findings (verified on a fixture: each of
# these hid a live payload under the unhardened commands). These files let us
# pass explicit, target-independent settings instead.
CFG="$OUT/.scanner-cfg"
mkdir -p "$CFG/empty"
printf '[extend]\nuseDefault = true\n' > "$CFG/gitleaks-default.toml"
: > "$CFG/osv-empty.toml"

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

# SkillSpector reports its own coverage gaps in analysis_completeness (a 3MB
# script came back as runtime_limit + a "degraded" analyzer) - the tool is
# honest about this, but a bare "ran" in the manifest threw it away. Prints
# "<ran|partial>|<detail>". reference_missing is benign noise (a doc mentions
# a path that isn't bundled) and does not count as a gap. $2=1 ignores the
# --recursive 32-skill cap, which the caller covers by scanning the remainder.
# Native Windows Python cannot open MSYS paths like /tmp/x, so every path handed
# to $PY goes through this (a no-op where cygpath does not exist).
pypath() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi; }

ss_coverage() {
  "$PY" - "$(pypath "$1")" "${2:-0}" <<'PY'
import json, sys, collections
d = json.load(open(sys.argv[1], encoding="utf-8"))
ignore_cap = sys.argv[2] == "1"
blocks = [d.get("analysis_completeness")]
if "skills" in d:
    blocks += [s.get("analysis_completeness") for s in d["skills"]]
reasons, limits = collections.Counter(), set()
for a in blocks:
    for e in (a or {}).get("ledger_exceptions", []) or []:
        reasons[e.get("reason_code", "?")] += 1
    for l in (a or {}).get("limitations", []) or []:
        if ignore_cap and ("recursive skill" in l or "aggregate limit" in l):
            continue
        limits.add(l)
omitted = 0 if ignore_cap else int(d.get("skills_omitted", 0) or 0)
material = {k: v for k, v in reasons.items() if k not in {"reference_missing", "aggregate_scan_limit"}}
bits = [f"{k} x{v}" for k, v in sorted(material.items())] + sorted(limits)
if omitted:
    bits.append(f"{omitted} skills unscanned")
print(("partial" if bits else "ran") + "|" + ("coverage gaps: " + "; ".join(bits) if bits else "coverage complete"))
PY
}

# Semgrep reports what it could not analyze in the JSON "errors" list, but a
# bare "exit 0" in the manifest threw that away (a rule that timed out on a file
# still gave "ran"). Prints "<ran|partial>|<detail>".
#  - Timeout: ONE rule did not finish on ONE file (the other rules still ran
#    there), but that rule's findings for that file are missing -> partial.
#  - Anything else except PartialParsing (out of memory, a file Semgrep could
#    not parse at all, skipped paths) -> partial.
#  - PartialParsing: the file was parsed up to the bad spot and the rest was
#    analyzed; counted in the detail only (minified/templated files do this).
#  - Errors about the target's top-level .git/ (hooks/*.sample) are repository
#    metadata, not target content, and are counted apart. The directory is still
#    scanned: excluding ".git" would also skip a nested sub/.git/ (verified: both
#    `--exclude .git` and `--exclude /.git` do), which a hostile zip could use
#    to hide files.
semgrep_coverage() {
  "$PY" - "$(pypath "$1")" "$(pypath "$2")" <<'PY'
import collections, json, os, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
target = sys.argv[2]


def is_target_git(path):
    p = path.replace("\\", "/")
    i = p.find("/.git/")
    if i < 0:
        return False
    try:
        return os.path.samefile(p[:i] or "/", target)
    except OSError:
        return False


hard, partial_parse, git_noise, examples = collections.Counter(), 0, 0, {}
for e in d.get("errors", []):
    t = e.get("type")
    t = t if isinstance(t, str) else (t[0] if t else "?")
    path = e.get("path") or ""
    if is_target_git(path):
        git_noise += 1
    elif t == "PartialParsing":
        partial_parse += 1
    else:
        hard[t] += 1
        examples.setdefault(t, (e.get("rule_id") or "", os.path.relpath(path, target).replace("\\", "/") if path else ""))
skipped = d.get("paths", {}).get("skipped") or []
if skipped:
    hard["skipped paths"] += len(skipped)
bits = []
for t, n in sorted(hard.items()):
    rule, rel = examples.get(t, ("", ""))
    short = rule.split(".")[-1] if rule else ""
    bits.append(f"{n} {t}" + (f" (e.g. rule {short} on {rel})" if short and rel else ""))
notes = []
if partial_parse:
    notes.append(f"{partial_parse} PartialParsing warning(s): those files were analyzed only up to the unparsable spot")
if git_noise:
    notes.append(f"{git_noise} warning(s) about the staged .git/ metadata ignored")
status = "partial" if bits else "ran"
detail = ("coverage gaps: " + "; ".join(bits) if bits else "no analysis errors") + ("; " + "; ".join(notes) if notes else "")
print(status + "|" + detail)
PY
}

echo "== Tier 0: secrets + known CVEs ==" >&2

if have gitleaks; then
  f="$OUT/tier0_gitleaks.json"; e="$OUT/tier0_gitleaks.err"
  if [[ -n "$DIR_TARGET" ]]; then
    # --config/--gitleaks-ignore-path/--ignore-gitleaks-allow: without these a
    # target's own .gitleaks.toml allowlist, .gitleaksignore, or an inline
    # "gitleaks:allow" comment silently drops its findings (all three hid a
    # live token on a hostile fixture; Semgrep caught it only by luck).
    rc=$(run_capture "$f" "$e" -- gitleaks detect --no-git -s "$DIR_TARGET" -f json -r "$f" \
      --config "$CFG/gitleaks-default.toml" --gitleaks-ignore-path "$CFG/empty" --ignore-gitleaks-allow)
    [[ "$rc" == "0" || "$rc" == "1" ]] && record 0 gitleaks ran "exit $rc (1 = leaks found, expected)" "$f" \
      || record 0 gitleaks ran-with-errors "exit $rc, see $e" "$e"
  else
    record 0 gitleaks skipped "registry references are scanned by tier 2, not gitleaks" ""
  fi
else
  record 0 gitleaks skipped "gitleaks not installed - see https://github.com/gitleaks/gitleaks for install" ""
fi

# Opt-in: scan git HISTORY for secrets that were committed and later removed
# (invisible to the --no-git scan above). Off by default because a full clone
# costs time and disk, and because it runs `git` against the target's .git:
# a .git/config from an untrusted source (zip, copied directory) can make git run
# commands (e.g. a diff.<x>.textconv driver during `git log -p`). So history is
# only scanned when .git/config holds nothing beyond a short allowlist of keys,
# which a fresh clone always satisfies; anything else is refused, not scanned.
git_config_unsafe() {
  local line key bad=()
  while IFS= read -r line; do
    key="${line%%=*}"
    case "$key" in
      core.repositoryformatversion|core.filemode|core.bare|core.logallrefupdates|core.ignorecase|core.precomposeunicode|core.symlinks) ;;
      remote.*.url|remote.*.fetch|remote.*.tagopt|branch.*.remote|branch.*.merge|user.name|user.email|init.defaultbranch) ;;
      *) bad+=("$key") ;;
    esac
  done < <(git config --file "$1/config" --list 2>/dev/null)
  [[ ${#bad[@]} -gt 0 ]] && printf '%s, ' "${bad[@]:0:5}"
}
if [[ "${TRIAGE_GIT_HISTORY:-0}" == "1" ]]; then
  if [[ -z "$DIR_TARGET" ]]; then
    record 0 gitleaks-history skipped "registry references have no git history" ""
  elif ! have gitleaks; then
    record 0 gitleaks-history skipped "gitleaks not installed" ""
  elif [[ ! -d "$DIR_TARGET/.git" ]]; then
    record 0 gitleaks-history skipped "TRIAGE_GIT_HISTORY=1 but the target has no .git directory (a zip, a bare directory, or a worktree/submodule gitfile), so there is no history to scan" ""
  elif [[ -n "$(git_config_unsafe "$DIR_TARGET/.git")" ]]; then
    record 0 gitleaks-history skipped "REFUSED to run git on this repository: .git/config has settings beyond a fresh clone's ($(git_config_unsafe "$DIR_TARGET/.git")) and such settings can make git execute programs. History was NOT scanned; re-stage it as a fresh clone (stage.sh with a git URL) to scan history" ""
  else
    f="$OUT/tier0_gitleaks_history.json"; e="$OUT/tier0_gitleaks_history.err"
    ncommits="$(git -C "$DIR_TARGET" rev-list --count --all 2>/dev/null || echo "?")"
    shallow="$(git -C "$DIR_TARGET" rev-parse --is-shallow-repository 2>/dev/null || echo false)"
    # No global/system git config either: only the (allowlisted) repo config applies.
    rc=$(GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_TERMINAL_PROMPT=0 \
      run_capture "$f" "$e" -- gitleaks detect -s "$DIR_TARGET" -f json -r "$f" \
      --config "$CFG/gitleaks-default.toml" --gitleaks-ignore-path "$CFG/empty" --ignore-gitleaks-allow)
    if [[ "$rc" == "0" || "$rc" == "1" ]]; then
      if [[ "$shallow" == "true" ]]; then
        record 0 gitleaks-history partial "only $ncommits commit(s) of history exist in this shallow clone, so secrets removed in earlier commits are NOT covered (stage with TRIAGE_CLONE_DEPTH=full); exit $rc (1 = leaks found)" "$f"
      else
        record 0 gitleaks-history ran "scanned $ncommits commit(s) across all refs; exit $rc (1 = leaks found, expected)" "$f"
      fi
    else
      record 0 gitleaks-history ran-with-errors "exit $rc, see $e" "$e"
    fi
  fi
fi

if have osv-scanner; then
  f="$OUT/tier0_osv.json"; e="$OUT/tier0_osv.err"
  if [[ -n "$DIR_TARGET" ]]; then
    # --no-ignore/--config: by default osv-scanner skips anything the target's
    # .gitignore lists and applies the target's own osv-scanner.toml, whose
    # PackageOverrides can mark a package ignored. Both hid all 91 CVEs of a
    # known-vulnerable dependency on a hostile fixture.
    rc=$(run_capture "$f" "$e" -- osv-scanner scan source --format json -r \
      --no-ignore --config "$CFG/osv-empty.toml" "$DIR_TARGET")
    # osv-scanner's exit codes: 0 = clean, 1 = vulns found, 128 = no
    # package manifest/lockfile present at all - a real, common, non-error
    # outcome (verified directly: this skill's own repo has no lockfile
    # and exits 128 with "No package sources found"), not a tool failure.
    case "$rc" in
      0|1) record 0 osv-scanner ran "exit $rc (1 = vulns found, expected)" "$f" ;;
      128)
        # 128 means no lockfile, NOT no dependencies. A package.json with
        # known-vulnerable pins and no lockfile also exits 128, and this used
        # to be reported as "nothing to check" - a clean-looking result with
        # zero dependency coverage behind it.
        declared="$(bash "$(dirname "$0")/detect_manifests.sh" "$DIR_TARGET" 2>/dev/null | grep -v '^github_action ' | awk '{print $1}' | sort -u | paste -sd, -)"
        if [[ -n "$declared" ]]; then
          record 0 osv-scanner partial "NO CVE COVERAGE: dependency manifests present (ecosystems: $declared) but no lockfile, so osv-scanner could not check them - a clean result here does not mean the dependencies are safe" "$f"
        else
          record 0 osv-scanner ran "exit 128 (no dependency manifests or lockfiles in target - nothing to check)" "$f"
        fi ;;
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
      if [[ "$rc" == "0" || "$rc" == "1" ]]; then
        cov="$(ss_coverage "$f")"
        record 1 skillspector "${cov%%|*}" "exit $rc (llm=${TRIAGE_SKILLSPECTOR_LLM:-0}, marker:$mcp_manifest_found); ${cov#*|}" "$f"
      else
        record 1 skillspector ran-with-errors "exit $rc, see $e" "$e"
      fi
    else
      # Scope the scan to each distinct skills-collection root instead of
      # the whole repo: a single SKILL.md is scanned via its own
      # directory (no --recursive needed); multiple SKILL.mds sharing a
      # common parent (e.g. skills/<name>/SKILL.md x46) are scanned once
      # against that shared parent with --recursive, which is what the
      # flag is for. This is what actually fixes the runtime problem for
      # monorepos - the earlier whole-repo-or-nothing gate above only
      # helped the zero-SKILL.md case, not this one.
      # No associative arrays here: macOS ships bash 3.2, where `declare -A`
      # fails, and with it this whole branch silently never ran (no SkillSpector
      # entry in the manifest at all). Newline-delimited strings work everywhere.
      roots_seen=$'\n'
      # The collection root of every SKILL.md, one per line; a root's line count
      # is how many skills share it. Built with parameter expansion in one pass:
      # the previous per-skill rescan forked `dirname` twice per PAIR of skills
      # (70 skills = ~9800 forks, minutes on Windows).
      all_roots=""
      for skill_md in "${real_skill_mds[@]}"; do
        sd="${skill_md%/*}"
        all_roots+="${sd%/*}"$'\n'
      done
      idx=0
      for skill_md in "${real_skill_mds[@]}"; do
        skill_dir="${skill_md%/*}"
        collection_root="${skill_dir%/*}"
        # If this SKILL.md is the only one under its collection_root,
        # scan its own directory directly instead (handles the common
        # single-skill-repo case correctly).
        siblings="$(printf '%s' "$all_roots" | grep -cxF -- "$collection_root" || true)"
        if [[ $siblings -le 1 ]]; then
          root="$skill_dir"; recursive_flag=""
        else
          root="$collection_root"; recursive_flag="--recursive"
        fi
        case "$roots_seen" in *$'\n'"$root"$'\n'*) continue ;; esac
        roots_seen+="$root"$'\n'
        idx=$((idx+1))
        f="$OUT/tier1_skillspector_${idx}.json"; e="${f%.json}.err"
        rc=$(run_capture "$f" "$e" -- skillspector scan "$root" --format json $recursive_flag $llm_flag)
        if [[ "$rc" == "0" || "$rc" == "1" ]]; then
          # recursive mode: the 32-skill cap is covered by the remainder
          # scan below, so don't flag it as a gap here
          cov="$(ss_coverage "$f" "$([[ -n "$recursive_flag" ]] && echo 1 || echo 0)")"
          record 1 skillspector "${cov%%|*}" "root:$root recursive:${recursive_flag:-no} exit $rc; ${cov#*|}" "$f"
        else
          record 1 skillspector ran-with-errors "root:$root exit $rc, see $e" "$e"
        fi

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
          # The remainder is scanned in copies of <=32 skills at a time (the
          # cap applies per --recursive call, so each batch is complete);
          # measured on 70 synthetic skills the one-skill-at-a-time fallback
          # took 10m18s. Copies, not symlinks (not followed on Windows). A
          # skill that a batch still does not report is scanned alone, so
          # coverage is never assumed. Skills are scanned in their own
          # directory either way, so results do not depend on batching.
          remaining=()
          for other in "${real_skill_mds[@]}"; do
            odir="$(dirname "$other")"
            [[ "$(dirname "$odir")" == "$root" ]] || continue
            grep -qxF "$(basename "$odir")" <<< "$scanned_names" && continue
            remaining+=("$odir")
          done
          bn=0; xn=0
          for ((bi = 0; bi < ${#remaining[@]}; bi += 32)); do
            bn=$((bn+1))
            bdir="$OUT/.batches/${idx}_$bn"; mkdir -p "$bdir"
            batch=("${remaining[@]:bi:32}")
            for odir in "${batch[@]}"; do cp -R "$odir" "$bdir/$(basename "$odir")"; done
            bf="$OUT/tier1_skillspector_${idx}_b${bn}.json"; be="${bf%.json}.err"
            brc=$(run_capture "$bf" "$be" -- skillspector scan "$bdir" --format json --recursive $llm_flag)
            bscanned=""
            if [[ "$brc" == "0" || "$brc" == "1" ]]; then
              bcov="$(ss_coverage "$bf" 1)"
              record 1 skillspector "${bcov%%|*}" "root:$root batch $bn (${#batch[@]} skills, recursive, past the 32-skill cap) exit $brc; ${bcov#*|}" "$bf"
              bscanned="$("$PY" - "$bf" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
print("\n".join(s["name"] for s in d.get("skills", []) if "issues" in s and "name" in s))
PY
)"
            else
              record 1 skillspector ran-with-errors "root:$root batch $bn exit $brc, see $be; its skills are scanned one at a time" "$be"
            fi
            for odir in "${batch[@]}"; do
              grep -qxF "$(basename "$odir")" <<< "$bscanned" && continue
              xn=$((xn+1))
              xf="$OUT/tier1_skillspector_${idx}_x${xn}.json"; xe="${xf%.json}.err"
              xrc=$(run_capture "$xf" "$xe" -- skillspector scan "$odir" --format json $llm_flag)
              if [[ "$xrc" == "0" || "$xrc" == "1" ]]; then
                xcov="$(ss_coverage "$xf")"
                record 1 skillspector "${xcov%%|*}" "root:$odir recursive:no (not reported by its batch) exit $xrc; ${xcov#*|}" "$xf"
              else
                record 1 skillspector ran-with-errors "root:$odir exit $xrc, see $xe" "$xe"
              fi
            done
            rm -rf "$bdir"
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
    # On a hostile fixture, plain `semgrep --config auto` missed a payload
    # hidden by each of: a "# nosemgrep" comment (--disable-nosem), the
    # target's own .semgrepignore (--x-ignore-semgrepignore-files), its
    # .gitignore (--no-git-ignore), and a >1MB file (--max-target-bytes 0;
    # the default 1000000 skips silently, and the JSON lists nothing as
    # skipped). The --x- flag is experimental: if a future Semgrep removes
    # it the run errors loudly (ran-with-errors) rather than under-scanning,
    # and the CI hostile-fixture test fails.
    # Default is the named ruleset p/default with metrics off. "auto" needs
    # Semgrep metrics ON (it errors with --metrics=off), which sends usage
    # metadata to semgrep.dev. Measured 2026-10-07 against auto on 411 Python
    # files and on OWASP/NodeGoat: identical findings (one extra auto hit was
    # run-to-run timeout noise), and p/default was faster. Opt back in with
    # TRIAGE_SEMGREP_CONFIG=auto.
    sg_config="${TRIAGE_SEMGREP_CONFIG:-p/default}"
    sg_metrics=""
    [[ "$sg_config" != "auto" ]] && sg_metrics="--metrics=off"
    rc=$(run_capture "$f" "$e" -- semgrep --config "$sg_config" $sg_metrics --json \
      --disable-nosem --no-git-ignore --max-target-bytes 0 --x-ignore-semgrepignore-files "$DIR_TARGET")
    if [[ "$rc" == "0" || "$rc" == "1" ]]; then
      cov="$(semgrep_coverage "$f" "$DIR_TARGET")"
      record 3 semgrep "${cov%%|*}" "exit $rc (config $sg_config); ${cov#*|}" "$f"
    else
      record 3 semgrep ran-with-errors "exit $rc, see $e" "$e"
    fi
  else
    record 3 semgrep skipped "no local files for a bare registry reference" ""
  fi
else
  record 3 semgrep skipped "not installed - pip install semgrep" ""
fi

echo "== Tier 4: sandboxed script execution (opt-in) ==" >&2

# Executes untrusted code, so sandbox_run.sh refuses unless TRIAGE_EXECUTE=1.
# Its own result file becomes the manifest entry, so a skip (not requested, no
# Docker, nothing to run), a partial run and a REFUSAL (containment probe
# failed) are all reported the same way as every other tier. It only adds
# coverage: it can never turn a static finding into "clean".
if [[ -z "$DIR_TARGET" ]]; then
  record 4 sandbox-exec skipped "no local files for a bare registry reference" ""
elif [[ ${#real_skill_mds[@]} -eq 0 ]]; then
  record 4 sandbox-exec skipped "no SKILL.md found, so there is no skill scripts/ directory to execute" ""
else
  skill_dirs=()
  for f in "${real_skill_mds[@]}"; do skill_dirs+=("$(cd "$(dirname "$f")" && pwd)"); done
  tgt_abs="$(cd "$DIR_TARGET" && pwd)"
  bash "$(dirname "$0")/sandbox_run.sh" "$tgt_abs" "$OUT" "${skill_dirs[@]}" >&2
  res="$OUT/dynamic/result.json"
  if [[ -f "$res" ]]; then
    read_field() { "$PY" -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$res" "$1"; }
    record 4 sandbox-exec "$(read_field status)" "$(read_field detail)" "$(read_field output)"
  else
    record 4 sandbox-exec ran-with-errors "sandbox_run.sh produced no result file" ""
  fi
fi

echo "== Tier 5: domain reputation ==" >&2

# Static only: extracts hosts from URLs in the target and matches them against
# locally cached abuse.ch feeds; never contacts a domain found in the target.
# Network is opt-in (TRIAGE_DOMAIN_LOOKUP=1: feed refresh + RDAP domain age),
# because it tells third parties which domains the target mentions. With no
# cached feeds the entry is `skipped`, not clean. A match corroborates other
# findings, it is not a verdict (see references/tool-notes.md).
if [[ -z "$DIR_TARGET" ]]; then
  record 5 domain-reputation skipped "no local files for a bare registry reference" ""
else
  dres="$OUT/tier5_domains.json"
  if "$PY" "$(dirname "$0")/domain_check.py" "$DIR_TARGET" "$dres" 2>"$OUT/tier5_domains.err" && [[ -f "$dres" ]]; then
    dfield() { "$PY" -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$dres" "$1"; }
    record 5 domain-reputation "$(dfield status)" "$(dfield detail)" "$dres"
  else
    record 5 domain-reputation ran-with-errors "domain_check.py failed, see $OUT/tier5_domains.err" "$OUT/tier5_domains.err"
  fi
fi

# Staging integrity, checked at the END so it also catches removals that
# happen during the scan. Found when scanning real malicious skills on a
# Windows host: Defender deleted 20 of 111 sampled malicious skills'
# files (the most blatant ones) and the pipeline just never saw them - no
# error, no gap in the manifest, a cleaner tree than the real artifact.
# `git ls-files --deleted` lists files git tracks that are gone from disk,
# which covers git clones and local repos; zip and bare-directory targets
# have no baseline to compare against and are not covered.
#
# Zip and bare-directory targets now have baselines too: stage.sh records the
# extracted file list next to a zip ("<dir>.expected"), and a bare directory is
# listed when this script starts. A directory baseline only catches removals
# DURING the scan; a file deleted before triage started was never seen, and the
# entry says so instead of implying a full guarantee.
if [[ -n "$DIR_TARGET" ]] && git -C "$DIR_TARGET" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  missing="$(git -C "$DIR_TARGET" ls-files --deleted -- . 2>/dev/null)"
  nmiss="$(printf '%s\n' "$missing" | grep -c . || true)"
  if [[ "$nmiss" -gt 0 ]]; then
    sample="$(printf '%s\n' "$missing" | head -3 | paste -sd, -)"
    record staging integrity partial "$nmiss tracked file(s) are missing from the scanned tree (antivirus removal, a failed checkout, or local deletions) - the scan covered an incomplete copy, so files that were removed were never analyzed. First: $sample" ""
  else
    record staging integrity ran "all git-tracked files present at end of scan" ""
  fi
elif [[ -n "$DIR_TARGET" ]]; then
  baseline=""; basis=""
  if [[ -f "${DIR_TARGET%/}.expected" ]]; then
    baseline="${DIR_TARGET%/}.expected"; basis="every file extracted from the zip"
  elif [[ -f "$OUT/.integrity-start.txt" ]]; then
    baseline="$OUT/.integrity-start.txt"; basis="every file present when the scan started (a directory has no earlier baseline, so files removed BEFORE the scan are not detectable)"
  fi
  if [[ -n "$baseline" ]]; then
    tr -d '\015' < "$baseline" | LC_ALL=C sort -u > "$OUT/.integrity-expected.txt"
    (cd "$DIR_TARGET" && find . -type f -not -path './.git/*' | sed 's|^\./||' | LC_ALL=C sort -u) > "$OUT/.integrity-now.txt"
    missing="$(LC_ALL=C comm -23 "$OUT/.integrity-expected.txt" "$OUT/.integrity-now.txt")"
    nmiss="$(printf '%s\n' "$missing" | grep -c . || true)"
    if [[ "$nmiss" -gt 0 ]]; then
      sample="$(printf '%s\n' "$missing" | head -3 | paste -sd, -)"
      record staging integrity partial "$nmiss file(s) were present at the start and are gone at the end of the scan (antivirus removal or deletion) - the scan covered an incomplete copy, so the removed files were never fully analyzed. First: $sample" ""
    else
      record staging integrity ran "$basis: all still present at end of scan" ""
    fi
  fi
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
