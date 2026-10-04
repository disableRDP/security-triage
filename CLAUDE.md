# CLAUDE.md

Reference doc for Claude Code sessions working in this repo. Keep this file
short — put rationale and narrative in `README.md`, not here.

## What this is

A Claude Code skill (see [README.md](README.md) for full scope and design
rationale). Public repo at
[github.com/disableRDP/security-triage](https://github.com/disableRDP/security-triage) —
also used locally, same as the other projects under `Projects/`. Not
installed as an active skill under `~/.claude/skills/` by default; clone or
copy this repo there if you want it auto-invokable by trigger phrase in
other sessions.

A `PROJECT_HANDOFF.md` may exist locally, git-ignored — private working
notes for planning across sessions, not part of the published repo. Don't
assume it exists or reference it in anything user-facing; `README.md` is
the canonical public doc.

## Status

v1 complete: a layered static-analysis pipeline (gitleaks + osv-scanner,
SkillSpector, GuardDog, Semgrep — see README's tier table). CI (GitHub
Actions, `.github/workflows/smoke-test.yml`) passes on ubuntu/macos/windows.
GuardDog is wired in but not installed locally (needs a Rust/Cargo
toolchain) — it's skipped gracefully, not broken. Tier 4 (opt-in, `TRIAGE_EXECUTE=1`) runs skill
scripts via `scripts/sandbox_run.sh`, a `--network none` wrapper with a
refuse-if-uncontained probe; verified only by the `sandbox-exec` CI workflow
(no Docker locally). `evals/sandbox/README.md` holds the evaluation (Harbor
only for live-agent prompt-injection testing, untested). Tier 5 (`scripts/domain_check.py`) matches URL hosts against cached abuse.ch
feeds; network (feed refresh, RDAP age) is opt-in via `TRIAGE_DOMAIN_LOOKUP=1`.
Drift detection, SBOM and license checks remain out of scope.

## Working conventions

- **Layered, not branched**: every tool either runs unconditionally
  (input-agnostic) or self-scopes to the files it understands. Never add
  a classifier that picks one tool and discards the rest — that's the
  exact failure mode this project exists to avoid (see README's "Why this
  exists").
- **No merged score across tools.** Findings are reported with provenance
  and confidence, never forced into one number.
- **Before accepting any SkillSpector/GuardDog finding, read the actual
  line it points to.** Check `references/tool-notes.md` for known
  false-positive patterns first — several are already documented,
  including self-referential ones in that file itself.
- **Verify by running it, not by reasoning about it.** Every real bug
  found in this project so far (a wrong CLI flag, a misclassified exit
  code, a CI action that couldn't match an asset) was caught by actually
  executing the thing, never by inspecting it. Don't skip that step.
- **Check what a probe actually measures.** A completed TCP handshake is
  not reachability (Harbor's egress sidecar completes handshakes locally);
  require a real response before claiming something is open or closed.
- **A tier that reports `ran` can still be partial.** Scanners also read
  ignore/suppression config from the target, so always pass explicit
  target-independent settings.
- **Never run real malware samples** (sandbox or not) without the user's
  explicit approval. Sandbox canaries use only fake credentials and
  198.51.100.7. No Docker locally; sandbox runs go through the manual
  `sandbox-eval` workflow on GitHub's runner.
- Write large files with the Write tool, not bash heredocs, and validate
  workflow YAML before pushing (a step name containing `: ` breaks it).
- Commit directly to `master` — solo project, no PR ritual needed.
- No real secrets, credentials, or live API keys in this repo — it's
  public, and it's a security tool besides.

## Commands

```bash
bash scripts/stage.sh "<input>"                    # dir / git URL / zip / registry ref -> local path
bash scripts/triage.sh "<staged_target>" "<out_dir>"  # run the pipeline, writes manifest.json

# prerequisites (each optional, auto-detected - see README for full list)
pip install semgrep
pip install "git+https://github.com/NVIDIA/skillspector.git"
pip install guarddog   # needs a Rust/Cargo toolchain first - not installed here
```

## Docs map

- `README.md` — design rationale, tier table, v1/v2 roadmap, install/usage
- `references/tool-notes.md` — per-tool false-positive calibration rules
- `evals/sandbox/README.md` — Harbor/sandbox evaluation results (research)
- `SKILL.md` — the actual skill definition Claude Code loads when invoked
- `.github/workflows/smoke-test.yml` — CI
- `.github/workflows/sandbox-eval.yml` — manual-only sandbox evaluation
- `tests/test_domain_check.py` — offline tests for tier 5 (fake feeds + fake RDAP)
- `.github/workflows/sandbox-exec.yml` — acceptance test for tier 4 (`scripts/sandbox_run.sh`)
