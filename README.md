# security-triage

[![smoke-test](https://github.com/disableRDP/security-triage/actions/workflows/smoke-test.yml/badge.svg)](https://github.com/disableRDP/security-triage/actions/workflows/smoke-test.yml)

A Claude Code skill that triages a third-party artifact — a Claude Code
skill, an MCP server, a package from a registry, or a general repo — for
security risk before you install, run, or otherwise trust it. Fully open
source, no third-party account or API token required.

## Why this exists

Pointing a skill-specific scanner at general application code produces
garbage: in testing, [SkillSpector](https://github.com/NVIDIA/skillspector)
scored a plain 856-file app repo 100/100 CRITICAL with 355 findings,
almost all false positives — an SVG icon flagged for "context window
stuffing," a `.dockerignore` line flagged for "credential access." The
opposite mismatch is just as real: a generic SAST tool has no concept of
a skill's trigger-phrase or tool-scope contract, so it can't catch a
skill that quietly auto-writes to `CLAUDE.md` or skips its own
confirmation prompt on certain phrases.

The fix here isn't a smarter classifier that picks one tool and discards
the rest — that's the same failure mode with extra confidence. It's
**layering**: every tool in this pipeline is either genuinely
input-agnostic (works identically on any code) or self-scoping (only
activates on the file types it understands, and silently finds nothing
otherwise). Nothing guesses "is this a skill or an app" and bets the
whole report on the answer.

## What v1 does

| Tier | Tool | Scope | Why |
|---|---|---|---|
| 0 | [gitleaks](https://github.com/gitleaks/gitleaks) + [OSV-Scanner](https://github.com/google/osv-scanner) | secrets, known CVEs | Exact-match tools — no semantic assumptions, always safe to run |
| 1 | [SkillSpector](https://github.com/NVIDIA/skillspector) | Claude Code skills, MCP servers, agent configs | Skipped entirely with no `SKILL.md`/MCP manifest anywhere (its output is discarded by rule otherwise); scoped to the actual skills-collection directory with `--recursive` when a monorepo bundles several — measured 10min → 35sec on a real 46-skill repo rather than scanning the whole tree |
| 2 | [GuardDog](https://github.com/DataDog/guarddog) | registry packages (npm/PyPI/Go/RubyGems/Cargo/GH Actions) | Runs per detected manifest, not a global guess |
| 3 | [Semgrep](https://github.com/semgrep/semgrep) `--config auto` | general source code | No skill/app assumptions to misapply |

Staging (local dir, git URL, zip, or registry reference) never executes
install/build/postinstall scripts — it only fetches or extracts.

The output is **not** a single merged score. Each tool's findings are
reported with their own provenance and a stated confidence, cross-checked
against `references/tool-notes.md` for known false-positive patterns
(see below) — forcing one number across tools that measure different
things is exactly what produced the meaningless 100/100 result above.

## Validated against real targets, not just self-scans

Beyond the CI fixtures, this pipeline has been run against two real,
independently-authored targets:

- A real, clean, published Claude Code skill — zero findings across every
  tier. Not a fabricated "it works" case; a genuine clean result.
- [OWASP NodeGoat](https://github.com/OWASP/NodeGoat) (a real,
  intentionally-vulnerable Node.js app, used because it has documented
  real vulnerabilities): gitleaks found a committed RSA private key,
  osv-scanner found **130 vulnerable packages / 312 known CVEs** against
  its real lockfile, and Semgrep independently corroborated the
  private-key finding. SkillSpector, run against the same target, scored
  it 100/100 CRITICAL/DO_NOT_INSTALL with findings like "Prompt
  Injection" matched against a plain HTML comment — the exact
  misapplication pattern described above, reproduced on a target nobody
  built to prove a point, and correctly discarded by the calibration rule
  in `references/tool-notes.md` without needing a pipeline change.

## What v1 deliberately leaves out

Two tools were evaluated and **not** included, on purpose:

- **GuardDog needs a Rust/Cargo toolchain** to build locally on most
  platforms (no prebuilt wheel for its native dependency). That's a
  heavy install for one tier that only fires when a package manifest is
  present. It's wired into the pipeline and used automatically if
  installed — `pip install guarddog` (after installing Rust) — but it's
  not a required dependency.
- **No dedicated MCP-server scanner.** A candidate (`skill-audit-mcp`)
  was rejected: single-maintainer, recently published, unverified at
  scale — and running it means executing someone else's unverified code
  locally, a real trust cost for a tool whose job is deciding whether to
  trust someone else's code. SkillSpector's `--mcp-registry` flag looks
  like a fit by name but isn't — it expects a bulk registry-*listing*
  payload, not one server's manifest (confirmed by testing; it errors
  with "must contain a servers list"). Plain `skillspector scan` already
  treats an MCP manifest as a normal component, which covers the common
  case without a second unverified dependency.

Full reasoning for both is in `references/tool-notes.md`.

## Known limitations (static analysis only)

This pipeline reads code; it does not run it. That means it cannot catch
a payload that only activates at runtime, cannot tell you if something
you already approved has since changed (no drift/rug-pull detection), and
does not adversarially test prompt-injection resistance beyond static
pattern matching. Every report this skill produces ends with this stated
explicitly — see the **v2 roadmap** below for what would close these
gaps.

## v2 roadmap (not built yet)

- Dynamic/behavioral sandbox execution — the highest-priority gap, since
  it's the one category of attack (obfuscated/runtime-only payloads)
  static analysis structurally cannot see. Candidate isolation layer:
  [Harbor](https://github.com/harbor-framework/harbor) (MIT, 5.7k stars,
  from the Terminal-Bench team) — evaluated directly by reading its
  source via NVIDIA's SkillEvaluator, which builds its own live-agent
  evaluation tier on top of it. SkillEvaluator's specific usage isn't
  reusable as-is (its task.toml generation hardcodes
  `network_mode = "public"` and its collector only captures
  task-outcome data, not security-relevant behavior — correct for
  evaluating whether a skill helps an agent, wrong for safely observing
  a potentially malicious one), but Harbor itself supports real network
  isolation (`network_mode = "no-network"`) and a clean
  `{environment, instruction, verifier}` task abstraction — the actual
  starting point would be our own Harbor task/verifier definitions, not
  a fork of SkillEvaluator's.
- Rug-pull/drift detection — hash-pin an approved artifact and alert if
  it changes later.
- Adversarial red-team fuzzing of prompt-injection resistance, beyond
  static regex matching.
- SBOM generation as a persisted audit artifact.
- License compliance / domain-reputation checks.
- An optional, opt-in Snyk Agent Scan layer for users who already have a
  Snyk account — not a required dependency, since it hard-requires a
  third-party token with no anonymous path to real findings.

## Install

Clone into your Claude Code skills directory:

```bash
git clone <this-repo-url> ~/.claude/skills/security-triage
```

(Or into a project's `.claude/skills/security-triage` for a project-scoped
install.)

### Prerequisites

Requires `bash` (Git Bash or WSL on Windows) and `python3`/`python`/`py`
on `PATH`. The scanner CLIs are each optional and independently
detected — the pipeline runs whatever's installed and reports what's
missing, with install instructions, rather than failing:

```bash
pip install semgrep
pip install "git+https://github.com/NVIDIA/skillspector.git"

# optional - needs Go
go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest

# optional - prebuilt binary, see https://github.com/gitleaks/gitleaks/releases

# optional - needs a Rust/Cargo toolchain first
pip install guarddog
```

## Usage

Trigger it conversationally in Claude Code:

> "Scan this skill before I install it: `<git-url>`"
> "Vet this npm package before I add it as a dependency: `left-pad`"
> "Is this repo safe to run? `<path-or-url>`"

Or invoke the scripts directly:

```bash
staged="$(bash scripts/stage.sh "<input>")"
bash scripts/triage.sh "$staged" "/path/to/output-dir"
```

`stage.sh` accepts a local directory, a git URL, a `.zip` path, or a
registry reference (`npm:left-pad`, `pypi:requests@2.0.0`, etc.).
`triage.sh` writes one raw output file per tool plus `manifest.json`
listing what ran, what was skipped, and why.

## License

MIT — see `LICENSE`. This skill orchestrates the tools above by shelling
out to them if installed; it does not vendor or redistribute their code,
and each remains under its own license (SkillSpector, GuardDog,
OSV-Scanner: open source per their respective repos; Semgrep Community
Edition: LGPL-2.1; gitleaks: MIT).
