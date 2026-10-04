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

## Measured against labeled malicious skills

The pipeline was run, unmodified, on a seeded random sample of
[MalSkillBench](https://github.com/lxyeternal/MalSkillBench) (111
malicious skills confirmed by runtime sandboxing or manual review, plus 64
popular benign ones). Honest summary, with the numbers that don't flatter
it:

- **Using only the finding categories that behave like real signals**
  (code execution, tool misuse, YARA, high-severity least-privilege and
  exfiltration), tested on skills held out from picking them: **64%
  recall at 9.4% false positives.** "Any finding at all" is a bad rule:
  it flags 44% of benign skills.
- **At realistic prevalence (about 2% of skills), that is roughly 12%
  precision.** A flag means "read this skill", not "this is malicious".
- **Weakest on prompt-injection-only skills (about 50% recall)**, since
  static pattern matching is least effective when the payload is plain
  language.
- **Antivirus deleted 20 of the 111 malicious samples before they could be
  scanned** (Windows Defender, the most blatant ones). The pipeline now
  reports that as partial coverage instead of silently seeing a cleaner
  tree. It also means the recall above is biased low.
- Semgrep flagged 36% of malicious vs 3% of benign skills; gitleaks was
  not useful for this (5% vs 3%).

Caveats: one sample, mixed provenance (real-world and generated samples
aren't separately labeled in the release), and a benign set of 64.
Per-category tables and the full method are in `references/tool-notes.md`.

## Hostile-target hardening

Several of these scanners read ignore and suppression settings from the
directory being scanned, which lets a hostile repo switch off its own
findings. This was tested, not assumed: against a fixture hiding one
payload per mechanism (an inline `gitleaks:allow`, a target
`.gitleaks.toml`, a `.gitignore`d lockfile, an `osv-scanner.toml` override,
`# nosemgrep`, a `.semgrepignore`, a file over Semgrep's silent 1MB cap),
stock scanner behavior reported **6 of 13** hidden payloads. The pipeline
now passes explicit target-independent settings and reports all of them.
CI re-runs a 10-payload version of that fixture on every push; run
locally, that test fails against the pre-hardening script and passes
against the current one. Details and the full table are in
`references/tool-notes.md`.

A tier whose result can't be trusted to be complete is marked `partial`
in the manifest rather than `ran`, e.g. a `package.json` with no lockfile
(osv-scanner can't check unpinned dependencies) or a SkillSpector run that
hit its own runtime limit.

## Known limitations

This pipeline reads code; it does not run it. That means it cannot catch
a payload that only activates at runtime. Every report this skill
produces ends with this stated explicitly — see the **v2 roadmap** below
for the one thing that would close it.

Also not covered: secrets that were committed and later removed (staging
clones with `--depth 1` and gitleaks scans the working tree), and
SkillSpector's LLM-assisted analyzers (off by default, so it runs
static-only). Semgrep's default `--config auto` requires Semgrep's metrics
to be enabled, which sends usage metadata to semgrep.dev; set
`TRIAGE_SEMGREP_CONFIG=p/default` to run with metrics off instead.

## Tier 4: sandboxed script execution (opt-in, 2026-10-04)

`scripts/sandbox_run.sh` runs a skill's own `scripts/*.py` and `scripts/*.sh`
in a locked-down container under strace and reports what they *tried* to do.
It executes untrusted code, so it only runs with `TRIAGE_EXECUTE=1`; otherwise
the manifest shows `skipped`. Also `skipped` when Docker (daemon, not just the
CLI) is missing or the skill has no runnable scripts. Scripts run with no
arguments under `--network none`; `package.json`/`setup.py` install hooks are
never executed. Before every run an identical container runs a containment
probe (no non-loopback interface, host listener / public HTTP / DNS / ICMP all
unreachable, not root, no capabilities, read-only rootfs, pids limit set) and
the tier **refuses to report** if any check fails or cannot be evaluated.
Timeouts and unexecuted files are `partial` coverage gaps, never "clean". It
only adds coverage: an argument- or time-gated payload is invisible to it, so
it never replaces the static tiers. Verified by the `sandbox-exec` workflow
(needs Docker; the author's machine has none), which includes tests that
deliberately weaken the sandbox and require a refusal.

## v2 roadmap (script execution built; the rest not)

**Sandbox evaluation done (2026-10-03):** Harbor is *not* the right layer
for running a suspect's scripts. Its default `no-network` still resolves
DNS and passes ICMP, its container is unhardened, and it fails open if its
egress sidecar can't start; a plain `docker run --network none` wrapper is
lighter and more clearly contained. Harbor remains the candidate for
live-agent prompt-injection testing, which is untested. Method,
containment table and caveats:
[`evals/sandbox/README.md`](evals/sandbox/README.md). The paragraphs below
are the original plan and predate that finding.

v2 is scoped to **dynamic/behavioral sandbox execution** — the one
category of attack (obfuscated/runtime-only payloads) static analysis
structurally cannot see by construction. Candidate isolation layer:
[Harbor](https://github.com/harbor-framework/harbor) (Apache-2.0, from the
Terminal-Bench team) — evaluated directly by reading its source
via NVIDIA's SkillEvaluator, which builds its own live-agent evaluation
tier on top of it. SkillEvaluator's specific usage isn't reusable as-is
(its task.toml generation hardcodes `network_mode = "public"` and its
collector only captures task-outcome data, not security-relevant
behavior — correct for evaluating whether a skill helps an agent, wrong
for safely observing a potentially malicious one), but Harbor itself
supports real network isolation (`network_mode = "no-network"`) and a
clean `{environment, instruction, verifier}` task abstraction — the
actual starting point would be our own Harbor task/verifier definitions,
not a fork of SkillEvaluator's.

**Adversarial prompt-injection fuzzing is in scope for this same work**,
not a separate item — firing adversarial prompts at a live agent with
the skill installed and checking whether it complies with injected
instructions needs the same sandboxed live-agent infrastructure as the
malicious-behavior check above. Building the sandbox without evaluating
this would mean redoing similar work later for a capability that was
sitting right there.

**Planned as a v1.x addition, not gated on the sandbox:** domain-
reputation checks (is a URL/domain referenced in the code a known-bad or
newly-registered endpoint). This is a lightweight static lookup — it
needs no dynamic execution — and would directly strengthen existing
findings, e.g. corroborating GuardDog's "suspicious domain" heuristic
with an actual reputation check.

**Out of scope, each for its own reason, not one blanket "non-dynamic"
rationale:**
- **Rug-pull/drift detection** — not a lower-priority version of this
  tool, a different product. This skill's own stated purpose is
  point-in-time triage, not continuous monitoring of something already
  installed (see "What this is not" in `SKILL.md`). Belongs in a sibling
  tool, not a feature here.
- **License compliance** — a legal/governance axis (am I allowed to
  depend on this), orthogonal to security risk. Dedicated license
  scanners already exist; bundling this in would blur what this tool is
  for.
- **SBOM generation** — plausibly useful as a durable audit record
  someday, but it doesn't detect anything on its own and nobody's asked
  for it yet. Shelved on "not yet justified," not "not useful" —
  revisit if a concrete need shows up.
- **An optional Snyk Agent Scan layer** — excluded on principle, not
  schedule: it hard-requires a third-party account/token with no
  anonymous path to real findings, which contradicts this project's
  "fully open source, no account needed" design. Nothing about future
  roadmap prioritization changes that.

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
