# Interpretation notes per tool

Read this before writing any synthesis. These are not generic tool
descriptions — they are the specific failure/success patterns observed or
documented for this pipeline, and how to weight a finding because of them.

## SkillSpector (tier 1)

Validated accurate on a real Claude Code skill with a `SKILL.md` present:
correctly caught a genuine persistence/prompt-injection risk (auto-write to
CLAUDE.md, trigger phrases that skip confirmation) and scored it
appropriately. **When pointed at a target with no `SKILL.md` anywhere in
the tree, its heuristics assume skill-shaped input and misfire badly** —
observed 355 findings and a meaningless 100/100 CRITICAL score on a plain
856-file application repo, almost entirely false positives (an SVG icon
flagged for "context window stuffing", a `.dockerignore` line flagged for
"credential access").

**Rule:** if no `SKILL.md` exists in the scanned tree, discard SkillSpector's
findings entirely from the trust synthesis — note that it ran and found
nothing *reliable*, don't repeat its score or findings as if they were
signal.

**A second, sharper false-positive pattern, observed even WITH a real
`SKILL.md` present:** running this pipeline on its own source (v2.12.0)
produced a HIGH "remote script download + execution" finding that was
actually just the literal string `"pip install git+https://..."` inside a
human-readable skip message in a shell script — never executed, just
descriptive text. A second MEDIUM "Excessive Agency / Autonomous Decision
Making" finding was prose in this very file *describing* a different
skill's known issue ("trigger phrases that skip confirmation"), not an
actual behavior. **Rule:** before accepting a SkillSpector finding, read
the actual line it points to. If the matched content is inside a string
literal, comment, or documentation prose rather than code that executes,
discard it — SkillSpector's static/YARA pass pattern-matches on text
content, not on whether that text is reachable, executable code.

**Scoping to a real skills collection speeds this up but does not fix
precision — they are separate problems.** `triage.sh` scopes SkillSpector
to the actual `SKILL.md` collection root with `--recursive` instead of
scanning the whole repo (measured: 10min -> 35sec on a 46-skill
monorepo, see PROJECT_HANDOFF.md), and this does produce useful,
differentiated per-skill scores instead of one meaningless blanket
number. But spot-checking the *highest-scoring* skill in that same real
monorepo found two more false positives from the same root causes as
above: "Hidden Instructions, HIGH" flagged a skill's entire normal,
auto-generated documentation body (lines 5-273 of a 423-line file — not
remotely hidden, just the whole doc), and "Data Exfiltration /
External Script Fetching" misread a `curl` call to the user's own
`http://localhost:...` server as external transmission — SkillSpector's
heuristic doesn't distinguish localhost from a remote host. A third
finding in the same skill ("MCP Rug Pull" for an unpinned `npx <pkg>`
install command) was a real, valid point filed under the wrong category
name — same mislabeling pattern as the Docker-tag case on NodeGoat.
**Rule:** scoping the scan and reading individual skill scores does not
mean the findings inside those skills are trustworthy by default — apply
the same "read the actual line" discipline per-skill, not just
per-repo. A broad span covering a whole normal doc section is likely a
"Hidden Instructions" false positive; a `curl`/HTTP example pointed at
`localhost` or `127.0.0.1` is likely a false "external transmission"
positive.

**Output schema differs by scan mode.** A single `SKILL.md` target
(no `--recursive`) returns one `risk_assessment` + `issues` list, as
documented above. A `--recursive` scan against a skills-collection root
returns a different top-level shape: `skill_count`, `max_risk_score`,
`skills_omitted` (a real count — some skills may be silently excluded
from the detailed per-skill `skills[]` array, worth checking if it's
nonzero), and a `skills[]` array where each entry has its *own*
`risk_assessment`/`issues`. Read whichever shape is actually present;
don't assume the single-skill schema when `--recursive` was used.

## MCP servers specifically (tier 1, no separate tool)

There's no dedicated MCP-server scanner in this pipeline. Two things ruled
that out:
- **skill-audit-mcp** was evaluated and rejected: single-maintainer,
  recently published, unverified at scale beyond its own claimed
  calibration — running it means executing someone else's unverified code
  locally, which is a real trust cost for a tool whose whole job is
  deciding whether to trust someone else's code.
- **SkillSpector's `--mcp-registry` flag looks like the fit by name but
  isn't.** It expects a bulk MCP-registry *listing* payload
  (`{"servers": [...]}`, e.g. a feed from the registry API) — tested
  directly against a single server's own manifest and it errored
  ("must contain a servers list"). It's for auditing a whole registry
  feed, not triaging one third-party MCP server.

**What actually covers an MCP server target:** plain `skillspector scan
<dir>` already treats an MCP manifest (`mcp.json`/`server.json`) as a
normal component alongside the server's code — verified directly, no
special flag needed. Tiers 0 and 3 (secrets, SAST) apply unchanged. If a
real gap shows up in practice (not just a hypothetical one), that's the
signal to revisit a dedicated MCP tool — not before.

## GuardDog (tier 2)

Two kinds of signal, different confidence levels:
- **Metadata heuristics** (typosquatting distance, binary file inclusion,
  new/low-reputation maintainer) are lower-confidence — a starting point
  for suspicion, not a verdict on their own.
- **Semgrep-rule-based behavioral findings** (e.g., a package that both
  has network-access capability AND references a suspicious domain in the
  same file) are higher-confidence — GuardDog deliberately requires both a
  capability and an indicator together before flagging these, which is
  the opposite of SkillSpector's failure mode above.

**Rule:** state which kind of finding it is when reporting a GuardDog hit.

## Semgrep `--config auto` (tier 3)

Tested on a real 856-file application with no `SKILL.md` (no skill-shaped
assumptions at all): found exactly one real issue (Dockerfile running as
root), zero noise. This is the most precision-trustworthy tool in the
pipeline for general code, precisely because it has no concept of "skill"
or "agent" semantics to misapply.

**Rule:** a Semgrep finding can be reported close to at-face-value; still
state the specific line/rule so the user can judge exploitability
themselves — Semgrep finds patterns, not proof of exploitability.

**`spawn-shell-true` / `detect-child-process` need the deepest trace of
any Semgrep category — the rule alone cannot tell you where the command
or its arguments originate, and that's the entire question.** Fully
traced on a real 23,872-file app (OmniRoute, 6 `spawn-shell-true` +
30 `detect-child-process` hits): all were false positives, via two
distinct safe patterns worth checking for specifically —
1. `shell: true` scoped narrowly to a documented Windows `.cmd`/`.bat`
   shim constraint (Node's CVE-2024-27980 fix refuses to exec them
   without a shell), where the *command* is always a hardcoded literal
   or an OS-resolved absolute path (never attacker/request input), and
   *arguments* are run through a purpose-built escaping utility
   mirroring `cross-spawn`'s correct double-escaping approach before
   reaching the shell.
2. For a request-handling code path specifically (not just a local CLI
   launcher an attacker would have to already be the operator of):
   trace whether the class/function that actually spawns is ever
   instantiated with caller-supplied arguments, or only with
   hardcoded/environment-derived ones. `new ZcodeExecutor()` with zero
   constructor args, falling through to server-operator environment
   variables, is what cleared it here — check the actual instantiation
   site, not just the class definition, since a class *accepting* an
   `args` option proves nothing about whether anything ever supplies one
   from untrusted input.

**Rule:** never report this category as "not fully traced" or "worth a
closer look" without actually doing the trace — unlike most Semgrep
categories, a file:line reference alone is not enough signal to act on
either way, and the investigation above is the actual bar.

## gitleaks / osv-scanner (tier 0)

Both are exact-match tools (a literal secret pattern; a literal
vulnerable version range) — inherently low false-positive-rate by
construction, unlike the heuristic/semantic tools above.

**Rule:** treat a tier-0 hit as high confidence by default. A gitleaks hit
on what looks like an example/placeholder key is the main realistic false
positive here — say so explicitly if the matched string looks like a
placeholder (e.g., contains "example", "xxxx", "00000000").

## A note on this file itself

The false-positive examples above are written out using the actual
trigger phrases SkillSpector matches on ("pip install git+https://...",
"trigger phrases that skip confirmation"). Scanning this skill with
SkillSpector will re-flag this very file for the same reasons it
describes — that's expected, not a bug to fix by rewording around the
scanner's patterns. Deliberately dodging a scanner's match is a worse
outcome than an explained false positive; leave it as-is.

## Cross-cutting rule

Never report a single merged score across tiers. These tools measure
different things (secrets, CVEs, skill-contract risk, package behavior,
code patterns) and forcing one number onto all of them is exactly what
produced the meaningless 100/100 CRITICAL result that motivated this
pipeline's layered design in the first place.
