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
`skills_omitted`, and a `skills[]` array where each entry has its *own*
`risk_assessment`/`issues`. Read whichever shape is actually present;
don't assume the single-skill schema when `--recursive` was used.

**`skills_omitted > 0` means those skills were never scanned — not that
they were trimmed from the report.** `--recursive` has a hardcoded
32-skill budget (`_MULTI_SKILL_MAX_SKILLS` in `skillspector/cli.py`, no
flag or env override); the rest get an `aggregate_scan_limit` stub and
zero analysis. On a real 46-skill monorepo the 14 skipped skills held 203
of the 375 real findings, so the uncapped total was more than double what
the capped scan reported. (An earlier version of this note wrongly said
they were merely "silently excluded from the detailed array".)
`triage.sh` now scans the remainder one at a time; if you ever see
`skills_omitted > 0` in a final manifest, coverage is partial and the
report must say so.

### Measured precision: 375 findings across 46 documentation-style skills

Source: OmniRoute's `/skills` collection, scanned completely (see cap note
above), static mode. 14 finding categories; I read the flagged source
lines for 34 findings spanning every category (up to 5 distinct skills
each). **Result: 0 genuinely risky findings.** 26 were plain false
positives, 3 were real-but-declared capabilities, 4 were a real-but-
mislabeled hygiene point, 1 was SkillSpector reporting its own coverage
gap. The score (up to 97 CRITICAL) was produced entirely by these.

| Category (count) | What actually matched | Disposition |
|---|---|---|
| Tool Misuse / TM1 HIGH (157) | API-doc headings like `### DELETE /api/keys/{id}`, a documented CLI flag `--skip-test` | False positive: documenting an endpoint is not misusing a tool |
| analysis-evasion / AE1 HIGH (72) | `references/endpoints.md (partial)`: one link, flagged once per link to it, all in one skill (826-line reference file) | Not a threat. SkillSpector's own incomplete analysis. Report as a **coverage limitation**, never a finding |
| Agent Snooping / AS3 (47) | An HTML comment naming another skill's path; a doc table URL; `ls ~/.codex/skills/...` | Mostly FP. The `ls` is a **declared capability**: check it against the skill's own description |
| Data Exfiltration / E1 (35) | `curl` examples against `localhost:20128` or `$OMNIROUTE_URL`, the user's own server | False positive. SkillSpector does not distinguish localhost/user-configured hosts from external ones |
| Prompt Injection / P2 "Hidden Instructions" HIGH (25) | Span covers the whole doc body after a benign generator notice comment | False positive when the HTML comment is benign. **Read the comment text itself, not the span**; a comment that addresses the agent is the real signal |
| MCP Rug Pull / RP1 (22) | Unpinned `npx omniroute` in an install line, identical in every skill | Real but mislabeled: unpinned-install hygiene, no MCP involved. Low severity |
| Whitespace Padding / P9 (4) | Space padding to align markdown tables | False positive |
| Rogue Agent / RA2, File System Enumeration / E3 (3 each) | systemd user service the documented daemon command installs; `ls ~/.codex/skills` | **Declared capability**: real, expected for the tool's stated purpose, worth a one-line mention, not a finding |
| E4, EA5, EA2, SC2, MP3 (1-2 each) | The words "send chat", `--model claude-...`, `--non-interactive`, the localhost `curl` again, the strategy name `reset-aware` | All false positives: keyword matches in docs |

**Caveats on these numbers, stated plainly.** (1) All 46 skills are
auto-generated from one template (every file carries the same
`generated by .../generator.ts` header), so findings are heavily
correlated: the count of *distinct root causes* is far smaller than 375,
and this is closer to one sample of the tool than 46. (2) These are
documentation-only skills with no executable scripts, which is the
worst case for a tool that regex-matches document text; this does not
show it is unreliable on a skill that ships scripts (it correctly caught
a real CLAUDE.md-persistence issue in an earlier, script-bearing skill).
(3) 34 inspected is a sample, not all 375.

**Rules that follow (read the ground-truth section below before applying
these; its measurements qualify the first bullet):**
- **Do not quote SkillSpector's score, severity label, or recommendation
  in a report.** On this collection it ranged to 97/CRITICAL with no true
  finding behind it. (Ground-truth data below shows the score is *not*
  noise on a typical mixed population, so this collection is an outlier,
  not the rule. The number still can't be read without knowing which kind
  of collection it came from.)
- **Report only findings that survive reading the actual flagged line**,
  and deduplicate: the same pattern repeated across skills (22 identical
  RP1) or links (72 identical AE1) is one observation, not N.
- **AE1 goes in the limitations line**, not the findings.
- **Declared capabilities** (AS3/E3/RA2 matching the skill's own stated
  purpose) get one plain-language mention each, not an alarm.

### Ground truth: MalSkillBench sample (measured 2026-10-03)

The OmniRoute work above is my judgment of individual findings. This is
measured against **labeled data**: [MalSkillBench](https://github.com/lxyeternal/MalSkillBench)
(malicious skills confirmed by runtime sandboxing or manual review; benign
= most-downloaded real skills). Seeded random sample (seed 20261003): 111
malicious, 64 benign, run through the full pipeline unmodified.

**Caveats first, because they bound everything below.**
- *Provenance is not labeled in the release.* Names with a `__CI/PI/MIXED_Bn__`
  suffix are LLM-generated; unsuffixed names are a mix of real-world samples
  and unsuffixed generated ones (~30% wild by the paper's counts). I report
  the two groups separately and cannot isolate the wild ones.
- *Antivirus deleted 20 of the 111 malicious skills before they were
  scanned* (Windows Defender; 0 of 64 benign, 0 of 48 generated, all from
  the unsuffixed group). Those are the most blatant samples, so every recall
  figure below is **biased low**, and the pipeline reported nothing about
  them (now fixed: see the `staging/integrity` entry).
- The malicious:benign mix here (91:64) is nothing like reality. At roughly
  2% prevalence (Snyk's ToxicSkills found 76 confirmed malicious payloads
  among 3,984 skills; I'm treating that as about 1.9%), the 64% recall /
  9.4% false-positive rate measured below works
  out to **about 12% precision**: most flags would be false alarms.
- Generated samples may be easier or harder than real ones; the benign set
  is 64 of 4,000. This is one sample, not a benchmark result.

**Results (91 malicious scanned, 64 benign):**

| | benign | unsuffixed-malicious (43) | generated-malicious (48) |
|---|---|---|---|
| Any SkillSpector finding | **44%** | 81% | 83% |
| Median SkillSpector score | 0 | 41 | 49 |
| Score AUC vs benign (0.5 = noise) | n/a | 0.79 | 0.81 |
| Semgrep: any finding | 3% | 36% (33/91 across both) | |
| gitleaks: any finding | 3% | 5% (5/91 across both) | |

- **"Any finding" is a bad rule** (44% of benign skills trip it).
- **The score carries real, moderate signal here (AUC about 0.8).** This
  corrects my earlier "score is noise" conclusion, which came from one
  unusually template-heavy docs collection.
- **gitleaks is nearly useless for detecting malicious skills** (5% vs 3%),
  as expected: these attacks don't need hardcoded secrets. Keep it for the
  case it's built for.
- **Semgrep is high precision, modest recall** (36% vs 3%). Rules that fired
  on malicious skills and zero benign ones: `subprocess-shell-true` (16),
  `insecure-file-permissions` (7), `request-with-http` (4),
  `python-reverse-shell` (3), `exec-detected` (2).

**Per-category separation (share of skills with at least one finding):**

| Behaves like a real signal | benign | malicious | | Behaves like noise | benign | malicious |
|---|---|---|---|---|---|---|
| AST4 Dangerous Code Execution | 0% | 37-38% | | E1 Data Exfiltration (MEDIUM) | 23% | 23-27% |
| TM2 Tool Misuse | 0% | 9-10% | | RP1 MCP Rug Pull | 8% | 0-4% |
| YR1 YARA Match | 0% | 2-9% | | AE1 analysis-evasion | 2% | 2% |
| LP1 MCP Least Privilege (HIGH) | 0% | 6-7% | | EA2 Autonomous Decision | 5% | 4-5% |
| P2 Prompt Injection (HIGH) | 0% | 7-8% | | AS3 Agent Snooping | 2% | 2% |
| AST5, E2 | 0% | 4-9% | | P9 Whitespace Padding | 2% | 0% |
| *Moderate:* LP3 undeclared capability | 5% | 46-49% | | *Moderate:* TM1 Tool Misuse (HIGH) | 5% | 23-28% |

Selecting "high-precision" categories on a random half of the skills and
testing on the other half (300 random splits) gave **64% recall at 9.4%
false positives**, versus 82% / 44% for "any finding". AST4, TM2, YR1, P2,
AST5 and LP1 were selected in 270 or more of the 300 splits, so they are
stable, not an accident of one split.

**Where it is blind.** Among generated skills, recall by attack vector
(in-sample, so optimistic): code injection 75%, mixed instruction-and-code
71%, **pure prompt injection 50%**. Static pattern matching is weakest
exactly where the payload is natural language. (This is the case the
roadmap's dynamic prompt-injection testing is meant to cover.)

**One category needs both views.** P2 "Hidden Instructions" never fired on
the 64 benign skills here, yet fired on 25 of OmniRoute's 32 because its
generator stamps an HTML comment on every file. A category being
high-precision *in aggregate* does not replace reading the flagged line.

**Revised rules (these replace the blanket "never trust SkillSpector"):**
1. Findings in AST4, AST5, TM2, YARA, LP1, E2, and (after reading the
   comment) P2 are the primary signal. They almost never fire on benign
   skills. Still read the flagged line.
2. E1, RP1, AE1, EA2, AS3 and P9 do not separate malicious from benign:
   treat as noise unless the flagged line itself says otherwise.
3. TM1, LP3, PE3 and SC2 are moderate: they raise the odds but need a
   read-through. LP3 (an undeclared capability) is the best single
   separator but has a 5% benign rate.
4. Never say "this skill is malicious" from these flags. At realistic
   prevalence a flag means "read this skill", about 1 in 8 of which will
   actually be bad. Say so.
5. A clean result is not a clean bill of health for a skill whose payload is
   plain-language instructions: static recall there is about half.

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

## Semgrep (tier 3; `--config p/default`, was `auto`)

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

## Hostile targets and silent partial coverage (swept 2026-10-03)

A triage tool is only as trustworthy as its *negative* result, so each tier
was tested against a hostile fixture where one payload was hidden per
mechanism. With the scanners' stock behavior, **6 of 13 hidden payloads
were reported**. Every gap below was reproduced, not inferred. Two of
them (the recursive skill cap, and Semgrep's size cap) had been silently
under-scanning real runs.

| Tool | Hidden by | Fix in `triage.sh` |
|---|---|---|
| gitleaks | inline `gitleaks:allow`; the target's own `.gitleaks.toml` allowlist | `--ignore-gitleaks-allow`, `--config` (default rules only), `--gitleaks-ignore-path` (empty dir) |
| osv-scanner | the target's `.gitignore`; its own `osv-scanner.toml` `PackageOverrides` | `--no-ignore`, `--config` (empty file) |
| Semgrep | `# nosemgrep`; the target's `.semgrepignore`; any file over 1,000,000 bytes (skipped with **nothing** listed as skipped) | `--disable-nosem`, `--no-git-ignore`, `--max-target-bytes 0`, `--x-ignore-semgrepignore-files` |
| SkillSpector | a baseline file shipped in the target | **None needed**: it ignores shipped baselines unless `--use-shipped-baseline` is passed, which we never do. Verified: 3 findings reported with a baseline present, 0 only with the opt-in |

Things that were assumed and turned out **wrong or unnecessary**: Semgrep
does *not* skip `tests/` or `vendor/` by default in this version (tested,
both scanned), so no extra include rule is needed.

**Redundancy helped, by accident.** Semgrep's secret rules flagged the
planted token in all four secret files, including both that gitleaks had
been talked out of. Layering is a real defense here, not just tidiness.

**Status values.** `partial` means the tool ran but did not cover
everything, and the manifest `detail` says what was missed. Two sources:
- osv-scanner exits 128 for "no lockfile", which is *not* "no
  dependencies": a `package.json` pinning known-vulnerable versions with no
  lockfile also exits 128. It used to be reported as "nothing to check".
  It is now `partial` ("NO CVE COVERAGE") whenever a dependency manifest is
  present.
- SkillSpector reports its own gaps in `analysis_completeness` (a 3MB
  script gave `runtime_limit` plus a `degraded` analyzer). `reference_missing`
  is benign noise and ignored; anything else makes the tier `partial`.

**Rule:** never describe a `partial` tier as "nothing found". Say "nothing
found in what could be checked" and name the gap.

**Semgrep `--config auto` requires metrics to be on** (verified: it errors
with `--metrics=off`), so usage metadata goes to semgrep.dev on every scan; I
did not verify exactly what is sent. The default is therefore `p/default` with
`--metrics=off`. Measured 2026-10-07: on 411 pip files 54 vs 54 findings, same
18 rules; on OWASP/NodeGoat 37 vs 37, same 20 rules (an extra `auto` hit on
minified jquery.min.js appeared only in a run where Semgrep logged a Timeout
on that file, and `auto` matched `p/default` in a second run; a later
`p/default` run then logged the same Timeout, so it is per-run variance on that
file under either config, not a ruleset difference). `p/default` was also faster (20s vs 29s; 39s vs 71s). Other languages are unmeasured;
`TRIAGE_SEMGREP_CONFIG=auto` restores the old behavior. The
`--x-ignore-semgrepignore-files` flag is experimental; if a future Semgrep
removes it the run errors loudly, and the hostile-fixture CI test fails.

**Known gaps not fixed:** secrets that were committed and later removed
are invisible (staging clones with `--depth 1`, and gitleaks runs
`--no-git`); and SkillSpector runs static-only by default, so its
LLM-assisted semantic analyzers are off (the manifest shows `llm=0`).

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

## Domain reputation (tier 5)

- **What a match is.** URLhaus lists hosts/URLs currently serving malware; a
  literal IP or an exact URL match is a strong signal. ThreatFox is different:
  on 2026-10-04, 1,210 of its 1,371 recent domain IOCs (88%) were marked
  `is_compromised`, meaning a legitimate site that was hacked. The finding
  says so; weigh it accordingly.
- **Host-level matching is deliberately narrow.** The URLhaus online list
  contains 5,287 `raw.githubusercontent.com` URLs and 883 `github.com` ones,
  so host-level matching there would flag every GitHub reference. Only exact
  URLs (and IP literals) match. ThreatFox also lists whole
  `*.workers.dev` subdomains; those match by exact name.
- **Absence is weak evidence.** The feeds hold current/recent entries; a
  domain that distributed malware last year is not in them.
- **`newly-registered` is weak alone.** It needs a second signal.
- **Domain age is not evaluable** for shared-hosting subdomains and IPs, and
  the registrable-domain guess uses a short built-in list of two-label
  suffixes (not the Public Suffix List), so an odd TLD can produce an RDAP
  404, reported as a coverage gap, not clean.
- Measured false positives: 0 matches over 1,091 domains in 10,914 benign
  files. Recall against real malicious code is untested.

**Semgrep coverage errors (tier 3).** The JSON `errors` list says what Semgrep
could not analyze. `Timeout` is one rule not finishing on one file (the other
rules still ran there) and means that rule's findings for that file are
missing; it, out-of-memory, unparsable files and skipped paths make the entry
`partial`, naming the rule and file. `PartialParsing` means the file was
analyzed only up to the unparsable spot; common on minified or templated files
(NodeGoat: 12), counted in the detail, not a gap by itself. Errors about the
staged top-level `.git/` (`hooks/*.sample`) are repository metadata and are set
aside. `.git/` is still scanned, not excluded: `--exclude .git` and
`--exclude /.git` both also skip a nested `sub/.git/`, which a hostile zip
could use to hide files. Semgrep's per-file timeout makes results on huge
minified files slightly non-deterministic, so do not assert exact counts there.
