---
name: security-triage
description: >
  Triage a third-party artifact (a Claude Code skill, an MCP server, a
  package from a registry, or a general repo/application) for security
  risk before installing, running, or trusting it. Runs a layered,
  fully-open-source static scan — secrets, known CVEs, skill/MCP-specific
  risk patterns, malicious-package heuristics, general SAST — and writes a
  synthesized trust report with explicit false-positive notes and a stated
  limitations line. Does not require any third-party account or API token.

  Trigger on explicit requests such as: "scan this skill before I install
  it", "triage this MCP server", "vet this package", "is this repo safe to
  run", "security-check this before I trust it", "audit this before
  installing". Also trigger when the user pastes a git URL, a local path,
  a zip, or a registry package name together with a request to check it
  for safety.

  Do NOT trigger on requests to review the user's OWN code for bugs or
  code quality (use the code-review or security-review skill for that —
  this skill is for vetting a THIRD-PARTY artifact before trusting it),
  on generic "look at this" with no safety/trust framing, or on requests
  about something already installed and in daily use with no stated
  concern about its origin.
allowed-tools: Bash, Read
---

# Security triage (v1 — static analysis only)

This skill vets a third-party artifact before the user installs, runs, or
otherwise extends trust to it. It is layered rather than branched: every
tool here is either genuinely input-agnostic (works identically on any
code) or self-scoping (only activates on the file types it understands and
silently finds nothing otherwise). Classification is never used to pick a
single tool and discard the rest — that produced meaningless, high-severity
false positives in earlier testing (a skill-specific scanner pointed at a
general app repo scored it 100/100 CRITICAL on noise). Run everything that
applies; never guess which lens is "right" for the input.

## When invoked

1. **Identify the input.** It will be one of: a local directory path, a
   git URL, a path to a zip file, or a registry package reference (e.g.
   "npm package left-pad", "pypi package requests==2.0.0"). Ask the user
   only if the input is genuinely ambiguous (e.g., a bare name with no
   stated ecosystem and no URL).

2. **Stage it.** This skill's own directory — the one containing this
   `SKILL.md` — also contains `scripts/`. Resolve that directory path
   first (it may be installed at the user level, at the project level, or
   under a different name if cloned manually), then run:
   ```
   bash "<this-skill-dir>/scripts/stage.sh" "<input>"
   ```
   This prints either a local staged directory path, or a
   `REGISTRY:<ecosystem>:<name>[@version]` marker for registry references
   that downstream tools handle natively. Staging never executes install
   scripts, build hooks, or postinstall steps — it only fetches/extracts.
   If staging fails, report the error; do not fall back to manually
   cloning or downloading yourself.

3. **Run the pipeline.** Run:
   ```
   bash "<this-skill-dir>/scripts/triage.sh" "<staged_target>" "<output_dir>"
   ```
   Pick a fresh `<output_dir>` under the scratchpad directory. This runs
   every applicable tier and writes one raw output file per tool plus a
   `manifest.json` listing what ran, what was skipped (and why — almost
   always a missing CLI, which the manifest states how to install), and
   where each tier's raw findings live. A tier marked `partial` ran but
   did not cover everything (the `detail` says what was missed): treat a
   clean result from it as "nothing found in what could be checked",
   never as "nothing found", and if the gap could change the verdict (for
   example no CVE coverage because dependencies have no lockfile), say so
   in the plain-language lead, not only in the details.

4. **Read every file the manifest points to.** Do not summarize from the
   manifest alone — read the actual tier output files before writing the
   report.

5. **Apply the interpretation notes** in `references/tool-notes.md` before
   presenting anything. These encode known false-positive patterns per
   tool (e.g., discard SkillSpector findings entirely if the target has no
   `SKILL.md` anywhere — that is the exact misapplication that produced
   garbage output in testing). Do not present a raw tool score as if it
   were a verdict. For SkillSpector specifically: don't quote its score,
   severity label, or recommendation (its score separates malicious from
   benign skills only moderately, and reached 97/CRITICAL on a harmless
   templated-docs collection), and report only findings that survive
   reading the flagged line, deduplicated (the same pattern repeated
   across skills or links is one observation). Weight categories by what
   was measured against labeled data in `references/tool-notes.md`: code
   execution, tool misuse (TM2), YARA, high-severity least-privilege and
   exfiltration findings are the primary signal; exfiltration (E1),
   rug-pull, analysis-evasion, autonomous-decision, snooping and
   whitespace findings did not separate malicious from benign and are
   noise unless the line itself says otherwise. "Analysis-evasion" is the
   tool's own coverage gap, so it goes in the limitations. A flag means
   "read this skill", never "this is malicious": at realistic prevalence
   only about 1 flag in 8 is. If a skill's payload is plain-language
   instructions, a clean static result is weak evidence (recall there is
   about half). If a `--recursive` result shows `skills_omitted > 0` in
   the final manifest, coverage was partial and the report must say so.
   A `staging/integrity` entry marked `partial` means files were removed
   from the scanned tree (often antivirus), so some of the artifact was
   never analyzed; say that plainly.
   A Semgrep entry marked `partial` names a rule that timed out (or ran out
   of memory) on a file: that rule's findings for that file are missing, so
   say a clean result there covers "what Semgrep could analyze".
   A `gitleaks-history` entry (only with `TRIAGE_GIT_HISTORY=1`) scans past
   commits: a hit there is a real credential even though it was removed
   from the current files, so say it should be treated as compromised
   (rotated), not as fixed. `partial` there means a shallow clone, so older
   commits were NOT checked; `skipped` with REFUSED means the repository's
   own git settings were unsafe to run and no history was scanned. Report
   those as absent coverage, never as "no secrets in history".

   **Tier 4 (`sandbox-exec`, only present when the user set
   `TRIAGE_EXECUTE=1`).** Its per-script `clean/review/high` describes what
   the script *attempted* when run once with no arguments and no network.
   `clean` is never evidence of safety (a payload gated on arguments, time
   or a network interface is invisible; that is a measured limit, not a
   guess), so do not let it soften a static finding. A `high` or `review`
   script means "read that script", and corroborates a static finding on
   the same file. `skipped` means nothing was run (say so, with the reason
   in the manifest); `REFUSED` (status `ran-with-errors`) means the
   containment check failed and **nothing was executed**: report dynamic
   coverage as absent, not as clean. Executed files and gaps are named in
   the entry's detail; repeat any gap that matters.

   **Tier 5 (`domain-reputation`).** A `known-bad-host/url/ip` match comes
   from abuse.ch feeds of current malware infrastructure: read the line it
   points to first (is it a download, a fetch at install time, or just a
   comment or test fixture?). A URLhaus match on a literal IP or exact URL
   is a strong signal and can lead Part 1 if the reference is live code. A
   ThreatFox match marked COMPROMISED means a legitimate site was hacked, so
   the domain itself may be innocent: weaker, say that. `newly-registered`
   is weak alone (new projects have new domains): mention it only next to
   another signal, or in Part 2. Not being listed proves little (the feeds
   hold current/recent entries only), and `skipped` or `partial` means some
   domains were NOT checked: say that, never "no bad domains". Never contact
   a domain from the target yourself to check it.

6. **Write the synthesis.** Two parts, in this order — the first part is
   for a reader who has never seen this skill's internals and never will:

   **Part 1 — plain-language verdict (lead with this, always):**
   2-4 sentences, no tool names, no rule IDs, no category jargon
   ("Supply Chain", "Excessive Agency", "MCP Rug Pull" etc. belong in
   Part 2, never in Part 1). State: is this safe to trust/install, and if
   not, what's the one concrete thing wrong (e.g. "a dependency has 12
   known security bugs," not "osv-scanner flagged axios@1.18.0"). If
   nothing survived scrutiny, say so plainly ("nothing concerning found")
   rather than padding this section with caveats that belong in Part 2.

   **Part 2 — details, for whoever wants to verify:**
   - One line per tier: ran / skipped (with reason), and a one-line
     takeaway if it ran.
   - Findings grouped by confidence, not by tool: corroborated across
     multiple tiers (high confidence) vs. single-source (lower confidence,
     state which tool and why it might still be noise per the reference
     notes).
   - Never a single merged numeric score across tools; the tiers measure
     different things and forcing one number is what caused the earlier
     false-positive failure. (Part 1's plain verdict is a sentence, not a
     score — it's fine for it to be definitive even though no number is
     computed.)
   - This exact closing line, verbatim, every time, at the very end:
     *"This is a static-analysis-only triage (v1): it does not execute
     the artifact, so it cannot catch payloads that only activate at
     runtime, does not detect an already-approved artifact changing
     later (no drift/rug-pull detection), and does not adversarially test
     prompt-injection resistance beyond static pattern matching."*

     If the manifest shows `sandbox-exec` with status `ran` or `partial`,
     use instead this line, because the first one would then be false:
     *"This triage was mostly static; the only code it ran was the skill's
     own scripts, once, with no arguments and no network, so it cannot
     catch payloads gated on arguments, time or network access, does not
     detect an already-approved artifact changing later (no drift/rug-pull
     detection), and does not adversarially test prompt-injection
     resistance beyond static pattern matching."*

   A reader should be able to stop after Part 1 and walk away with the
   right answer. Part 2 exists for someone who wants to check your work,
   not because the answer needs that much qualification to be true.

## What this is not

This is pre-install/pre-trust triage of one artifact, not continuous
monitoring of an already-installed agent surface, not a replacement for
reading the code yourself on anything it flags, and not sufficient alone
for a high-stakes trust decision (e.g., production credentials, financial
systems) — say so if the user's stated use case sounds like that.

This skill also needs broad `Bash` access itself — it shells out to
whichever external scanner CLIs are installed (git, pip, gitleaks,
osv-scanner, skillspector, guarddog, semgrep). There's no finer-grained
Claude Code frontmatter scope for "Bash, but only for these specific
commands," so `allowed-tools: Bash, Read` is the honest declaration, not
a gap to engineer around. Read `scripts/` yourself before trusting this
skill, for the same reason it exists.
