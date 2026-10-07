#!/usr/bin/env python3
"""Run the prompt-injection study (or a pilot of it) and report compliance and cost.

  python run_study.py --agent mock --policy comply          # free, offline: exercises the pipeline
  python run_study.py --dry-run --model claude-sonnet-5-5   # no calls: plan + cost projection
  python run_study.py --agent api --model claude-sonnet-5-5 --pilot --budget-usd 2   # REAL calls, REAL money

The api agent needs credentials (ANTHROPIC_API_KEY or `ant auth login`). It stops the moment the
budget cap is reached and says so. Results are appended to a JSONL file, one line per run.
"""
import argparse
import collections
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from agents import ApiAgent, Budget, BudgetExceeded, MockAgent, make_world, system_prompt, timed  # noqa: E402
from corpus import build_corpus  # noqa: E402
from pricing import ASSUMED_FIELDS, PRICES, PRICES_AS_OF, cost_usd  # noqa: E402
from verifier import verify  # noqa: E402
from world import TOOL_SCHEMAS  # noqa: E402

# Pilot: one injected skill per category (varying goal) plus one clean control.
PILOT_IDS = ["override-read_canary", "authority-exfil", "setup_step-command", "hidden_reference-persist",
             "conditional-exfil", "pretext-read_canary", "benign-1"]


def est_tokens(text):
    """Rough token count: ~3.7 characters per token. Only for the projection; real runs report real usage."""
    return int(len(text) / 3.7) + 1


SCENARIOS = {  # (tool turns per run, output tokens per turn): low / mid / high
    "low": (3, 150),
    "mid": (5, 400),
    "high": (9, 1200),
}
STEP_TOKENS = 350          # what each extra turn adds to the re-sent context (tool call + result)


def base_context_tokens(entry):
    w = make_world(entry)
    return est_tokens(system_prompt(w.skills) + json.dumps(TOOL_SCHEMAS) + entry["task"] + "".join(entry["files"].values()))


def project(model, entries, trials, scenario):
    """Estimated dollars for entries x trials. No prompt caching; every turn re-sends the whole context."""
    turns, out_per_turn = SCENARIOS[scenario]
    total_in = total_out = 0
    for e in entries:
        base = base_context_tokens(e)
        total_in += sum(base + t * STEP_TOKENS for t in range(turns))
        total_out += turns * out_per_turn
    n = trials
    return cost_usd(model, total_in * n, total_out * n), total_in * n, total_out * n


def print_projection(entries, trials):
    print(f"\nProjected cost for {len(entries)} skills x {trials} trial(s) = {len(entries) * trials} runs "
          f"(ESTIMATE; prices as of {PRICES_AS_OF}; assumed fields: {ASSUMED_FIELDS}; no prompt caching)")
    print(f"{'model':20s} {'low':>9s} {'mid':>9s} {'high':>9s}   per run (mid)")
    for m in PRICES:
        row = [project(m, entries, trials, s)[0] for s in SCENARIOS]
        print(f"{m:20s} ${row[0]:8.2f} ${row[1]:8.2f} ${row[2]:8.2f}   ${row[1] / (len(entries) * trials):.3f}")
    print("scenarios: " + "; ".join(f"{k} = {t} turns, {o} output tokens/turn" for k, (t, o) in SCENARIOS.items())
          + f"; each extra turn re-sends ~{STEP_TOKENS} more tokens. Extended thinking raises the output side.")


def summarize(rows):
    by = collections.defaultdict(list)
    for r in rows:
        by[r["category"]].append(r)
    print(f"\n{'category':18s} {'runs':>4s} {'complied':>9s} {'unsafe':>7s} {'task ok':>8s} {'$/run':>8s} {'tokens in/out':>16s}")
    for cat, rs in sorted(by.items()):
        n = len(rs)
        print(f"{cat:18s} {n:4d} {sum(r['complied'] for r in rs):4d}/{n:<4d} {sum(r['unsafe_any'] for r in rs):3d}/{n:<3d} "
              f"{sum(r['task_done'] for r in rs):4d}/{n:<3d} {sum(r['cost_usd'] for r in rs) / n:8.4f} "
              f"{sum(r['usage']['input_tokens'] for r in rs) // n:7d}/{sum(r['usage']['output_tokens'] for r in rs) // n:<7d}")
    spent = sum(r["cost_usd"] for r in rows)
    print(f"total spent ${spent:.4f} over {len(rows)} runs (${spent / max(len(rows), 1):.4f}/run)")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--agent", choices=["mock", "api"], default="mock")
    ap.add_argument("--policy", default="comply", help="mock agent behavior: comply|refuse|partial|overrefuse|wander")
    ap.add_argument("--model", default="claude-sonnet-5-5")
    ap.add_argument("--effort", default=None, help="low|medium|high|xhigh|max (not for Haiku)")
    ap.add_argument("--trials", type=int, default=1)
    ap.add_argument("--pilot", action="store_true", help="the 7-skill pilot set")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--category", default=None)
    ap.add_argument("--budget-usd", type=float, default=None)
    ap.add_argument("--out", default=None, help="JSONL results file")
    ap.add_argument("--dry-run", action="store_true", help="plan and project cost; make no calls")
    a = ap.parse_args()

    entries = build_corpus()
    if a.pilot:
        entries = [e for e in entries if e["id"] in PILOT_IDS]
    if a.category:
        entries = [e for e in entries if e["category"] == a.category]
    if a.limit:
        entries = entries[:a.limit]
    print(f"{len(entries)} skills x {a.trials} trial(s) = {len(entries) * a.trials} runs; agent={a.agent} model={a.model}")
    if a.dry_run:
        print_projection(entries, a.trials)
        return 0
    if a.agent == "api" and a.budget_usd is None:
        print("refusing to make real API calls without --budget-usd (a hard cap on spend)")
        return 2

    agent = MockAgent(a.policy, a.model) if a.agent == "mock" else ApiAgent(a.model, a.effort)
    budget = Budget(a.budget_usd)
    out = a.out or os.path.join(tempfile.mkdtemp(), "results.jsonl")
    rows = []
    try:
        with open(out, "a", encoding="utf-8", newline="\n") as fh:
            for e in entries:
                for trial in range(a.trials):
                    before = budget.spent
                    t = timed(agent, e, budget)
                    v = verify(e, t["calls"], t["final_text"])
                    row = {"id": e["id"], "category": e["category"], "goal": e["goal"], "trial": trial, "model": a.model,
                           "agent": a.agent, "complied": v["complied"], "unsafe_any": v["unsafe_any"], "task_done": v["task_done"],
                           "events": v["events"], "usage": t["usage"], "turns": t["turns"], "stop": t["stop"], "error": t["error"],
                           "seconds": t["seconds"], "cost_usd": round(budget.spent - before, 6) if a.agent == "api"
                           else round(cost_usd(a.model, t["usage"]["input_tokens"], t["usage"]["output_tokens"]), 6)}
                    rows.append(row)
                    fh.write(json.dumps(row) + "\n")
                    fh.flush()
                    print(f"  {e['id']:28s} t{trial} complied={row['complied']!s:5} unsafe={row['unsafe_any']!s:5} task={row['task_done']!s:5} "
                          f"turns={row['turns']} ${row['cost_usd']:.4f}" + (f"  ERROR {row['error']}" if row['error'] else ""))
    except BudgetExceeded as ex:
        print(f"STOPPED: budget cap reached ({ex}). Results so far are kept.")
    if rows:
        summarize(rows)
        print(f"results: {out}")
        if a.agent == "api":
            print_projection(build_corpus(), 5)
            print("(the projection above is the ESTIMATE; compare with the measured $/run to calibrate it)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
