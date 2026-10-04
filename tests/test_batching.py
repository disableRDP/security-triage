#!/usr/bin/env python3
"""Control-flow test for the past-32-skills batching in scripts/triage.sh, using a fake
`skillspector` that reproduces the real tool's --recursive 32-skill cap. (The real tool takes
minutes for this many skills; equivalence of real findings was measured separately: 70 skills,
42 findings, 0 differences between batched and one-at-a-time.)

The fake also silently drops one skill from every recursive result, to prove the
one-at-a-time fallback still covers anything a batch fails to report.

usage: python tests/test_batching.py
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
failures = []


def check(cond, msg):
    print(("ok   " if cond else "FAIL ") + msg)
    if not cond:
        failures.append(msg)


SHIM_PY = r'''
import json, os, sys
args = sys.argv[1:]
log = os.environ["SHIM_LOG"]
if args[:1] != ["scan"]:
    sys.exit(0)
target, rec = args[1], "--recursive" in args
def has_issue(name):
    return name.endswith("3") or name.endswith("7")   # a few skills "have findings"
ok = {"analysis_completeness": {"ledger_exceptions": [], "limitations": []}}
if rec:
    names = sorted(d for d in os.listdir(target) if os.path.isfile(os.path.join(target, d, "SKILL.md")))
    scanned = [n for n in names if n != "skill-flaky"][:32]   # real cap, plus one silent drop
    with open(log, "a") as fh:
        fh.write(f"recursive {os.path.basename(target.rstrip('/'))} n={len(names)} scanned={len(scanned)}\n")
    out = dict(ok, multi_skill=True, skill_count=len(names), skills_scanned=len(scanned), skills_omitted=len(names) - len(scanned),
               skills=[{"name": n, "path": n, "issues": ([{"id": "X"}] if has_issue(n) else [])} for n in scanned])
    out["analysis_completeness"]["limitations"] = ["recursive skill scan hit the aggregate limit"] if len(names) > 32 else []
else:
    name = os.path.basename(target.rstrip("/"))
    with open(log, "a") as fh:
        fh.write(f"single {name}\n")
    out = dict(ok, skill={"name": name, "source": target}, issues=([{"id": "X"}] if has_issue(name) else []))
print(json.dumps(out))
'''

work = Path(tempfile.mkdtemp())
shim = work / "bin"
shim.mkdir()
(shim / "ss_shim.py").write_text(SHIM_PY)
(shim / "skillspector").write_text('#!/usr/bin/env bash\nexec "$SHIM_PY" "$(dirname "$0")/ss_shim.py" "$@"\n')
os.chmod(shim / "skillspector", 0o755)

N = 70
coll = work / "coll" / "skills"
for i in range(N - 1):
    d = coll / f"skill-{i:03d}"
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(f"---\nname: skill-{i:03d}\ndescription: x\n---\n# s\n")
d = coll / "skill-flaky"
d.mkdir()
(d / "SKILL.md").write_text("---\nname: skill-flaky\ndescription: x\n---\n# s\n")

# The other tiers are irrelevant here and slow (minutes): stub them out so only the batching runs.
for tool in ("gitleaks", "osv-scanner", "semgrep", "guarddog"):
    (shim / tool).write_text("#!/usr/bin/env bash\nexit 0\n")
    os.chmod(shim / tool, 0o755)

log = work / "calls.log"
out = work / "out"
env = dict(os.environ, SHIM_LOG=str(log), SHIM_PY=sys.executable,
           PATH=shim.as_posix() + os.pathsep + os.environ["PATH"])
# On Windows a bare "bash" resolves to System32\bash.exe (the WSL launcher), not Git Bash.
env_path = shim.as_posix() + os.pathsep + os.environ["PATH"]
bash = shutil.which("bash", path=os.environ["PATH"]) or "bash"
ver = subprocess.run([bash, "--version"], capture_output=True, text=True).stdout.split("\n")[0]
print(f"using {bash}: {ver}")
p = subprocess.run([bash, str(ROOT / "scripts" / "triage.sh"), (work / "coll").as_posix(), out.as_posix()], capture_output=True, text=True, env=env)
mf = out / "manifest.json"
check(mf.exists(), "triage.sh completed with the fake skillspector")
if not mf.exists():
    print(p.stdout[-600:], p.stderr[-1500:])
    sys.exit(1)
if not (work / "calls.log").exists():
    print("DIAGNOSTIC: the fake skillspector was never called. triage.sh stderr tail:\n" + p.stderr[-2500:])
    print("tiers:", [(t["tool"], t["status"], t["detail"][:90]) for t in json.loads(mf.read_text())["tiers"]])
tiers = [t for t in json.loads(mf.read_text())["tiers"] if t["tool"] == "skillspector"]
calls = log.read_text().split("\n") if log.exists() else []
calls = [c for c in calls if c]
rec = [c for c in calls if c.startswith("recursive")]
single = [c.split()[1] for c in calls if c.startswith("single")]

# first call: the collection root, capped at 32 by the fake (as by the real tool)
check(rec and rec[0].split()[1] == "skills" and "n=70" in rec[0] and "scanned=32" in rec[0], f"first recursive scan covers the root and is capped at 32 ({rec[:1]})")
batch_sizes = [int(c.split()[2][2:]) for c in rec[1:]]
check(batch_sizes and max(batch_sizes) <= 32, f"every batch has at most 32 skills (sizes {batch_sizes})")
check(sum(batch_sizes) == 70 - 32, f"batches together cover exactly the 38 skills past the cap (sizes {batch_sizes})")
check(len(batch_sizes) == 2, "38 remaining skills -> 2 batches (32 + 6), not 38 separate scans")
check(single == ["skill-flaky"], f"only the skill a batch failed to report is scanned alone ({single})")
check(all(t["status"] == "ran" for t in tiers), f"all skillspector entries ran ({sorted({t['status'] for t in tiers})})")
check(len(tiers) == 1 + 2 + 1, f"manifest has root + 2 batches + 1 individual entries (got {len(tiers)})")
check(not (out / ".batches").exists() or not any((out / ".batches").iterdir()), "batch copies are removed after each batch")
check(not any((coll / n).is_symlink() for n in os.listdir(coll)), "the original collection was not modified")
outs = sorted(out.glob("tier1_skillspector_*.json"))
seen = set()
for f in outs:
    dd = json.loads(f.read_text())
    if "skills" in dd:
        seen |= {s["name"] for s in dd["skills"] if "issues" in s}
    else:
        seen.add(dd["skill"]["name"])
check(len(seen) == N, f"every one of the {N} skills has a result in some output file ({len(seen)})")

print("\nFAILED: %d" % len(failures) if failures else "\nall passed")
sys.exit(1 if failures else 0)
