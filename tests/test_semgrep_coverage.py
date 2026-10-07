#!/usr/bin/env python3
"""Tests for how triage.sh reports Semgrep: the default config and flags, and whether the
JSON "errors" list reaches the manifest (a Timeout used to still say "ran, exit 0").

A fake `semgrep` prints crafted JSON, so no real Semgrep (or network) is needed and every
other tier is stubbed out.

usage: python tests/test_semgrep_coverage.py
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
target = args[-1]
open(os.environ["SHIM_ARGS"], "w").write(" ".join(args))
case = os.environ.get("SG_CASE", "clean")
j = lambda rel: os.path.join(target, *rel.split("/"))
timeout = {"type": "Timeout", "level": "warn", "code": 2, "rule_id": "javascript.lang.security.some-rule", "path": j("app/vendor/big.min.js"), "message": "Timeout"}
partial = lambda rel: {"type": ["PartialParsing", [{"path": j(rel)}]], "level": "warn", "code": 3, "path": j(rel), "message": "Syntax error"}
errors = {
    "clean": [],
    "timeout": [timeout],
    "partial_only": [partial("src/a.js"), partial("src/b.js")],
    "git_top": [partial(".git/hooks/pre-rebase.sample"), dict(timeout, path=j(".git/hooks/x.sample"))],
    "git_nested": [dict(timeout, path=j("sub/.git/nested.js"))],
    "oom": [{"type": "OutOfMemory", "level": "warn", "code": 2, "rule_id": "a.b.rule-x", "path": j("src/huge.js"), "message": "oom"}],
}[case]
print(json.dumps({"results": [], "errors": errors, "paths": {"scanned": []}}))
'''

work = Path(tempfile.mkdtemp())
shim = work / "bin"
shim.mkdir()
(shim / "sg_shim.py").write_text(SHIM_PY)
(shim / "semgrep").write_text('#!/usr/bin/env bash\nexec "$SHIM_PY" "$(dirname "$0")/sg_shim.py" "$@"\n')
os.chmod(shim / "semgrep", 0o755)
for tool in ("gitleaks", "osv-scanner", "skillspector", "guarddog"):   # irrelevant here, and slow
    (shim / tool).write_text("#!/usr/bin/env bash\nexit 0\n")
    os.chmod(shim / tool, 0o755)

target = work / "target"
for rel in ("src/a.js", "app/vendor/big.min.js", "sub/.git/nested.js", ".git/hooks/pre-rebase.sample", ".git/HEAD"):
    f = target / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("x\n")

BASH = shutil.which("bash") or "bash"   # not System32\bash.exe (WSL) on Windows


def run(case, **extra):
    out = Path(tempfile.mkdtemp())
    args_file = work / "args.txt"
    if args_file.exists():
        args_file.unlink()
    env = dict(os.environ, SG_CASE=case, SHIM_ARGS=str(args_file), SHIM_PY=sys.executable,
               PATH=shim.as_posix() + os.pathsep + os.environ["PATH"], **extra)
    env.pop("TRIAGE_SEMGREP_CONFIG", None) if "TRIAGE_SEMGREP_CONFIG" not in extra else None
    subprocess.run([BASH, str(ROOT / "scripts" / "triage.sh"), target.as_posix(), out.as_posix()], capture_output=True, text=True, env=env)
    mf = out / "manifest.json"
    tiers = {t["tool"]: t for t in json.loads(mf.read_text())["tiers"]} if mf.exists() else {}
    return tiers.get("semgrep", {}), (args_file.read_text() if args_file.exists() else "")


s, args = run("clean")
check("--config p/default" in args and "--metrics=off" in args, f"default is p/default with metrics off ({args[:70]})")
check("--config auto" not in args, "auto is not the default any more")
check(s.get("status") == "ran" and "no analysis errors" in s.get("detail", ""), "no errors -> ran, says so")

s, args = run("clean", TRIAGE_SEMGREP_CONFIG="auto")
check("--config auto" in args and "--metrics=off" not in args, "TRIAGE_SEMGREP_CONFIG=auto still works and does not pass --metrics=off")

s, _ = run("timeout")
d = s.get("detail", "")
check(s.get("status") == "partial" and "1 Timeout" in d and "some-rule" in d and "app/vendor/big.min.js" in d,
      "a Timeout -> partial, naming the rule and the file")

s, _ = run("oom")
check(s.get("status") == "partial" and "OutOfMemory" in s.get("detail", ""), "OutOfMemory -> partial")

s, _ = run("partial_only")
check(s.get("status") == "ran" and "2 PartialParsing" in s.get("detail", ""), "PartialParsing only -> still ran, counted in the detail")

s, _ = run("git_top")
check(s.get("status") == "ran" and "2 warning(s) about the staged .git/" in s.get("detail", ""),
      "errors about the TOP-LEVEL .git/ are set aside, not counted as gaps")

s, _ = run("git_nested")
check(s.get("status") == "partial" and "sub/.git/nested.js" in s.get("detail", ""),
      "an error under a NESTED .git/ is still a gap (that directory is target content, not repo metadata)")

print("\nFAILED: %d" % len(failures) if failures else "\nall passed")
sys.exit(1 if failures else 0)
