#!/usr/bin/env python3
"""Tests for the zip / bare-directory integrity baselines, the zip size cap, and the opt-in
git-history scan (including refusing a hostile .git/config).

Runs the real scripts/stage.sh and scripts/triage.sh, so it needs bash, git and python; the
history cases also need gitleaks and are skipped (loudly) without it.

usage: python tests/test_integrity_history.py
"""
import json
import os
import random
import shutil
import string
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
failures, skipped = [], []


def check(cond, msg):
    print(("ok   " if cond else "FAIL ") + msg)
    if not cond:
        failures.append(msg)


def sh(args, env=None, cwd=None):
    e = dict(os.environ)
    e.update(env or {})
    return subprocess.run(["bash"] + [str(a) for a in args], capture_output=True, text=True, env=e, cwd=cwd)


def triage(target, env=None):
    out = Path(tempfile.mkdtemp())
    p = sh([ROOT / "scripts" / "triage.sh", Path(target).as_posix(), out.as_posix()], env)
    mf = out / "manifest.json"
    if not mf.exists():
        print(p.stdout[-800:], p.stderr[-800:])
        return out, {}
    return out, {(t["tool"]): t for t in json.loads(mf.read_text())["tiers"]}


def stage_zip(zpath, env=None):
    root = Path(tempfile.mkdtemp())
    p = sh([ROOT / "scripts" / "stage.sh", Path(zpath).as_posix()], dict(env or {}, TRIAGE_STAGE_ROOT=root.as_posix()))
    return p, Path(p.stdout.strip()) if p.returncode == 0 else None


def git(*args, cwd=None):
    return subprocess.run(["git", *args], capture_output=True, text=True, cwd=cwd, check=True)


# ---------------------------------------------------------------- zip baseline
z = Path(tempfile.mkdtemp()) / "t.zip"
with zipfile.ZipFile(z, "w") as zf:
    zf.writestr("pkg/a.py", "print('a')\n")
    zf.writestr("pkg/b.py", "print('b')\n")
p, staged = stage_zip(z)
check(p.returncode == 0 and staged and Path(str(staged) + ".expected").exists(), "stage.sh records the extracted file list next to a zip")
if staged:
    exp = Path(str(staged) + ".expected").read_text().split()
    check(exp == ["pkg/a.py", "pkg/b.py"], f"expected list is the extracted files ({exp})")
    _, m = triage(staged)
    check(m.get("integrity", {}).get("status") == "ran" and "zip" in m["integrity"]["detail"], "zip with nothing removed -> integrity ran")
    (staged / "pkg" / "b.py").unlink()
    _, m = triage(staged)
    i = m.get("integrity", {})
    check(i.get("status") == "partial" and "pkg/b.py" in i.get("detail", ""), "a file deleted after extraction -> integrity partial, naming the file")

# zip size cap: refused before anything is extracted
p, staged = stage_zip(z, {"TRIAGE_ZIP_MAX_FILES": "1"})
check(p.returncode != 0 and "over the limit" in p.stderr, "zip over the file-count limit is refused with an explanation")

# ---------------------------------------------------------------- bare directory baseline
d = Path(tempfile.mkdtemp())
(d / "keep.py").write_text("print(1)\n")
(d / "victim.txt").write_text("stand-in for a file antivirus deletes mid-scan\n")
_, m = triage(d)
i = m.get("integrity", {})
check(i.get("status") == "ran" and "BEFORE the scan are not detectable" in i.get("detail", ""), "bare dir, nothing removed -> ran, with the baseline's limit stated")
shim = Path(tempfile.mkdtemp())
(shim / "gitleaks").write_text(f'#!/usr/bin/env bash\nrm -f "{(d / "victim.txt").as_posix()}"\nexit 0\n')
os.chmod(shim / "gitleaks", 0o755)
_, m = triage(d, {"PATH": shim.as_posix() + os.pathsep + os.environ["PATH"]})
i = m.get("integrity", {})
(d / "victim.txt").write_text("restore\n")
check(i.get("status") == "partial" and "victim.txt" in i.get("detail", ""), "bare dir, file removed DURING the scan -> integrity partial, naming the file")

# ---------------------------------------------------------------- git history
if shutil.which("gitleaks") is None:
    skipped.append("git history cases (gitleaks not installed)")
    print("SKIP git history cases: gitleaks not installed")
else:
    token = "ghp_" + "".join(random.SystemRandom().choices(string.ascii_letters + string.digits, k=36))  # random fake, not a real token
    repo = Path(tempfile.mkdtemp()) / "repo"
    repo.mkdir()
    git("init", "-q", cwd=repo)
    git("config", "user.email", "t@example.com", cwd=repo)
    git("config", "user.name", "t", cwd=repo)
    git("config", "core.autocrlf", "false", cwd=repo)
    (repo / "app.py").write_text("print('hello')\n")
    git("add", "-A", cwd=repo); git("commit", "-q", "-m", "initial", cwd=repo)
    (repo / ".env").write_text(f"GITHUB_TOKEN={token}\n")
    git("add", "-A", cwd=repo); git("commit", "-q", "-m", "add config", cwd=repo)
    git("rm", "-q", ".env", cwd=repo); git("commit", "-q", "-m", "remove config", cwd=repo)
    (repo / "README.md").write_text("# docs\n")
    git("add", "-A", cwd=repo); git("commit", "-q", "-m", "docs", cwd=repo)
    git("config", "--unset", "core.autocrlf", cwd=repo)

    def leaks(out):
        f = out / "tier0_gitleaks_history.json"
        return json.loads(f.read_text() or "[]") if f.exists() else None

    out, m = triage(repo)
    check("gitleaks-history" not in m, "history scan is off by default (no manifest entry)")
    base = json.loads((out / "tier0_gitleaks.json").read_text() or "[]")
    check(len(base) == 0, "default scan cannot see a secret that was committed and later removed")

    out, m = triage(repo, {"TRIAGE_GIT_HISTORY": "1"})
    h = m.get("gitleaks-history", {})
    found = leaks(out) or []
    check(h.get("status") == "ran" and "4 commit" in h.get("detail", ""), f"TRIAGE_GIT_HISTORY=1 on a full repo -> ran ({h.get('detail', '')[:70]})")
    check(len(found) >= 1 and found[0].get("File") == ".env", "history scan finds the removed secret in .env")

    shallow = Path(tempfile.mkdtemp()) / "shallow"
    git("clone", "-q", "--depth", "1", "--no-tags", repo.as_uri(), str(shallow))
    out, m = triage(shallow, {"TRIAGE_GIT_HISTORY": "1"})
    h = m.get("gitleaks-history", {})
    check(h.get("status") == "partial" and "shallow" in h.get("detail", ""), "shallow clone -> partial, says earlier commits are NOT covered")
    check(len(leaks(out) or []) == 0, "shallow clone does not contain the removed secret, so nothing is found (hence partial)")

    _, m = triage(d, {"TRIAGE_GIT_HISTORY": "1"})
    check(m.get("gitleaks-history", {}).get("status") == "skipped" and "no .git" in m["gitleaks-history"]["detail"], "target without .git -> skipped with a reason")

    # hostile .git/config: a textconv driver makes `git log -p` run a program
    hostile = Path(tempfile.mkdtemp()) / "hostile"
    shutil.copytree(repo, hostile)
    canary = Path(tempfile.mkdtemp()) / "PWNED"
    with open(hostile / ".git" / "config", "a") as fh:
        fh.write(f'[diff "evil"]\n\ttextconv = touch {canary.as_posix()}\n')
    (hostile / ".git" / "info").mkdir(exist_ok=True)
    (hostile / ".git" / "info" / "attributes").write_text("*.py diff=evil\n*.env diff=evil\n")
    subprocess.run(["git", "log", "-p", "--all"], cwd=hostile, capture_output=True)
    control = canary.exists()
    check(control, "positive control: this hostile config DOES make a plain `git log -p` run a program (so the next check is meaningful)")
    if canary.exists():
        canary.unlink()
    out, m = triage(hostile, {"TRIAGE_GIT_HISTORY": "1"})
    h = m.get("gitleaks-history", {})
    check(h.get("status") == "skipped" and "REFUSED" in h.get("detail", "") and "diff.evil.textconv" in h.get("detail", ""),
          "hostile .git/config -> history scan REFUSED, naming the setting")
    check(not canary.exists(), "the textconv program was NOT executed during triage")

print()
if skipped:
    print("skipped:", "; ".join(skipped))
print("FAILED: %d" % len(failures) if failures else "all passed")
sys.exit(1 if failures else 0)
