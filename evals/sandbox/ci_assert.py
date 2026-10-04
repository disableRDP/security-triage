#!/usr/bin/env python3
"""CI assertions for scripts/sandbox_run.sh.

usage: ci_assert.py ok <out_dir> <sample_dir>...             # full run over the canary samples
       ci_assert.py refused <out_dir> [failing_check ...]    # sandbox deliberately weakened; the
                                                             # named probe checks must be among the failures

Exits non-zero (printing why) on any unmet expectation.
"""
import json
import os
import sys

mode, out = sys.argv[1], sys.argv[2]
res = json.load(open(os.path.join(out, "dynamic", "result.json")))
problems = []


def expect(cond, msg):
    if not cond:
        problems.append(msg)


if mode == "refused":
    expect(res["status"] == "ran-with-errors", f"status should be ran-with-errors, got {res['status']}")
    expect("REFUSED" in res["detail"], "detail should say REFUSED")
    # Nothing may have been executed: no trace directory contents, no analysis.
    for dp, _, fs in os.walk(os.path.join(out, "dynamic")):
        expect("analysis.json" not in fs, f"analysis.json exists in {dp}: scripts ran despite a failed probe")
        expect("trace.tar" not in fs or os.path.getsize(os.path.join(dp, "trace.tar")) == 0, f"trace.tar written in {dp}")
    print("failed checks:", res["detail"].split("Failed checks:")[-1].strip())
    want = sys.argv[3:]
    if want:
        probe = json.load(open(os.path.join(out, "dynamic", "1", "probe.json")))
        failed = {c["name"] for c in probe["checks"] if not c["ok"]}
        for name in want:
            expect(name in failed, f"probe check {name!r} should have failed on the weakened sandbox but did not (failed: {sorted(failed)})")
else:
    samples = [os.path.basename(s.rstrip("/")) for s in sys.argv[3:]]
    expect(res["status"] in ("ran", "partial"), f"status {res['status']}: {res['detail']}")
    verdicts, gaps = {}, {}
    for i, name in enumerate(samples, 1):
        p = os.path.join(out, "dynamic", str(i), "analysis.json")
        if not os.path.exists(p):
            problems.append(f"no analysis for {name}")
            continue
        a = json.load(open(p))
        verdicts[name] = {k: v["verdict"] for k, v in a["scripts"].items()}
        gaps[name] = a["coverage_gaps"]
        print(f"{name:20s} {verdicts[name]} gaps={len(gaps[name])}")
    flat = lambda n: set(verdicts.get(n, {}).values())
    expect(flat("malicious-canary") == {"high"}, f"malicious-canary should be high: {flat('malicious-canary')}")
    expect(flat("evasive-tamper") == {"high"}, f"evasive-tamper should be high (trace must survive tampering): {flat('evasive-tamper')}")
    expect(flat("benign") == {"clean"}, f"benign should be clean: {flat('benign')}")
    expect(flat("evasive-argsgated") == {"clean"}, "evasive-argsgated is invisible to dynamic execution and should be clean")
    # The trace of the tamper sample must be intact: it tries to zero /trace/*.trace.
    tdir = os.path.join(out, "dynamic", str(samples.index("evasive-tamper") + 1), "trace") if "evasive-tamper" in samples else None
    if tdir and os.path.isdir(tdir):
        for f in os.listdir(tdir):
            if f.endswith(".trace"):
                expect(b"\x00" not in open(os.path.join(tdir, f), "rb").read(), f"{f} contains NUL bytes: the trace was tampered with")
    # Raw-socket DNS exfil: the destination only appears in the packet body.
    if "evasive-rawdns" in samples:
        a = json.load(open(os.path.join(out, "dynamic", str(samples.index("evasive-rawdns") + 1), "analysis.json")))
        iocs = [i for s_ in a["scripts"].values() for i in s_["iocs"]]
        q = [i["detail"] for i in iocs if i["kind"] == "dns-query"]
        expect(any("canary.example" in d for d in q), f"evasive-rawdns: qname not decoded, dns-query iocs = {q}")
        expect(flat("evasive-rawdns") == {"high"}, f"evasive-rawdns should be high: {flat('evasive-rawdns')}")
    expect(len(gaps.get("evasive-delayed", [])) >= 1, "evasive-delayed must be reported as a coverage gap, not as clean")
    expect(res["status"] == "partial", "the delayed sample's gap must make the overall status partial")

if problems:
    print("FAILED:\n  " + "\n  ".join(problems))
    sys.exit(1)
print("OK")
