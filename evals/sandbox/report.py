#!/usr/bin/env python3
"""Print a one-line-per-sample verdict table from either result layout.

usage: report.py plain <results_dir>     (dirs holding *.trace + exit_codes.txt)
       report.py harbor <jobs_dir>       (Harbor trials holding verifier/ioc_report.json)
"""
import json, os, subprocess, sys

mode, root = sys.argv[1], sys.argv[2]
here = os.path.dirname(os.path.abspath(__file__))
rows = []
if mode == "plain":
    for name in sorted(os.listdir(root)):
        d = os.path.join(root, name)
        if os.path.exists(os.path.join(d, "exit_codes.txt")):
            out = subprocess.run([sys.executable, os.path.join(here, "monitor", "analyze_trace.py"), d],
                                 capture_output=True, text=True, check=True).stdout
            rows.append((name, json.loads(out)))
else:
    for dirpath, _, files in os.walk(root):
        if "ioc_report.json" in files:
            trial = os.path.basename(os.path.dirname(dirpath))
            rows.append((trial.rsplit("__", 1)[0], json.load(open(os.path.join(dirpath, "ioc_report.json")))))
for name, r in sorted(rows):
    kinds = sorted({i["kind"] for s in r["scripts"].values() for i in s["iocs"]})
    gap = f"  GAPS:{len(r['coverage_gaps'])}" if r["coverage_gaps"] else ""
    print(f"{name:20s} {r['verdict']:7s}{gap}  {', '.join(kinds)}")
if not rows:
    print("NO RESULTS FOUND under", root)
    sys.exit(1)
