"""
HVMC continuous monitoring — single entry point for scheduled runs.

Horizon Valley Medical Center (HVMC) - Risk Management Implementation
Author: Sabitha S Karanavar

Runs, in order (all read-only):
  1. kri_monitor.py      - 15 automated key risk indicators with Green/Amber/Red thresholds
  2. change_detector.py  - environmental change detection vs previous snapshot (+ CISA KEV threat feed)
Appends one line per run to monitoring_log.jsonl (the historical record) and exits
2 if any KRI is Red or any High/Critical change is detected, so the scheduler alerts.

    python3 continuous_monitor.py
"""
import datetime as dt
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def run(*cmd):
    p = subprocess.run([sys.executable, *cmd], cwd=HERE, capture_output=True, text=True)
    return p.returncode, p.stdout


def main():
    k_rc, k_out = run("kri_monitor.py")
    c_rc, c_out = run("change_detector.py", "--threat-feed")
    kri = json.load(open(os.path.join(HERE, "kri_status.json")))
    chg = json.load(open(os.path.join(HERE, "change_report.json")))
    tf = chg.get("threat_feed", {})
    entry = dict(run=dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), kri=kri["summary"], kri_error=kri.get("error"),
                 changes=chg["counts"], first_baseline=chg["first_run"], kev_hits=len(tf.get("hits", [])) if tf.get("ok") else None,
                 alert=bool(k_rc == 2 or c_rc == 2))
    with open(os.path.join(HERE, "monitoring_log.jsonl"), "a") as f:
        f.write(json.dumps(entry) + "\n")
    print(k_out + c_out)
    print("LOGGED:", json.dumps(entry))
    sys.exit(2 if entry["alert"] else 0)


if __name__ == "__main__":
    main()
