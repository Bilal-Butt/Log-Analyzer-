#!/usr/bin/env python3
"""
Log Analyzer & Alert Engine
Supports: Linux auth logs, Windows Event logs (CSV)
Outputs: JSON report + HTML dashboard
"""

import re
import csv
import json
import argparse
from datetime import datetime
from pathlib import Path
from collections import defaultdict

from detectors.auth_detector import analyze_auth_log
from detectors.windows_detector import analyze_windows_csv
from reporters.json_reporter import generate_json_report
from reporters.html_reporter import generate_html_report


def detect_log_type(filepath: str) -> str:
    path = Path(filepath)
    if path.suffix.lower() == ".csv":
        return "windows"
    with open(filepath, "r", errors="ignore") as f:
        sample = f.read(500)
    if "sshd" in sample or "sudo" in sample or "pam_unix" in sample:
        return "linux_auth"
    return "unknown"


def run_analysis(filepath: str, log_type: str = None) -> dict:
    if not log_type:
        log_type = detect_log_type(filepath)
        print(f"[*] Auto-detected log type: {log_type}")

    print(f"[*] Analyzing: {filepath}")

    if log_type == "linux_auth":
        alerts, stats = analyze_auth_log(filepath)
    elif log_type == "windows":
        alerts, stats = analyze_windows_csv(filepath)
    else:
        print("[!] Unknown log type. Use --type linux_auth or windows")
        return {}

    result = {
        "meta": {
            "file": filepath,
            "log_type": log_type,
            "analyzed_at": datetime.now().isoformat(),
            "total_alerts": len(alerts),
        },
        "stats": stats,
        "alerts": alerts,
    }

    severity_counts = defaultdict(int)
    for a in alerts:
        severity_counts[a["severity"]] += 1
    result["meta"]["severity_summary"] = dict(severity_counts)

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Log Analyzer & Alert Engine — SOC Blue Team Tool"
    )
    parser.add_argument("logfile", help="Path to log file")
    parser.add_argument(
        "--type",
        choices=["linux_auth", "windows"],
        help="Force log type (auto-detected if omitted)",
    )
    parser.add_argument(
        "--output", "-o", default="report", help="Output filename base (default: report)"
    )
    parser.add_argument(
        "--no-html", action="store_true", help="Skip HTML report generation"
    )
    parser.add_argument(
        "--no-json", action="store_true", help="Skip JSON report generation"
    )
    args = parser.parse_args()

    result = run_analysis(args.logfile, args.type)
    if not result:
        return

    total = result["meta"]["total_alerts"]
    summary = result["meta"]["severity_summary"]
    print(f"\n[+] Analysis complete — {total} alert(s) found")
    for sev, count in sorted(summary.items()):
        print(f"    {sev}: {count}")

    if not args.no_json:
        json_path = f"{args.output}.json"
        generate_json_report(result, json_path)
        print(f"[+] JSON report: {json_path}")

    if not args.no_html:
        html_path = f"{args.output}.html"
        generate_html_report(result, html_path)
        print(f"[+] HTML report: {html_path}")


if __name__ == "__main__":
    main()
