#!/usr/bin/env python3
"""
Log Analyzer
------------
Parses SSH authentication logs (auth.log format) and web server access logs
(Apache/Nginx combined format) to detect real security-relevant patterns:

  - Brute-force login attempts (repeated failures from one IP)
  - Successful login immediately following a burst of failures
  - Web scanning / probing behavior (many 404s from one IP)
  - Basic SQL injection patterns in request URLs

This performs actual regex parsing and threshold-based detection against
the log content given to it — it does not fabricate results.

Usage:
    python log_analyzer.py sample_logs/auth.log --type ssh
    python log_analyzer.py sample_logs/access.log --type web
    python log_analyzer.py sample_logs/auth.log --type ssh --threshold 5
"""

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path
from urllib.parse import unquote


# --- SSH auth.log parsing -----------------------------------------------

SSH_FAILED_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+"
)

SSH_ACCEPTED_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Accepted (?P<method>\w+) for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+"
)


def parse_ssh_log(lines: list) -> dict:
    """Parse SSH auth log lines into structured failed/accepted events."""
    failed_events = []
    accepted_events = []

    for line in lines:
        m = SSH_FAILED_RE.search(line)
        if m:
            failed_events.append(m.groupdict())
            continue
        m = SSH_ACCEPTED_RE.search(line)
        if m:
            accepted_events.append(m.groupdict())

    return {"failed": failed_events, "accepted": accepted_events}


def detect_brute_force(parsed: dict, threshold: int = 5) -> list:
    """
    Flag any source IP with >= threshold failed login attempts.
    Also flags if a successful login came from an IP that had just
    failed >= threshold times (classic "brute-force then success" pattern).
    """
    failures_by_ip = defaultdict(list)
    for event in parsed["failed"]:
        failures_by_ip[event["ip"]].append(event)

    alerts = []
    for ip, events in failures_by_ip.items():
        if len(events) >= threshold:
            users_tried = sorted({e["user"] for e in events})
            alerts.append({
                "type": "brute_force",
                "ip": ip,
                "attempt_count": len(events),
                "usernames_tried": users_tried,
                "severity": "high" if len(events) >= threshold * 2 else "medium",
            })

    # Check for a successful login from an IP that also had many failures
    flagged_ips = {a["ip"] for a in alerts}
    for event in parsed["accepted"]:
        if event["ip"] in flagged_ips:
            alerts.append({
                "type": "possible_compromised_credential",
                "ip": event["ip"],
                "user": event["user"],
                "severity": "critical",
                "note": "Successful login from an IP that previously brute-forced this host",
            })

    return alerts


# --- Web access log parsing ----------------------------------------------

ACCESS_LOG_RE = re.compile(
    r'^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
)

SQLI_PATTERNS = [
    re.compile(r"union\s+select", re.IGNORECASE),
    re.compile(r"['\"]\s*or\s*['\"]?\d*['\"]?\s*=\s*['\"]?\d*", re.IGNORECASE),
    re.compile(r"--\s*$"),
    re.compile(r";\s*drop\s+table", re.IGNORECASE),
]


def parse_access_log(lines: list) -> list:
    """Parse Apache/Nginx combined-format access log lines."""
    events = []
    for line in lines:
        m = ACCESS_LOG_RE.search(line)
        if m:
            events.append(m.groupdict())
    return events


def detect_web_anomalies(events: list, scan_threshold: int = 4) -> list:
    """
    Detect:
      - IPs generating many 404s (scanning/probing for hidden paths)
      - IPs with repeated failed logins (401) followed by success
      - Requests containing likely SQL injection payloads
    """
    alerts = []

    not_found_by_ip = defaultdict(list)
    login_failures_by_ip = defaultdict(list)
    login_success_by_ip = defaultdict(list)

    for event in events:
        status = event["status"]
        path = event["path"]

        if status == "404":
            not_found_by_ip[event["ip"]].append(event)

        if path.lower().startswith("/login"):
            if status == "401":
                login_failures_by_ip[event["ip"]].append(event)
            elif status == "200":
                login_success_by_ip[event["ip"]].append(event)

        decoded_path = unquote(path)
        for pattern in SQLI_PATTERNS:
            if pattern.search(decoded_path):
                alerts.append({
                    "type": "possible_sql_injection",
                    "ip": event["ip"],
                    "path": path,
                    "severity": "critical",
                })
                break

    for ip, events_404 in not_found_by_ip.items():
        if len(events_404) >= scan_threshold:
            paths = [e["path"] for e in events_404]
            alerts.append({
                "type": "directory_scanning",
                "ip": ip,
                "attempt_count": len(events_404),
                "paths_probed": paths,
                "severity": "medium",
            })

    for ip, failures in login_failures_by_ip.items():
        if len(failures) >= scan_threshold:
            alerts.append({
                "type": "brute_force_web_login",
                "ip": ip,
                "attempt_count": len(failures),
                "severity": "high",
            })
            if ip in login_success_by_ip:
                alerts.append({
                    "type": "possible_compromised_credential",
                    "ip": ip,
                    "severity": "critical",
                    "note": "Successful web login from an IP that previously failed repeatedly",
                })

    return alerts


# --- Reporting -------------------------------------------------------------

def print_report(alerts: list, total_lines: int, log_type: str):
    print("\n" + "=" * 65)
    print(f"  LOG ANALYSIS REPORT ({log_type})")
    print("=" * 65)
    print(f"  Lines analyzed : {total_lines}")
    print(f"  Alerts found   : {len(alerts)}")
    print("-" * 65)

    if not alerts:
        print("  No suspicious activity detected.")
    else:
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        alerts_sorted = sorted(alerts, key=lambda a: severity_order.get(a["severity"], 9))
        for a in alerts_sorted:
            print(f"\n  [{a['severity'].upper()}] {a['type']}")
            for k, v in a.items():
                if k in ("type", "severity"):
                    continue
                print(f"    {k}: {v}")
    print("\n" + "=" * 65 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Analyze SSH or web server logs for security anomalies")
    parser.add_argument("logfile", help="Path to the log file to analyze")
    parser.add_argument("--type", choices=["ssh", "web"], required=True, help="Log format to parse")
    parser.add_argument("--threshold", type=int, default=5,
                         help="Number of failed attempts before flagging as brute force (default: 5)")
    parser.add_argument("--json", action="store_true", help="Output raw JSON instead of a formatted report")
    args = parser.parse_args()

    path = Path(args.logfile)
    if not path.exists():
        print(f"[!] File not found: {args.logfile}")
        sys.exit(1)

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    if args.type == "ssh":
        parsed = parse_ssh_log(lines)
        alerts = detect_brute_force(parsed, threshold=args.threshold)
    else:
        events = parse_access_log(lines)
        alerts = detect_web_anomalies(events, scan_threshold=args.threshold)

    if args.json:
        import json
        print(json.dumps(alerts, indent=2))
    else:
        print_report(alerts, len(lines), args.type)


if __name__ == "__main__":
    main()
