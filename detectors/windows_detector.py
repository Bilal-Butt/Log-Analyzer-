"""
Windows Event Log Detector (CSV export format)
Detects: Failed logons, account lockouts, privilege use, suspicious processes
"""

import csv
from collections import defaultdict
from datetime import datetime


EVENT_IDS = {
    "4625": "Failed Logon",
    "4624": "Successful Logon",
    "4648": "Explicit Credential Logon",
    "4720": "User Account Created",
    "4722": "User Account Enabled",
    "4724": "Password Reset Attempt",
    "4728": "Member Added to Security Group",
    "4732": "Member Added to Local Group",
    "4740": "Account Lockout",
    "4756": "Member Added to Universal Group",
    "4768": "Kerberos TGT Request",
    "4769": "Kerberos Service Ticket Request",
    "4771": "Kerberos Pre-auth Failed",
    "4776": "NTLM Auth Attempt",
    "7045": "New Service Installed",
    "4698": "Scheduled Task Created",
    "4702": "Scheduled Task Updated",
    "1102": "Audit Log Cleared",
    "4697": "Service Installed",
}

BRUTE_FORCE_THRESHOLD = 5


def analyze_windows_csv(filepath: str):
    alerts = []
    stats = {
        "total_events": 0,
        "failed_logons": 0,
        "successful_logons": 0,
        "account_lockouts": 0,
        "event_id_counts": defaultdict(int),
        "user_fail_counts": defaultdict(int),
        "source_ip_fails": defaultdict(int),
    }

    rows = _read_csv(filepath)
    if not rows:
        return alerts, stats

    stats["total_events"] = len(rows)

    for row in rows:
        event_id = str(row.get("EventID", row.get("Event ID", row.get("Id", "")))).strip()
        timestamp = row.get("TimeCreated", row.get("Time", row.get("Date", "Unknown")))
        user = row.get("SubjectUserName", row.get("TargetUserName", row.get("User", "Unknown"))).strip()
        source_ip = row.get("IpAddress", row.get("WorkstationName", row.get("Source IP", ""))).strip()

        stats["event_id_counts"][event_id] += 1

        if event_id == "4625":
            stats["failed_logons"] += 1
            stats["user_fail_counts"][user] += 1
            if source_ip:
                stats["source_ip_fails"][source_ip] += 1

        elif event_id == "4624":
            stats["successful_logons"] += 1

        elif event_id == "4740":
            stats["account_lockouts"] += 1
            alerts.append(_alert(
                "HIGH",
                "Account Lockout",
                f"Account '{user}' was locked out at {timestamp}",
                {"user": user, "timestamp": timestamp, "source": source_ip},
                "Investigate repeated failed logon attempts against this account."
            ))

        elif event_id == "1102":
            alerts.append(_alert(
                "CRITICAL",
                "Audit Log Cleared",
                f"Security audit log was cleared at {timestamp} by {user}",
                {"user": user, "timestamp": timestamp},
                "This is a strong indicator of anti-forensics activity. Immediate investigation required."
            ))

        elif event_id == "4720":
            alerts.append(_alert(
                "HIGH",
                "New User Account Created",
                f"User account created: {user} at {timestamp}",
                {"user": user, "timestamp": timestamp},
                "Verify this account creation was authorized. Unauthorized accounts may indicate persistence."
            ))

        elif event_id in ("4728", "4732", "4756"):
            group = row.get("GroupName", row.get("TargetUserName", "Unknown Group"))
            alerts.append(_alert(
                "HIGH",
                "User Added to Privileged Group",
                f"User '{user}' was added to group '{group}' at {timestamp}",
                {"user": user, "group": group, "timestamp": timestamp},
                "Verify this group membership change was authorized. Could indicate privilege escalation."
            ))

        elif event_id in ("7045", "4697"):
            service = row.get("ServiceName", row.get("param1", "Unknown Service"))
            alerts.append(_alert(
                "HIGH",
                "New Service Installed",
                f"Service '{service}' was installed at {timestamp} by {user}",
                {"service": service, "user": user, "timestamp": timestamp},
                "Malware often installs as a service. Verify this service is legitimate."
            ))

        elif event_id in ("4698", "4702"):
            task = row.get("TaskName", row.get("param1", "Unknown Task"))
            alerts.append(_alert(
                "MEDIUM",
                "Scheduled Task Created or Modified",
                f"Scheduled task '{task}' was created or modified at {timestamp} by {user}",
                {"task": task, "user": user, "timestamp": timestamp},
                "Scheduled tasks are a common persistence mechanism. Verify legitimacy."
            ))

        elif event_id == "4648":
            alerts.append(_alert(
                "MEDIUM",
                "Explicit Credential Logon",
                f"Explicit credentials used by {user} at {timestamp} from {source_ip}",
                {"user": user, "timestamp": timestamp, "source": source_ip},
                "Could indicate lateral movement or pass-the-hash attack."
            ))

    for user, count in stats["user_fail_counts"].items():
        if count >= BRUTE_FORCE_THRESHOLD and user not in ("-", "", "Unknown"):
            severity = "CRITICAL" if count >= 20 else "HIGH"
            alerts.append(_alert(
                severity,
                "Windows Logon Brute Force",
                f"Account '{user}' had {count} failed logon attempts (Event ID 4625)",
                {"user": user, "failed_attempts": count},
                "Enable account lockout policy. Investigate source of login attempts."
            ))

    for ip, count in stats["source_ip_fails"].items():
        if count >= BRUTE_FORCE_THRESHOLD and ip not in ("-", "", "::1", "127.0.0.1"):
            alerts.append(_alert(
                "HIGH",
                "Brute Force from Remote IP",
                f"IP {ip} caused {count} failed Windows logons",
                {"ip": ip, "failed_attempts": count},
                "Block this IP at the firewall. Investigate for lateral movement."
            ))

    stats["event_id_counts"] = dict(stats["event_id_counts"])
    stats["user_fail_counts"] = dict(stats["user_fail_counts"])
    stats["source_ip_fails"] = dict(stats["source_ip_fails"])

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    alerts.sort(key=lambda a: severity_order.get(a["severity"], 99))

    return alerts, stats


def _read_csv(filepath: str):
    rows = []
    try:
        with open(filepath, newline="", encoding="utf-8-sig", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append(dict(row))
    except Exception as e:
        print(f"[!] Error reading CSV: {e}")
    return rows


def _alert(severity, title, description, data, recommendation):
    return {
        "severity": severity,
        "title": title,
        "description": description,
        "data": data,
        "recommendation": recommendation,
        "timestamp": datetime.now().isoformat(),
    }
