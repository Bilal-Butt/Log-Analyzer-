"""
Linux Auth Log Detector
Detects: SSH brute force, root login attempts, sudo abuse, account lockouts
"""

import re
from collections import defaultdict
from datetime import datetime


PATTERNS = {
    "ssh_failed": re.compile(
        r"(\w+\s+\d+\s[\d:]+).*Failed password for (?:invalid user )?(\S+) from ([\d.]+)"
    ),
    "ssh_success": re.compile(
        r"(\w+\s+\d+\s[\d:]+).*Accepted password for (\S+) from ([\d.]+)"
    ),
    "ssh_invalid_user": re.compile(
        r"(\w+\s+\d+\s[\d:]+).*Invalid user (\S+) from ([\d.]+)"
    ),
    "sudo_command": re.compile(
        r"(\w+\s+\d+\s[\d:]+).*sudo.*:\s+(\S+)\s+:.*COMMAND=(.*)"
    ),
    "sudo_failed": re.compile(
        r"(\w+\s+\d+\s[\d:]+).*sudo.*authentication failure.*user=(\S+)"
    ),
    "root_login": re.compile(
        r"(\w+\s+\d+\s[\d:]+).*Accepted.*for root from ([\d.]+)"
    ),
    "session_opened": re.compile(
        r"(\w+\s+\d+\s[\d:]+).*session opened for user (\S+)"
    ),
}

BRUTE_FORCE_THRESHOLD = 5
DISTRIBUTED_THRESHOLD = 10


def analyze_auth_log(filepath: str):
    alerts = []
    stats = {
        "total_lines": 0,
        "failed_ssh": 0,
        "successful_ssh": 0,
        "sudo_commands": 0,
        "unique_ips": set(),
        "targeted_users": defaultdict(int),
        "ip_fail_counts": defaultdict(int),
    }

    with open(filepath, "r", errors="ignore") as f:
        lines = f.readlines()

    stats["total_lines"] = len(lines)

    for line in lines:

        m = PATTERNS["ssh_failed"].search(line)
        if m:
            timestamp, user, ip = m.group(1), m.group(2), m.group(3)
            stats["failed_ssh"] += 1
            stats["unique_ips"].add(ip)
            stats["targeted_users"][user] += 1
            stats["ip_fail_counts"][ip] += 1
            continue

        m = PATTERNS["ssh_success"].search(line)
        if m:
            timestamp, user, ip = m.group(1), m.group(2), m.group(3)
            stats["successful_ssh"] += 1
            stats["unique_ips"].add(ip)
            if user == "root":
                alerts.append(_alert(
                    "CRITICAL",
                    "Root SSH Login Succeeded",
                    f"Root login accepted from {ip} at {timestamp}",
                    {"ip": ip, "user": user, "timestamp": timestamp},
                    "Immediate investigation required. Disable root SSH login (PermitRootLogin no)."
                ))
            continue

        m = PATTERNS["ssh_invalid_user"].search(line)
        if m:
            timestamp, user, ip = m.group(1), m.group(2), m.group(3)
            stats["ip_fail_counts"][ip] += 1
            stats["unique_ips"].add(ip)
            continue

        m = PATTERNS["sudo_command"].search(line)
        if m:
            timestamp, user, command = m.group(1), m.group(2), m.group(3)
            stats["sudo_commands"] += 1
            sensitive = any(kw in command.lower() for kw in [
                "/bin/bash", "/bin/sh", "passwd", "visudo",
                "chmod 777", "nc ", "wget", "curl"
            ])
            if sensitive:
                alerts.append(_alert(
                    "HIGH",
                    "Suspicious Sudo Command",
                    f"User {user} ran sensitive command via sudo: {command.strip()} at {timestamp}",
                    {"user": user, "command": command.strip(), "timestamp": timestamp},
                    "Review whether this command is authorized. Check for privilege escalation."
                ))
            continue

        m = PATTERNS["sudo_failed"].search(line)
        if m:
            timestamp, user = m.group(1), m.group(2)
            alerts.append(_alert(
                "MEDIUM",
                "Sudo Authentication Failure",
                f"User {user} failed sudo authentication at {timestamp}",
                {"user": user, "timestamp": timestamp},
                "May indicate password guessing or unauthorized privilege escalation attempt."
            ))
            continue

        m = PATTERNS["root_login"].search(line)
        if m:
            timestamp, ip = m.group(1), m.group(2)
            alerts.append(_alert(
                "CRITICAL",
                "Root SSH Login",
                f"Root login accepted from {ip} at {timestamp}",
                {"ip": ip, "timestamp": timestamp},
                "Disable root SSH login immediately."
            ))
            continue

    for ip, count in stats["ip_fail_counts"].items():
        if count >= BRUTE_FORCE_THRESHOLD:
            severity = "CRITICAL" if count >= 20 else "HIGH"
            alerts.append(_alert(
                severity,
                "SSH Brute Force Detected",
                f"IP {ip} had {count} failed SSH login attempts",
                {"ip": ip, "failed_attempts": count},
                f"Block IP {ip} via firewall (iptables/ufw). Investigate origin."
            ))

    if stats["failed_ssh"] >= DISTRIBUTED_THRESHOLD and len(stats["ip_fail_counts"]) > 3:
        alerts.append(_alert(
            "HIGH",
            "Distributed SSH Attack",
            f"{stats['failed_ssh']} failed logins from {len(stats['ip_fail_counts'])} unique IPs",
            {"total_failures": stats["failed_ssh"], "unique_ips": len(stats["ip_fail_counts"])},
            "Enable fail2ban or equivalent rate-limiting. Review firewall rules."
        ))

    for user, count in stats["targeted_users"].items():
        if count >= 3:
            alerts.append(_alert(
                "MEDIUM",
                "Targeted User Account",
                f"Account '{user}' was targeted {count} times via SSH",
                {"user": user, "attempts": count},
                "Consider disabling password auth for this account. Use SSH keys only."
            ))

    stats["unique_ips"] = list(stats["unique_ips"])
    stats["targeted_users"] = dict(stats["targeted_users"])
    stats["ip_fail_counts"] = dict(stats["ip_fail_counts"])

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    alerts.sort(key=lambda a: severity_order.get(a["severity"], 99))

    return alerts, stats


def _alert(severity, title, description, data, recommendation):
    return {
        "severity": severity,
        "title": title,
        "description": description,
        "data": data,
        "recommendation": recommendation,
        "timestamp": datetime.now().isoformat(),
    }
