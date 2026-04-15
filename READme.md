# Log Analyzer & Alert Engine

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![Focus](https://img.shields.io/badge/Focus-SOC%20%7C%20Blue%20Team-darkblue)

A Python-based security log analysis tool built for SOC and Blue Team workflows.
Parses Linux auth logs and Windows Event logs, detects suspicious activity,
and generates color-coded HTML dashboards and structured JSON reports.

Built as part of a cybersecurity portfolio targeting SOC Analyst and Threat Analyst roles.

---

## Why I Build This

In a real SOC environment, analysts manually review hundreds of log lines every day looking for signs of attacks. This tool automates that triage process, point it at a log file and it produces a full severity-ranked report in seconds. The detection logic mirrors Tier 1 and Tier 2 SOC workflows and maps directly to common SIEM alerting patterns used in tools like Splunk.


---

## Features

**Linux Auth Log Detection**
- SSH brute force detection with per-IP threshold tracking
- Distributed SSH attack pattern detection
- Root SSH login alerts
- Suspicious sudo command detection (shell spawns, wget, curl, passwd changes)
- Sudo authentication failure tracking
- Targeted user account enumeration detection

**Windows Event Log Detection**
- Logon brute force detection (Event ID 4625)
- Account lockout alerts (Event ID 4740)
- Audit log cleared detection (Event ID 1102) — anti-forensics indicator
- New user account creation (Event ID 4720)
- User added to privileged group (Event ID 4728, 4732)
- New service installation (Event ID 7045)
- Scheduled task creation and modification (Event ID 4698, 4702)
- Explicit credential use and lateral movement (Event ID 4648)

**Output**
- HTML dashboard with severity color coding and remediation guidance
- JSON report for SIEM integration or pipeline use
- <img width="932" height="777" alt="image" src="https://github.com/user-attachments/assets/fdb5f0bb-fefb-4806-88e5-f41902227fa8" />


---

## Project Structure

log-analyzer/
├── analyzer.py                  ← main entry point
├── detectors/
│   ├── auth_detector.py         ← Linux auth log analysis
│   └── windows_detector.py      ← Windows Event log analysis
├── reporters/
│   ├── json_reporter.py         ← JSON report output
│   └── html_reporter.py         ← HTML dashboard output
└── samples/
├── sample_auth.log          ← sample Linux auth log
└── sample_windows.csv       ← sample Windows Event log
---

## Requirements

Python 3.8 or higher. No external libraries required — uses Python standard library only.

---

## Installation

```bash
git clone https://github.com/Bilal-Butt/Log-Analyzer-.git
cd Log-Analyzer-
```

---

## Usage

```bash
# Analyze a Linux auth log
python3 analyzer.py samples/sample_auth.log -o output/auth_report

# Analyze a Windows Event CSV
python3 analyzer.py samples/sample_windows.csv -o output/windows_report

# Force log type manually
python3 analyzer.py mylog.log --type linux_auth

# Generate JSON report only
python3 analyzer.py auth.log --no-html

# Generate HTML report only
python3 analyzer.py auth.log --no-json
```

Output files are saved as `report.html` and `report.json` in the output folder.

---

## Running Against Real Logs

**On Linux:**
```bash
python3 analyzer.py /var/log/auth.log -o output/real_report
firefox output/real_report.html
```

**On Windows:**
Export the Security Event log from Event Viewer as a CSV file, transfer it to your
Linux machine and run:
```bash
python3 analyzer.py windows_events.csv -o output/windows_report
```

---

## Sample Output

Running against the sample Linux auth log:

[] Auto-detected log type: linux_auth
[] Analyzing: samples/sample_auth.log
[+] Analysis complete — 13 alert(s) found
CRITICAL: 1
HIGH: 5
MEDIUM: 7
[+] JSON report: output/auth_report.json
[+] HTML report: output/auth_report.html

---

## Alert Severity Levels

| Severity | Examples |
|----------|---------|
| CRITICAL | Root SSH login, audit log cleared |
| HIGH | Brute force detected, new user created, service installed |
| MEDIUM | Sudo failure, targeted account, scheduled task change |
| LOW | Informational anomalies |

---

## Windows Event IDs Monitored

| Event ID | Description | Why It Matters |
|----------|-------------|----------------|
| 4625 | Failed Logon | Brute force detection |
| 4624 | Successful Logon | Confirms successful access |
| 4740 | Account Lockout | Evidence of brute force |
| 4720 | User Account Created | Persistence technique |
| 4648 | Explicit Credential Logon | Lateral movement indicator |
| 4698 | Scheduled Task Created | Persistence technique |
| 4732 | User Added to Local Group | Privilege escalation |
| 1102 | Audit Log Cleared | Anti-forensics indicator |
| 7045 | New Service Installed | Malware persistence |

---

## Skills Demonstrated

- Python scripting and regex pattern matching
- Linux and Windows log format knowledge
- SOC Tier 1 and Tier 2 detection logic
- Threshold-based alerting similar to SIEM tools like Splunk
- Threat hunting and incident triage workflows
- Structured reporting for analyst handoff

---

## Author

Bilal Butt — Computer Engineering Graduate
Actively pursuing SOC Analyst and Threat Analyst roles in the NYC/Long Island area.  
[LinkedIn](linkedin.com/in/muhammad-bilal-butt-03a476232) | [GitHub](https://github.com/Bilal-Butt)


