"""
HTML Reporter — generates a polished SOC-style dashboard
"""

from datetime import datetime


SEVERITY_CONFIG = {
    "CRITICAL": {"color": "#ff3c3c", "bg": "rgba(255,60,60,0.08)", "border": "#ff3c3c"},
    "HIGH":     {"color": "#ff8c00", "bg": "rgba(255,140,0,0.08)",  "border": "#ff8c00"},
    "MEDIUM":   {"color": "#f5c518", "bg": "rgba(245,197,24,0.08)", "border": "#f5c518"},
    "LOW":      {"color": "#4fc3f7", "bg": "rgba(79,195,247,0.08)", "border": "#4fc3f7"},
    "INFO":     {"color": "#78909c", "bg": "rgba(120,144,156,0.08)","border": "#78909c"},
}


def generate_html_report(result: dict, output_path: str):
    meta = result.get("meta", {})
    stats = result.get("stats", {})
    alerts = result.get("alerts", [])
    severity_summary = meta.get("severity_summary", {})

    alert_cards = _build_alert_cards(alerts)
    stat_blocks = _build_stat_blocks(meta, stats)
    severity_pills = _build_severity_pills(severity_summary)
    log_type_label = "Linux Auth Log" if meta.get("log_type") == "linux_auth" else "Windows Event Log"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Log Analysis Report</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Syne:wght@400;700;800&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg:       #0a0c10;
      --surface:  #111318;
      --surface2: #181b22;
      --border:   #1f2430;
      --text:     #c9d1e0;
      --muted:    #4a5568;
      --accent:   #00e5ff;
      --font-mono: 'JetBrains Mono', monospace;
      --font-head: 'Syne', sans-serif;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: var(--bg);
      color: var(--text);
      font-family: var(--font-mono);
      font-size: 13px;
      min-height: 100vh;
    }}
    header {{
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      padding: 20px 40px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      position: sticky;
      top: 0;
      z-index: 100;
    }}
    .logo {{
      font-family: var(--font-head);
      font-weight: 800;
      font-size: 18px;
      color: var(--accent);
      letter-spacing: 0.05em;
    }}
    .logo span {{ color: var(--text); opacity: 0.5; }}
    .header-meta {{
      font-size: 11px;
      color: var(--muted);
      text-align: right;
      line-height: 1.6;
    }}
    .header-meta strong {{ color: var(--text); }}
    .container {{
      max-width: 1200px;
      margin: 0 auto;
      padding: 40px;
    }}
    .hero {{
      margin-bottom: 40px;
      padding: 36px 40px;
      background: var(--surface);
      border: 1px solid var(--border);
      border-left: 3px solid var(--accent);
    }}
    .hero-label {{
      font-size: 11px;
      color: var(--accent);
      letter-spacing: 0.2em;
      text-transform: uppercase;
      margin-bottom: 10px;
    }}
    .hero-title {{
      font-family: var(--font-head);
      font-size: 30px;
      font-weight: 800;
      color: #fff;
      margin-bottom: 8px;
    }}
    .hero-file {{
      font-size: 12px;
      color: var(--muted);
    }}
    .hero-file strong {{ color: var(--text); }}
    .severity-row {{
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      margin-bottom: 36px;
    }}
    .sev-pill {{
      padding: 8px 18px;
      border-radius: 2px;
      font-size: 12px;
      font-weight: 600;
      letter-spacing: 0.08em;
      border: 1px solid;
      display: flex;
      align-items: center;
      gap: 8px;
    }}
    .sev-pill .count {{
      font-size: 18px;
      font-family: var(--font-head);
      font-weight: 800;
    }}
    .stats-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 16px;
      margin-bottom: 40px;
    }}
    .stat-card {{
      background: var(--surface);
      border: 1px solid var(--border);
      padding: 20px;
    }}
    .stat-label {{
      font-size: 10px;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.15em;
      margin-bottom: 8px;
    }}
    .stat-value {{
      font-family: var(--font-head);
      font-size: 28px;
      font-weight: 800;
      color: #fff;
    }}
    .stat-value.accent {{ color: var(--accent); }}
    .section-heading {{
      font-family: var(--font-head);
      font-size: 14px;
      font-weight: 700;
      color: #fff;
      text-transform: uppercase;
      letter-spacing: 0.15em;
      margin-bottom: 20px;
      padding-bottom: 10px;
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      gap: 12px;
    }}
    .section-heading::before {{
      content: '';
      display: block;
      width: 3px;
      height: 16px;
      background: var(--accent);
    }}
    .alerts-list {{
      display: flex;
      flex-direction: column;
      gap: 12px;
    }}
    .alert-card {{
      border: 1px solid;
      padding: 20px 24px;
    }}
    .alert-header {{
      display: flex;
      align-items: flex-start;
      gap: 14px;
      margin-bottom: 8px;
    }}
    .alert-sev-badge {{
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.15em;
      padding: 3px 8px;
      border: 1px solid;
      white-space: nowrap;
      margin-top: 2px;
    }}
    .alert-title {{
      font-family: var(--font-head);
      font-size: 15px;
      font-weight: 700;
      color: #fff;
    }}
    .alert-desc {{
      font-size: 12px;
      color: var(--text);
      margin-bottom: 12px;
      line-height: 1.6;
    }}
    .alert-rec {{
      font-size: 11px;
      color: var(--muted);
      padding: 10px 14px;
      background: rgba(0,0,0,0.3);
      border-left: 2px solid var(--accent);
      line-height: 1.6;
    }}
    .alert-rec strong {{ color: var(--accent); }}
    .alert-data {{
      font-size: 11px;
      color: var(--muted);
      margin-top: 10px;
    }}
    .alert-data span {{ color: var(--text); margin-left: 4px; }}
    .empty-state {{
      text-align: center;
      padding: 60px;
      color: var(--muted);
    }}
    .empty-state .big {{ font-size: 48px; margin-bottom: 16px; }}
    footer {{
      margin-top: 60px;
      padding: 24px 40px;
      border-top: 1px solid var(--border);
      text-align: center;
      font-size: 11px;
      color: var(--muted);
    }}
  </style>
</head>
<body>
<header>
  <div class="logo">LOG<span>/</span>ANALYZER</div>
  <div class="header-meta">
    <strong>{log_type_label}</strong><br>
    Analyzed: {meta.get("analyzed_at", "N/A")[:19].replace("T", " ")}
  </div>
</header>
<div class="container">
  <div class="hero">
    <div class="hero-label">Security Analysis Report</div>
    <div class="hero-title">{meta.get("total_alerts", 0)} Alert{"s" if meta.get("total_alerts", 0) != 1 else ""} Detected</div>
    <div class="hero-file">File: <strong>{meta.get("file", "N/A")}</strong> &nbsp;|&nbsp; Type: <strong>{log_type_label}</strong></div>
  </div>
  <div class="severity-row">{severity_pills}</div>
  <div class="stats-grid">{stat_blocks}</div>
  <div class="section-heading">Alert Details</div>
  <div class="alerts-list">
    {alert_cards if alert_cards else _empty_state()}
  </div>
</div>
<footer>
  Generated by Log Analyzer — SOC Blue Team Toolkit — {datetime.now().strftime("%Y")}
</footer>
</body>
</html>"""

    with open(output_path, "w") as f:
        f.write(html)


def _build_severity_pills(summary: dict) -> str:
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    pills = ""
    for sev in order:
        count = summary.get(sev, 0)
        if count == 0:
            continue
        cfg = SEVERITY_CONFIG.get(sev, SEVERITY_CONFIG["INFO"])
        pills += f"""
        <div class="sev-pill" style="color:{cfg['color']};border-color:{cfg['border']};background:{cfg['bg']};">
          <span class="count">{count}</span>{sev}
        </div>"""
    if not pills:
        pills = '<div class="sev-pill" style="color:#78909c;border-color:#78909c;">0 Alerts</div>'
    return pills


def _build_stat_blocks(meta: dict, stats: dict) -> str:
    log_type = meta.get("log_type", "")
    blocks = []
    total_lines = stats.get("total_lines", stats.get("total_events", 0))
    label = "Total Lines" if log_type == "linux_auth" else "Total Events"
    blocks.append(f'<div class="stat-card"><div class="stat-label">{label}</div><div class="stat-value">{total_lines:,}</div></div>')
    if log_type == "linux_auth":
        blocks.append(f'<div class="stat-card"><div class="stat-label">Failed SSH</div><div class="stat-value accent">{stats.get("failed_ssh", 0):,}</div></div>')
        blocks.append(f'<div class="stat-card"><div class="stat-label">Successful SSH</div><div class="stat-value">{stats.get("successful_ssh", 0):,}</div></div>')
        blocks.append(f'<div class="stat-card"><div class="stat-label">Unique IPs</div><div class="stat-value">{len(stats.get("unique_ips", [])):,}</div></div>')
        blocks.append(f'<div class="stat-card"><div class="stat-label">Sudo Commands</div><div class="stat-value">{stats.get("sudo_commands", 0):,}</div></div>')
    elif log_type == "windows":
        blocks.append(f'<div class="stat-card"><div class="stat-label">Failed Logons</div><div class="stat-value accent">{stats.get("failed_logons", 0):,}</div></div>')
        blocks.append(f'<div class="stat-card"><div class="stat-label">Successful Logons</div><div class="stat-value">{stats.get("successful_logons", 0):,}</div></div>')
        blocks.append(f'<div class="stat-card"><div class="stat-label">Account Lockouts</div><div class="stat-value">{stats.get("account_lockouts", 0):,}</div></div>')
    blocks.append(f'<div class="stat-card"><div class="stat-label">Total Alerts</div><div class="stat-value accent">{meta.get("total_alerts", 0)}</div></div>')
    return "\n".join(blocks)


def _build_alert_cards(alerts: list) -> str:
    if not alerts:
        return ""
    cards = []
    for alert in alerts:
        sev = alert.get("severity", "INFO")
        cfg = SEVERITY_CONFIG.get(sev, SEVERITY_CONFIG["INFO"])
        data_items = ""
        for k, v in alert.get("data", {}).items():
            data_items += f'<span style="margin-right:16px;">{k}:<span>{v}</span></span>'
        cards.append(f"""
    <div class="alert-card" style="background:{cfg['bg']};border-color:{cfg['border']};">
      <div class="alert-header">
        <span class="alert-sev-badge" style="color:{cfg['color']};border-color:{cfg['border']};">{sev}</span>
        <span class="alert-title">{alert.get("title", "Alert")}</span>
      </div>
      <div class="alert-desc">{alert.get("description", "")}</div>
      <div class="alert-rec"><strong>Recommendation:</strong> {alert.get("recommendation", "")}</div>
      {f'<div class="alert-data">{data_items}</div>' if data_items else ''}
    </div>""")
    return "\n".join(cards)


def _empty_state() -> str:
    return """
    <div class="empty-state">
      <div class="big">✅</div>
      <p>No alerts detected. Log appears clean.</p>
    </div>"""
