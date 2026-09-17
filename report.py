from __future__ import annotations

import html
from datetime import datetime

from nmap_scan import HostInfo
from exploits import ExploitMatch

_BAR = "=" * 60

APP_NAME = "NetSploitXZ"
REPORT_TITLE = "NETWORK RECONNAISSANCE & EXPLOIT DISCOVERY REPORT"
REPORT_SUBTITLE = "NETWORK RECONNAISSANCE & EXPLOIT DISCOVERY"


# ---------------------------------------------------------------------
# shared logic (used by both TXT and HTML reports)
# ---------------------------------------------------------------------

def _security_observations(host: HostInfo) -> list[str]:
    # simple, explainable heuristics, not a vulnerability scanner.
    # flags things worth a human looking at, nothing more. each
    # observation is a plain string starting with a severity tag,
    # e.g. "[HIGH] ...".
    observations: list[str] = []
    open_services = [s for s in host.services if s.state == "open"]

    for service in open_services:
        name = service.service_name.lower()

        if service.product and service.version:
            observations.append(
                f"[LOW] {service.port}/{service.protocol}: service banner discloses "
                f"software and version ({service.product} {service.version}), which can "
                f"help an attacker identify known issues."
            )
        elif not service.product:
            observations.append(
                f"[LOW] {service.port}/{service.protocol}: service could not be positively "
                f"identified by Nmap."
            )

        if "ftp" in name and "sftp" not in name:
            observations.append(
                f"[MEDIUM] {service.port}/{service.protocol}: FTP service detected. "
                f"Review whether encrypted alternatives are available and whether anonymous "
                f"access is enabled."
            )
        elif "telnet" in name:
            observations.append(
                f"[HIGH] {service.port}/{service.protocol}: Telnet service detected. "
                f"Telnet transmits traffic without encryption and should generally be "
                f"replaced with SSH."
            )
        elif name == "http":
            observations.append(
                f"[LOW] {service.port}/{service.protocol}: HTTP service detected. "
                f"Verify whether sensitive information is exposed over an unencrypted channel."
            )
        elif "microsoft-ds" in name or "netbios-ssn" in name or name == "smb":
            observations.append(
                f"[MEDIUM] {service.port}/{service.protocol}: SMB service detected. "
                f"Review SMB configuration, authentication controls, and network exposure."
            )
        elif "ssh" in name:
            observations.append(
                f"[INFO] {service.port}/{service.protocol}: SSH service detected. "
                f"Review SSH authentication and configuration."
            )

    if len(open_services) >= 8:
        observations.append(
            f"[MEDIUM] {len(open_services)} open services were detected on this host. "
            f"Review whether all discovered services are required."
        )

    if not observations:
        observations.append("No specific observations generated for this scan.")
    return observations


def _summary_counts(host: HostInfo, exploit_matches: list[ExploitMatch]) -> dict:
    open_ports = [s for s in host.services if s.state == "open"]
    services_identified = sum(1 for s in open_ports if s.product)
    return {
        "open_ports": len(open_ports),
        "services_identified": services_identified,
        "total_matches": len(exploit_matches),
        "high": sum(1 for m in exploit_matches if m.confidence == "High"),
        "medium": sum(1 for m in exploit_matches if m.confidence == "Medium"),
        "low": sum(1 for m in exploit_matches if m.confidence == "Low"),
    }


# ---------------------------------------------------------------------
# TXT report
# ---------------------------------------------------------------------

def generate_report(
    host: HostInfo,
    exploit_matches: list[ExploitMatch],
    scan_profile: str,
    exploitdb_available: bool,
    errors: list[str] | None = None,
) -> str:
    errors = errors or []
    lines: list[str] = []

    lines.append(_BAR)
    lines.append(APP_NAME.center(60).rstrip())
    lines.append(REPORT_SUBTITLE.center(60).rstrip())
    lines.append(_BAR)
    lines.append("")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Scan profile: {scan_profile}")
    if host.nmap_command:
        lines.append(f"Nmap options: {host.nmap_command}")
    if host.scan_started:
        lines.append(
            f"Scan started: {host.scan_started}    Completed: {host.scan_completed}    "
            f"Duration: {host.scan_duration_seconds:.0f}s"
        )
    lines.append("")

    if host.state == "up":
        counts = _summary_counts(host, exploit_matches)
        lines.append("## EXECUTIVE SUMMARY")
        lines.append(f"Target:                  {host.target_input}")
        lines.append(f"Host status:             {host.state}")
        lines.append(f"Open ports:              {counts['open_ports']}")
        lines.append(f"Services identified:     {counts['services_identified']}")
        lines.append(f"Potential exploit matches: {counts['total_matches']}")
        lines.append(f"High-confidence matches:   {counts['high']}")
        lines.append(f"Medium-confidence matches: {counts['medium']}")
        lines.append(f"Low-confidence matches:    {counts['low']}")
        lines.append("")

    lines.append("## TARGET")
    lines.append(f"Input:    {host.target_input}")
    lines.append(f"IP:       {host.ip_address or 'unknown'}")
    lines.append(f"Hostname: {host.hostname or 'unknown'}")
    lines.append(f"Status:   {host.state}")
    lines.append("")

    if host.state != "up":
        lines.append("Host did not respond as up. Recon stopped here.")
        lines.append(_BAR)
        return "\n".join(lines)

    lines.append("## HOST INFORMATION")
    lines.append(f"OS guess:      {host.os_guess or 'unknown'}"
                  + (f" (accuracy {host.os_accuracy}%)" if host.os_accuracy else ""))
    if host.mac_address:
        lines.append(f"MAC address:   {host.mac_address}" + (f" ({host.mac_vendor})" if host.mac_vendor else ""))
    if host.uptime_seconds:
        lines.append(f"Uptime:        {host.uptime_seconds} seconds (last boot: {host.last_boot})")
    if host.distance_hops:
        lines.append(f"Network hops:  {host.distance_hops}")
    for warning in host.warnings:
        lines.append(f"Note: {warning}")
    lines.append("")

    open_ports = [s for s in host.services if s.state == "open"]

    lines.append("## OPEN PORTS & SERVICES")
    if open_ports:
        for s in open_ports:
            version_str = f"{s.product} {s.version}".strip() or "unknown"
            lines.append(f"{s.port}/{s.protocol:<5} {s.service_name or 'unknown':<10} {version_str}")
            if s.cpe:
                lines.append(f"    CPE: {', '.join(s.cpe)}")
            for script in s.scripts:
                lines.append(f"    [{script.script_id}] {script.output.strip()}")
    else:
        lines.append("No open ports detected.")
    lines.append("")

    if host.host_scripts:
        lines.append("## HOST SCRIPT OUTPUT")
        for script in host.host_scripts:
            lines.append(f"[{script.script_id}] {script.output.strip()}")
        lines.append("")

    lines.append("## SECURITY OBSERVATIONS")
    for obs in _security_observations(host):
        lines.append(obs)
    lines.append("")

    lines.append("## EXPLOIT DISCOVERY")
    if not exploitdb_available:
        lines.append("Exploit-DB local index was not available for this scan.")
        lines.append("(Set the exploitdb CSV path in the app to enable exploit discovery.)")
    elif not exploit_matches:
        lines.append("No potentially applicable public exploits were found for the detected services.")
    else:
        lines.append(
            "The following are POTENTIALLY APPLICABLE public exploits based on service/version "
            "matching. Their existence does not prove the target is vulnerable -- review each "
            "manually via the linked Exploit-DB page."
        )
        lines.append("")
        by_port: dict[int, list[ExploitMatch]] = {}
        for m in exploit_matches:
            by_port.setdefault(m.matched_service_port, []).append(m)

        for port, matches in sorted(by_port.items()):
            lines.append(f"--- Port {port} ({matches[0].matched_product} {matches[0].matched_version}) ---")
            for m in matches:
                lines.append(f"EDB-ID:     {m.edb_id}")
                lines.append(f"Title:      {m.title}")
                lines.append(f"Type:       {m.exploit_type or 'unknown'}")
                lines.append(f"Platform:   {m.platform or 'unknown'}")
                lines.append(f"Confidence: {m.confidence} (score {m.score})")
                lines.append(f"Exploit-DB: {m.url}")
                lines.append("")
    lines.append("")

    lines.append("## RECOMMENDATIONS")
    lines.append("- Update affected software to the latest stable version.")
    lines.append("- Disable unnecessary services and close unused ports.")
    lines.append("- Restrict network exposure of sensitive services where possible.")
    lines.append("- Manually review each referenced Exploit-DB entry before drawing conclusions.")
    lines.append("")

    if errors:
        lines.append("## SCAN NOTES / NON-FATAL ISSUES")
        for e in errors:
            lines.append(f"- {e}")
        lines.append("")

    lines.append(_BAR)
    return "\n".join(lines)


# ---------------------------------------------------------------------
# HTML report - self-contained single file, stdlib only (html.escape()
# for every piece of dynamic text, no template engine, no JS framework)
# ---------------------------------------------------------------------

_HTML_CSS = """
body { font-family: 'Segoe UI', Arial, sans-serif; background: #f4f5f7; color: #222; margin: 0; padding: 0; }
.wrap { max-width: 900px; margin: 24px auto; background: #fff; padding: 32px 40px; border-radius: 6px;
        box-shadow: 0 0 12px rgba(0,0,0,0.08); }
h1 { font-size: 22px; margin-bottom: 4px; color: #1a1a2e; }
.subtitle { color: #666; margin-bottom: 24px; font-size: 13px; }
h2 { font-size: 15px; text-transform: uppercase; letter-spacing: 0.5px; color: #2f5f8f;
     border-bottom: 2px solid #e0e4ea; padding-bottom: 6px; margin-top: 30px; }
table { width: 100%; border-collapse: collapse; margin: 10px 0 20px 0; font-size: 13px; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid #e5e7eb; vertical-align: top; }
th { background: #f0f2f5; color: #333; }
.summary-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 4px 24px; font-size: 13px; margin: 10px 0 20px 0; }
.summary-grid div span.label { color: #666; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: bold; color: #fff; }
.badge-high { background: #d9534f; }
.badge-medium { background: #e0a325; }
.badge-low { background: #4a90d9; }
.badge-info { background: #6c757d; }
pre.mono { background: #f7f7f9; border: 1px solid #e5e7eb; padding: 10px; font-family: Consolas, monospace;
           font-size: 12px; white-space: pre-wrap; word-wrap: break-word; border-radius: 4px; }
.note { color: #666; font-size: 12px; margin-top: 4px; }
.footer { margin-top: 30px; font-size: 11px; color: #999; border-top: 1px solid #e5e7eb; padding-top: 10px; }
.exploit-block { border: 1px solid #e5e7eb; border-radius: 4px; padding: 10px 14px; margin-bottom: 10px; }
.brand { font-size: 12px; font-weight: bold; letter-spacing: 1px; color: #2f5f8f; text-transform: uppercase; }
"""

_BADGE_CLASS = {"HIGH": "badge-high", "MEDIUM": "badge-medium", "LOW": "badge-low", "INFO": "badge-info"}


def _badge(text: str) -> str:
    key = text.strip("[]").upper()
    css_class = _BADGE_CLASS.get(key, "badge-info")
    return f'<span class="badge {css_class}">{html.escape(text.strip("[]"))}</span>'


def _confidence_badge(confidence: str) -> str:
    key = confidence.upper()
    css_class = _BADGE_CLASS.get(key, "badge-info")
    return f'<span class="badge {css_class}">{html.escape(confidence)}</span>'


def generate_html_report(
    host: HostInfo,
    exploit_matches: list[ExploitMatch],
    scan_profile: str,
    exploitdb_available: bool,
    errors: list[str] | None = None,
) -> str:
    errors = errors or []
    e = html.escape  # short alias, used everywhere dynamic text is inserted

    parts: list[str] = []
    parts.append(f"<!DOCTYPE html><html><head><meta charset='utf-8'>")
    parts.append(f"<title>{e(APP_NAME)} &mdash; {e(REPORT_TITLE)}</title><style>{_HTML_CSS}</style></head><body><div class='wrap'>")

    parts.append(f"<div class='brand'>{e(APP_NAME)}</div>")
    parts.append(f"<h1>{e(REPORT_TITLE)}</h1>")
    subtitle = f"Generated {e(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))} &middot; Profile: {e(scan_profile)}"
    if host.scan_started:
        subtitle += f" &middot; Duration: {host.scan_duration_seconds:.0f}s"
    parts.append(f"<div class='subtitle'>{subtitle}</div>")

    if host.state == "up":
        counts = _summary_counts(host, exploit_matches)
        parts.append("<h2>Executive Summary</h2><div class='summary-grid'>")
        rows = [
            ("Target", host.target_input),
            ("Host status", host.state),
            ("Open ports", counts["open_ports"]),
            ("Services identified", counts["services_identified"]),
            ("Potential exploit matches", counts["total_matches"]),
            ("High confidence", counts["high"]),
            ("Medium confidence", counts["medium"]),
            ("Low confidence", counts["low"]),
        ]
        for label, value in rows:
            parts.append(f"<div><span class='label'>{e(label)}:</span> {e(str(value))}</div>")
        parts.append("</div>")

    parts.append("<h2>Target</h2><div class='summary-grid'>")
    parts.append(f"<div><span class='label'>Input:</span> {e(host.target_input)}</div>")
    parts.append(f"<div><span class='label'>IP address:</span> {e(host.ip_address or 'unknown')}</div>")
    parts.append(f"<div><span class='label'>Hostname:</span> {e(host.hostname or 'unknown')}</div>")
    parts.append(f"<div><span class='label'>Status:</span> {e(host.state)}</div>")
    parts.append("</div>")

    if host.nmap_command or host.scan_started:
        parts.append("<h2>Scan Configuration</h2><div class='summary-grid'>")
        parts.append(f"<div><span class='label'>Profile:</span> {e(scan_profile)}</div>")
        if host.nmap_command:
            parts.append(f"<div><span class='label'>Nmap options:</span> {e(host.nmap_command)}</div>")
        if host.scan_started:
            parts.append(f"<div><span class='label'>Started:</span> {e(host.scan_started)}</div>")
            parts.append(f"<div><span class='label'>Completed:</span> {e(host.scan_completed)}</div>")
        parts.append("</div>")

    if host.state != "up":
        parts.append("<p>Host did not respond as up. Recon stopped here.</p>")
        parts.append(_html_footer())
        parts.append("</div></body></html>")
        return "".join(parts)

    parts.append("<h2>Host Information</h2><div class='summary-grid'>")
    os_line = host.os_guess or "unknown"
    if host.os_accuracy:
        os_line += f" (accuracy {host.os_accuracy}%)"
    parts.append(f"<div><span class='label'>OS guess:</span> {e(os_line)}</div>")
    if host.mac_address:
        mac_line = host.mac_address + (f" ({host.mac_vendor})" if host.mac_vendor else "")
        parts.append(f"<div><span class='label'>MAC address:</span> {e(mac_line)}</div>")
    if host.uptime_seconds:
        parts.append(f"<div><span class='label'>Uptime:</span> {e(host.uptime_seconds)}s (last boot: {e(host.last_boot)})</div>")
    if host.distance_hops:
        parts.append(f"<div><span class='label'>Network hops:</span> {e(host.distance_hops)}</div>")
    parts.append("</div>")
    if host.warnings:
        for w in host.warnings:
            parts.append(f"<div class='note'>Note: {e(w)}</div>")

    open_ports = [s for s in host.services if s.state == "open"]
    parts.append("<h2>Open Ports &amp; Services</h2>")
    if open_ports:
        parts.append("<table><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Product</th>"
                      "<th>Version</th><th>CPE</th></tr>")
        for s in open_ports:
            cpe_text = ", ".join(s.cpe) if s.cpe else "-"
            parts.append(
                f"<tr><td>{e(str(s.port))}</td><td>{e(s.protocol)}</td><td>{e(s.service_name or '-')}</td>"
                f"<td>{e(s.product or '-')}</td><td>{e(s.version or '-')}</td><td>{e(cpe_text)}</td></tr>"
            )
        parts.append("</table>")
    else:
        parts.append("<p>No open ports detected.</p>")

    script_lines = []
    for s in open_ports:
        for script in s.scripts:
            script_lines.append(f"[{s.port}] [{script.script_id}] {script.output.strip()}")
    for script in host.host_scripts:
        script_lines.append(f"[host] [{script.script_id}] {script.output.strip()}")
    if script_lines:
        parts.append("<h2>Nmap Script Output</h2>")
        parts.append(f"<pre class='mono'>{e(chr(10).join(script_lines))}</pre>")

    parts.append("<h2>Security Observations</h2>")
    for obs in _security_observations(host):
        # observations normally start with a "[SEVERITY]" tag; the one
        # exception is the "no observations" fallback message, which has
        # no tag at all and should just be shown as plain text
        if obs.startswith("[") and "]" in obs:
            tag_end = obs.find("]") + 1
            tag, rest = obs[:tag_end], obs[tag_end:]
            parts.append(f"<div style='margin-bottom:8px'>{_badge(tag)} {e(rest.strip())}</div>")
        else:
            parts.append(f"<div style='margin-bottom:8px'>{e(obs)}</div>")

    parts.append("<h2>Exploit Discovery</h2>")
    if not exploitdb_available:
        parts.append("<p>Exploit-DB local index was not available for this scan.</p>")
    elif not exploit_matches:
        parts.append("<p>No potentially applicable public exploits were found for the detected services.</p>")
    else:
        parts.append(
            "<p class='note'>The following are <strong>potentially applicable</strong> public exploits "
            "based on service/version matching. An Exploit-DB match does not prove that the target is "
            "vulnerable — review each manually via the linked Exploit-DB page.</p>"
        )
        by_port: dict[int, list[ExploitMatch]] = {}
        for m in exploit_matches:
            by_port.setdefault(m.matched_service_port, []).append(m)
        for port, matches in sorted(by_port.items()):
            parts.append(f"<h3>Port {e(str(port))} &mdash; {e(matches[0].matched_product)} {e(matches[0].matched_version)}</h3>")
            for m in matches:
                parts.append("<div class='exploit-block'>")
                parts.append(f"<div><strong>EDB-{e(m.edb_id)}</strong> {_confidence_badge(m.confidence)} "
                              f"<span class='note'>score {m.score}</span></div>")
                parts.append(f"<div>{e(m.title)}</div>")
                parts.append(
                    f"<div class='note'>Type: {e(m.exploit_type or 'unknown')} &middot; "
                    f"Platform: {e(m.platform or 'unknown')}</div>"
                )
                parts.append(f"<div><a href='{e(m.url)}'>{e(m.url)}</a></div>")
                parts.append("</div>")

    parts.append("<h2>Recommendations</h2><ul>")
    for rec in (
        "Update affected software to the latest stable version.",
        "Disable unnecessary services and close unused ports.",
        "Restrict network exposure of sensitive services where possible.",
        "Manually review each referenced Exploit-DB entry before drawing conclusions.",
    ):
        parts.append(f"<li>{e(rec)}</li>")
    parts.append("</ul>")

    if errors:
        parts.append("<h2>Scan Notes / Non-Fatal Issues</h2><ul>")
        for err in errors:
            parts.append(f"<li>{e(err)}</li>")
        parts.append("</ul>")

    parts.append(_html_footer())
    parts.append("</div></body></html>")
    return "".join(parts)


def _html_footer() -> str:
    return f"<div class='footer'>Generated by {html.escape(APP_NAME)}.</div>"
