# Network Recon & Exploit Discovery Tool

A lightweight Windows-first EHPT lab tool: Nmap-based reconnaissance
correlated against a local Exploit-DB index, with a Tkinter GUI and
TXT/HTML report export.

## Features

- IPv4 / IPv6 / hostname validation
- Nmap service and version detection
- OS fingerprinting
- TCP scanning
- UDP scanning
- NSE script enumeration
- Local Exploit-DB correlation with a simple additive confidence score
- Confidence-rated exploit matches (High / Medium / Low)
- CPE-aware matching and display
- Security observations (FTP, Telnet, HTTP, SMB, SSH, and exposure heuristics)
- TXT report generation
- HTML report generation
- Background scanning (non-blocking GUI)
- Scan cancellation
- Scan profiles (Quick / Standard / Full / Comprehensive)

## Architecture

```
             ┌─────────────┐
             │    GUI      │
             └──────┬──────┘
                    │
             ┌──────▼──────┐
             │ Validation  │
             └──────┬──────┘
                    │
             ┌──────▼──────┐
             │    Nmap     │
             └──────┬──────┘
                    │ XML
             ┌──────▼──────┐
             │ XML Parser  │
             └──────┬──────┘
                    │
        ┌───────────▼───────────┐
        │ Service Correlation   │
        └───────────┬───────────┘
                    │
             ┌──────▼──────┐
             │ Exploit-DB  │
             └──────┬──────┘
                    │
          ┌─────────▼─────────┐
          │ Findings / Report │
          └───────────────────┘
```

## Requirements
- Python 3.10+ (stdlib only — no pip installs needed)
- Nmap installed and on PATH: https://nmap.org/download.html
  (select "Add to PATH" during setup; run as Administrator for OS
  detection / UDP scans to work fully)
- A local copy of exploitdb's `files_exploits.csv`, e.g. by cloning:
  https://gitlab.com/exploit-database/exploitdb
  You'll be prompted to select this file the first time you set it
  via the "Set Exploit-DB CSV..." button in the app.

## Running
    python main.py

## Files
- main.py        - entry point
- gui.py          - Tkinter window, threading, rendering, export
- nmap_scan.py     - runs nmap, parses XML into HostInfo/ServiceInfo
- exploits.py       - loads exploitdb CSV, normalizes + correlates matches
- report.py          - builds the plain-text report
- env_check.py        - startup checks for Nmap / Exploit-DB availability
- validate.py          - target IP/hostname input validation
- config.py             - settings, scan profiles, constants

## Scan profiles
- Quick: top 100 ports, version detection only
- Standard: top 1000 ports, version + OS detection
- Full: all 65535 TCP ports, version + OS detection
- Comprehensive: all TCP ports + top UDP ports + OS detection + default
  Nmap scripts (-sC). Slowest, most detailed. Needs admin for full results.

## Important
This tool performs reconnaissance and exploit *discovery* only. It never
downloads or executes exploit code. A matched exploit is a lead to
investigate manually via the linked Exploit-DB page, not proof the
target is vulnerable. Only scan systems you are authorized to test.

## Limitations
- Exploit-DB correlation is a simple keyword + version heuristic score, not a
  vulnerability scanner. It can miss real matches and can produce false leads.
- Version-range parsing in exploit titles covers common patterns only (exact
  version, `<`, `<=`, `before`, `X through Y`, `X-Y`, and `X.x` wildcards) —
  it is not a full semantic version engine.
- OS detection, SYN scans, and UDP scans are more accurate (and sometimes
  only possible at all) when the app is run with Administrator/root
  privileges.
