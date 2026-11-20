<div align="center">

# NetSploitXZ

### Network Reconnaissance & Exploit Discovery Tool

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20(primary)-lightgrey)
![Nmap](https://img.shields.io/badge/requires-Nmap-critical)
![Status](https://img.shields.io/badge/status-educational%20%2F%20lab%20use-yellow)

NetSploitXZ wraps **Nmap** scanning, **Exploit-DB** correlation, and report
generation behind a single lightweight **Tkinter GUI** — so you can scan a
target, see what's running, discover potentially relevant public exploits,
and export a shareable report, all in one window.

</div>

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [How It Works](#how-it-works)
- [Scan Profiles](#scan-profiles)
- [Custom Command Scans](#custom-command-scans)
- [Exploit Discovery](#exploit-discovery)
- [Reports](#reports)
- [Requirements](#requirements)
- [Installing Nmap](#installing-nmap)
- [Exploit-DB Setup](#exploit-db-setup)
- [Running the Project](#running-the-project)
- [Project Structure](#project-structure)
- [Limitations](#limitations)
- [Responsible Use](#responsible-use)
- [Author](#author)

---

## Overview

NetSploitXZ is a Python-based network reconnaissance and exploit discovery
tool. It uses Nmap to identify hosts, open ports, running services, and
service versions, and correlates what it finds against a local Exploit-DB
index to surface potentially relevant public exploits — all from one
Tkinter GUI, without needing to juggle a terminal, a browser, and a
spreadsheet.

## Features

- Network reconnaissance using Nmap
- IPv4, IPv6, and hostname target validation
- Open port and service detection
- Service and version detection
- OS detection
- TCP and UDP scanning
- Nmap NSE script scanning
- Exploit discovery using Exploit-DB, with an in-app filter box and a one-click "Open Exploit-DB" link for the selected match
- Security observations for commonly exposed services (HTTP, FTP, Telnet, SMB, etc.)
- TXT and HTML report generation
- Scan cancellation
- Background scanning (the GUI stays responsive while a scan runs)
- Quick, Standard, Full, and Comprehensive scan profiles
- Custom Command tab for building your own Nmap scan (service/version detection, OS detection, script scan, UDP scan, timing, port selection, and free-form extra arguments), with results shown in the same tabs as a profile scan
- Environment readiness check (verifies Python, Nmap, the Exploit-DB index, and privilege level before scanning)
- Sortable result tables (click any column header in the Ports & Services or Exploit Discovery tabs)
- Persistent settings (remembers the selected Exploit-DB CSV path and last-used scan profile between runs)

## How It Works

```text
Target
  |
  v
Target Validation
  |
  v
Nmap Scan (Scan Profile or Custom Command)
  |
  v
Nmap XML Output
  |
  v
XML Parser
  |
  v
Service & Version Detection
  |
  v
Exploit-DB Correlation
  |
  v
Exploit Matches
  |
  v
Security Findings & Reports
```

Results are organized into dedicated tabs: **Host Info**, **Ports &
Services**, **Security Findings**, **Exploit Discovery**, and **Custom
Command** — the same set of tabs regardless of whether the scan came from
a fixed profile or the Custom Command builder.

## Scan Profiles

| Profile | Ports | Extras | Typical timeout |
|---|---|---|---|
| **Quick** | Top 100 TCP | Version detection only | ~4 min |
| **Standard** *(default)* | Top 1000 TCP | Version + best-effort OS detection | ~7 min |
| **Full** | All 65,535 TCP | Version + OS detection | ~30 min |
| **Comprehensive** | All TCP + top 100 UDP | Version + OS detection + default NSE scripts (`-sC`) | ~60 min |

The **Standard** profile is used by default. Each profile has its own
timeout so a scan can't hang indefinitely — the scan can also be cancelled
manually at any time.

## Custom Command Scans

In addition to the fixed scan profiles, the **Custom Command** tab lets you
build your own Nmap scan against the target entered at the top of the
window:

- Service/Version Detection (`-sV`)
- OS Detection (`-O`)
- Default Script Scan (`-sC`)
- UDP Scan (`-sS -sU`)
- Timing template (`-T0` through `-T5`)
- Port selection: default top 1000, all ports (`-p-`), top *N* ports, or a custom port list/range (e.g. `22,80,8000-8100`)
- Additional arguments field for any other Nmap flags not covered above

A live preview shows the exact command that will run. A custom scan goes
through the same pipeline as a profile scan, so its results appear in the
Host Info, Ports & Services, Security Findings, and Exploit Discovery tabs,
and can be exported the same way.

> The Custom Command tab builds a standard Nmap command line from the
> selected options — it does not accept arbitrary shell syntax (pipes,
> redirects, etc.) beyond Nmap's own arguments.

## Exploit Discovery

NetSploitXZ uses a local Exploit-DB `files_exploits.csv` index to find
potentially relevant exploits for services detected by Nmap.

The matching system looks for the detected product name (and, when
available, version) inside each Exploit-DB entry's title, and surfaces
version-matched entries first. Matches can be filtered by keyword directly
in the Exploit Discovery tab, and the matching exploit's Exploit-DB page can
be opened in your browser with one click.

The matching system is a simple heuristic and is intended to help identify
exploits for further investigation.

**NetSploitXZ does not download or execute exploit code.**

## Reports

The tool can generate:

- **TXT reports**
- **HTML reports**

Reports contain information such as:

- Target information
- Host status
- Open ports
- Detected services
- Software versions
- OS information
- Nmap script results
- Security observations
- Potential exploit matches
- Recommendations
- Scan information

## Requirements

- Python 3.10+
- Nmap
- Local Exploit-DB repository/index
- Windows is the primary target environment

The project uses Python's standard library only and does not require any
additional Python packages.

## Installing Nmap

Nmap must be installed and available on the system `PATH`.

On Windows, install Nmap and select the option to add Nmap to `PATH`
during installation.

Administrator privileges may be required for some Nmap features such as OS
detection and UDP scanning — scanning still works without elevated
privileges, just with reduced accuracy for those features.

## Exploit-DB Setup

Clone the Exploit-DB repository:

```bash
git clone https://gitlab.com/exploit-database/exploitdb
```

Locate the following file:

```text
files_exploits.csv
```

Start NetSploitXZ and use the **Set Exploit-DB CSV** option to select the
file.

## Running the Project

Clone the repository:

```bash
git clone https://github.com/liubvg/NetsploitXZ.git
```

Go into the project directory:

```bash
cd NetsploitXZ
```

Run the application:

```bash
python main.py
```

## Project Structure

```text
NetsploitXZ/
│
├── main.py
├── gui.py
├── nmap_scan.py
├── exploits.py
├── report.py
├── env_check.py
├── validate.py
├── config.py
├── .gitignore
│
└── reports/
```

### File Description

| File | Description |
|---|---|
| `main.py` | Application entry point |
| `gui.py` | Tkinter graphical interface |
| `nmap_scan.py` | Builds and runs Nmap scans (scan profiles and custom commands) and parses XML results |
| `exploits.py` | Loads and matches Exploit-DB data |
| `report.py` | Generates TXT and HTML reports |
| `env_check.py` | Checks required components |
| `validate.py` | Validates IP addresses and hostnames |
| `config.py` | Application settings and scan profiles |

## Limitations

- The exploit discovery system is based on matching and is **not** a complete vulnerability scanner.
- A matching Exploit-DB entry does not confirm that a target is definitely vulnerable. Results should be manually reviewed.
- OS detection, SYN scans, and UDP scans may require Administrator/root privileges for complete results.
- The Custom Command tab builds a standard Nmap scan from the selected options; it does not accept arbitrary shell syntax (pipes, redirects, etc.) beyond Nmap's own arguments.

## Responsible Use

NetSploitXZ is intended for **educational purposes, cybersecurity labs, and
authorized security testing.**

**Only scan systems and networks that you are authorized to test.**

## Author

**Nitay Kapoor**
