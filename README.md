# NetSploitXZ

## Network Reconnaissance & Exploit Discovery Tool

NetSploitXZ is a Python-based network reconnaissance and exploit discovery tool. It uses Nmap to identify hosts, open ports, running services, and service versions, and uses a local Exploit-DB index to find potentially relevant public exploits.

The project provides a simple Tkinter GUI for running scans, viewing results, discovering exploits, and generating reports.

## Features

- Network reconnaissance using Nmap
- IPv4, IPv6, and hostname validation
- Open port and service detection
- Service and version detection
- OS detection
- TCP and UDP scanning
- Nmap NSE script scanning
- Exploit discovery using Exploit-DB
- Security observations for commonly exposed services
- TXT and HTML report generation
- Scan cancellation
- Background scanning
- Quick, Standard, Full, and Comprehensive scan profiles
- Custom Command tab for building your own Nmap scan (service/version detection, OS detection, script scan, UDP scan, timing, port selection, and free-form extra arguments), with results shown in the same tabs as a profile scan

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

## Scan Profiles

### Quick
Scans the top 100 TCP ports with version detection.

### Standard
Scans the top 1000 TCP ports with version detection and best-effort OS detection.

### Full
Scans all 65,535 TCP ports with version and OS detection.

### Comprehensive
Scans all TCP ports and the top UDP ports, with version detection, OS detection, and Nmap default scripts.

The Standard profile is used by default.

## Custom Command Scans

In addition to the fixed scan profiles, the **Custom Command** tab lets you build your own Nmap scan against the target entered at the top of the window:

- Service/Version Detection (`-sV`)
- OS Detection (`-O`)
- Default Script Scan (`-sC`)
- UDP Scan (`-sS -sU`)
- Timing template (`-T0` through `-T5`)
- Port selection: default top 1000, all ports (`-p-`), top N ports, or a custom port list/range
- Additional arguments field for any other Nmap flags not covered above

A live preview shows the exact command that will run. A custom scan goes through the same pipeline as a profile scan, so its results appear in the Host Info, Ports & Services, Security Findings, and Exploit Discovery tabs, and can be exported the same way.

## Exploit Discovery

NetSploitXZ uses a local Exploit-DB `files_exploits.csv` index to find potentially relevant exploits for services detected by Nmap.

The matching system looks for the detected product name (and, when available, version) inside each Exploit-DB entry's title.

The matching system is a simple heuristic and is intended to help identify exploits for further investigation.

NetSploitXZ does not download or execute exploit code.

## Reports

The tool can generate:

- TXT reports
- HTML reports

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

The project uses Python's standard library and does not require additional Python packages.

## Installing Nmap

Nmap must be installed and available in the system PATH.

On Windows, install Nmap and select the option to add Nmap to PATH during installation.

Administrator privileges may be required for some Nmap features such as OS detection and UDP scanning.

## Exploit-DB Setup

Clone the Exploit-DB repository:

```bash
git clone https://gitlab.com/exploit-database/exploitdb
```

Locate the following file:

```text
files_exploits.csv
```

Start NetSploitXZ and use the **Set Exploit-DB CSV** option to select the file.

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

The exploit discovery system is based on matching and is not a complete vulnerability scanner.

A matching Exploit-DB entry does not confirm that a target is definitely vulnerable. Results should be manually reviewed.

OS detection, SYN scans, and UDP scans may require Administrator/root privileges for complete results.

The Custom Command tab builds a standard Nmap scan from the selected options; it does not accept arbitrary shell syntax (pipes, redirects, etc.) beyond Nmap's own arguments.

## Responsible Use

NetSploitXZ is intended for educational purposes, cybersecurity labs, and authorized security testing.

Only scan systems and networks that you are authorized to test.

## Author

Nitay Kapoor
