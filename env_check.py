"""
env_check.py — Phase 1: checks whether Nmap and the exploitdb CSV are
available before we let the user start a scan, plus a simple privilege
check (informational only -- we never block scanning because of it).
No Tkinter here, so this can be tested without a display.
"""

from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass

from config import Settings
from exploits import load_exploit_index


@dataclass
class ComponentStatus:
    name: str
    available: bool
    detail: str
    impact_if_missing: str


@dataclass
class EnvironmentReport:
    python: ComponentStatus
    nmap: ComponentStatus
    exploitdb: ComponentStatus
    privileges: ComponentStatus

    @property
    def can_scan(self) -> bool:
        return self.nmap.available

    @property
    def can_discover_exploits(self) -> bool:
        return self.exploitdb.available


def check_python() -> ComponentStatus:
    return ComponentStatus(
        name="Python",
        available=True,
        detail=f"Python {sys.version.split()[0]}",
        impact_if_missing="N/A",
    )


def check_nmap() -> ComponentStatus:
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        return ComponentStatus(
            name="Nmap",
            available=False,
            detail="nmap executable not found on PATH.",
            impact_if_missing=(
                "Scanning cannot begin. Install Nmap from https://nmap.org/download.html "
                "(select 'Add to PATH' during setup), then restart this app."
            ),
        )
    try:
        result = subprocess.run([nmap_path, "-V"], capture_output=True, text=True, timeout=10)
        first_line = result.stdout.splitlines()[0] if result.stdout else "Nmap (version unknown)"
        return ComponentStatus(
            name="Nmap", available=True, detail=f"{first_line} ({nmap_path})", impact_if_missing="N/A"
        )
    except (subprocess.SubprocessError, OSError) as exc:
        return ComponentStatus(
            name="Nmap",
            available=False,
            detail=f"Found at {nmap_path} but failed to execute: {exc}",
            impact_if_missing="Scanning cannot begin until Nmap runs correctly.",
        )


def check_exploitdb(settings: Settings) -> ComponentStatus:
    if not settings.exploitdb_csv_path:
        return ComponentStatus(
            name="Exploit-DB (local index)",
            available=False,
            detail="No exploitdb CSV selected yet.",
            impact_if_missing=(
                "Nmap reconnaissance still works. Exploit discovery is unavailable "
                "until you select your local exploitdb 'files_exploits.csv' file."
            ),
        )

    entries, error, skipped = load_exploit_index(settings.exploitdb_csv_path)
    if error:
        return ComponentStatus(
            name="Exploit-DB (local index)",
            available=False,
            detail=error,
            impact_if_missing="Nmap reconnaissance still works. Exploit discovery is unavailable.",
        )

    detail = f"{len(entries):,} entries loaded"
    if skipped:
        detail += f" ({skipped} malformed rows skipped)"
    return ComponentStatus(
        name="Exploit-DB (local index)",
        available=True,
        detail=detail,
        impact_if_missing="N/A",
    )


def check_privileges() -> ComponentStatus:
    """
    Informational only. Some Nmap features (OS detection, SYN/UDP scans)
    need elevated privileges to work fully, but we never block a scan
    just because the app isn't elevated -- Nmap itself will just fall
    back to slower/less accurate techniques.
    """
    try:
        if os.name == "nt":
            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
            label = "Administrator" if is_admin else "Not elevated"
        else:
            is_admin = hasattr(os, "geteuid") and os.geteuid() == 0
            label = "root" if is_admin else "Not elevated"
    except (AttributeError, OSError):
        return ComponentStatus(
            name="Privileges",
            available=False,
            detail="Could not determine privilege level.",
            impact_if_missing="Some scan features may be limited.",
        )

    return ComponentStatus(
        name="Privileges",
        available=is_admin,
        detail=label,
        impact_if_missing=(
            "OS detection and some scan types may be less accurate or fail without "
            "Administrator/root privileges. This does not block scanning."
        ),
    )


def run_environment_check() -> EnvironmentReport:
    settings = Settings.load()
    return EnvironmentReport(
        python=check_python(),
        nmap=check_nmap(),
        exploitdb=check_exploitdb(settings),
        privileges=check_privileges(),
    )
