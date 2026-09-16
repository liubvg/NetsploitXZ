"""
config.py — settings, scan profiles, and constants used across the app.

Kept deliberately simple: a small JSON settings file (stdlib json + pathlib),
no config framework.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path

# Where we remember small settings between runs (e.g. path to the
# exploitdb CSV you selected last time).
APP_DIR = Path.home() / ".ehpt_recon_tool"
SETTINGS_FILE = APP_DIR / "settings.json"

DEFAULT_REPORTS_DIR = Path.cwd() / "reports"

EXPLOITDB_CSV_FILENAME = "files_exploits.csv"

# Scan profiles: name -> extra nmap arguments (added on top of the base
# -sV -oX - flags that are always used).
SCAN_PROFILES = {
    "Quick": {
        "description": "Fast scan of top 100 ports, version detection only.",
        "args": ["--top-ports", "100"],
        "os_detection": False,
        "script_scan": False,
        "udp": False,
        "timeout_seconds": 240,
    },
    "Standard": {
        "description": "Default top-1000 ports, version + best-effort OS detection.",
        "args": [],
        "os_detection": True,
        "script_scan": False,
        "udp": False,
        "timeout_seconds": 420,
    },
    "Full": {
        "description": "All 65535 TCP ports, version + best-effort OS detection. Slow.",
        "args": ["-p-"],
        "os_detection": True,
        "script_scan": False,
        "udp": False,
        "timeout_seconds": 1800,
    },
    "Comprehensive": {
        "description": (
            "Everything: all 65535 TCP ports, top 100 UDP ports, version detection, "
            "OS detection, and default Nmap scripts (-sC) for extra service info. "
            "Slowest option — can take a long time depending on the target."
        ),
        "args": ["-p", "T:1-65535,U:1-100"],  # TCP all ports + top UDP ports, combined syntax
        "os_detection": True,
        "script_scan": True,
        "udp": True,
        "timeout_seconds": 3600,
    },
}

DEFAULT_PROFILE = "Standard"

CONFIDENCE_HIGH = "High"
CONFIDENCE_MEDIUM = "Medium"
CONFIDENCE_LOW = "Low"

EXPLOITDB_URL_TEMPLATE = "https://www.exploit-db.com/exploits/{edb_id}"


@dataclass
class Settings:
    exploitdb_csv_path: str | None = None
    last_profile: str = DEFAULT_PROFILE

    @classmethod
    def load(cls) -> "Settings":
        if SETTINGS_FILE.exists():
            try:
                data = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
                return cls(**{**asdict(cls()), **data})
            except (json.JSONDecodeError, OSError, TypeError):
                return cls()
        return cls()

    def save(self) -> None:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        SETTINGS_FILE.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")
