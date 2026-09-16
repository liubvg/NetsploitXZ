"""
validate.py — checks that whatever the user typed is a syntactically
valid IPv4/IPv6 address or hostname. This does NOT restrict which
targets are allowed (no whitelist/blacklist) — same as Nmap itself, the
tool doesn't police authorization, the operator is responsible for that
(see README: only scan systems you're authorized to test).
"""

from __future__ import annotations

import ipaddress
import re

# Loose but correct-enough hostname pattern (RFC 1123): labels of
# letters/digits/hyphens separated by dots, no leading/trailing hyphen.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def validate_target(raw_input: str) -> tuple[str | None, str | None]:
    """
    Returns (cleaned_target, error_message) — exactly one is None.
    Accepts: any valid IPv4 address, any valid IPv6 address, or any
    syntactically valid hostname/FQDN. No range or ownership checks —
    intentionally, the same way `nmap <target>` doesn't check either.
    """
    target = raw_input.strip()

    if not target:
        return None, "Enter a target IP address or hostname."

    # Try IPv4/IPv6 first
    try:
        ipaddress.ip_address(target)
        return target, None
    except ValueError:
        pass

    # Fall back to hostname syntax
    if _HOSTNAME_RE.match(target):
        return target, None

    return None, f"'{target}' doesn't look like a valid IP address or hostname."
