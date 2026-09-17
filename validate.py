from __future__ import annotations

import ipaddress
import re

# loose but correct-enough hostname pattern (RFC 1123): labels of
# letters/digits/hyphens separated by dots, no leading/trailing hyphen
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def validate_target(raw_input: str) -> tuple[str | None, str | None]:
    # returns (cleaned_target, error_message), exactly one is None.
    # accepts any valid IPv4/IPv6 address or syntactically valid
    # hostname/FQDN. no range or ownership checks, same as `nmap <target>`
    target = raw_input.strip()

    if not target:
        return None, "Enter a target IP address or hostname."

    # try IPv4/IPv6 first
    try:
        ipaddress.ip_address(target)
        return target, None
    except ValueError:
        pass

    # fall back to hostname syntax
    if _HOSTNAME_RE.match(target):
        return target, None

    return None, f"'{target}' doesn't look like a valid IP address or hostname."
