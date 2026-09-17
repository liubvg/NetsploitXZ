from __future__ import annotations

import shutil
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime

from config import SCAN_PROFILES


# ---------------------------------------------------------------------
# data model (kept here rather than a separate models.py since these
# classes only exist to describe what nmap_scan.py produces)
# ---------------------------------------------------------------------

@dataclass
class ScriptResult:
    # output from an individual nmap script (only populated when -sC is used)
    script_id: str
    output: str


@dataclass
class ServiceInfo:
    port: int
    protocol: str
    state: str
    service_name: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""
    tunnel: str = ""             # e.g. "ssl" for https-over-ssl detection
    method: str = ""             # how nmap determined the service: "probed" or "table"
    conf: str = ""                # nmap's confidence (1-10) in the service ID itself
    cpe: list[str] = field(default_factory=list)   # CPE strings, if present
    scripts: list[ScriptResult] = field(default_factory=list)  # -sC output for this port


@dataclass
class HostInfo:
    target_input: str
    ip_address: str = ""
    mac_address: str = ""
    mac_vendor: str = ""
    hostname: str = ""
    state: str = "unknown"          # "up" / "down" / "unknown"
    os_guess: str = ""
    os_accuracy: str = ""
    uptime_seconds: str = ""
    last_boot: str = ""
    distance_hops: str = ""        # network hops away, if nmap reports it
    services: list[ServiceInfo] = field(default_factory=list)
    host_scripts: list[ScriptResult] = field(default_factory=list)  # host-level -sC output
    warnings: list[str] = field(default_factory=list)
    # scan metadata (filled in by scan_target, not by the XML parser itself)
    nmap_command: str = ""          # the actual nmap command line that was run
    scan_started: str = ""
    scan_completed: str = ""
    scan_duration_seconds: float = 0.0


def build_nmap_command(target: str, profile_name: str) -> tuple[list[str], str | None]:
    # builds the nmap argument list for the given target/profile.
    # returns (command, error_message), error_message set if nmap isn't found.
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        return [], "Nmap executable not found on PATH."

    profile = SCAN_PROFILES.get(profile_name, SCAN_PROFILES["Standard"])

    cmd = [nmap_path, "-sV"]
    if profile["os_detection"]:
        cmd.append("-O")
    if profile.get("udp"):
        # -sS = TCP SYN scan, -sU = UDP scan, combined so the "T:"/"U:"
        # port syntax in the profile's args is interpreted correctly
        cmd += ["-sS", "-sU"]
    if profile.get("script_scan"):
        cmd.append("-sC")  # run nmap's default (safe) script set for extra banner/info detail
    cmd += profile["args"]
    cmd += ["-T4", "-oX", "-", target]
    return cmd, None


# ---------------------------------------------------------------------
# step 1: run nmap, capture xml
# ---------------------------------------------------------------------

def run_nmap(
    target: str,
    profile_name: str,
    cancel_event: "threading.Event | None" = None,
) -> tuple[str | None, str | None, list[str]]:
    # runs nmap against `target` using the given scan profile.
    # returns (xml_output, error_message, command), exactly one of
    # xml_output/error_message is set. `command` is the actual argument
    # list used, so callers/reports can show what was run.
    #
    # `cancel_event` is an optional threading.Event. if it becomes set
    # while nmap is running, the process is terminated and (None,
    # "Scan cancelled by user.", command) is returned. no orphan nmap
    # process is left behind either way.
    cmd, error = build_nmap_command(target, profile_name)
    if error:
        return None, error, []

    profile = SCAN_PROFILES.get(profile_name, SCAN_PROFILES["Standard"])
    timeout_seconds = profile["timeout_seconds"]

    try:
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
    except OSError as exc:
        return None, f"Failed to start nmap: {exc}", cmd

    # nmap's xml output can be larger than the OS pipe buffer (a few tens
    # of KB). if we only poll process.poll() without reading the pipes,
    # nmap blocks trying to write and the scan hangs forever once the
    # buffer fills. so a background thread drains both pipes via
    # communicate() while this loop just watches for cancel/timeout.
    result_holder: dict = {}

    def _drain_pipes():
        result_holder["stdout"], result_holder["stderr"] = process.communicate()

    reader_thread = threading.Thread(target=_drain_pipes, daemon=True)
    reader_thread.start()

    start_time = time.monotonic()
    poll_interval = 0.25
    while reader_thread.is_alive():
        if cancel_event is not None and cancel_event.is_set():
            process.terminate()
            reader_thread.join(timeout=5)
            if reader_thread.is_alive():
                process.kill()  # make sure nothing orphaned survives
                reader_thread.join()
            return None, "Scan cancelled by user.", cmd

        if time.monotonic() - start_time > timeout_seconds:
            process.kill()
            reader_thread.join()
            return None, f"Scan timed out after {timeout_seconds} seconds.", cmd

        time.sleep(poll_interval)

    stdout = result_holder.get("stdout", "") or ""
    stderr = result_holder.get("stderr", "") or ""

    if process.returncode != 0 and not stdout:
        # nmap sometimes still returns useful stdout even with warnings on
        # stderr, so only treat it as a hard failure if we got no xml at all
        return None, f"Nmap exited with an error: {stderr.strip() or 'unknown error'}", cmd

    return stdout, None, cmd


# ---------------------------------------------------------------------
# step 2: parse nmap's xml into HostInfo/ServiceInfo
# ---------------------------------------------------------------------

def parse_nmap_xml(xml_text: str, target_input: str) -> HostInfo:
    # parses a single-host nmap xml report. if nmap scanned multiple
    # hosts (shouldn't happen for our single-target use case) only the
    # first is used.
    host_info = HostInfo(target_input=target_input)

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        host_info.warnings.append(f"Could not parse nmap XML output: {exc}")
        return host_info

    host_el = root.find("host")
    if host_el is None:
        host_info.warnings.append("Nmap reported no host data (target may be unreachable).")
        return host_info

    # host state (up/down)
    status_el = host_el.find("status")
    if status_el is not None:
        host_info.state = status_el.get("state", "unknown")

    # addresses (ipv4/ipv6 + mac if the target is on the local network)
    for addr_el in host_el.findall("address"):
        addrtype = addr_el.get("addrtype")
        if addrtype in ("ipv4", "ipv6"):
            host_info.ip_address = addr_el.get("addr", "")
        elif addrtype == "mac":
            host_info.mac_address = addr_el.get("addr", "")
            host_info.mac_vendor = addr_el.get("vendor", "")

    # hostname
    hostnames_el = host_el.find("hostnames")
    if hostnames_el is not None:
        hostname_el = hostnames_el.find("hostname")
        if hostname_el is not None:
            host_info.hostname = hostname_el.get("name", "")

    # uptime / distance (only present if nmap could determine them)
    uptime_el = host_el.find("uptime")
    if uptime_el is not None:
        host_info.uptime_seconds = uptime_el.get("seconds", "")
        host_info.last_boot = uptime_el.get("lastboot", "")

    distance_el = host_el.find("distance")
    if distance_el is not None:
        host_info.distance_hops = distance_el.get("value", "")

    # host-level script output (-sC scripts not tied to a specific port,
    # e.g. smb-os-discovery, traceroute-geolocation)
    hostscript_el = host_el.find("hostscript")
    if hostscript_el is not None:
        for script_el in hostscript_el.findall("script"):
            host_info.host_scripts.append(
                ScriptResult(
                    script_id=script_el.get("id", ""),
                    output=script_el.get("output", ""),
                )
            )

    # ports / services
    ports_el = host_el.find("ports")
    if ports_el is not None:
        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            state = state_el.get("state", "") if state_el is not None else ""

            service_el = port_el.find("service")
            cpe_list = []
            if service_el is not None:
                cpe_list = [cpe_el.text for cpe_el in service_el.findall("cpe") if cpe_el.text]

            service = ServiceInfo(
                port=int(port_el.get("portid", 0)),
                protocol=port_el.get("protocol", "tcp"),
                state=state,
                service_name=service_el.get("name", "") if service_el is not None else "",
                product=service_el.get("product", "") if service_el is not None else "",
                version=service_el.get("version", "") if service_el is not None else "",
                extra_info=service_el.get("extrainfo", "") if service_el is not None else "",
                tunnel=service_el.get("tunnel", "") if service_el is not None else "",
                method=service_el.get("method", "") if service_el is not None else "",
                conf=service_el.get("conf", "") if service_el is not None else "",
                cpe=cpe_list,
            )

            # per-port script output (-sC), e.g. http-title, ssl-cert, banner grabs
            for script_el in port_el.findall("script"):
                service.scripts.append(
                    ScriptResult(
                        script_id=script_el.get("id", ""),
                        output=script_el.get("output", ""),
                    )
                )

            host_info.services.append(service)

    # os guess (best-effort, may legitimately be absent). only worth a
    # warning if the host was actually up; if it's down, no OS scan was
    # possible for an unrelated reason and the warning would be misleading.
    os_el = host_el.find("os")
    if os_el is not None:
        osmatch_el = os_el.find("osmatch")
        if osmatch_el is not None:
            host_info.os_guess = osmatch_el.get("name", "")
            host_info.os_accuracy = osmatch_el.get("accuracy", "")
    elif host_info.state == "up":
        host_info.warnings.append(
            "OS detection produced no result (may require Administrator/root privileges)."
        )

    return host_info


# ---------------------------------------------------------------------
# convenience wrapper combining both steps
# ---------------------------------------------------------------------

def scan_target(
    target: str,
    profile_name: str,
    cancel_event: "threading.Event | None" = None,
) -> tuple[HostInfo | None, str | None]:
    # returns (HostInfo, error_message), exactly one is None (this
    # includes cancellation, which comes back as a "Scan cancelled by
    # user." error). also records the command used and scan start/end
    # timing onto HostInfo.
    started_at = datetime.now()
    start_clock = time.monotonic()

    xml_output, error, cmd = run_nmap(target, profile_name, cancel_event=cancel_event)

    duration = time.monotonic() - start_clock

    if error:
        return None, error

    host_info = parse_nmap_xml(xml_output, target)
    host_info.nmap_command = " ".join(cmd)
    host_info.scan_started = started_at.strftime("%Y-%m-%d %H:%M:%S")
    host_info.scan_completed = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    host_info.scan_duration_seconds = round(duration, 1)
    return host_info, None
